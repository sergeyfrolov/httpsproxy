// Copyright 2018 Jigsaw Operations LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// HTTPS proxy based pluggable transport client.
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"

	pt "git.torproject.org/pluggable-transports/goptlib.git"
	"golang.org/x/net/http2"
)

var ptInfo pt.ClientInfo

// When a connection handler starts, +1 is written to this channel; when it
// ends, -1 is written.
var handlerChan = make(chan int)

// TODO: stop goroutine leaking in copyLoops: if one side closes - close another after timeout

// This function is copypasted from https://github.com/caddyserver/forwardproxy/blob/master/forwardproxy.go
// TODO: replace with padding-enabled function
// flushingIoCopy is analogous to buffering io.Copy(), but also attempts to flush on each iteration.
// If dst does not implement http.Flusher(e.g. net.TCPConn), it will do a simple io.CopyBuffer().
// Reasoning: http2ResponseWriter will not flush on its own, so we have to do it manually.
func flushingIoCopy(dst io.Writer, src io.Reader, buf []byte) (written int64, err error) {
	flusher, ok := dst.(http.Flusher)
	if !ok {
		return io.CopyBuffer(dst, src, buf)
	}
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			flusher.Flush()
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return
}

// simple copy loop without padding, works with http/1.1
// TODO: we can't pad, but we probably can split
func copyLoop(local, remote net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		io.Copy(remote, local)
		wg.Done()
	}()
	go func() {
		io.Copy(local, remote)
		wg.Done()
	}()
	// TODO: try not to spawn extra goroutine

	wg.Wait()
}

func h2copyLoop(w1 io.Writer, r1 io.Reader, w2 io.Writer, r2 io.Reader) {
	var wg sync.WaitGroup
	wg.Add(2)

	buf1 := make([]byte, 16384)
	buf2 := make([]byte, 16384)
	go func() {
		flushingIoCopy(w1, r1, buf1)
		wg.Done()
	}()
	go func() {
		flushingIoCopy(w2, r2, buf2)
		wg.Done()
	}()
	// TODO: try not to spawn extra goroutine

	wg.Wait()
}

func parseTCPAddr(s string) (*net.TCPAddr, error) {
	hostStr, portStr, err := net.SplitHostPort(s)
	if err != nil {
		fmt.Printf("net.SplitHostPort(%s) failed: %+v", s, err)
		return nil, err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		fmt.Printf("strconv.Atoi(%s) failed: %+v", portStr, err)
		return nil, err
	}

	ip := net.ParseIP(hostStr)
	if ip == nil {
		err = errors.New("net.ParseIP(" + s + ") returned nil")
		fmt.Printf("%+v\n", err)
		return nil, err
	}

	return &net.TCPAddr{Port: port, IP: ip}, nil
}

// handler will process a PT request, requests webproxy(that is given in URL arg) to connect to
// the Req.Target and relay traffic between client and webproxy
func handler(conn *pt.SocksConn) error {
	handlerChan <- 1
	defer func() {
		handlerChan <- -1
	}()
	defer conn.Close()

	guardTCPAddr, err := parseTCPAddr(conn.Req.Target)
	if err != nil {
		conn.Reject()
		return err
	}

	webproxyUrlArg, ok := conn.Req.Args.Get("url")
	if !ok {
		err := errors.New("address of webproxy in form of `url=https://username:password@example.com` is required")
		conn.Reject()
		return err
	}

	httpsClient, err := NewHTTPSClient(webproxyUrlArg)
	if err != nil {
		log.Printf("NewHTTPSClient(%s, nil) failed: %s\n", webproxyUrlArg, err)
		conn.Reject()
		return err
	}

	err = httpsClient.Connect(conn.Req.Target)
	if err != nil {
		log.Printf("httpsClient.Connect(%s, nil) failed: %s\n", conn.Req.Target, err)
		conn.Reject()
		return err
	}

	err = conn.Grant(guardTCPAddr)
	if err != nil {
		log.Printf("conn.Grant(%s) failed: %s\n", guardTCPAddr, err)
		conn.Reject()
		return err
	}

	return httpsClient.CopyLoop(conn)
}

func acceptLoop(ln *pt.SocksListener) error {
	defer ln.Close()
	for {
		conn, err := ln.AcceptSocks()
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Temporary() {
				continue
			}
			return err
		}
		go handler(conn)
	}
}

func main() {
	var err error

	logFile := flag.String("log", "", "Log file for debugging")
	flag.Parse()

	ptInfo, err = pt.ClientSetup(nil)
	if err != nil {
		os.Exit(1)
	}

	if ptInfo.ProxyURL != nil {
		pt.ProxyError("proxy is not supported")
		os.Exit(1)
	}

	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0660)
		if err != nil {
			pt.CmethodError("httpsproxy",
				fmt.Sprintf("error opening file %s: %v", logFile, err))
			os.Exit(2)
		}
		defer f.Close()
		log.SetOutput(f)
	}

	listeners := make([]net.Listener, 0)
	for _, methodName := range ptInfo.MethodNames {
		switch methodName {
		case "httpsproxy":
			ln, err := pt.ListenSocks("tcp", "127.0.0.1:0")
			if err != nil {
				pt.CmethodError(methodName, err.Error())
				break
			}
			go acceptLoop(ln)
			pt.Cmethod(methodName, ln.Version(), ln.Addr())
			log.Printf("Started %s %s at %s\n", methodName, ln.Version(), ln.Addr())
			listeners = append(listeners, ln)
		default:
			pt.CmethodError(methodName, "no such method")
		}
	}
	pt.CmethodsDone()

	var numHandlers = 0
	var sig os.Signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM)

	if os.Getenv("TOR_PT_EXIT_ON_STDIN_CLOSE") == "1" {
		// This environment variable means we should treat EOF on stdin
		// just like SIGTERM: https://bugs.torproject.org/15435.
		go func() {
			io.Copy(ioutil.Discard, os.Stdin)
			sigChan <- syscall.SIGTERM
		}()
	}

	// keep track of handlers and wait for a signal
	sig = nil
	for sig == nil {
		select {
		case n := <-handlerChan:
			numHandlers += n
		case sig = <-sigChan:
		}
	}

	// signal received, shut down
	for _, ln := range listeners {
		ln.Close()
	}
	for numHandlers > 0 {
		numHandlers += <-handlerChan
	}
}

type HTTPConnectClient struct {
	Header    http.Header
	ProxyHost string
	TlsConf   tls.Config

	Conn *tls.Conn

	In  io.Writer
	Out io.Reader
}

// NewHTTPSClient creates one-time use client to tunnel traffic via HTTPS proxy.
// If spkiFp is set, HTTPSClient will use it as SPKI fingerprint to confirm identity of the
// proxy, instead of relying on standard PKI CA roots
func NewHTTPSClient(proxyUrlStr string) (*HTTPConnectClient, error) {
	proxyUrl, err := url.Parse(proxyUrlStr)
	if err != nil {
		return nil, err
	}

	switch proxyUrl.Scheme {
	case "http", "":
		fallthrough
	default:
		return nil, errors.New("Scheme " + proxyUrl.Scheme + " is not supported")
	case "https":
	}

	if proxyUrl.Host == "" {
		return nil, errors.New("misparsed `url=`, make sure to specify full url like https://username:password@hostname.com:443/")
	}

	if proxyUrl.Port() == "" {
		proxyUrl.Host = net.JoinHostPort(proxyUrl.Host, "443")
	}

	tlsConf := tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
		ServerName: proxyUrl.Hostname(),
	}

	client := &HTTPConnectClient{
		Header:    make(http.Header),
		ProxyHost: proxyUrl.Host,
		TlsConf:   tlsConf,
	}

	if proxyUrl.User.Username() != "" {
		password, _ := proxyUrl.User.Password()
		client.Header.Set("Proxy-Authorization", "Basic "+
			base64.StdEncoding.EncodeToString([]byte(proxyUrl.User.Username()+":"+password)))
	}
	return client, nil
}

func (c *HTTPConnectClient) Connect(target string) error {
	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Host: target},
		Header: c.Header,
		Host:   target,
	}

	tcpConn, err := net.Dial("tcp", c.ProxyHost)
	if err != nil {
		return err
	}

	c.Conn = tls.Client(tcpConn, &c.TlsConf)

	err = c.Conn.Handshake()
	if err != nil {
		return err
	}

	var resp *http.Response
	switch c.Conn.ConnectionState().NegotiatedProtocol {
	case "":
		fallthrough
	case "http/1.1":
		req.Proto = "HTTP/1.1"
		req.ProtoMajor = 1
		req.ProtoMinor = 1

		err = req.Write(c.Conn)
		if err != nil {
			c.Conn.Close()
			return err
		}

		resp, err = http.ReadResponse(bufio.NewReader(c.Conn), req)
		if err != nil {
			c.Conn.Close()
			return err
		}

		c.In = c.Conn
		c.Out = c.Conn
	case "h2":
		req.Proto = "HTTP/2.0"
		req.ProtoMajor = 2
		req.ProtoMinor = 0
		pr, pw := io.Pipe()
		req.Body = ioutil.NopCloser(pr)

		t := http2.Transport{}
		h2client, err := t.NewClientConn(c.Conn)
		if err != nil {
			c.Conn.Close()
			return err
		}

		resp, err = h2client.RoundTrip(req)
		if err != nil {
			c.Conn.Close()
			return err
		}

		c.In = pw
		c.Out = resp.Body
	default:
		c.Conn.Close()
		return errors.New("negotiated unsupported application layer protocol: " +
			c.Conn.ConnectionState().NegotiatedProtocol)
	}

	if resp.StatusCode != http.StatusOK {
		c.Conn.Close()
		return errors.New("Proxy responded with non 200 code: " + resp.Status)
	}

	return nil
}

func (c *HTTPConnectClient) CopyLoop(conn net.Conn) error {
	defer c.Conn.Close()
	defer conn.Close()

	switch c.Conn.ConnectionState().NegotiatedProtocol {
	case "":
		fallthrough
	case "http/1.1":
		copyLoop(conn, c.Conn)
	case "h2":
		h2copyLoop(c.In, conn, conn, c.Out)
	default:
		return errors.New("negotiated unsupported application layer protocol: " +
			c.Conn.ConnectionState().NegotiatedProtocol)
	}
	return nil
}
