# [httpsproxy](https://trac.torproject.org/projects/tor/ticket/26923)

## Spin up a full Tor bridge
This instruction explains how to install and start following components:
* Caddy Web Server
* Pluggable Transport
* Tor daemon

```bash
sudo apt install tor

# build server from source code
git clone https://git.torproject.org/pluggable-transports/httpsproxy.git
cd httpsproxy/server
go get
go build
sudo cp server /var/lib/tor/httpsproxy

# allow binding to ports 80 and 443
sudo /sbin/setcap 'cap_net_bind_service=+ep' /var/lib/tor/httpsproxy
sudo sed -i -e 's/NoNewPrivileges=yes/NoNewPrivileges=no/g' /lib/systemd/system/tor@default.service
sudo sed -i -e 's/NoNewPrivileges=yes/NoNewPrivileges=no/g' /lib/systemd/system/tor@.service
sudo systemctl daemon-reload

# don't forget to set correct ContactInfo
sudo cat <<EOT >> /etc/tor/torrc
  RunAsDaemon 1
  BridgeRelay 1
  ExitRelay 0

  PublishServerDescriptor 0 # 1 for public bridge

  ORPort 9001
  ExtORPort auto

  ServerTransportPlugin httpsproxy exec /var/lib/tor/httpsproxy -servername yourdomain.com -agree -email youremail@gmail.com
  Address 1.2.3.4 # might be required per https://trac.torproject.org/projects/tor/ticket/12020
  
  ContactInfo Dr Stephen Falken steph@gtnw.org
  Nickname joshua
EOT

sudo systemctl start tor

# monitor logs:
sudo less +F /var/log/tor/log
sudo less +F /var/lib/tor/pt_state/caddy.log
```

### PT arguments
As mentioned in code, `flag` package is global and PT arguments are passed together with those of Caddy.

```

Usage of ./server:
  -runcaddy
       Start Caddy web server on ports 443 and 80 (redirects to 443) together with the PT.
       You can disable this option, set static 'ServerTransportListenAddr httpsproxy 127.0.0.1:ptPort' in torrc,
       spin up frontend manually, and forward client's CONNECT request to 127.0.0.1:ptPort. (default true)
    -servername string
         Server Name used. Used as TLS SNI on the client side, and to start Caddy.
      -agree
           Agree to the CA's Subscriber Agreement
      -email string
           Default ACME CA account email address
    -cert string
         Path to TLS cert. Requires --key. If set, caddy will not get Lets Encrypt TLS certificate.
    -key string
         Path to TLS key. Requires --cert. If set, caddy will not get Lets Encrypt TLS certificate.
  -logfile string
       Log file for Pluggable Transport. (default: "$TOR_PT_STATE_LOCATION/caddy.log" -> /var/lib/tor/pt_state/caddy.log)
  -url string
       Set/override access url in form of https://username:password@1.2.3.4:443/.
       If servername is set or cert argument has a certificate with correct domain name,
       this arg is optional and will be inferred, username:password will be auto-generated and stored, if not provided.
```

## Configure client

Ideally, this will be integrated with the Tor browser and distributed automatically, so clients would have to do nothing
In the meantime, here's how to test it with Tor Browser Bundle:

1. Download [Tor Browser](https://www.torproject.org/projects/torbrowser.html.en)
2. Build httpsclient and configure torrc:
```
  git clone https://git.torproject.org/pluggable-transports/httpsproxy.git
  cd httpsproxy/client
  go get
  go build
  PATH_TO_CLIENT=`pwd`
  PATH_TO_TORRC="/etc/tor/torrc" # if TBB is used, path will be different
  echo "ClientTransportPlugin httpsproxy exec ${PATH_TO_CLIENT}/client" >> $PATH_TO_TORRC
```
4. Launch Tor Browser, select "Tor is censored in my country" -> "Provide a bridge I know"
5. Copy bridge line like "httpsproxy 0.4.2.0:3 url=https://username:password@httpsproxy.com".
   If you set up your own server, bridge line will be printed to caddy.log on server launch.

