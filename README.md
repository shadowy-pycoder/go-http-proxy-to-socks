# GoHPTS - HTTP(S) and TCP/UDP transparent proxy to SOCKS4/SOCKS5 proxy (chain) written in Go

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-yellow.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Go Reference](https://pkg.go.dev/badge/github.com/shadowy-pycoder/go-http-proxy-to-socks.svg)](https://pkg.go.dev/github.com/shadowy-pycoder/go-http-proxy-to-socks)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/shadowy-pycoder/go-http-proxy-to-socks)
[![Go Report Card](https://goreportcard.com/badge/github.com/shadowy-pycoder/go-http-proxy-to-socks)](https://goreportcard.com/report/github.com/shadowy-pycoder/go-http-proxy-to-socks)
![GitHub Release](https://img.shields.io/github/v/release/shadowy-pycoder/go-http-proxy-to-socks)
![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/shadowy-pycoder/go-http-proxy-to-socks/total)
![GitHub Downloads (all assets, latest release)](https://img.shields.io/github/downloads/shadowy-pycoder/go-http-proxy-to-socks/latest/total)

![GoHPTS - Colors example](resources/sniffing_color.png)

## Table of contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Configuration via CLI flags](#configuration-via-cli-flags)
  - [Configuration via YAML file](#configuration-via-yaml-file)
- [Transparent proxy](#transparent-proxy)
  - [redirect (via NAT and SO_ORIGINAL_DST)](#redirect-via-nat-and-so_original_dst)
  - [Auto configuration for redirect mode](#auto-configuration-for-redirect-mode)
  - [tproxy (via MANGLE and IP_TRANSPARENT)](#tproxy-via-mangle-and-ip_transparent)
  - [Auto configuration for tproxy mode](#auto-configuration-for-tproxy-mode)
  - [UDP support](#udp-support)
  - [Android support](#android-support)
  - [YAML configuration](#yaml-configuration)
- [Traffic sniffing](#traffic-sniffing)
  - [JSON format](#json-format)
  - [Colored format](#colored-format)
- [HTTP2 and HTTP3 support](#http2-and-http3-support)
  - [Example setup using self-signed certificate](#example-setup-using-self-signed-certificate)
  - [Test connection](#test-connection)
  - [Test connection in a browser](#test-connection-in-a-browser)
- [IPv6 support](#ipv6-support)
- [ARP spoofing](#arp-spoofing)
- [NDP spoofing](#ndp-spoofing)
- [DNS spoofing](#dns-spoofing)
- [Packet Capture](#packet-capture)
- [Network Namespaces](#network-namespaces)
  - [Playground setup](#playground-setup)
  - [Usage examples](#usage-examples)
- [Links](#links)
- [Contributing](#contributing)
- [License](#license)

## Introduction

[[Back]](#table-of-contents)

`GoHPTS` CLI tool is a bridge between HTTP clients and a SOCKS5 proxy server or multiple servers (chain). It listens locally as an HTTP proxy, accepts standard HTTP
or HTTPS (via CONNECT) requests and forwards the connection through a SOCKS5 proxy. Inspired by [http-proxy-to-socks](https://github.com/oyyd/http-proxy-to-socks) and [Proxychains](https://github.com/rofl0r/proxychains-ng)

Possible use case: you need to connect to external API via Postman, but this API only available from some remote server.
The following commands will help you to perform such a task:

Create SOCKS5 proxy server via `ssh`:

```shell
ssh <remote server> -D 1080 -Nf
```

Create HTTP-to-SOCKS5 connection with `gohpts`

```shell
gohpts -s :1080 -l :8080
```

Specify http server in proxy configuration of Postman

## Features

[[Back]](#table-of-contents)

- **Proxy Chain functionality**\
  Supports `strict`, `dynamic`, `random`, `round_robin` chains of SOCKS4/SOCKS5 proxy

- **Transparent proxy**\
  Supports `redirect` (SO_ORIGINAL_DST) and `tproxy` (IP_TRANSPARENT) modes

- **TCP and UDP Transparent proxy**\
  `tproxy` and `tlocal` (IP_TRANSPARENT) handle TCP and UDP traffic

- **Traffic sniffing**\
  Proxy is able to parse HTTP headers, TLS handshake, DNS messages and more

- **ARP spoofing**\
  Proxy entire subnets with ARP spoofing approach

- **NDP spoofing**\
  Proxy IPv6 connections using Router/Neighbor Advertisement and RDNSS injections.

- **DNS spoofing**\
  Redirect clients to arbitrary domains using DNS records manipulation

- **Packet Capture**\
  Capture traffic into txt/pcap/pcapng files and analyze with Wireshark

- **DNS Leak Protection**\
  DNS resolution occurs on SOCKS5 server side.

- **CONNECT Method Support**\
  Supports HTTP CONNECT tunneling, enabling HTTPS and other TCP-based protocols.

- **HTTP2/HTTP3 Support**\
  Supports modern HTTP/2 and HTTP/3 transport, enabling efficient multiplexed connections over TLS 1.3

- **Network Namespaces support**\
  Supports custom Linux network namespaces for listening sockets and outbound connections

- **Trailer Headers Support**\
  Handles HTTP trailer headers

- **Chunked Transfer Encoding**\
  Handles chunked and streaming responses

- **SOCKS5 Authentication Support**\
  Supports username/password authentication for SOCKS5 proxies.

- **HTTP Authentication Support**\
  Supports username/password authentication for HTTP proxy server.

- **Lightweight and Fast**\
  Designed with minimal overhead and efficient request handling.

- **Cross-Platform**\
  Compatible with all major operating systems.

## Installation

[[Back]](#table-of-contents)

- Arch Linux/CachyOS/EndeavourOS

  ```shell
  yay -S gohpts
  ```

  Or using `paru`:

  ```shell
  paru -S gohpts
  ```

- Download the binary for your platform from [Releases](https://github.com/shadowy-pycoder/go-http-proxy-to-socks/releases) page:

  ```shell
  GOHPTS_RELEASE=v1.15.0; wget -v https://github.com/shadowy-pycoder/go-http-proxy-to-socks/releases/download/$GOHPTS_RELEASE/gohpts-$GOHPTS_RELEASE-linux-amd64.tar.gz -O gohpts && tar xvzf gohpts && mv -f gohpts-$GOHPTS_RELEASE-linux-amd64 gohpts && ./gohpts -h
  ```

- Install using `go install` command (requires Go [1.26](https://go.dev/doc/install) or later):

  ```shell
  CGO_ENABLED=0 go install -ldflags "-s -w" -trimpath github.com/shadowy-pycoder/go-http-proxy-to-socks/cmd/gohpts@latest
  ```

  This will install the `gohpts` binary to your `$GOPATH/bin` directory.

- Build from source:

  ```shell
  git clone https://github.com/shadowy-pycoder/go-http-proxy-to-socks.git
  cd go-http-proxy-to-socks
  make build
  ./bin/gohpts
  ```

- Run in docker:

  ```shell
  docker run -it --privileged --network host -v "$PWD/gohpts.yaml:/config.yaml" shadowypycoder/gohpts:latest -f config.yaml
  ```

## Usage

[[Back]](#table-of-contents)

```shell
gohpts -h
   _____       _    _ _____ _______ _____
  / ____|     | |  | |  __ \__   __/ ____|
 | |  __  ___ | |__| | |__) | | | | (___
 | | |_ |/ _ \|  __  |  ___/  | |  \___ \
 | |__| | (_) | |  | | |      | |  ____) |
  \_____|\___/|_|  |_|_|      |_| |_____/

GoHPTS (HTTP(S) Proxy to SOCKS4/SOCKS5 proxy) by shadowy-pycoder
GitHub: https://github.com/shadowy-pycoder/go-http-proxy-to-socks
Codeberg: https://codeberg.org/shadowy-pycoder/go-http-proxy-to-socks

Usage: gohpts [OPTIONS]
OPTIONS:
  General:
  -h         Show this help message and exit
  -v         Show version and build information
  -D         Run as a daemon (provide -logfile to see logs)
  -I         Display list of network interfaces and exit
  -f         Path to proxy configuration file in YAML format

  Proxy:
  -l         Address of HTTP proxy server (Default: "127.0.0.1:8080")
  -s         Address of SOCKS5 proxy server (Default: "127.0.0.1:1080")
  -c         Path to certificate PEM encoded file
  -k         Path to private key PEM encoded file
  -U         User for HTTP proxy (basic auth). This flag invokes prompt for password (not echoed to terminal)
  -u         User for SOCKS5 proxy authentication. This flag invokes prompt for password (not echoed to terminal)
  -i         Bind proxy to specific network interface (either by interface name or index)
  -6         Enable IPv6 support for TCP and UDP
  -socks4    Use SOCKS4/SOCKS4a as the upstream proxy protocol (default: SOCKS5)
  -nohttp    Disable HTTP proxy server
  -nosocks   Disable SOCKS upstream proxy
  -dns       Use custom DNS server (Example: "8.8.8.8" or "2001:4860:4860::8888")

  Logs:
  -d         Show logs in DEBUG mode
  -j         Show logs in JSON format
  -logfile   Log file path (Default: stdout)
  -nocolor   Disable colored output for logs (no effect if -j flag specified)
  -pprof     Address of pprof server with profiling data

  Sniffing:
  -sniff     Enable traffic sniffing for HTTP and TLS
  -snifflog  Sniffed traffic log file path (Default: the same as -logfile)
  -body      Collect request and response body for HTTP traffic (credentials, tokens, etc)

  TProxy:
  -T         Address of transparent proxy server
  -Tu        Address of transparent UDP proxy server
  -M         Transparent proxy mode: (redirect, tproxy, tlocal)
  -w         Number of instances of transparent proxy server (Default: number of CPU cores)
  -wu        Number of instances of transparent UDP proxy server (Default: number of CPU cores)
  -auto      Automatically setup iptables and kernel parameters for transparent proxy (requires elevated privileges)
  -mark      Set mark for each packet sent through transparent proxy (Default: redirect 0, tproxy 100, tlocal 100)
  -P         Comma separated list of ports to ignore when proxying traffic (Example: "22,80,443,9092")
  -dump      Dump iptables rules and other system settings generated by -auto flag

  Spoofing:
  -arpspoof  Enable ARP spoof proxy for selected targets (Example: "targets 10.0.0.1,10.0.0.5-10,192.168.1.*,192.168.10.0/24;fullduplex false;debug true;interval 10s")
  -ndpspoof  Enable NDP spoof proxy for selected targets (Example: "ra true;na true;targets fe80::3a1c:7bff:fe22:91a4;fullduplex false;debug true;interval 10s")

  Packet Capture:
  -pcap      Enable packet capture (Example: "promisc true;expr ip proto tcp;snaplen 65535;timeout 10s;packet_count 100;packet_buffer 8192;exts txt,pcap,pcapng")

  Namespaces:
  -in-netns  Name or path of network namespace for inbound listeners (Default: default namespace)
  -out-netns Name or path of network namespace for outbound connections (Default: default namespace)
```

### Configuration via CLI flags

[[Back]](#table-of-contents)

```shell
gohpts -s 1080 -l 8080 -d -j
```

Output:

```shell
{"level":"info","time":"2025-05-28T06:15:18+00:00","message":"SOCKS5 Proxy: :1080"}
{"level":"info","time":"2025-05-28T06:15:18+00:00","message":"HTTP Proxy: :8080"}
{"level":"debug","time":"2025-05-28T06:15:22+00:00","message":"HTTP/1.1 - CONNECT - www.google.com:443"}
```

Specify username and password for SOCKS5 proxy server:

```shell
gohpts -s 1080 -l 8080 -d -j -u user
SOCKS5 Password: #you will be prompted for password input here
```

Specify username and password for HTTP proxy server:

```shell
gohpts -s 1080 -l 8080 -d -j -U user
HTTP Password: #you will be prompted for password input here
```

When both `-u` and `-U` are present, you will be prompted twice

Run http proxy over TLS connection

```shell
gohpts -s 1080 -l 8080 -c "path/to/certificate" -k "path/to/private/key"
```

Run proxy as a daemon (logfile is needed for logging output, otherwise you will see nothing)

```shell
gohpts -D -logfile /tmp/gohpts.log
```

```shell
# output
gohpts pid: <pid>
```

```shell
# kill the process
kill <pid>
#or
kill $(pidof gohpts)
```

`-u` and `-U` flags do not work in a daemon mode (and therefore authentication), but you can provide a config file (see below)

### Configuration via YAML file

[[Back]](#table-of-contents)

Configuration files are useful when you want to preconfigure your proxy without messing with CLI too much or just want multiple profiles for different needs.

Run http proxy in SOCKS5 proxy chain mode (specify server settings via YAML configuration file)

```shell
gohpts -f "~/gohtps.yaml" -d -j
```

Config example:

```yaml
# bind proxy to specific network interface (either by interface name or index)
interface: "eth0" # if specified, overrides http server IP address
disable_http: false # disable http proxy (default: false)
disable_socks: false # disable upstream socks proxy (default: false)
ipv6: false # this must be enabled for ndpspoof (default: false)
socks4: false # use SOCKS4/SOCKS4a protocol (tcp only protocol, no udp tproxy or http3 possible) (default: false)
dns: 8.8.8.8 # custom DNS server (used in direct dialer, namespaces, spoofing)

http_server:
  address: 127.0.0.1:8080
  # username and password for adding basic authentication (comment out to disable auth)
  username: username
  password: password

# list of socks5 proxy
# if proxy_chain is disabled, uses first server in a list as upstream
proxy_list:
  - address: 127.0.0.1:1080
  - address: 127.0.0.1:1081
  - address: :1082 # empty host means localhost

proxy_chain:
  enabled: false
  # Explanations for chains taken from /etc/proxychains4.conf

  # strict - Each connection will be done via chained proxies
  # all proxies chained in the order as they appear in the list
  # all proxies must be online to play in chain

  # dynamic - Each connection will be done via chained proxies
  # all proxies chained in the order as they appear in the list
  # at least one proxy must be online to play in chain
  # (dead proxies are skipped)

  # random - Each connection will be done via random proxy
  # (or proxy chain, see  chain_len) from the list.
  # this option is good to test your IDS :)

  # round_robin - Each connection will be done via chained proxies
  # of chain_len length
  # all proxies chained in the order as they appear in the list
  # at least one proxy must be online to play in chain
  # (dead proxies are skipped).
  # the start of the current proxy chain is the proxy after the last
  # proxy in the previously invoked proxy chain.
  # if the end of the proxy chain is reached while looking for proxies
  # start at the beginning again.
  # These semantics are not guaranteed in a multithreaded environment.
  type: strict # dynamic, strict, random, round_robin
  length: 2 # maximum number of proxy in a chain (works only for random chain and round_robin chain)

logging:
  debug: true
  json: false
  # defaults to standard output
  #logfile: /tmp/gohpts.log
  # use colored output in logs (no effect if json enabled)
  nocolor: false
  # profiling data
  pprof: 127.0.0.1:8081
```

You can override almost any settings specified in configuration file by providing corresponding CLI flags:

```shell
gohpts -l :6969 -f "~/gohtps.yaml" -nocolor
```

Proxy takes all the settings specified in `~/gohpts.yaml` but spins up http server on `127.0.0.1:6969` insted of `127.0.0.1:8080` and also disables colored output in logs.

Some settings (e.g. proxy_chain and dns filters) can only be configured via file.

Full version of config can be found here: [example_gohpts.yaml](./resources/example_gohpts.yaml)

To learn more about proxy chains visit [Proxychains Github](https://github.com/rofl0r/proxychains-ng)

## Transparent proxy

[[Back]](#table-of-contents)

> Also known as an `intercepting proxy`, `inline proxy`, or `forced proxy`, a transparent proxy intercepts normal application layer communication without requiring any special client configuration. Clients need not be aware of the existence of the proxy. A transparent proxy is normally located between the client and the Internet, with the proxy performing some of the functions of a gateway or router
>
> -- _From [Wiki](https://en.wikipedia.org/wiki/Proxy_server)_

This functionality available only on Linux systems and Android (arm64) and requires additional setup (`iptables`, ip route, etc)

`-T address` flag specifies the address of transparent proxy server

There are three modes `redirect`, `tproxy` and `tlocal` (same as `tproxy` but also intercepts local traffic) that can be specified with `-M` flag

### `redirect` (via _NAT_ and _SO_ORIGINAL_DST_)

[[Back]](#table-of-contents)

In this mode proxying happens with `iptables` `nat` table and `REDIRECT` target. Host of incoming packet changes to the address of running `redirect` transparent proxy, but it also contains original destination that can be retrieved with `getsockopt(SO_ORIGINAL_DST)`

To run `GoHPTS` in this mode you use `-T` flag with `-M redirect`

### Example

[[Back]](#table-of-contents)

```shell
# run the proxy
gohpts -s 1080 -T 1090 -M redirect -d
```

```shell
# run socks5 server on 127.0.0.1:1080
ssh remote -D 1080 -Nf
```

Setup your operating system:

```shell
# commands below require elevated privileges (you can run it with `sudo -i`)

#enable ip forwarding
sysctl -w net.ipv4.ip_forward=1

# create `GOHPTS` nat chain
iptables -t nat -N GOHPTS

# set no redirection rules for local, http proxy, ssh and redirect proxy itself
iptables -t nat -A GOHPTS -d 127.0.0.0/8 -j RETURN
iptables -t nat -A GOHPTS -p tcp --dport 8080 -j RETURN
iptables -t nat -A GOHPTS -p tcp --dport 1090 -j RETURN
iptables -t nat -A GOHPTS -p tcp --dport 22 -j RETURN

# redirect traffic to transparent proxy
iptables -t nat -A GOHPTS -p tcp -j REDIRECT --to-ports 1090

# setup prerouting by adding our proxy
iptables -t nat -A PREROUTING -p tcp -j GOHPTS

# intercept local traffic for testing
iptables -t nat -A OUTPUT -p tcp -j GOHPTS
```

Test connection:

```shell
#traffic should be redirected via 127.0.0.1:1090
curl http://example.com
```

```shell
#traffic should be redirected via 127.0.0.1:8080
curl --proxy http://127.0.0.1:8080 http://example.com
```

Undo everything:

```shell
sysctl -w net.ipv4.ip_forward=0
iptables -t nat -D PREROUTING -p tcp -j GOHPTS
iptables -t nat -D OUTPUT -p tcp -j GOHPTS
iptables -t nat -F GOHPTS
iptables -t nat -X GOHPTS
```

### Auto configuration for `redirect` mode

[[Back]](#table-of-contents)

To configure your system automatically, run the following command:

```shell
sudo env PATH=$PATH gohpts -d -T 8888 -M redirect -auto
```

Please note, automatic configuration requires `sudo` and is very generic, which might not be suitable for your needs.

You can optionally specify `-mark <value>` to prevent possible proxy loops

```shell
sudo env PATH=$PATH gohpts -d -T 8888 -M redirect -auto -mark 100
```

### `tproxy` (via _MANGLE_ and _IP_TRANSPARENT_)

[[Back]](#table-of-contents)

In this mode proxying happens with `iptables` `mangle` table and `TPROXY` target. Transparent proxy sees destination address as is, it is not being rewrited by the kernel. For this to work the proxy binds with socket option `IP_TRANSPARENT`, `iptables` intercepts traffic using TPROXY target, routing rules tell marked packets to go to the local proxy without changing their original destination.

This mode requires elevated privileges to run `GoHPTS`. You can do that by running the follwing command:

```shell
sudo setcap 'cap_net_admin+ep' ~/go/bin/gohpts
```

To run `GoHPTS` in this mode you use `-T` flag with `-M tproxy`

### Example

[[Back]](#table-of-contents)

```shell
# run the proxy
gohpts -s 1080 -T 0.0.0.0:1090 -M tproxy -d
```

```shell
# run socks5 server on 127.0.0.1:1080
ssh remote -D 1080 -Nf
```

Setup your operating system:

```shell
ip netns add ns-client
ip link add dev veth0 type veth peer name veth1 netns ns-client
ip addr add 10.0.0.1/24 dev veth0
ip link set dev veth0 up
ip netns exec ns-client ip addr add 10.0.0.2/24 dev veth1
ip netns exec ns-client ip link set dev lo up
ip netns exec ns-client ip link set dev veth1 up
ip netns exec ns-client ip route add default via 10.0.0.1
sysctl -w net.ipv4.ip_forward=1

iptables -t mangle -A PREROUTING -i veth0 -p tcp -j TPROXY --on-port 1090 --tproxy-mark 0x1/0x1

ip rule add fwmark 1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
```

Test connection:

```shell
ip netns exec ns-client curl http://1.1.1.1
```

Undo everything:

```shell
sysctl -w net.ipv4.ip_forward=0
iptables -t mangle -F
ip rule del fwmark 1 lookup 100
ip route flush table 100
ip netns del ns-client
```

### Auto configuration for `tproxy` mode

[[Back]](#table-of-contents)

To configure your system automatically, run the following command (for example, on a separate VM):

```shell
ssh remote -D 1080 -Nf
sudo env PATH=$PATH gohpts -d -T 8888 -M tproxy -auto -mark 100
```

Run the following on your host:

```shell
ip route show default > /tmp/default-route.txt

ip route add 0.0.0.0/1 via 192.168.0.1 # change with ip of your VM
ip route add 128.0.0.0/1 via 192.168.0.1
```

Test connection:

```shell
curl http://example.com #check logs on your VM
```

Undo everything:

```shell
ip route del 0.0.0.0/1 via 192.168.0.1 2>/dev/null || true
ip route del 128.0.0.0/1 via 192.168.0.1 2>/dev/null || true

if [[ -f /tmp/default-route.txt ]]; then
    eval $(awk '{print "ip route add "$0}' /tmp/default-route.txt)
    rm -f /tmp/default-route.txt
else
    echo "Something went wrong"
fi
```

### UDP support

[[Back]](#table-of-contents)

`GoHPTS` has UDP support that can be enabled in `tproxy` and `tlocal` modes. For this setup to work you need to connect to a socks5 server capable of serving UDP connections (`UDP ASSOCIATE`). For example, you can use [https://github.com/wzshiming/socks5](https://github.com/wzshiming/socks5) to deploy UDP capable socks5 server on some remote or local machine. Once you have the server to connect to, run the following command:

```shell
sudo env PATH=$PATH gohpts -s remote -Tu :8989 -M tproxy -auto -mark 100 -d
```

This command will configure your operating system and setup server on `0.0.0.0:8989` address.

To test it locally, you can combine UDP transparent proxy with `-arpspoof` flag. For example:

1. Setup VM on your system with any Linux distributive that supports `tproxy` (Kali Linux, for instance).
2. Enable `bridged` network so that VM could access your host machine.
3. Move `gohpts` binary to VM (via `ssh`, for instance) or build it there in case of different OS/arch.
4. On your VM run the following command:

```shell
# Do not forget to replace <socks5 server> and <your host> with actual addresses
sudo ./gohpts -s <socks5 server> -T 8888 -Tu :8989 -M tproxy -sniff -body -auto -mark 100 -d -arpspoof "targets <your host>;fullduplex true;debug false"
```

5. Check connection on your host machine, the traffic should go through Kali machine.

### Android support

[[Back]](#table-of-contents)

Transparent proxy can be enabled on Android devices (arm64) with root access. You can install [Termux](https://github.com/termux/termux-app) and run `GoHPTS` as a CLI tool there:

```shell
# you need to root your device first
pkg install tsu iproute2
# Android support added in v1.10.2
GOHPTS_RELEASE=v1.10.2; wget -v https://github.com/shadowy-pycoder/go-http-proxy-to-socks/releases/download/$GOHPTS_RELEASE/gohpts-$GOHPTS_RELEASE-android-arm64.tar.gz -O gohpts && tar xvzf gohpts && mv -f gohpts-$GOHPTS_RELEASE-android-arm64 gohpts && ./gohpts -h
# use your phone as router for LAN devices redirecting their traffic to remote socks5 server
sudo ./gohpts -s remote -T 8888 -Tu :8989 -M tproxy -sniff -body -auto -mark 100 -d -arpspoof "fullduplex true;debug false"
```

### YAML configuration

[[Back]](#table-of-contents)

```yaml
transparent_proxy:
  tcp:
    enabled: true
    address: 0.0.0.0:8888
    # number of instances of transparent proxy server (Default: number of CPU cores)
    workers: 1
  udp:
    enabled: true
    address: 0.0.0.0:8889
    # number of instances of transparent UDP proxy server (Default: number of CPU cores)
    workers: 1
  mode: "tproxy" # available modes are "redirect", "tproxy" and "tlocal" (udp requires tproxy or tlocal mode)
  # automatically setup iptables and kernel parameters for transparent proxy (requires elevated privileges)
  auto: true
  # dump iptables rules and other system settings generated by auto setting
  dump_rules: false
  # list of ports to ignore when proxying traffic (Example: [22,80,443,9092])
  ignored_ports: []
  # set mark for each packet sent through transparent proxy (Default: redirect 0, tproxy 100, tlocal 100)
  mark: 100
```

## Traffic sniffing

[[Back]](#table-of-contents)

<p align="center"><img alt="MrGopher" src="resources/mr_gopher_small.png"/>

`GoHPTS` proxy allows one to capture and monitor traffic that goes through the service. This procces is known as `traffic sniffing`, `packet sniffing` or just `sniffing`. In particular, proxy tries to identify whether it is a plain text (HTTP) or TLS traffic, and after identification is done, it parses request/response metadata and writes it to the file or console. In the case of `GoHTPS` proxy a parsed metadata looks like the following (TLS Handshake):

### JSON format

[[Back]](#table-of-contents)

```json
[
  {
    "connection": {
      "tproxy_mode": "redirect",
      "src_local": "127.0.0.1:8888",
      "src_remote": "192.168.0.107:51142",
      "dst_local": "127.0.0.1:56256",
      "dst_remote": "127.0.0.1:1080",
      "original_dst": "216.58.209.206:443"
    }
  },
  {
    "tls_request": {
      "sni": "www.youtube.com",
      "type": "Client hello (1)",
      "version": "TLS 1.2 (0x0303)",
      "session_id": "2670a6779b4346e5e84d46890ad2aaf7a53b08adcfe0c9f6868c2d9882242e39",
      "cipher_suites": [
        "TLS_AES_128_GCM_SHA256 (0x1301)",
        "TLS_CHACHA20_POLY1305_SHA256 (0x1303)",
        "TLS_AES_256_GCM_SHA384 (0x1302)",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c)",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)",
        "TLS_RSA_WITH_AES_128_GCM_SHA256 (0x9c)",
        "TLS_RSA_WITH_AES_256_GCM_SHA384 (0x9d)",
        "TLS_RSA_WITH_AES_128_CBC_SHA (0x2f)",
        "TLS_RSA_WITH_AES_256_CBC_SHA (0x35)"
      ],
      "extensions": [
        "server_name (0)",
        "extended_master_secret (23)",
        "renegotiation_info (65281)",
        "supported_groups (10)",
        "ec_point_formats (11)",
        "session_ticket (35)",
        "application_layer_protocol_negotiation (16)",
        "status_request (5)",
        "delegated_credential (34)",
        "signed_certificate_timestamp (18)",
        "key_share (51)",
        "supported_versions (43)",
        "signature_algorithms (13)",
        "psk_key_exchange_modes (45)",
        "record_size_limit (28)",
        "compress_certificate (27)",
        "encrypted_client_hello (65037)"
      ],
      "alpn": ["h2", "http/1.1"]
    }
  },
  {
    "tls_response": {
      "type": "Server hello (2)",
      "version": "TLS 1.2 (0x0303)",
      "session_id": "2670a6779b4346e5e84d46890ad2aaf7a53b08adcfe0c9f6868c2d9882242e39",
      "cipher_suite": "TLS_AES_128_GCM_SHA256 (0x1301)",
      "extensions": ["key_share (51)", "supported_versions (43)"],
      "supported_version": "TLS 1.3 (0x0304)"
    }
  }
]
```

And HTTP request with curl:

```json
[
  {
    "connection": {
      "tproxy_mode": "redirect",
      "src_local": "127.0.0.1:8888",
      "src_remote": "192.168.0.107:45736",
      "dst_local": "127.0.0.1:37640",
      "dst_remote": "127.0.0.1:1080",
      "original_dst": "96.7.128.198:80"
    }
  },
  {
    "http_request": {
      "host": "example.com",
      "uri": "/",
      "method": "GET",
      "proto": "HTTP/1.1",
      "header": {
        "Accept": ["*/*"],
        "My": ["Header"],
        "User-Agent": ["curl/7.81.0"]
      }
    }
  },
  {
    "http_response": {
      "proto": "HTTP/1.1",
      "status": "200 OK",
      "content-length": 1256,
      "header": {
        "Cache-Control": ["max-age=2880"],
        "Connection": ["keep-alive"],
        "Content-Length": ["1256"],
        "Content-Type": ["text/html"],
        "Date": ["Tue, 17 Jun 2025 14:43:24 GMT"],
        "Etag": ["\"84238dfc8092e5d9c0dac8ef93371a07:1736799080.121134\""],
        "Last-Modified": ["Mon, 13 Jan 2025 20:11:20 GMT"]
      }
    }
  }
]
```

Usage as simple as specifying `-sniff` flag along with regular flags

```shell
gohpts -d -T 8888 -M redirect -sniff -j
```

You can also specify a file to which write sniffed traffic:

```shell
gohpts -sniff -snifflog ~/sniff.log -j
```

### Colored format

[[Back]](#table-of-contents)

You can see the example of colored output in the picture above. In this mode, `GoHPTS` tries to highlight import information such as TLS Handshake, HTTP metadata, something that looks line login/passwords or different types of auth and secret tokens. The output is limited comparing to JSON but way easier to read for humans.

To run `GoHPTS` in this mode you use the following flags:

```shell
gohpts -sniff -body
```

You can combine sniffing with transparent mode:

```shell
./gohpts -T 8888 -M redirect -sniff -body
```

To disable colors add `-nocolor`:

```shell
gohpts -sniff -body -nocolor
```

## HTTP2 and HTTP3 support

[[Back]](#table-of-contents)

`GoHPTS` proxy handles HTTP/1.1, HTTP/2, and HTTP/3 requests using the same server address and TLS certificate. This allows clients to automatically choose the best available protocol without changing configuration. TLS certificate can be obtained in several ways: cloud providers (Google, AWS, Cloudflare), free certificate from Let's Encrypt, or you can create self-signed certificate using `openssl` (Linux/macOS) or `New-SelfSignedCertificate` (Windows).

### Example setup using self-signed certificate

[[Back]](#table-of-contents)

- Create `key.pem` and `cert.pem` files:

  ```shell
  openssl req -x509 -newkey rsa:2048 \
  -keyout key.pem \
  -out cert.pem \
  -sha256 \
  -days 365 \
  -nodes \
  -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=127.0.0.1" \
  -addext "subjectAltName=IP:127.0.0.1"
  ```

- Prepare socks5 server with UDP ASSOCIATE support

  ```shell
  git clone https://github.com/wzshiming/socks5.git && cd socks5
  go build -o socks5_server ./cmd/socks5/main.go
  ./bin/socks5_server -a 0.0.0.0:1080
  ```

- Open another terminal and install `GoHPTS` proxy:

  ```shell
  go install github.com/shadowy-pycoder/go-http-proxy-to-socks/cmd/gohpts@latest
  ```

  You can use other methods described in [Installation](#installation) section.

- Finally:
  1. Create minimal config for your proxy

  ```yaml
  # gohpts_config.yaml
  http_server:
    address: 127.0.0.1:8080
    cert_file: ./cert.pem
    key_file: ./key.pem

  proxy_list:
    - address: 127.0.0.1:1080

  logging:
    debug: true

  sniffing:
    enabled: true
    body: true
  ```

  Run the proxy:

  ```shell
  gohpts -f ./gohpts_config.yaml
  ```

  2. Or if you prefer command line arguments:

  ```shell
  gohpts -l :8080 -s 1080 -c ./cert.pem -k ./key.pem -d -sniff -body
  ```

  You should see something like that:

  ```shell
    [15:20:32] INF SOCKS5 Proxy: 127.0.0.1:1080
    [15:20:32] INF HTTPS Proxy: 127.0.0.1:8080
    [15:20:32] INF HTTP3 Proxy (QUIC): 127.0.0.1:8080
  ```

### Test connection

[[Back]](#table-of-contents)

- For HTTP/2 proxy server you can use `curl`:

  ```shell
    curl -Nvk --http2 --proxy-insecure --proxy-http2 --proxy https://localhost:8080 "https://stream.wikimedia.org/v2/stream/recentchange"
  ```

  Press `Ctrl+C` to stop running stream.

- For HTTP/3 it is different since (at the time of writing) `curl` doesn't support HTTP3 proxy, so I will use my custom client I created for testing purposes.

  Download and install [Simple HTTP3 to SOCKS5 proxy example](https://github.com/shadowy-pycoder/http3-socks-proxy):

  ```shell
  git clone https://github.com/shadowy-pycoder/http3-socks-proxy.git && cd http3-socks-proxy
  make
  ```

  Run the following command:

  ```shell
  ./bin/client -a 127.0.0.1:8080 www.google.com
  ```

  You should see some gibberish resembling HTML page.

  Go to terminal tab with `GoHPTS` proxy and check logs, you should see all your requests there.

### Test connection in a browser

[[Back]](#table-of-contents)

- Create proper self-signed ceritificate for browser:

  ```shell
  git clone https://github.com/shadowy-pycoder/go-http-proxy-to-socks.git
  cd go-http-proxy-to-socks
  cp ./resources/makecert.sh makecert.sh && chmod +x makecert.sh
  ./makecert.sh
  ```

  More information can be found here: [Creating a browser trusted, self signed, SSL certificate](https://medium.com/@tbusser/creating-a-browser-trusted-self-signed-ssl-certificate-2709ce43fd15)

- Add newly created `rootCA.crt` to system trust store:
  1. Debian/Ubuntu:

  ```shell
  sudo cp rootCA.crt /usr/local/share/ca-certificates/rootCA.crt
  sudo update-ca-certificates
  ```

  2. Arch Linux/CachyOS/EndeavourOS:

  ```shell
  sudo trust anchor rootCA.crt
  ```

- Run the proxy using `server.crt` and `server.key`:

  ```shell
  gohpts -l :8080 -s 1080 -c ./server.crt -k ./server.key -d -sniff -body
  ```

- Run the browser and go to any website:

  ```shell
  chromium --proxy-server="https://127.0.0.1:8080"
  ```

## IPv6 support

[[Back]](#table-of-contents)

To enable IPv6 handling just add `-6` flag, for example when using with transparent proxy:

```shell
sudo ./gohpts -T 8888 -M redirect -sniff -body -auto -mark 100 -d -6
```

For this to work, your ISP and remote socks5 proxy should have active IPv6 support, you can visit [https://test-ipv6.com/](https://test-ipv6.com/) to find out you can access IPv6 addresses.
To test proxy in IPv6 mode you can use any Linux VM:

1. On your virtual machine:

```shell
# add your host machine as gateway for VM
export GATEWAY="<host IPv4 address>"
ip route add 0.0.0.0/1 via "$GATEWAY"
ip route add 128.0.0.0/1 via "$GATEWAY"

# add your host machine as gateway IPv6 for VM
export GATEWAY6="<host IPv6 address>"
ip -6 route add ::/1 via "$GATEWAY6" dev eth0
ip -6 route add 8000::/1 via "$GATEWAY6" dev eth0
```

2. On your host:

```shell
# run proxy on your host
sudo ./gohpts -T 8888 -Tu 8889 -M tproxy -sniff -body -auto -d -6
```

3. Visit any website on your virtual machine and see traffic in proxy logs

## ARP spoofing

[[Back]](#table-of-contents)

`GoHPTS` has in-built ARP spoofer that can be used to make all TCP talking devices of your LAN to use proxy server to connect to the Internet.
This is achieved by adding `-arpspoof` flag with couple of parameters, separated by semicolon.

Example:

```shell
ssh remote -D 1080 -Nf
sudo env PATH=$PATH gohpts -d -T 8888 -M tproxy -sniff -body -auto -mark 100 -arpspoof "targets 192.168.10.0/24;fullduplex true;debug true"
```

Proxy will scan for devices in subnet `192.168.10.0/24` and send them ARP packets to pretend to be a gateway, if `fullduplex` is true,
proxy will send ARP packets to gateway as well to make it believe our proxy has each IP on the subnet.

After proxy is stopped with `Ctrl+C`, it will automatically unspoof all targets.

`GoHPTS` can also be used with tools like [Bettercap](https://github.com/bettercap/bettercap) to proxy ARP spoofed traffic.

Run the proxy:

```shell
ssh remote -D 1080 -Nf
sudo env PATH=$PATH gohpts -d -T 8888 -M tproxy -sniff -body -auto -mark 100
```

Run `bettercap` with this command (see [documentation](https://www.bettercap.org/)):

```shell
sudo bettercap -eval "net.probe on;net.recon on;set arp.spoof.fullduplex true;arp.spoof on"
```

Check proxy logs for traffic from other devices from your LAN

For more information about arpspoof options see `gohpts -h` and [https://github.com/shadowy-pycoder/arpspoof](https://github.com/shadowy-pycoder/arpspoof)

## NDP spoofing

[[Back]](#table-of-contents)

`GoHPTS` has in-built functionality to perform NDP spoofing in IPv6 networks with Router Advertisement (RA) and Neighbor Advertisement (NA) packets. It also includes RDNSS option in RA packets to put host as a IPv6 nameserver for affected clients. When combined with transparent proxy mode (TCP/UDP), NDP spoofing allows `gohpts` to proxy traffic for clients in the local networks. As is the case with [ARP spoofing](#arp-spoofing), you can set ndp spoof options with single `-ndpspoof` flag:

Example:

```shell
sudo env PATH=$PATH gohpts -d -T 8888 -M tproxy -sniff -body -auto -mark 100 -ndpspoof "ra true;na true;targets fe80::3a1c:7bff:fe22:91a4;fullduplex false;debug true"
```

For more information about ndpspoof options see `gohpts -h` and [https://github.com/shadowy-pycoder/ndpspoof](https://github.com/shadowy-pycoder/ndpspoof)

Plese note that some options like `rdnss`, `gateway`, `interface` are set automatically by `gohpts` itself to properly function as a proxy.

Since `gohpts` proxies all connections via upstream SOCKS5 server, you need to have a working server with IPv4/IPv6 and TCP/UDP support. Obviously, a remote machine (e.g. VPS) should also have IPv6 connectivity working. Needless to say, the machine on which `gohpts` should be part of network with IPv6 support.

Example setup for NDP spoofing to work correctly:

1. Connect to VPS

```shell
ssh remote@203.0.113.10
```

2. Install dependencies

```shell
GO_VERSION=$(curl 'https://go.dev/VERSION?m=text' | head -n1)
cd ~/Downloads/ && wget https://go.dev/dl/$GO_VERSION.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf $GO_VERSION.linux-amd64.tar.gz
```

3. Setup SOCKS5 server (make sure firewall rules do not block used ports)

```shell
git clone https://github.com/wzshiming/socks5.git && cd socks5
go build -o ./bin/socks5_server ./cmd/socks5/*.go
./bin/socks5_server -a :3000
```

4. Go back to your host machine and install `gohpts` (see [Installation](#installation))

5. Run `gohtps`:

```shell

gohpts -s 203.0.113.10:3000 -T 8888 -Tu 8889 -M tproxy -sniff -body -auto -mark 100 -arpspoof "fullduplex true;debug true" -ndpspoof "ra true;debug true
" -6 -d
```

6. Get another device (phone, tablet, etc) and connect it to the same network. Try to access Internet and check if some traffic appears on your host machine. Check public IP address with some online tools (it should match your VPS address `203.0.113.10` in this case or global IPv6 address)

7. Stop proxy by hitting Ctrl+C

8. Profit!

## DNS spoofing

[[Back]](#table-of-contents)

To enforce DNS filters and spoof targets by changing DNS records, host running `GoHPTS` should become a default gateway for LAN devices. For this to work, just run transparent proxy with udp enabled and also run ARP/NDP spoofing to make targets use your DNS server.

DNS replies created by `GoHPTS` look like normal packets coming from router or trusted DNS servers (Google, Cloudflare), which results in clients updating their cache with what you tell them. Keep in mind, however, that it only works for "standard" unencrypted DNS traffic (`DOT`/`DOH` not filtered or spoofed).

DNS filters and domains for spoofing can be configured in `dns_filter` section of yaml file configuration. All lists accept URLs, file paths and entries similar to those usually found in hosts file, see [https://en.wikipedia.org/wiki/Hosts\_(file)](<https://en.wikipedia.org/wiki/Hosts_(file)>).

Example:

```yaml
# dns filters require udp transparent proxy and arpspoof/ndpspoof
# filters accept hosts like entries (use either links, file paths or just plain comma separated lists
dns_filter:
  enabled: true
  whitelist: ["/tmp/whitelisted_domains.txt", "example.com", "*.google.com"] # ip is optional, domains can start with *. to match all subdomains
  blacklist:
    ["https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"]
  blacklist_all: false # block all non whitelisted domains
  spooflist: ["127.0.0.1 example.com"] # ip address is required here
```

Use cases:

- Ad and tracker blocker for all LAN devices
- Parental control via blocking specific categories of websites
- Block known phishing and malware domains
- Traffic redirection for analysis
- Credential harvesting via redirection
- Traffic hijacking and manipulation (inject ads, scripts, tracking)
- Surveillance and profiling

Mimimal config for this setup:

```yaml
# gohpts_dns_spoof.yaml
proxy_list:
  - address: 127.0.0.1:1080 # point to socks5 server supporting TCP/UDP

sniffing:
  enabled: true
  body: true

transparent_proxy:
  tcp:
    enabled: true
    address: 0.0.0.0:8888
  udp:
    enabled: true
    address: 0.0.0.0:8889
  mode: "tproxy"
  auto: true

arpspoof:
  enabled: true
  settings: "fullduplex 1;debug 1;interval 1s"

dns_filter:
  enabled: true
  whitelist: []
  blacklist: [
      "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    ] # list of domains to filter
  blacklist_all: true
  # all requests for example.com will be redirected to 0.0.0.0 address
  spooflist: ["0.0.0.0 example.com"]
```

Run:

```shell
sudo ./gohpts -f ./gohpts_dns_spoof.yaml
```

More information can be found here: [https://en.wikipedia.org/wiki/DNS_spoofing](https://en.wikipedia.org/wiki/DNS_spoofing)

## Packet Capture

[[Back]](#table-of-contents)

Traffic can be captured into pcap, pcapng or custom txt formats and later analyzed with tools like Wireshark, tcpdump and many others.

First, make sure `GoHPTS` executable has elevated privileges to be able to capture raw packets, you have two options:

- Run `sudo setcap cap_net_raw+ep ~/go/bin/gohpts` one time to give proxy raw traffic access
- Run proxy with `sudo` when you need to specify `-pcap` flag in CLI or `pcap.enabled` in file configuration.

Configure proxy using CLI:

```shell
gohpts -pcap "promisc true;timeout 10s;exts txt,pcap,pcapng"
```

Configuration file:

```yaml
pcap:
  enabled: true
  settings: "promisc true;expr ip proto tcp;snaplen 65535;timeout 10s;packet_count 100;packet_buffer 8192;exts txt,pcap,pcapng"
```

These commands produce three packet capture files with corresponding formats that later can be analyzed by various tools.

For more information about pcap options see `gohpts -h` and [https://github.com/shadowy-pycoder/mshark](https://github.com/shadowy-pycoder/mshark)

## Network Namespaces

[[Back]](#table-of-contents)

By default `GoHPTS` proxy is running within single network namespace but this can be overriden. Listening sockets (e.g. http server or transparent proxy server) and outbound sockets (socks proxy or direct dialer) created by `GoHPTS` can be isolated with Linux/Android [network_namespaces (7)](https://man7.org/linux/man-pages/man7/network_namespaces.7.html). When starting proxy process, users can specify `-in-netns` (listeners) and `-out-netns` (dialers) flags with name or path to network namespace to control in which isolated environment to create sockets. If you want to create either listeners or dialers in the current (default) namespace, just omit the flag. To specify host namespace explicitly you can use path `/proc/1/ns/net` - this allows proxy to correctly identify system nameservers.

`GoHPTS` supports [ip-netns (8)](https://man7.org/linux/man-pages/man8/ip-netns.8.html) convention for providing network configuration via files located in `/etc/netns/NAME/` directory. So, to specify custom nameservers for `ns1` network namespace you do the following:

```shell
sudo mkdir -p /etc/netns/ns1
sudo tee /etc/netns/ns1/resolv.conf << EOF
8.8.8.8
2001:4860:4860:0:0:0:0:8888
EOF
```

If no config is found, Google DNS servers will be used to resolve domain names.

### Playground setup

[[Back]](#table-of-contents)

- Run socks5 server with UDP ASSOCIATE support

  ```shell
  git clone https://github.com/wzshiming/socks5.git && cd socks5
  go build -o socks5_server ./cmd/socks5/main.go
  ./bin/socks5_server -a 0.0.0.0:1080
  ```

- Download and install [Simple HTTP3 to SOCKS5 proxy example](https://github.com/shadowy-pycoder/http3-socks-proxy):

  ```shell
  git clone https://github.com/shadowy-pycoder/http3-socks-proxy.git
  cd http3-socks-proxy
  make
  ```

- Clone the repo and compile

  ```shell
  git clone https://github.com/shadowy-pycoder/go-http-proxy-to-socks.git
  cd go-http-proxy-to-socks
  make
  ```

- Create `key.pem` and `cert.pem` files:

  ```shell
  openssl req -x509 -newkey rsa:2048 \
  -keyout key.pem \
  -out cert.pem \
  -sha256 \
  -days 365 \
  -nodes \
  -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=127.0.0.1" \
  -addext "subjectAltName=IP:127.0.0.1"
  ```

- Create a network namespace `ns1` and configure veth network

  ```shell
  sudo ip netns add ns1
  sudo ip link add dev veth0 type veth peer name veth1 netns ns1
  sudo ip addr add 10.0.0.1/24 dev veth0
  sudo ip -6 addr add fd12:3456:789a::1/64 dev veth0
  sudo ip link set dev veth0 up
  sudo ip netns exec ns1 ip addr add 10.0.0.2/24 dev veth1
  sudo ip netns exec ns1 ip -6 addr add fd12:3456:789a::2/64 dev veth1
  sudo ip netns exec ns1 ip link set dev lo up
  sudo ip netns exec ns1 ip link set dev veth1 up
  ```

- Determine `wlan0` ip address to be able connect to local socks5

  ```shell
  WLAN_IP=$(ip -4 -c=never route get 8.8.8.8 | awk '{print $7}' | tr -d '\n')
  ```

### Usage examples

[[Back]](#table-of-contents)

1. **HTTP proxy - proxy listeners in `ns1` (no default route, no internet access), outbound sockets on host**

   Run proxy:

   ```shell
   sudo ./bin/gohpts -s 0.0.0.0:1080 -l :8083 -6 -d -sniff -body -in-netns ns1
   ```

   Make request via `ns1`

   ```shell
   sudo ip netns exec ns1 curl -Nv --proxy http://127.0.0.1:8083 https://example.com
   ```

   Request should succeed

2. **HTTP2 proxy - proxy listeners in `ns1` (no default route, no internet access), outbound sockets on host**

   Run proxy:

   ```shell
   sudo ./bin/gohpts -s 0.0.0.0:1080 -l :8083 -6 -d -sniff -body -in-netns ns1 -c ./cert.pem -k ./key.pem
   ```

   Make request via `ns1`

   ```shell
   sudo ip netns exec ns1 curl -Nvk --http2 --proxy-insecure --proxy-http2 --proxy https://127.0.0.1:8083 https://example.com
   ```

   Request should succeed

3. **HTTP3 proxy - proxy listeners in `ns1` (no default route, no internet access), outbound sockets on host**

   Run proxy:

   ```shell
   sudo ./bin/gohpts -s 0.0.0.0:1080 -l :8083 -6 -d -sniff -body -in-netns ns1 -c ./cert.pem -k ./key.pem
   ```

   Make request via `ns1`

   ```shell
   sudo ip netns exec ns1 ./http3-socks-proxy/bin/client -a 127.0.0.1:8083 www.google.com
   ```

   Request should succeed

4. **Redirect transparent proxy (`-M redirect`) - proxy listeners in `ns1` (default route, no internet access), outbound sockets on host**

   Run proxy:

   ```shell
   sudo ./bin/gohpts -s 0.0.0.0:1080 -l :8083 -6 -d -sniff -body -in-netns ns1 -nohttp -M redirect -T :8888 -auto
   ```

   Make request via `ns1`

   ```shell
   sudo ip netns exec ns1 curl -Nv https://example.com
   ```

   Request should fail

   Add default route to `ns1`

   ```shell
   sudo ip netns exec ns1 ip route add default via 10.0.0.1
   sudo ip netns exec ns1 ip -6 route add default via fd12:3456:789a::1
   ```

   Try again

   ```shell
   sudo ip netns exec ns1 curl -Nv https://example.com
   ```

   Now request should succeed

5. **HTTP proxy - proxy listeners on host, outbound sockets in `ns1` (default route, internet access)**

   Add NAT rules to allow `ns1` connect to internet via `wlan0`

   ```shell
   sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o wlan0 -j MASQUERADE
   sudo ip6tables -t nat -A POSTROUTING -s fd12:3456:789a::/64 -o wlan0 -j MASQUERADE
   ```

   Run proxy:

   ```
   sudo ./bin/gohpts -s :1080 -l :8083 -6 -d -sniff -body -out-netns ns1 -i wlan0
   ```

   Make request via host

   ```shell
   curl -Nv --proxy http://$WLAN_IP:8083 https://example.com
   ```

   Request should succeed

6. **HTTP3 proxy - proxy listeners on host, outbound sockets in `ns1` (default route, internet access)**

   Run proxy:

   ```
   sudo ./bin/gohpts -s :1080 -l :8083 -6 -d -sniff -body -out-netns ns1 -i wlan0 -c ./cert.pem -k ./key.pem
   ```

   Make request via host

   ```shell
   ./http3-socks-proxy/bin/client -a $WLAN_IP:8083 www.google.com
   ```

   Request should succeed

7. **Redirect transparent proxy - proxy listeners on host, outbound sockets in `ns1` (default route, internet access)**

   Run proxy (`-auto` does not work with local socks5 server for me, so I use remote one):

   ```
   sudo ./bin/gohpts -s <remote> -6 -d -sniff -body -out-netns ns1 -nohttp -M redirect -T :8888 -auto
   ```

   Make request via host

   ```shell
   curl -Nv https://example.com
   ```

   Request should succeed

8. **HTTP proxy - LAN (`ns2` (proxy listeners), `ns3`, `ns4`), outbound sockets in `ns1` (default route, internet access)**

   Create LAN

   ```shell
   sudo ip link add br0 type bridge
   sudo ip addr add 10.0.1.1/24 dev br0
   sudo ip -6 addr add fd12:3456:789b::1/64 dev br0
   sudo ip link set br0 up

   sudo ip netns add ns2
   sudo ip link add veth2 type veth peer name veth3 netns ns2
   sudo ip link set veth2 master br0
   sudo ip link set veth2 up
   sudo ip netns exec ns2 ip addr add 10.0.1.2/24 dev veth3
   sudo ip netns exec ns2 ip -6 addr add fd12:3456:789b::2/64 dev veth3
   sudo ip netns exec ns2 ip link set lo up
   sudo ip netns exec ns2 ip link set veth3 up
   sudo ip netns exec ns2 ip route add default via 10.0.1.1
   sudo ip netns exec ns2 ip -6 route add default via fd12:3456:789b::1

   sudo ip netns add ns3
   sudo ip link add veth4 type veth peer name veth5 netns ns3
   sudo ip link set veth4 master br0
   sudo ip link set veth4 up
   sudo ip netns exec ns3 ip addr add 10.0.1.3/24 dev veth5
   sudo ip netns exec ns3 ip -6 addr add fd12:3456:789b::3/64 dev veth5
   sudo ip netns exec ns3 ip link set lo up
   sudo ip netns exec ns3 ip link set veth5 up
   sudo ip netns exec ns3 ip route add default via 10.0.1.1
   sudo ip netns exec ns3 ip -6 route add default via fd12:3456:789b::1

   sudo ip netns add ns4
   sudo ip link add veth6 type veth peer name veth7 netns ns4
   sudo ip link set veth6 master br0
   sudo ip link set veth6 up
   sudo ip netns exec ns4 ip addr add 10.0.1.4/24 dev veth7
   sudo ip netns exec ns4 ip -6 addr add fd12:3456:789b::4/64 dev veth7
   sudo ip netns exec ns4 ip link set lo up
   sudo ip netns exec ns4 ip link set veth7 up
   sudo ip netns exec ns4 ip route add default via 10.0.1.1
   sudo ip netns exec ns4 ip -6 route add default via fd12:3456:789b::1
   ```

   Run proxy:

   ```
   sudo ./bin/gohpts -s $WLAN_IP:1080 -l 0.0.0.0:8083 -6 -d -sniff -body -in-netns ns2 -out-netns ns1
   ```

   Make requests

   ```shell
   curl -Nv --proxy http://10.0.1.2:8083 http://example.com
   sudo ip netns exec ns2 curl -Nv --proxy http://10.0.1.2:8083 https://example.com
   sudo ip netns exec ns3 curl -Nv --proxy http://10.0.1.2:8083 https://example.com
   sudo ip netns exec ns4 curl -Nv --proxy http://10.0.1.2:8083 https://example.com
   ```

   All requests should succeed

9. **HTTP3 proxy - LAN (`ns2` (proxy listeners), `ns3`, `ns4`), outbound sockets in `ns1` (default route, internet access)**

   Run proxy:

   ```
   sudo ./bin/gohpts -s $WLAN_IP:1080 -l 0.0.0.0:8083 -6 -d -sniff -body -in-netns ns2 -out-netns ns1 -c ./cert.pem -k ./key.pem
   ```

   Make requests

   ```shell
   ./http3-socks-proxy/bin/client -a 10.0.1.2:8083 www.google.com
   sudo ip netns exec ns2 ./http3-socks-proxy/bin/client -a 10.0.1.2:8083 www.google.com
   sudo ip netns exec ns3 ./http3-socks-proxy/bin/client -a 10.0.1.2:8083 www.google.com
   sudo ip netns exec ns4 ./http3-socks-proxy/bin/client -a 10.0.1.2:8083 www.google.com
   ```

   All requests should succeed

10. **Redirect transparent proxy - LAN (`ns2` (proxy listeners), `ns3`, `ns4`), outbound sockets in `ns1` (default route, internet access)**

    Run proxy:

    ```shell
    sudo ./bin/gohpts -s $WLAN_IP:1080 -6 -d -sniff -body -in-netns ns2 -out-netns ns1 -nohttp -M redirect -T :8888 -auto
    ```

    Make requests

    ```shell
    sudo ip netns exec ns2 curl -Nv https://example.com
    ```

    For `ns3` and `ns4` request fails

11. **Transparent proxy with `IP_TRANSPARENT` (arp/ndp spoofing enabled) LAN (`ns2` (proxy listeners), `ns3`, `ns4`), outbound sockets in `ns1` (default route, internet access)**

    Run proxy:

    ```shell
    sudo ./bin/gohpts -s $WLAN_IP:1080 -6 -d -sniff -body -in-netns ns2 -out-netns ns1 -nohttp -M tproxy -T :8888 -auto -arpspoof "fullduplex 1;debug 1;interval 1s" -ndpspoof "ra true;interval 10s;debug 1"
    ```

    Now previous requests on `ns3` and `ns4` should work

    ```
    sudo ip netns exec ns3 curl -Nv https://example.com
    sudo ip netns exec ns4 curl -Nv https://example.com
    ```

12. **HTTP3 proxy - proxy listeners in `ns1`, outbound sockets on host, `-nosocks` flag**

    Run proxy:

    ```shell
    sudo ./bin/gohpts -l 0.0.0.0:8083 -6 -d -sniff -body -in-netns ns1 -c ./cert.pem -k ./key.pem -nosocks
    ```

    Make request

    ```shell
    ./http3-socks-proxy/bin/client -a 10.0.0.2:8083 www.google.com
    ```

    Request should succeed

13. **HTTP3 proxy - proxy listeners on host, outbound sockets in `ns1`, `-nosocks` flag**

    Run proxy:

    ```shell
    sudo ./bin/gohpts -l 0.0.0.0:8083 -6 -d -sniff -body -out-netns ns1 -c ./cert.pem -k ./key.pem -nosocks
    ```

    Make request

    ```shell
    ./http3-socks-proxy/bin/client -a 127.0.0.1:8083 www.google.com
    ```

    Request should fail

    Add rules to `FORWARD` chain

    ```shell
    sudo iptables -A FORWARD -i wlan0 -o veth0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    sudo iptables -A FORWARD -i veth0 -o wlan0 -j ACCEPT

    sudo ip6tables -A FORWARD -i veth0 -j ACCEPT
    sudo ip6tables -A FORWARD -o veth0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    ```

    Make request

    ```shell
    ./http3-socks-proxy/bin/client -a 127.0.0.1:8083 www.google.com
    ```

    Request should succeed

## Links

[[Back]](#table-of-contents)

Learn more about transparent proxies by visiting the following links:

- [Transparent proxy support in Linux Kernel](https://docs.kernel.org/networking/tproxy.html)
- [Transparent proxy tutorial by Gost](https://latest.gost.run/en/tutorials/redirect/)
- [Simple tproxy example](https://github.com/FarFetchd/simple_tproxy_example)
- [Golang TProxy](https://github.com/KatelynHaworth/go-tproxy)
- [Transparent Proxy Implementation using eBPF and Go](https://medium.com/all-things-ebpf/building-a-transparent-proxy-with-ebpf-50a012237e76)
- [https://github.com/heiher/hev-socks5-tproxy](https://github.com/heiher/hev-socks5-tproxy)

  `socks5` proxy with `UDP ASSOCIATE` support:

- [https://github.com/wzshiming/socks5](https://github.com/wzshiming/socks5)
- [https://github.com/things-go/go-socks5](https://github.com/things-go/go-socks5)
- [https://github.com/0990/socks5](https://github.com/0990/socks5)
- [https://github.com/dizda/fast-socks5](https://github.com/dizda/fast-socks5)
- [https://github.com/semigodking/redsocks](https://github.com/semigodking/redsocks)
- [https://github.com/ginuerzh/gost](https://github.com/ginuerzh/gost)

IPv4/IPv6 network security:

- [https://caster0x00.com/legless/](https://caster0x00.com/legless/)
- [https://caster0x00.com/intercept/](https://caster0x00.com/intercept/)
- [https://www.prosec-networks.com/en/blog/ipv6-mitm/](https://www.prosec-networks.com/en/blog/ipv6-mitm/)

## Contributing

[[Back]](#table-of-contents)

Are you a developer?

- Fork the repository
- Create your feature branch: `git switch -c my-new-feature`
- Commit your changes: `git commit -am 'Add some feature'`
- Push to the branch: `git push origin my-new-feature`
- Submit a pull request

## License

[[Back]](#table-of-contents)

GPLv3
