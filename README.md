# GoHPTS - HTTP(S) proxy to SOCKS5 proxy (chain) written in Go

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Reference](https://pkg.go.dev/badge/github.com/shadowy-pycoder/go-http-proxy-to-socks.svg)](https://pkg.go.dev/github.com/shadowy-pycoder/go-http-proxy-to-socks)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/shadowy-pycoder/go-http-proxy-to-socks)
[![Go Report Card](https://goreportcard.com/badge/github.com/shadowy-pycoder/go-http-proxy-to-socks)](https://goreportcard.com/report/github.com/shadowy-pycoder/go-http-proxy-to-socks)
![GitHub Release](https://img.shields.io/github/v/release/shadowy-pycoder/go-http-proxy-to-socks)
![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/shadowy-pycoder/go-http-proxy-to-socks/total)

## Introduction

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

- **Proxy Chain functionality**  
  Supports `strict`, `dynamic`, `random`, `round_robin` chains of SOCKS5 proxy

- **Transparent proxy**  
  Supports `redirect` (SO_ORIGINAL_DST) and `tproxy` (IP_TRANSPARENT) modes

- **DNS Leak Protection**  
  DNS resolution occurs on SOCKS5 server side.

- **CONNECT Method Support**  
  Supports HTTP CONNECT tunneling, enabling HTTPS and other TCP-based protocols.

- **Trailer Headers Support**  
  Handles HTTP trailer headers

- **Chunked Transfer Encoding**  
  Handles chunked and streaming responses

- **SOCKS5 Authentication Support**  
  Supports username/password authentication for SOCKS5 proxies.

- **HTTP Authentication Support**  
  Supports username/password authentication for HTTP proxy server.

- **Lightweight and Fast**  
  Designed with minimal overhead and efficient request handling.

- **Cross-Platform**  
  Compatible with all major operating systems.

## Installation

You can download the binary for your platform from [Releases](https://github.com/shadowy-pycoder/go-http-proxy-to-socks/releases) page.

Example:

```shell
HPTS_RELEASE=v1.6.0; wget -v https://github.com/shadowy-pycoder/go-http-proxy-to-socks/releases/download/$HPTS_RELEASE/gohpts-$HPTS_RELEASE-linux-amd64.tar.gz -O gohpts && tar xvzf gohpts && mv -f gohpts-$HPTS_RELEASE-linux-amd64 gohpts && ./gohpts -h
```

Alternatively, you can install it using `go install` command (requires Go [1.24](https://go.dev/doc/install) or later):

```shell
CGO_ENABLED=0 go install -ldflags "-s -w" -trimpath github.com/shadowy-pycoder/go-http-proxy-to-socks/cmd/gohpts@latest
```

This will install the `gohpts` binary to your `$GOPATH/bin` directory.

Another alternative is to build from source:

```shell
git clone https://github.com/shadowy-pycoder/go-http-proxy-to-socks.git
cd go-http-proxy-to-socks
make build
./bin/gohpts
```

## Usage

```shell
gohpts -h
    _____       _    _ _____ _______ _____
  / ____|     | |  | |  __ \__   __/ ____|
 | |  __  ___ | |__| | |__) | | | | (___
 | | |_ |/ _ \|  __  |  ___/  | |  \___ \
 | |__| | (_) | |  | | |      | |  ____) |
  \_____|\___/|_|  |_|_|      |_| |_____/

GoHPTS (HTTP(S) Proxy to SOCKS5 proxy) by shadowy-pycoder
GitHub: https://github.com/shadowy-pycoder/go-http-proxy-to-socks

Usage: gohpts [OPTIONS]
Options:
  -h    Show this help message and exit.
  -M value
    	Transparent proxy mode: [redirect tproxy]
  -T string
    	Address of transparent proxy server (no HTTP)
  -U string
    	User for HTTP proxy (basic auth). This flag invokes prompt for password (not echoed to terminal)
  -c string
    	Path to certificate PEM encoded file
  -d	Show logs in DEBUG mode
  -f string
    	Path to server configuration file in YAML format
  -j	Show logs in JSON format
  -k string
    	Path to private key PEM encoded file
  -l string
    	Address of HTTP proxy server (default "127.0.0.1:8080")
  -s string
    	Address of SOCKS5 proxy server (default "127.0.0.1:1080")
  -t string
    	Address of transparent proxy server (it starts along with HTTP proxy server)
  -u string
    	User for SOCKS5 proxy authentication. This flag invokes prompt for password (not echoed to terminal)
  -v	print version
```

## Example

### Configuration via CLI flags

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

### Configuration via YAML file

Run http proxy in SOCKS5 proxy chain mode (specify server settings via YAML configuration file)

```shell
gohpts -f "path/to/proxychain/config" -d -j
```

Config example:

```yaml
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

chain:
  type: strict # dynamic, strict, random, round_robin
  length: 2 # maximum number of proxy in a chain (works only for random chain and round_robin chain)
proxy_list:
  - address: 127.0.0.1:1080
    username: username # username and password are optional
    password: password
  - address: 127.0.0.1:1081
  - address: :1082 # empty host means localhost
server:
  address: 127.0.0.1:8080 # the only required field in this section
  # these are for adding basic authentication
  username: username
  password: password
  # comment out these to use HTTP instead of HTTPS
  cert_file: ~/local.crt
  key_file: ~/local.key
```

To learn more about proxy chains visit [Proxychains Github](https://github.com/rofl0r/proxychains-ng)

## Transparent proxy

> Also known as an `intercepting proxy`, `inline proxy`, or `forced proxy`, a transparent proxy intercepts normal application layer communication without requiring any special client configuration. Clients need not be aware of the existence of the proxy. A transparent proxy is normally located between the client and the Internet, with the proxy performing some of the functions of a gateway or router
>
> -- _From [Wiki](https://en.wikipedia.org/wiki/Proxy_server)_

This functionality available only on Linux systems and requires additional setup (`iptables`, ip route, etc)

`-T address` flag specifies the address of transparent proxy server (`GoHPTS` will be running without HTTP server).

`-t address` flag specifies the address of transparent proxy server (other functionality stays the same).

In other words, `-T` spins up a single server, but `-t` two servers, `http` and `tcp`.

There are two modes `redirect` and `tproxy` that can be specified with `-M` flag

## `redirect` (Transparent proxy via NAT)

In this mode proxying happens with `iptables` `nat` table and `REDIRECT` target. Host of incoming packet changes to the address of running `redirect` transparent proxy, but it also contains original destination that can be retrieved with `getsockopt(SO_ORIGINAL_DST)`

To run `GoHPTS` in this mode you use `-t` or `-T` flags with `-M redirect`

### Example

```shell
# run the proxy
gohpts -s 1080 -t 1090 -M redirect -d
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

# set no redirection rules for local, http proxy, ssh and redirect procy itself
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

## `tproxy` (Transparent proxy with IP_TRANSPARENT socket option)

In this mode proxying happens with `iptables` `mangle` table and `TPROXY` target. Transparent proxy sees destination address as is, it is not being rewrited by the kernel. For this to work the proxy binds with socket option `IP_TRANSPARENT`, `iptables` intercepts traffic using TPROXY target, routing rules tell marked packets to go to the local proxy without changing their original destination.

This mode requires elevated privileges to run `GoHPTS`. You can do that by running the follwing command:

```shell
sudo setcap 'cap_net_admin+ep' ~/go/bin/gohpts
```

To run `GoHPTS` in this mode you use `-t` or `-T` flags with `-M tproxy`

### Example

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
ip netns exec ns-client ip route add default via 10.0.0.1
sysctl -w net.ipv4.ip_forward=1

iptables -t mangle -A PREROUTING -i veth1 -p tcp -j TPROXY --on-port 1090 --tproxy-mark 0x1/0x1

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
ip link del veth1
```

Learn more about transparent proxies by visiting the following links:

- [Transparent proxy support in Linux Kernel](https://docs.kernel.org/networking/tproxy.html)
- [Transparent proxy tutorial by Gost](https://latest.gost.run/en/tutorials/redirect/)
- [Simple tproxy example](https://github.com/FarFetchd/simple_tproxy_example)
- [Golang TProxy](https://github.com/KatelynHaworth/go-tproxy)
- [Transparent Proxy Implementation using eBPF and Go](https://medium.com/all-things-ebpf/building-a-transparent-proxy-with-ebpf-50a012237e76)

## License

MIT
