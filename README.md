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
  Supports `strict`, `dynamic`, `random` chains of SOCKS5 proxy

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

- **Lightweight and Fast**  
  Designed with minimal overhead and efficient request handling.

- **Cross-Platform**  
  Compatible with all major operating systems.

## Installation

You can download the binary for your platform from [Releases](https://github.com/shadowy-pycoder/go-http-proxy-to-socks/releases) page.

Example:

```shell
HPTS_RELEASE=v1.5.0; wget -v https://github.com/shadowy-pycoder/go-http-proxy-to-socks/releases/download/$HPTS_RELEASE/gohpts-$HPTS_RELEASE-linux-amd64.tar.gz -O gohpts && tar xvzf gohpts && mv -f gohpts-$HPTS_RELEASE-linux-amd64 gohpts && ./gohpts -h
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

GoHPTS (HTTP Proxy to SOCKS5) by shadowy-pycoder
GitHub: https://github.com/shadowy-pycoder/go-http-proxy-to-socks

Usage: gohpts [OPTIONS]
Options:
  -h    Show this help message and exit.
  -c string
        Path to certificate PEM encoded file
  -d    Show logs in DEBUG mode
  -f string
        Path to proxychain YAML configuration file
  -j    Show logs in JSON format
  -k string
        Path to private key PEM encoded file
  -l value
        Address of HTTP proxy server (Default: localhost:8080)
  -p    Password for SOCKS5 proxy (not echoed to terminal)
  -s value
        Address of SOCKS5 proxy server (Default: localhost:1080)
  -u string
        User for SOCKS5 proxy
  -v    print version
```

## Example

```shell
gohpts -s 1080 -l 8080 -d -j
```

Output:

```shell
{"level":"info","time":"2025-05-28T06:15:18+00:00","message":"SOCKS5 Proxy: :1080"}
{"level":"info","time":"2025-05-28T06:15:18+00:00","message":"HTTP Proxy: :8080"}
{"level":"debug","time":"2025-05-28T06:15:22+00:00","message":"HTTP/1.1 - CONNECT - www.google.com:443"}
```

Specify username and password fo SOCKS5 proxy server:

```shell
gohpts -s 1080 -l 8080 -d -j -u user -p
SOCKS5 Password: #you will be prompted for password input here
```

Run http proxy over TLS connection

```shell
gohpts -s 1080 -l 8080 -c "path/to/certificate" -k "path/to/private/key"
```

Run http proxy in SOCKS5 proxy chain mode

```shell
gohpts -f "path/to/proxychain/config" -d
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

# round_robin - Not supported

chain:
  type: strict # dynamic, strict, random
  length: 2 # maximum number of proxy in a chain (works only for random chain)
proxy_list:
  - address: 127.0.0.1:1080
    username: username # username and password are optional
    password: password
  - address: 127.0.0.1:1081
  - address: :1082 # empty host means localhost
```

To learn more about proxy chains visit [Proxychains Github](https://github.com/rofl0r/proxychains-ng)

## License

MIT
