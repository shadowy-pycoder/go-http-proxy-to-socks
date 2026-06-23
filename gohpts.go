package gohpts

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"math/rand"
	"net"
	"net/http"
	"net/http/pprof"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog"
	"github.com/shadowy-pycoder/arpspoof"
	"github.com/shadowy-pycoder/mshark"
	"github.com/shadowy-pycoder/mshark/layers"
	"github.com/shadowy-pycoder/mshark/mpcap"
	"github.com/shadowy-pycoder/mshark/mpcapng"
	"github.com/shadowy-pycoder/mshark/network"
	"github.com/shadowy-pycoder/ndpspoof"
	"github.com/vishvananda/netns"
)

const (
	App                      string        = "gohpts"
	addrSOCKS                string        = "127.0.0.1:1080"
	addrHTTP                 string        = "127.0.0.1:8080"
	readTimeout              time.Duration = 30 * time.Second
	writeTimeout             time.Duration = 30 * time.Second
	timeout                  time.Duration = 10 * time.Second
	shutdownTimeout          time.Duration = 30 * time.Second
	hopTimeout               time.Duration = 3 * time.Second
	flushTimeout             time.Duration = 10 * time.Millisecond
	availProxyUpdateInterval time.Duration = 30 * time.Second
	maxIdleTimeout           time.Duration = 30 * time.Second
	keepAlivePeriod          time.Duration = 10 * time.Second
	maxIncomingStreams       int64         = 1000
	maxIncomingUniStreams    int64         = 100
	handshakeIdleTimeout     time.Duration = 10 * time.Second
	rrIndexMax               uint32        = 1_000_000
	maxBodySize              int64         = 2 << 15
)

var (
	supportedChainTypes  = []string{"strict", "dynamic", "random", "round_robin"}
	SupportedTProxyModes = []string{"redirect", "tproxy"}
	SupportedTProxyOS    = []string{"linux", "android"}
	errInvalidWrite      = errors.New("invalid write result")
)

type logWriter struct {
	file    *os.File
	nocolor bool
}

func (w logWriter) Write(bytes []byte) (int, error) {
	ts := colorizeTimestamp(time.Now(), w.nocolor)
	msg := colorizeErrMessage(string(bytes), w.nocolor)
	return fmt.Fprintf(w.file, "%s %s %s", ts, colorizeErr(w.nocolor), msg)
}

type jsonLogWriter struct {
	file *os.File
}

func (writer jsonLogWriter) Write(bytes []byte) (int, error) {
	return fmt.Fprintf(writer.file, "{\"level\":\"error\",\"time\":\"%s\",\"message\":\"%s\"}\n",
		time.Now().Format(time.RFC3339), strings.TrimRight(string(bytes), "\n"))
}

type httpClienter interface {
	io.Closer
	Do(req *http.Request) (*http.Response, error)
}

var (
	_ httpClienter = &httpClient{}
	_ httpClienter = &http3Client{}
)

func newHTTPClient(dialer contextDialer) *httpClient {
	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext:     dialer.DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &httpClient{Client: c}
}

type httpClient struct {
	*http.Client
}

func (c *httpClient) Close() error {
	if c == nil {
		return nil
	}
	c.CloseIdleConnections()
	return nil
}

func newHTTP3Client(dial func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error)) *http3Client {
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{http3.NextProtoH3},
		},
		Dial: dial,
	}
	c := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &http3Client{Client: c, tr: tr}
}

type http3Client struct {
	*http.Client
	tr *http3.Transport
}

func (c *http3Client) Close() error {
	if c == nil {
		return nil
	}
	c.CloseIdleConnections()
	return c.tr.Close()
}

type chainedDialer struct {
	dialer contextDialer
	err    error
}

type Proxy struct {
	httpEnabled bool
	// httpServerAddr for HTTP/1.2, HTTP/2 (tcp) and HTTP/3 (udp) servers
	httpServerAddr string
	// HTTP server for HTTP/1.1 and HTTP/2 handling
	httpServer *http.Server
	// http client with socks5 proxy dialer
	httpClient *httpClient
	// http client for local connections
	httpLocalClient *httpClient
	// HTTP server for HTTP/3 handling
	http3Server *http3.Server
	// http3 client with socks5 proxy dialer
	http3Client *http3Client
	// http3 client for local connections
	http3LocalClient *http3Client
	// enable upstream socks proxy
	socksEnabled bool
	// enable socks4/socks4a
	socks4enabled bool
	// socks protocol version for logging
	socksProto string
	// socks5 dialer with UDP ASSOCIATE support or socks4/socks4a TCP only
	sockDialer contextDialer
	// contextDialer with timeout (used for local connections and as a forward dialer in socks5 proxy)
	baseDialer contextDialer
	// credetials used in HTTP BasicAuth
	user, pass string

	// allows running HTTP server over TLS (required for HTTP/2 and HTTP/3)
	certFile, keyFile string

	// proxychain
	proxychain   ProxyChain
	proxylist    []ProxyEntry
	rrIndex      atomic.Uint32
	rrIndexReset uint32

	mu             sync.RWMutex // guards availProxyList and chDialer
	availProxyList []ProxyEntry
	chDialer       *chainedDialer

	// logging

	logger, snifflogger *zerolog.Logger
	// enables sniffing
	sniff bool
	//  capture request and response body in HTTP request
	body bool
	// disable colorized output
	nocolor bool
	// logs in JSON format
	json bool
	// enable debug output
	debug bool

	// address of a server with profiling data
	pprofAddr   string
	pprofServer *http.Server

	// network interface proxy bound to, also used in spoofing tools
	//
	// if not specified, servers bound to loopback address
	iface *net.Interface
	// user specified interface name
	ifacename string
	prefix    *netip.Prefix
	prefix6   *netip.Prefix

	// network types ("tcp", "udp" when IPv6 is enabled, "tcp4" and "udp4" otherwise)
	tcp, udp    string
	ipv6enabled bool

	// address of tcp transparent proxy
	tproxyAddr string
	// address of udp transparent proxy
	tproxyAddrUDP string
	// tproxy or redirect
	tproxyMode string
	// number of tcp transparent proxy servers
	tproxyWorkers uint
	// number of udp transparent proxy servers
	tproxyUDPWorkers uint
	// indicates whether auto configuaration is enabled
	auto bool
	// used to indicate proxy outbound traffic
	mark         uint
	ignoredPorts string
	// dump iptables rules and kernel parameters generated by auto
	dumpRules bool
	dump      strings.Builder

	// spoofing
	arpSpoofConf string
	arpspoofer   *arpspoof.ARPSpoofer
	ndpSpoofConf string
	ndpspoofer   *ndpspoof.NDPSpoofer
	raEnabled    bool
	gwDNS        *net.UDPAddr
	gwDNS6       *net.UDPAddr
	hostDNS6     *net.UDPAddr

	// dns filtering/spoofing
	dnsFilterConf *DNSFilterLists
	filter        *dnsFilter

	// packet capture
	pcapConf string

	// network namespaces
	nsEnabled       bool
	inNS            *netns.NsHandle
	inNSPathOrName  string
	outNS           *netns.NsHandle
	outNSPathOrName string
	outDNS          *net.UDPAddr
	outDNS6         *net.UDPAddr

	// connection graceful shutdown channel
	closeConn chan bool
}

func New(conf *Config) (*Proxy, error) {
	if err := parseConfig(conf); err != nil {
		return nil, fmt.Errorf("failed parsing configuration file: %v", err)
	}

	var logger, snifflogger zerolog.Logger
	var p Proxy
	logfile := os.Stdout
	var snifflog *os.File
	var err error

	// setting namespace
	if conf.InNetNS != "" || conf.OutNetNS != "" {
		if conf.InNetNS != "" {
			var inNS netns.NsHandle
			if strings.HasPrefix(conf.InNetNS, "/") {
				inNS, err = netns.GetFromPath(conf.InNetNS)
			} else {
				inNS, err = netns.GetFromName(conf.InNetNS)
			}
			if err != nil {
				return nil, fmt.Errorf("failed getting namespace %s: %v", conf.InNetNS, err)
			}
			p.inNS = &inNS
			p.inNSPathOrName = conf.InNetNS
		} else { // defaults to host namespace
			currentNs, err := netns.Get()
			if err != nil {
				return nil, fmt.Errorf("failed getting current namespace: %v", err)
			}
			p.inNS = &currentNs
		}
		if conf.OutNetNS != "" {
			var outNS netns.NsHandle
			if strings.HasPrefix(conf.OutNetNS, "/") {
				outNS, err = netns.GetFromPath(conf.OutNetNS)
			} else {
				outNS, err = netns.GetFromName(conf.OutNetNS)
			}
			if err != nil {
				return nil, fmt.Errorf("failed getting namespace %s: %v", conf.OutNetNS, err)
			}
			p.outNS = &outNS
			p.outNSPathOrName = conf.OutNetNS
		} else {
			currentNs, err := netns.Get()
			if err != nil {
				return nil, fmt.Errorf("failed getting current namespace: %v", err)
			}
			p.outNS = &currentNs
		}
		p.nsEnabled = true
	}

	// misc stuff
	p.auto = conf.Auto
	if p.auto {
		if os.Geteuid() != 0 {
			return nil, fmt.Errorf("auto configuration requires root privileges")
		}
	}

	p.dumpRules = conf.Dump
	if p.dumpRules && !p.auto {
		return nil, fmt.Errorf("dumping rules is only possible in auto configuration")
	}
	p.dump.WriteString("#!/usr/bin/env bash\n\nset -ex\n")

	// setup loggers
	p.sniff = conf.Sniff
	p.body = conf.Body
	p.json = conf.JSON
	p.nocolor = conf.JSON || conf.NoColor
	p.debug = conf.Debug

	if conf.LogFilePath != "" {
		f, err := os.OpenFile(conf.LogFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %v", err)
		}
		logfile = f
	}

	if conf.SniffLogFile != "" && conf.SniffLogFile != conf.LogFilePath {
		f, err := os.OpenFile(conf.SniffLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, fmt.Errorf("failed to open sniff log file: %v", err)
		}
		snifflog = f
	} else {
		snifflog = logfile
	}

	if p.json {
		log.SetFlags(0)
		jsonWriter := jsonLogWriter{file: logfile}
		log.SetOutput(jsonWriter)
		logger = zerolog.New(logfile).With().Timestamp().Logger()
		snifflogger = zerolog.New(snifflog).With().Timestamp().Logger()
	} else {
		log.SetFlags(0)
		logWriter := logWriter{file: logfile, nocolor: p.nocolor}
		log.SetOutput(logWriter)
		output := zerolog.ConsoleWriter{Out: logfile, NoColor: p.nocolor}

		output.FormatTimestamp = func(i any) string {
			ts, _ := time.Parse(time.RFC3339, i.(string))
			return colorizeTimestamp(ts, p.nocolor)
		}
		output.FormatMessage = func(i any) string {
			if i == nil || i == "" {
				return ""
			}
			return colorizeLogMessage(i.(string), p.nocolor)
		}

		output.FormatErrFieldName = func(i any) string {
			return fmt.Sprintf("%s", i)
		}

		output.FormatErrFieldValue = func(i any) string {
			s := i.(string)
			return colorizeErrMessage(s, p.nocolor)
		}
		logger = zerolog.New(output).With().Timestamp().Logger()
		sniffoutput := zerolog.ConsoleWriter{Out: snifflog, TimeFormat: time.RFC3339, NoColor: p.nocolor, PartsExclude: []string{"level"}}
		sniffoutput.FormatTimestamp = func(i any) string {
			ts, _ := time.Parse(time.RFC3339, i.(string))
			return colorizeTimestamp(ts, p.nocolor)
		}
		sniffoutput.FormatMessage = func(i any) string {
			if i == nil || i == "" {
				return ""
			}
			return fmt.Sprintf("%s", i)
		}
		sniffoutput.FormatErrFieldName = func(i any) string {
			return fmt.Sprintf("%s", i)
		}

		sniffoutput.FormatErrFieldValue = func(i any) string {
			return colorizeErrMessage(i.(string), p.nocolor)
		}
		snifflogger = zerolog.New(sniffoutput).With().Timestamp().Logger()
	}
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	lvl := zerolog.InfoLevel
	if p.debug {
		lvl = zerolog.DebugLevel
	}
	// the only way I found to make debug level independent between loggers
	l := logger.Level(lvl)
	sl := snifflogger.Level(lvl)
	p.logger = &l
	p.snifflogger = &sl

	// enable ipv6
	if conf.IPv6Enabled {
		p.tcp = "tcp"
		p.udp = "udp"
		p.ipv6enabled = true
	} else {
		p.tcp = "tcp4"
		p.udp = "udp4"
		p.ipv6enabled = false
	}

	// set socks4 flag
	p.socks4enabled = conf.SOCKS4Enabled
	if p.socks4enabled {
		p.socksProto = "socks4"
	} else {
		p.socksProto = "socks5"
	}

	// transparent proxy setup
	if conf.TProxyMode != "" && (conf.TProxy != "" || conf.TProxyUDP != "") {
		p.tproxyMode = conf.TProxyMode
		if !slices.Contains(SupportedTProxyModes, p.tproxyMode) {
			return nil, fmt.Errorf("unknown transparent proxy mode: %s", p.tproxyMode)
		}
		// check addresses for transparent proxy
		if conf.TProxy != "" {
			var tproxyAddr netip.AddrPort
			tproxyAddr, err = network.ParseAddrPort(conf.TProxy, "0.0.0.0")
			if err != nil {
				return nil, err
			}
			p.tproxyAddr = tproxyAddr.String()
		}
		if conf.TProxyUDP != "" {
			if p.tproxyMode != "tproxy" {
				return nil, fmt.Errorf("[%s] transparent UDP server only supports tproxy mode", conf.TProxyMode)
			}
			if p.socks4enabled {
				return nil, fmt.Errorf("[%s] transparent UDP server requires socks5 enabled", conf.TProxyMode)
			}
			var tproxyAddrUDP netip.AddrPort
			tproxyAddrUDP, err = network.ParseAddrPort(conf.TProxyUDP, "0.0.0.0")
			if err != nil {
				return nil, err
			}
			p.tproxyAddrUDP = tproxyAddrUDP.String()
		}

		// calculate number of server instances
		p.tproxyWorkers = conf.TProxyWorkers
		if p.tproxyWorkers == 0 && slices.Contains(SupportedTProxyOS, runtime.GOOS) {
			p.tproxyWorkers = uint(runtime.NumCPU())
		}
		p.tproxyUDPWorkers = conf.TProxyUDPWorkers
		if p.tproxyUDPWorkers == 0 && slices.Contains(SupportedTProxyOS, runtime.GOOS) {
			p.tproxyUDPWorkers = uint(runtime.NumCPU())
		}

		p.mark = conf.Mark
		if p.mark > 0xFFFFFFFF {
			return nil, fmt.Errorf("option SO_MARK is out of range")
		}
		if p.mark == 0 && p.tproxyMode == "tproxy" {
			p.mark = 100
		}

		if conf.IgnoredPorts != "" {
			if !p.auto {
				return nil, fmt.Errorf("ignoring ports is only possible in auto configuration")
			}
			if !portsPattern.MatchString(conf.IgnoredPorts) {
				return nil, fmt.Errorf("ignored ports must be a comma separated list of port numbers")
			}
			p.ignoredPorts = conf.IgnoredPorts
		}
	}

	// interface
	p.ifacename = conf.Interface

	// set pprof address
	p.pprofAddr = conf.AddrPprof

	// set http address and certificates
	p.httpEnabled = !conf.NoHTTP
	if p.httpEnabled {
		p.httpServerAddr = conf.AddrHTTP
		if conf.CertFile != "" {
			p.certFile = expandPath(conf.CertFile)
			if _, err := os.Stat(p.certFile); err != nil {
				return nil, err
			}
		}
		if conf.KeyFile != "" {
			p.keyFile = expandPath(conf.KeyFile)
			if _, err := os.Stat(p.keyFile); err != nil {
				return nil, err
			}
		}
		p.user = conf.ServerUser
		p.pass = conf.ServerPass
	}

	// set proxy chain
	p.socksEnabled = !conf.NoSOCKS
	if p.socksEnabled {
		p.proxychain = conf.SocksProxyChain
		p.proxylist = conf.SocksProxy
		if p.proxychain.Enabled {
			chainType := p.proxychain.Type
			if !slices.Contains(supportedChainTypes, chainType) {
				return nil, fmt.Errorf("chain type `%s` is not supported", chainType)
			}
			p.rrIndexReset = rrIndexMax
		}
	}

	p.arpSpoofConf = conf.ARPSpoof
	p.ndpSpoofConf = conf.NDPSpoof
	p.dnsFilterConf = &conf.DNSFilter
	p.pcapConf = conf.Pcap
	return &p, nil
}

func (p *Proxy) Run() error {
	var currentNs netns.NsHandle
	var err error
	if p.nsEnabled {
		runtime.LockOSThread()
		if currentNs, err = netns.Get(); err != nil {
			return fmt.Errorf("failed getting current namespace: %v", err)
		}
		if err = netns.Set(*p.inNS); err != nil {
			if errors.Is(err, os.ErrPermission) {
				return fmt.Errorf("permission denied (try setting CAP_SYS_ADMIN and CAP_NET_RAW capabilities): %v", err)
			}
			return fmt.Errorf("failed setting namespace: %v", err)
		}
	}
	// getting interface
	bindToLocalhost := true
	if p.ifacename != "" {
		p.logger.Debug().Msgf("Configuring %s interface...", p.ifacename)
		p.iface, err = net.InterfaceByName(p.ifacename)
		if err != nil {
			if ifIdx, err := strconv.Atoi(p.ifacename); err == nil {
				p.iface, err = net.InterfaceByIndex(ifIdx)
				if err != nil {
					p.logger.Warn().Err(err).Msgf("Failed binding to %s, using default interface", p.ifacename)
				}
			} else {
				p.logger.Warn().Msgf("Failed binding to %s, using default interface", p.ifacename)
			}
		}
		if p.iface != nil {
			bindToLocalhost = false
		}
	}
	if slices.Contains(SupportedTProxyOS, runtime.GOOS) {
		// TODO: add support for non linux systems in network module
		if bindToLocalhost {
			p.logger.Debug().Msg("Configuring default interface...")
			// getting default interface
			p.iface, err = network.GetDefaultInterface()
			if err != nil {
				p.iface, err = network.GetDefaultInterfaceFromRoute()
				if err != nil {
					p.iface, err = network.GetDefaultInterfaceFromRouteIPv6()
					if err != nil {
						p.logger.Warn().Msg("failed getting default network interface, trying detect from route")
						p.iface, err = network.GetFirstAvailableInterfaceFromRoute()
						if err != nil {
							return fmt.Errorf("failed getting default network interface")
						}
					}
				}
			}
		}
		if p.auto {
			// getting prefixes
			p.logger.Debug().Msg("Configuring network prefixes...")
			prefix, err := network.GetIPv4PrefixFromInterface(p.iface)
			if err != nil {
				p.logger.Warn().Err(err).Msgf("Failed getting prefix for %s", p.iface.Name)
			} else {
				p.prefix = &prefix
			}
			if p.ipv6enabled {
				prefix6, err := network.GetIPv6GlobalUnicastPrefixFromInterface(p.iface)
				if err != nil {
					p.logger.Warn().Err(err).Msgf("Failed getting IPv6 prefix for %s", p.iface.Name)
				} else {
					p.prefix6 = &prefix6
				}
			}
		}
	}

	// getting address from interface
	p.logger.Debug().Msg("Configuring interface address...")
	ifaceAddr, err := getAddressFromInterface(p.iface, p.ipv6enabled, bindToLocalhost)
	if err != nil {
		return err
	}

	// configure base dialer
	p.logger.Debug().Msg("Configuring base dialer...")
	if p.nsEnabled {
		p.logger.Debug().Msg("Configuring default interface for outbound namespace...")
		var iface *net.Interface
		if p.outNS.Equal(*p.inNS) {
			iface = p.iface
		} else {
			if err = netns.Set(*p.outNS); err != nil {
				return fmt.Errorf("failed setting namespace: %v", err)
			}
			iface, err = network.GetDefaultInterface()
			if err != nil {
				iface, err = network.GetDefaultInterfaceFromRoute()
				if err != nil {
					iface, err = network.GetDefaultInterfaceFromRouteIPv6()
					if err != nil {
						p.logger.Warn().Msg("failed getting default network interface for outbound namespace, trying detect from route")
						iface, err = network.GetFirstAvailableInterfaceFromRoute()
						if err != nil {
							return fmt.Errorf("failed getting default network interface for outbound namespace")
						}
					}
				}
			}
			if err = netns.Set(*p.inNS); err != nil {
				return fmt.Errorf("failed setting namespace: %v", err)
			}
		}
		p.logger.Debug().Msg("Configuring DNS IPv4 (netns)...")
		p.outDNS = network.GetIPv4ResolverFromNetworkNamespace(p.outNSPathOrName)
		p.logger.Debug().Msg("Configuring DNS IPv6 (netns)...")
		p.outDNS6 = network.GetIPv6ResolverFromNetworkNamespace(iface, p.outNSPathOrName)
		outNSDNS := p.outDNS
		if p.ipv6enabled {
			outNSDNS = p.outDNS6
		}
		p.baseDialer = getNSDialer(p.outNS, timeout, p.mark, outNSDNS)
	} else {
		p.baseDialer = getBaseDialer(timeout, p.mark)
	}

	// pprof address configuration
	if p.pprofAddr != "" {
		p.logger.Debug().Msg("Configuring PPROF server address...")
		parsedAddrPprof, err := network.ParseAddrPort(p.pprofAddr, ifaceAddr)
		if err != nil {
			return err
		}
		p.pprofAddr = parsedAddrPprof.String()
		if !bindToLocalhost {
			p.pprofAddr = netip.AddrPortFrom(netip.MustParseAddr(ifaceAddr), parsedAddrPprof.Port()).String()
		}
		p.logger.Debug().Msg("Configuring PPROF server...")
		sm := http.NewServeMux()
		sm.HandleFunc("/debug/pprof/", pprof.Index)
		sm.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		sm.HandleFunc("/debug/pprof/profile", pprof.Profile)
		sm.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		sm.HandleFunc("/debug/pprof/trace", pprof.Trace)
		p.pprofServer = &http.Server{Handler: sm}
	}

	// configure socks addresses
	var sockAddr string
	if p.socksEnabled {
		if p.proxychain.Enabled {
			p.logger.Debug().Msgf("Configuring %s proxy chain...", p.socksProto)
			p.availProxyList = make([]ProxyEntry, 0, len(p.proxylist))
			seen := make(map[string]struct{})
			for idx, pr := range p.proxylist {
				hpAddr, err := network.ParseAddrPort(pr.Address, ifaceAddr)
				if err != nil {
					return err
				}
				addr := hpAddr.String()
				if _, ok := seen[addr]; !ok {
					seen[addr] = struct{}{}
					p.proxylist[idx].Address = addr
				} else {
					return fmt.Errorf("proxy list duplicate entry `%s`", addr)
				}
			}
			sockAddr = p.printProxyChain(p.proxylist)
		} else {
			p.logger.Debug().Msgf("Configuring %s proxy client...", p.socksProto)
			socksProxy := p.proxylist[0]
			hostPortSOCKS, err := network.ParseAddrPort(socksProxy.Address, ifaceAddr)
			if err != nil {
				return err
			}
			sockAddr = hostPortSOCKS.String()
			auth := auth{
				User:     socksProxy.Username,
				Password: socksProxy.Password,
			}
			dialer, err := p.newSOCKSDialer(sockAddr, &auth, p.baseDialer, p.tcp)
			if err != nil {
				return fmt.Errorf("unable to create %s dialer: %v", p.socksProto, err)
			}
			p.sockDialer = dialer
			p.proxylist[0].Address = sockAddr // used in auto configuration
		}
	}

	if p.httpEnabled {
		// configure http address
		var httpHandler http.Handler
		httpProto := "HTTP"
		if p.certFile != "" && p.keyFile != "" {
			httpProto = "HTTPS"
		}
		p.logger.Debug().Msgf("Configuring %s server address...", httpProto)
		parsedAddrHTTP, err := network.ParseAddrPort(p.httpServerAddr, ifaceAddr)
		if err != nil {
			return err
		}
		p.httpServerAddr = parsedAddrHTTP.String()
		if !bindToLocalhost {
			p.httpServerAddr = netip.AddrPortFrom(netip.MustParseAddr(ifaceAddr), parsedAddrHTTP.Port()).String()
		}
		if p.user != "" && p.pass != "" {
			httpHandler = p.proxyAuth(p.handler())
		} else {
			httpHandler = p.handler()
		}
		// configure http server
		p.logger.Debug().Msgf("Configuring %s server...", httpProto)
		hs := &http.Server{
			Handler:        httpHandler,
			ReadTimeout:    readTimeout,
			WriteTimeout:   writeTimeout,
			MaxHeaderBytes: 1 << 20,
			Protocols:      new(http.Protocols),
			TLSConfig: &tls.Config{
				MinVersion:       tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				},
			},
		}
		hs.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
		hs.Protocols.SetHTTP1(true)
		p.httpServer = hs
		p.httpLocalClient = newHTTPClient(p.baseDialer)
		if p.sockDialer != nil {
			p.httpClient = newHTTPClient(p.sockDialer)
		}

		// configure HTTP/2 and HTTP/3 support
		if p.certFile != "" && p.keyFile != "" {
			p.logger.Debug().Msg("Configuring HTTP2 server...")
			p.httpServer.Protocols.SetHTTP2(true)
			p.httpServer.Protocols.SetUnencryptedHTTP2(true)
			if !p.socks4enabled {
				p.logger.Debug().Msg("Configuring HTTP3 server...")
				p.http3Server = &http3.Server{
					Handler:        p.replayCheck(httpHandler),
					MaxHeaderBytes: 1 << 20,
				}
				if p.nsEnabled {
					p.http3LocalClient = newHTTP3Client(getNSQUICDialer(p.baseDialer.(*nsDialer)))
				} else {
					p.http3LocalClient = newHTTP3Client(nil)
				}
				if p.sockDialer != nil {
					p.http3Client = newHTTP3Client(getQUICDialer(p.sockDialer))
				}
			}

		}
	}

	// configure arp spoofing
	if p.arpSpoofConf != "" {
		p.logger.Debug().Msg("Configuring arp spoofer...")
		if p.iface == nil {
			return fmt.Errorf("failed getting network interface")
		}
		if !p.auto {
			p.logger.Warn().Msg("arpspoof setup requires iptables configuration")
		}
		asc, err := arpspoof.NewARPSpoofConfig(p.arpSpoofConf, p.logger)
		if err != nil {
			return fmt.Errorf("failed creating arp spoofer: %v", err)
		}
		asc.Interface = p.iface.Name
		asc.NetNS = ""
		if p.nsEnabled {
			asc.NetNS = p.inNSPathOrName
		}
		p.arpspoofer, err = arpspoof.NewARPSpoofer(asc)
		if err != nil {
			return fmt.Errorf("failed creating arp spoofer: %v", err)
		}
		p.logger.Debug().Msg("Configuring DNS IPv4 (gateway)...")
		gw := p.arpspoofer.GatewayIP()
		p.gwDNS = &net.UDPAddr{IP: net.ParseIP(gw.String()), Port: 53}
	}

	// configure ndp spoofing
	if p.ndpSpoofConf != "" {
		p.logger.Debug().Msg("Configuring ndp spoofer...")
		if p.iface == nil {
			return fmt.Errorf("failed getting network interface")
		}
		if !p.ipv6enabled {
			return fmt.Errorf("ndpspoof requires IPv6 enabled")
		}
		if !p.auto {
			p.logger.Warn().Msg("nfpspoof setup requires iptables configuration")
		}
		nsc, err := ndpspoof.NewNDPSpoofConfig(p.ndpSpoofConf, p.logger)
		if err != nil {
			return fmt.Errorf("failed creating ndp spoofer: %v", err)
		}
		nsc.Interface = p.iface.Name
		nsc.RDNSS = ""
		nsc.Auto = false
		nsc.NoColor = p.nocolor
		nsc.NetNS = ""
		if p.nsEnabled {
			nsc.NetNS = p.inNSPathOrName
		}
		if nsc.RA {
			var hostIP netip.Addr
			p.logger.Debug().Msg("Configuring DNS IPv6 (host)...")
			hostIP, err = network.GetHostIPv6GlobalUnicastFromRoute()
			if err != nil {
				if p.prefix6 != nil {
					hostIP = p.prefix6.Addr()
				} else {
					pr, err := network.GetIPv6GlobalUnicastPrefixFromInterface(p.iface)
					if err != nil {
						return err
					}
					hostIP = pr.Addr()
				}
			}
			nsc.RDNSS = hostIP.String() // use host ip as DNS server
			p.raEnabled = true
			p.hostDNS6 = &net.UDPAddr{IP: net.ParseIP(hostIP.String()), Port: 53}
		}
		p.ndpspoofer, err = ndpspoof.NewNDPSpoofer(nsc)
		if err != nil {
			return fmt.Errorf("failed creating ndp spoofer: %v", err)
		}
		p.logger.Debug().Msg("Configuring DNS IPv6 (gateway)...")
		if p.nsEnabled {
			p.gwDNS6 = p.outDNS6
		} else {
			p.gwDNS6 = network.GetIPv6Resolver(p.iface)
		}
	}

	// configuring DNS filters
	if p.dnsFilterConf.Enabled {
		p.logger.Debug().Msg("Configuring DNS filters...")
		p.filter = newDNSFilter(p.dnsFilterConf, p.baseDialer, p.logger)
	}

	// configure packet capture
	var pcc *mshark.Config
	pcapW := make([]mshark.PacketWriter, 0, 4)
	if p.pcapConf != "" {
		p.logger.Debug().Msg("Configuring packet capture...")
		if p.iface == nil {
			return fmt.Errorf("failed getting network interface")
		}
		pcc, err = mshark.NewConfig(p.pcapConf)
		if err != nil {
			return fmt.Errorf("failed configuring packet capture: %v", err)
		}
		pcc.Device = p.iface
		pcc.Promisc = true
		for _, ext := range pcc.Exts {
			switch ext {
			case "txt":
				f, err := createPcapFile(App, ext)
				if err != nil {
					return err
				}
				w := mshark.NewWriter(f, true)
				if err := w.WriteHeader(pcc); err != nil {
					w.Close()
					return err
				}
				pcapW = append(pcapW, w)
			case "pcap":
				f, err := createPcapFile(App, ext)
				if err != nil {
					return err
				}
				w := mpcap.NewWriter(f)
				if err := w.WriteHeader(pcc.Snaplen); err != nil {
					w.Close()
					return err
				}
				pcapW = append(pcapW, w)
			case "pcapng":
				f, err := createPcapFile(App, ext)
				if err != nil {
					return err
				}
				w := mpcapng.NewWriter(f)
				if err := w.WriteHeader(App, pcc.Device, pcc.Expr, pcc.Snaplen); err != nil {
					w.Close()
					return err
				}
				pcapW = append(pcapW, w)
			default:
				return fmt.Errorf("unsupported file format: %s", ext)
			}
		}
		if len(pcapW) == 0 {
			f, err := createPcapFile(App, "pcapng")
			if err != nil {
				return err
			}
			w := mpcapng.NewWriter(f)
			if err := w.WriteHeader(App, pcc.Device, pcc.Expr, pcc.Snaplen); err != nil {
				w.Close()
				return err
			}
			pcapW = append(pcapW, w)
		}
	}

	// configure listeners
	var lnPprof, lnHTTP net.Listener
	var lnHTTP3 *quic.EarlyListener
	var pcapConn net.PacketConn
	if p.pprofServer != nil {
		lnPprof, err = net.Listen(p.tcp, p.pprofAddr)
		if err != nil {
			return err
		}
	}
	if p.httpServer != nil {
		lnHTTP, err = net.Listen(p.tcp, p.httpServerAddr)
		if err != nil {
			return err
		}
	}
	if p.http3Server != nil {
		cert, err := tls.LoadX509KeyPair(p.certFile, p.keyFile)
		if err != nil {
			return err
		}
		tlsConf := http3.ConfigureTLSConfig(&tls.Config{
			MinVersion:   tls.VersionTLS13,
			NextProtos:   []string{http3.NextProtoH3},
			Certificates: []tls.Certificate{cert},
		})
		quicConf := &quic.Config{
			MaxIdleTimeout:          maxIdleTimeout,
			KeepAlivePeriod:         keepAlivePeriod,
			MaxIncomingStreams:      maxIncomingStreams,
			MaxIncomingUniStreams:   maxIncomingUniStreams,
			HandshakeIdleTimeout:    handshakeIdleTimeout,
			DisablePathMTUDiscovery: false,
			Allow0RTT:               true,
		}
		lnHTTP3, err = quic.ListenAddrEarly(p.httpServerAddr, tlsConf, quicConf)
		if err != nil {
			return err
		}
	}
	tproxyEnabled := p.tproxyAddr != ""
	tproxyServers := make([]*tproxyServer, p.tproxyWorkers)
	if tproxyEnabled {
		for i := range tproxyServers {
			tproxyServers[i], err = newTproxyServer(p)
			if err != nil {
				return err
			}
		}
	}
	tproxyUDPEnabled := p.tproxyAddrUDP != ""
	tproxyUDPServers := make([]*tproxyServerUDP, p.tproxyUDPWorkers)
	if tproxyUDPEnabled {
		for i := range tproxyUDPServers {
			tproxyUDPServers[i], err = newTproxyServerUDP(p)
			if err != nil {
				return err
			}
		}
	}
	opts := make(map[string]string, 20)
	if p.auto {
		p.logger.Info().Msg("Configuring iptables and kernel parameters...")
		p.applyCommonRedirectRules(opts)
		if tproxyEnabled {
			tproxyServers[0].ApplyRedirectRules(opts) // NOTE: probably stupid, need to move TCP settings in a separate function
		}
		if tproxyUDPEnabled {
			tproxyUDPServers[0].ApplyRedirectRules(opts)
		}
	}

	if pcc != nil {
		lc := &network.ListenConfig{Device: pcc.Device, Promiscuous: &pcc.Promisc, FilterExpr: pcc.Expr}
		pcapConn, err = network.ListenPacket(lc)
		if err != nil {
			return err
		}
	}

	// all listening sockets created, restore namespace
	if p.nsEnabled {
		if currentNs > 0 {
			netns.Set(currentNs)
			currentNs.Close()
		}
		runtime.UnlockOSThread()
	}

	// proxy starting
	done := make(chan bool)
	quit := make(chan os.Signal, 1)
	p.closeConn = make(chan bool)
	signal.Notify(quit, os.Interrupt)

	if p.ipv6enabled {
		p.logger.Info().Msg("IPv6 enabled")
	} else {
		p.logger.Info().Msg("IPv6 disabled")
	}
	if p.socksEnabled {
		p.logger.Info().Msgf("SOCKS version: %s", p.socksProto)
	}

	if p.proxychain.Enabled {
		p.chDialer = &chainedDialer{}
		chainType := p.proxychain.Type
		ctl := colorizeChainType(chainType, p.nocolor)
		go func() {
			if p.nsEnabled {
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				currentNs, err := netns.Get()
				if err == nil {
					defer currentNs.Close()
					defer netns.Set(currentNs)
				}
				netns.Set(*p.outNS)
			}
			p.updateSocksList()
			ticker := time.NewTicker(availProxyUpdateInterval)
			defer ticker.Stop()
			for {
				select {
				case <-p.closeConn:
					return
				case <-ticker.C:
					p.logger.Debug().Msgf("%s Updating available proxy", ctl)
					p.updateSocksList()
				}
			}
		}()
	}

	// logging which servers are enabled
	if p.socksEnabled {
		if p.proxychain.Enabled {
			p.logger.Info().Msgf("%s Proxy [%s] chain: %s", strings.ToUpper(p.socksProto), p.proxychain.Type, sockAddr)
		} else {
			p.logger.Info().Msgf("%s Proxy: %s", strings.ToUpper(p.socksProto), sockAddr)
		}
	}

	if p.httpEnabled {
		if p.certFile != "" && p.keyFile != "" {
			p.logger.Info().Msgf("HTTPS Proxy: %s", p.httpServerAddr)
			if !p.socks4enabled {
				p.logger.Info().Msgf("HTTP3 Proxy (QUIC): %s", p.httpServerAddr)
			}
		} else {
			p.logger.Info().Msgf("HTTP Proxy: %s", p.httpServerAddr)
		}
	}

	if p.tproxyAddr != "" {
		suffix := ""
		if p.tproxyWorkers != 1 {
			suffix = "s"
		}
		if p.tproxyMode == "tproxy" {
			p.logger.Info().Msgf("TPROXY: %s (%d instance%s)", p.tproxyAddr, p.tproxyWorkers, suffix)
		} else {
			p.logger.Info().Msgf("REDIRECT: %s (%d instance%s)", p.tproxyAddr, p.tproxyWorkers, suffix)
		}
	}

	if p.tproxyAddrUDP != "" {
		suffix := ""
		if p.tproxyUDPWorkers != 1 {
			suffix = "s"
		}
		p.logger.Info().Msgf("TPROXY (udp): %s (%d instance%s)", p.tproxyAddrUDP, p.tproxyUDPWorkers, suffix)
	}
	if p.outDNS != nil {
		p.logger.Info().Msgf("DNS IPv4 (netns): %s", p.outDNS)
	}
	if p.outDNS6 != nil {
		p.logger.Info().Msgf("DNS IPv6 (netns): %s", p.outDNS6)
	}
	if p.gwDNS != nil {
		p.logger.Info().Msgf("DNS IPv4 (gateway): %s", p.gwDNS)
	}
	if p.gwDNS6 != nil {
		p.logger.Info().Msgf("DNS IPv6 (gateway): %s", p.gwDNS6)
	}
	if p.hostDNS6 != nil {
		p.logger.Info().Msgf("DNS IPv6 (host): %s", p.hostDNS6)
	}

	if p.pprofAddr != "" {
		p.logger.Info().Msgf("PPROF: %s", p.pprofAddr)
	}

	var pcapWg sync.WaitGroup
	if pcc != nil {
		pcapWg.Go(func() {
			p.logger.Info().Msg("Starting packet capture...")
			if err := mshark.OpenLiveFromPacketConn(pcapConn, pcc, pcapW...); err != nil {
				p.logger.Error().Err(err).Msg("Failed capturing packets")
			}
		})
	}

	if p.arpspoofer != nil {
		go p.arpspoofer.Start()
	}

	if p.ndpspoofer != nil {
		go p.ndpspoofer.Start()
	}

	if p.pprofServer != nil {
		go func() {
			if err := p.pprofServer.Serve(lnPprof); err != nil && err != http.ErrServerClosed {
				p.logger.Error().Err(err).Msg("Unable to start PPROF server")
				quit <- os.Interrupt
			}
		}()
	}

	if p.httpServer != nil {
		go func() {
			<-quit
			signal.Ignore(os.Interrupt)
			close(p.closeConn)
			var wg sync.WaitGroup
			if p.arpspoofer != nil {
				wg.Go(func() {
					err := p.arpspoofer.Stop()
					if err != nil {
						p.logger.Error().Err(err).Msg("Failed stopping arp spoofer")
					}
				})
			}
			if p.ndpspoofer != nil {
				wg.Go(func() {
					err := p.ndpspoofer.Stop()
					if err != nil {
						p.logger.Error().Err(err).Msg("Failed stopping ndp spoofer")
					}
				})
			}
			if tproxyEnabled {
				p.logger.Info().Msgf("[tcp %s] Server is shutting down...", p.tproxyMode)
				wg.Add(int(p.tproxyWorkers))
				for i, tproxyServer := range tproxyServers {
					go func() {
						p.logger.Info().Msgf("[tcp %s] Server %d is shutting down...", p.tproxyMode, i)
						tproxyServer.Shutdown()
						p.logger.Info().Msgf("[tcp %s] Server %d gracefully shutdown", p.tproxyMode, i)
						wg.Done()
					}()
				}
			}
			if tproxyUDPEnabled {
				p.logger.Info().Msgf("[udp %s] Server is shutting down...", p.tproxyMode)
				wg.Add(int(p.tproxyUDPWorkers))
				for i, tproxyServerUDP := range tproxyUDPServers {
					go func() {
						p.logger.Info().Msgf("[udp %s] Server %d is shutting down...", p.tproxyMode, i)
						tproxyServerUDP.Shutdown()
						p.logger.Info().Msgf("[udp %s] Server %d gracefully shutdown", p.tproxyMode, i)
						wg.Done()
					}()
				}
			}
			if p.auto {
				wg.Go(func() {
					if p.nsEnabled {
						runtime.LockOSThread()
						defer runtime.UnlockOSThread()
						currentNs, err := netns.Get()
						if err == nil {
							defer currentNs.Close()
							defer netns.Set(currentNs)
						}
						netns.Set(*p.inNS)
					}
					p.logger.Info().Msg("Restoring iptables and kernel parameters...")
					if tproxyEnabled {
						err := tproxyServers[0].ClearRedirectRules()
						if err != nil {
							p.logger.Error().Err(err).Msg("Failed clearing iptables rules")
						}
					}
					if tproxyUDPEnabled {
						err := tproxyUDPServers[0].ClearRedirectRules()
						if err != nil {
							p.logger.Error().Err(err).Msg("Failed clearing iptables rules")
						}
					}
					err = p.clearCommonRedirectRules(opts)
					if err != nil {
						p.logger.Error().Err(err).Msg("Failed clearing iptables rules")
					}
				})
			}
			p.logger.Info().Msg("HTTP clients are shutting down...")
			for _, c := range []httpClienter{p.http3LocalClient, p.http3Client, p.http3LocalClient, p.http3Client} {
				wg.Go(func() {
					c.Close()
				})
			}
			ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)

			defer cancel()
			wg.Go(func() {
				p.httpServer.SetKeepAlivesEnabled(false)
				httpServerStr := "HTTP"
				if p.certFile != "" && p.keyFile != "" {
					httpServerStr = "HTTPS"
				}
				p.logger.Info().Msgf("%s Server is shutting down...", httpServerStr)
				if err := p.httpServer.Shutdown(ctx); err != nil {
					p.logger.Error().Err(err).Msgf("Could not gracefully shutdown %s server", httpServerStr)
				} else {
					p.logger.Info().Msgf("%s Server gracefully shutdown", httpServerStr)
				}
			})
			if p.http3Server != nil {
				p.logger.Info().Msg("HTTP3 Server is shutting down...")
				wg.Go(func() {
					if err := p.http3Server.Shutdown(ctx); err != nil {
						p.logger.Error().Err(err).Msg("Could not gracefully shutdown HTTP3 server")
					} else {
						p.logger.Info().Msg("HTTP3 Server gracefully shutdown")
					}
				})
			}
			if p.pprofServer != nil {
				p.logger.Info().Msg("PPROF Server is shutting down...")
				wg.Go(func() {
					p.pprofServer.SetKeepAlivesEnabled(false)
					if err := p.pprofServer.Shutdown(ctx); err != nil {
						p.logger.Error().Err(err).Msg("Could not gracefully shutdown PPROF server")
					} else {
						p.logger.Info().Msg("PPROF Server gracefully shutdown")
					}
				})
			}
			if p.pcapConf != "" {
				wg.Go(func() {
					p.logger.Info().Msg("Shutting down packet capture..")
					pcapWg.Wait()
				})
			}
			wg.Wait()
			close(done)
		}()
		if tproxyEnabled {
			for _, tproxyServer := range tproxyServers {
				go tproxyServer.Serve()
			}
		}
		if tproxyUDPEnabled {
			for _, tproxyServerUDP := range tproxyUDPServers {
				go tproxyServerUDP.Serve()
			}
		}
		if p.certFile != "" && p.keyFile != "" {
			go func() {
				if err := p.httpServer.ServeTLS(lnHTTP, p.certFile, p.keyFile); err != nil && err != http.ErrServerClosed {
					p.logger.Error().Err(err).Msg("Unable to start HTTPS server")
					quit <- os.Interrupt
				}
			}()
			if p.http3Server != nil {
				if err := p.http3Server.ServeListener(lnHTTP3); err != nil && err != http.ErrServerClosed {
					p.logger.Error().Err(err).Msg("Unable to start HTTP3 server")
					quit <- os.Interrupt
				}
			}
		} else {
			if err := p.httpServer.Serve(lnHTTP); err != nil && err != http.ErrServerClosed {
				p.logger.Error().Err(err).Msg("Unable to start HTTP server")
				quit <- os.Interrupt
			}
		}
	} else {
		go func() {
			<-quit
			signal.Ignore(os.Interrupt)
			close(p.closeConn)
			var wg sync.WaitGroup
			if p.arpspoofer != nil {
				wg.Go(func() {
					err := p.arpspoofer.Stop()
					if err != nil {
						p.logger.Error().Err(err).Msg("Failed stopping arp spoofer")
					}
				})
			}
			if p.ndpspoofer != nil {
				wg.Go(func() {
					err := p.ndpspoofer.Stop()
					if err != nil {
						p.logger.Error().Err(err).Msg("Failed stopping ndp spoofer")
					}
				})
			}
			if tproxyEnabled {
				wg.Add(int(p.tproxyWorkers))
				for i, tproxyServer := range tproxyServers {
					go func() {
						p.logger.Info().Msgf("[tcp %s] Server %d is shutting down...", p.tproxyMode, i)
						tproxyServer.Shutdown()
						p.logger.Info().Msgf("[tcp %s] Server %d gracefully shutdown", p.tproxyMode, i)
						wg.Done()
					}()
				}
			}
			if tproxyUDPEnabled {
				wg.Add(int(p.tproxyUDPWorkers))
				for i, tproxyServerUDP := range tproxyUDPServers {
					go func() {
						p.logger.Info().Msgf("[udp %s] Server %d is shutting down...", p.tproxyMode, i)
						tproxyServerUDP.Shutdown()
						p.logger.Info().Msgf("[udp %s] Server %d gracefully shutdown", p.tproxyMode, i)
						wg.Done()
					}()
				}
			}
			if p.pprofServer != nil {
				p.logger.Info().Msg("PPROF Server is shutting down...")
				ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
				defer cancel()
				wg.Go(func() {
					p.pprofServer.SetKeepAlivesEnabled(false)
					if err := p.pprofServer.Shutdown(ctx); err != nil {
						p.logger.Error().Err(err).Msg("Could not gracefully shutdown PPROF server")
					} else {
						p.logger.Info().Msg("PPROF Server gracefully shutdown")
					}
				})
			}
			if p.auto {
				wg.Go(func() {
					if p.nsEnabled {
						runtime.LockOSThread()
						defer runtime.UnlockOSThread()
						currentNs, err := netns.Get()
						if err == nil {
							defer currentNs.Close()
							defer netns.Set(currentNs)
						}
						netns.Set(*p.inNS)
					}
					p.logger.Info().Msg("Restoring iptables and kernel parameters...")
					if tproxyEnabled {
						err := tproxyServers[0].ClearRedirectRules()
						if err != nil {
							p.logger.Error().Err(err).Msg("Failed clearing iptables rules")
						}
					}
					if tproxyUDPEnabled {
						err := tproxyUDPServers[0].ClearRedirectRules()
						if err != nil {
							p.logger.Error().Err(err).Msg("Failed clearing iptables rules")
						}
					}
					err := p.clearCommonRedirectRules(opts)
					if err != nil {
						p.logger.Error().Err(err).Msg("Failed clearing iptables rules")
					}
				})
			}
			if p.pcapConf != "" {
				wg.Go(func() {
					p.logger.Info().Msg("Shutting down packet capture..")
					pcapWg.Wait()
				})
			}
			wg.Wait()
			close(done)
		}()
		if tproxyEnabled && tproxyUDPEnabled {
			for _, tproxyServerUDP := range tproxyUDPServers {
				go tproxyServerUDP.Serve()
			}
			for i, tproxyServer := range tproxyServers {
				if i < len(tproxyServers)-1 {
					go tproxyServer.Serve()
				} else {
					tproxyServer.Serve()
				}
			}
		} else if tproxyEnabled {
			for i, tproxyServer := range tproxyServers {
				if i < len(tproxyServers)-1 {
					go tproxyServer.Serve()
				} else {
					tproxyServer.Serve()
				}
			}
		} else {
			for i, tproxyServerUDP := range tproxyUDPServers {
				if i < len(tproxyUDPServers)-1 {
					go tproxyServerUDP.Serve()
				} else {
					tproxyServerUDP.Serve()
				}
			}
		}
	}
	<-done
	if p.nsEnabled {
		p.inNS.Close()
		p.outNS.Close()
	}
	if p.dumpRules {
		err := os.WriteFile("rules.sh", []byte(p.dump.String()), 0o755)
		if err != nil {
			p.logger.Error().Err(err).Msg("Failed dumping rules")
		}
	}
	p.logger.Info().Msg("Proxy stopped")
	return nil
}

func (p *Proxy) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if p.http3Server != nil && r.ProtoMajor < 3 {
			p.http3Server.SetQUICHeaders(w.Header())
		}
		if r.ProtoMajor == 3 {
			p.handleForward(w, r) // NOTE: method CONNECT for http3 is not supported
		} else if r.Method == http.MethodConnect {
			p.handleTunnel(w, r)
		} else {
			p.handleForward(w, r)
		}
	}
}

func (p *Proxy) handleForward(w http.ResponseWriter, r *http.Request) {
	proto := r.ProtoMajor
	switch proto {
	case 2:
		r.URL.Host = r.Host
		r.URL.Scheme = "http"
	case 3:
		r.URL.Host = r.Host
		r.URL.Scheme = "https"
	}
	// handle urls like http://example.com:443
	if strings.HasSuffix(r.Host, ":443") {
		r.URL.Scheme = "https"
	}
	var reqBodySaved []byte
	if p.sniff && p.body {
		reqBodySaved, _ = io.ReadAll(io.LimitReader(r.Body, maxBodySize))
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(reqBodySaved), r.Body))
	}
	req, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		p.logger.Error().Err(err).Msgf("Error during NewRequest() %s: %s", r.URL.String(), err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	req.RequestURI = ""
	copyHeader(req.Header, r.Header)
	delConnectionHeaders(req.Header)
	delHopHeaders(req.Header)
	if _, ok := req.Header["User-Agent"]; !ok {
		req.Header.Set("User-Agent", "")
	}
	if proto == 3 {
		if remoteAddr := r.Context().Value(http3.RemoteAddrContextKey).(net.Addr); remoteAddr != nil {
			appendHostToXForwardHeader(req.Header, remoteAddr.String())
		}
	} else {
		// TODO: find out why req.RemoteAddr is empty
		if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
			appendHostToXForwardHeader(req.Header, clientIP)
		}
	}
	var resp *http.Response
	var chunked bool
	var respBodySaved []byte
	var c httpClienter
	if !p.socksEnabled || network.IsLocalAddress(r.Host) {
		if proto == 3 {
			c = p.http3LocalClient
		} else {
			fmt.Println("get dilaer")
			c = p.httpLocalClient
		}
	} else if !p.proxychain.Enabled {
		if proto == 3 {
			c = p.http3Client
		} else {
			c = p.httpClient
		}
	} else {
		if proto == 3 {
			c, err = p.getHTTP3Client()
		} else {
			c, err = p.getHTTPClient()
		}
		if err != nil {
			p.logger.Error().Err(err).Msgf("Failed getting %s client", p.socksProto)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		defer c.Close()
	}
	resp, err = p.doReq(req, c)
	if err != nil {
		p.logger.Error().Err(err).Msg("")
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	chunked = proto == 3 || slices.Contains(resp.TransferEncoding, "chunked")
	if p.sniff {
		if p.body {
			if chunked {
				buf := make([]byte, maxBodySize)
				n, _ := resp.Body.Read(buf)
				respBodySaved = buf[:n]
				resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf[:n]), resp.Body))
			} else {
				respBodySaved, _ = io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
				resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(respBodySaved), resp.Body))
			}
			if resp.Header.Get("Content-Encoding") == "gzip" {
				gzr, err := gzip.NewReader(bytes.NewReader(respBodySaved))
				if err == nil {
					respBodySaved, _ = io.ReadAll(gzr)
					gzr.Close()
				}
			}
			reqBodySaved = bytes.Trim(reqBodySaved, "\r\n\t ")
			respBodySaved = bytes.Trim(respBodySaved, "\r\n\t ")
		}
		if p.json {
			sniffdata := make([]string, 0, 4)
			j, err := json.Marshal(&layers.HTTPMessage{Request: r})
			if err == nil {
				sniffdata = append(sniffdata, string(j))
			}
			j, err = json.Marshal(&layers.HTTPMessage{Response: resp})
			if err == nil {
				sniffdata = append(sniffdata, string(j))
			}
			if p.body && len(reqBodySaved) > 0 {
				sniffdata = append(sniffdata, fmt.Sprintf("{\"req_body\":%s}", reqBodySaved))
			}
			if p.body && len(respBodySaved) > 0 {
				sniffdata = append(sniffdata, fmt.Sprintf("{\"resp_body\":%s}", respBodySaved))
			}
			p.snifflogger.Log().Msg(fmt.Sprintf("[%s]", strings.Join(sniffdata, ",")))
		} else {
			id := getID(p.nocolor)
			p.snifflogger.Log().Msg(colorizeHTTP(req, resp, &reqBodySaved, &respBodySaved, id, false, p.body, p.nocolor))
		}
	}
	announcedTrailers := len(resp.Trailer)
	if announcedTrailers > 0 {
		trailerKeys := make([]string, 0, announcedTrailers)
		for k := range resp.Trailer {
			trailerKeys = append(trailerKeys, k)
		}
		w.Header().Add("Trailer", strings.Join(trailerKeys, ", "))
	}
	delConnectionHeaders(resp.Header)
	delHopHeaders(resp.Header)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	var written int64
	var wg sync.WaitGroup
	rc := http.NewResponseController(w)
	wg.Go(func() {
		buf := make([]byte, 32*1024)
		ticker := time.NewTicker(flushTimeout)
		defer ticker.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-p.closeConn:
				return
			case <-ticker.C:
				err := rc.Flush()
				if err != nil {
					p.logger.Error().Err(err).Msg("Failed flushing buffer")
					return
				}
				err = rc.SetReadDeadline(time.Now().Add(readTimeout))
				if err != nil {
					p.logger.Error().Err(err).Msg("Failed setting read deadline")
					return
				}
				err = rc.SetWriteDeadline(time.Now().Add(writeTimeout))
				if err != nil {
					p.logger.Error().Err(err).Msg("Failed setting write deadline")
					return
				}
			default:
				nr, er := resp.Body.Read(buf)
				if nr > 0 {
					nw, ew := w.Write(buf[:nr])
					if nw < 0 || nr < nw {
						nw = 0
						if ew == nil {
							ew = errInvalidWrite
						}
					}
					written += int64(nw)
					if ew != nil {
						if ne, ok := ew.(net.Error); ok && ne.Timeout() {
							return
						}
						if errors.Is(ew, net.ErrClosed) {
							return
						}
						return
					}
					if nr != nw {
						return
					}
				}
				if er != nil {
					if errors.Is(er, os.ErrDeadlineExceeded) {
						continue
					}
					if ne, ok := er.(net.Error); ok && ne.Timeout() {
						continue
					}
					if errors.Is(er, net.ErrClosed) {
						return
					}
					if errors.Is(er, io.EOF) {
						return
					}
					return
				}
			}
		}
	})
	wg.Wait()
	resp.Body.Close()
	writtenBytes := network.PrettifyBytes(written)
	if chunked {
		writtenBytes = fmt.Sprintf("%s - chunked", writtenBytes)
	}
	status := resp.Status
	if !p.nocolor {
		status = colorizeStatus(resp.StatusCode, status, false)
	}
	p.logger.Debug().Msgf("%s - %s - %s - %s - %s", r.Proto, r.Method, r.Host, status, writtenBytes)
	if len(resp.Trailer) == announcedTrailers {
		copyHeader(w.Header(), resp.Trailer)
	}
	for key, values := range resp.Trailer {
		key = http.TrailerPrefix + key
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
}

func (p *Proxy) handleTunnel(w http.ResponseWriter, r *http.Request) {
	var dstConn net.Conn
	var err error
	if !p.socksEnabled || network.IsLocalAddress(r.Host) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		fmt.Println("get kwdkw")
		dstConn, err = p.baseDialer.DialContext(ctx, p.tcp, r.Host)
		if err != nil {
			p.logger.Error().Err(err).Msgf("Failed connecting to %s", r.Host)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
	} else {
		sockDialer, err := p.getSockDialer()
		if err != nil {
			p.logger.Error().Err(err).Msgf("Failed getting %s client", p.socksProto)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		dstConn, err = sockDialer.DialContext(ctx, p.tcp, r.Host)
		if err != nil {
			p.logger.Error().Err(err).Msgf("Failed connecting to %s", r.Host)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
	}
	arrow := "→ "
	if p.nocolor {
		arrow = "->"
	}
	defer dstConn.Close()
	reqChan := make(chan layers.Layer)
	respChan := make(chan layers.Layer)
	var wg sync.WaitGroup
	var srcConnRemote, srcConnLocal, dstConnRemote, dstConnLocal string
	if r.ProtoMajor == 2 {
		flusher, ok := w.(http.Flusher)
		if !ok {
			p.logger.Error().Msg("webserver doesn't support flushing")
			http.Error(w, "webserver doesn't support flushing", http.StatusInternalServerError)
			return
		}
		flusher.Flush()
		srcConnRemote = r.RemoteAddr
		srcConnLocal = r.Host
		dstConnRemote = dstConn.RemoteAddr().String()
		dstConnLocal = dstConn.LocalAddr().String()
		dstConnStr := fmt.Sprintf("%s%s%s%s%s", dstConnLocal, arrow, dstConnRemote, arrow, r.Host)
		srcConnStr := fmt.Sprintf("%s%s%s", srcConnRemote, arrow, srcConnLocal)

		p.logger.Debug().Msgf("%s - %s - %s", r.Proto, r.Method, r.Host)
		p.logger.Debug().Msgf("src: %s - dst: %s", srcConnStr, dstConnStr)
		wg.Add(2)
		go p.transferHTTP2(&wg, w, r, dstConn, dstConnStr, srcConnStr, reqChan, respChan)
	} else {
		hj, ok := w.(http.Hijacker)
		if !ok {
			p.logger.Error().Msg("webserver doesn't support hijacking")
			http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
			return
		}
		srcConn, _, err := hj.Hijack()
		if err != nil {
			p.logger.Error().Err(err).Msg("Failed hijacking src connection")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer srcConn.Close()
		srcConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		srcConnRemote = srcConn.RemoteAddr().String()
		srcConnLocal = srcConn.LocalAddr().String()
		dstConnRemote = dstConn.RemoteAddr().String()
		dstConnLocal = dstConn.LocalAddr().String()

		dstConnStr := fmt.Sprintf("%s%s%s%s%s", dstConnLocal, arrow, dstConnRemote, arrow, r.Host)
		srcConnStr := fmt.Sprintf("%s%s%s", srcConnRemote, arrow, srcConnLocal)

		p.logger.Debug().Msgf("%s - %s - %s", r.Proto, r.Method, r.Host)
		p.logger.Debug().Msgf("src: %s - dst: %s", srcConnStr, dstConnStr)
		wg.Add(2)
		go p.transfer(&wg, dstConn, srcConn, dstConnStr, srcConnStr, reqChan)
		go p.transfer(&wg, srcConn, dstConn, srcConnStr, dstConnStr, respChan)
	}
	if p.sniff {
		wg.Add(1)
		sniffdata := make([]string, 0, 6)
		id := getID(p.nocolor)
		if p.json {
			sniffdata = append(
				sniffdata,
				fmt.Sprintf("{\"connection\":{\"src_remote\":%q,\"src_local\":%q,\"dst_local\":%q,\"dst_remote\":%q}}",
					srcConnRemote, srcConnLocal, dstConnLocal, dstConnRemote),
			)
			j, err := json.Marshal(&layers.HTTPMessage{Request: r})
			if err == nil {
				sniffdata = append(sniffdata, string(j))
			}
		} else {
			connections := colorizeConnections(
				srcConnRemote,
				srcConnLocal,
				dstConnRemote,
				dstConnLocal,
				id,
				r,
				p.nocolor,
			)
			sniffdata = append(sniffdata, connections)
		}
		go p.sniffreporter(&wg, &sniffdata, reqChan, respChan, id)
	}
	wg.Wait()
}

func (p *Proxy) printProxyChain(pc []ProxyEntry) string {
	var sb strings.Builder
	arrow := " →  "
	if p.nocolor {
		arrow = " -> "
	}
	sb.WriteString("client")
	sb.WriteString(arrow)
	if p.httpServerAddr != "" {
		if p.certFile != "" && p.keyFile != "" {
			if p.socks4enabled {
				fmt.Fprintf(&sb, "%s (https)", p.httpServerAddr)
			} else {
				fmt.Fprintf(&sb, "%s (https/http3)", p.httpServerAddr)
			}
		} else {
			fmt.Fprintf(&sb, "%s (http)", p.httpServerAddr)
		}
		if p.tproxyAddr != "" {
			sb.WriteString(" | ")
			sb.WriteString(p.tproxyAddr)
			fmt.Fprintf(&sb, " (tcp/%s)", p.tproxyMode)
		}
		if p.tproxyAddrUDP != "" {
			sb.WriteString(" | ")
			sb.WriteString(p.tproxyAddrUDP)
			fmt.Fprintf(&sb, " (udp/%s)", p.tproxyMode)
		}
		sb.WriteString(arrow)
	} else if p.tproxyAddr != "" || p.tproxyAddrUDP != "" {
		if p.tproxyAddr != "" && p.tproxyAddrUDP != "" {
			sb.WriteString(p.tproxyAddr)
			fmt.Fprintf(&sb, " (tcp/%s)", p.tproxyMode)
			sb.WriteString(" | ")
			sb.WriteString(p.tproxyAddrUDP)
			fmt.Fprintf(&sb, " (udp/%s)", p.tproxyMode)
		} else if p.tproxyAddr != "" {
			sb.WriteString(p.tproxyAddr)
			fmt.Fprintf(&sb, " (tcp/%s)", p.tproxyMode)
		} else {
			sb.WriteString(p.tproxyAddrUDP)
			fmt.Fprintf(&sb, " (udp/%s)", p.tproxyMode)
		}
		sb.WriteString(arrow)
	}
	for _, pe := range pc {
		sb.WriteString(pe.String())
		fmt.Fprintf(&sb, " (%s)", p.socksProto)
		sb.WriteString(arrow)
	}
	sb.WriteString("target")
	return sb.String()
}

func (p *Proxy) updateSocksList() {
	// TODO: transports should be reused, for chains it makes sense to create a map where different chains map to transport
	p.mu.Lock()
	defer p.mu.Unlock()
	p.availProxyList = p.availProxyList[:0]
	var dialer contextDialer
	var err error
	failed := 0
	chainType := p.proxychain.Type
	ctl := colorizeChainType(chainType, p.nocolor)
	for _, pr := range p.proxylist {
		auth := auth{
			User:     pr.Username,
			Password: pr.Password,
		}
		dialer, err = p.newSOCKSDialer(pr.Address, &auth, p.baseDialer, p.tcp)
		if err != nil {
			p.logger.Error().Err(err).Msgf("%s Unable to create %s dialer %s", ctl, p.socksProto, pr.Address)
			failed++
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), hopTimeout)
		defer cancel()
		conn, err := dialer.DialContext(ctx, p.tcp, pr.Address)
		if err != nil && !errors.Is(err, io.EOF) { // check for EOF to include localhost SOCKS5 in the chain
			p.logger.Error().Err(err).Msgf("%s Unable to connect to %s", ctl, pr.Address)
			failed++
			if conn != nil {
				conn.Close()
			}
			continue
		} else {
			p.availProxyList = append(p.availProxyList, ProxyEntry{Address: pr.Address, Username: pr.Username, Password: pr.Password})
			if conn != nil {
				conn.Close()
			}
			break
		}
	}
	if failed == len(p.proxylist) {
		p.logger.Error().Err(err).Msgf("%s No %s Proxy available", ctl, p.socksProto)
		p.chDialer.err = fmt.Errorf("no %s proxy available", p.socksProto)
		return
	}
	currentDialer := dialer
	for _, pr := range p.proxylist[failed+1:] {
		auth := auth{
			User:     pr.Username,
			Password: pr.Password,
		}
		dialer, err = p.newSOCKSDialer(pr.Address, &auth, currentDialer, p.tcp)
		if err != nil {
			p.logger.Error().Err(err).Msgf("%s Unable to create %s dialer %s", ctl, p.socksProto, pr.Address)
			continue
		}
		// https://github.com/golang/go/issues/37549#issuecomment-1178745487
		ctx, cancel := context.WithTimeout(context.Background(), hopTimeout)
		defer cancel()
		conn, err := dialer.DialContext(ctx, p.tcp, pr.Address)
		if err != nil {
			p.logger.Error().Err(err).Msgf("%s Unable to connect to %s", ctl, pr.Address)
			if conn != nil {
				conn.Close()
			}
			continue
		}
		conn.Close()
		currentDialer = dialer
		p.availProxyList = append(p.availProxyList, ProxyEntry{Address: pr.Address, Username: pr.Username, Password: pr.Password})
	}
	if len(p.availProxyList) == 0 {
		p.logger.Error().Msgf("%s No %s Proxy available", ctl, p.socksProto)
		p.chDialer.err = fmt.Errorf("no %s proxy available", p.socksProto)
		return
	}
	p.logger.Debug().Msgf("%s Available %s Proxy [%d/%d]: %s", ctl, p.socksProto,
		len(p.availProxyList), len(p.proxylist), p.printProxyChain(p.availProxyList))
	var chainLength int
	if p.proxychain.Length > len(p.availProxyList) || p.proxychain.Length <= 0 {
		chainLength = len(p.availProxyList)
	} else {
		chainLength = p.proxychain.Length
	}
	copyProxyList := make([]ProxyEntry, 0, len(p.availProxyList))
	switch chainType {
	case "strict", "dynamic":
		copyProxyList = p.availProxyList
	case "random":
		copyProxyList = append(copyProxyList, p.availProxyList...)
		shuffle(copyProxyList)
		copyProxyList = copyProxyList[:chainLength]
	case "round_robin":
		var start uint32
		for {
			start = p.rrIndex.Load()
			next := start + 1
			if start >= p.rrIndexReset {
				p.logger.Debug().Msg("Resetting round robin index")
				next = 0
			}
			if p.rrIndex.CompareAndSwap(start, next) {
				break
			}
		}
		startIdx := int(start % uint32(len(p.availProxyList)))
		for i := range chainLength {
			idx := (startIdx + i) % len(p.availProxyList)
			copyProxyList = append(copyProxyList, p.availProxyList[idx])
		}
	default:
		p.logger.Fatal().Msg("Unreachable")
	}
	if len(copyProxyList) == 0 {
		p.logger.Error().Msgf("%s No %s Proxy available", ctl, p.socksProto)
		p.chDialer.err = fmt.Errorf("no %s proxy available", p.socksProto)
		return
	}
	if p.proxychain.Type == "strict" && len(copyProxyList) != len(p.proxylist) {
		p.logger.Error().Msgf("%s Not all %s Proxy available", ctl, p.socksProto)
		p.chDialer.err = fmt.Errorf("not all %s proxy available", p.socksProto)
		return
	}
	dialer = p.baseDialer
	for _, pr := range copyProxyList {
		auth := auth{
			User:     pr.Username,
			Password: pr.Password,
		}
		dialer, err = p.newSOCKSDialer(pr.Address, &auth, dialer, p.tcp)
		if err != nil {
			p.logger.Error().Err(err).Msgf("%s Unable to create %s dialer %s", ctl, p.socksProto, pr.Address)
			p.chDialer.err = err
			return
		}
	}
	p.chDialer.dialer = dialer
	p.chDialer.err = nil
	p.logger.Debug().Msgf("%s Request chain: %s", ctl, p.printProxyChain(copyProxyList))
}

// https://www.calhoun.io/how-to-shuffle-arrays-and-slices-in-go/
func shuffle(vals []ProxyEntry) {
	r := rand.New(rand.NewSource(time.Now().Unix()))
	for len(vals) > 0 {
		n := len(vals)
		randIndex := r.Intn(n)
		vals[n-1], vals[randIndex] = vals[randIndex], vals[n-1]
		vals = vals[:n-1]
	}
}

func (p *Proxy) getSockDialer() (contextDialer, error) {
	if !p.proxychain.Enabled {
		return p.sockDialer, nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.chDialer.dialer, p.chDialer.err
}

func (p *Proxy) getHTTPClient() (*httpClient, error) {
	sockDialer, err := p.getSockDialer()
	if err != nil {
		return nil, err
	}
	httpClient := newHTTPClient(sockDialer)
	return httpClient, nil
}

func (p *Proxy) getHTTP3Client() (*http3Client, error) {
	sockDialer, err := p.getSockDialer()
	if err != nil {
		return nil, err
	}
	http3Client := newHTTP3Client(getQUICDialer(sockDialer))
	return http3Client, nil
}

func (p *Proxy) doReq(r *http.Request, c httpClienter) (*http.Response, error) {
	resp, err := c.Do(r)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("empty response")
	}
	return resp, nil
}

func (p *Proxy) transfer(
	wg *sync.WaitGroup,
	dst net.Conn,
	src net.Conn,
	destName, srcName string,
	msgChan chan<- layers.Layer,
) {
	defer func() {
		wg.Done()
		close(msgChan)
	}()
	n, err := p.copyWithTimeout(dst, src, msgChan)
	if err != nil {
		p.logger.Error().Err(err).Msgf("Error during copy from %s to %s: %v", srcName, destName, err)
	}
	if n > 0 {
		p.logger.Debug().Msgf("Copied %s from %s to %s", network.PrettifyBytes(n), srcName, destName)
	}
	src.Close()
}

func (p *Proxy) gatherSniffData(req, resp layers.Layer, sniffdata *[]string, id string) error {
	switch reqt := req.(type) {
	case *layers.HTTPMessage:
		var reqBodySaved, respBodySaved []byte
		var rest *layers.HTTPMessage
		// TODO: find out why req and resp sometimes confused
		if reqt.Request == nil {
			return fmt.Errorf("empty request")
		}
		rest = resp.(*layers.HTTPMessage)
		if rest.Response == nil {
			return fmt.Errorf("empty response")
		}
		if p.body {
			reqBodySaved, _ = io.ReadAll(reqt.Request.Body)
			respBodySaved, _ = io.ReadAll(rest.Response.Body)
			reqBodySaved = bytes.Trim(reqBodySaved, "\r\n\t ")
			respBodySaved = bytes.Trim(respBodySaved, "\r\n\t ")
		}
		if p.json {
			j1, err := json.Marshal(reqt)
			if err != nil {
				return err
			}
			j2, err := json.Marshal(rest)
			if err != nil {
				return err
			}
			*sniffdata = append(*sniffdata, string(j1), string(j2))
			if p.body && len(reqBodySaved) > 0 {
				*sniffdata = append(*sniffdata, fmt.Sprintf("{\"req_body\":%s}", reqBodySaved))
			}
			if p.body && len(respBodySaved) > 0 {
				*sniffdata = append(*sniffdata, fmt.Sprintf("{\"resp_body\":%s}", respBodySaved))
			}
		} else {
			*sniffdata = append(*sniffdata, colorizeHTTP(reqt.Request, rest.Response, &reqBodySaved, &respBodySaved, id, true, p.body, p.nocolor))
		}
	case *layers.TLSMessage:
		var chs *layers.TLSClientHello
		var shs *layers.TLSServerHello
		hsrec := reqt.Records[0]                         // len(Records) > 0 after dispatch
		if hsrec.ContentType == layers.HandshakeTLSVal { // TODO: add more cases, parse all records
			switch parser := layers.HSTLSParserByType(hsrec.Data[0]).(type) {
			case *layers.TLSClientHello:
				err := parser.ParseHS(hsrec.Data)
				if err != nil {
					return err
				}
				chs = parser
			}
		}
		rest := resp.(*layers.TLSMessage)
		hsrec = rest.Records[0]
		if hsrec.ContentType == layers.HandshakeTLSVal {
			switch parser := layers.HSTLSParserByType(hsrec.Data[0]).(type) {
			case *layers.TLSServerHello:
				err := parser.ParseHS(hsrec.Data)
				if err != nil {
					return err
				}
				shs = parser
			}
		}
		if chs != nil && shs != nil {
			if p.json {
				j1, err := json.Marshal(chs)
				if err != nil {
					return err
				}
				j2, err := json.Marshal(shs)
				if err != nil {
					return err
				}
				*sniffdata = append(*sniffdata, string(j1), string(j2))
			} else {
				*sniffdata = append(*sniffdata, colorizeTLS(chs, shs, id, p.nocolor))
			}
		}
	case *layers.DNSMessage:
		rest := resp.(*layers.DNSMessage)
		if p.json {
			j1, err := json.Marshal(reqt)
			if err != nil {
				return err
			}
			j2, err := json.Marshal(rest)
			if err != nil {
				return err
			}
			*sniffdata = append(*sniffdata, string(j1), string(j2))
		} else {
			*sniffdata = append(*sniffdata, colorizeDNS(reqt, rest, id, p.nocolor))
		}
	}
	return nil
}

func (p *Proxy) sniffreporter(wg *sync.WaitGroup, sniffdata *[]string, reqChan, respChan <-chan layers.Layer, id string) {
	defer wg.Done()
	sniffdatalen := len(*sniffdata)
	var reqTLSQueue, respTLSQueue, reqHTTPQueue, respHTTPQueue, reqDNSQueue, respDNSQueue []layers.Layer
	for {
		select {
		case req, ok := <-reqChan:
			if !ok {
				return
			} else {
				switch req.(type) {
				case *layers.TLSMessage:
					reqTLSQueue = append(reqTLSQueue, req)
				case *layers.HTTPMessage:
					reqHTTPQueue = append(reqHTTPQueue, req)
				case *layers.DNSMessage:
					reqDNSQueue = append(reqDNSQueue, req)
				}
			}
		case resp, ok := <-respChan:
			if !ok {
				return
			} else {
				switch resp.(type) {
				case *layers.TLSMessage:
					// request comes first or response arrived first
					if len(reqTLSQueue) > 0 || len(respTLSQueue) == 0 {
						respTLSQueue = append(respTLSQueue, resp)
						// remove unmatched response if still no requests
					} else if len(reqTLSQueue) == 0 && len(respTLSQueue) == 1 {
						respTLSQueue = respTLSQueue[1:]
					}
				case *layers.HTTPMessage:
					if len(reqHTTPQueue) > 0 || len(respHTTPQueue) == 0 {
						respHTTPQueue = append(respHTTPQueue, resp)
					} else if len(reqHTTPQueue) == 0 && len(respHTTPQueue) == 1 {
						respHTTPQueue = respHTTPQueue[1:]
					}
				case *layers.DNSMessage:
					if len(reqDNSQueue) > 0 || len(respDNSQueue) == 0 {
						respDNSQueue = append(respDNSQueue, resp)
					} else if len(reqDNSQueue) == 0 && len(respDNSQueue) == 1 {
						respDNSQueue = respDNSQueue[1:]
					}
				}
			}
		}
		if len(reqHTTPQueue) > 0 && len(respHTTPQueue) > 0 {
			req := reqHTTPQueue[0]
			resp := respHTTPQueue[0]
			reqHTTPQueue = reqHTTPQueue[1:]
			respHTTPQueue = respHTTPQueue[1:]

			err := p.gatherSniffData(req, resp, sniffdata, id)
			if err == nil && len(*sniffdata) > sniffdatalen {
				if p.json {
					p.snifflogger.Log().Msg(fmt.Sprintf("[%s]", strings.Join(*sniffdata, ",")))
				} else {
					p.snifflogger.Log().Msg(strings.Join(*sniffdata, "\n"))
				}
			}
			*sniffdata = (*sniffdata)[:sniffdatalen]
		}
		if len(reqTLSQueue) > 0 && len(respTLSQueue) > 0 {
			req := reqTLSQueue[0]
			resp := respTLSQueue[0]
			reqTLSQueue = reqTLSQueue[1:]
			respTLSQueue = respTLSQueue[1:]

			err := p.gatherSniffData(req, resp, sniffdata, id)
			if err == nil && len(*sniffdata) > sniffdatalen {
				if p.json {
					p.snifflogger.Log().Msg(fmt.Sprintf("[%s]", strings.Join(*sniffdata, ",")))
				} else {
					p.snifflogger.Log().Msg(strings.Join(*sniffdata, "\n"))
				}
			}
			*sniffdata = (*sniffdata)[:sniffdatalen]
		}
		if len(reqDNSQueue) > 0 && len(respDNSQueue) > 0 {
			req := reqDNSQueue[0]
			resp := respDNSQueue[0]
			reqDNSQueue = reqDNSQueue[1:]
			respDNSQueue = respDNSQueue[1:]

			err := p.gatherSniffData(req, resp, sniffdata, id)
			if err == nil && len(*sniffdata) > sniffdatalen {
				if p.json {
					p.snifflogger.Log().Msg(fmt.Sprintf("[%s]", strings.Join(*sniffdata, ",")))
				} else {
					p.snifflogger.Log().Msg(strings.Join(*sniffdata, "\n"))
				}
			}
			*sniffdata = (*sniffdata)[:sniffdatalen]
		}
	}
}

func dispatch(data []byte) (layers.Layer, error) {
	// TODO: check if it is http or tls beforehand
	h := &layers.HTTPMessage{}
	if err := h.Parse(data); err == nil && !h.IsEmpty() {
		return h, nil
	}
	m := &layers.TLSMessage{}
	if err := m.Parse(data); err == nil && len(m.Records) > 0 {
		return m, nil
	}
	return nil, fmt.Errorf("failed sniffing traffic")
}

func (p *Proxy) transferHTTP2(
	wg *sync.WaitGroup,
	w http.ResponseWriter,
	r *http.Request,
	dst net.Conn,
	destName, srcName string,
	reqChan, respChan chan<- layers.Layer,
) {
	var writtenSrcDst, writtenDstSrc atomic.Int64
	defer func() {
		p.logger.Debug().Msgf("Copied %s from %s to %s", network.PrettifyBytes(writtenSrcDst.Load()), srcName, destName)
		p.logger.Debug().Msgf("Copied %s from %s to %s", network.PrettifyBytes(writtenDstSrc.Load()), destName, srcName)
	}()

	ctx := r.Context()
	flusher := w.(http.Flusher)

	go func() {
		defer wg.Done()
		defer dst.Close()
		buf := make([]byte, 32*1024)
		for {
			nr, er := r.Body.Read(buf)
			if nr > 0 {
				ewd := dst.SetWriteDeadline(time.Now().Add(writeTimeout))
				if ewd != nil {
					if !errors.Is(ewd, net.ErrClosed) {
						p.logger.Error().Err(ewd).Msgf("Error during copy from %s to %s: ", srcName, destName)
					}
					return
				}
				if p.sniff {
					l, err := dispatch(buf[0:nr])
					if err == nil {
						reqChan <- l
					}
				}
				nw, ew := dst.Write(buf[:nr])
				if nw < 0 || nr < nw {
					nw = 0
					if ew == nil {
						ew = errInvalidWrite
					}
				}
				writtenSrcDst.Add(int64(nw))
				if ew != nil {
					if ne, ok := ew.(net.Error); ok && ne.Timeout() {
						return
					}
					if errors.Is(ew, net.ErrClosed) {
						return
					}
					p.logger.Error().Err(ew).Msgf("Error during copy from %s to %s: ", srcName, destName)
					return
				}
				if nr != nw {
					p.logger.Error().Err(io.ErrShortWrite).Msgf("Error during copy from %s to %s: ", srcName, destName)
					return
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-p.closeConn:
				return
			default:
			}
			if er != nil {
				if errors.Is(er, os.ErrDeadlineExceeded) {
					continue
				}
				if ne, ok := er.(net.Error); ok && ne.Timeout() {
					continue
				}
				if errors.Is(er, net.ErrClosed) {
					return
				}
				if errors.Is(er, io.EOF) {
					return
				}
				p.logger.Error().Err(er).Msgf("Error during copy from %s to %s: ", srcName, destName)
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			erd := dst.SetReadDeadline(time.Now().Add(readTimeout))
			if erd != nil {
				if errors.Is(erd, net.ErrClosed) {
					return
				}
				p.logger.Error().Err(erd).Msgf("Error during copy from %s to %s: ", destName, srcName)
				return
			}
			nr, er := dst.Read(buf)
			if nr > 0 {
				if p.sniff {
					l, err := dispatch(buf[0:nr])
					if err == nil {
						respChan <- l
					}
				}
				nw, ew := w.Write(buf[:nr])
				if nw < 0 || nr < nw {
					nw = 0
					if ew == nil {
						ew = errInvalidWrite
					}
				}
				writtenDstSrc.Add(int64(nw))
				if ew != nil {
					if ne, ok := ew.(net.Error); ok && ne.Timeout() {
						return
					}
					if errors.Is(ew, net.ErrClosed) {
						return
					}
					p.logger.Error().Err(ew).Msgf("Error during copy from %s to %s: ", destName, srcName)
					return
				}
				if nr != nw {
					p.logger.Error().Err(io.ErrShortWrite).Msgf("Error during copy from %s to %s: ", destName, srcName)
					return
				}
				flusher.Flush()
			}
			select {
			case <-ctx.Done():
				return
			case <-p.closeConn:
				return
			default:
			}
			if er != nil {
				if errors.Is(er, os.ErrDeadlineExceeded) {
					continue
				}
				if ne, ok := er.(net.Error); ok && ne.Timeout() {
					continue
				}
				if errors.Is(er, net.ErrClosed) {
					return
				}
				if errors.Is(er, io.EOF) {
					return
				}
				p.logger.Error().Err(er).Msgf("Error during copy from %s to %s: ", destName, srcName)
				return
			}
		}
	}()
}

func (p *Proxy) copyWithTimeout(dst net.Conn, src net.Conn, msgChan chan<- layers.Layer) (written int64, err error) {
	buf := make([]byte, 32*1024)
readLoop:
	for {
		select {
		case <-p.closeConn:
			break readLoop
		default:
			erd := src.SetReadDeadline(time.Now().Add(readTimeout))
			if erd != nil {
				if errors.Is(erd, net.ErrClosed) {
					break readLoop
				}
				err = erd
				break readLoop
			}
			nr, er := src.Read(buf)
			if nr > 0 {
				ewd := dst.SetWriteDeadline(time.Now().Add(writeTimeout))
				if ewd != nil {
					if errors.Is(ewd, net.ErrClosed) {
						break readLoop
					}
					err = ewd
					break readLoop
				}
				if p.sniff {
					l, err := dispatch(buf[0:nr])
					if err == nil {
						msgChan <- l
					}
				}
				nw, ew := dst.Write(buf[0:nr])
				if nw < 0 || nr < nw {
					nw = 0
					if ew == nil {
						ew = errInvalidWrite
					}
				}
				// TODO: detect overflow and convert to megabytes/gigabytes
				written += int64(nw)
				if ew != nil {
					if ne, ok := ew.(net.Error); ok && ne.Timeout() {
						break readLoop
					}
					if errors.Is(ew, net.ErrClosed) {
						break readLoop
					}
				}
				if nr != nw {
					err = io.ErrShortWrite
					break readLoop
				}
			}
			if er != nil {
				if ne, ok := er.(net.Error); ok && ne.Timeout() {
					continue // support long-lived connections (SSE, WebSockets, etc)
				}
				if errors.Is(er, net.ErrClosed) {
					break readLoop
				}
				if errors.Is(er, io.EOF) {
					break readLoop
				}
				err = er
				break readLoop
			}
		}
	}
	return written, err
}

func (p *Proxy) replayCheck(next http.Handler) http.Handler {
	// https://quic-go.net/docs/http3/server/#0-rtt
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !r.TLS.HandshakeComplete {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.WriteHeader(http.StatusTooEarly)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (p *Proxy) proxyAuth(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Proxy-Authorization")
		r.Header.Del("Proxy-Authorization")
		username, password, ok := parseProxyAuth(auth)
		if ok {
			usernameHash := sha256.Sum256([]byte(username))
			passwordHash := sha256.Sum256([]byte(password))
			expectedUsernameHash := sha256.Sum256([]byte(p.user))
			expectedPasswordHash := sha256.Sum256([]byte(p.pass))

			usernameMatch := (subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1)
			passwordMatch := (subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1)

			if usernameMatch && passwordMatch {
				next.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("Proxy-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		w.WriteHeader(http.StatusProxyAuthRequired)
	})
}

func (p *Proxy) runRuleCmd(rule string) {
	var setex string
	if p.debug {
		setex = "set -ex"
	}
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
    %s
    %s
    `, setex, rule))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if !p.debug {
		cmd.Stdout = nil
	}
	if err := cmd.Run(); err != nil {
		p.logger.Error().Err(err).Msgf("[%s] Failed running rule command", p.tproxyMode)
	}
	p.dump.WriteString(rule)
}

func (p *Proxy) newSOCKSDialer(address string, auth *auth, forward contextDialer, network string) (contextDialer, error) {
	if p.socks4enabled {
		return newSOCKS4Dialer(address, auth, forward, network)
	}
	return newSOCKS5Dialer(address, auth, forward, network)
}

func (p *Proxy) applyCommonRedirectRules(opts map[string]string) {
	// TODO: add support for nftables
	var setex string
	if p.debug {
		setex = "set -ex"
	}
	if p.tproxyMode == "tproxy" {
		cmdClear0 := `
iptables -t mangle -F DIVERT 2>/dev/null || true
iptables -t mangle -X DIVERT 2>/dev/null || true

ip rule del fwmark 1 lookup 100 2>/dev/null || true
ip route flush table 100 2>/dev/null || true
`
		p.runRuleCmd(cmdClear0)
		if p.ipv6enabled {
			cmdClear1 := `
ip6tables -t mangle -F DIVERT 2>/dev/null || true
ip6tables -t mangle -X DIVERT 2>/dev/null || true

ip -6 rule del fwmark 1 lookup 100 2>/dev/null || true
ip -6 route flush table 100 2>/dev/null || true
`
			p.runRuleCmd(cmdClear1)
		}
		cmdInit0 := `
ip rule add fwmark 1 lookup 100 2>/dev/null || true
ip route add local 0.0.0.0/0 dev lo table 100 2>/dev/null || true

iptables -t mangle -N DIVERT 2>/dev/null || true
iptables -t mangle -F DIVERT 2>/dev/null || true
iptables -t mangle -A DIVERT -j MARK --set-mark 1
iptables -t mangle -A DIVERT -j ACCEPT
`
		p.runRuleCmd(cmdInit0)
		if p.ipv6enabled {
			cmdInit1 := `
ip -6 rule add fwmark 1 lookup 100 2>/dev/null || true
ip -6 route add local ::/0 dev lo table 100 2>/dev/null || true

ip6tables -t mangle -N DIVERT 2>/dev/null || true
ip6tables -t mangle -F DIVERT 2>/dev/null || true
ip6tables -t mangle -A DIVERT -j MARK --set-mark 1
ip6tables -t mangle -A DIVERT -j ACCEPT
`
			p.runRuleCmd(cmdInit1)
		}
	}
	_ = runSysctlOptCmd("net.ipv4.ip_forward", "1", setex, opts, p.debug, &p.dump)
	if p.arpspoofer != nil {
		_ = runSysctlOptCmd("net.ipv4.conf.all.send_redirects", "0", setex, opts, p.debug, &p.dump)
		_ = runSysctlOptCmd(fmt.Sprintf("net.ipv4.conf.%s.send_redirects", p.arpspoofer.Interface().Name), "0", setex, opts, p.debug, &p.dump)
		_ = runSysctlOptCmd("net.ipv4.conf.all.accept_redirects", "0", setex, opts, p.debug, &p.dump)
		_ = runSysctlOptCmd("net.ipv4.conf.default.accept_redirects", "0", setex, opts, p.debug, &p.dump)
	}
	if p.ipv6enabled {
		_ = runSysctlOptCmd("net.ipv6.conf.all.forwarding", "1", setex, opts, p.debug, &p.dump)
		_ = runSysctlOptCmd("net.ipv6.conf.default.forwarding", "1", setex, opts, p.debug, &p.dump)
	}
	if p.ndpspoofer != nil {
		_ = runSysctlOptCmd("net.ipv6.conf.all.accept_ra", "0", setex, opts, p.debug, &p.dump)
		_ = runSysctlOptCmd("net.ipv6.conf.all.accept_redirects", "0", setex, opts, p.debug, &p.dump)
		_ = runSysctlOptCmd("net.ipv6.conf.default.accept_redirects", "0", setex, opts, p.debug, &p.dump)
	}
	_ = runSysctlOptCmd("net.core.rmem_default", "4194304", setex, opts, p.debug, &p.dump)
	_ = runSysctlOptCmd("net.core.wmem_default", "4194304", setex, opts, p.debug, &p.dump)
	_ = runSysctlOptCmd("net.core.rmem_max", "4194304", setex, opts, p.debug, &p.dump)
	_ = runSysctlOptCmd("net.core.wmem_max", "4194304", setex, opts, p.debug, &p.dump)
	_ = runSysctlOptCmd("net.core.netdev_budget", "600", setex, opts, p.debug, &p.dump)
	_ = runSysctlOptCmd("net.core.netdev_budget_usecs", "8000", setex, opts, p.debug, &p.dump)
	_ = runSysctlOptCmd("net.core.netdev_max_backlog", "250000", setex, opts, p.debug, &p.dump)
	_ = runSysctlOptCmd("fs.file-max", "2097152", setex, opts, p.debug, &p.dump)
	cmdClearForward0 := `
iptables -t filter -F GOHPTS 2>/dev/null || true
iptables -t filter -D FORWARD -j GOHPTS  2>/dev/null || true
iptables -t filter -X GOHPTS  2>/dev/null || true
`
	p.runRuleCmd(cmdClearForward0)
	if p.ipv6enabled {
		cmdClearForward1 := `
ip6tables -t filter -F GOHPTS 2>/dev/null || true
ip6tables -t filter -D FORWARD -j GOHPTS  2>/dev/null || true
ip6tables -t filter -X GOHPTS  2>/dev/null || true
`
		p.runRuleCmd(cmdClearForward1)
	}
	cmdForwardFilter0 := fmt.Sprintf(`
iptables -t filter -N GOHPTS 2>/dev/null
iptables -t filter -F GOHPTS
iptables -t filter -A FORWARD -j GOHPTS
iptables -t filter -A GOHPTS -i %s -j ACCEPT
iptables -t filter -A GOHPTS -o %s -j ACCEPT
`,
		p.iface.Name, p.iface.Name)

	p.runRuleCmd(cmdForwardFilter0)
	if p.ipv6enabled {
		cmdForwardFilter1 := fmt.Sprintf(`
ip6tables -t filter -N GOHPTS 2>/dev/null
ip6tables -t filter -F GOHPTS
ip6tables -t filter -A FORWARD -j GOHPTS
ip6tables -t filter -A GOHPTS -i %s -j ACCEPT
ip6tables -t filter -A GOHPTS -o %s -j ACCEPT
`, p.iface.Name, p.iface.Name)
		p.runRuleCmd(cmdForwardFilter1)
		if p.raEnabled {
			cmdForwardFilter2 := `
ip6tables -t filter -A INPUT -p ipv6-icmp --icmpv6-type redirect -j DROP
ip6tables -t filter -A OUTPUT -p ipv6-icmp --icmpv6-type redirect -j DROP
`
			p.runRuleCmd(cmdForwardFilter2)
		}
	}
}

func (p *Proxy) clearCommonRedirectRules(opts map[string]string) error {
	cmdClear0 := `
iptables -t filter -F GOHPTS 2>/dev/null || true
iptables -t filter -D FORWARD -j GOHPTS  2>/dev/null || true
iptables -t filter -X GOHPTS  2>/dev/null || true
`
	p.runRuleCmd(cmdClear0)
	if p.ipv6enabled {
		cmdClear1 := `
ip6tables -t filter -F GOHPTS 2>/dev/null || true
ip6tables -t filter -D FORWARD -j GOHPTS  2>/dev/null || true
ip6tables -t filter -X GOHPTS  2>/dev/null || true
`
		p.runRuleCmd(cmdClear1)
		if p.raEnabled {
			cmdClear2 := `
ip6tables -t filter -D INPUT -p ipv6-icmp --icmpv6-type redirect -j DROP
ip6tables -t filter -D OUTPUT -p ipv6-icmp --icmpv6-type redirect -j DROP
`
			p.runRuleCmd(cmdClear2)
		}
	}
	cmds := make([]string, 0, len(opts))
	for _, cmd := range slices.Sorted(maps.Keys(opts)) {
		cmds = append(cmds, fmt.Sprintf("sysctl -w %s=%q", cmd, opts[cmd]))
	}
	cmdRestoreOpts := strings.Join(cmds, "\n")
	p.runRuleCmd(cmdRestoreOpts)
	if p.tproxyMode == "tproxy" {
		cmd0 := `
iptables -t mangle -F DIVERT 2>/dev/null || true
iptables -t mangle -X DIVERT 2>/dev/null || true

ip rule del fwmark 1 lookup 100 2>/dev/null || true
ip route flush table 100 2>/dev/null || true
`
		p.runRuleCmd(cmd0)
		if p.ipv6enabled {
			cmd1 := `
ip6tables -t mangle -F DIVERT 2>/dev/null || true
ip6tables -t mangle -X DIVERT 2>/dev/null || true

ip -6 rule del fwmark 1 lookup 100 2>/dev/null || true
ip -6 route flush table 100 2>/dev/null || true
`
			p.runRuleCmd(cmd1)
		}
	}
	return nil
}
