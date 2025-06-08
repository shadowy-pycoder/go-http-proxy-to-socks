package gohpts

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/rs/zerolog"
	"golang.org/x/net/proxy"
)

const (
	readTimeout              time.Duration = 10 * time.Second
	writeTimeout             time.Duration = 10 * time.Second
	timeout                  time.Duration = 10 * time.Second
	hopTimeout               time.Duration = 3 * time.Second
	flushTimeout             time.Duration = 10 * time.Millisecond
	availProxyUpdateInterval time.Duration = 30 * time.Second
	kbSize                   int64         = 1000
	rrIndexMax               uint32        = 1_000_000
)

var supportedChainTypes = []string{"strict", "dynamic", "random", "round_robin"}

// Hop-by-hop headers
// https://datatracker.ietf.org/doc/html/rfc2616#section-13.5.1
var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te", // canonicalized version of "TE"
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func delHopHeaders(header http.Header) {
	for _, h := range hopHeaders {
		header.Del(h)
	}
}

// delConnectionHeaders removes hop-by-hop headers listed in the "Connection" header
// https://datatracker.ietf.org/doc/html/rfc7230#section-6.1
func delConnectionHeaders(h http.Header) {
	for _, f := range h["Connection"] {
		for _, sf := range strings.Split(f, ",") {
			if sf = strings.TrimSpace(sf); sf != "" {
				h.Del(sf)
			}
		}
	}
}

func appendHostToXForwardHeader(header http.Header, host string) {
	if prior, ok := header["X-Forwarded-For"]; ok {
		host = strings.Join(prior, ", ") + ", " + host
	}
	header.Set("X-Forwarded-For", host)
}

func isLocalAddress(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	if ip != nil {
		return ip.IsLoopback()
	}
	host = strings.ToLower(host)
	return strings.HasSuffix(host, ".local") || host == "localhost"
}

type proxyApp struct {
	httpServer     *http.Server
	sockClient     *http.Client
	httpClient     *http.Client
	sockDialer     proxy.Dialer
	logger         *zerolog.Logger
	certFile       string
	keyFile        string
	httpServerAddr string
	proxychain     *proxyChainConfig
	rrIndex        uint32
	rrIndexReset   uint32

	mu             sync.RWMutex
	availProxyList []proxyEntry
}

func (p *proxyApp) printProxyChain(pc []proxyEntry) string {
	var sb strings.Builder
	sb.WriteString("client -> ")
	sb.WriteString(p.httpServerAddr)
	sb.WriteString(" -> ")
	for _, pe := range pc {
		sb.WriteString(pe.String())
		sb.WriteString(" -> ")
	}
	sb.WriteString("target")
	return sb.String()
}

func (p *proxyApp) updateSocksList() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.availProxyList = p.availProxyList[:0]
	var base proxy.Dialer = &net.Dialer{Timeout: timeout}
	var dialer proxy.Dialer
	var err error
	failed := 0
	chainType := p.proxychain.Chain.Type
	for _, pr := range p.proxychain.ProxyList {
		auth := proxy.Auth{
			User:     pr.Username,
			Password: pr.Password,
		}
		dialer, err = proxy.SOCKS5("tcp", pr.Address, &auth, base)
		if err != nil {
			p.logger.Error().Err(err).Msgf("[%s] Unable to create SOCKS5 dialer %s", chainType, pr.Address)
			failed++
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), hopTimeout)
		defer cancel()
		conn, err := dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", pr.Address)
		if err != nil && !errors.Is(err, io.EOF) { // check for EOF to include localhost SOCKS5 in the chain
			p.logger.Error().Err(err).Msgf("[%s] Unable to connect to %s", chainType, pr.Address)
			failed++
			continue
		} else {
			if conn != nil {
				conn.Close()
			}
			p.availProxyList = append(p.availProxyList, proxyEntry{Address: pr.Address, Username: pr.Username, Password: pr.Password})
			break
		}
	}
	if failed == len(p.proxychain.ProxyList) {
		p.logger.Error().Err(err).Msgf("[%s] No SOCKS5 Proxy available", chainType)
		return
	}
	currentDialer := dialer
	for _, pr := range p.proxychain.ProxyList[failed+1:] {
		auth := proxy.Auth{
			User:     pr.Username,
			Password: pr.Password,
		}
		dialer, err = proxy.SOCKS5("tcp", pr.Address, &auth, currentDialer)
		if err != nil {
			p.logger.Error().Err(err).Msgf("[%s] Unable to create SOCKS5 dialer %s", chainType, pr.Address)
			continue
		}
		// https://github.com/golang/go/issues/37549#issuecomment-1178745487
		ctx, cancel := context.WithTimeout(context.Background(), hopTimeout)
		defer cancel()
		conn, err := dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", pr.Address)
		if err != nil {
			p.logger.Error().Err(err).Msgf("[%s] Unable to connect to %s", chainType, pr.Address)
			continue
		}
		conn.Close()
		currentDialer = dialer
		p.availProxyList = append(p.availProxyList, proxyEntry{Address: pr.Address, Username: pr.Username, Password: pr.Password})
	}
	p.logger.Debug().Msgf("[%s] Available SOCKS5 Proxy [%d/%d]: %s", chainType,
		len(p.availProxyList), len(p.proxychain.ProxyList), p.printProxyChain(p.availProxyList))
}

// https://www.calhoun.io/how-to-shuffle-arrays-and-slices-in-go/
func shuffle(vals []proxyEntry) {
	r := rand.New(rand.NewSource(time.Now().Unix()))
	for len(vals) > 0 {
		n := len(vals)
		randIndex := r.Intn(n)
		vals[n-1], vals[randIndex] = vals[randIndex], vals[n-1]
		vals = vals[:n-1]
	}
}

func (p *proxyApp) getSocks() (proxy.Dialer, *http.Client, error) {
	if p.proxychain == nil {
		return p.sockDialer, p.sockClient, nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	chainType := p.proxychain.Chain.Type
	var chainLength int
	if p.proxychain.Chain.Length > len(p.availProxyList) || p.proxychain.Chain.Length <= 0 {
		chainLength = len(p.availProxyList)
	} else {
		chainLength = p.proxychain.Chain.Length
	}
	copyProxyList := make([]proxyEntry, 0, len(p.availProxyList))
	switch chainType {
	case "strict", "dynamic":
		copyProxyList = p.availProxyList
	case "random":
		copy(copyProxyList, p.availProxyList)
		shuffle(copyProxyList)
		copyProxyList = copyProxyList[:chainLength]
	case "round_robin":
		var start uint32
		for {
			start = atomic.LoadUint32(&p.rrIndex)
			next := start + 1
			if start >= p.rrIndexReset {
				p.logger.Debug().Msg("Resetting round robin index")
				next = 0
			}
			if atomic.CompareAndSwapUint32(&p.rrIndex, start, next) {
				break
			}
		}
		startIdx := int(start % uint32(len(p.availProxyList)))
		for i := 0; i < chainLength; i++ {
			idx := (startIdx + i) % len(p.availProxyList)
			copyProxyList = append(copyProxyList, p.availProxyList[idx])
		}
	default:
		p.logger.Fatal().Msg("Unreachable")
	}
	if len(copyProxyList) == 0 {
		p.logger.Error().Msgf("[%s] No SOCKS5 Proxy available", chainType)
		return nil, nil, fmt.Errorf("no socks5 proxy available")
	}
	if p.proxychain.Chain.Type == "strict" && len(copyProxyList) != len(p.proxychain.ProxyList) {
		p.logger.Error().Msgf("[%s] Not all SOCKS5 Proxy available", chainType)
		return nil, nil, fmt.Errorf("not all socks5 proxy available")
	}
	var dialer proxy.Dialer = &net.Dialer{Timeout: timeout}
	var err error
	for _, pr := range copyProxyList {
		auth := proxy.Auth{
			User:     pr.Username,
			Password: pr.Password,
		}
		dialer, err = proxy.SOCKS5("tcp", pr.Address, &auth, dialer)
		if err != nil {
			p.logger.Error().Err(err).Msgf("[%s] Unable to create SOCKS5 dialer %s", &chainType, pr.Address)
			return nil, nil, err
		}
	}
	socks := &http.Client{
		Transport: &http.Transport{
			Dial: dialer.Dial,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	p.logger.Debug().Msgf("[%s] Current chain: %s", chainType, p.printProxyChain(copyProxyList))
	return dialer, socks, nil
}

func (p *proxyApp) doReq(w http.ResponseWriter, r *http.Request, sock *http.Client) *http.Response {
	var (
		resp   *http.Response
		err    error
		msg    string
		client *http.Client
	)
	if sock != nil {
		client = sock
		msg = "Connection to SOCKS5 server failed"
	} else {
		client = p.httpClient
		msg = "Connection failed"
	}
	resp, err = client.Do(r)
	if err != nil {
		p.logger.Error().Err(err).Msg(msg)
		w.WriteHeader(http.StatusServiceUnavailable)
		return nil
	}
	if resp == nil {
		p.logger.Error().Msg(msg)
		w.WriteHeader(http.StatusServiceUnavailable)
		return nil
	}
	return resp
}

func (p *proxyApp) handleForward(w http.ResponseWriter, r *http.Request) {

	req, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		p.logger.Error().Err(err).Msgf("Error during NewRequest() %s: %s", r.URL.String(), err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	req.RequestURI = ""
	delConnectionHeaders(r.Header)
	delHopHeaders(r.Header)
	copyHeader(req.Header, r.Header)
	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		appendHostToXForwardHeader(req.Header, clientIP)
	}
	var resp *http.Response
	var chunked bool
	p.httpClient.Timeout = timeout
	if isLocalAddress(r.Host) {
		resp = p.doReq(w, req, nil)
		if resp == nil {
			return
		}
		if slices.Contains(resp.TransferEncoding, "chunked") {
			chunked = true
			p.httpClient.Timeout = 0
			resp.Body.Close()
			resp = p.doReq(w, req, nil)
			if resp == nil {
				return
			}
		}
	} else {
		_, sockClient, err := p.getSocks()
		if err != nil {
			p.logger.Error().Err(err).Msg("Failed getting SOCKS5 client")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		resp = p.doReq(w, req, sockClient)
		if resp == nil {
			return
		}
		if slices.Contains(resp.TransferEncoding, "chunked") {
			chunked = true
			sockClient.Timeout = 0
			resp.Body.Close()
			resp = p.doReq(w, req, sockClient)
			if resp == nil {
				return
			}
		}
	}
	defer resp.Body.Close()
	done := make(chan bool)
	if chunked {
		rc := http.NewResponseController(w)
		go func() {
			for {
				select {
				case <-time.Tick(flushTimeout):
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
				case <-done:
					return
				}
			}
		}()
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
	n, err := io.Copy(w, resp.Body)
	if err != nil {
		p.logger.Error().Err(err).Msgf("Error during Copy() %s: %s", r.URL.String(), err)
		close(done)
		return
	}
	var written string
	if n < kbSize {
		written = fmt.Sprintf("%dB", n)
	} else {
		written = fmt.Sprintf("%dKB", n/kbSize)
	}
	if chunked {
		written = fmt.Sprintf("%s - chunked", written)
	}
	p.logger.Debug().Msgf("%s - %s - %s - %d - %s", r.Proto, r.Method, r.Host, resp.StatusCode, written)
	if len(resp.Trailer) == announcedTrailers {
		copyHeader(w.Header(), resp.Trailer)
	}
	for key, values := range resp.Trailer {
		key = http.TrailerPrefix + key
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	close(done)
}

func (p *proxyApp) handleTunnel(w http.ResponseWriter, r *http.Request) {
	var dstConn net.Conn
	var err error
	if isLocalAddress(r.Host) {
		dstConn, err = net.DialTimeout("tcp", r.Host, timeout)
		if err != nil {
			p.logger.Error().Err(err).Msgf("Failed connecting to %s", r.Host)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
	} else {
		sockDialer, _, err := p.getSocks()
		if err != nil {
			p.logger.Error().Err(err).Msg("Failed getting SOCKS5 client")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		dstConn, err = sockDialer.Dial("tcp", r.Host)
		if err != nil {
			p.logger.Error().Err(err).Msgf("Failed connecting to %s", r.Host)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
	}
	defer dstConn.Close()
	w.WriteHeader(http.StatusOK)

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

	dstConnStr := fmt.Sprintf("%s->%s->%s", dstConn.LocalAddr().String(), dstConn.RemoteAddr().String(), r.Host)
	srcConnStr := fmt.Sprintf("%s->%s", srcConn.LocalAddr().String(), srcConn.RemoteAddr().String())

	p.logger.Debug().Msgf("%s - %s - %s", r.Proto, r.Method, r.Host)
	p.logger.Debug().Msgf("src: %s - dst: %s", srcConnStr, dstConnStr)

	var wg sync.WaitGroup
	wg.Add(2)
	go p.transfer(&wg, dstConn, srcConn, dstConnStr, srcConnStr)
	go p.transfer(&wg, srcConn, dstConn, srcConnStr, dstConnStr)
	wg.Wait()
}

func (p *proxyApp) transfer(wg *sync.WaitGroup, destination io.Writer, source io.Reader, destName, srcName string) {
	defer wg.Done()
	n, err := io.Copy(destination, source)
	if err != nil {
		p.logger.Error().Err(err).Msgf("Error during copy from %s to %s: %v", srcName, destName, err)
	}
	var written string
	if n < kbSize {
		written = fmt.Sprintf("%dB", n)
	} else {
		written = fmt.Sprintf("%dKB", n/kbSize)
	}
	p.logger.Debug().Msgf("copied %s from %s to %s", written, srcName, destName)
}

func (p *proxyApp) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			p.handleTunnel(w, r)
		} else {
			p.handleForward(w, r)
		}
	}
}

func (p *proxyApp) Run() {
	done := make(chan bool)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	if p.proxychain != nil {
		chainType := p.proxychain.Chain.Type
		go func() {
			for {
				p.logger.Debug().Msgf("[%s] Updating available proxy", chainType)
				p.updateSocksList()
				time.Sleep(availProxyUpdateInterval)
			}
		}()
	}
	go func() {
		<-quit
		p.logger.Info().Msg("Server is shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

		defer cancel()
		p.httpServer.SetKeepAlivesEnabled(false)
		if err := p.httpServer.Shutdown(ctx); err != nil {
			p.logger.Fatal().Err(err).Msg("Could not gracefully shutdown the server")
		}
		close(done)
	}()
	p.httpServer.Handler = p.handler()
	if p.certFile != "" && p.keyFile != "" {
		if err := p.httpServer.ListenAndServeTLS(p.certFile, p.keyFile); err != nil && err != http.ErrServerClosed {
			p.logger.Fatal().Err(err).Msg("Unable to start HTTPS server")
		}
	} else {
		if err := p.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			p.logger.Fatal().Err(err).Msg("Unable to start HTTP server")
		}
	}
	<-done
	p.logger.Info().Msg("Server stopped")
}

type Config struct {
	AddrHTTP       string
	AddrSOCKS      string
	Debug          bool
	Json           bool
	User           string
	Pass           string
	CertFile       string
	KeyFile        string
	ProxyChainPath string
}
type logWriter struct {
}

func (writer logWriter) Write(bytes []byte) (int, error) {
	return fmt.Print(fmt.Sprintf("%s | ERROR | %s", time.Now().Format(time.RFC3339), string(bytes)))
}

type jsonLogWriter struct {
}

func (writer jsonLogWriter) Write(bytes []byte) (int, error) {
	return fmt.Print(fmt.Sprintf("{\"level\":\"error\",\"time\":\"%s\",\"message\":\"%s\"}\n",
		time.Now().Format(time.RFC3339), strings.TrimRight(string(bytes), "\n")))
}

type proxyEntry struct {
	Address  string `yaml:"address"`
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
}

func (pe proxyEntry) String() string {
	return pe.Address
}

type proxyChainConfig struct {
	Chain struct {
		Type   string `yaml:"type"`
		Length int    `yaml:"length"`
	} `yaml:"chain"`
	ProxyList []proxyEntry `yaml:"proxy_list"`
}

func New(conf *Config) *proxyApp {
	var logger zerolog.Logger
	var p proxyApp
	if conf.Json {
		log.SetFlags(0)
		log.SetOutput(new(jsonLogWriter))
		logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
	} else {
		log.SetFlags(0)
		log.SetOutput(new(logWriter))
		output := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339, NoColor: true}
		output.FormatLevel = func(i interface{}) string {
			return strings.ToUpper(fmt.Sprintf("| %-6s|", i))
		}
		logger = zerolog.New(output).With().Timestamp().Logger()
	}

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if conf.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	p.logger = &logger
	if conf.ProxyChainPath != "" {
		var pcconf proxyChainConfig
		yamlFile, err := os.ReadFile(filepath.FromSlash(conf.ProxyChainPath))
		if err != nil {
			p.logger.Fatal().Err(err).Msg("[proxychain config] Parsing failed")
		}
		err = yaml.Unmarshal(yamlFile, &pcconf)
		if err != nil {
			p.logger.Fatal().Err(err).Msg("[proxychain config] Parsing failed")
		}
		p.proxychain = &pcconf
		p.availProxyList = make([]proxyEntry, 0, len(p.proxychain.ProxyList))
	} else {
		p.proxychain = nil
	}

	if p.proxychain != nil {
		if len(p.proxychain.ProxyList) == 0 {
			p.logger.Fatal().Msg("[proxychain config] Proxy list is empty")
		}
		seen := make(map[string]struct{})
		for _, pr := range p.proxychain.ProxyList {
			var addr string
			if strings.HasPrefix(pr.Address, ":") {
				addr = fmt.Sprintf("127.0.0.1%s", pr.Address)
			} else {
				addr = pr.Address
			}
			if _, ok := seen[addr]; !ok {
				seen[addr] = struct{}{}
			} else {
				p.logger.Fatal().Msgf("[proxychain config] Duplicate entry `%s`", addr)
			}
		}
		chainType := p.proxychain.Chain.Type
		if !slices.Contains(supportedChainTypes, chainType) {
			p.logger.Fatal().Msgf("[proxychain config] Chain type `%s` is not supported", chainType)
		}
		p.rrIndexReset = rrIndexMax
	} else {
		auth := proxy.Auth{
			User:     conf.User,
			Password: conf.Pass,
		}
		dialer, err := proxy.SOCKS5("tcp", conf.AddrSOCKS, &auth, &net.Dialer{Timeout: timeout})
		if err != nil {
			p.logger.Fatal().Err(err).Msg("Unable to create SOCKS5 dialer")
		}
		p.sockDialer = dialer
		socks := &http.Client{
			Transport: &http.Transport{
				Dial: dialer.Dial,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		p.sockClient = socks
	}
	hs := &http.Server{
		Addr:           conf.AddrHTTP,
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
			},
		},
	}
	hs.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	hs.Protocols.SetHTTP1(true)
	p.httpServer = hs
	p.httpServerAddr = conf.AddrHTTP
	if strings.HasPrefix(p.httpServerAddr, ":") {
		p.httpServerAddr = fmt.Sprintf("127.0.0.1%s", p.httpServerAddr)
	}
	hc := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	p.httpClient = hc
	if p.proxychain != nil {
		p.logger.Info().Msgf("SOCKS5 proxy chain [%s]: %s", p.proxychain.Chain.Type, p.printProxyChain(p.proxychain.ProxyList))
	} else {
		p.logger.Info().Msgf("SOCKS5 Proxy: %s", conf.AddrSOCKS)
	}
	if conf.CertFile != "" && conf.KeyFile != "" {
		p.certFile = conf.CertFile
		p.keyFile = conf.KeyFile
		p.logger.Info().Msgf("HTTPS Proxy: %s", p.httpServerAddr)
	} else {
		p.logger.Info().Msgf("HTTP Proxy: %s", p.httpServerAddr)
	}
	return &p
}
