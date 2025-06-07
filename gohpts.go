package gohpts

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/net/proxy"
)

const (
	readTimeout  time.Duration = 10 * time.Second
	writeTimeout time.Duration = 10 * time.Second
	timeout      time.Duration = 10 * time.Second
	flushTimeout time.Duration = 10 * time.Millisecond
	kbSize       int64         = 1000
)

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
	httpServer *http.Server
	sockClient *http.Client
	httpClient *http.Client
	sockDialer proxy.Dialer
	logger     *zerolog.Logger
	certFile   string
	keyFile    string
}

func (p *proxyApp) doReq(w http.ResponseWriter, r *http.Request, socks bool) *http.Response {
	var (
		resp   *http.Response
		err    error
		msg    string
		client *http.Client
	)
	if socks {
		client = p.sockClient
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
	p.sockClient.Timeout = timeout
	if isLocalAddress(r.Host) {
		resp = p.doReq(w, req, false)
		if resp == nil {
			return
		}
		if slices.Contains(resp.TransferEncoding, "chunked") {
			chunked = true
			p.httpClient.Timeout = 0
			p.sockClient.Timeout = 0
			resp.Body.Close()
			resp = p.doReq(w, req, false)
			if resp == nil {
				return
			}
		}
	} else {
		resp = p.doReq(w, req, true)
		if resp == nil {
			return
		}
		if slices.Contains(resp.TransferEncoding, "chunked") {
			chunked = true
			p.httpClient.Timeout = 0
			p.sockClient.Timeout = 0
			resp.Body.Close()
			resp = p.doReq(w, req, true)
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
		dstConn, err = p.sockDialer.Dial("tcp", r.Host)
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
	AddrHTTP  string
	AddrSOCKS string
	Debug     bool
	Json      bool
	User      string
	Pass      string
	CertFile  string
	KeyFile   string
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

func New(conf *Config) *proxyApp {
	var logger zerolog.Logger
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
	auth := proxy.Auth{
		User:     conf.User,
		Password: conf.Pass,
	}
	dialer, err := proxy.SOCKS5("tcp", conf.AddrSOCKS, &auth, &net.Dialer{Timeout: timeout})
	if err != nil {
		logger.Fatal().Err(err).Msg("Unable to create SOCKS5 dialer")
	}
	socks := &http.Client{
		Transport: &http.Transport{
			Dial: dialer.Dial,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
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
	hc := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	logger.Info().Msgf("SOCKS5 Proxy: %s", conf.AddrSOCKS)
	if conf.CertFile != "" && conf.KeyFile != "" {
		logger.Info().Msgf("HTTPS Proxy: %s", conf.AddrHTTP)
	} else {
		logger.Info().Msgf("HTTP Proxy: %s", conf.AddrHTTP)
	}
	return &proxyApp{
		httpServer: hs,
		sockClient: socks,
		httpClient: hc,
		sockDialer: dialer,
		logger:     &logger,
		certFile:   conf.CertFile,
		keyFile:    conf.KeyFile,
	}
}
