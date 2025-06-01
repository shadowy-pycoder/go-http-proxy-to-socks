package gohpts

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
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

type app struct {
	hs     *http.Server
	sc     *http.Client
	hc     *http.Client
	dialer proxy.Dialer
	logger *zerolog.Logger
}

func (app *app) handleForward(w http.ResponseWriter, r *http.Request) {

	req, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		app.logger.Error().Err(err).Msgf("Error during NewRequest() %s: %s", r.URL.String(), err)
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
	if isLocalAddress(r.Host) {
		resp, err = app.hc.Do(req)
		if err != nil {
			app.logger.Error().Err(err).Msg("Connection failed")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if resp == nil {
			app.logger.Error().Err(err).Msg("Connection failed")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
	} else {
		resp, err = app.sc.Do(req)
		if err != nil {
			app.logger.Error().Err(err).Msg("Connection to SOCKS5 server failed")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if resp == nil {
			app.logger.Error().Err(err).Msg("Connection to SOCKS5 server failed")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
	}
	defer resp.Body.Close()

	delConnectionHeaders(resp.Header)
	delHopHeaders(resp.Header)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	n, err := io.Copy(w, resp.Body)
	if err != nil {
		app.logger.Error().Err(err).Msgf("Error during Copy() %s: %s", r.URL.String(), err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	var written string
	if n < kbSize {
		written = fmt.Sprintf("%dB", n)
	} else {
		written = fmt.Sprintf("%dKB", n/kbSize)
	}
	app.logger.Debug().Msgf("%s - %s - %s - %d - %s", r.Proto, r.Method, r.Host, resp.StatusCode, written)
}

func (app *app) handleTunnel(w http.ResponseWriter, r *http.Request) {
	var dstConn net.Conn
	var err error
	if isLocalAddress(r.Host) {
		dstConn, err = net.DialTimeout("tcp", r.Host, timeout)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
	} else {
		dstConn, err = app.dialer.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
	}
	defer dstConn.Close()
	w.WriteHeader(http.StatusOK)

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
		return
	}
	srcConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer srcConn.Close()

	dstConnStr := fmt.Sprintf("%s->%s->%s", dstConn.LocalAddr().String(), dstConn.RemoteAddr().String(), r.Host)
	srcConnStr := fmt.Sprintf("%s->%s", srcConn.LocalAddr().String(), srcConn.RemoteAddr().String())

	app.logger.Debug().Msgf("%s - %s - %s", r.Proto, r.Method, r.Host)
	app.logger.Debug().Msgf("src: %s - dst: %s", srcConnStr, dstConnStr)

	var wg sync.WaitGroup
	wg.Add(2)
	go app.transfer(&wg, dstConn, srcConn, dstConnStr, srcConnStr)
	go app.transfer(&wg, srcConn, dstConn, srcConnStr, dstConnStr)
	wg.Wait()
}

func (app *app) transfer(wg *sync.WaitGroup, destination io.Writer, source io.Reader, destName, srcName string) {
	defer wg.Done()
	n, err := io.Copy(destination, source)
	if err != nil {
		app.logger.Error().Err(err).Msgf("Error during copy from %s to %s: %v", srcName, destName, err)
	}
	var written string
	if n < kbSize {
		written = fmt.Sprintf("%dB", n)
	} else {
		written = fmt.Sprintf("%dKB", n/kbSize)
	}
	app.logger.Debug().Msgf("copied %s from %s to %s", written, srcName, destName)
}

func (app *app) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			app.handleTunnel(w, r)
		} else {
			app.handleForward(w, r)
		}
	}
}

func (app *app) Run() {
	app.hs.Handler = app.handler()
	if err := app.hs.ListenAndServe(); err != nil {
		app.logger.Fatal().Err(err).Msg("Unable to start HTTP server")
	}
}

type Config struct {
	AddrHTTP  string
	AddrSOCKS string
	Debug     bool
	Json      bool
	User      string
	Pass      string
}

func New(conf *Config) *app {
	var logger zerolog.Logger
	if conf.Json {
		logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
	} else {
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
		Timeout: timeout,
	}
	hs := &http.Server{
		Addr:           conf.AddrHTTP,
		ReadTimeout:    readTimeout,
		WriteTimeout:   writeTimeout,
		MaxHeaderBytes: 1 << 20,
	}
	hc := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: timeout,
	}
	logger.Info().Msgf("SOCKS5 Proxy: %s", conf.AddrSOCKS)
	logger.Info().Msgf("HTTP Proxy: %s", conf.AddrHTTP)
	return &app{hs: hs, sc: socks, hc: hc, dialer: dialer, logger: &logger}
}
