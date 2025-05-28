package gohpts

import (
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

type app struct {
	hs     *http.Server
	sc     *http.Client
	logger *zerolog.Logger
}

func (app *app) handleSOCKS(w http.ResponseWriter, r *http.Request) {
	req, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		app.logger.Error().Err(err).Msgf("Error during NewRequest() %s: %s", r.URL.String(), err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	for key, values := range r.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	resp, err := app.sc.Do(req)
	if err != nil {
		app.logger.Error().Err(err).Msg("Connection to SOCKS5 server closed")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if resp == nil {
		app.logger.Error().Err(err).Msg("Connection to SOCKS5 server closed")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	written, err := io.Copy(w, resp.Body)
	if err != nil {
		app.logger.Error().Err(err).Msgf("Error during Copy() %s: %s", r.URL.String(), err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	app.logger.Debug().Msgf("%s - %s - %s - %d - %dKB", r.Proto, r.Method, r.Host, resp.StatusCode, written/1000)
}

func (app *app) handleTunnel(w http.ResponseWriter, r *http.Request) {
	dstConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
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

	dstConnStr := fmt.Sprintf("%s->%s", dstConn.LocalAddr().String(), dstConn.RemoteAddr().String())
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
	written, err := io.Copy(destination, source)
	if err != nil {
		app.logger.Error().Err(err).Msgf("Error during copy from %s to %s: %v", srcName, destName, err)
	}
	app.logger.Debug().Msgf("copied %d bytes from %s to %s", written, srcName, destName)
}

func (app *app) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			app.handleTunnel(w, r)
		} else {
			app.handleSOCKS(w, r)
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
	dialer, err := proxy.SOCKS5("tcp", conf.AddrSOCKS, nil, nil)
	if err != nil {
		logger.Fatal().Err(err).Msg("Unable to create SOCKS5 client")
	}
	socks := &http.Client{
		Transport: &http.Transport{
			Dial: dialer.Dial,
		},
	}
	hs := &http.Server{
		Addr:           conf.AddrHTTP,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	logger.Info().Msgf("SOCKS5 Proxy: %s", conf.AddrSOCKS)
	logger.Info().Msgf("HTTP Proxy: %s", conf.AddrHTTP)
	return &app{hs: hs, sc: socks, logger: &logger}
}
