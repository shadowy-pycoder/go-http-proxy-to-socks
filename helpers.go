package gohpts

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/shadowy-pycoder/mshark/network"
	"github.com/wzshiming/socks5"
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
		for sf := range strings.SplitSeq(f, ",") {
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

func expandPath(p string) string {
	p = os.ExpandEnv(p)
	if strings.HasPrefix(p, "~") {
		if home, err := os.UserHomeDir(); err == nil {
			return strings.Replace(p, "~", home, 1)
		}
	}
	return p
}

func getAddressFromInterface(iface *net.Interface, ipv6 bool) (string, error) {
	if iface == nil {
		return "127.0.0.1", nil
	}
	var prefix netip.Prefix
	var err error
	prefix, err = network.GetIPv4PrefixFromInterface(iface)
	if err != nil && ipv6 {
		prefix, err = network.GetIPv6LinkLocalUnicastPrefixFromInterface(iface)
		if err != nil {
			return "", err
		}
	}
	return prefix.Addr().String(), nil
}

func parseProxyAuth(auth string) (username, password string, ok bool) {
	if auth == "" {
		return "", "", false
	}
	const prefix = "Basic "
	if len(auth) < len(prefix) || !strings.EqualFold(prefix, auth[:len(prefix)]) {
		return "", "", false
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return "", "", false
	}
	cs := string(c)
	username, password, ok = strings.Cut(cs, ":")
	if !ok {
		return "", "", false
	}
	return username, password, true
}

func splitHostPort(address string) (string, int, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, err
	}
	portnum, err := strconv.Atoi(port)
	if err != nil {
		return "", 0, err
	}
	if 1 > portnum || portnum > 0xffff {
		return "", 0, errors.New("port number out of range " + port)
	}
	return host, portnum, nil
}

type auth struct {
	User, Password string
}

type contextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

var (
	_ contextDialer = &socks5.Dialer{}
	_ contextDialer = &net.Dialer{}
)

func newSOCKS5Dialer(address string, auth *auth, forward contextDialer, network string) (*socks5.Dialer, error) {
	d := &socks5.Dialer{
		ProxyNetwork: network,
		IsResolve:    false,
	}
	host, port, err := splitHostPort(address)
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(host)
	if err == nil {
		host = ip.String()
	}
	d.ProxyAddress = net.JoinHostPort(host, strconv.Itoa(port))
	if auth != nil {
		d.Username = auth.User
		d.Password = auth.Password
	}
	if forward != nil {
		d.ProxyDial = forward.DialContext
	}
	return d, nil
}

func getQUICDialer(dialer contextDialer) func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	return func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		udpConn, err := dialer.DialContext(ctx, "udp", addr)
		if err != nil {
			return nil, err
		}
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			udpConn.Close()
			return nil, err
		}
		return quic.DialEarly(ctx, udpConn.(net.PacketConn), udpAddr, tlsCfg, cfg)
	}
}

func runSysctlOptCmd(opt, value, setex string, opts map[string]string, debug bool, dump *strings.Builder) error {
	data, err := os.ReadFile(fmt.Sprintf("/proc/sys/%s", strings.ReplaceAll(opt, ".", "/")))
	if err != nil {
		return err
	}
	cmdOpt := fmt.Sprintf(`sysctl -w %s=%q`, opt, value)
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
    %s
    %s`, setex, cmdOpt))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if !debug {
		cmd.Stdout = nil
	}
	if err := cmd.Run(); err != nil {
		return err
	}
	opts[opt] = strings.ReplaceAll(strings.TrimRight(string(data), "\n"), "\t", " ")
	dump.WriteString(cmdOpt)
	dump.WriteString("\n")
	return nil
}

func createPcapFile(app, ext string) (*os.File, error) {
	path := fmt.Sprintf("./%s_%s.%s", app, time.Now().UTC().Format("20060102_150405"), ext)
	f, err := os.OpenFile(filepath.FromSlash(path), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	return f, nil
}
