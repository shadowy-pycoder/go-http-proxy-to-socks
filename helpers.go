package gohpts

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shadowy-pycoder/mshark/network"
)

const (
	bufSize       int   = 32 * 1024
	maxBodySize   int64 = 2 << 15
	oobSize       int   = 1500
	udpBufferSize int   = 4096
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

func getAddressFromInterface(iface *net.Interface, ipv6only, bindToLocalhost bool) (string, error) {
	if bindToLocalhost {
		if ipv6only {
			return "::1", nil
		}
		return "127.0.0.1", nil
	}
	var addr string
	if ipv6only {
		prefix, err := network.GetIPv6LinkLocalUnicastPrefixFromInterface(iface)
		if err != nil {
			return "", err
		}
		addr = prefix.Addr().WithZone(iface.Name).String()
	} else {
		prefix, err := network.GetIPv4PrefixFromInterface(iface)
		if err != nil {
			return "", err
		}
		addr = prefix.Addr().String()
	}
	return addr, nil
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

func runSysctlOptCmd(opt, value, setex string, opts map[string]string, dumpRules bool, dump *strings.Builder) error {
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
	if !dumpRules {
		cmd.Stdout = nil
	}
	if err := cmd.Run(); err != nil {
		return err
	}
	opts[opt] = strings.ReplaceAll(strings.TrimRight(string(data), "\n"), "\t", " ")
	if dumpRules {
		dump.WriteString(cmdOpt)
		dump.WriteString("\n")
	}
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

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, bufSize)
		return &b
	},
}

func getBufferFromPool() *[]byte {
	return bufPool.Get().(*[]byte)
}

func putBufferToPool(buf *[]byte) {
	bufPool.Put(buf)
}

var bodyPool = sync.Pool{
	New: func() any {
		b := make([]byte, maxBodySize)
		return &b
	},
}

func getBodyBufferFromPool() *[]byte {
	return bodyPool.Get().(*[]byte)
}

func putBodyBufferToPool(buf *[]byte) {
	bodyPool.Put(buf)
}

var udpPool = sync.Pool{
	New: func() any {
		b := make([]byte, udpBufferSize)
		return &b
	},
}

func getUDPBufferFromPool() *[]byte {
	return udpPool.Get().(*[]byte)
}

func putUDPBufferToPool(buf *[]byte) {
	udpPool.Put(buf)
}

var oobPool = sync.Pool{
	New: func() any {
		b := make([]byte, oobSize)
		return &b
	},
}

func getOOBBufferFromPool() *[]byte {
	return oobPool.Get().(*[]byte)
}

func putOOBBufferToPool(buf *[]byte) {
	oobPool.Put(buf)
}
