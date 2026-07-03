package gohpts

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"strconv"

	quic "github.com/quic-go/quic-go"
	"github.com/wzshiming/socks4"
	"github.com/wzshiming/socks5"
)

type auth struct {
	User, Password string
}

type contextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

var (
	_ contextDialer = &socks4.Dialer{}
	_ contextDialer = &socks5.Dialer{}
	_ contextDialer = &net.Dialer{}
)

func newSOCKS5Dialer(
	address string,
	auth *auth,
	forward contextDialer,
	tcp string,
	packetDial func(ctx context.Context, network string, address string) (net.PacketConn, error),
) (*socks5.Dialer, error) {
	d := &socks5.Dialer{
		ProxyNetwork: tcp,
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
	d.ProxyDial = forward.DialContext
	d.ProxyPacketDial = packetDial
	return d, nil
}

func newSOCKS4Dialer(address string, auth *auth, forward contextDialer, tcp string) (*socks4.Dialer, error) {
	d := &socks4.Dialer{
		ProxyNetwork: tcp,
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
	}
	d.ProxyDial = forward.DialContext
	return d, nil
}

func getQUICDialer(
	dialer contextDialer,
	udp string,
) func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	return func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		udpConn, err := dialer.DialContext(ctx, udp, addr)
		if err != nil {
			return nil, err
		}
		udpAddr, err := net.ResolveUDPAddr(udp, addr)
		if err != nil {
			udpConn.Close()
			return nil, err
		}
		return quic.DialEarly(ctx, udpConn.(net.PacketConn), udpAddr, tlsCfg, cfg)
	}
}
