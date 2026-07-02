//go:build !linux && !(android && arm)

package gohpts

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/vishvananda/netns"
)

func getBaseDialer(ipver string, timeout time.Duration, mark uint, nameserver *net.UDPAddr) *net.Dialer {
	_ = mark
	dnsDialer := &net.Dialer{Timeout: timeout}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if nameserver != nil {
				address = nameserver.String()
			}
			switch ipver {
			case "ip4":
				network += "4"
			case "ip6":
				network += "6"
			}
			return dnsDialer.DialContext(ctx, network, address)
		},
	}
	return &net.Dialer{Timeout: timeout, Resolver: resolver}
}

var _ contextDialer = &nsDialer{}

type nsDialer struct {
	dialer   contextDialer
	ns       *netns.NsHandle
	mark     uint
	resolver *net.Resolver
}

func getNSDialer(ipver string, ns *netns.NsHandle, timeout time.Duration, mark uint, nameserver *net.UDPAddr) *nsDialer {
	_ = mark
	_ = nameserver
	dnsDialer := &net.Dialer{Timeout: timeout}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			switch ipver {
			case "ip4":
				network += "4"
			case "ip6":
				network += "6"
			}
			return dnsDialer.DialContext(ctx, network, address)
		},
	}
	dialer := &net.Dialer{Timeout: timeout, Resolver: resolver}
	return &nsDialer{dialer: dialer, ns: ns, mark: 0, resolver: resolver}
}

func (d *nsDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dialer.DialContext(ctx, network, address)
}

func getNSQUICDialer(
	dialer contextDialer,
	ipver, udp string,
	resolver *net.Resolver,
) func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	_ = dialer
	_ = ipver
	_ = udp
	_ = resolver
	return quic.DialAddrEarly
}

func getNSQUICDialerDirect(
	dialer *nsDialer,
	ipver, udp string,
) func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	_ = dialer
	_ = ipver
	_ = udp
	return quic.DialAddrEarly
}

func getPacketDial(udp string, mark uint, ns *netns.NsHandle) func(ctx context.Context, network, addr string) (net.PacketConn, error) {
	_ = mark
	_ = ns
	lc := &net.ListenConfig{}
	return func(ctx context.Context, network, addr string) (net.PacketConn, error) {
		return lc.ListenPacket(ctx, udp, addr)
	}
}
