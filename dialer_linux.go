//go:build linux || (android && arm)

package gohpts

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"runtime"
	"syscall"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func getBaseDialer(ipver string, timeout time.Duration, mark uint, nameserver *net.UDPAddr) *net.Dialer {
	dialer := &net.Dialer{Timeout: timeout}
	control := func(_, _ string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
		})
	}
	if mark > 0 {
		dialer.Control = control
	}
	dnsDialer := &net.Dialer{Timeout: timeout}
	if mark > 0 {
		dnsDialer.Control = control
		dialer.Resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				if nameserver != nil {
					address = nameserver.String()
				}
				return dnsDialer.DialContext(ctx, ipver, address)
			},
		}
	} else if nameserver != nil {
		dialer.Resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return dnsDialer.DialContext(ctx, ipver, nameserver.String())
			},
		}
	} else {
		dialer.Resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return dnsDialer.DialContext(ctx, ipver, address)
			},
		}
	}
	return dialer
}

var _ contextDialer = &nsDialer{}

type nsDialer struct {
	dialer   contextDialer
	ns       *netns.NsHandle
	mark     uint
	resolver *net.Resolver
}

func getNSDialer(ipver string, ns *netns.NsHandle, timeout time.Duration, mark uint, nameserver *net.UDPAddr) *nsDialer {
	dialer := &net.Dialer{Timeout: timeout, FallbackDelay: -1}
	control := func(_, _ string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
		})
	}
	if mark > 0 {
		dialer.Control = control
	}
	dnsDialer := &net.Dialer{Timeout: timeout}
	if mark > 0 {
		dnsDialer.Control = control
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			currentNs, err := netns.Get()
			if err != nil {
				return nil, err
			}
			defer currentNs.Close()
			defer netns.Set(currentNs)
			if err := netns.Set(*ns); err != nil {
				return nil, err
			}
			return dnsDialer.DialContext(ctx, ipver, nameserver.String())
		},
	}
	dialer.Resolver = resolver
	return &nsDialer{dialer: dialer, ns: ns, mark: mark, resolver: resolver}
}

func (d *nsDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	currentNs, err := netns.Get()
	if err != nil {
		return nil, err
	}
	defer currentNs.Close()
	defer netns.Set(currentNs)

	if err := netns.Set(*d.ns); err != nil {
		return nil, err
	}
	return d.dialer.DialContext(ctx, network, address)
}

func getNSQUICDialer(
	dialer contextDialer,
	ipver, udp string,
	resolver *net.Resolver,
) func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	return func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		udpConn, err := dialer.DialContext(ctx, udp, addr)
		if err != nil {
			return nil, err
		}
		host, port, err := splitHostPort(addr)
		if err != nil {
			return nil, err
		}

		addrs, err := resolver.LookupIP(ctx, ipver, host)
		if err != nil {
			udpConn.Close()
			return nil, err
		}
		if len(addrs) == 0 {
			udpConn.Close()
			return nil, fmt.Errorf("no addresses for %s", host)
		}
		udpAddr := &net.UDPAddr{IP: addrs[0], Port: port}
		return quic.DialEarly(ctx, udpConn.(net.PacketConn), udpAddr, tlsCfg, cfg)
	}
}

func getNSQUICDialerDirect(
	dialer *nsDialer,
	ipver, udp string,
) func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	ip := net.IPv4zero
	if udp == "udp6" {
		ip = net.IPv6zero
	}
	return func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		host, port, err := splitHostPort(addr)
		if err != nil {
			return nil, err
		}

		addrs, err := dialer.resolver.LookupIP(ctx, ipver, host)
		if err != nil {
			return nil, err
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("no addresses for %s", host)
		}
		udpAddr := &net.UDPAddr{IP: addrs[0], Port: port}

		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		currentNs, err := netns.Get()
		if err != nil {
			return nil, err
		}
		defer currentNs.Close()
		defer netns.Set(currentNs)

		if err := netns.Set(*dialer.ns); err != nil {
			return nil, err
		}

		udpConn, err := net.ListenUDP(udp, &net.UDPAddr{IP: ip, Port: 0})
		if err != nil {
			return nil, err
		}

		if dialer.mark > 0 {
			raw, err := udpConn.SyscallConn()
			if err != nil {
				udpConn.Close()
				return nil, err
			}
			raw.Control(func(fd uintptr) {
				unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(dialer.mark))
			})
		}
		return quic.DialEarly(ctx, udpConn, udpAddr, tlsCfg, cfg)
	}
}

func getPacketDial(udp string, mark uint, ns *netns.NsHandle) func(ctx context.Context, network, addr string) (net.PacketConn, error) {
	lc := &net.ListenConfig{}
	if mark > 0 {
		lc = &net.ListenConfig{
			Control: func(_, _ string, c syscall.RawConn) error {
				return c.Control(func(fd uintptr) {
					unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
				})
			},
		}
	}
	return func(ctx context.Context, network, addr string) (net.PacketConn, error) {
		if ns != nil {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			currentNs, err := netns.Get()
			if err != nil {
				return nil, err
			}
			defer currentNs.Close()
			defer netns.Set(currentNs)
			if err := netns.Set(*ns); err != nil {
				return nil, err
			}
		}
		return lc.ListenPacket(ctx, udp, addr)
	}
}
