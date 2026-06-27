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

func getBaseDialer(timeout time.Duration, mark uint, nameserver *net.UDPAddr) *net.Dialer {
	var dialer *net.Dialer
	if mark > 0 {
		dialer = &net.Dialer{
			Timeout: timeout,
			Control: func(_, _ string, c syscall.RawConn) error {
				return c.Control(func(fd uintptr) {
					unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
				})
			},
		}
	} else {
		dialer = &net.Dialer{Timeout: timeout}
	}
	resolver := net.DefaultResolver
	if nameserver != nil {
		dnsDialer := &net.Dialer{Timeout: timeout}
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return dnsDialer.DialContext(ctx, network, nameserver.String())
			},
		}
	}
	dialer.Resolver = resolver
	return dialer
}

var _ contextDialer = &nsDialer{}

type nsDialer struct {
	dialer   contextDialer
	ns       *netns.NsHandle
	mark     uint
	resolver *net.Resolver
}

func getNSDialer(ns *netns.NsHandle, timeout time.Duration, mark uint, nameserver *net.UDPAddr) *nsDialer {
	var dialer *net.Dialer
	if mark > 0 {
		dialer = &net.Dialer{
			Timeout:       timeout,
			FallbackDelay: -1,
			Control: func(_, _ string, c syscall.RawConn) error {
				return c.Control(func(fd uintptr) {
					unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
				})
			},
		}
	} else {
		dialer = &net.Dialer{Timeout: timeout, FallbackDelay: -1}
	}
	dnsDialer := &net.Dialer{Timeout: timeout}

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
			return dnsDialer.DialContext(ctx, network, nameserver.String())
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
	resolver *net.Resolver,
) func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	return func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		udpConn, err := dialer.DialContext(ctx, "udp", addr)
		if err != nil {
			return nil, err
		}
		host, port, err := splitHostPort(addr)
		if err != nil {
			return nil, err
		}

		addrs, err := resolver.LookupIPAddr(ctx, host)
		if err != nil {
			udpConn.Close()
			return nil, err
		}
		if len(addrs) == 0 {
			udpConn.Close()
			return nil, fmt.Errorf("no addresses for %s", host)
		}
		udpAddr := &net.UDPAddr{IP: addrs[0].IP, Port: port, Zone: addrs[0].Zone}
		return quic.DialEarly(ctx, udpConn.(net.PacketConn), udpAddr, tlsCfg, cfg)
	}
}

func getNSQUICDialerDirect(dialer *nsDialer) func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	return func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		host, port, err := splitHostPort(addr)
		if err != nil {
			return nil, err
		}

		addrs, err := dialer.resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("no addresses for %s", host)
		}
		udpAddr := &net.UDPAddr{IP: addrs[0].IP, Port: port, Zone: addrs[0].Zone}

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

		udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
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

func getPacketDial(mark uint, ns *netns.NsHandle) func(ctx context.Context, network, addr string) (net.PacketConn, error) {
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
		return lc.ListenPacket(ctx, network, addr)
	}
}
