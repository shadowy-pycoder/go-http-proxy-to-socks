//go:build linux || (android && arm)

package gohpts

import (
	"context"
	"net"
	"runtime"
	"syscall"
	"time"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func getBaseDialer(timeout time.Duration, mark uint) *net.Dialer {
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
	return dialer
}

var _ contextDialer = &nsDialer{}

type nsDialer struct {
	dialer contextDialer
	ns     netns.NsHandle
}

func getNSDialer(ns netns.NsHandle, timeout time.Duration, mark uint) *nsDialer {
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
	dnsDialer := &net.Dialer{Timeout: timeout}
	dialer.Resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			origNs, err := netns.Get()
			if err != nil {
				return nil, err
			}
			defer origNs.Close()
			defer netns.Set(origNs)
			if err := netns.Set(ns); err != nil {
				return nil, err
			}
			return dnsDialer.DialContext(ctx, "udp", address)
		},
	}
	return &nsDialer{dialer: dialer, ns: ns}
}

func (d *nsDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	origNs, err := netns.Get()
	if err != nil {
		return nil, err
	}
	defer origNs.Close()
	defer netns.Set(origNs)

	if err := netns.Set(d.ns); err != nil {
		return nil, err
	}
	return d.dialer.DialContext(ctx, network, address)
}
