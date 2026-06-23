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

func getBaseDialer(timeout time.Duration, mark uint) *net.Dialer {
	_ = mark
	return &net.Dialer{Timeout: timeout}
}

var _ contextDialer = &nsDialer{}

type nsDialer struct {
	dialer   contextDialer
	ns       *netns.NsHandle
	mark     uint
	resolver *net.Resolver
}

func getNSDialer(ns *netns.NsHandle, timeout time.Duration, mark uint, nameserver *net.UDPAddr) *nsDialer {
	_ = mark
	_ = nameserver
	dialer := &net.Dialer{Timeout: timeout}
	return &nsDialer{dialer: dialer, ns: ns, mark: 0, resolver: net.DefaultResolver}
}

func (d *nsDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dialer.DialContext(ctx, network, address)
}

func getNSQUICDialer(dialer *nsDialer) func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	_ = dialer
	return quic.DialAddrEarly
}
