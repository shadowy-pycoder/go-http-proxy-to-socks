//go:build !linux && !(android && arm)

package gohpts

import (
	"context"
	"net"
	"time"

	"github.com/vishvananda/netns"
)

func getBaseDialer(timeout time.Duration, mark uint) *net.Dialer {
	_ = mark
	return &net.Dialer{Timeout: timeout}
}

var _ contextDialer = &nsDialer{}

type nsDialer struct {
	dialer contextDialer
	ns     netns.NsHandle
}

func getNSDialer(ns netns.NsHandle, timeout time.Duration, mark uint) *nsDialer {
	_ = mark
	dialer := &net.Dialer{Timeout: timeout}
	return &nsDialer{dialer: dialer, ns: ns}
}

func (d *nsDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dialer.DialContext(ctx, network, address)
}
