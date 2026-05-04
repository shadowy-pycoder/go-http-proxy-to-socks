//go:build !linux && !(android && arm)

package gohpts

import (
	"net"
	"time"
)

func getBaseDialer(timeout time.Duration, mark uint) *net.Dialer {
	_ = mark
	return &net.Dialer{Timeout: timeout}
}
