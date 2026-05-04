//go:build linux || (android && arm)

package gohpts

import (
	"net"
	"syscall"
	"time"

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
