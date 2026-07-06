package gohpts

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/wzshiming/socks5"
)

var _ socksServer = &socks5.Server{}

type socksServer interface {
	ServeConn(conn net.Conn)
}

type sockLogger struct {
	nocolor bool
	json    bool
}

func (l sockLogger) Println(a ...any) {
	if l.json {
		fmt.Printf("{\"level\":\"error\",\"time\":\"%s\",\"message\":\"%s\"}\n",
			time.Now().Format(time.RFC3339), strings.TrimRight(fmt.Sprint(a...), "\n"))
	} else {
		ts := colorizeTimestamp(time.Now(), l.nocolor)
		msg := colorizeErrMessage(fmt.Sprint(a...), l.nocolor)
		if strings.Contains(msg, "broken pipe") || strings.Contains(msg, "connection reset") {
			return
		}
		fmt.Printf("%s %s %s\n", ts, colorizeErr(l.nocolor), msg)
	}
}

func newSOCKS5Server(
	dial func(ctx context.Context, network string, address string) (net.Conn, error),
	packetDial func(ctx context.Context, network string, address string) (net.PacketConn, error),
	logger sockLogger,
) *socks5.Server {
	return &socks5.Server{
		ProxyDial:         dial,
		ProxyListenPacket: packetDial,
		BytesPool:         bytesPool,
		Logger:            logger,
	}
}
