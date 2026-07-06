package gohpts

import (
	"context"
	"net"

	"github.com/wzshiming/socks4"
)

var _ socksServer = &socks4.Server{}

func newSOCKS4Server(
	dial func(ctx context.Context, network string, address string) (net.Conn, error),
	logger sockLogger,
) *socks4.Server {
	return &socks4.Server{
		ProxyDial: dial,
		BytesPool: bytesPool,
		Logger:    logger,
	}
}
