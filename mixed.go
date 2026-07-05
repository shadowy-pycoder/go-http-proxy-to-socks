package gohpts

import (
	"bufio"
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"

	nw "github.com/shadowy-pycoder/mshark/network"
)

var (
	_ contextDialer = &mixedDialer{}
	_ net.Listener  = &mixedListener{}
)

type mixedListener struct {
	addr   net.Addr
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newMixedListener(addr net.Addr) *mixedListener {
	return &mixedListener{
		addr:   addr,
		conns:  make(chan net.Conn, 128),
		closed: make(chan struct{}),
	}
}

func (l *mixedListener) Accept() (net.Conn, error) {
	select {
	case c, ok := <-l.conns:
		if !ok {
			return nil, io.EOF
		}
		return c, nil

	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *mixedListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
		close(l.conns)
	})
	return nil
}

func (l *mixedListener) Addr() net.Addr {
	return l.addr
}

func (l *mixedListener) ServeConn(conn net.Conn) error {
	select {
	case l.conns <- conn:
		return nil
	case <-l.closed:
		conn.Close()
		return net.ErrClosed
	}
}

var _ net.Conn = &mixedConn{}

type mixedConn struct {
	r *bufio.Reader
	net.Conn
}

func newMixedConn(c net.Conn) *mixedConn {
	if conn, ok := c.(*mixedConn); ok {
		return conn
	}
	return &mixedConn{getBufReaderFromPool(c), c}
}

func (c *mixedConn) Reader() *bufio.Reader                    { return c.r }
func (c *mixedConn) Read(p []byte) (int, error)               { return c.r.Read(p) }
func (c *mixedConn) Peek(n int) ([]byte, error)               { return c.r.Peek(n) }
func (c *mixedConn) WriteTo(w io.Writer) (n int64, err error) { return c.r.WriteTo(w) }
func (c *mixedConn) Close() error {
	putBufReaderToPool(c.r)
	return c.Conn.Close()
}

func getSimpleMixedDialer(
	dialer contextDialer,
	sockDialer contextDialer,
) func(ctx context.Context, network string, address string) (net.Conn, error) {
	return func(ctx context.Context, network string, address string) (net.Conn, error) {
		if nw.IsLocalAddress(address) {
			return dialer.DialContext(ctx, network, address)
		}
		return sockDialer.DialContext(ctx, network, address)
	}
}

type mixedDialer struct {
	dialer     contextDialer
	sockDialer atomic.Value
}

func newMixedDialer(dialer, sockDialer contextDialer) *mixedDialer {
	m := &mixedDialer{
		dialer: dialer,
	}
	m.sockDialer.Store(sockDialer)
	return m
}

func (m *mixedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if nw.IsLocalAddress(address) {
		return m.dialer.DialContext(ctx, network, address)
	}
	return m.sockDialer.Load().(contextDialer).DialContext(ctx, network, address)
}

func (m *mixedDialer) SetProxy(d contextDialer) {
	m.sockDialer.Store(d)
}
