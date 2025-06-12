//go:build !linux
// +build !linux

package gohpts

import (
	"net"
	"sync"
	"syscall"
)

type tproxyServer struct {
	listener net.Listener
	quit     chan struct{}
	wg       sync.WaitGroup
	pa       *proxyapp
}

func newTproxyServer(pa *proxyapp) *tproxyServer {
	_ = pa
	return nil
}

func (ts *tproxyServer) ListenAndServe() {
	ts.serve()
}

func (ts *tproxyServer) serve() {
	ts.handleConnection(nil)
}

func (ts *tproxyServer) getOriginalDst(rawConn syscall.RawConn) (string, error) {
	_ = rawConn
	return "", nil
}

func (ts *tproxyServer) handleConnection(srcConn net.Conn) {
	_ = srcConn
	ts.getOriginalDst(nil)
}

func (ts *tproxyServer) Shutdown() {}
