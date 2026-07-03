//go:build !linux && !(android && arm)

package gohpts

import (
	"net"
	"sync"
)

type tproxyServer struct {
	listener net.Listener
	quit     chan struct{}
	wg       sync.WaitGroup
	p        *Proxy
}

func newTproxyServer(p *Proxy) (*tproxyServer, error) {
	_ = p
	return nil, nil
}

func (ts *tproxyServer) Serve() {
}

func (ts *tproxyServer) Shutdown() {}

func (ts *tproxyServer) ApplyRedirectRules(opts map[string]string) map[string]string {
	_ = opts
	return nil
}

func (ts *tproxyServer) ClearRedirectRules() error {
	return nil
}
