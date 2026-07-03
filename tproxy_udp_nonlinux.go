//go:build !linux && !(android && arm)

package gohpts

type tproxyServerUDP struct{}

func newTproxyServerUDP(p *Proxy) (*tproxyServerUDP, error) {
	_ = p
	return nil, nil
}

func (tsu *tproxyServerUDP) Serve() {
}

func (tsu *tproxyServerUDP) Shutdown() {
}

func (tsu *tproxyServerUDP) ApplyRedirectRules(opts map[string]string) {
	_ = opts
}

func (tsu *tproxyServerUDP) ClearRedirectRules() error {
	return nil
}
