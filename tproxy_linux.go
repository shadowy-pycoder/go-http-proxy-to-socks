//go:build linux || (android && arm)

package gohpts

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/shadowy-pycoder/mshark/layers"
	"github.com/shadowy-pycoder/mshark/network"
	"golang.org/x/sys/unix"
)

type tproxyServer struct {
	listener     net.Listener
	quit         chan struct{}
	wg           sync.WaitGroup
	p            *Proxy
	startingFlag atomic.Bool
	closingFlag  atomic.Bool
}

func newTproxyServer(p *Proxy) (*tproxyServer, error) {
	ts := &tproxyServer{
		quit: make(chan struct{}),
		p:    p,
	}
	// https://iximiuz.com/en/posts/go-net-http-setsockopt-example/
	lc := net.ListenConfig{
		Control: func(network, address string, conn syscall.RawConn) error {
			var operr error
			size := 2 * 1024 * 1024
			if err := conn.Control(func(fd uintptr) {
				operr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int(timeout.Milliseconds()))
				operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
				operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, size)
				operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, size)
				if ts.p.tproxyMode == "tproxy" {
					operr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
					if ts.p.ipv6enabled {
						operr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
					}
				}
			}); err != nil {
				return err
			}
			return operr
		},
	}

	ln, err := lc.Listen(context.Background(), ts.p.tcp, ts.p.tproxyAddr)
	if err != nil {
		return nil, err
	}
	ts.listener = ln
	return ts, nil
}

func (ts *tproxyServer) Serve() {
	ts.startingFlag.Store(true)
	ts.wg.Add(1)
	go ts.serve()
	ts.startingFlag.Store(false)
}

func (ts *tproxyServer) serve() {
	defer ts.wg.Done()

	for {
		conn, err := ts.listener.Accept()
		if err != nil {
			select {
			case <-ts.quit:
				return
			default:
				ts.p.logger.Error().Err(err).Msg("Failed accepting connection")
			}
		} else {
			if ts.closingFlag.Load() {
				return
			}
			ts.wg.Add(1)
			err := conn.SetDeadline(time.Now().Add(timeout))
			if err != nil {
				ts.p.logger.Error().Err(err).Msg("")
			}
			go func() {
				ts.handleConnection(conn)
				ts.wg.Done()
			}()
		}
	}
}

func getsockopt(s int, level int, optname int, optval unsafe.Pointer, optlen *uint32) (err error) {
	_, _, e := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(s),
		uintptr(level),
		uintptr(optname),
		uintptr(optval),
		uintptr(unsafe.Pointer(optlen)),
		0,
	)
	if e != 0 {
		return e
	}
	return nil
}

func (ts *tproxyServer) getOriginalDst(rawConn syscall.RawConn, addr *net.TCPAddr) (string, error) {
	var dstHost netip.Addr
	var dstPort uint16
	err := rawConn.Control(func(fd uintptr) {
		if addr.IP.To4() != nil {
			var originalDst unix.RawSockaddrInet4
			optlen := uint32(unsafe.Sizeof(originalDst))
			err := getsockopt(int(fd), unix.SOL_IP, unix.SO_ORIGINAL_DST, unsafe.Pointer(&originalDst), &optlen)
			if err != nil {
				ts.p.logger.Error().Err(err).Msgf("")
				return
			}
			dstHost = netip.AddrFrom4(originalDst.Addr)
			dstPort = uint16(originalDst.Port<<8) | originalDst.Port>>8
		} else {
			var originalDst unix.RawSockaddrInet6
			optlen := uint32(unsafe.Sizeof(originalDst))
			err := getsockopt(int(fd), unix.SOL_IPV6, unix.SO_ORIGINAL_DST, unsafe.Pointer(&originalDst), &optlen)
			if err != nil {
				ts.p.logger.Error().Err(err).Msgf("")
				return
			}
			dstHost = netip.AddrFrom16(originalDst.Addr)
			dstPort = uint16(originalDst.Port<<8) | originalDst.Port>>8
		}
	})
	if err != nil {
		ts.p.logger.Error().Err(err).Msgf("[tcp %s] Failed invoking control connection", ts.p.tproxyMode)
		return "", err
	}
	if !dstHost.IsValid() || dstPort == 0 {
		return "", fmt.Errorf("[tcp %s] getsockopt SO_ORIGINAL_DST failed", ts.p.tproxyMode)
	}
	return netip.AddrPortFrom(dstHost, dstPort).String(), nil
}

func (ts *tproxyServer) handleConnection(srcConn net.Conn) {
	var (
		dstConn net.Conn
		dst     string
		err     error
	)
	defer srcConn.Close()
	switch ts.p.tproxyMode {
	case "redirect":
		rawConn, err := srcConn.(*net.TCPConn).SyscallConn()
		if err != nil {
			ts.p.logger.Error().Err(err).Msgf("[tcp %s] Failed to get raw connection", ts.p.tproxyMode)
			return
		}
		addr := srcConn.RemoteAddr().(*net.TCPAddr)
		dst, err = ts.getOriginalDst(rawConn, addr)
		if err != nil {
			ts.p.logger.Error().Err(err).Msgf("[tcp %s] Failed to get destination address", ts.p.tproxyMode)
			return
		}
	case "tproxy":
		dst = srcConn.LocalAddr().String()
	default:
		ts.p.logger.Fatal().Msg("Unknown tproxyMode")
	}
	if network.IsLocalAddress(dst) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		dstConn, err = getBaseDialer(timeout, ts.p.mark).DialContext(ctx, ts.p.tcp, dst)
		if err != nil {
			ts.p.logger.Error().Err(err).Msgf("[tcp %s] Failed connecting to %s", ts.p.tproxyMode, dst)
			return
		}
	} else {
		sockDialer, err := ts.p.getSockDialer()
		if err != nil {
			ts.p.logger.Error().Err(err).Msgf("[tcp %s] Failed getting %s client", ts.p.tproxyMode, ts.p.socksProto)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		dstConn, err = sockDialer.DialContext(ctx, ts.p.tcp, dst)
		if err != nil {
			ts.p.logger.Error().Err(err).Msgf("[tcp %s] Failed connecting to %s", ts.p.tproxyMode, dst)
			return
		}
	}
	defer dstConn.Close()

	arrow := "→ "
	if ts.p.nocolor {
		arrow = "->"
	}
	dstConnStr := fmt.Sprintf("%s%s%s%s%s", dstConn.LocalAddr().String(), arrow, dstConn.RemoteAddr().String(), arrow, dst)
	srcConnStr := fmt.Sprintf("%s%s%s", srcConn.RemoteAddr().String(), arrow, srcConn.LocalAddr().String())

	ts.p.logger.Debug().Msgf("[tcp %s] src: %s - dst: %s", ts.p.tproxyMode, srcConnStr, dstConnStr)

	reqChan := make(chan layers.Layer)
	respChan := make(chan layers.Layer)
	var wg sync.WaitGroup
	wg.Add(2)
	go ts.p.transfer(&wg, dstConn, srcConn, dstConnStr, srcConnStr, reqChan)
	go ts.p.transfer(&wg, srcConn, dstConn, srcConnStr, dstConnStr, respChan)
	if ts.p.sniff {
		wg.Add(1)
		sniffheader := make([]string, 0, 6)
		id := getID(ts.p.nocolor)
		if ts.p.json {
			sniffheader = append(
				sniffheader,
				fmt.Sprintf(
					"{\"connection\":{\"tproxy_mode\":%q,\"src_remote\":%q,\"src_local\":%q,\"dst_local\":%q,\"dst_remote\":%q,\"original_dst\":%q}}",
					ts.p.tproxyMode,
					srcConn.RemoteAddr(),
					srcConn.LocalAddr(),
					dstConn.LocalAddr(),
					dstConn.RemoteAddr(),
					dst,
				),
			)
		} else {
			connections := colorizeConnectionsTransparent(
				srcConn.RemoteAddr(),
				srcConn.LocalAddr(),
				dstConn.LocalAddr(),
				dstConn.RemoteAddr(),
				dst, id, ts.p.nocolor,
			)
			sniffheader = append(sniffheader, connections)
		}
		go ts.p.sniffreporter(&wg, &sniffheader, reqChan, respChan, id)
	}
	wg.Wait()
}

func (ts *tproxyServer) Shutdown() {
	for ts.startingFlag.Load() {
		time.Sleep(50 * time.Millisecond)
	}
	close(ts.quit)
	ts.closingFlag.Store(true)
	ts.listener.Close()
	done := make(chan struct{})
	go func() {
		ts.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return
	case <-time.After(shutdownTimeout):
		ts.p.logger.Error().Msgf("[tcp %s] Server timed out waiting for connections to finish", ts.p.tproxyMode)
		return
	}
}

func (ts *tproxyServer) ApplyRedirectRules(opts map[string]string) {
	_, tproxyPort, _ := net.SplitHostPort(ts.p.tproxyAddr)
	var setex string
	if ts.p.debug {
		setex = "set -ex"
	}
	switch ts.p.tproxyMode {
	case "redirect":
		cmdClear0 := `
iptables -t nat -D PREROUTING -p tcp -j GOHPTS 2>/dev/null || true
iptables -t nat -D OUTPUT -p tcp -j GOHPTS 2>/dev/null || true
iptables -t nat -F GOHPTS 2>/dev/null || true
iptables -t nat -X GOHPTS 2>/dev/null || true
`
		ts.p.runRuleCmd(cmdClear0)
		if ts.p.ipv6enabled {
			cmdClear1 := `
ip6tables -t nat -D PREROUTING -p tcp -j GOHPTS 2>/dev/null || true
ip6tables -t nat -D OUTPUT -p tcp -j GOHPTS 2>/dev/null || true
ip6tables -t nat -F GOHPTS 2>/dev/null || true
ip6tables -t nat -X GOHPTS 2>/dev/null || true
`
			ts.p.runRuleCmd(cmdClear1)
		}
		cmdInit0 := `
iptables -t nat -N GOHPTS 2>/dev/null
iptables -t nat -F GOHPTS

iptables -t nat -A GOHPTS -p tcp -d 127.0.0.0/8 -j RETURN
iptables -t nat -A GOHPTS -p tcp --dport 22 -j RETURN
`
		ts.p.runRuleCmd(cmdInit0)
		if ts.p.ipv6enabled {
			cmdInit1 := `
ip6tables -t nat -N GOHPTS 2>/dev/null
ip6tables -t nat -F GOHPTS

ip6tables -t nat -A GOHPTS -p tcp -d ::1/128 -j RETURN
ip6tables -t nat -A GOHPTS -p tcp --dport 22 -j RETURN
`
			ts.p.runRuleCmd(cmdInit1)
		}
		if ts.p.ignoredPorts != "" {
			cmdInit2 := fmt.Sprintf(`
iptables -t nat -A GOHPTS -p tcp -m multiport --dports %s -j RETURN
iptables -t nat -A GOHPTS -p tcp -m multiport --sports %s -j RETURN
`, ts.p.ignoredPorts, ts.p.ignoredPorts)
			ts.p.runRuleCmd(cmdInit2)
			if ts.p.ipv6enabled {
				cmdInit3 := fmt.Sprintf(`
ip6tables -t nat -A GOHPTS -p tcp -m multiport --dports %s -j RETURN
ip6tables -t nat -A GOHPTS -p tcp -m multiport --sports %s -j RETURN
`, ts.p.ignoredPorts, ts.p.ignoredPorts)
				ts.p.runRuleCmd(cmdInit3)
			}
		}
		if ts.p.httpServerAddr != "" {
			_, httpPort, _ := net.SplitHostPort(ts.p.httpServerAddr)
			cmdHTTP0 := fmt.Sprintf(`iptables -t nat -A GOHPTS -p tcp --dport %s -j RETURN`, httpPort)
			ts.p.runRuleCmd(cmdHTTP0)
			if ts.p.ipv6enabled {
				cmdHTTP1 := fmt.Sprintf(`ip6tables -t nat -A GOHPTS -p tcp --dport %s -j RETURN`, httpPort)
				ts.p.runRuleCmd(cmdHTTP1)
			}
		}
		if ts.p.mark > 0 {
			cmdMark0 := fmt.Sprintf(`iptables -t nat -A GOHPTS -p tcp -m mark --mark %d -j RETURN`, ts.p.mark)
			ts.p.runRuleCmd(cmdMark0)
			if ts.p.ipv6enabled {
				cmdMark1 := fmt.Sprintf(`ip6tables -t nat -A GOHPTS -p tcp -m mark --mark %d -j RETURN`, ts.p.mark)
				ts.p.runRuleCmd(cmdMark1)
			}
		} else {
			cmd0 := fmt.Sprintf(`iptables -t nat -A GOHPTS -p tcp --dport %s -j RETURN`, tproxyPort)
			ts.p.runRuleCmd(cmd0)
			if ts.p.ipv6enabled {
				cmd01 := fmt.Sprintf(`ip6tables -t nat -A GOHPTS -p tcp --dport %s -j RETURN`, tproxyPort)
				ts.p.runRuleCmd(cmd01)
			}
			if len(ts.p.proxylist) > 0 {
				for _, pr := range ts.p.proxylist {
					_, port, _ := net.SplitHostPort(pr.Address)
					cmd1 := fmt.Sprintf(`iptables -t nat -A GOHPTS -p tcp --dport %s -j RETURN`, port)
					ts.p.runRuleCmd(cmd1)
					if ts.p.ipv6enabled {
						cmd11 := fmt.Sprintf(`ip6tables -t nat -A GOHPTS -p tcp --dport %s -j RETURN`, port)
						ts.p.runRuleCmd(cmd11)
					}
					if ts.p.proxychain.Type == "strict" {
						break
					}
				}
			}
		}
		var cmdDocker string
		if ts.p.ipv6enabled {
			cmdDocker = `
if command -v docker >/dev/null 2>&1
then
for subnet in $(docker network inspect $(docker network ls -q)  --format '{{range .IPAM.Config}}{{println .Subnet}}{{end}}'); do
  if [[ "$subnet" == *:* ]]; then
	ip6tables -t nat -A GOHPTS -p tcp -d "$subnet" -j RETURN
  else
	iptables -t nat -A GOHPTS -p tcp -d "$subnet" -j RETURN
  fi
done
fi
`
		} else {
			cmdDocker = `
if command -v docker >/dev/null 2>&1
then
for subnet in $(docker network inspect $(docker network ls -q)  --format '{{range .IPAM.Config}}{{println .Subnet}}{{end}}'); do
  if [[ "$subnet" == *:* ]]; then
	continue
  else
	iptables -t nat -A GOHPTS -p tcp -d "$subnet" -j RETURN
  fi
done
fi
`
		}
		ts.p.runRuleCmd(cmdDocker)
		cmdNat0 := fmt.Sprintf(`
iptables -t nat -A GOHPTS -p tcp -j REDIRECT --to-ports %s

iptables -t nat -C PREROUTING -p tcp -j GOHPTS 2>/dev/null || \
iptables -t nat -A PREROUTING -p tcp -j GOHPTS

iptables -t nat -C OUTPUT -p tcp -j GOHPTS 2>/dev/null || \
iptables -t nat -A OUTPUT -p tcp -j GOHPTS
`, tproxyPort)
		ts.p.runRuleCmd(cmdNat0)
		if ts.p.ipv6enabled {
			cmdNat1 := fmt.Sprintf(`
ip6tables -t nat -A GOHPTS -p tcp -j REDIRECT --to-ports %s

ip6tables -t nat -C PREROUTING -p tcp -j GOHPTS 2>/dev/null || \
ip6tables -t nat -A PREROUTING -p tcp -j GOHPTS

ip6tables -t nat -C OUTPUT -p tcp -j GOHPTS 2>/dev/null || \
ip6tables -t nat -A OUTPUT -p tcp -j GOHPTS
`, tproxyPort)
			ts.p.runRuleCmd(cmdNat1)
		}
	case "tproxy":
		cmdClear0 := `
iptables -t mangle -D PREROUTING -p tcp -m socket -j DIVERT 2>/dev/null || true
iptables -t mangle -D PREROUTING -p tcp -j GOHPTS 2>/dev/null || true
iptables -t mangle -F GOHPTS 2>/dev/null || true
iptables -t mangle -X GOHPTS 2>/dev/null || true
`
		ts.p.runRuleCmd(cmdClear0)
		if ts.p.ipv6enabled {
			cmdClear1 := `
ip6tables -t mangle -D PREROUTING -p tcp -m socket -j DIVERT 2>/dev/null || true
ip6tables -t mangle -D PREROUTING -p tcp -j GOHPTS 2>/dev/null || true
ip6tables -t mangle -F GOHPTS 2>/dev/null || true
ip6tables -t mangle -X GOHPTS 2>/dev/null || true
`
			ts.p.runRuleCmd(cmdClear1)
		}
		cmdInit0 := `
iptables -t mangle -N GOHPTS 2>/dev/null || true
iptables -t mangle -F GOHPTS

iptables -t mangle -A GOHPTS -p tcp -d 127.0.0.0/8 -j RETURN
iptables -t mangle -A GOHPTS -p tcp -d 224.0.0.0/4 -j RETURN
iptables -t mangle -A GOHPTS -p tcp -d 255.255.255.255/32 -j RETURN
`
		ts.p.runRuleCmd(cmdInit0)
		if ts.p.ipv6enabled {
			cmdInit01 := `
ip6tables -t mangle -N GOHPTS 2>/dev/null || true
ip6tables -t mangle -F GOHPTS

ip6tables -t mangle -A GOHPTS -p tcp -d ::/128 -j RETURN
ip6tables -t mangle -A GOHPTS -p tcp -d ::1/128 -j RETURN
ip6tables -t mangle -A GOHPTS -p tcp -d ff00::/8 -j RETURN
ip6tables -t mangle -A GOHPTS -p tcp -d fe80::/10 -j RETURN
ip6tables -t mangle -A GOHPTS -p tcp -d fc00::/7 -j RETURN
`
			ts.p.runRuleCmd(cmdInit01)

			if ts.p.prefix6 != nil {
				cmdInit02 := fmt.Sprintf(`
ip6tables -t mangle -A GOHPTS -p tcp -s %s -d %s -j RETURN
`, ts.p.prefix6.Masked(), ts.p.prefix6.Masked())
				ts.p.runRuleCmd(cmdInit02)
			}
		}
		if ts.p.ignoredPorts != "" {
			cmdInit1 := fmt.Sprintf(`
iptables -t mangle -A GOHPTS -p tcp -m multiport --dports %s -j RETURN
iptables -t mangle -A GOHPTS -p tcp -m multiport --sports %s -j RETURN
`, ts.p.ignoredPorts, ts.p.ignoredPorts)
			ts.p.runRuleCmd(cmdInit1)
			if ts.p.ipv6enabled {
				cmdInit11 := fmt.Sprintf(`
ip6tables -t mangle -A GOHPTS -p tcp -m multiport --dports %s -j RETURN
ip6tables -t mangle -A GOHPTS -p tcp -m multiport --sports %s -j RETURN
`, ts.p.ignoredPorts, ts.p.ignoredPorts)
				ts.p.runRuleCmd(cmdInit11)
			}
		}
		var cmdDocker string
		if ts.p.ipv6enabled {
			cmdDocker = `
if command -v docker >/dev/null 2>&1
then
for subnet in $(docker network inspect $(docker network ls -q)  --format '{{range .IPAM.Config}}{{println .Subnet}}{{end}}'); do
  if [[ "$subnet" == *:* ]]; then
	ip6tables -t mangle -A GOHPTS -p tcp -d "$subnet" -j RETURN
  else
	iptables -t mangle -A GOHPTS -p tcp -d "$subnet" -j RETURN
  fi
done
fi
`
		} else {
			cmdDocker = `
if command -v docker >/dev/null 2>&1
then
for subnet in $(docker network inspect $(docker network ls -q)  --format '{{range .IPAM.Config}}{{println .Subnet}}{{end}}'); do
  if [[ "$subnet" == *:* ]]; then
	continue
  else
	iptables -t mangle -A GOHPTS -p tcp -d "$subnet" -j RETURN
  fi
done
fi
`
		}
		ts.p.runRuleCmd(cmdDocker)
		cmdInit2 := fmt.Sprintf(`
iptables -t mangle -A GOHPTS -p tcp -m mark --mark %d -j RETURN
iptables -t mangle -A GOHPTS -p tcp -j TPROXY --on-port %s --tproxy-mark 1

iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
iptables -t mangle -A PREROUTING -p tcp -j GOHPTS
`, ts.p.mark, tproxyPort)
		ts.p.runRuleCmd(cmdInit2)
		if ts.p.ipv6enabled {
			cmdInit21 := fmt.Sprintf(`
ip6tables -t mangle -A GOHPTS -p tcp -m mark --mark %d -j RETURN
ip6tables -t mangle -A GOHPTS -p tcp -j TPROXY --on-port %s --tproxy-mark 1

ip6tables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
ip6tables -t mangle -A PREROUTING -p tcp -j GOHPTS
`, ts.p.mark, tproxyPort)
			ts.p.runRuleCmd(cmdInit21)
		}
	default:
		ts.p.logger.Fatal().Msgf("Unreachable, unknown mode: %s", ts.p.tproxyMode)
	}
	cmdCheckBBR := exec.Command("bash", "-c", fmt.Sprintf(`
    %s
	if command -v lsmod >/dev/null 2>&1 && command -v modprobe >/dev/null 2>&1
	then
	lsmod | grep -q '^tcp_bbr' || modprobe tcp_bbr
	fi
    `, setex))
	cmdCheckBBR.Stdout = os.Stdout
	cmdCheckBBR.Stderr = os.Stderr
	if !ts.p.debug {
		cmdCheckBBR.Stdout = nil
	}
	if err := cmdCheckBBR.Run(); err == nil {
		_ = runSysctlOptCmd("net.ipv4.tcp_congestion_control", "bbr", setex, opts, ts.p.debug, &ts.p.dump)
	}
	_ = runSysctlOptCmd("net.core.default_qdisc", "fq", setex, opts, ts.p.debug, &ts.p.dump)
	_ = runSysctlOptCmd("net.ipv4.tcp_tw_reuse", "1", setex, opts, ts.p.debug, &ts.p.dump)
	_ = runSysctlOptCmd("net.ipv4.tcp_fin_timeout", "15", setex, opts, ts.p.debug, &ts.p.dump)
	_ = runSysctlOptCmd("net.ipv4.tcp_rmem", "4096 65536 4194304", setex, opts, ts.p.debug, &ts.p.dump)
	_ = runSysctlOptCmd("net.ipv4.tcp_wmem", "4096 65536 4194304", setex, opts, ts.p.debug, &ts.p.dump)
	_ = runSysctlOptCmd("net.ipv4.tcp_window_scaling", "1", setex, opts, ts.p.debug, &ts.p.dump)
	_ = runSysctlOptCmd("net.core.somaxconn", "65535", setex, opts, ts.p.debug, &ts.p.dump)
}

func (ts *tproxyServer) ClearRedirectRules() error {
	switch ts.p.tproxyMode {
	case "redirect":
		cmd0 := `
iptables -t nat -D PREROUTING -p tcp -j GOHPTS 2>/dev/null || true
iptables -t nat -D OUTPUT -p tcp -j GOHPTS 2>/dev/null || true
iptables -t nat -F GOHPTS 2>/dev/null || true
iptables -t nat -X GOHPTS 2>/dev/null || true
`
		ts.p.runRuleCmd(cmd0)
		if ts.p.ipv6enabled {
			cmd1 := `
ip6tables -t nat -D PREROUTING -p tcp -j GOHPTS 2>/dev/null || true
ip6tables -t nat -D OUTPUT -p tcp -j GOHPTS 2>/dev/null || true
ip6tables -t nat -F GOHPTS 2>/dev/null || true
ip6tables -t nat -X GOHPTS 2>/dev/null || true
`
			ts.p.runRuleCmd(cmd1)
		}
	case "tproxy":
		cmd0 := `
iptables -t mangle -D PREROUTING -p tcp -m socket -j DIVERT 2>/dev/null || true
iptables -t mangle -D PREROUTING -p tcp -j GOHPTS 2>/dev/null || true
iptables -t mangle -F GOHPTS 2>/dev/null || true
iptables -t mangle -X GOHPTS 2>/dev/null || true
`
		ts.p.runRuleCmd(cmd0)
		if ts.p.ipv6enabled {
			cmd1 := `
ip6tables -t mangle -D PREROUTING -p tcp -m socket -j DIVERT 2>/dev/null || true
ip6tables -t mangle -D PREROUTING -p tcp -j GOHPTS 2>/dev/null || true
ip6tables -t mangle -F GOHPTS 2>/dev/null || true
ip6tables -t mangle -X GOHPTS 2>/dev/null || true
`
			ts.p.runRuleCmd(cmd1)
		}
	}
	return nil
}
