//go:build linux || (android && arm)

package gohpts

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/shadowy-pycoder/mshark/layers"
	"github.com/shadowy-pycoder/mshark/network"
	"github.com/wzshiming/socks5"
	"golang.org/x/sys/unix"
)

const (
	readTimeoutUDP  time.Duration = 5 * time.Second
	writeTimeoutUDP time.Duration = 5 * time.Second
	idleTimeoutUDP  time.Duration = 30 * time.Second
	udpBufferSize   int           = 4096
)

type udpConn struct {
	*socks5.UDPConn
	srcAddr  *net.UDPAddr
	dstAddr  *net.UDPAddr
	lastSeen time.Time
	written  atomic.Uint64
	reqChan  chan layers.Layer
	respChan chan layers.Layer
}

func (uc *udpConn) SrcPort() *uint16 {
	srcPort := uint16(uc.dstAddr.Port)
	return &srcPort
}

func (uc *udpConn) DstPort() *uint16 {
	dstPort := uint16(uc.dstAddr.Port)
	return &dstPort
}

func (uc *udpConn) close() error {
	close(uc.reqChan)
	close(uc.respChan)
	return uc.Close()
}

func newUDPConn(srcAddr *net.UDPAddr, dstAddr *net.UDPAddr, sockDialer contextDialer, network string) (*udpConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := sockDialer.DialContext(ctx, network, dstAddr.String())
	if err != nil {
		return nil, err
	}
	relayConn, ok := conn.(*socks5.UDPConn)
	if !ok {
		return nil, fmt.Errorf("failed obtaining relay connection")
	}
	return &udpConn{
		UDPConn:  relayConn,
		srcAddr:  srcAddr,
		dstAddr:  dstAddr,
		lastSeen: time.Now(),
		reqChan:  make(chan layers.Layer),
		respChan: make(chan layers.Layer),
	}, nil
}

type udpConnections struct {
	wg   sync.WaitGroup
	quit chan struct{}
	sync.RWMutex
	clients map[string]*udpConn
}

func (ucs *udpConnections) Add(conn *udpConn) {
	ucs.Lock()
	ucs.clients[fmt.Sprintf("%s,%s", conn.srcAddr, conn.dstAddr)] = conn
	ucs.Unlock()
}

func (ucs *udpConnections) Get(srcAddr, dstAddr *net.UDPAddr) (*udpConn, bool) {
	ucs.RLock()
	defer ucs.RUnlock()
	conn, ok := ucs.clients[fmt.Sprintf("%s,%s", srcAddr, dstAddr)]
	return conn, ok
}

func (ucs *udpConnections) Remove(conn *udpConn) {
	ucs.Lock()
	delete(ucs.clients, fmt.Sprintf("%s,%s", conn.srcAddr, conn.dstAddr))
	ucs.Unlock()
}

func (ucs *udpConnections) UpdateLastSeen(conn *udpConn) {
	ucs.Lock()
	conn.lastSeen = time.Now()
	ucs.Unlock()
}

func (ucs *udpConnections) RemoveByAddr(addr string) {
	ucs.Lock()
	delete(ucs.clients, addr)
	ucs.Unlock()
}

func (ucs *udpConnections) Cleanup() {
	ucs.wg.Add(1)
	t := time.NewTicker(idleTimeoutUDP)
	for {
		select {
		case <-ucs.quit:
			ucs.Lock()
			for _, conn := range ucs.clients {
				conn.close()
			}
			ucs.Unlock()
			ucs.wg.Done()
			return
		case <-t.C:
			ucs.Lock()
			for k, conn := range ucs.clients {
				if time.Since(conn.lastSeen) > idleTimeoutUDP {
					conn.close()
					ucs.RemoveByAddr(k)
				}
			}
			ucs.Unlock()
		}
	}
}

type tproxyServerUDP struct {
	conn         *net.UDPConn
	quit         chan struct{}
	wg           sync.WaitGroup
	p            *Proxy
	clients      *udpConnections
	gwConn       *net.UDPConn
	gwConn6      *net.UDPConn
	startingFlag atomic.Bool
	closingFlag  atomic.Bool
}

func newTproxyServerUDP(p *Proxy) (*tproxyServerUDP, error) {
	tsu := &tproxyServerUDP{
		quit: make(chan struct{}),
		p:    p,
	}
	lc := net.ListenConfig{
		Control: func(network, address string, conn syscall.RawConn) error {
			var operr error
			size := 2 * 1024 * 1024
			if err := conn.Control(func(fd uintptr) {
				operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
				operr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
				operr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
				if tsu.p.ipv6enabled {
					operr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
					operr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
				}
				operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, size)
				operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, size)
			}); err != nil {
				return err
			}
			return operr
		},
	}
	pconn, err := lc.ListenPacket(context.Background(), tsu.p.udp, tsu.p.tproxyAddrUDP)
	if err != nil {
		return nil, err
	}
	tsu.conn = pconn.(*net.UDPConn)
	tsu.clients = &udpConnections{quit: tsu.quit, clients: make(map[string]*udpConn)}
	if tsu.p.arpspoofer != nil && tsu.p.gwDNS != nil {
		lc = net.ListenConfig{
			Control: func(network, address string, conn syscall.RawConn) error {
				var operr error
				size := 2 * 1024 * 1024
				if err := conn.Control(func(fd uintptr) {
					operr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
					operr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_FREEBIND, 1)
					operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
					operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
					operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, size)
					operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, size)
				}); err != nil {
					return err
				}
				return operr
			},
		}
		pconn, err = lc.ListenPacket(context.Background(), tsu.p.udp, tsu.p.gwDNS.String())
		if err != nil {
			return nil, err
		}
		tsu.gwConn = pconn.(*net.UDPConn)
	}
	if tsu.p.ndpspoofer != nil && tsu.p.raEnabled && tsu.p.hostDNS6 != nil && tsu.p.gwDNS6 != nil {
		lc = net.ListenConfig{
			Control: func(network, address string, conn syscall.RawConn) error {
				var operr error
				size := 2 * 1024 * 1024
				if err := conn.Control(func(fd uintptr) {
					operr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
					operr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_FREEBIND, 1)
					operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
					operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
					operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, size)
					operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, size)
				}); err != nil {
					return err
				}
				return operr
			},
		}
		pconn, err = lc.ListenPacket(context.Background(), tsu.p.udp, tsu.p.hostDNS6.String())
		if err != nil {
			return nil, err
		}
		tsu.gwConn6 = pconn.(*net.UDPConn)
	}
	return tsu, nil
}

// TODO: try to minimize code duplication here

func (tsu *tproxyServerUDP) Serve() {
	tsu.startingFlag.Store(true)
	tsu.wg.Add(1)
	go tsu.clients.Cleanup()
	if tsu.p.arpspoofer != nil {
		go func() {
			tsu.listenAndServeDNS(tsu.gwConn, tsu.p.gwDNS)
			tsu.wg.Done()
		}()
	}
	if tsu.p.ndpspoofer != nil && tsu.p.raEnabled {
		go func() {
			tsu.listenAndServeDNS(tsu.gwConn6, tsu.p.gwDNS6)
			tsu.wg.Done()
		}()
	}
	buf := make([]byte, udpBufferSize)
	oob := make([]byte, 1500)
	tsu.startingFlag.Store(false)
	arrow := "→ "
	if tsu.p.nocolor {
		arrow = "->"
	}
	for {
		select {
		case <-tsu.quit:
			tsu.wg.Done()
			return
		default:
			erd := tsu.conn.SetReadDeadline(time.Now().Add(readTimeoutUDP))
			if erd != nil {
				if errors.Is(erd, net.ErrClosed) {
					continue
				}
				tsu.p.logger.Error().Err(erd).Msgf("[udp %s] Failed setting read deadline", tsu.p.tproxyMode)
				continue
			}
			n, oobn, _, srcAddr, er := tsu.conn.ReadMsgUDP(buf, oob)
			if n > 0 {
				dstAddr, err := tsu.getOriginalDst(oob[:oobn])
				if err != nil {
					tsu.p.logger.Error().Err(err).Msgf("[udp %s] Failed getting original destination", tsu.p.tproxyMode)
					continue
				}
				if dstAddr.Port == 53 {
					conn, err := newDNSDirectConn(srcAddr, dstAddr, tsu.p.mark, tsu.p.udp)
					if err != nil {
						tsu.p.logger.Error().
							Err(err).
							Msgf("[udp %s] Failed creating UDP connection for %s%s%s", tsu.p.tproxyMode, srcAddr, arrow, dstAddr)
						continue
					}
					srcConnStr := fmt.Sprintf("%s%s%s", conn.srcAddr, arrow, conn.dstAddr)
					dstConnStr := fmt.Sprintf("%s%s%s", conn.LocalAddr(), arrow, conn.dstAddr)
					tsu.p.logger.Debug().Msgf("[udp %s] src: %s - dst: %s", tsu.p.tproxyMode, srcConnStr, dstConnStr)
					ewd := conn.SetWriteDeadline(time.Now().Add(writeTimeoutUDP))
					if ewd != nil {
						if errors.Is(ewd, net.ErrClosed) {
							conn.close()
							continue
						}
						tsu.p.logger.Error().Err(ewd).Msgf("[udp %s] Failed setting write deadline", tsu.p.tproxyMode)
						conn.close()
						continue
					}
					if tsu.p.sniff || tsu.p.filter != nil {
						dnsQuery := &layers.DNSMessage{}
						if err := dnsQuery.Parse(buf[:n]); err == nil {
							if tsu.closingFlag.Load() {
								conn.close()
								continue
							}
							if tsu.p.sniff {
								tsu.wg.Add(1)
								sniffheader := make([]string, 0, 3)
								id := getID(tsu.p.nocolor)
								if tsu.p.json {
									sniffheader = append(
										sniffheader,
										fmt.Sprintf(
											"{\"connection\":{\"tproxy_mode\":%q,\"src_remote\":%q,\"src_local\":%q,\"dst_local\":%q,\"dst_remote\":%q,\"original_dst\":%q}}",
											tsu.p.tproxyMode,
											srcAddr,
											conn.dstAddr,
											conn.LocalAddr(),
											conn.dstAddr,
											conn.dstAddr.String(),
										),
									)
								} else {
									connections := colorizeConnectionsTransparent(
										srcAddr,
										conn.dstAddr,
										conn.LocalAddr(),
										conn.dstAddr,
										conn.dstAddr.String(),
										id, tsu.p.nocolor,
									)
									sniffheader = append(sniffheader, connections)
								}
								go tsu.p.sniffreporter(&tsu.wg, &sniffheader, conn.reqChan, conn.respChan, id)
								conn.reqChan <- dnsQuery
							}
							// NOTE: checking only the first record of questions
							if tsu.p.filter != nil {
								question := dnsQuery.Questions[0]
								domain := question.Name
								typ := question.Type
								addr, ok := tsu.p.filter.domainIsSpoofed(domain)
								var dnsReply *layers.DNSMessage
								if ok {
									flags := layers.NewDNSFlags(
										layers.QRFlagReply,
										layers.OpCodeQuery,
										false,
										false,
										dnsQuery.Flags.RD != 0,
										true,
										false,
										false,
										dnsQuery.Flags.NA != 0,
										layers.RCodeNoError,
									)
									answers := []*layers.ResourceRecord{}
									var rdata layers.RData
									if typ.Val == layers.RecTypeA && addr.Is4() { // answer IPv4 for A query
										rdata = &layers.RDataA{Address: addr}
									} else if typ.Val == layers.RecTypeAAAA && network.Is6(addr) { // AAAA
										rdata = &layers.RDataAAAA{Address: addr}
									}
									if rdata != nil {
										rdlen := uint16(len(rdata.ToBytes()))
										answers = append(answers, &layers.ResourceRecord{
											Name:     domain,
											Type:     typ,
											Class:    question.Class,
											TTL:      3600,
											RDLength: rdlen,
											RData:    rdata,
										})
									}
									dnsReply, err = layers.NewDNSMessage(dnsQuery.TransactionID, flags, dnsQuery.Questions, answers, nil, nil)
									if err != nil {
										tsu.p.logger.Error().Err(err).
											Msgf("[udp %s] Failed creating reply dns message %s%s%s", tsu.p.tproxyMode, conn.LocalAddr(), arrow, conn.srcAddr)
										goto reply // reply normally
									}
								} else if tsu.p.filter.domainIsBlacklisted(domain) {
									flags := layers.NewDNSFlags(
										layers.QRFlagReply,
										layers.OpCodeQuery,
										false,
										false,
										dnsQuery.Flags.RD != 0,
										true,
										false,
										false,
										dnsQuery.Flags.NA != 0,
										layers.RCodeNameError,
									)
									dnsReply, err = layers.NewDNSMessage(dnsQuery.TransactionID, flags, dnsQuery.Questions, nil, nil, nil)
									if err != nil {
										tsu.p.logger.Error().Err(err).
											Msgf("[udp %s] Failed creating reply dns message %s%s%s", tsu.p.tproxyMode, conn.LocalAddr(), arrow, conn.srcAddr)
										goto reply
									}
								}
								if dnsReply != nil {
									if err := conn.replyToClient(dnsReply.ToBytes()); err != nil {
										tsu.p.logger.Error().Err(err).
											Msgf("[udp %s] Failed creating reply dns message %s%s%s", tsu.p.tproxyMode, conn.LocalAddr(), arrow, conn.srcAddr)
										goto reply
									}
									if tsu.p.sniff {
										conn.respChan <- dnsReply
									}
									conn.written.Add(uint64(len(dnsReply.ToBytes())))
									srcConnStr := fmt.Sprintf("%s%s%s", conn.srcAddr, arrow, conn.dstAddr)
									dstConnStr := fmt.Sprintf("%s%s%s", conn.LocalAddr(), arrow, conn.dstAddr)
									tsu.p.logger.Debug().
										Msgf("Copied %s for udp src: %s - dst: %s", network.PrettifyBytes(int64(conn.written.Load())), srcConnStr, dstConnStr)
									conn.close()
									continue
								}
							}
						}
					}
				reply:
					nw, err := conn.Write(buf[:n])
					if err != nil {
						if ne, ok := err.(net.Error); ok && ne.Timeout() {
							conn.close()
							continue
						}
						if errors.Is(err, net.ErrClosed) {
							conn.close()
							continue
						}
						tsu.p.logger.Error().
							Err(err).
							Msgf("[udp %s] Failed sending message %s%s%s", tsu.p.tproxyMode, conn.LocalAddr(), arrow, conn.dstAddr)
						conn.close()
						continue
					}
					conn.written.Add(uint64(nw))
					go func() {
						tsu.handleDNSDirectConnection(conn)
					}()
				} else {
					conn, found := tsu.clients.Get(srcAddr, dstAddr)
					if !found {
						sockDialer, err := tsu.p.getSockDialer()
						if err != nil {
							tsu.p.logger.Error().
								Err(err).
								Msgf("[udp %s] Failed getting %s client for %s%s%s", tsu.p.tproxyMode, tsu.p.socksProto, srcAddr, arrow, dstAddr)
							continue
						}
						conn, err = newUDPConn(srcAddr, dstAddr, sockDialer, tsu.p.udp)
						if err != nil {
							tsu.p.logger.Error().
								Err(err).
								Msgf("[udp %s] Failed creating UDP connection for %s%s%s", tsu.p.tproxyMode, srcAddr, arrow, dstAddr)
							continue
						}
						tsu.clients.Add(conn)
						go func() {
							tsu.handleConnection(conn)
						}()
					}

					srcConnStr := fmt.Sprintf("%s%s%s", srcAddr, arrow, dstAddr)
					dstConnStr := fmt.Sprintf("%s%s%s%s%s", tsu.conn.LocalAddr(), arrow, conn.LocalAddr(), arrow, dstAddr)
					tsu.p.logger.Debug().Msgf("[udp %s] src: %s - dst: %s", tsu.p.tproxyMode, srcConnStr, dstConnStr)
					ewd := conn.SetWriteDeadline(time.Now().Add(writeTimeoutUDP))
					if ewd != nil {
						if errors.Is(ewd, net.ErrClosed) {
							continue
						}
						tsu.p.logger.Error().Err(ewd).Msgf("[udp %s] Failed setting write deadline", tsu.p.tproxyMode)
						continue
					}
					if tsu.p.sniff {
						if next := layers.ParseNextLayer(buf[:n], conn.SrcPort(), conn.DstPort()); next != nil {
							if tsu.closingFlag.Load() {
								continue
							}
							// NOTE: assume no dns messages here, otherwise call direct dns handling
							tsu.wg.Add(1)
							sniffheader := make([]string, 0, 3)
							id := getID(tsu.p.nocolor)
							if tsu.p.json {
								sniffheader = append(
									sniffheader,
									fmt.Sprintf(
										"{\"connection\":{\"tproxy_mode\":%q,\"src_remote\":%q,\"src_local\":%q,\"dst_local\":%q,\"dst_remote\":%q,\"original_dst\":%s}}",
										tsu.p.tproxyMode,
										srcAddr,
										conn.dstAddr,
										tsu.conn.LocalAddr(),
										conn.LocalAddr(),
										conn.dstAddr,
									),
								)
							} else {
								connections := colorizeConnectionsTransparent(
									srcAddr,
									conn.dstAddr,
									tsu.conn.LocalAddr(),
									conn.LocalAddr(),
									conn.dstAddr.String(),
									id, tsu.p.nocolor,
								)
								sniffheader = append(sniffheader, connections)
							}
							go tsu.p.sniffreporter(&tsu.wg, &sniffheader, conn.reqChan, conn.respChan, id)
							conn.reqChan <- next
						}
					}
					nw, err := conn.WriteToUDP(buf[:n], dstAddr)
					if err != nil {
						if ne, ok := err.(net.Error); ok && ne.Timeout() {
							continue
						}
						if errors.Is(err, net.ErrClosed) {
							continue
						}
						tsu.p.logger.Error().Err(err).Msgf("[udp %s] Failed sending message %s%s%s", tsu.p.tproxyMode, srcAddr, arrow, dstAddr)
						continue
					}
					conn.written.Add(uint64(nw))
					tsu.clients.UpdateLastSeen(conn)
				}
			}
			if er != nil {
				if ne, ok := er.(net.Error); ok && ne.Timeout() {
					continue
				}
				if errors.Is(er, net.ErrClosed) {
					continue
				}
				if errors.Is(er, io.EOF) {
					continue
				}
				tsu.p.logger.Error().Err(er).Msgf("[udp %s] Failed reading UDP message", tsu.p.tproxyMode)
				continue
			}
		}
	}
}

func (tsu *tproxyServerUDP) handleConnection(conn *udpConn) {
	if tsu.closingFlag.Load() {
		return
	}
	tsu.wg.Add(1)
	buf := make([]byte, udpBufferSize)
	arrow := "→ "
	if tsu.p.nocolor {
		arrow = "->"
	}
	defer func() {
		srcConnStr := fmt.Sprintf("%s%s%s", conn.srcAddr, arrow, conn.dstAddr)
		dstConnStr := fmt.Sprintf("%s%s%s%s%s", tsu.conn.LocalAddr(), arrow, conn.LocalAddr(), arrow, conn.dstAddr)
		tsu.p.logger.Debug().Msgf("Copied %s for udp src: %s - dst: %s", network.PrettifyBytes(int64(conn.written.Load())), srcConnStr, dstConnStr)
		tsu.wg.Done()
	}()
readLoop:
	for {
		select {
		case <-tsu.quit:
			return
		default:
			erd := conn.SetReadDeadline(time.Now().Add(readTimeoutUDP))
			if erd != nil {
				if errors.Is(erd, net.ErrClosed) {
					return
				}
				tsu.p.logger.Debug().Err(erd).Msgf("[udp %s] Failed setting read deadline %s%s%s", tsu.p.tproxyMode, conn.LocalAddr(), arrow, tsu.conn.LocalAddr())
				break readLoop
			}
			nr, er := conn.Read(buf)
			if nr > 0 {
				ewd := tsu.conn.SetWriteDeadline(time.Now().Add(writeTimeoutUDP))
				if ewd != nil {
					tsu.p.logger.Debug().Err(ewd).Msgf("[udp %s] Failed setting write deadline %s%s%s", tsu.p.tproxyMode, tsu.conn.LocalAddr(), arrow, conn.srcAddr)
					break readLoop
				}
				if tsu.p.sniff {
					if next := layers.ParseNextLayer(buf[:nr], conn.SrcPort(), conn.DstPort()); next != nil {
						conn.respChan <- next
					}
				}
				nw, ew := tsu.conn.WriteToUDP(buf[0:nr], conn.srcAddr)
				if nw < 0 || nr < nw {
					nw = 0
					if ew == nil {
						ew = errInvalidWrite
					}
				}
				conn.written.Add(uint64(nw))
				if ew != nil {
					if errors.Is(ew, net.ErrClosed) {
						return
					}
					if ne, ok := ew.(net.Error); ok && ne.Timeout() {
						break readLoop
					}
				}
				if nr != nw {
					tsu.p.logger.Debug().Err(io.ErrShortWrite).Msgf("[udp %s] Failed sending message %s%s%s", tsu.p.tproxyMode, tsu.conn.LocalAddr(), arrow, conn.srcAddr)
					break readLoop
				}
			}
			if er != nil {
				if ne, ok := er.(net.Error); ok && ne.Timeout() {
					break readLoop
				}
				if errors.Is(er, net.ErrClosed) {
					return
				}
				if errors.Is(er, io.EOF) {
					break readLoop
				}
				break readLoop
			}
		}
	}
	conn.Close()
	tsu.clients.Remove(conn)
}

type dnsConn struct {
	*net.UDPConn
	srcAddr  *net.UDPAddr
	dstAddr  *net.UDPAddr
	written  atomic.Uint64
	reqChan  chan layers.Layer
	respChan chan layers.Layer
}

func (dc *dnsConn) close() error {
	close(dc.reqChan)
	close(dc.respChan)
	return dc.Close()
}

func newDNSConn(srcAddr, dstAddr *net.UDPAddr, mark uint, network string) (*dnsConn, error) {
	dialer := getBaseDialer(timeout, mark)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := dialer.DialContext(ctx, network, dstAddr.String())
	if err != nil {
		return nil, err
	}
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		return nil, fmt.Errorf("failed obtaining dns connection")
	}
	return &dnsConn{
		UDPConn:  udpConn,
		srcAddr:  srcAddr,
		dstAddr:  dstAddr,
		reqChan:  make(chan layers.Layer),
		respChan: make(chan layers.Layer),
	}, nil
}

func (tsu *tproxyServerUDP) listenAndServeDNS(gwConn *net.UDPConn, gwDNS *net.UDPAddr) {
	if tsu.closingFlag.Load() {
		return
	}
	tsu.wg.Add(1)
	buf := make([]byte, udpBufferSize)
	arrow := "→ "
	if tsu.p.nocolor {
		arrow = "->"
	}
	for {
		select {
		case <-tsu.quit:
			return
		default:
			erd := gwConn.SetReadDeadline(time.Now().Add(readTimeoutUDP))
			if erd != nil {
				if errors.Is(erd, net.ErrClosed) {
					continue
				}
				tsu.p.logger.Error().Err(erd).Msgf("[udp %s] Failed setting read deadline", tsu.p.tproxyMode)
				continue
			}
			n, srcAddr, er := gwConn.ReadFromUDP(buf)
			if n > 0 {
				conn, err := newDNSConn(srcAddr, gwDNS, tsu.p.mark, tsu.p.udp)
				if err != nil {
					tsu.p.logger.Error().Err(err).Msgf("[udp %s] Failed creating UDP connection %s%s%s", tsu.p.tproxyMode, srcAddr, arrow, gwDNS)
					continue
				}
				srcConnStr := fmt.Sprintf("%s%s%s", srcAddr, arrow, gwConn.LocalAddr())
				dstConnStr := fmt.Sprintf("%s%s%s", conn.LocalAddr(), arrow, conn.dstAddr)
				tsu.p.logger.Debug().Msgf("[udp %s] src: %s - dst: %s", tsu.p.tproxyMode, srcConnStr, dstConnStr)
				ewd := conn.SetWriteDeadline(time.Now().Add(writeTimeoutUDP))
				if ewd != nil {
					if errors.Is(ewd, net.ErrClosed) {
						conn.close()
						continue
					}
					tsu.p.logger.Error().Err(ewd).Msgf("[udp %s] Failed setting write deadline", tsu.p.tproxyMode)
					conn.close()
					continue
				}
				if tsu.p.sniff || tsu.p.filter != nil {
					dnsQuery := &layers.DNSMessage{}
					if err := dnsQuery.Parse(buf[:n]); err == nil {
						if tsu.closingFlag.Load() {
							conn.close()
							continue
						}
						if tsu.p.sniff {
							tsu.wg.Add(1)
							sniffheader := make([]string, 0, 3)
							id := getID(tsu.p.nocolor)
							if tsu.p.json {
								sniffheader = append(
									sniffheader,
									fmt.Sprintf(
										"{\"connection\":{\"tproxy_mode\":%q,\"src_remote\":%q,\"src_local\":%q,\"dst_local\":%q,\"dst_remote\":%q,\"original_dst\":%q}}",
										tsu.p.tproxyMode,
										srcAddr,
										gwConn.LocalAddr(),
										conn.LocalAddr(),
										conn.dstAddr,
										gwConn.LocalAddr(),
									),
								)
							} else {
								connections := colorizeConnectionsTransparent(
									srcAddr,
									gwConn.LocalAddr(),
									conn.LocalAddr(),
									conn.dstAddr,
									gwConn.LocalAddr().String(),
									id, tsu.p.nocolor,
								)
								sniffheader = append(sniffheader, connections)
							}
							go tsu.p.sniffreporter(&tsu.wg, &sniffheader, conn.reqChan, conn.respChan, id)
							conn.reqChan <- dnsQuery
						}

						if tsu.p.filter != nil {
							question := dnsQuery.Questions[0]
							domain := question.Name
							typ := question.Type
							addr, ok := tsu.p.filter.domainIsSpoofed(domain)
							var dnsReply *layers.DNSMessage
							if ok {
								flags := layers.NewDNSFlags(
									layers.QRFlagReply,
									layers.OpCodeQuery,
									false,
									false,
									dnsQuery.Flags.RD != 0,
									true,
									false,
									false,
									dnsQuery.Flags.NA != 0,
									layers.RCodeNoError,
								)
								answers := []*layers.ResourceRecord{}
								var rdata layers.RData
								if typ.Val == layers.RecTypeA && addr.Is4() {
									rdata = &layers.RDataA{Address: addr}
								} else if typ.Val == layers.RecTypeAAAA && network.Is6(addr) {
									rdata = &layers.RDataAAAA{Address: addr}
								}
								if rdata != nil {
									rdlen := uint16(len(rdata.ToBytes()))
									answers = append(answers, &layers.ResourceRecord{
										Name:     domain,
										Type:     typ,
										Class:    question.Class,
										TTL:      3600,
										RDLength: rdlen,
										RData:    rdata,
									})
								}
								dnsReply, err = layers.NewDNSMessage(dnsQuery.TransactionID, flags, dnsQuery.Questions, answers, nil, nil)
								if err != nil {
									tsu.p.logger.Error().Err(err).
										Msgf("[udp %s] Failed creating reply dns message %s%s%s", tsu.p.tproxyMode, conn.LocalAddr(), arrow, conn.srcAddr)
									goto gwReply
								}
							} else if tsu.p.filter.domainIsBlacklisted(domain) {
								flags := layers.NewDNSFlags(
									layers.QRFlagReply,
									layers.OpCodeQuery,
									false,
									false,
									dnsQuery.Flags.RD != 0,
									true,
									false,
									false,
									dnsQuery.Flags.NA != 0,
									layers.RCodeNameError,
								)
								dnsReply, err = layers.NewDNSMessage(dnsQuery.TransactionID, flags, dnsQuery.Questions, nil, nil, nil)
								if err != nil {
									tsu.p.logger.Error().Err(err).
										Msgf("[udp %s] Failed creating reply dns message %s%s%s", tsu.p.tproxyMode, conn.LocalAddr(), arrow, conn.srcAddr)
									goto gwReply
								}
							}
							if dnsReply != nil {
								nw, err := gwConn.WriteToUDP(dnsReply.ToBytes(), conn.srcAddr)
								if err != nil {
									tsu.p.logger.Error().Err(err).
										Msgf("[udp %s] Failed creating reply dns message %s%s%s", tsu.p.tproxyMode, conn.LocalAddr(), arrow, conn.srcAddr)
									goto gwReply
								}
								if tsu.p.sniff {
									conn.respChan <- dnsReply
								}
								conn.written.Add(uint64(nw))
								srcConnStr := fmt.Sprintf("%s%s%s", conn.srcAddr, arrow, conn.dstAddr)
								dstConnStr := fmt.Sprintf("%s%s%s", conn.LocalAddr(), arrow, conn.dstAddr)
								tsu.p.logger.Debug().
									Msgf("Copied %s for udp src: %s - dst: %s", network.PrettifyBytes(int64(conn.written.Load())), srcConnStr, dstConnStr)
								conn.close()
								continue
							}
						}
					}
				}
			gwReply:
				nw, err := conn.Write(buf[:n])
				if err != nil {
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						conn.close()
						continue
					}
					if errors.Is(err, net.ErrClosed) {
						conn.close()
						continue
					}
					tsu.p.logger.Error().
						Err(err).
						Msgf("[udp %s] Failed sending message %s%s%s", tsu.p.tproxyMode, conn.LocalAddr(), arrow, conn.dstAddr)
					conn.close()
					continue
				}
				conn.written.Add(uint64(nw))
				go tsu.handleDNSConnection(conn, gwConn)
			}
			if er != nil {
				if ne, ok := er.(net.Error); ok && ne.Timeout() {
					// NOTE: conn can still be created and open
					continue
				}
				if errors.Is(er, net.ErrClosed) {
					continue
				}
				if errors.Is(er, io.EOF) {
					continue
				}
				tsu.p.logger.Error().Err(er).Msgf("[udp %s] Failed reading UDP message", tsu.p.tproxyMode)
				continue
			}
		}
	}
}

func (tsu *tproxyServerUDP) handleDNSConnection(conn *dnsConn, gwConn *net.UDPConn) {
	if tsu.closingFlag.Load() {
		return
	}
	tsu.wg.Add(1)
	arrow := "→ "
	if tsu.p.nocolor {
		arrow = "->"
	}
	defer func() {
		srcConnStr := fmt.Sprintf("%s%s%s", conn.srcAddr, arrow, gwConn.LocalAddr())
		dstConnStr := fmt.Sprintf("%s%s%s", conn.LocalAddr(), arrow, conn.dstAddr)
		tsu.p.logger.Debug().Msgf("Copied %s for udp src: %s - dst: %s", network.PrettifyBytes(int64(conn.written.Load())), srcConnStr, dstConnStr)
		conn.close()
		tsu.wg.Done()
	}()
	buf := make([]byte, udpBufferSize)
	erd := conn.SetReadDeadline(time.Now().Add(readTimeoutUDP))
	if erd != nil {
		if errors.Is(erd, net.ErrClosed) {
			return
		}
		tsu.p.logger.Debug().Err(erd).Msgf("[udp %s] Failed setting read deadline %s%s%s", tsu.p.tproxyMode, conn.dstAddr, arrow, conn.LocalAddr())
		return
	}
	nr, er := conn.Read(buf)
	if nr > 0 {
		ewd := gwConn.SetWriteDeadline(time.Now().Add(writeTimeoutUDP))
		if er != nil {
			if errors.Is(ewd, net.ErrClosed) {
				return
			}
			tsu.p.logger.Debug().
				Err(ewd).
				Msgf("[udp %s] Failed setting write deadline %s%s%s", tsu.p.tproxyMode, conn.LocalAddr(), arrow, conn.srcAddr)
			return
		}
		if tsu.p.sniff {
			dns := &layers.DNSMessage{}
			if err := dns.Parse(buf[:nr]); err == nil {
				conn.respChan <- dns
			} else {
				tsu.p.logger.Debug().Err(err).Msgf("%v", buf[:nr])
			}
		}
		nw, ew := gwConn.WriteToUDP(buf[0:nr], conn.srcAddr)
		if nw < 0 || nr < nw {
			nw = 0
			if ew == nil {
				ew = errInvalidWrite
			}
		}
		conn.written.Add(uint64(nw))
		if ew != nil {
			if errors.Is(ew, net.ErrClosed) {
				return
			}
			if ne, ok := ew.(net.Error); ok && ne.Timeout() {
				return
			}
		}
		if nr != nw {
			tsu.p.logger.Debug().
				Err(io.ErrShortWrite).
				Msgf("[udp %s] Failed sending message %s%s%s", tsu.p.tproxyMode, conn.LocalAddr(), arrow, conn.srcAddr)
			return
		}
	}
	if er != nil {
		return
	}
}

type dnsDirectConn struct {
	*net.UDPConn
	srcAddr  *net.UDPAddr
	dstAddr  *net.UDPAddr
	written  atomic.Uint64
	reqChan  chan layers.Layer
	respChan chan layers.Layer
}

func (ddc *dnsDirectConn) close() error {
	close(ddc.reqChan)
	close(ddc.respChan)
	return ddc.Close()
}

func (ddc *dnsDirectConn) replyToClient(data []byte) error {
	if ddc.dstAddr.IP.To4() != nil {
		return replyToClient4(ddc.srcAddr, ddc.dstAddr, data)
	}
	return replyToClient6(ddc.srcAddr, ddc.dstAddr, data)
}

func replyToClient4(clientAddr, originalDst *net.UDPAddr, data []byte) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TRANSPARENT, 1); err != nil {
		return err
	}

	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return err
	}
	bindAddr := &unix.SockaddrInet4{
		Port: originalDst.Port,
	}
	copy(bindAddr.Addr[:], originalDst.IP.To4())
	if err := unix.Bind(fd, bindAddr); err != nil {
		return err
	}
	srcAddr := &unix.SockaddrInet4{
		Port: clientAddr.Port,
	}
	copy(srcAddr.Addr[:], clientAddr.IP.To4())
	if err := unix.Sendto(fd, data, 0, srcAddr); err != nil {
		return err
	}
	return nil
}

func replyToClient6(clientAddr, originalDst *net.UDPAddr, data []byte) error {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil {
		return err
	}

	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return err
	}
	bindAddr := &unix.SockaddrInet6{
		Port: originalDst.Port,
	}
	copy(bindAddr.Addr[:], originalDst.IP.To16())
	if err := unix.Bind(fd, bindAddr); err != nil {
		return err
	}
	srcAddr := &unix.SockaddrInet6{
		Port: clientAddr.Port,
	}
	copy(srcAddr.Addr[:], clientAddr.IP.To16())
	if err := unix.Sendto(fd, data, 0, srcAddr); err != nil {
		return err
	}
	return nil
}

func newDNSDirectConn(srcAddr, dstAddr *net.UDPAddr, mark uint, network string) (*dnsDirectConn, error) {
	dialer := getBaseDialer(timeout, mark)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := dialer.DialContext(ctx, network, dstAddr.String())
	if err != nil {
		return nil, err
	}
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		return nil, fmt.Errorf("failed obtaining dns connection")
	}
	return &dnsDirectConn{
		UDPConn:  udpConn,
		srcAddr:  srcAddr,
		dstAddr:  dstAddr,
		reqChan:  make(chan layers.Layer),
		respChan: make(chan layers.Layer),
	}, nil
}

func (tsu *tproxyServerUDP) handleDNSDirectConnection(conn *dnsDirectConn) {
	if tsu.closingFlag.Load() {
		return
	}
	tsu.wg.Add(1)
	arrow := "→ "
	if tsu.p.nocolor {
		arrow = "->"
	}
	defer func() {
		srcConnStr := fmt.Sprintf("%s%s%s", conn.srcAddr, arrow, conn.dstAddr)
		dstConnStr := fmt.Sprintf("%s%s%s", conn.LocalAddr(), arrow, conn.dstAddr)
		tsu.p.logger.Debug().Msgf("Copied %s for udp src: %s - dst: %s", network.PrettifyBytes(int64(conn.written.Load())), srcConnStr, dstConnStr)
		conn.close()
		tsu.wg.Done()
	}()
	buf := make([]byte, udpBufferSize)
	erd := conn.SetReadDeadline(time.Now().Add(readTimeoutUDP))
	if erd != nil {
		if errors.Is(erd, net.ErrClosed) {
			return
		}
		tsu.p.logger.Debug().Err(erd).Msgf("[udp %s] Failed setting read deadline %s%s%s", tsu.p.tproxyMode, conn.dstAddr, arrow, conn.LocalAddr())
		return
	}
	nr, er := conn.Read(buf)
	if nr > 0 {
		ewd := conn.SetWriteDeadline(time.Now().Add(writeTimeoutUDP))
		if ewd != nil {
			if errors.Is(ewd, net.ErrClosed) {
				return
			}
			tsu.p.logger.Debug().
				Err(ewd).
				Msgf("[udp %s] Failed setting write deadline %s%s%s", tsu.p.tproxyMode, conn.LocalAddr(), arrow, conn.srcAddr)
			return
		}
		if tsu.p.sniff {
			dns := &layers.DNSMessage{}
			if err := dns.Parse(buf[:nr]); err == nil {
				conn.respChan <- dns
			} else {
				tsu.p.logger.Debug().Err(err).Msgf("%v", buf[:nr])
			}
		}
		err := conn.replyToClient(buf[:nr])
		if err != nil {
			tsu.p.logger.Debug().
				Err(io.ErrShortWrite).
				Msgf("[udp %s] Failed sending message %s%s%s", tsu.p.tproxyMode, conn.LocalAddr(), arrow, conn.srcAddr)
			return
		}
		conn.written.Add(uint64(nr)) // NOTE: do not have access to written bytes
	}
	if er != nil {
		tsu.p.logger.Debug().
			Err(er).
			Msgf("[udp %s] Failed reading message %s%s%s", tsu.p.tproxyMode, conn.LocalAddr(), arrow, conn.srcAddr)
		return
	}
}

func (tsu *tproxyServerUDP) Shutdown() {
	for tsu.startingFlag.Load() {
		time.Sleep(50 * time.Millisecond)
	}
	close(tsu.quit)
	tsu.closingFlag.Store(true)
	done := make(chan struct{})
	go func() {
		tsu.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return
	case <-time.After(shutdownTimeout):
		tsu.p.logger.Error().Msgf("[udp %s] Server timed out waiting for connections to finish", tsu.p.tproxyMode)
		return
	}
}

func (tsu *tproxyServerUDP) getOriginalDst(oob []byte) (*net.UDPAddr, error) {
	cmsgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}
	for _, cmsg := range cmsgs {
		if cmsg.Header.Level == unix.SOL_IP && cmsg.Header.Type == unix.IP_RECVORIGDSTADDR {
			originalDst := &syscall.RawSockaddrInet4{}
			copy((*[unsafe.Sizeof(*originalDst)]byte)(unsafe.Pointer(originalDst))[:], cmsg.Data)
			dstHost := netip.AddrFrom4(originalDst.Addr)
			dstPort := uint16(originalDst.Port<<8) | originalDst.Port>>8
			dstAddr, err := net.ResolveUDPAddr(tsu.p.udp /* NOTE: does not matter */, netip.AddrPortFrom(dstHost, dstPort).String())
			if err != nil {
				return nil, err
			}
			return dstAddr, nil
		}
		if cmsg.Header.Level == unix.SOL_IPV6 && cmsg.Header.Type == unix.IPV6_RECVORIGDSTADDR {
			originalDst := &syscall.RawSockaddrInet6{}
			copy((*[unsafe.Sizeof(*originalDst)]byte)(unsafe.Pointer(originalDst))[:], cmsg.Data)
			dstHost := netip.AddrFrom16(originalDst.Addr)
			dstPort := uint16(originalDst.Port<<8) | originalDst.Port>>8
			dstAddr, err := net.ResolveUDPAddr(tsu.p.udp, netip.AddrPortFrom(dstHost, dstPort).String())
			if err != nil {
				return nil, err
			}
			return dstAddr, nil
		}
	}
	return nil, fmt.Errorf("original destination not found")
}

func (tsu *tproxyServerUDP) ApplyRedirectRules(opts map[string]string) {
	_, tproxyPortUDP, _ := net.SplitHostPort(tsu.p.tproxyAddrUDP)
	var setex string
	if tsu.p.debug {
		setex = "set -ex"
	}
	switch tsu.p.tproxyMode {
	case "redirect":
		tsu.p.logger.Fatal().Msgf("Unsupported mode: %s", tsu.p.tproxyMode)
	case "tproxy":
		cmdClear0 := `
iptables -t mangle -D PREROUTING -p udp -m socket -j DIVERT 2>/dev/null || true
iptables -t mangle -D PREROUTING -p udp -j GOHPTS_UDP 2>/dev/null || true
iptables -t mangle -F GOHPTS_UDP 2>/dev/null || true
iptables -t mangle -X GOHPTS_UDP 2>/dev/null || true
`
		tsu.p.runRuleCmd(cmdClear0)
		if tsu.p.ipv6enabled {
			cmdClear1 := `
ip6tables -t mangle -D PREROUTING -p udp -m socket -j DIVERT 2>/dev/null || true
ip6tables -t mangle -D PREROUTING -p udp -j GOHPTS_UDP 2>/dev/null || true
ip6tables -t mangle -F GOHPTS_UDP 2>/dev/null || true
ip6tables -t mangle -X GOHPTS_UDP 2>/dev/null || true
`
			tsu.p.runRuleCmd(cmdClear1)
		}

		cmdInit0 := `
iptables -t mangle -N GOHPTS_UDP 2>/dev/null || true
iptables -t mangle -F GOHPTS_UDP

iptables -t mangle -A GOHPTS_UDP -p udp -d 127.0.0.0/8 -j RETURN
iptables -t mangle -A GOHPTS_UDP -p udp -d 224.0.0.0/4 -j RETURN
iptables -t mangle -A GOHPTS_UDP -p udp -d 255.255.255.255/32 -j RETURN
`
		tsu.p.runRuleCmd(cmdInit0)
		var prefix *netip.Prefix
		pr, err := network.GetIPv4PrefixFromInterface(tsu.p.iface)
		if err != nil {
			tsu.p.logger.Error().Err(err).Msgf("[udp %s] Failed getting host from %s", tsu.p.tproxyMode, tsu.p.iface.Name)
		} else {
			prefix = &pr
			cmdInit00 := fmt.Sprintf(`
iptables -t mangle -A GOHPTS_UDP -p udp -d %s -j RETURN
`, prefix.Masked())
			tsu.p.runRuleCmd(cmdInit00)
		}
		if tsu.p.ipv6enabled {
			cmdInit01 := `
ip6tables -t mangle -N GOHPTS_UDP 2>/dev/null || true
ip6tables -t mangle -F GOHPTS_UDP

ip6tables -t mangle -A GOHPTS_UDP -p udp -d ::/128 -j RETURN
ip6tables -t mangle -A GOHPTS_UDP -p udp -d ::1/128 -j RETURN
ip6tables -t mangle -A GOHPTS_UDP -p udp -d ff00::/8 -j RETURN
ip6tables -t mangle -A GOHPTS_UDP -p udp -d fe80::/10 -j RETURN
ip6tables -t mangle -A GOHPTS_UDP -p udp -d fc00::/7 -j RETURN
`
			tsu.p.runRuleCmd(cmdInit01)
			if prefix6, err := network.GetIPv6GlobalUnicastPrefixFromInterface(tsu.p.iface); err == nil {
				cmdInit02 := fmt.Sprintf(`
ip6tables -t mangle -A GOHPTS_UDP -p udp -s %s -d %s -j RETURN
`, prefix6.Masked(), prefix6.Masked())
				tsu.p.runRuleCmd(cmdInit02)
			}
		}
		if tsu.p.ignoredPorts != "" {
			cmdInit1 := fmt.Sprintf(`
iptables -t mangle -A GOHPTS_UDP -p udp -m multiport --dports %s -j RETURN
iptables -t mangle -A GOHPTS_UDP -p udp -m multiport --sports %s -j RETURN
`, tsu.p.ignoredPorts, tsu.p.ignoredPorts)
			tsu.p.runRuleCmd(cmdInit1)
			if tsu.p.ipv6enabled {
				cmdInit11 := fmt.Sprintf(`
ip6tables -t mangle -A GOHPTS_UDP -p udp -m multiport --dports %s -j RETURN
ip6tables -t mangle -A GOHPTS_UDP -p udp -m multiport --sports %s -j RETURN
`, tsu.p.ignoredPorts, tsu.p.ignoredPorts)
				tsu.p.runRuleCmd(cmdInit11)
			}
		}
		var cmdDocker string
		if tsu.p.ipv6enabled {
			cmdDocker = `
if command -v docker >/dev/null 2>&1
then
for subnet in $(docker network inspect $(docker network ls -q)  --format '{{range .IPAM.Config}}{{println .Subnet}}{{end}}'); do
  if [[ "$subnet" == *:* ]]; then
	ip6tables -t mangle -A GOHPTS_UDP -p udp -d "$subnet" -j RETURN
  else
	iptables -t mangle -A GOHPTS_UDP -p udp -d "$subnet" -j RETURN
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
	iptables -t mangle -A GOHPTS_UDP -p udp -d "$subnet" -j RETURN
  fi
done
fi
`
		}
		tsu.p.runRuleCmd(cmdDocker)
		cmdInit00 := fmt.Sprintf(`
iptables -t mangle -A GOHPTS_UDP -p udp -m mark --mark %d -j RETURN
`, tsu.p.mark)
		tsu.p.runRuleCmd(cmdInit00)
		if prefix != nil {
			cmdInit01 := fmt.Sprintf(`
iptables -t mangle -A GOHPTS_UDP -s %s -p udp -j TPROXY --on-port %s --tproxy-mark 1
`, prefix.Masked(), tproxyPortUDP)
			tsu.p.runRuleCmd(cmdInit01)
		}
		cmdInit02 := `
iptables -t mangle -A PREROUTING -p udp -m socket -j DIVERT
iptables -t mangle -A PREROUTING -p udp -j GOHPTS_UDP
`
		tsu.p.runRuleCmd(cmdInit02)
		if tsu.p.ipv6enabled {
			cmdInit6 := fmt.Sprintf(`
ip6tables -t mangle -A GOHPTS_UDP -p udp -m mark --mark %d -j RETURN
ip6tables -t mangle -A GOHPTS_UDP -p udp -j TPROXY --on-port %s --tproxy-mark 1

ip6tables -t mangle -A PREROUTING -p udp -m socket -j DIVERT
ip6tables -t mangle -A PREROUTING -p udp -j GOHPTS_UDP
`, tsu.p.mark, tproxyPortUDP)
			tsu.p.runRuleCmd(cmdInit6)
		}
		_ = runSysctlOptCmd("net.ipv4.ip_nonlocal_bind", "1", setex, opts, tsu.p.debug, &tsu.p.dump)
		if tsu.p.ipv6enabled {
			_ = runSysctlOptCmd("net.ipv6.ip_nonlocal_bind", "1", setex, opts, tsu.p.debug, &tsu.p.dump)
		}
	default:
		tsu.p.logger.Fatal().Msgf("Unreachable, unknown mode: %s", tsu.p.tproxyMode)
	}
}

func (tsu *tproxyServerUDP) ClearRedirectRules() error {
	if tsu.p.tproxyMode == "tproxy" {
		cmd0 := `
iptables -t mangle -D PREROUTING -p udp -m socket -j DIVERT 2>/dev/null || true
iptables -t mangle -D PREROUTING -p udp -j GOHPTS_UDP 2>/dev/null || true
iptables -t mangle -F GOHPTS_UDP 2>/dev/null || true
iptables -t mangle -X GOHPTS_UDP 2>/dev/null || true
`
		tsu.p.runRuleCmd(cmd0)
		if tsu.p.ipv6enabled {
			cmd1 := `
ip6tables -t mangle -D PREROUTING -p udp -m socket -j DIVERT 2>/dev/null || true
ip6tables -t mangle -D PREROUTING -p udp -j GOHPTS_UDP 2>/dev/null || true
ip6tables -t mangle -F GOHPTS_UDP 2>/dev/null || true
ip6tables -t mangle -X GOHPTS_UDP 2>/dev/null || true
`
			tsu.p.runRuleCmd(cmd1)
		}
	}
	return nil
}
