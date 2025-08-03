package client

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/config"
	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/crypt"
	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/mux"
	"github.com/djylb/nps/server/proxy"
	"github.com/quic-go/quic-go"
	"github.com/xtaci/kcp-go/v5"
)

// ------------------------------
// P2PManager
// ------------------------------

type Closer interface{ Close() error }

type P2PManager struct {
	ctx          context.Context
	cancel       context.CancelFunc
	mu           sync.Mutex
	wg           sync.WaitGroup
	p2p          bool
	secret       bool
	cfg          *config.CommonConfig
	local        *config.LocalServer
	udpConn      net.Conn
	muxSession   *mux.Mux
	quicConn     *quic.Conn
	bridge       *p2pBridge
	statusOK     bool
	statusCh     chan struct{}
	proxyServers []Closer
	lastActive   time.Time
}

type p2pBridge struct {
	mgr *P2PManager
}

func NewP2PManager(parentCtx context.Context) *P2PManager {
	ctx, cancel := context.WithCancel(parentCtx)
	mgr := &P2PManager{
		ctx:          ctx,
		cancel:       cancel,
		statusCh:     make(chan struct{}, 1),
		proxyServers: make([]Closer, 0),
	}
	mgr.bridge = &p2pBridge{
		mgr: mgr,
	}
	go func() {
		<-parentCtx.Done()
		mgr.Close()
	}()
	return mgr
}

func (b *p2pBridge) SendLinkInfo(_ int, link *conn.Link, _ *file.Tunnel) (net.Conn, error) {
	mgr := b.mgr
	ctx, cancel := context.WithTimeout(mgr.ctx, 200*time.Millisecond)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	first := true
	for {
		var tick <-chan time.Time
		if first {
			first = false
			ch := make(chan time.Time, 1)
			ch <- time.Time{}
			tick = ch
		} else {
			tick = ticker.C
		}
		select {
		case <-ctx.Done():
			mgr.mu.Lock()
			mgr.statusOK = false
			mgr.mu.Unlock()
			return nil, errors.New("timeout waiting P2P tunnel")
		case <-tick:
			if mgr.p2p {
				mgr.mu.Lock()
				qConn := mgr.quicConn
				session := mgr.muxSession
				idle := time.Since(mgr.lastActive)
				mgr.mu.Unlock()
				// ---------- QUIC ----------
				if qConn != nil {
					logs.Trace("using P2P[QUIC] for connection")
					if idle > 5*time.Second {
						logs.Trace("sent ACK before proceeding")
						link.Option.NeedAck = true
					}
					stream, err := qConn.OpenStreamSync(mgr.ctx)
					if err != nil {
						mgr.resetStatus(false)
						return nil, err
					}
					nc := conn.NewQuicStreamConn(stream, qConn)
					if _, err = conn.NewConn(nc).SendInfo(link, ""); err != nil {
						_ = nc.Close()
						mgr.resetStatus(false)
						return nil, err
					}
					if link.Option.NeedAck {
						err = conn.ReadACK(nc, 3*time.Second)
						if err != nil {
							_ = nc.Close()
							mgr.resetStatus(false)
							logs.Warn("can not read ACK %v", err)
							return nil, err
						}
						mgr.mu.Lock()
						mgr.lastActive = time.Now()
						mgr.mu.Unlock()
					}
					mgr.resetStatus(true)
					return nc, nil
				}
				// ---------- KCP ----------
				if session != nil {
					logs.Trace("using P2P[KCP] for connection")
					nowConn, err := session.NewConn()
					if err != nil {
						mgr.resetStatus(false)
						return nil, err
					}
					if _, err := conn.NewConn(nowConn).SendInfo(link, ""); err != nil {
						_ = nowConn.Close()
						mgr.resetStatus(false)
						return nil, err
					}
					mgr.resetStatus(true)
					return nowConn, nil
				}
			}
			if mgr.secret {
				if mgr.p2p {
					logs.Warn("P2P not ready, fallback to secret")
				} else {
					logs.Trace("using Secret for connection")
				}
				sc, err := mgr.getSecretConn()
				if _, err = conn.NewConn(sc).SendInfo(link, ""); err != nil {
					_ = sc.Close()
					mgr.resetStatus(false)
					return nil, err
				}
				return sc, nil
			}
		}
	}
}

func (b *p2pBridge) IsServer() bool {
	return false
}

func (mgr *P2PManager) StartLocalServer(l *config.LocalServer, cfg *config.CommonConfig) error {
	if mgr.ctx.Err() != nil {
		return errors.New("parent context canceled")
	}
	if l.Type != "secret" {
		mgr.p2p = true
		mgr.secret = false
		mgr.wg.Add(1)
		go func() {
			defer mgr.wg.Done()
			mgr.handleUdpMonitor(cfg, l)
		}()
	}
	if l.Type == "p2p" || l.Type == "secret" {
		mgr.secret = true
	}
	task := &file.Tunnel{
		Port:     l.Port,
		ServerIp: "0.0.0.0",
		Status:   true,
		Client: &file.Client{
			Cnf: &file.Config{
				U:        "",
				P:        "",
				Compress: cfg.Client.Cnf.Compress,
			},
			Status:    true,
			RateLimit: 0,
			Flow:      &file.Flow{},
		},
		HttpProxy:   true,
		Socks5Proxy: true,
		Flow:        &file.Flow{},
		Target: &file.Target{
			TargetStr: l.Target,
		},
	}
	mgr.local = l
	mgr.cfg = cfg

	switch l.Type {
	case "p2ps":
		logs.Info("start http/socks5 monitor port %d", l.Port)
		srv := proxy.NewTunnelModeServer(proxy.ProcessMix, mgr.bridge, task)
		mgr.mu.Lock()
		mgr.proxyServers = append(mgr.proxyServers, srv)
		mgr.mu.Unlock()
		mgr.wg.Add(1)
		go func() {
			defer mgr.wg.Done()
			_ = srv.Start()
		}()
		return nil
	case "p2pt":
		logs.Info("start tcp trans monitor port %d", l.Port)
		srv := proxy.NewTunnelModeServer(proxy.HandleTrans, mgr.bridge, task)
		mgr.mu.Lock()
		mgr.proxyServers = append(mgr.proxyServers, srv)
		mgr.mu.Unlock()
		mgr.wg.Add(1)
		go func() {
			defer mgr.wg.Done()
			_ = srv.Start()
		}()
		return nil
	}

	if l.TargetType == common.CONN_ALL || l.TargetType == common.CONN_TCP {
		logs.Info("local tcp monitoring started on port %d", l.Port)
		srv := proxy.NewTunnelModeServer(proxy.ProcessTunnel, mgr.bridge, task)
		mgr.mu.Lock()
		mgr.proxyServers = append(mgr.proxyServers, srv)
		mgr.mu.Unlock()
		mgr.wg.Add(1)
		go func() {
			defer mgr.wg.Done()
			_ = srv.Start()
		}()
	}
	if l.TargetType == common.CONN_ALL || l.TargetType == common.CONN_UDP {
		logs.Info("local udp monitoring started on port %d", l.Port)
		srv := proxy.NewUdpModeServer(mgr.bridge, task)
		mgr.mu.Lock()
		mgr.proxyServers = append(mgr.proxyServers, srv)
		mgr.mu.Unlock()
		mgr.wg.Add(1)
		go func() {
			defer mgr.wg.Done()
			_ = srv.Start()
		}()
	}

	return nil
}

func (mgr *P2PManager) getSecretConn() (net.Conn, error) {
	remoteConn, err := NewConn(mgr.cfg.Tp, mgr.cfg.VKey, mgr.cfg.Server, common.WORK_SECRET, mgr.cfg.ProxyUrl)
	if err != nil {
		logs.Error("secret NewConn failed: %v", err)
		_ = remoteConn.Close()
		return nil, err
	}
	if _, err := remoteConn.Write([]byte(crypt.Md5(mgr.local.Password))); err != nil {
		logs.Error("secret write failed: %v", err)
		_ = remoteConn.Close()
		return nil, err
	}
	return remoteConn, nil
}

func (mgr *P2PManager) handleUdpMonitor(cfg *config.CommonConfig, l *config.LocalServer) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-mgr.ctx.Done():
			return
		case <-ticker.C:
		case <-mgr.statusCh:
		}
		mgr.mu.Lock()
		ok := mgr.statusOK && (mgr.udpConn != nil || mgr.quicConn != nil)
		oldConn := mgr.udpConn
		oldQuicConn := mgr.quicConn
		mgr.mu.Unlock()

		if ok {
			continue
		}

		mgr.mu.Lock()
		if oldConn != nil {
			_ = oldConn.Close()
			mgr.udpConn = nil
		}
		if oldQuicConn != nil {
			_ = oldQuicConn.CloseWithError(0, "monitor close")
			mgr.quicConn = nil
		}
		mgr.mu.Unlock()

		tmpConnV4, errV4 := common.GetLocalUdp4Addr()
		if errV4 != nil {
			logs.Warn("Failed to get local IPv4 address: %v", errV4)
		} else {
			logs.Debug("IPv4 address: %v", tmpConnV4.LocalAddr())
		}

		tmpConnV6, errV6 := common.GetLocalUdp6Addr()
		if errV6 != nil {
			logs.Warn("Failed to get local IPv6 address: %v", errV6)
		} else {
			logs.Debug("IPv6 address: %v", tmpConnV6.LocalAddr())
		}

		if errV4 != nil && errV6 != nil {
			logs.Error("Both IPv4 and IPv6 address retrieval failed, exiting.")
			mgr.resetStatus(false)
			return
		}

		for i := 0; i < 10; i++ {
			logs.Debug("try P2P hole punch %d", i+1)
			select {
			case <-mgr.ctx.Done():
				return
			default:
			}
			if errV4 == nil {
				mgr.newUdpConn(tmpConnV4.LocalAddr().String(), cfg, l)
			}
			mgr.mu.Lock()
			if mgr.statusOK {
				mgr.mu.Unlock()
				break
			}
			mgr.mu.Unlock()
			if errV6 == nil {
				mgr.newUdpConn(tmpConnV6.LocalAddr().String(), cfg, l)
			}
			mgr.mu.Lock()
			if mgr.statusOK {
				mgr.mu.Unlock()
				break
			}
			mgr.mu.Unlock()
			time.Sleep(50 * time.Millisecond)
		}
	}
}

func (mgr *P2PManager) newUdpConn(localAddr string, cfg *config.CommonConfig, l *config.LocalServer) {
	remoteConn, err := NewConn(cfg.Tp, cfg.VKey, cfg.Server, common.WORK_P2P, cfg.ProxyUrl)
	if err != nil {
		logs.Error("Failed to connect to server: %v", err)
		time.Sleep(5 * time.Second)
		return
	}
	defer remoteConn.Close()
	if _, err := remoteConn.Write([]byte(crypt.Md5(l.Password))); err != nil {
		logs.Error("Failed to send password to server: %v", err)
		time.Sleep(5 * time.Second)
		return
	}
	rAddrBuf, err := remoteConn.GetShortLenContent()
	if err != nil {
		logs.Error("Target client is offline or tunnel config not found: %v", err)
		time.Sleep(5 * time.Second)
		return
	}
	rAddr := string(rAddrBuf)
	remoteIP := net.ParseIP(common.GetIpByAddr(remoteConn.RemoteAddr().String()))
	if remoteIP != nil && (remoteIP.IsPrivate() || remoteIP.IsLoopback() || remoteIP.IsLinkLocalUnicast()) {
		rAddr = common.BuildAddress(remoteIP.String(), strconv.Itoa(common.GetPortByAddr(rAddr)))
	}

	if !common.IsSameIPType(localAddr, rAddr) {
		logs.Debug("IP type mismatch local=%s remote=%s", localAddr, rAddr)
		//return
	}
	//logs.Debug("localAddr is %s, rAddr is %s", localAddr, rAddr)

	var remoteAddr, role, mode, data string
	var localConn net.PacketConn
	localConn, remoteAddr, localAddr, role, mode, data, err = handleP2PUdp(mgr.ctx, localAddr, rAddr, crypt.Md5(l.Password), common.WORK_P2P_VISITOR, common.CONN_QUIC, "")
	if err != nil {
		logs.Error("Handle P2P failed: %v", err)
		return
	}
	if mode == "" {
		mode = common.CONN_KCP
	}
	//logs.Debug("handleP2PUdp ok")

	var udpTunnel net.Conn
	var sess *quic.Conn
	if mode == common.CONN_QUIC {
		rUDPAddr, err := net.ResolveUDPAddr("udp", remoteAddr)
		if err != nil {
			logs.Error("Failed to resolve remote UDP addr: %v", err)
			_ = localConn.Close()
			return
		}
		sess, err = quic.Dial(mgr.ctx, localConn, rUDPAddr, TlsCfg, QuicConfig)
		if err != nil {
			logs.Error("QUIC dial error: %v", err)
			_ = localConn.Close()
			return
		}
		state := sess.ConnectionState().TLS
		if len(state.PeerCertificates) == 0 {
			logs.Error("Failed to get QUIC certificate")
			_ = localConn.Close()
			return
		}
		leaf := state.PeerCertificates[0]
		if data != string(crypt.GetHMAC(cfg.VKey, leaf.Raw)) {
			logs.Error("Failed to verify QUIC certificate")
			_ = localConn.Close()
			return
		}
	} else {
		kcpTunnel, err := kcp.NewConn(remoteAddr, nil, 150, 3, localConn)
		if err != nil || kcpTunnel == nil {
			logs.Warn("KCP NewConn failed: %v", err)
			_ = localConn.Close()
			return
		}
		conn.SetUdpSession(kcpTunnel)
		udpTunnel = kcpTunnel
	}

	logs.Info("P2P UDP[%s] tunnel established to %s, role[%s]", mode, remoteAddr, role)

	mgr.mu.Lock()
	mgr.lastActive = time.Now()
	if mgr.udpConn != nil {
		_ = mgr.udpConn.Close()
	}
	if mgr.muxSession != nil {
		_ = mgr.muxSession.Close()
	}
	if mgr.quicConn != nil {
		_ = mgr.quicConn.CloseWithError(0, "new connection")
	}
	if mode == common.CONN_QUIC {
		mgr.quicConn = sess
		mgr.udpConn = nil
		mgr.muxSession = nil
	} else {
		mgr.udpConn = udpTunnel
		mgr.muxSession = mux.NewMux(udpTunnel, "kcp", cfg.DisconnectTime)
	}
	mgr.statusOK = true
	mgr.mu.Unlock()
}

func (mgr *P2PManager) resetStatus(ok bool) {
	mgr.mu.Lock()
	oldStatus := mgr.statusOK
	mgr.statusOK = ok
	mgr.mu.Unlock()
	if !ok && oldStatus {
		select {
		case mgr.statusCh <- struct{}{}:
		default:
		}
	}
}

func (mgr *P2PManager) Close() {
	mgr.cancel()
	mgr.mu.Lock()
	psList := mgr.proxyServers
	udp := mgr.udpConn
	muxSess := mgr.muxSession
	qConn := mgr.quicConn
	mgr.mu.Unlock()

	for _, srv := range psList {
		_ = srv.Close()
	}
	if udp != nil {
		_ = udp.Close()
	}
	if muxSess != nil {
		_ = muxSess.Close()
	}
	if qConn != nil {
		_ = qConn.CloseWithError(0, "close quic")
	}
	mgr.wg.Wait()
}
