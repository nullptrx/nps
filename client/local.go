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
	"github.com/djylb/nps/lib/nps_mux"
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
	tcpLn        []*net.TCPListener
	udpConn      net.Conn
	muxSession   *nps_mux.Mux
	quicConn     *quic.Conn
	bridge       *p2pBridge
	statusOK     bool
	proxyServers []Closer
}

type p2pBridge struct{ mgr *P2PManager }

func NewP2PManager(parentCtx context.Context) *P2PManager {
	ctx, cancel := context.WithCancel(parentCtx)
	mgr := &P2PManager{
		ctx:          ctx,
		cancel:       cancel,
		proxyServers: make([]Closer, 0),
	}
	mgr.bridge = &p2pBridge{mgr: mgr}
	go func() {
		<-parentCtx.Done()
		mgr.Close()
	}()
	return mgr
}

func (b *p2pBridge) SendLinkInfo(clientId int, link *conn.Link, t *file.Tunnel) (net.Conn, error) {
	mgr := b.mgr
	ctx, cancel := context.WithTimeout(mgr.ctx, 200*time.Millisecond)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			mgr.mu.Lock()
			mgr.statusOK = false
			mgr.mu.Unlock()
			return nil, errors.New("timeout waiting P2P tunnel")
		case <-ticker.C:
			mgr.mu.Lock()
			qConn := mgr.quicConn
			session := mgr.muxSession
			mgr.mu.Unlock()
			// ---------- QUIC ----------
			if qConn != nil {
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
				mgr.resetStatus(true)
				return nc, nil
			}
			// ---------- KCP ----------
			if session != nil {
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
	}
}

func (mgr *P2PManager) StartLocalServer(l *config.LocalServer, cfg *config.CommonConfig) error {
	if mgr.ctx.Err() != nil {
		return errors.New("parent context canceled")
	}
	if l.Type != "secret" {
		mgr.wg.Add(1)
		go func() {
			defer mgr.wg.Done()
			mgr.handleUdpMonitor(cfg, l)
		}()
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
		Target:      &file.Target{},
	}
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

	listenTCP, errTCP := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4zero, Port: l.Port})
	if errTCP != nil {
		logs.Error("local tcp monitoring startup failed port %d, error %v", l.Port, errTCP)
		return errTCP
	}
	mgr.mu.Lock()
	mgr.tcpLn = append(mgr.tcpLn, listenTCP)
	mgr.mu.Unlock()

	logs.Info("local tcp monitoring started on port %d", l.Port)
	if l.Type == "p2p" {
		task.Target.TargetStr = l.Target
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

	mgr.wg.Add(1)
	go func() {
		defer mgr.wg.Done()
		conn.Accept(listenTCP, func(c net.Conn) {
			logs.Trace("new %s connection, remote address %s", l.Type, c.RemoteAddr().String())
			if l.Type == "secret" {
				mgr.handleSecret(c, cfg, l)
			} else if l.Type == "p2p" {
				mgr.handleP2PVisitor(c, cfg, l)
			}
		})
	}()

	return nil
}

func (mgr *P2PManager) handleUdpMonitor(cfg *config.CommonConfig, l *config.LocalServer) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-mgr.ctx.Done():
			return
		case <-ticker.C:
		}
		mgr.mu.Lock()
		ok := mgr.statusOK && mgr.udpConn != nil
		oldConn := mgr.udpConn
		mgr.mu.Unlock()

		if ok {
			continue
		}

		mgr.mu.Lock()
		if oldConn != nil {
			_ = oldConn.Close()
			mgr.udpConn = nil
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
			mgr.mu.Lock()
			mgr.statusOK = false
			mgr.mu.Unlock()
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
	mode = common.CONN_KCP
	localConn, remoteAddr, localAddr, role, mode, data, err = handleP2PUdp(mgr.ctx, localAddr, rAddr, crypt.Md5(l.Password), common.WORK_P2P_VISITOR, common.CONN_QUIC, "")
	if err != nil {
		logs.Error("Handle P2P failed: %v", err)
		return
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
		mgr.muxSession = nps_mux.NewMux(udpTunnel, "kcp", cfg.DisconnectTime)
	}
	mgr.statusOK = true
	mgr.mu.Unlock()
}

func (mgr *P2PManager) handleSecret(c net.Conn, cfg *config.CommonConfig, l *config.LocalServer) {
	remoteConn, err := NewConn(cfg.Tp, cfg.VKey, cfg.Server, common.WORK_SECRET, cfg.ProxyUrl)
	if err != nil {
		logs.Error("secret NewConn failed: %v", err)
		_ = c.Close()
		return
	}
	defer remoteConn.Close()
	if _, err := remoteConn.Write([]byte(crypt.Md5(l.Password))); err != nil {
		logs.Error("secret write failed: %v", err)
		_ = c.Close()
		return
	}
	conn.CopyWaitGroup(remoteConn.Conn, c, false, false, nil, nil, false, 0, nil, nil)
}

func (mgr *P2PManager) handleP2PVisitor(c net.Conn, cfg *config.CommonConfig, l *config.LocalServer) {
	mgr.mu.Lock()
	tunnel := mgr.udpConn
	qConn := mgr.quicConn
	ok := mgr.statusOK
	mgr.mu.Unlock()

	if (tunnel == nil && qConn == nil) || !ok {
		logs.Warn("P2P not ready, fallback to secret")
		mgr.handleSecret(c, cfg, l)
		return
	}
	logs.Trace("using P2P for connection")
	//TODO just support compress now because there is not tls file in client packages
	link := conn.NewLink(common.CONN_TCP, l.Target, false, cfg.Client.Cnf.Compress, c.LocalAddr().String(), false)
	target, err := mgr.bridge.SendLinkInfo(0, link, nil)
	if err != nil {
		logs.Error("SendLinkInfo failed: %v", err)
		mgr.mu.Lock()
		mgr.statusOK = false
		mgr.mu.Unlock()
		_ = c.Close()
		return
	}
	defer target.Close()
	conn.CopyWaitGroup(target, c, false, cfg.Client.Cnf.Compress, nil, nil, false, 0, nil, nil)
}

func (mgr *P2PManager) resetStatus(ok bool) {
	mgr.mu.Lock()
	mgr.statusOK = ok
	mgr.mu.Unlock()
}

func (mgr *P2PManager) Close() {
	mgr.cancel()
	mgr.mu.Lock()
	lnList := mgr.tcpLn
	psList := mgr.proxyServers
	udp := mgr.udpConn
	mux := mgr.muxSession
	qConn := mgr.quicConn
	mgr.mu.Unlock()

	for _, ln := range lnList {
		_ = ln.Close()
	}
	for _, srv := range psList {
		_ = srv.Close()
	}
	if udp != nil {
		_ = udp.Close()
	}
	if mux != nil {
		_ = mux.Close()
	}
	if qConn != nil {
		_ = qConn.CloseWithError(0, "close quic")
	}
	mgr.wg.Wait()
}
