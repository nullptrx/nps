package client

import (
	"context"
	"errors"
	"net"
	"net/http"
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
	"github.com/xtaci/kcp-go/v5"
)

var (
	ctxLocal, cancelLocal = context.WithCancel(context.Background())
	muGlobal              sync.Mutex
	LocalServer           []*net.TCPListener
	udpConn               net.Conn
	muxSession            *nps_mux.Mux
	fileServer            []*http.Server
	p2pNetBridge          *p2pBridge
	lock                  sync.RWMutex
	udpConnStatus         bool
)

type p2pBridge struct{}

func (p2pBridge *p2pBridge) SendLinkInfo(clientId int, link *conn.Link, t *file.Tunnel) (target net.Conn, err error) {
	for i := 0; muxSession == nil; i++ {
		if i >= 20 {
			err = errors.New("p2pBridge: too many retries waiting for muxSession")
			logs.Error("%v", err)
			return
		}
		//runtime.Gosched() // waiting for another goroutine establish the mux connection
		time.Sleep(10 * time.Millisecond)
	}
	nowConn, err := muxSession.NewConn()
	if err != nil {
		muGlobal.Lock()
		udpConn = nil
		muGlobal.Unlock()
		return nil, err
	}
	if _, err := conn.NewConn(nowConn).SendInfo(link, ""); err != nil {
		muGlobal.Lock()
		udpConnStatus = false
		muGlobal.Unlock()
		return nil, err
	}
	return nowConn, nil
}

func CloseLocalServer() {
	cancelLocal()
	muGlobal.Lock()
	defer muGlobal.Unlock()
	for _, ln := range LocalServer {
		ln.Close()
	}
	for _, srv := range fileServer {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		srv.Shutdown(ctx)
		cancel()
	}
	if udpConn != nil {
		udpConn.Close()
		udpConn = nil
	}
}

func startLocalFileServer(config *config.CommonConfig, t *file.Tunnel, vkey string) {
	remoteConn, err := NewConn(config.Tp, vkey, config.Server, common.WORK_FILE, config.ProxyUrl)
	if err != nil {
		logs.Error("Local connection server failed %v", err)
		return
	}
	srv := &http.Server{
		Handler: http.StripPrefix(t.StripPre, http.FileServer(http.Dir(t.LocalPath))),
	}
	logs.Info("start local file system, local path %s, strip prefix %s ,remote port %s ", t.LocalPath, t.StripPre, t.Ports)
	muGlobal.Lock()
	fileServer = append(fileServer, srv)
	muGlobal.Unlock()
	listener := nps_mux.NewMux(remoteConn.Conn, common.CONN_TCP, config.DisconnectTime)
	err = srv.Serve(listener)
	if err != nil {
		logs.Error("serve mux failed: remote=%s proto=TCP timeout=%s error=%v", remoteConn.Conn.RemoteAddr(), config.DisconnectTime, err)
		return
	}
}

func StartLocalServer(l *config.LocalServer, config *config.CommonConfig) error {
	if l.Type != "secret" {
		go handleUdpMonitor(config, l)
	}
	task := &file.Tunnel{
		Port:     l.Port,
		ServerIp: "0.0.0.0",
		Status:   true,
		Client: &file.Client{
			Cnf: &file.Config{
				U:        "",
				P:        "",
				Compress: config.Client.Cnf.Compress,
			},
			Status:    true,
			RateLimit: 0,
			Flow:      &file.Flow{},
		},
		Flow:   &file.Flow{},
		Target: &file.Target{},
	}
	switch l.Type {
	case "p2ps":
		logs.Info("start http/socks5 monitor port %d", l.Port)
		return proxy.NewTunnelModeServer(proxy.ProcessMix, p2pNetBridge, task).Start()
	case "p2pt":
		logs.Info("start tcp trans monitor port %d", l.Port)
		return proxy.NewTunnelModeServer(proxy.HandleTrans, p2pNetBridge, task).Start()
	case "p2p", "secret":
		listenTCP, errTCP := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4zero, Port: l.Port})
		if errTCP != nil {
			logs.Error("local listen TCP startup failed port %d, error %v", l.Port, errTCP)
			return errTCP
		}
		muGlobal.Lock()
		LocalServer = append(LocalServer, listenTCP)
		muGlobal.Unlock()
		logs.Info("successful start-up of local tcp monitoring, port %d", l.Port)
		if l.Type == "p2p" {
			task.Target.TargetStr = l.Target
			logs.Info("successful start-up of local udp monitoring, port %d", l.Port)
			go proxy.NewUdpModeServer(p2pNetBridge, task).Start()
		}
		conn.Accept(listenTCP, func(c net.Conn) {
			logs.Trace("new %s connection", l.Type)
			if l.Type == "secret" {
				handleSecret(c, config, l)
			} else if l.Type == "p2p" {
				handleP2PVisitor(c, config, l)
			}
		})
	}
	return nil
}

func handleUdpMonitor(config *config.CommonConfig, l *config.LocalServer) {
	ticker := time.NewTicker(time.Second * 1)
	defer ticker.Stop()
	for {
		select {
		case <-ctxLocal.Done():
			return
		case <-ticker.C:
			muGlobal.Lock()
			status := udpConnStatus
			muGlobal.Unlock()
			if !status {
				muGlobal.Lock()
				udpConn = nil
				muGlobal.Unlock()
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
					return
				}

				for i := 0; i < 10; i++ {
					logs.Debug("try to connect to the server %d", i+1)
					if errV4 == nil {
						newUdpConn(tmpConnV4.LocalAddr().String(), config, l)
						muGlobal.Lock()
						if udpConn != nil {
							udpConnStatus = true
							muGlobal.Unlock()
							break
						}
						muGlobal.Unlock()
					}
					if errV6 == nil {
						newUdpConn(tmpConnV6.LocalAddr().String(), config, l)
						muGlobal.Lock()
						if udpConn != nil {
							udpConnStatus = true
							muGlobal.Unlock()
							break
						}
						muGlobal.Unlock()
					}
				}
			}
		}
	}
}

func handleSecret(localTcpConn net.Conn, config *config.CommonConfig, l *config.LocalServer) {
	remoteConn, err := NewConn(config.Tp, config.VKey, config.Server, common.WORK_SECRET, config.ProxyUrl)
	if err != nil {
		logs.Error("secret connect failed: %v", err)
		return
	}
	defer remoteConn.Close()
	if _, err := remoteConn.Write([]byte(crypt.Md5(l.Password))); err != nil {
		logs.Error("secret write failed: %v", err)
		return
	}
	conn.CopyWaitGroup(remoteConn.Conn, localTcpConn, false, false, nil, nil, false, 0, nil, nil)
}

func handleP2PVisitor(localTcpConn net.Conn, config *config.CommonConfig, l *config.LocalServer) {
	muGlobal.Lock()
	tunnel := udpConn
	muGlobal.Unlock()
	if tunnel == nil {
		logs.Warn("P2P not ready, fallback to secret")
		handleSecret(localTcpConn, config, l)
		return
	}
	logs.Trace("attempting P2P Visit")
	//TODO just support compress now because there is not tls file in client packages
	link := conn.NewLink(common.CONN_TCP, l.Target, false, config.Client.Cnf.Compress, localTcpConn.LocalAddr().String(), false)
	target, err := p2pNetBridge.SendLinkInfo(0, link, nil)
	if err != nil {
		logs.Error("SendLinkInfo failed: %v", err)
		muGlobal.Lock()
		udpConnStatus = false
		muGlobal.Unlock()
		return
	}
	defer target.Close()
	conn.CopyWaitGroup(target, localTcpConn, false, config.Client.Cnf.Compress, nil, nil, false, 0, nil, nil)
}

func newUdpConn(localAddr string, config *config.CommonConfig, l *config.LocalServer) {
	muGlobal.Lock()
	defer muGlobal.Unlock()
	if udpConn != nil {
		udpConn.Close()
		udpConn = nil
	}
	remoteConn, err := NewConn(config.Tp, config.VKey, config.Server, common.WORK_P2P, config.ProxyUrl)
	if err != nil {
		logs.Error("newUdpConn NewConn failed: %v", err)
		return
	}
	defer remoteConn.Close()
	if _, err := remoteConn.Write([]byte(crypt.Md5(l.Password))); err != nil {
		logs.Error("newUdpConn write failed: %v", err)
		return
	}
	rAddrBuf, err := remoteConn.GetShortLenContent()
	if err != nil {
		logs.Error("newUdpConn GetShortLenContent: %v", err)
		return
	}
	rAddr := string(rAddrBuf)

	if !common.IsSameIPType(localAddr, rAddr) {
		logs.Debug("IP type mismatch local=%s remote=%s", localAddr, rAddr)
		return
	}
	//logs.Debug("localAddr is %s, rAddr is %s", localAddr, rAddr)

	remoteAddress, localConn, err := handleP2PUdp(localAddr, rAddr, crypt.Md5(l.Password), common.WORK_P2P_VISITOR)
	if err != nil {
		logs.Error("handleP2PUdp failed: %v", err)
		return
	}
	defer localConn.Close()
	//logs.Debug("remoteAddress: %s", remoteAddress)

	udpTunnel, err := kcp.NewConn(remoteAddress, nil, 150, 3, localConn)
	if err != nil || udpTunnel == nil {
		logs.Warn("kcp NewConn failed: %v", err)
		return
	}
	logs.Info("P2P UDP tunnel established to %s", remoteAddress)
	conn.SetUdpSession(udpTunnel)
	udpConn = udpTunnel
	muxSession = nps_mux.NewMux(udpConn, "kcp", config.DisconnectTime)
	p2pNetBridge = &p2pBridge{}
}
