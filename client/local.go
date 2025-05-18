package client

import (
	"errors"
	"net"
	"net/http"
	"runtime"
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
	LocalServer   []*net.TCPListener
	udpConn       net.Conn
	muxSession    *nps_mux.Mux
	fileServer    []*http.Server
	p2pNetBridge  *p2pBridge
	lock          sync.RWMutex
	udpConnStatus bool
)

type p2pBridge struct {
}

func (p2pBridge *p2pBridge) SendLinkInfo(clientId int, link *conn.Link, t *file.Tunnel) (target net.Conn, err error) {
	for i := 0; muxSession == nil; i++ {
		if i >= 20 {
			err = errors.New("p2pBridge:too many times to get muxSession")
			logs.Error("%v", err)
			return
		}
		runtime.Gosched() // waiting for another goroutine establish the mux connection
	}
	nowConn, err := muxSession.NewConn()
	if err != nil {
		udpConn = nil
		return nil, err
	}
	if _, err := conn.NewConn(nowConn).SendInfo(link, ""); err != nil {
		udpConnStatus = false
		return nil, err
	}
	return nowConn, nil
}

func CloseLocalServer() {
	for _, v := range LocalServer {
		v.Close()
	}
	for _, v := range fileServer {
		v.Close()
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
	fileServer = append(fileServer, srv)
	listener := nps_mux.NewMux(remoteConn.Conn, common.CONN_TCP, config.DisconnectTime)
	err = srv.Serve(listener)
	if err != nil {
		logs.Error("%v", err)
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
		logs.Info("successful start-up of local socks5 monitoring, port %d", l.Port)
		return proxy.NewTunnelModeServer(proxy.ProcessMix, p2pNetBridge, task).Start()
	case "p2pt":
		logs.Info("successful start-up of local tcp trans monitoring, port %d", l.Port)
		return proxy.NewTunnelModeServer(proxy.HandleTrans, p2pNetBridge, task).Start()
	case "p2p", "secret":
		listenTCP, errTCP := net.ListenTCP("tcp", &net.TCPAddr{net.ParseIP("0.0.0.0"), l.Port, ""})
		if errTCP != nil {
			logs.Error("local listen TCP startup failed port %d, error %v", l.Port, errTCP)
			return errTCP
		}
		LocalServer = append(LocalServer, listenTCP)
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
		case <-ticker.C:
			if !udpConnStatus {
				udpConn = nil

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
						if udpConn != nil {
							udpConnStatus = true
							break
						}
					}
					if errV6 == nil {
						newUdpConn(tmpConnV6.LocalAddr().String(), config, l)
						if udpConn != nil {
							udpConnStatus = true
							break
						}
					}
				}
			}
		}
	}
}

func handleSecret(localTcpConn net.Conn, config *config.CommonConfig, l *config.LocalServer) {
	remoteConn, err := NewConn(config.Tp, config.VKey, config.Server, common.WORK_SECRET, config.ProxyUrl)
	if err != nil {
		logs.Error("Local connection server failed %v", err)
		return
	}
	if _, err := remoteConn.Write([]byte(crypt.Md5(l.Password))); err != nil {
		logs.Error("Local connection server failed %v", err)
		return
	}
	conn.CopyWaitGroup(remoteConn.Conn, localTcpConn, false, false, nil, nil, false, 0, nil, nil)
}

func handleP2PVisitor(localTcpConn net.Conn, config *config.CommonConfig, l *config.LocalServer) {
	if udpConn == nil {
		logs.Warn("new conn, P2P can not penetrate successfully, traffic will be transferred through the server")
		handleSecret(localTcpConn, config, l)
		return
	}
	logs.Trace("start trying to connect with the server")
	//TODO just support compress now because there is not tls file in client packages
	link := conn.NewLink(common.CONN_TCP, l.Target, false, config.Client.Cnf.Compress, localTcpConn.LocalAddr().String(), false)
	if target, err := p2pNetBridge.SendLinkInfo(0, link, nil); err != nil {
		logs.Error("%v", err)
		udpConnStatus = false
		return
	} else {
		conn.CopyWaitGroup(target, localTcpConn, false, config.Client.Cnf.Compress, nil, nil, false, 0, nil, nil)
	}
}

func newUdpConn(localAddr string, config *config.CommonConfig, l *config.LocalServer) {
	lock.Lock()
	defer lock.Unlock()
	remoteConn, err := NewConn(config.Tp, config.VKey, config.Server, common.WORK_P2P, config.ProxyUrl)
	if err != nil {
		logs.Error("Local connection server failed %v", err)
		return
	}
	if _, err := remoteConn.Write([]byte(crypt.Md5(l.Password))); err != nil {
		logs.Error("Local connection server failed %v", err)
		return
	}
	var rAddr []byte
	//读取服务端地址、密钥 继续做处理
	if rAddr, err = remoteConn.GetShortLenContent(); err != nil {
		logs.Error("%v", err)
		return
	}

	if !common.IsSameIPType(localAddr, string(rAddr)) {
		logs.Debug("IP type mismatch: localAddr is %s, rAddr is %s", localAddr, rAddr)
		return
	}
	//logs.Debug("localAddr is %s, rAddr is %s", localAddr, rAddr)

	var localConn net.PacketConn
	var remoteAddress string
	if remoteAddress, localConn, err = handleP2PUdp(localAddr, string(rAddr), crypt.Md5(l.Password), common.WORK_P2P_VISITOR); err != nil {
		logs.Error("%v", err)
		return
	}
	//logs.Debug("remoteAddress: %s", remoteAddress)

	udpTunnel, err := kcp.NewConn(remoteAddress, nil, 150, 3, localConn)
	if err != nil || udpTunnel == nil {
		logs.Warn("%v", err)
		return
	}
	logs.Info("successful create a connection with server %s", remoteAddress)
	conn.SetUdpSession(udpTunnel)
	udpConn = udpTunnel
	muxSession = nps_mux.NewMux(udpConn, "kcp", config.DisconnectTime)
	p2pNetBridge = &p2pBridge{}
}
