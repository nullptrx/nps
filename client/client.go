package client

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/config"
	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/crypt"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/nps_mux"
	"github.com/quic-go/quic-go"
	"github.com/xtaci/kcp-go/v5"
)

type TRPClient struct {
	svrAddr        string
	bridgeConnType string
	proxyUrl       string
	vKey           string
	p2pAddr        map[string]string
	tunnel         *nps_mux.Mux
	signal         *conn.Conn
	ticker         *time.Ticker
	cnf            *config.Config
	disconnectTime int
	ctx            context.Context
	cancel         context.CancelFunc
	healthChecker  *HealthChecker
	once           sync.Once
}

// NewRPClient new client
func NewRPClient(svrAddr string, vKey string, bridgeConnType string, proxyUrl string, cnf *config.Config, disconnectTime int) *TRPClient {
	return &TRPClient{
		svrAddr:        svrAddr,
		p2pAddr:        make(map[string]string),
		vKey:           vKey,
		bridgeConnType: bridgeConnType,
		proxyUrl:       proxyUrl,
		cnf:            cnf,
		disconnectTime: disconnectTime,
		once:           sync.Once{},
	}
}

var NowStatus int
var HasFailed = false

func (s *TRPClient) Start() {
	s.ctx, s.cancel = context.WithCancel(context.Background())
	defer s.Close()
	NowStatus = 0
	c, err := NewConn(s.bridgeConnType, s.vKey, s.svrAddr, common.WORK_MAIN, s.proxyUrl)
	if err != nil {
		HasFailed = true
		logs.Error("The connection server failed and will be reconnected in five seconds, error %v", err)
		return
	}
	logs.Info("Successful connection with server %s", s.svrAddr)
	s.signal = c
	//start a channel connection
	s.newChan()
	//monitor the connection
	go s.ping()
	//start health check if it's open
	if s.cnf != nil && len(s.cnf.Healths) > 0 {
		s.healthChecker = NewHealthChecker(s.ctx, s.cnf.Healths, s.signal)
		s.healthChecker.Start()
	}
	NowStatus = 1
	//msg connection, eg udp
	s.handleMain()
}

// handle main connection
func (s *TRPClient) handleMain() {
	defer s.Close()
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		flags, err := s.signal.ReadFlag()
		if err != nil {
			logs.Error("Accept server data error %v, end this service", err)
			return
		}
		switch flags {
		case common.NEW_UDP_CONN:
			//read server udp addr and password
			if lAddr, err := s.signal.GetShortLenContent(); err != nil {
				logs.Warn("%v", err)
				return
			} else if pwd, err := s.signal.GetShortLenContent(); err == nil {
				rAddr := string(lAddr)
				remoteIP := net.ParseIP(common.GetIpByAddr(s.signal.RemoteAddr().String()))
				if remoteIP != nil && (remoteIP.IsPrivate() || remoteIP.IsLoopback() || remoteIP.IsLinkLocalUnicast()) {
					rAddr = common.BuildAddress(remoteIP.String(), strconv.Itoa(common.GetPortByAddr(rAddr)))
				}
				var localAddr string
				//The local port remains unchanged for a certain period of time
				if v, ok := s.p2pAddr[crypt.Md5(string(pwd)+strconv.Itoa(int(time.Now().Unix()/100)))]; !ok {
					if strings.Contains(rAddr, "]:") {
						tmpConn, err := common.GetLocalUdp6Addr()
						if err != nil {
							logs.Error("%v", err)
							return
						}
						localAddr = tmpConn.LocalAddr().String()
					} else {
						tmpConn, err := common.GetLocalUdp4Addr()
						if err != nil {
							logs.Error("%v", err)
							return
						}
						localAddr = tmpConn.LocalAddr().String()
					}
				} else {
					localAddr = v
				}
				go s.newUdpConn(localAddr, rAddr, string(pwd))
			}
		}
	}
}

func (s *TRPClient) newUdpConn(localAddr, rAddr string, md5Password string) {
	var localConn net.PacketConn
	var err error
	var remoteAddress, role, mode, data string
	sendData := string(crypt.GetHMAC(s.vKey, crypt.GetCert().Certificate[0]))
	//logs.Debug("newUdpConn %s %s", localAddr, rAddr)
	if localConn, remoteAddress, localAddr, role, mode, data, err = handleP2PUdp(s.ctx, localAddr, rAddr, md5Password, common.WORK_P2P_PROVIDER, common.CONN_QUIC, sendData); err != nil {
		logs.Error("%v", err)
		return
	}
	defer localConn.Close()
	if mode == "" {
		mode = common.CONN_KCP
	}
	var kcpListener *kcp.Listener
	var quicListener *quic.Listener
	if mode == common.CONN_QUIC {
		quicListener, err = quic.Listen(localConn, crypt.GetCertCfg(), QuicConfig)
		if err != nil {
			logs.Error("quic.Listen err: %v", err)
			return
		}
		defer quicListener.Close()
	} else {
		kcpListener, err = kcp.ServeConn(nil, 150, 3, localConn)
		if err != nil {
			logs.Error("kcp.ServeConn err: %v", err)
			return
		}
		defer kcpListener.Close()
	}

	logs.Trace("start local p2p udp[%s] listen, role[%s], local address %s %v", mode, role, localAddr, localConn.LocalAddr())
	if data != "" {
		logs.Trace("P2P udp data is %s", data)
	}
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		switch mode {
		case common.CONN_QUIC:
			sess, err := quicListener.Accept(s.ctx)
			if err != nil {
				logs.Warn("QUIC accept session error: %v", err)
				return
			}
			if sess.RemoteAddr().String() != remoteAddress {
				_ = sess.CloseWithError(0, "unexpected peer")
				continue
			}
			go func(sess *quic.Conn) {
				for {
					stream, err := sess.AcceptStream(s.ctx)
					if err != nil {
						logs.Trace("QUIC accept stream error: %v", err)
						return
					}
					c := conn.NewQuicStreamConn(stream, sess)
					go s.handleChan(c)
				}
			}(sess)
		default:
			udpTunnel, err := kcpListener.AcceptKCP()
			if err != nil {
				logs.Error("acceptKCP failed on listener %v waiting for remote %s: %v", localConn.LocalAddr(), remoteAddress, err)
				return
			}
			if udpTunnel.RemoteAddr().String() == remoteAddress {
				conn.SetUdpSession(udpTunnel)
				logs.Trace("successful connection with client ,address %v", udpTunnel.RemoteAddr())
				//read link info from remote
				tunnel := nps_mux.NewMux(udpTunnel, "kcp", s.disconnectTime)
				conn.Accept(tunnel, func(c net.Conn) {
					go s.handleChan(c)
				})
				logs.Trace("p2p connection closed, remote %v", udpTunnel.RemoteAddr())
				_ = tunnel.Close()
				return
			}
		}
	}
}

// mux tunnel
func (s *TRPClient) newChan() {
	tunnel, err := NewConn(s.bridgeConnType, s.vKey, s.svrAddr, common.WORK_CHAN, s.proxyUrl)
	if err != nil {
		logs.Error("failed to connect to server %s error: %v", s.svrAddr, err)
		return
	}
	s.tunnel = nps_mux.NewMux(tunnel.Conn, s.bridgeConnType, s.disconnectTime)
	go func() {
		for {
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			src, err := s.tunnel.Accept()
			if err != nil {
				logs.Warn("Accept error on mux: %v", err)
				s.Close()
				return
			}
			go s.handleChan(src)
		}
	}()
}

func (s *TRPClient) handleChan(src net.Conn) {
	lk, err := conn.NewConn(src).GetLinkInfo()
	if err != nil || lk == nil {
		_ = src.Close()
		logs.Error("get connection info from server error %v", err)
		return
	}
	//ack
	if lk.Option.NeedAck {
		if err := conn.WriteACK(src, lk.Option.Timeout); err != nil {
			logs.Warn("write ACK failed: %v", err)
			_ = src.Close()
			return
		}
		logs.Trace("sent ACK before proceeding")
	}
	//host for target processing
	lk.Host = common.FormatAddress(lk.Host)
	//if RateConn type is http, read the request and log
	if lk.ConnType == "http" {
		if targetConn, err := net.DialTimeout(common.CONN_TCP, lk.Host, lk.Option.Timeout); err != nil {
			logs.Warn("connect to %s error %v", lk.Host, err)
			_ = src.Close()
		} else {
			srcConn := conn.GetConn(src, lk.Crypt, lk.Compress, nil, false)
			go func() {
				_, _ = common.CopyBuffer(srcConn, targetConn)
				_ = srcConn.Close()
				_ = targetConn.Close()
			}()
			for {
				select {
				case <-s.ctx.Done():
					_ = srcConn.Close()
					_ = targetConn.Close()
					return
				default:
				}
				if r, err := http.ReadRequest(bufio.NewReader(srcConn)); err != nil {
					logs.Error("http read error: %v", err)
					_ = srcConn.Close()
					_ = targetConn.Close()
					return
				} else {
					remoteAddr := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
					if len(remoteAddr) == 0 {
						remoteAddr = r.RemoteAddr
					}
					logs.Trace("http request, method %s, host %s, url %s, remote address %s", r.Method, r.Host, r.URL.Path, remoteAddr)
					_ = r.Write(targetConn)
				}
			}
		}
		return
	}
	if lk.ConnType == "udp5" {
		logs.Trace("new %s connection with the goal of %s, remote address:%s", lk.ConnType, lk.Host, lk.RemoteAddr)
		s.handleUdp(src, lk.Option.Timeout)
	}
	//connect to target if conn type is tcp or udp
	if targetConn, err := net.DialTimeout(lk.ConnType, lk.Host, lk.Option.Timeout); err != nil {
		logs.Warn("connect to %s error %v", lk.Host, err)
		_ = src.Close()
	} else {
		logs.Trace("new %s connection with the goal of %s, remote address:%s", lk.ConnType, lk.Host, lk.RemoteAddr)
		conn.CopyWaitGroup(src, targetConn, lk.Crypt, lk.Compress, nil, nil, false, 0, nil, nil)
	}
}

func (s *TRPClient) handleUdp(serverConn net.Conn, timeout time.Duration) {
	// bind a local udp port
	defer serverConn.Close()
	local, err := net.ListenUDP("udp", nil)
	if err != nil {
		logs.Error("bind local udp port error %v", err)
		return
	}
	defer local.Close()
	relayCtx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	var lastActive atomic.Value
	bump := func() { lastActive.Store(time.Now()) }
	bump()
	go func() {
		t := time.NewTimer(timeout)
		defer func() {
			t.Stop()
			cancel()
			_ = local.SetReadDeadline(time.Now())
			_ = local.SetWriteDeadline(time.Now())
			_ = serverConn.SetReadDeadline(time.Now())
			_ = serverConn.SetWriteDeadline(time.Now())
		}()
		for {
			select {
			case <-relayCtx.Done():
				return
			case <-t.C:
				la := lastActive.Load().(time.Time)
				idle := time.Since(la)
				if idle >= timeout {
					return
				}
				t.Reset(timeout - idle)
			}
		}
	}()
	go func() {
		defer cancel()
		defer serverConn.Close()
		b := common.BufPoolUdp.Get().([]byte)
		defer common.BufPoolUdp.Put(b)
		for {
			select {
			case <-relayCtx.Done():
				return
			default:
			}
			n, rAddr, err := local.ReadFrom(b)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					logs.Info("local UDP closed, exiting goroutine")
					return
				}
				var ne net.Error
				if errors.As(err, &ne) && (ne.Temporary() || ne.Timeout()) {
					logs.Warn("temporary UDP read error, retrying: %v", err)
					continue
				}
				logs.Error("read data from remote server error %v", err)
				return
			}
			bump()
			buf := bytes.Buffer{}
			dgram := common.NewUDPDatagram(common.NewUDPHeader(0, 0, common.ToSocksAddr(rAddr)), b[:n])
			_ = dgram.Write(&buf)
			b, err := conn.GetLenBytes(buf.Bytes())
			if err != nil {
				logs.Warn("get len bytes error %v", err)
				continue
			}
			if _, err := serverConn.Write(b); err != nil {
				logs.Error("write data to remote error %v", err)
				return
			}
			bump()
		}
	}()
	b := common.BufPoolUdp.Get().([]byte)
	defer common.BufPoolUdp.Put(b)
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		n, err := serverConn.Read(b)
		if err != nil {
			logs.Error("read udp data from server error %v", err)
			return
		}
		bump()
		udpData, err := common.ReadUDPDatagram(bytes.NewReader(b[:n]))
		if err != nil {
			logs.Error("unpack data error %v", err)
			return
		}
		rAddr, err := net.ResolveUDPAddr("udp", udpData.Header.Addr.String())
		if err != nil {
			logs.Error("build remote addr err %v", err)
			continue // drop silently
		}
		_, err = local.WriteTo(udpData.Data, rAddr)
		if err != nil {
			logs.Error("write data to remote %v error %v", rAddr, err)
			return
		}
		bump()
	}
}

// Whether the monitor channel is closed
func (s *TRPClient) ping() {
	s.ticker = time.NewTicker(time.Second * 5)
	for {
		select {
		case <-s.ticker.C:
			if s.tunnel == nil || s.tunnel.IsClosed() {
				s.Close()
				return
			}
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *TRPClient) Close() {
	s.once.Do(s.closing)
}

func (s *TRPClient) closing() {
	NowStatus = 0
	if s.healthChecker != nil {
		s.healthChecker.Stop()
	}
	s.cancel()
	if s.tunnel != nil {
		_ = s.tunnel.Close()
	}
	if s.signal != nil {
		_ = s.signal.Close()
	}
	if s.ticker != nil {
		s.ticker.Stop()
	}
}
