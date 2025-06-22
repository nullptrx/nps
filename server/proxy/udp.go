package proxy

import (
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/beego/beego"
	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/logs"
)

type UdpModeServer struct {
	BaseServer
	addrMap  sync.Map // key: clientAddr.String(), value: io.ReadWriteCloser
	listener *net.UDPConn
}

func NewUdpModeServer(bridge NetBridge, task *file.Tunnel) *UdpModeServer {
	allowLocalProxy, _ := beego.AppConfig.Bool("allow_local_proxy")
	s := new(UdpModeServer)
	s.bridge = bridge
	s.task = task
	s.allowLocalProxy = allowLocalProxy
	return s
}

func (s *UdpModeServer) Start() error {
	var err error
	if s.task.ServerIp == "" {
		s.task.ServerIp = "0.0.0.0"
	}
	s.listener, err = net.ListenUDP("udp", &net.UDPAddr{net.ParseIP(s.task.ServerIp), s.task.Port, ""})
	if err != nil {
		return err
	}
	for {
		buf := common.BufPoolUdp.Get().([]byte)
		n, addr, err := s.listener.ReadFromUDP(buf)
		if err != nil {
			common.PutBufPoolUdp(buf)
			if strings.Contains(err.Error(), "use of closed network connection") {
				break
			}
			continue
		}

		// IP Black
		if IsGlobalBlackIp(addr.String()) || common.IsBlackIp(addr.String(), s.task.Client.VerifyKey, s.task.Client.BlackIpList) {
			common.PutBufPoolUdp(buf)
			continue
		}

		logs.Trace("New udp connection,client %d,remote address %v", s.task.Client.Id, addr)
		//go s.process(addr, buf[:n])
		go func(b []byte, ln int, a *net.UDPAddr) {
			defer common.PutBufPoolUdp(b)
			s.process(a, b[:ln])
		}(buf, n, addr)
	}
	return nil
}

func (s *UdpModeServer) process(addr *net.UDPAddr, data []byte) {
	if s.task.Target.ProxyProtocol != 0 {
		hdr := conn.BuildProxyProtocolHeaderByAddr(addr, &net.UDPAddr{Port: s.task.Port}, s.task.Target.ProxyProtocol)
		if len(hdr) != 0 {
			tmp := make([]byte, len(hdr)+len(data))
			copy(tmp, hdr)
			copy(tmp[len(hdr):], data)
			data = tmp
		}
	}

	if v, ok := s.addrMap.Load(addr.String()); ok {
		clientConn, ok := v.(io.ReadWriteCloser)
		if ok {
			_, err := clientConn.Write(data)
			if err != nil {
				s.addrMap.Delete(addr.String())
				logs.Warn("%v", err)
				return
			}

			dataLength := int64(len(data))
			s.task.Flow.Add(dataLength, 0)
			s.task.Client.Flow.Add(dataLength, dataLength)
			return
		}
	} else {
		if err := s.CheckFlowAndConnNum(s.task.Client); err != nil {
			logs.Warn("client id %d, task id %d,error %v, when udp connection", s.task.Client.Id, s.task.Id, err)
			return
		}
		defer s.task.Client.CutConn()
		s.task.AddConn()
		defer s.task.CutConn()

		link := conn.NewLink(common.CONN_UDP, s.task.Target.TargetStr, s.task.Client.Cnf.Crypt, s.task.Client.Cnf.Compress, addr.String(), s.allowLocalProxy && s.task.Target.LocalProxy)
		clientConn, err := s.bridge.SendLinkInfo(s.task.Client.Id, link, s.task)
		if err != nil {
			return
		}
		target := conn.GetConn(clientConn, s.task.Client.Cnf.Crypt, s.task.Client.Cnf.Compress, nil, true)
		s.addrMap.Store(addr.String(), target)
		defer target.Close()

		_, err = target.Write(data)
		if err != nil {
			s.addrMap.Delete(addr.String())
			logs.Warn("%v", err)
			return
		}
		dataLength := int64(len(data))
		s.task.Flow.Add(dataLength, 0)
		s.task.Client.Flow.Add(dataLength, dataLength)

		buf := common.BufPoolUdp.Get().([]byte)
		defer common.PutBufPoolUdp(buf)

		for {
			clientConn.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, err := target.Read(buf)
			if err != nil {
				s.addrMap.Delete(addr.String())
				logs.Warn("%v", err)
				return
			}
			_, err = s.listener.WriteTo(buf[:n], addr)
			if err != nil {
				logs.Warn("%v", err)
				return
			}

			n64 := int64(n)
			s.task.Flow.Add(0, n64)
			s.task.Client.Flow.Add(n64, n64)
		}
	}
}

func (s *UdpModeServer) Close() error {
	return s.listener.Close()
}
