package proxy

import (
	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/logs"
	"net"
)

type SecretServer struct {
	BaseServer
}

func NewSecretServer(bridge NetBridge, task *file.Tunnel) *SecretServer {
	return &SecretServer{
		BaseServer: *NewBaseServer(bridge, task),
	}
}

func (s *SecretServer) HandleSecret(src net.Conn) error {
	s.Task.AddConn()
	defer s.Task.CutConn()
	if err := s.CheckFlowAndConnNum(s.Task.Client); err != nil {
		logs.Warn("Connection limit exceeded, client id %d, host id %d, error %v", s.Task.Client.Id, s.Task.Id, err)
		return err
	}
	defer s.Task.Client.CutConn()

	var rb []byte
	tee := conn.NewTeeConn(src)
	c := conn.NewConn(tee)
	lk, err := c.GetLinkInfo()
	if err != nil || lk == nil {
		//_ = c.Close()
		//logs.Error("get connection info error: %v", err)
		//return err
		lk = &conn.Link{ConnType: common.CONN_TCP}
		_, rb = tee.Release()
	}
	tee.StopAndClean()

	link := conn.NewLink(lk.ConnType, s.Task.Target.TargetStr, s.Task.Client.Cnf.Crypt, s.Task.Client.Cnf.Compress, c.Conn.RemoteAddr().String(), false)
	target, err := s.Bridge.SendLinkInfo(s.Task.Client.Id, link, s.Task)
	if err != nil {
		_ = c.Close()
		logs.Warn("failed to get backend connection: %v", err)
		return err
	}

	conn.CopyWaitGroup(target, c.Conn, link.Crypt, link.Compress, s.Task.Client.Rate, []*file.Flow{s.Task.Flow, s.Task.Client.Flow}, true, s.Task.Target.ProxyProtocol, rb, s.Task)
	return nil
}
