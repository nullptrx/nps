//go:build !windows
// +build !windows

package proxy

import (
	"net"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/transport"
	"golang.org/x/sys/unix"
)

func SetTcpKeepAliveParams(tc *net.TCPConn, idle, intvl, probes int) error {
	raw, err := tc.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		if sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPIDLE, idle); sockErr != nil {
			return
		}
		if sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPINTVL, intvl); sockErr != nil {
			return
		}
		sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPCNT, probes)
	})
	if err != nil {
		return err
	}
	return sockErr
}

func HandleTrans(c *conn.Conn, s *TunnelModeServer) error {
	if addr, err := transport.GetAddress(c.Conn); err != nil {
		return err
	} else {
		return s.DealClient(c, s.Task.Client, addr, nil, common.CONN_TCP, nil, []*file.Flow{s.Task.Flow, s.Task.Client.Flow}, s.Task.Target.ProxyProtocol, s.Task.Target.LocalProxy, s.Task)
	}
}
