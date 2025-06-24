package conn

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/beego/beego"
	"github.com/djylb/nps/lib/logs"
	"github.com/quic-go/quic-go"
	"github.com/xtaci/kcp-go/v5"
)

func NewTcpListenerAndProcess(addr string, f func(c net.Conn), listener *net.Listener) error {
	var err error
	*listener, err = net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	Accept(*listener, f)
	return nil
}

func NewKcpListenerAndProcess(addr string, f func(c net.Conn)) error {
	kcpListener, err := kcp.ListenWithOptions(addr, nil, 150, 3)
	if err != nil {
		logs.Error("KCP listen error: %v", err)
		return err
	}
	for {
		c, err := kcpListener.AcceptKCP()
		SetUdpSession(c)
		if err != nil {
			logs.Trace("KCP accept session error: %v", err)
			continue
		}
		go f(c)
	}
	return nil
}

func NewQuicListenerAndProcess(addr string, tlsConfig *tls.Config, f func(c net.Conn)) error {
	keepAliveSec := beego.AppConfig.DefaultInt("quic_keep_alive_period", 10)
	idleTimeoutSec := beego.AppConfig.DefaultInt("quic_max_idle_timeout", 30)
	maxStreams := beego.AppConfig.DefaultInt64("quic_max_incoming_streams", 100000)

	quicConfig := &quic.Config{
		KeepAlivePeriod:    time.Duration(keepAliveSec) * time.Second,
		MaxIdleTimeout:     time.Duration(idleTimeoutSec) * time.Second,
		MaxIncomingStreams: maxStreams,
	}
	listener, err := quic.ListenAddr(addr, tlsConfig, quicConfig)
	if err != nil {
		logs.Error("QUIC listen error: %v", err)
		return err
	}
	for {
		sess, err := listener.Accept(context.Background())
		if err != nil {
			logs.Warn("QUIC accept session error: %v", err)
			continue
		}
		go func(sess *quic.Conn) {
			for {
				stream, err := sess.AcceptStream(context.Background())
				if err != nil {
					logs.Trace("QUIC accept stream error: %v", err)
					return
				}
				conn := NewQuicConn(stream, sess)
				go f(conn)
			}
		}(sess)
	}
}

func Accept(l net.Listener, f func(c net.Conn)) {
	for {
		c, err := l.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				break
			}
			if strings.Contains(err.Error(), "the mux has closed") {
				break
			}
			logs.Warn("%v", err)
			continue
		}
		if c == nil {
			logs.Warn("nil connection")
			break
		}
		go f(c)
	}
}

type OneConnListener struct {
	conn      net.Conn
	accepted  bool
	mu        sync.Mutex
	done      chan struct{}
	closeOnce sync.Once
}

func NewOneConnListener(c net.Conn) *OneConnListener {
	return &OneConnListener{
		conn: c,
		done: make(chan struct{}),
	}
}

func (l *OneConnListener) Accept() (net.Conn, error) {
	//logs.Trace("OneConnListener Accept")
	l.mu.Lock()
	if !l.accepted {
		l.accepted = true
		l.mu.Unlock()
		return l.conn, nil
	}
	l.mu.Unlock()
	<-l.done
	return nil, io.EOF
}

func (l *OneConnListener) Close() error {
	err := l.conn.Close()
	l.closeOnce.Do(func() {
		close(l.done)
		//logs.Trace("OneConnListener Close")
	})
	return err
}

func (l *OneConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}
