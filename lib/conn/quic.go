package conn

import (
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

type QuicConn struct {
	stream quic.Stream
	sess   quic.Connection
}

func NewQuicConn(stream quic.Stream, sess quic.Connection) *QuicConn {
	return &QuicConn{stream: stream, sess: sess}
}

func (q *QuicConn) Read(p []byte) (int, error) {
	return q.stream.Read(p)
}

func (q *QuicConn) Write(p []byte) (int, error) {
	return q.stream.Write(p)
}

func (q *QuicConn) Close() error {
	err1 := q.stream.Close()
	err2 := q.sess.CloseWithError(0, "")
	if err1 != nil {
		return err1
	}
	return err2
}

func (q *QuicConn) LocalAddr() net.Addr {
	return q.sess.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (q *QuicConn) RemoteAddr() net.Addr {
	return q.sess.RemoteAddr()
}

func (q *QuicConn) SetDeadline(t time.Time) error      { return nil }
func (q *QuicConn) SetReadDeadline(t time.Time) error  { return nil }
func (q *QuicConn) SetWriteDeadline(t time.Time) error { return nil }
