package conn

import (
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

type QuicConn struct {
	stream *quic.Stream
	sess   *quic.Conn
}

func NewQuicConn(stream *quic.Stream, sess *quic.Conn) *QuicConn {
	return &QuicConn{stream: stream, sess: sess}
}

func (q *QuicConn) Read(p []byte) (int, error) {
	return q.stream.Read(p)
}

func (q *QuicConn) Write(p []byte) (int, error) {
	return q.stream.Write(p)
}

func (q *QuicConn) Close() error {
	err := q.stream.Close()
	if err != nil {
		return err
	}
	return q.sess.CloseWithError(0, "")
}

func (q *QuicConn) LocalAddr() net.Addr {
	return q.sess.LocalAddr()
}

func (q *QuicConn) RemoteAddr() net.Addr {
	return q.sess.RemoteAddr()
}

func (q *QuicConn) SetDeadline(t time.Time) error {
	return q.stream.SetDeadline(t)
}

func (q *QuicConn) SetReadDeadline(t time.Time) error {
	return q.stream.SetReadDeadline(t)
}

func (q *QuicConn) SetWriteDeadline(t time.Time) error {
	return q.stream.SetWriteDeadline(t)
}
