package conn

import (
	"bytes"
	"net"
	"sync"
	"time"
)

type TeeConn struct {
	underlying net.Conn
	buf        *bytes.Buffer
	mu         sync.Mutex
	detached   bool
}

func NewTeeConn(conn net.Conn) *TeeConn {
	return &TeeConn{
		underlying: conn,
		buf:        new(bytes.Buffer),
	}
}

func (t *TeeConn) Read(p []byte) (n int, err error) {
	n, err = t.underlying.Read(p)
	if n > 0 {
		t.mu.Lock()
		if !t.detached {
			t.buf.Write(p[:n])
		}
		t.mu.Unlock()
	}
	return n, err
}

func (t *TeeConn) Write(p []byte) (n int, err error) {
	return t.underlying.Write(p)
}

func (t *TeeConn) LocalAddr() net.Addr {
	return t.underlying.LocalAddr()
}

func (t *TeeConn) RemoteAddr() net.Addr {
	return t.underlying.RemoteAddr()
}

func (t *TeeConn) SetDeadline(deadline time.Time) error {
	return t.underlying.SetDeadline(deadline)
}

func (t *TeeConn) SetReadDeadline(deadline time.Time) error {
	return t.underlying.SetReadDeadline(deadline)
}

func (t *TeeConn) SetWriteDeadline(deadline time.Time) error {
	return t.underlying.SetWriteDeadline(deadline)
}

func (t *TeeConn) StopBuffering() {
	t.mu.Lock()
	t.detached = true
	t.mu.Unlock()
}

func (t *TeeConn) Close() error {
	t.StopBuffering()
	return t.underlying.Close()
}

func (t *TeeConn) Buffered() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]byte(nil), t.buf.Bytes()...)
}

func (t *TeeConn) ResetBuffer() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf.Reset()
}

func (t *TeeConn) ExtractAndReset() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	data := append([]byte(nil), t.buf.Bytes()...)
	t.buf.Reset()
	return data
}

func (t *TeeConn) Release() (net.Conn, []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.detached = true
	data := append([]byte(nil), t.buf.Bytes()...)
	t.buf = new(bytes.Buffer)
	return t.underlying, data
}

func (t *TeeConn) StopAndClean() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.detached = true
	t.buf = new(bytes.Buffer)
}
