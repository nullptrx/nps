package conn

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

type WSConn struct {
	*websocket.Conn
	readBuf []byte
}

func NewWSConn(ws *websocket.Conn) *WSConn {
	return &WSConn{Conn: ws, readBuf: make([]byte, 0)}
}

func (c *WSConn) Read(p []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}
	mt, r, err := c.NextReader()
	if err != nil {
		return 0, err
	}
	if mt == websocket.CloseMessage {
		return 0, io.EOF
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return 0, err
	}
	n := copy(p, data)
	if n < len(data) {
		c.readBuf = append(c.readBuf, data[n:]...)
	}
	return n, nil
}

func (c *WSConn) Write(p []byte) (int, error) {
	w, err := c.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return 0, err
	}
	n, err := w.Write(p)
	if err != nil {
		return n, err
	}
	return n, w.Close()
}

func (c *WSConn) Close() error         { return c.Conn.Close() }
func (c *WSConn) LocalAddr() net.Addr  { return c.Conn.UnderlyingConn().LocalAddr() }
func (c *WSConn) RemoteAddr() net.Addr { return c.Conn.UnderlyingConn().RemoteAddr() }
func (c *WSConn) SetDeadline(t time.Time) error {
	c.Conn.SetReadDeadline(t)
	return c.Conn.SetWriteDeadline(t)
}
func (c *WSConn) SetReadDeadline(t time.Time) error  { return c.Conn.SetReadDeadline(t) }
func (c *WSConn) SetWriteDeadline(t time.Time) error { return c.Conn.SetWriteDeadline(t) }

type httpListener struct {
	acceptCh chan net.Conn
	closeCh  chan struct{}
	addr     net.Addr
}

func NewWSListener(base net.Listener, path string) net.Listener {
	ch := make(chan net.Conn, 16)
	hl := &httpListener{acceptCh: ch, closeCh: make(chan struct{}), addr: base.Addr()}
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-hl.closeCh:
			return
		default:
		}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		ch <- NewWSConn(ws)
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(base)
	go func() {
		<-hl.closeCh
		srv.Close()
	}()
	return hl
}

func NewWSSListener(base net.Listener, path string, cert tls.Certificate) net.Listener {
	ch := make(chan net.Conn, 16)
	hl := &httpListener{acceptCh: ch, closeCh: make(chan struct{}), addr: base.Addr()}
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-hl.closeCh:
			return
		default:
		}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		ch <- NewWSConn(ws)
	})
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	srv := &http.Server{Handler: mux, TLSConfig: tlsConfig}
	go srv.Serve(tls.NewListener(base, tlsConfig))
	go func() {
		<-hl.closeCh
		srv.Close()
	}()
	return hl
}

func (hl *httpListener) Accept() (net.Conn, error) {
	select {
	case c := <-hl.acceptCh:
		return c, nil
	case <-hl.closeCh:
		return nil, io.EOF
	}
}

func (hl *httpListener) Close() error {
	close(hl.closeCh)
	return nil
}

func (hl *httpListener) Addr() net.Addr {
	return hl.addr
}

func DialWS(ctx context.Context, urlStr string, timeout time.Duration) (net.Conn, error) {
	d := websocket.Dialer{HandshakeTimeout: timeout}
	ws, _, err := d.DialContext(ctx, urlStr, nil)
	if err != nil {
		return nil, err
	}
	return NewWSConn(ws), nil
}

func DialWSS(ctx context.Context, urlStr string, timeout time.Duration) (net.Conn, error) {
	d := websocket.Dialer{HandshakeTimeout: timeout, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	ws, _, err := d.DialContext(ctx, urlStr, nil)
	if err != nil {
		return nil, err
	}
	return NewWSConn(ws), nil
}
