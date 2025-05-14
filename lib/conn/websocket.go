package conn

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
)

// --------------------------------------------------------------------
// Adapter: wrap *websocket.Conn as net.Conn
// --------------------------------------------------------------------

type WSConn struct {
	*websocket.Conn
}

func WrapWebsocket(ws *websocket.Conn) net.Conn {
	return &WSConn{Conn: ws}
}

func (c *WSConn) Read(b []byte) (int, error) {
	for {
		mt, r, err := c.NextReader()
		if err != nil {
			return 0, err
		}
		if mt == websocket.BinaryMessage {
			return r.Read(b)
		}
	}
}

func (c *WSConn) Write(b []byte) (int, error) {
	w, err := c.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return 0, err
	}
	n, err := w.Write(b)
	if err != nil {
		return n, err
	}
	return n, w.Close()
}

func (c *WSConn) Close() error                        { return c.Conn.Close() }
func (c *WSConn) LocalAddr() net.Addr                 { return c.Conn.UnderlyingConn().LocalAddr() }
func (c *WSConn) RemoteAddr() net.Addr                { return c.Conn.UnderlyingConn().RemoteAddr() }
func (c *WSConn) SetDeadline(t time.Time) error       { c.Conn.SetReadDeadline(t); return c.Conn.SetWriteDeadline(t) }
func (c *WSConn) SetReadDeadline(t time.Time) error   { return c.Conn.SetReadDeadline(t) }
func (c *WSConn) SetWriteDeadline(t time.Time) error  { return c.Conn.SetWriteDeadline(t) }

// --------------------------------------------------------------------
// Wrap an existing TCP Listener into WS or WSS
// --------------------------------------------------------------------

type httpListener struct {
	base     net.Listener
	server   *http.Server
	acceptCh chan net.Conn
}

func NewWSListenerFromListener(base net.Listener, path string) net.Listener {
	hl := &httpListener{
		base:     base,
		acceptCh: make(chan net.Conn),
	}
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		hl.acceptCh <- WrapWebsocket(ws)
	})
	hl.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 60 * time.Second,
	}
	go hl.server.Serve(base)
	return hl
}

func NewWSSListenerFromListener(base net.Listener, path string, cert tls.Certificate) net.Listener {
	hl := &httpListener{
		base:     base,
		acceptCh: make(chan net.Conn),
	}
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		hl.acceptCh <- WrapWebsocket(ws)
	})
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	hl.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 60 * time.Second,
		TLSConfig:         tlsConfig,
	}
	go hl.server.Serve(tls.NewListener(base, tlsConfig))
	return hl
}

func (h *httpListener) Accept() (net.Conn, error) {
	c, ok := <-h.acceptCh
	if !ok {
		return nil, nil
	}
	return c, nil
}

func (h *httpListener) Close() error {
	err := h.server.Close()
	close(h.acceptCh)
	return err
}

func (h *httpListener) Addr() net.Addr {
	return h.base.Addr()
}

// --------------------------------------------------------------------
// Client-side: perform WS/WSS handshake over an existing net.Conn
// --------------------------------------------------------------------

func DialWSOverConn(rawConn net.Conn, urlStr string, timeout time.Duration) (net.Conn, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	d := websocket.Dialer{
		NetDial: func(network, addr string) (net.Conn, error) {
			return rawConn, nil
		},
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}

	rawConn.SetDeadline(time.Now().Add(timeout))
	ws, resp, err := d.Dial(u.String(), http.Header{})
	rawConn.SetDeadline(time.Time{})
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	return WrapWebsocket(ws), nil
}

func DialWSSOverConn(rawConn net.Conn, urlStr string, tlsConfig *tls.Config, timeout time.Duration) (net.Conn, error) {
	tlsConn := tls.Client(rawConn, tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(timeout))
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	tlsConn.SetDeadline(time.Time{})

	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	d := websocket.Dialer{
		NetDial: func(network, addr string) (net.Conn, error) {
			return tlsConn, nil
		},
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}

	tlsConn.SetDeadline(time.Now().Add(timeout))
	ws, resp, err := d.Dial(u.String(), http.Header{})
	tlsConn.SetDeadline(time.Time{})
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	return WrapWebsocket(ws), nil
}
