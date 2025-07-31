package bridge

import (
	"sync/atomic"

	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/nps_mux"
	"github.com/djylb/nps/lib/pool"
)

type SelectMode int32

const (
	Primary SelectMode = iota
	RoundRobin
	Random
)

var ConnSelectMode = Primary

type live interface {
	comparable
	IsClosed() bool
	Close() error
}

func pickLive[T live](pl *pool.Pool[T], round bool) (T, bool) {
	for {
		var (
			v  T
			ok bool
		)
		if round {
			v, ok = pl.Next()
		} else {
			v, ok = pl.Random()
		}
		if !ok {
			var zero T
			return zero, false
		}
		if !v.IsClosed() {
			return v, true
		}
		pl.Remove(v)
	}
}

type Client struct {
	Id        int
	signal    *conn.Conn   // WORK_MAIN connection
	tunnel    *nps_mux.Mux // WORK_CHAN connection
	file      *nps_mux.Mux // WORK_FILE connection
	signals   *pool.Pool[*conn.Conn]
	tunnels   *pool.Pool[*nps_mux.Mux]
	files     *pool.Pool[*nps_mux.Mux]
	Version   string
	retryTime int // it will add 1 when ping not ok until to 3 will close the client
	closed    uint32
}

func NewClient(id int, t, f *nps_mux.Mux, s *conn.Conn, vs string) *Client {
	cli := &Client{
		Id:      id,
		signal:  s,
		tunnel:  t,
		file:    f,
		Version: vs,
		signals: pool.New[*conn.Conn](),
		tunnels: pool.New[*nps_mux.Mux](),
		files:   pool.New[*nps_mux.Mux](),
	}
	if s != nil {
		cli.signals.Add(s)
	}
	if t != nil {
		cli.tunnels.Add(t)
	}
	if f != nil {
		cli.files.Add(f)
	}
	return cli
}

func (c *Client) AddSignal(s *conn.Conn) {
	if c.IsClosed() {
		_ = s.Close()
		return
	}
	c.signals.Add(s)
	c.signal = s
}

func (c *Client) AddTunnel(t *nps_mux.Mux) {
	if c.IsClosed() {
		_ = t.Close()
		return
	}
	c.tunnels.Add(t)
	c.tunnel = t
}

func (c *Client) AddFile(f *nps_mux.Mux) {
	if c.IsClosed() {
		_ = f.Close()
		return
	}
	c.files.Add(f)
	c.file = f
}

func (c *Client) SwitchSignal() {
	if c.signal != nil && !c.signal.IsClosed() {
		return
	}
	for {
		v, ok := c.signals.Next()
		if !ok {
			c.signal = nil
			return
		}
		if v.IsClosed() {
			_ = v.Close()
			c.signals.Remove(v)
			continue
		}
		c.signal = v
		logs.Info("Client %d switched to backup signal", c.Id)
		return
	}
}

func (c *Client) SwitchTunnel() {
	if c.tunnel != nil && !c.tunnel.IsClosed() {
		return
	}
	for {
		v, ok := c.tunnels.Next()
		if !ok {
			c.tunnel = nil
			return
		}
		if v.IsClosed() {
			_ = v.Close()
			c.tunnels.Remove(v)
			continue
		}
		c.tunnel = v
		logs.Info("Client %d switched to backup tunnel", c.Id)
		return
	}
}

func (c *Client) SwitchFile() {
	if c.file != nil && !c.file.IsClosed() {
		return
	}
	for {
		v, ok := c.files.Next()
		if !ok {
			c.file = nil
			return
		}
		if v.IsClosed() {
			_ = v.Close()
			c.files.Remove(v)
			continue
		}
		c.file = v
		logs.Info("Client %d switched to backup file", c.Id)
		return
	}
}

func (c *Client) GetSignal() *conn.Conn {
	switch ConnSelectMode {
	case Primary:
		c.SwitchSignal()
		return c.signal
	case RoundRobin:
		if v, ok := pickLive(c.signals, true); ok {
			return v
		}
	case Random:
		if v, ok := pickLive(c.signals, false); ok {
			return v
		}
	}
	return c.signal
}

func (c *Client) GetTunnel() *nps_mux.Mux {
	switch ConnSelectMode {
	case Primary:
		c.SwitchTunnel()
		return c.tunnel
	case RoundRobin:
		if v, ok := pickLive(c.tunnels, true); ok {
			return v
		}
	case Random:
		if v, ok := pickLive(c.tunnels, false); ok {
			return v
		}
	}
	return c.tunnel
}

func (c *Client) GetFile() *nps_mux.Mux {
	switch ConnSelectMode {
	case Primary:
		c.SwitchFile()
		return c.file
	case RoundRobin:
		if v, ok := pickLive(c.files, true); ok {
			return v
		}
	case Random:
		if v, ok := pickLive(c.files, false); ok {
			return v
		}
	}
	return c.file
}

func (c *Client) IsClosed() bool {
	return atomic.LoadUint32(&c.closed) == 1
}

func (c *Client) Close() error {
	if !atomic.CompareAndSwapUint32(&c.closed, 0, 1) {
		return nil
	}
	if c.signal != nil {
		_ = c.signal.Close()
	}
	if c.tunnel != nil {
		_ = c.tunnel.Close()
	}
	if c.file != nil {
		_ = c.file.Close()
	}

	c.signals.Clear(func(s *conn.Conn) { _ = s.Close() })
	c.tunnels.Clear(func(m *nps_mux.Mux) { _ = m.Close() })
	c.files.Clear(func(m *nps_mux.Mux) { _ = m.Close() })
	return nil
}
