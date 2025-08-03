package bridge

import (
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/mux"
	"github.com/djylb/nps/lib/pool"
)

type SelectMode int32

const (
	Primary SelectMode = iota
	RoundRobin
	Random
)

var selectModeNames = [...]string{
	"Primary",
	"RoundRobin",
	"Random",
}

func nameOf(m SelectMode) string {
	if i := int(m); i >= 0 && i < len(selectModeNames) {
		return selectModeNames[i]
	}
	return fmt.Sprintf("%d", m)
}

var ClientSelectMode = Primary

func SetClientSelectMode(v any) error {
	const (
		minMode = int32(Primary)
		maxMode = int32(Random)
	)

	var mode SelectMode
	var bad bool

	switch x := v.(type) {
	case SelectMode:
		mode = x
	case int:
		mode = SelectMode(x)
	case int32:
		mode = SelectMode(x)
	case int64:
		mode = SelectMode(int(x))
	case string:
		s := strings.TrimSpace(strings.ToLower(x))
		switch s {
		case "", "primary", "p":
			mode = Primary
		case "roundrobin", "round", "rr":
			mode = RoundRobin
		case "random", "rand":
			mode = Random
		default:
			n, err := strconv.Atoi(s)
			if err != nil {
				bad = true
			} else {
				mode = SelectMode(n)
			}
		}
	default:
		bad = true
	}

	if int32(mode) < minMode || int32(mode) > maxMode {
		bad = true
	}

	if bad {
		ClientSelectMode = Primary
		logs.Warn("Invalid client select mode %v; fallback to %s(%d)", v, nameOf(Primary), Primary)
		return fmt.Errorf("invalid select mode %v: fallback to Primary", v)
	}
	ClientSelectMode = mode
	logs.Info("Client select mode set to %s(%d)", nameOf(mode), mode)
	return nil
}

type Client struct {
	Id        int
	signal    atomic.Pointer[conn.Conn] // WORK_MAIN
	tunnel    atomic.Pointer[mux.Mux]   // WORK_CHAN
	file      atomic.Pointer[mux.Mux]   // WORK_FILE
	signals   *pool.Pool[*conn.Conn]
	tunnels   *pool.Pool[*mux.Mux]
	files     *pool.Pool[*mux.Mux]
	Version   string
	retryTime int // it will add 1 when ping not ok until to 3 will close the client
	closed    uint32
}

func NewClient(id int, t, f *mux.Mux, s *conn.Conn, vs string) *Client {
	cli := &Client{
		Id:      id,
		Version: vs,
		signals: pool.New[*conn.Conn](),
		tunnels: pool.New[*mux.Mux](),
		files:   pool.New[*mux.Mux](),
	}
	if s != nil {
		cli.signal.Store(s)
		cli.signals.Add(s)
	}
	if t != nil {
		cli.tunnel.Store(t)
		cli.tunnels.Add(t)
	}
	if f != nil {
		cli.file.Store(f)
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
	c.signal.Store(s)
}

func (c *Client) AddTunnel(t *mux.Mux) {
	if c.IsClosed() {
		_ = t.Close()
		return
	}
	c.tunnels.Add(t)
	c.tunnel.Store(t)
}

func (c *Client) AddFile(f *mux.Mux) {
	if c.IsClosed() {
		_ = f.Close()
		return
	}
	c.files.Add(f)
	c.file.Store(f)
}

func (c *Client) SwitchSignal() {
	cur := c.signal.Load()
	if cur != nil && !cur.IsClosed() {
		return
	}
	c.signal.Store(nil)
	for {
		v, ok := c.signals.Next()
		if !ok {
			return
		}
		if v.IsClosed() {
			_ = v.Close()
			c.signals.Remove(v)
			continue
		}
		c.signal.Store(v)
		logs.Info("Client %d switched to backup signal", c.Id)
		return
	}
}

func (c *Client) SwitchTunnel() {
	cur := c.tunnel.Load()
	if cur != nil && !cur.IsClosed() {
		return
	}
	c.tunnel.Store(nil)
	for {
		v, ok := c.tunnels.Next()
		if !ok {
			return
		}
		if v.IsClosed() {
			_ = v.Close()
			c.tunnels.Remove(v)
			continue
		}
		c.tunnel.Store(v)
		logs.Info("Client %d switched to backup tunnel", c.Id)
		return
	}
}

func (c *Client) SwitchFile() {
	cur := c.file.Load()
	if cur != nil && !cur.IsClosed() {
		return
	}
	for {
		v, ok := c.files.Next()
		if !ok {
			return
		}
		if v.IsClosed() {
			_ = v.Close()
			c.files.Remove(v)
			continue
		}
		c.file.Store(v)
		logs.Info("Client %d switched to backup file", c.Id)
		return
	}
}

func (c *Client) GetSignal() *conn.Conn {
	switch ClientSelectMode {
	case Primary:
		c.SwitchSignal()
		return c.signal.Load()
	case RoundRobin:
		if v, ok := pickLive(c.signals, true); ok {
			return v
		}
	case Random:
		if v, ok := pickLive(c.signals, false); ok {
			return v
		}
	default:
	}
	return c.signal.Load()
}

func (c *Client) GetTunnel() *mux.Mux {
	switch ClientSelectMode {
	case Primary:
		c.SwitchTunnel()
		return c.tunnel.Load()
	case RoundRobin:
		if v, ok := pickLive(c.tunnels, true); ok {
			return v
		}
	case Random:
		if v, ok := pickLive(c.tunnels, false); ok {
			return v
		}
	default:
	}
	return c.tunnel.Load()
}

func (c *Client) GetFile() *mux.Mux {
	switch ClientSelectMode {
	case Primary:
		c.SwitchFile()
		return c.file.Load()
	case RoundRobin:
		if v, ok := pickLive(c.files, true); ok {
			return v
		}
	case Random:
		if v, ok := pickLive(c.files, false); ok {
			return v
		}
	default:
	}
	return c.file.Load()
}

func (c *Client) IsClosed() bool {
	return atomic.LoadUint32(&c.closed) == 1
}

func (c *Client) Close() error {
	if !atomic.CompareAndSwapUint32(&c.closed, 0, 1) {
		return nil
	}
	if v := c.signal.Load(); v != nil {
		_ = v.Close()
		c.signal.Store(nil)
	}
	if v := c.tunnel.Load(); v != nil {
		_ = v.Close()
		c.tunnel.Store(nil)
	}
	if v := c.file.Load(); v != nil {
		_ = v.Close()
		c.file.Store(nil)
	}

	c.signals.Clear(func(s *conn.Conn) { _ = s.Close() })
	c.tunnels.Clear(func(m *mux.Mux) { _ = m.Close() })
	c.files.Clear(func(m *mux.Mux) { _ = m.Close() })
	return nil
}

type live interface {
	comparable
	IsClosed() bool
	Close() error
}

func pickLive[T live](pl *pool.Pool[T], round bool) (T, bool) {
	for {
		var v T
		var ok bool
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
		_ = v.Close()
		pl.Remove(v)
	}
}
