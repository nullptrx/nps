package bridge

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/mux"
	"github.com/djylb/nps/lib/pool"
	"github.com/quic-go/quic-go"
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

type Node struct {
	mu      sync.RWMutex
	Client  *Client
	Addr    string
	Version string
	BaseVer int
	signal  *conn.Conn
	tunnel  any //*mux.Mux or *quic.Conn
}

func NewNode(addr, vs string, bv int) *Node {
	return &Node{
		Addr:    addr,
		Version: vs,
		BaseVer: bv,
	}
}

func (n *Node) AddNode(node *Node) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if node.Version != "" {
		n.Version = node.Version
	}
	if node.BaseVer != 0 {
		n.BaseVer = node.BaseVer
	}
	if node.signal != nil {
		n.addSignal(node.signal)
	}
	if node.tunnel != nil {
		n.addTunnel(node.tunnel)
	}
}

func (n *Node) AddSignal(signal *conn.Conn) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.addSignal(signal)
}

func (n *Node) addSignal(signal *conn.Conn) {
	if n.signal != nil && n.signal != signal {
		_ = n.signal.Close()
	}
	n.signal = signal
}

func (n *Node) AddTunnel(tunnel any) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.addTunnel(tunnel)
}

func (n *Node) addTunnel(tunnel any) {
	if n.tunnel != tunnel {
		_ = n.closeTunnel("override")
		n.tunnel = tunnel
	}
}

func (n *Node) GetSignal() *conn.Conn {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.signal
}

func (n *Node) GetTunnel() any {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.tunnel
}

func (n *Node) IsOnline() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.isOnline()
}

func (n *Node) isOnline() bool {
	return !n.isTunnelClosed() && (n.signal != nil && !n.signal.IsClosed()) || n.Client.Id < 0
}

func (n *Node) isTunnelClosed() bool {
	if n.tunnel == nil {
		return true
	}
	switch t := n.tunnel.(type) {
	case *mux.Mux:
		return t.IsClosed()
	case *quic.Conn:
		return t.Context().Err() != nil
	default:
		return true
	}
}

func (n *Node) IsOffline() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.BaseVer < 5 {
		return n.isTunnelClosed() && (n.signal == nil || n.signal.IsClosed()) && n.Client.Id > 0
	}
	return !n.isOnline()
}

func (n *Node) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	_ = n.closeTunnel("node close")
	if n.signal != nil {
		_ = n.signal.Close()
		n.signal = nil
	}
	return nil
}

func (n *Node) closeTunnel(err string) error {
	if n.tunnel != nil {
		switch t := n.tunnel.(type) {
		case *mux.Mux:
			_ = t.IsClosed()
		case *quic.Conn:
			_ = t.CloseWithError(0, err)
		default:
		}
		n.tunnel = nil
	}
	return nil
}

type Client struct {
	mu        sync.RWMutex
	Id        int
	LastAddr  string
	nodeList  *pool.Pool[string] // addr
	nodes     sync.Map           // map[addr]*Node
	files     sync.Map           // map[fileUUID]addr
	retryTime int                // it will add 1 when ping not ok until to 3 will close the client
	closed    uint32
}

func NewClient(id int, n *Node) *Client {
	c := &Client{
		Id:       id,
		LastAddr: n.Addr,
		nodeList: pool.New[string](),
	}
	n.Client = c
	c.nodes.Store(n.Addr, n)
	c.nodeList.Add(n.Addr)
	return c
}

func (c *Client) AddNode(n *Node) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.nodes.Load(n.Addr); ok {
		existing := v.(*Node)
		if existing.IsOnline() {
			_ = n.Close()
			return
		}
		existing.AddNode(n)
		c.LastAddr = n.Addr
		return
	}
	n.Client = c
	c.nodes.Store(n.Addr, n)
	c.nodeList.Add(n.Addr)
	c.LastAddr = n.Addr
}

func (c *Client) AddFile(key, addr string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.nodes.Load(addr); !ok {
		return fmt.Errorf("addr %q not found", addr)
	}
	c.files.Store(key, addr)
	return nil
}

func (c *Client) RemoveFile(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.files.Delete(key)
}

func (c *Client) GetNodeByFile(key string) (*Node, bool) {
	c.mu.RLock()
	v, ok := c.files.Load(key)
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	addr, ok := v.(string)
	if !ok {
		return nil, false
	}
	c.mu.RLock()
	n, ok := c.nodes.Load(addr)
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	node, ok := n.(*Node)
	if ok {
		if node.IsOnline() {
			return node, true
		}
		_ = node.Close()
		c.mu.Lock()
		c.removeNode(addr)
		c.mu.Unlock()
	}
	return nil, false
}

func (c *Client) CheckNode() *Node {
	c.mu.RLock()
	size := c.nodeList.Size()
	c.mu.RUnlock()
	if size == 0 {
		logs.Warn("Client %d has no nodes to switch to", c.Id)
		return nil
	}
	first := true
	for {
		var addr string
		c.mu.RLock()
		addr = c.LastAddr
		c.mu.RUnlock()
		if addr == "" {
			var nextAddr string
			switch ClientSelectMode {
			case Primary, RoundRobin:
				nextAddr, _ = c.nodeList.Next()
			case Random:
				nextAddr, _ = c.nodeList.Random()
			default:
				nextAddr, _ = c.nodeList.Next()
			}
			if nextAddr == "" {
				logs.Warn("Client %d has no nodes to switch to", c.Id)
				return nil
			}
			c.mu.Lock()
			c.LastAddr = nextAddr
			c.mu.Unlock()
			addr = nextAddr
		}
		c.mu.RLock()
		raw, ok := c.nodes.Load(addr)
		c.mu.RUnlock()
		if ok {
			node, ok := raw.(*Node)
			if ok {
				if !node.IsOffline() {
					if !first {
						logs.Info("Client %d switched to backup node %s", c.Id, addr)
					}
					return node
				}
				_ = node.Close()
			}
		}
		first = false
		c.mu.Lock()
		removed := c.LastAddr
		c.removeNode(removed)
		c.mu.Unlock()
		logs.Info("Client %d removed node %s", c.Id, removed)
	}
}

func (c *Client) GetNode() *Node {
	switch ClientSelectMode {
	case Primary:
		return c.CheckNode()
	case RoundRobin:
		c.mu.Lock()
		c.LastAddr, _ = c.nodeList.Next()
		c.mu.Unlock()
		return c.CheckNode()
	case Random:
		c.mu.Lock()
		c.LastAddr, _ = c.nodeList.Random()
		c.mu.Unlock()
		return c.CheckNode()
	default:
	}
	return c.CheckNode()
}

func (c *Client) GetNodeByAddr(addr string) (*Node, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	raw, ok := c.nodes.Load(addr)
	if !ok {
		return nil, false
	}
	node, ok := raw.(*Node)
	return node, ok
}

func (c *Client) NodeCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.nodeList.Size()
}

func (c *Client) removeNode(addr string) {
	c.nodes.Delete(addr)
	c.nodeList.Remove(addr)
	if c.LastAddr == addr {
		if next, ok := c.nodeList.Next(); ok {
			c.LastAddr = next
		} else {
			c.LastAddr = ""
		}
	}
	c.files.Range(func(key, value interface{}) bool {
		if v, ok := value.(string); ok && v == addr {
			c.files.Delete(key)
		}
		return true
	})
}

func (c *Client) IsClosed() bool {
	return atomic.LoadUint32(&c.closed) == 1
}

func (c *Client) Close() error {
	if !atomic.CompareAndSwapUint32(&c.closed, 0, 1) {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nodes.Range(func(key, value interface{}) bool {
		if n, ok := value.(*Node); ok {
			_ = n.Close()
		}
		return true
	})
	c.nodeList.Clear(nil)
	c.nodes = sync.Map{}
	c.files = sync.Map{}
	return nil
}
