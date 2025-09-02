package ipguard

import (
	"context"
	"sync"
	"time"
)

func New(opts Options) *Guard {
	if opts.CacheTTL == 0 {
		opts.CacheTTL = time.Minute
	}
	if opts.CacheCap == 0 {
		opts.CacheCap = 65536
	}
	g := &Guard{
		provider: opts.Provider,
		cache:    newTTLCache[Decision](opts.CacheCap, opts.CacheTTL),
	}
	g.rules.Store([]Rule{}) // 初始化为空规则集
	return g
}

func (g *Guard) UpdateRules(r []Rule) { g.rules.Store(r) }

func (g *Guard) Decide(ctx context.Context, ip string) (Decision, Meta, error) {
	if d, ok := g.cache.Get(ip); ok {
		return d, Meta{}, nil // 决策缓存命中（极快）
	}
	m, err := g.provider.Lookup(ctx, ip)
	if err != nil {
		return Unknown, Meta{}, err
	}
	rules := g.rules.Load().([]Rule)
	dec := firstMatch(rules, ip, m)
	if dec == Unknown {
		dec = Deny
	} // 默认策略：未知即拒（你也可改为 Allow）
	g.cache.Set(ip, dec)
	return dec, m, nil
}

func (g *Guard) Close() error { return g.provider.Close() }

// 简单 TTL LRU（无第三方依赖）
type ttlEntry[T any] struct {
	v   T
	exp int64
}
type ttlCache[T any] struct {
	mu  sync.Mutex
	ttl time.Duration
	cap int
	m   map[string]ttlEntry[T]
}

func newTTLCache[T any](cap int, ttl time.Duration) *ttlCache[T] {
	return &ttlCache[T]{cap: cap, ttl: ttl, m: make(map[string]ttlEntry[T])}
}
func (c *ttlCache[T]) Get(k string) (T, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[k]; ok && time.Now().UnixNano() < e.exp {
		return e.v, true
	}
	var zero T
	delete(c.m, k)
	return zero, false
}
func (c *ttlCache[T]) Set(k string, v T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= c.cap { // 粗暴淘汰：任意删除一个
		for k0 := range c.m {
			delete(c.m, k0)
			break
		}
	}
	c.m[k] = ttlEntry[T]{v: v, exp: time.Now().Add(c.ttl).UnixNano()}
}
