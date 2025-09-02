package ipguard

import (
	"context"
	"sync/atomic"
	"time"
)

type Decision int

const (
	Unknown Decision = iota
	Allow
	Deny
)

type Meta struct {
	Country string // e.g. "CN"
	ASN     uint   // e.g. 4134
	Org     string // e.g. "China Telecom"
}

type Provider interface {
	Lookup(ctx context.Context, ip string) (Meta, error)
	Close() error
}

type Rule interface {
	Eval(ip string, m Meta) Decision
}

type Guard struct {
	provider Provider
	rules    atomic.Value // []Rule
	cache    *ttlCache[Decision]
}

type Options struct {
	CacheTTL time.Duration
	CacheCap int
	Provider Provider
}
