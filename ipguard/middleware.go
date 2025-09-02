package ipguard

import (
	"context"
	"net"
	"net/http"
	"strings"
)

func parseClientIP(r *http.Request) string {
	// 可选：尊重反代头（注意安全）
	for _, h := range []string{"X-Forwarded-For", "X-Real-IP"} {
		if v := r.Header.Get(h); v != "" {
			ip := strings.TrimSpace(strings.Split(v, ",")[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func (g *Guard) Middleware(next http.Handler, denyHandler http.Handler) http.Handler {
	if denyHandler == nil {
		denyHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "forbidden", http.StatusForbidden)
		})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := parseClientIP(r)
		dec, _, _ := g.Decide(r.Context(), ip)
		if dec == Deny {
			denyHandler.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// 对于原生 TCP：在 Accept 后、握手前做一次判定
func (g *Guard) AllowConn(ctx context.Context, remoteAddr net.Addr) bool {
	host, _, _ := net.SplitHostPort(remoteAddr.String())
	dec, _, _ := g.Decide(ctx, host)
	return dec != Deny
}
