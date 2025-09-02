package ipguard

import (
	"net"
)

func isPrivate(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	privateCIDRs := []*net.IPNet{
		mustCIDR("10.0.0.0/8"), mustCIDR("172.16.0.0/12"),
		mustCIDR("192.168.0.0/16"), mustCIDR("127.0.0.0/8"),
		mustCIDR("::1/128"), mustCIDR("fc00::/7"),
	}
	for _, c := range privateCIDRs {
		if c.Contains(parsed) {
			return true
		}
	}
	return false
}
func mustCIDR(s string) *net.IPNet { _, n, _ := net.ParseCIDR(s); return n }

// 固定规则：私网/本地直通
type AllowPrivate struct{}
func (AllowPrivate) Eval(ip string, _ Meta) Decision {
	if isPrivate(ip) {
		return Allow
	}
	return Unknown
}

type AllowCountries struct{ Set map[string]struct{} } // e.g. {"CN":{}}
func (r AllowCountries) Eval(_ string, m Meta) Decision {
	if _, ok := r.Set[m.Country]; ok {
		return Allow
	}
	return Unknown
}

type DenyNotCountries struct{ Set map[string]struct{} } // 反向：非这些国家一律拒
func (r DenyNotCountries) Eval(_ string, m Meta) Decision {
	if _, ok := r.Set[m.Country]; ok {
		return Unknown
	}
	return Deny
}

type AllowASNs struct{ Set map[uint]struct{} } // 家宽 ASN 白名单
func (r AllowASNs) Eval(_ string, m Meta) Decision {
	if _, ok := r.Set[m.ASN]; ok {
		return Allow
	}
	return Unknown
}

type DenyASNs struct{ Set map[uint]struct{} } // 云厂商 ASN 黑名单
func (r DenyASNs) Eval(_ string, m Meta) Decision {
	if _, ok := r.Set[m.ASN]; ok {
		return Deny
	}
	return Unknown
}

// 规则链：按序第一个非 Unknown 生效
func firstMatch(rules []Rule, ip string, m Meta) Decision {
	for _, r := range rules {
		if d := r.Eval(ip, m); d != Unknown {
			return d
		}
	}
	return Unknown
}
