package shared

import (
	"net"
	"strings"
)

func IsInternalIP(ip string) bool {
	netIP := net.ParseIP(ip)
	if netIP == nil {
		return false
	}
	for _, cidr := range InternalCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(netIP) {
			return true
		}
	}
	return false
}

func IsLoopbackIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback()
}

func IsWildcardIP(ip string) bool {
	return ip == "0.0.0.0" || ip == "::"
}

func UDPScopeCounts(list []UDPListenerInfo) (internal, external, loopback int) {
	for _, u := range list {
		switch {
		case IsLoopbackIP(u.LocalAddress):
			loopback++
		case IsInternalIP(u.LocalAddress):
			internal++
		default:
			external++
		}
	}
	return
}

func ScopeLabelForLocalAddress(addr string) string {
	switch {
	case IsWildcardIP(addr):
		return "any"
	case IsLoopbackIP(addr):
		return "loopback"
	case IsInternalIP(addr):
		return "internal"
	default:
		return "external"
	}
}

func TrimName(name string, max int) string {
	if len(name) <= max {
		return name
	}
	if max <= 3 {
		return name[:max]
	}
	return name[:max-3] + "..."
}

func ParseRoleFilter(s string) map[string]bool {
	out := make(map[string]bool)
	s = strings.TrimSpace(s)
	if s == "" {
		return out
	}
	for _, r := range strings.Split(s, ",") {
		r = strings.TrimSpace(r)
		if r != "" {
			out[r] = true
		}
	}
	return out
}
