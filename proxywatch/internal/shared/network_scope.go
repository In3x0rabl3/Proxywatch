package shared

import (
	"net"
	"strings"
)

func IsInternalIP(ip string) bool {
	netIP := parseIP(ip)
	if netIP == nil {
		return false
	}
	if netIP.IsLoopback() || netIP.IsPrivate() {
		return true
	}
	if netIP.IsLinkLocalUnicast() || netIP.IsLinkLocalMulticast() {
		return true
	}
	return netIP.IsInterfaceLocalMulticast()
}

func IsLoopbackIP(ip string) bool {
	parsed := parseIP(ip)
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

func parseIP(raw string) net.IP {
	ip := strings.TrimSpace(raw)
	if ip == "" {
		return nil
	}
	if zone := strings.IndexByte(ip, '%'); zone > 0 {
		ip = ip[:zone]
	}
	return net.ParseIP(ip)
}
