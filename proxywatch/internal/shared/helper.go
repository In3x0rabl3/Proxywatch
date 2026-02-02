package shared

import (
	"net"
	"os"
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
	// Known atomic roles
	allRoles := []string{
		"reverse-control",
		"reverse-transport",
		"reverse-proxy",
		"reverse-tunnel",
		"proxy-listener",
		"listener-with-clients",
		"listener-with-outbound",
		"listener-only",
		"susp-beacon",
		"susp-session",
		"susp-tun",
		"outbound-only",
	}

	// Group shortcuts (limit of 5 per user request)
	roleGroups := map[string][]string{
		"all":       allRoles,
		"reverse":   {"reverse-control", "reverse-transport", "reverse-proxy", "reverse-tunnel"},
		"listeners": {"proxy-listener", "listener-with-clients", "listener-with-outbound", "listener-only"},
		"susp":      {"susp-beacon", "susp-session", "susp-tun"},
		"control":   {"reverse-control", "reverse-transport", "susp-session", "susp-beacon", "susp-tun"},
	}

	out := make(map[string]bool)
	s = strings.TrimSpace(s)
	if s == "" {
		return out
	}
	for _, r := range strings.Split(s, ",") {
		r = strings.TrimSpace(r)
		if r != "" {
			if expanded, ok := roleGroups[strings.ToLower(r)]; ok {
				for _, er := range expanded {
					out[er] = true
				}
				continue
			}
			out[r] = true
		}
	}
	return out
}

func DefaultHostID(fallback string) string {
	name, err := os.Hostname()
	if err == nil {
		name = strings.TrimSpace(name)
	}
	if name == "" {
		return fallback
	}
	return name
}

// IsLikelyBenignBeacon heuristically skips known-legit updater/AV beacons.
func IsLikelyBenignBeacon(p *ProcessInfo) bool {
	if p == nil {
		return false
	}
	name := strings.ToLower(strings.TrimSpace(p.Name))
	path := strings.ToLower(strings.TrimSpace(p.ExePath))
	company := strings.ToLower(strings.TrimSpace(p.Company))

	if strings.Contains(company, "microsoft") {
		if strings.Contains(name, "mpdefender") ||
			strings.Contains(name, "msmpeng") ||
			strings.Contains(path, "windows defender") {
			return true
		}
	}
	return false
}
