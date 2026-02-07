package shared

import (
	"net"
	"os"
	"strings"
)

var InternalCIDRs = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"fc00::/7",
	"fe80::/10",
}

var LateralPorts = map[int]bool{
	445:  true,
	3389: true,
	5985: true,
	5986: true,
	139:  true,
	389:  true,
	636:  true,
	1433: true,
}

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
		"tunnel":    {"reverse-transport", "reverse-proxy", "reverse-tunnel", "susp-tun"},
		"session":   {"reverse-control", "susp-session"},
		"beacon":    {"susp-beacon"},
		"listener":  {"proxy-listener", "listener-with-clients", "listener-with-outbound", "listener-only"},
		"outbound":  {"outbound-only"},
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

func DisplayHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return "local"
	}
	return host
}

func RoleMatchesFilter(role string, roleFilter map[string]bool) bool {
	if len(roleFilter) == 0 {
		return true
	}
	if roleFilter[role] {
		return true
	}
	return roleFilter[RoleFamily(role)]
}

// IsLikelyBenignBeacon heuristically skips known-legit updater/AV beacons.
func IsLikelyBenignBeacon(p *ProcessInfo) bool {
	if p == nil {
		return false
	}
	if !IsLikelyBenignControlClient(p) {
		return false
	}
	path := normalizeExePath(p.ExePath)
	if path == "" {
		return false
	}
	if strings.Contains(path, "/tmp/") ||
		strings.Contains(path, "/var/tmp/") ||
		strings.Contains(path, "/downloads/") ||
		strings.Contains(path, "/appdata/local/temp/") {
		return false
	}
	return true
}

func IsLikelyBenignControlClient(p *ProcessInfo) bool {
	if p == nil {
		return false
	}
	path := normalizeExePath(p.ExePath)
	if path == "" {
		return false
	}

	roots := []string{
		"/usr/",
		"/bin/",
		"/sbin/",
		"/lib/",
		"/lib64/",
		"/opt/",
		"/snap/",
		"/nix/store/",
		"c:/windows/",
		"c:/program files/",
		"c:/program files (x86)/",
	}
	for _, root := range roots {
		if strings.HasPrefix(path, root) {
			return true
		}
	}

	// Some trusted Windows services ship in ProgramData vendor paths.
	// Treat those as benign only when the vendor path segment aligns with
	// publisher metadata and the process runs in a service-like security context.
	if strings.HasPrefix(path, "c:/programdata/") &&
		isServiceLikeContext(p) &&
		programDataVendorMatchesCompany(path, p.Company) {
		return true
	}

	return false
}

func normalizeExePath(path string) string {
	path = strings.ToLower(strings.TrimSpace(path))
	return strings.ReplaceAll(path, "\\", "/")
}

func isServiceLikeContext(p *ProcessInfo) bool {
	if p == nil {
		return false
	}
	user := strings.ToLower(strings.TrimSpace(p.UserName))
	integrity := strings.ToLower(strings.TrimSpace(p.Integrity))

	switch integrity {
	case "system", "protected":
		return true
	}

	if strings.Contains(user, "nt authority\\") {
		return true
	}
	if strings.Contains(user, "local service") || strings.Contains(user, "network service") {
		return true
	}
	if strings.HasSuffix(user, "\\system") {
		return true
	}
	return false
}

func programDataVendorMatchesCompany(path, company string) bool {
	const prefix = "c:/programdata/"
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	company = strings.ToLower(strings.TrimSpace(company))
	if company == "" {
		return false
	}

	rel := strings.TrimPrefix(path, prefix)
	slash := strings.IndexByte(rel, '/')
	if slash <= 0 {
		return false
	}
	vendor := strings.TrimSpace(rel[:slash])
	if len(vendor) < 3 {
		return false
	}

	return strings.Contains(company, vendor)
}
