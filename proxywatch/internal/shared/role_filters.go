package shared

import "strings"

func ParseRoleFilter(s string) map[string]bool {
	// Known atomic roles
	allRoles := []string{
		"reverse-control",
		"reverse-transport",
		"reverse-proxy",
		"reverse-tunnel",
		"smb-pipe",
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
		"recommended": {"reverse-control", "susp-session", "susp-beacon", "reverse-transport", "reverse-proxy", "reverse-tunnel", "smb-pipe", "susp-tun"},
		"all":         allRoles,
		"reverse":     {"reverse-control", "reverse-transport", "reverse-proxy", "reverse-tunnel"},
		"listeners":   {"proxy-listener", "listener-with-clients", "listener-with-outbound", "listener-only"},
		"susp":        {"susp-beacon", "susp-session", "susp-tun"},
		"control":     {"reverse-control", "reverse-transport", "smb-pipe", "susp-session", "susp-beacon", "susp-tun"},
		"tunnel":      {"reverse-transport", "reverse-proxy", "reverse-tunnel", "smb-pipe", "susp-tun"},
		"session":     {"reverse-control", "susp-session"},
		"beacon":      {"susp-beacon"},
		"listener":    {"proxy-listener", "listener-with-clients", "listener-with-outbound", "listener-only"},
		"outbound":    {"outbound-only"},
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

func RoleMatchesFilter(role string, roleFilter map[string]bool) bool {
	if len(roleFilter) == 0 {
		return true
	}
	if roleFilter[role] {
		return true
	}
	return roleFilter[RoleFamily(role)]
}
