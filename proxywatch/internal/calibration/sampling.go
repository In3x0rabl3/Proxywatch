package calibration

import (
	"strings"

	"proxywatch/internal/detection"
	"proxywatch/internal/shared"
)

func SamplesFromSnapshot(snap *shared.Snapshot, hostID, scope string) []shared.Candidate {
	scored := classifier.ClassifyAllForCalibration(snap)
	if len(scored) == 0 {
		return nil
	}
	host := strings.TrimSpace(hostID)
	if host == "" {
		host = shared.DefaultHostID("local")
	}
	for i := range scored {
		scored[i].Host = host
	}
	return filterSamplesByScope(scored, scope)
}

func filterSamplesByScope(samples []shared.Candidate, scope string) []shared.Candidate {
	filter := scopeRoleFilter(scope)
	if len(filter) == 0 {
		out := make([]shared.Candidate, len(samples))
		copy(out, samples)
		return out
	}
	out := make([]shared.Candidate, 0, len(samples))
	for _, sample := range samples {
		if shared.RoleMatchesFilter(sample.Role, filter) {
			out = append(out, sample)
		}
	}
	return out
}

func scopeRoleFilter(scope string) map[string]bool {
	s := strings.ToLower(strings.TrimSpace(scope))
	switch s {
	case "", "recommended", "all":
		return shared.ParseRoleFilter("all")
	case "session":
		return shared.ParseRoleFilter("session")
	case "beacon":
		return shared.ParseRoleFilter("beacon")
	case "tunnel":
		return shared.ParseRoleFilter("tunnel")
	case "listen":
		return shared.ParseRoleFilter("listen")
	case "outbound":
		return shared.ParseRoleFilter("outbound")
	// Legacy aliases.
	case "command":
		return shared.ParseRoleFilter("session,beacon")
	case "network":
		return shared.ParseRoleFilter("listen,outbound")
	case "control", "reverse":
		return shared.ParseRoleFilter("session,beacon,tunnel")
	case "listener":
		return shared.ParseRoleFilter("listen")
	default:
		parsed := shared.ParseRoleFilter(s)
		if len(parsed) == 0 {
			return shared.ParseRoleFilter("session,beacon,tunnel")
		}
		return parsed
	}
}
