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
	case "", "recommended":
		// Calibration "recommended" learns baseline environment traffic, so it
		// must include normal outbound/listener behavior as well.
		return shared.ParseRoleFilter("all")
	case "all":
		return shared.ParseRoleFilter("all")
	case "control":
		return shared.ParseRoleFilter("control")
	case "reverse":
		return shared.ParseRoleFilter("reverse")
	case "listener":
		return shared.ParseRoleFilter("listener")
	case "outbound":
		return shared.ParseRoleFilter("outbound")
	default:
		parsed := shared.ParseRoleFilter(s)
		if len(parsed) == 0 {
			return shared.ParseRoleFilter("session,beacon,tunnel")
		}
		return parsed
	}
}
