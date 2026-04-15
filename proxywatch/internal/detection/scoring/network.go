package scoring

import (
	"fmt"
	"proxywatch/internal/shared"
	"time"
)

func HasSMBListenerPort(ports map[int]struct{}) bool {
	if len(ports) == 0 {
		return false
	}
	if _, ok := ports[445]; ok {
		return true
	}
	if _, ok := ports[139]; ok {
		return true
	}
	return false
}

func SocksListenerPorts(listeners []shared.ListenerInfo) (map[int]struct{}, bool, bool) {
	ports := make(map[int]struct{})
	loopbackOnly := true
	anyWildcard := false

	for _, l := range listeners {
		ports[l.LocalPort] = struct{}{}
		if shared.IsWildcardIP(l.LocalAddress) {
			anyWildcard = true
			loopbackOnly = false
		} else if !shared.IsLoopbackIP(l.LocalAddress) {
			loopbackOnly = false
		}
	}
	return ports, loopbackOnly, anyWildcard
}

func CountActiveClientSessions(
	conns []shared.ConnectionInfo,
	ports map[int]struct{},
) (int, map[string]int) {

	ips := make(map[string]int)
	count := 0

	for _, c := range conns {
		if !IsActiveConnState(c.State) {
			continue
		}
		if _, ok := ports[c.LocalPort]; !ok {
			continue
		}
		if c.RemoteAddress == "" || shared.IsWildcardIP(c.RemoteAddress) {
			continue
		}
		count++
		ips[c.RemoteAddress]++
	}
	return count, ips
}

func OutboundTargets(
	conns []shared.ConnectionInfo,
	ports map[int]struct{},
) (total, external, internal, loopback int) {

	for _, c := range conns {
		if !IsActiveConnState(c.State) {
			continue
		}
		if c.RemoteAddress == "" ||
			shared.IsWildcardIP(c.RemoteAddress) {
			continue
		}
		if shared.IsLoopbackIP(c.RemoteAddress) {
			loopback++
			continue
		}
		if _, ok := ports[c.LocalPort]; ok {
			continue
		}

		total++
		if shared.IsInternalIP(c.RemoteAddress) {
			internal++
		} else {
			external++
		}
	}
	return
}

func OutboundActivity(
	conns []shared.ConnectionInfo,
	ports map[int]struct{},
) (total int, distinctTargets map[string]struct{}, distinctPorts map[int]struct{}, targetPrefixes map[string]struct{}) {
	distinctTargets = make(map[string]struct{})
	distinctPorts = make(map[int]struct{})
	targetPrefixes = make(map[string]struct{})

	for _, c := range conns {
		if !IsActiveConnState(c.State) {
			continue
		}
		if c.RemoteAddress == "" ||
			shared.IsWildcardIP(c.RemoteAddress) ||
			shared.IsLoopbackIP(c.RemoteAddress) {
			continue
		}
		if _, ok := ports[c.LocalPort]; ok {
			continue
		}

		total++
		key := fmt.Sprintf("%s:%d", c.RemoteAddress, c.RemotePort)
		distinctTargets[key] = struct{}{}
		if c.RemotePort > 0 {
			distinctPorts[c.RemotePort] = struct{}{}
		}
		if prefix := shared.TargetPrefix(c.RemoteAddress); prefix != "" {
			targetPrefixes[prefix] = struct{}{}
		}
	}
	return
}

func OutboundConnAgeStats(
	conns []shared.ConnectionInfo,
	ports map[int]struct{},
	now time.Time,
) (longLived int, shortLived int) {
	for _, c := range conns {
		if !IsEstablishedState(c.State) {
			continue
		}
		if c.RemoteAddress == "" ||
			shared.IsWildcardIP(c.RemoteAddress) ||
			shared.IsLoopbackIP(c.RemoteAddress) {
			continue
		}
		if _, ok := ports[c.LocalPort]; ok {
			continue
		}

		key := ConnKeyFromConn(c.Pid, c)
		first, ok := shared.ConnFirstSeen[key]
		if !ok {
			continue
		}
		age := now.Sub(first)
		if age >= shared.LongLivedOutboundMinAge {
			longLived++
		}
		if age <= shared.ShortLivedOutboundMaxAge {
			shortLived++
		}
	}
	return
}

func OutboundConnsForVerification(
	conns []shared.ConnectionInfo,
	ports map[int]struct{},
) []shared.ConnectionInfo {
	out := make([]shared.ConnectionInfo, 0, len(conns))
	for _, c := range conns {
		if !IsActiveConnState(c.State) {
			continue
		}
		if c.RemoteAddress == "" ||
			shared.IsWildcardIP(c.RemoteAddress) ||
			shared.IsLoopbackIP(c.RemoteAddress) {
			continue
		}
		if _, ok := ports[c.LocalPort]; ok {
			continue
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func OutboundExternalPrefixes(conns []shared.ConnectionInfo) map[string]struct{} {
	prefixes := make(map[string]struct{})
	for _, c := range conns {
		if shared.IsInternalIP(c.RemoteAddress) || shared.IsLoopbackIP(c.RemoteAddress) {
			continue
		}
		if prefix := shared.TargetPrefix(c.RemoteAddress); prefix != "" {
			prefixes[prefix] = struct{}{}
		}
	}
	return prefixes
}

func TrafficVerifiedByDest(
	conns []shared.ConnectionInfo,
	outExternal int,
	internalLateral bool,
	behavior *shared.ProcessBehavior,
	externalPrefixes map[string]struct{},
) bool {
	if len(conns) == 0 {
		return false
	}
	if outExternal == 0 && !internalLateral {
		return true
	}
	if behavior == nil || behavior.Observations < 6 {
		return false
	}
	if len(externalPrefixes) == 0 {
		return false
	}

	known := 0
	for prefix := range externalPrefixes {
		if behavior.KnownPrefixes[prefix] > 0 {
			known++
		}
	}
	knownRatio := float64(known) / float64(len(externalPrefixes))
	if knownRatio < 0.65 {
		return false
	}

	allowedExternal := behavior.AvgOutExternal*2.5 + 2
	if float64(outExternal) > allowedExternal {
		return false
	}

	if behavior.Observations > 0 {
		suspiciousRatio := float64(behavior.SuspiciousObservations) / float64(behavior.Observations)
		if suspiciousRatio > 0.35 {
			return false
		}
	}
	return true
}

func OutboundInternalSummary(
	conns []shared.ConnectionInfo,
	ports map[int]struct{},
) (internalTargets map[string]struct{}, internalPorts map[int]struct{}, internalLateral bool) {
	internalTargets = make(map[string]struct{})
	internalPorts = make(map[int]struct{})

	for _, c := range conns {
		if !IsActiveConnState(c.State) {
			continue
		}
		if c.RemoteAddress == "" ||
			shared.IsWildcardIP(c.RemoteAddress) ||
			shared.IsLoopbackIP(c.RemoteAddress) {
			continue
		}
		if _, ok := ports[c.LocalPort]; ok {
			continue
		}
		if !shared.IsInternalIP(c.RemoteAddress) {
			continue
		}

		internalTargets[c.RemoteAddress] = struct{}{}
		if c.RemotePort > 0 {
			internalPorts[c.RemotePort] = struct{}{}
		}
	}
	internalLateral = len(internalTargets) >= 3 || (len(internalTargets) >= 2 && len(internalPorts) >= 2)
	return
}

func SmbPipeActivity(
	conns []shared.ConnectionInfo,
	ports map[int]struct{},
	now time.Time,
) (connCount int, targetCount int, longLived int, external bool, maxAgeSecs int) {
	targets := make(map[string]struct{})

	for _, c := range conns {
		if !IsActiveConnState(c.State) {
			continue
		}
		if c.RemotePort != 445 && c.RemotePort != 139 {
			continue
		}
		if c.RemoteAddress == "" ||
			shared.IsWildcardIP(c.RemoteAddress) ||
			shared.IsLoopbackIP(c.RemoteAddress) {
			continue
		}
		if _, ok := ports[c.LocalPort]; ok {
			continue
		}

		connCount++
		targets[c.RemoteAddress] = struct{}{}
		if !shared.IsInternalIP(c.RemoteAddress) {
			external = true
		}

		key := ConnKeyFromConn(c.Pid, c)
		first, ok := shared.ConnFirstSeen[key]
		if !ok {
			continue
		}
		age := now.Sub(first)
		if age >= shared.ReverseControlMinDuration {
			longLived++
		}
		ageSecs := int(age.Seconds())
		if ageSecs > maxAgeSecs {
			maxAgeSecs = ageSecs
		}
	}

	targetCount = len(targets)
	return
}

func OutboundTargetsExcluding(
	conns []shared.ConnectionInfo,
	ports map[int]struct{},
	exclude *shared.ConnKey,
) (total, external, internal int) {

	for _, c := range conns {
		if !IsActiveConnState(c.State) {
			continue
		}
		if exclude != nil && *exclude == ConnKeyFromConn(c.Pid, c) {
			continue
		}
		if c.RemoteAddress == "" ||
			shared.IsWildcardIP(c.RemoteAddress) ||
			shared.IsLoopbackIP(c.RemoteAddress) {
			continue
		}
		if _, ok := ports[c.LocalPort]; ok {
			continue
		}

		total++
		if shared.IsInternalIP(c.RemoteAddress) {
			internal++
		} else {
			external++
		}
	}
	return
}

func LocalTransportActivity(conns []shared.ConnectionInfo) (bool, int, int) {
	count := 0
	remotePorts := make(map[int]struct{})
	for _, c := range conns {
		if !IsActiveConnState(c.State) {
			continue
		}
		if shared.IsLoopbackIP(c.LocalAddress) &&
			shared.IsLoopbackIP(c.RemoteAddress) &&
			c.LocalPort != c.RemotePort {
			count++
			if c.RemotePort > 0 {
				remotePorts[c.RemotePort] = struct{}{}
			}
		}
	}
	return count > 0, count, len(remotePorts)
}

func InternalFanoutBoost(targets map[string]struct{}, ports map[int]struct{}) int {
	score := 0
	if len(targets) >= 3 {
		score += 15
	}
	if len(ports) >= 2 {
		score += 10
	}
	if len(targets) >= 2 && len(ports) >= 3 {
		score += 10
	}
	return score
}
