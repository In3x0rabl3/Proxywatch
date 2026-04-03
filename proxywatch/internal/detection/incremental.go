package classifier

import (
	"time"

	"proxywatch/internal/shared"
)

const (
	fnvOffset64 uint64 = 1469598103934665603
	fnvPrime64  uint64 = 1099511628211
)

func candidateSignature(c shared.Candidate) shared.CandidateSignature {
	var listenerHash uint64
	for _, l := range c.Listeners {
		h := fnvOffset64
		h = fnvAddString(h, l.LocalAddress)
		h = fnvAddUint64(h, nonNegativeIntToUint64(l.LocalPort))
		h = fnvAddString(h, l.State)
		listenerHash ^= h
	}
	for _, u := range c.UDPListeners {
		h := fnvOffset64
		h = fnvAddString(h, u.LocalAddress)
		h = fnvAddUint64(h, nonNegativeIntToUint64(u.LocalPort))
		listenerHash ^= h
	}

	var connHash uint64
	for _, cn := range c.Conns {
		h := fnvOffset64
		h = fnvAddString(h, cn.LocalAddress)
		h = fnvAddUint64(h, nonNegativeIntToUint64(cn.LocalPort))
		h = fnvAddString(h, cn.RemoteAddress)
		h = fnvAddUint64(h, nonNegativeIntToUint64(cn.RemotePort))
		h = fnvAddString(h, cn.State)
		connHash ^= h
	}

	procHash := fnvOffset64
	if c.Proc != nil {
		procHash = fnvAddString(procHash, c.Proc.Name)
		procHash = fnvAddString(procHash, c.Proc.ExePath)
		procHash = fnvAddString(procHash, c.Proc.UserName)
		procHash = fnvAddUint64(procHash, nonNegativeIntToUint64(c.Proc.ParentPid))
	}

	return shared.CandidateSignature{
		ListenerHash: listenerHash,
		ConnHash:     connHash,
		ProcHash:     procHash,
	}
}

func reuseCandidate(dst, src *shared.Candidate) {
	dst.Score = src.Score
	dst.Confidence = src.Confidence
	dst.Reasons = append(dst.Reasons[:0], src.Reasons...)
	dst.Signals = append(dst.Signals[:0], src.Signals...)
	dst.Role = src.Role
	dst.ActiveProxying = src.ActiveProxying
	dst.UDPListeners = append(dst.UDPListeners[:0], src.UDPListeners...)
	dst.OutTotal = src.OutTotal
	dst.OutExternal = src.OutExternal
	dst.OutInternal = src.OutInternal
	dst.OutLoopback = src.OutLoopback
	dst.OutLongLived = src.OutLongLived
	dst.OutShortLived = src.OutShortLived
	dst.InboundTotal = src.InboundTotal
	dst.TrafficVerified = src.TrafficVerified
	dst.StrongEvidence = src.StrongEvidence
	dst.ControlDurationSeconds = src.ControlDurationSeconds
	if src.ControlChannel != nil {
		tmp := *src.ControlChannel
		dst.ControlChannel = &tmp
	} else {
		dst.ControlChannel = nil
	}
}

func touchHistoryFromCandidate(c *shared.Candidate, now time.Time) {
	if c == nil || c.Proc == nil {
		return
	}
	scopedPID := historyPIDForCandidate(c)
	hist := getHistory(scopedPID, now)

	if c.InboundTotal > 0 {
		shared.RecentClientSeen[scopedPID] = now
	}
	if c.OutTotal > 0 {
		shared.RecentOutboundSeen[scopedPID] = now
	}

	if c.ActiveProxying {
		hist.LastActive = now
	}

	// Only set SuspicionProxy when the process is actively proxying traffic.
	// Setting it for all tunnel/pivot roles causes the suspicion memory to
	// cascade re-promote processes to tunnel on every refresh, even when
	// current evidence points to a session.
	if c.ActiveProxying {
		hist.LastSuspicious = now
		hist.SuspicionKind = shared.SuspicionProxy
	} else if shared.IsControlRole(c.Role) {
		hist.LastSuspicious = now
		hist.SuspicionKind = shared.SuspicionControl
	}

	if hist.StickyScore < c.Score {
		hist.StickyScore = c.Score
	}
}

func shouldRescoreUnchangedCandidate(c *shared.Candidate, prev *shared.Candidate, now time.Time) bool {
	if c == nil || c.Proc == nil || prev == nil {
		return false
	}
	if !hasEstablishedEgress(c.Conns) {
		return false
	}
	switch prev.Role {
	case "outbound", "control-session", "control-beacon", "control-channel", "control-tunnel", "control-pivot", "listen":
		// Time-based signals (e.g., persistent control duration, burst cadence)
		// must still evolve even when socket tuple signatures are unchanged.
	default:
		return false
	}
	hist := getHistory(historyPIDForCandidate(c), now)
	if hist.LastScoreEval.IsZero() {
		return true
	}
	return now.Sub(hist.LastScoreEval) >= time.Second
}

func hasEstablishedEgress(conns []shared.ConnectionInfo) bool {
	for _, cn := range conns {
		if !isEstablishedState(cn.State) {
			continue
		}
		if cn.RemoteAddress == "" ||
			shared.IsWildcardIP(cn.RemoteAddress) ||
			shared.IsLoopbackIP(cn.RemoteAddress) {
			continue
		}
		return true
	}
	return false
}

func fnvAddString(h uint64, s string) uint64 {
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= fnvPrime64
	}
	return h
}

func fnvAddUint64(h uint64, v uint64) uint64 {
	for i := 0; i < 8; i++ {
		h ^= v & 0xff
		h *= fnvPrime64
		v >>= 8
	}
	return h
}

func nonNegativeIntToUint64(v int) uint64 {
	if v < 0 {
		return 0
	}
	return uint64(v)
}
