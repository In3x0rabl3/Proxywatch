package shared

import (
	"sort"
	"strings"
	"time"
)

type LingerEntry struct {
	Candidate Candidate
	FirstSeen time.Time
	LastSeen  time.Time
}

// ApplyCandidateLinger keeps recently seen candidates visible for keepFor.
// This preserves short-lived process visibility in the UI without altering classifier output.
func ApplyCandidateLinger(current []Candidate, now time.Time, keepFor time.Duration, cache *map[string]LingerEntry) []Candidate {
	if keepFor <= 0 || cache == nil {
		sort.Slice(current, func(i, j int) bool { return CandidateLess(current[i], current[j]) })
		return current
	}

	if *cache == nil {
		*cache = make(map[string]LingerEntry, len(current))
	}

	out := make([]Candidate, 0, len(current)+len(*cache))
	seen := make(map[string]struct{}, len(current))

	for _, c := range current {
		key := CandidateKey(c)
		if IsProxywatchProcess(c.Proc) {
			delete(*cache, key)
			continue
		}
		seen[key] = struct{}{}
		firstSeen := now
		if entry, ok := (*cache)[key]; ok && !entry.FirstSeen.IsZero() {
			firstSeen = entry.FirstSeen
			// Merge previous REASONS only (display-only, don't affect scoring).
			// NEVER merge signals — signals must come fresh from the current
			// scoring cycle because they feed back into role decisions.
			c.Reasons = mergeStringSlice(c.Reasons, entry.Candidate.Reasons)
			if len(c.Reasons) > 12 {
				c.Reasons = c.Reasons[:12]
			}
		}
		c.SeenSeconds = max(0, int(now.Sub(firstSeen).Seconds()))
		(*cache)[key] = LingerEntry{
			Candidate: c,
			FirstSeen: firstSeen,
			LastSeen:  now,
		}
		out = append(out, c)
	}

	for key, entry := range *cache {
		if _, ok := seen[key]; ok {
			continue
		}
		if IsProxywatchProcess(entry.Candidate.Proc) {
			delete(*cache, key)
			continue
		}
		if now.Sub(entry.LastSeen) > lingerKeepFor(entry.Candidate, keepFor) {
			delete(*cache, key)
			continue
		}

		stale := entry.Candidate
		stale.SeenSeconds = max(0, int(now.Sub(entry.FirstSeen).Seconds()))
		stale.Exited = true
		if stale.Proc != nil {
			stale.Proc.IOReadBps = 0
			stale.Proc.IOWriteBps = 0
			stale.Proc.IOOtherBps = 0
		}
		// Preserve connection data, role, signals, and ActiveProxying on
		// exited processes. This evidence is needed for:
		// - post-mortem role display (what was it doing when alive)
		// - child tunnel aggregation (correlate children with parent)
		// - training data (short-lived processes are valid samples)
		// Only zero live IO rates — the rest is historical evidence.
		out = append(out, stale)
	}

	sort.Slice(out, func(i, j int) bool { return CandidateLess(out[i], out[j]) })
	return out
}

// mergeStringSlice returns a slice containing all unique entries from both
// current and prev, preserving the order of current first. Transient entries
// are excluded and prefix-based dedup prevents near-duplicate reasons.
func mergeStringSlice(current, prev []string) []string {
	if len(prev) == 0 {
		return current
	}
	// Build prefix set from current reasons for dedup.
	// Reasons like "Single persistent connection to one target (45s)" and "(60s)"
	// share the same prefix before the parenthesized number.
	seen := make(map[string]struct{}, len(current))
	prefixes := make(map[string]struct{}, len(current))
	for _, s := range current {
		seen[s] = struct{}{}
		if p := reasonPrefix(s); p != "" {
			prefixes[p] = struct{}{}
		}
	}
	merged := append([]string(nil), current...)
	for _, s := range prev {
		if _, ok := seen[s]; ok {
			continue
		}
		if isTransientEntry(s) {
			continue
		}
		// Skip if a current reason already covers this prefix.
		if p := reasonPrefix(s); p != "" {
			if _, ok := prefixes[p]; ok {
				continue
			}
			prefixes[p] = struct{}{}
		}
		merged = append(merged, s)
		seen[s] = struct{}{}
	}
	return merged
}

// reasonPrefix extracts the stable prefix of a reason string, stripping
// trailing parenthesized numbers/details that change between cycles.
func reasonPrefix(s string) string {
	// Find last '(' — everything before it is the stable prefix.
	idx := strings.LastIndex(s, " (")
	if idx > 10 {
		return s[:idx]
	}
	// If no parenthesized suffix, use first 40 chars as prefix.
	if len(s) > 40 {
		return s[:40]
	}
	return ""
}

// isTransientEntry returns true for reasons/signals that change each cycle
// and should not persist across linger merges.
func isTransientEntry(s string) bool {
	// Analyzing/warmup countdown reasons.
	if strings.Contains(s, "warming up (") {
		return true
	}
	if strings.HasPrefix(s, "Analyzing:") {
		return true
	}
	if strings.HasPrefix(s, "analyzing") {
		return true
	}
	// Warmup signals.
	if strings.HasPrefix(s, "warmup-") {
		return true
	}
	// Model decision reasons that change per cycle.
	if strings.HasPrefix(s, "model:") {
		return true
	}
	// Transient scoring reasons with changing numbers.
	if strings.Contains(s, "observations)") {
		return true
	}
	if strings.HasPrefix(s, "collecting") {
		return true
	}
	return false
}

// AggregateLingerChildEvidence correlates exited children (from linger cache)
// with live parent processes. When a short-lived child had internal connections
// (e.g., SSH SOCKS proxy fork), transfer tunnel evidence to the parent.
// This catches cases where the child exits before AggregateChildTunnelEvidence
// runs inside Classify.
//
// Holds ClassifyMu for the duration of the write to TunnelingSeen so the
// UI render thread (which RLocks ClassifyMu via CandidateState) can never
// observe a half-written map. Without this, the runtime panics with
// "concurrent map writes" / "concurrent map iteration and map write" at
// random times — exactly the random-timing TUI crash on the Windows binary.
func AggregateLingerChildEvidence(cands []Candidate, now time.Time) {
	// Build parent PID → index map for processes with listeners.
	parentIdx := make(map[int]int)
	for i := range cands {
		c := &cands[i]
		if c.Proc == nil || c.Exited {
			continue
		}
		if len(c.Listeners) > 0 || len(c.UDPListeners) > 0 {
			parentIdx[c.Proc.Pid] = i
		}
	}
	if len(parentIdx) == 0 {
		return
	}

	ClassifyMu.Lock()
	defer ClassifyMu.Unlock()

	// Find exited children that had internal connections.
	for i := range cands {
		c := &cands[i]
		if c.Proc == nil || c.Proc.ParentPid <= 0 {
			continue
		}
		pidx, ok := parentIdx[c.Proc.ParentPid]
		if !ok {
			continue
		}

		childInternal := 0
		for _, conn := range c.Conns {
			if IsInternalIP(conn.RemoteAddress) && conn.RemotePort > 0 {
				childInternal++
			}
		}
		if childInternal == 0 {
			continue
		}

		parent := &cands[pidx]

		// Vendor-IPC bypass — mirror of the gate added to
		// scoring.AggregateChildTunnelEvidence. A signature-trusted system
		// binary in a system install path with no external traffic and
		// no implant-decisive signals is the legitimate Windows IPC
		// profile (services.exe / lsass.exe → workers doing RPC). Don't
		// promote those to pivot just because a lingered exited
		// child briefly forwarded an internal connection — that's
		// normal service worker turnover. A real attack would either
		// generate external traffic or trip an implant-decisive signal.
		if IsTrustedSystemVendorIPCContext(parent) {
			continue
		}

		parent.ActiveProxying = true
		if parent.Role == "listen" || parent.Role == "listener" {
			parent.Role = "pivot"
		}
		TunnelingSeen[parent.Proc.Pid] = now
		parent.OutInternal += childInternal
		parent.OutTotal += childInternal

		hasSignal := false
		for _, sig := range parent.Signals {
			if sig == "child-tunnel-relay" {
				hasSignal = true
				break
			}
		}
		if !hasSignal {
			parent.Signals = AppendUniqueSignal(parent.Signals, "child-tunnel-relay")
			parent.Reasons = AppendUniqueSignal(parent.Reasons, "Exited child processes forwarded internal connections through listener")
		}
	}
}

func lingerKeepFor(c Candidate, base time.Duration) time.Duration {
	keep := base
	if keep <= 0 {
		keep = CandidateLingerTTL
	}
	// Processes with beacon-related signals need longer linger to stay
	// visible between callbacks. Without this, beacons blink in and out.
	for _, sig := range c.Signals {
		if strings.HasPrefix(sig, "beacon") || sig == "session-reconnect-pattern" || sig == "connection-state-syn-sent" {
			if CandidateSuspiciousLingerTTL > keep {
				keep = CandidateSuspiciousLingerTTL
			}
			break
		}
	}
	// Children of tunnel/pivot parents (e.g., sshd SOCKS forks) get extended
	// linger so their connection evidence persists for parent correlation.
	// RLock TunnelingSeen — pcap mode running concurrently with the live
	// scanner writes this map from inside detection.Classify, so an
	// unprotected read here can race the write and panic the runtime.
	if c.Proc != nil && c.Proc.ParentPid > 0 {
		ClassifyMu.RLock()
		_, ok := TunnelingSeen[c.Proc.ParentPid]
		ClassifyMu.RUnlock()
		if ok {
			if CandidateSuspiciousLingerTTL > keep {
				keep = CandidateSuspiciousLingerTTL
			}
		}
	}
	if c.StrongEvidence && CandidateStrongLingerTTL > keep {
		keep = CandidateStrongLingerTTL
	}
	if IsControlRole(c.Role) && CandidateSuspiciousLingerTTL > keep {
		keep = CandidateSuspiciousLingerTTL
	}
	return keep
}
