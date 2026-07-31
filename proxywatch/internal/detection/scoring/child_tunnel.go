package scoring

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"proxywatch/internal/shared"
)

// AggregateChildTunnelEvidence transfers connection evidence from short-lived
// child processes to their parent when the parent has a listener.
// This catches SSH SOCKS proxies where sshd forks children for each forwarded
// connection — the children exit quickly but the parent stays alive.
func AggregateChildTunnelEvidence(candidates []shared.Candidate, now time.Time) {
	// Build parent PID → candidate index map for processes with listeners.
	parentIdx := make(map[int]int) // PID → index in candidates
	for i := range candidates {
		c := &candidates[i]
		if c.Proc == nil {
			continue
		}
		if len(c.Listeners) > 0 || len(c.UDPListeners) > 0 {
			parentIdx[c.Proc.Pid] = i
		}
	}
	if len(parentIdx) == 0 {
		return
	}

	// Find children that made internal connections and transfer evidence to parent.
	for i := range candidates {
		c := &candidates[i]
		if c.Proc == nil || c.Proc.ParentPid <= 0 {
			continue
		}
		pidx, ok := parentIdx[c.Proc.ParentPid]
		if !ok {
			continue
		}

		// Count child's internal connections.
		childInternal := 0
		for _, conn := range c.Conns {
			if shared.IsInternalIP(conn.RemoteAddress) && conn.RemotePort > 0 {
				childInternal++
			}
		}
		if childInternal == 0 {
			continue
		}

		// Transfer: mark parent as actively proxying when children forward
		// internal connections. This catches SSH SOCKS proxies where sshd
		// forks children that exit quickly.
		parent := &candidates[pidx]
		parent.ActiveProxying = true
		// Promote listener → control-pivot when actively relaying.
		// A listener with child-forwarded internal connections is a relay,
		// not a pure service.
		if parent.Role == "listen" || parent.Role == "listener" {
			parent.Role = "control-pivot"
		}

		// Remember that this parent is tunneling — persists across refresh cycles
		// so tunneling shows even after the short-lived child exits.
		shared.TunnelingSeen[parent.Proc.Pid] = now

		// Add child's internal connection count to parent's counters.
		parent.OutInternal += childInternal
		parent.OutTotal += childInternal

		// Add signal to parent if not already present.
		hasSignal := false
		for _, sig := range parent.Signals {
			if sig == "child-tunnel-relay" {
				hasSignal = true
				break
			}
		}
		if !hasSignal {
			parent.Signals = append(parent.Signals, "child-tunnel-relay")
			parent.Reasons = append(parent.Reasons, "Child processes forwarding internal connections through listener")
		}
	}
}

// pivotLingerWindow is how long a process stays pinned to control-pivot after
// observing a pivot moment (pivot-non-loopback-internal + relay context).
const pivotLingerWindow = 60 * time.Second

// ApplyPivotLinger scans candidates for "pivot moments" (internal-only
// forwarding from processes in a relay context), stamps shared.PivotUntil for
// each, and forces role=control-pivot for any candidate whose PivotUntil is
// still in the future. Runs after AggregateChildTunnelEvidence so parent
// candidates already reflect child-forwarded evidence.
//
// A pivot moment requires pivot-non-loopback-internal (OutExternal==0 +
// NonLoopbackInternalCount>0) AND one of:
//   - C1: already in a control role (session/beacon/control-* doing a SOCKS
//     sub-tunnel — refine to control-pivot while the tunnel is active).
//   - C2: process owns a listener that is taking inbound (direct relay).
//   - C3: parent owns a listener that is taking inbound (Windows sshd
//     per-session child pattern — parent owns :22 + has inbound, child does
//     the forwarding with no listener of its own).
//
// pivot-non-loopback-internal already requires OutExternal==0 and excludes
// loopback targets, so benign external-talking processes never qualify.
// Requiring parent.InboundTotal>0 for C3 excludes daemon-chatter cases where
// a service daemon has a listener but no actual inbound connections.
func ApplyPivotLinger(candidates []shared.Candidate, processes map[int]*shared.ProcessInfo, now time.Time) {
	if len(candidates) == 0 {
		return
	}

	parentIdx := make(map[int]int, len(candidates))
	for i := range candidates {
		if candidates[i].Proc != nil {
			parentIdx[candidates[i].Proc.Pid] = i
		}
	}

	// findRelayAncestor walks up the process tree (via processes map) up to
	// maxAncestorDepth levels, looking for an ancestor that is in candidates
	// and matches the relay shape (has a listener + inbound connections).
	// This catches sshd's two-level privsep tree on Windows OpenSSH:
	// sshd_main(3136, listener+inbound) -> sshd_priv(7008, intermediate, often
	// not in candidates) -> sshd_session(9556, child doing the forwarding).
	const maxAncestorDepth = 4
	findRelayAncestor := func(startParentPid int) (parentL, parentIn int, found bool) {
		pid := startParentPid
		for depth := 0; depth < maxAncestorDepth && pid > 0; depth++ {
			if pidx, ok := parentIdx[pid]; ok {
				p := &candidates[pidx]
				lcount := len(p.Listeners) + len(p.UDPListeners)
				if lcount > 0 && p.InboundTotal > 0 {
					return lcount, p.InboundTotal, true
				}
			}
			// Walk up via the global process map even if this PID isn't a
			// candidate (intermediate privsep helpers get filtered out).
			if processes != nil {
				if proc, ok := processes[pid]; ok && proc != nil {
					pid = proc.ParentPid
					continue
				}
			}
			break
		}
		return 0, 0, false
	}

	for i := range candidates {
		c := &candidates[i]
		if c.Proc == nil {
			continue
		}

		hasPivotInternal := false
		for _, sig := range c.Signals {
			if sig == "pivot-non-loopback-internal" {
				hasPivotInternal = true
				break
			}
		}

		if hasPivotInternal {
			c1 := isRelayRole(c.Role)
			c2 := len(c.Listeners) > 0 && c.InboundTotal > 0
			c3 := false
			if !c1 && !c2 && c.Proc.ParentPid > 0 {
				if _, _, ok := findRelayAncestor(c.Proc.ParentPid); ok {
					c3 = true
				}
			}
			if c1 || c2 || c3 {
				shared.PivotUntil[c.Proc.Pid] = now.Add(pivotLingerWindow)
			}
		}

		if expiry, ok := shared.PivotUntil[c.Proc.Pid]; ok {
			if now.Before(expiry) {
				if c.Role != "control-pivot" {
					c.Role = "control-pivot"
					c.Reasons = append(c.Reasons, describePivotEvidence(c, expiry.Sub(now)))
				}
				// ActiveProxying=true lets CandidateState enter the
				// confirmedTunnel block where the STRICT real-time flow
				// gate (ioActive+hasInternalConn OR fresh internal conn)
				// decides whether to return "tunneling" THIS cycle.
				// We intentionally do NOT pre-stamp TunnelingSeen — the
				// role linger (PivotUntil) holds for 60s regardless of
				// current flow, but tunneling state must drop to "watch"
				// the moment data stops flowing. Tool through the tunnel
				// running → new conns fire connActive → tunneling.
				// Tool stopped → no new conns, zero IO → watch.
				c.ActiveProxying = true
			} else {
				delete(shared.PivotUntil, c.Proc.Pid)
			}
		}
	}
}

// describePivotEvidence builds a reason string for a control-pivot promotion
// that spells out exactly what's being relayed — TCP targets (ip:port) and
// named pipes — so operators don't have to cross-reference the connection
// table to see the pivot shape.
func describePivotEvidence(c *shared.Candidate, remaining time.Duration) string {
	var parts []string

	// TCP relay targets: active internal connections (ESTABLISHED to RFC1918
	// non-loopback IPs). Dedupe by ip:port, cap display to 3 with a "+N more"
	// summary so the reason stays readable for fan-out scans.
	tcpTargets := make(map[string]struct{})
	for _, conn := range c.Conns {
		if conn.RemoteAddress == "" || conn.RemotePort == 0 {
			continue
		}
		if shared.IsLoopbackIP(conn.RemoteAddress) || !shared.IsInternalIP(conn.RemoteAddress) {
			continue
		}
		if conn.State != "ESTABLISHED" && conn.State != "" {
			continue
		}
		tcpTargets[fmt.Sprintf("%s:%d", conn.RemoteAddress, conn.RemotePort)] = struct{}{}
	}
	if len(tcpTargets) > 0 {
		list := make([]string, 0, len(tcpTargets))
		for t := range tcpTargets {
			list = append(list, t)
		}
		sort.Strings(list)
		shown := list
		suffix := ""
		if len(list) > 3 {
			shown = list[:3]
			suffix = fmt.Sprintf(" +%d more", len(list)-3)
		}
		parts = append(parts, fmt.Sprintf("TCP relay → %s%s", strings.Join(shown, ", "), suffix))
	}

	// Named pipes: show up to 3, strip the \\.\pipe\ prefix where present so
	// the pipe names themselves are legible.
	if len(c.NamedPipes) > 0 {
		pipes := make([]string, 0, len(c.NamedPipes))
		seen := make(map[string]struct{})
		for _, p := range c.NamedPipes {
			name := p
			name = strings.TrimPrefix(name, `\\.\pipe\`)
			name = strings.TrimPrefix(name, `\Device\NamedPipe\`)
			if name == "" {
				continue
			}
			if _, dup := seen[name]; dup {
				continue
			}
			seen[name] = struct{}{}
			pipes = append(pipes, name)
		}
		if len(pipes) > 0 {
			sort.Strings(pipes)
			shown := pipes
			suffix := ""
			if len(pipes) > 3 {
				shown = pipes[:3]
				suffix = fmt.Sprintf(" +%d more", len(pipes)-3)
			}
			parts = append(parts, fmt.Sprintf("named pipe(s): %s%s", strings.Join(shown, ", "), suffix))
		}
	}

	// SMB pipe pivot signal: if pivot-admin-share-smb fired and TCP targets
	// include :445, call it out explicitly so the operator sees SMB specifically.
	hasSMBSignal := false
	for _, sig := range c.Signals {
		if sig == "pivot-admin-share-smb" {
			hasSMBSignal = true
			break
		}
	}
	if hasSMBSignal {
		parts = append(parts, "SMB admin-share relay (port 445)")
	}

	secsLeft := int(remaining.Seconds())
	if secsLeft < 1 {
		secsLeft = 1
	}
	prefix := fmt.Sprintf("Pivot active (%ds left): internal forwarding in relay context", secsLeft)
	if len(parts) == 0 {
		return prefix
	}
	return prefix + " — " + strings.Join(parts, "; ")
}

// isRelayRole returns true for roles where we should refine to control-pivot
// during active internal-only forwarding. Covers current + legacy role names.
func isRelayRole(role string) bool {
	switch role {
	case "control-channel", "control-pivot",
		"control-session", "control-beacon", "control-tunnel",
		"session", "beacon", "tunnel":
		return true
	}
	return false
}
