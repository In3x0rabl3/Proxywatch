package scoring

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"proxywatch/internal/shared"
)

// AggregateChildTunnelEvidence transfers connection evidence from short-lived
// child processes to their parent when the parent has a listener.
// This catches SSH SOCKS proxies where sshd forks children for each forwarded
// connection — the children exit quickly but the parent stays alive.
//
// The lookup walks up the parent chain (via the processes map) up to
// maxAggregateAncestorDepth levels — same shape as ApplyPivotLinger's
// findRelayAncestor — so the Windows OpenSSH privsep tree is handled:
// sshd_main(listener) -> sshd_priv (intermediate, often not a candidate) ->
// sshd_session (the child doing the SOCKS forwarding). Without the walk,
// the immediate parent (privsep) is missing from parentIdx and the
// listener→pivot promotion is delayed until ApplyPivotLinger
// catches it via its own walk on the next cycle, producing a 1-cycle lag
// where an active SOCKS tunnel still shows as outbound/watch.
func AggregateChildTunnelEvidence(candidates []shared.Candidate, processes map[int]*shared.ProcessInfo, now time.Time) {
	if now.IsZero() {
		now = shared.PcapNow()
	}
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

	const maxAggregateAncestorDepth = 4
	findListenerAncestor := func(startParentPid int) (int, bool) {
		pid := startParentPid
		for depth := 0; depth < maxAggregateAncestorDepth && pid > 0; depth++ {
			if pidx, ok := parentIdx[pid]; ok {
				return pidx, true
			}
			if processes == nil {
				break
			}
			proc, ok := processes[pid]
			if !ok || proc == nil {
				break
			}
			pid = proc.ParentPid
		}
		return 0, false
	}

	// Find children that made internal connections and transfer evidence to parent.
	for i := range candidates {
		c := &candidates[i]
		if c.Proc == nil || c.Proc.ParentPid <= 0 {
			continue
		}
		pidx, ok := findListenerAncestor(c.Proc.ParentPid)
		if !ok {
			continue
		}

		// Count child's internal connections, also tracking distinct
		// remote IPs — used by the pcap-mode FP guard further down.
		childInternal := 0
		childDistinctIPs := make(map[string]struct{})
		for _, conn := range c.Conns {
			if shared.IsInternalIP(conn.RemoteAddress) && conn.RemotePort > 0 {
				childInternal++
				childDistinctIPs[conn.RemoteAddress] = struct{}{}
			}
		}
		if childInternal == 0 {
			continue
		}
		// Pcap-mode tightening: synthetic-PID parent linkage (pcap
		// ingest's listenerOnIP map) wires every same-IP outbound flow
		// as a "child" of the IP's listener. On Windows hosts running
		// sshd, ANY same-host process making internal connections
		// (chrome.exe doing Chromecast 8009 + printer :80 probes,
		// svchost.exe doing AD lookups, etc.) gets falsely attributed
		// to sshd as "children" — lighting up child-tunnel-relay on
		// every Windows host with sshd installed. Operator confirmation
		// 2026-05-03 (LIVE-vs-PCAP comparison): LIVE classifies sshd
		// as `listener` (just a service, no pivot), but PCAP shows
		// `pivot TUNNEL=yes` because Chrome's LAN probes are
		// linked as sshd's "children".
		//
		// Pcap-mode gate (STRICT): require listener-inbound-external on
		// the parent listener. This is the only DYNAMIC, data-driven
		// discriminator that cleanly distinguishes a real reverse-tunnel
		// (sshd -z, attacker connects from outside the LAN) from admin
		// SSH (internal inbound only).
		//
		// Why no byte/IP-count escape: byte thresholds are tunable
		// targets that browsers / vendor downloads / chatty internal
		// services routinely cross. The "≥3 distinct internal IPs"
		// rule fires on Chrome's Chromecast + printer probes. Both
		// approaches require constant tuning per fixture and produce
		// FPs on every Windows host running sshd. listener-inbound-
		// external is BINARY: either the inbound came from outside
		// the LAN (real attacker) or it didn't (admin / IT).
		//
		// Trade-off: an attacker who pivots from one INTERNAL box
		// to another via internal SSH SOCKS won't trip this. That
		// case is detectable via OTHER paths — pivot-socks-candidate
		// (SOCKS handshake bytes), or the outbound-side cluster
		// itself if it shows beacon shape. The structural FP
		// (admin SSH on every Windows host with sshd installed) is
		// far more common and PCAP-mode-specific.
		//
		// Operator confirmed 2026-05-03: LIVE classifies sshd as
		// `listener` (no pivot). PCAP must match.
		if shared.IsPcapMode(c) {
			parentListenerHasExternalInbound := false
			if pidx, ok := parentIdx[c.Proc.ParentPid]; ok {
				p := &candidates[pidx]
				for _, s := range p.Signals {
					if s == "listener-inbound-external" {
						parentListenerHasExternalInbound = true
						break
					}
				}
			}
			if !parentListenerHasExternalInbound {
				continue
			}
		}

		// Transfer: mark parent as actively proxying when children forward
		// internal connections. This catches SSH SOCKS proxies where sshd
		// forks children that exit quickly.
		parent := &candidates[pidx]

		// Vendor-IPC bypass: a signature-trusted system binary in a system
		// install path with no external traffic and no implant-decisive
		// signals is the legitimate Windows IPC profile (services.exe →
		// svchost workers doing RPC, lsass.exe → SAM/LSA, etc.). Promoting
		// these to pivot every cycle their children make internal
		// connections is the recurring 2026-04-28 services.exe FP. Skip
		// the entire evidence transfer — no signal, no role change, no
		// TunnelingSeen stamp. A real attack on services.exe would either
		// generate external traffic (failing the OutExternal==0 gate) or
		// trip an implant-decisive signal (failing the signal gate).
		if shared.IsTrustedSystemVendorIPCContext(parent) {
			continue
		}

		// Cross-platform helper-mesh bypass: catches the SAME structural
		// pattern on Linux/macOS where SignatureTrust isn't reliably
		// populated. Desktop apps (chrome, code, electron, slack, zoom)
		// and many system daemons (geoclue, claude/copilot CLI, telegram)
		// run a parent + utility/renderer/extension subprocesses, where
		// children connect to the parent's own loopback listener for IPC.
		// That topology matches "parent listener → child internal conn"
		// exactly even though no relay is happening.
		//
		// Structural test (no name lists):
		//   - parent has at least one listener AND every listener binds
		//     loopback only (no 0.0.0.0 / private interface / public IP)
		//   - parent itself makes zero external connections
		//   - child's internal connections are to loopback only
		//   - no implant-decisive signal on the parent
		//
		// All four conditions match helper-mesh IPC and never match a
		// real relay (real relay needs a non-loopback listener for
		// peers to connect, OR external traffic on the parent).
		if isHelperMeshIPCContext(parent, c) {
			continue
		}

		parent.ActiveProxying = true
		// Promote listener → pivot when actively relaying.
		// A listener with child-forwarded internal connections is a relay,
		// not a pure service. This includes SSH servers when they're being
		// used to tunnel traffic — that's exactly the pivot scenario we detect.
		if parent.Role == "listen" || parent.Role == "listener" {
			parent.Role = "pivot"
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
			parent.Signals = shared.AppendUniqueSignal(parent.Signals, "child-tunnel-relay")
			parent.Reasons = shared.AppendUniqueSignal(parent.Reasons, "Child processes forwarding internal connections through listener")
		}
	}
}

// pivotLingerWindow is how long a process stays pinned to pivot after
// observing a pivot moment (pivot-non-loopback-internal + relay context).
const pivotLingerWindow = 60 * time.Second

// ApplyPivotLinger scans candidates for "pivot moments" (internal-only
// forwarding from processes in a relay context), stamps shared.PivotUntil for
// each, and forces role=pivot for any candidate whose PivotUntil is
// still in the future. Runs after AggregateChildTunnelEvidence so parent
// candidates already reflect child-forwarded evidence.
//
// A pivot moment requires pivot-non-loopback-internal (OutExternal==0 +
// NonLoopbackInternalCount>0) AND one of:
//   - C1: already in a control role (session/beacon/beacon-* doing a SOCKS
//     sub-tunnel — refine to pivot while the tunnel is active).
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
	if now.IsZero() {
		now = shared.PcapNow()
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
				// Pcap-mode gate: pivot-non-loopback-internal is a packet-
				// observable signal, but on its own it routinely fires for
				// admin / IT-management traffic that hits internal CIDRs
				// without external counterparts. The 60s linger then
				// pins pivot across many ticks. Require a
				// packet-decisive signal (SYN cycle, SOCKS, listener+
				// egress, tunnel shape, etc) before stamping the linger.
				// Live mode is unaffected — process metadata feeds the
				// suppression signals that already filter benign IT.
				if shared.IsPcapMode(c) && !shared.HasPacketDecisiveSignal(c) {
					// don't stamp linger; current-tick role guard still applies
				} else if shared.IsPcapMode(c) && pcapClientLikeAdminSSH(c) {
					// Admin-SSH-client / RDP-client guard. In pcap mode an
					// outbound-only cluster from host A to a single internal
					// target on a single admin port (22 / 3389 / 5985 / 23
					// etc.) is structurally indistinguishable from
					// SOCKS-tunneled SSH on the CLIENT SIDE — the multiplexed
					// SOCKS traffic is encrypted inside the SSH channel.
					// SOCKS-tunnel detection lives on the SERVER side: the
					// listener at .81:22 picks up child-tunnel-relay only
					// when the server's sshd actually spawns concurrent
					// outbound to multiple internal targets. Letting the
					// client-side cluster promote here just because
					// beacon-syn-cycle-cadence fires (SSH session reconnects)
					// produces FPs on every admin SSH session — operator
					// confirmation 2026-05-03: 172.16.1.139→.81:22 with
					// 15.9 MB and beacon-syn-cycle-cadence at 100%
					// precision was admin SSH, not a SOCKS tunnel.
					// don't stamp linger
				} else {
					shared.PivotUntil[c.Proc.Pid] = now.Add(pivotLingerWindow)
				}
			}
		}

		if expiry, ok := shared.PivotUntil[c.Proc.Pid]; ok {
			if now.Before(expiry) {
				// Promote to pivot if evidence exists in linger window.
				// NOTE: SSH servers CAN be promoted here — an sshd child session
				// that is actively tunneling traffic SHOULD be flagged as pivot.
				// The parent listener protection is in the aggregation loop above.
				if c.Role != "pivot" {
					c.Role = "pivot"
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

// describePivotEvidence builds a reason string for a pivot promotion
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

// isRelayRole returns true for roles where we should refine to pivot
// during active internal-only forwarding. Covers current + legacy role names.
func isRelayRole(role string) bool {
	switch role {
	case "beacon", "pivot", "tunnel":
		return true
	}
	return false
}

// isHelperMeshIPCContext returns true when the parent + child topology
// matches the legitimate desktop-app / system-daemon helper-mesh
// pattern (parent runs an IPC listener on loopback, children connect
// to that loopback to talk to the parent). Cross-platform structural
// check — no name lists, no signature-trust requirement (Linux
// binaries often lack the rich attestation Windows binaries carry).
//
// Returns true ONLY when ALL four conditions match:
//
//  1. Parent owns at least one listener AND every listener binds a
//     loopback address (127.0.0.0/8 / ::1) — no 0.0.0.0, no internal
//     interface, no public IP. A real relay needs a non-loopback
//     listener for peers to reach.
//
//  2. Parent itself makes zero external connections (OutExternal==0).
//     A real C2 / pivot has a callback channel of its own.
//
//  3. The child's internal connections are all to loopback addresses.
//     Helper-mesh children talk to 127.0.0.1; a real relay child
//     forwards to RFC1918 hosts on the LAN.
//
//  4. Parent carries no implant-decisive signal (raw-socket,
//     named-pipe-c2-pattern, beacon-syn-cycle-cadence,
//     ssh-tunnel-flags, injection-rwx-external,
//     pivot-anon-exec-memory). These survive any structural disguise
//     and lock the candidate's role.
//
// Real chrome/code/electron/geoclue/telegram/pia all match. Real
// pivots / SOCKS relays / SSH tunnels never match because they
// either bind a non-loopback listener (so their LAN peers can
// reach them) or have external traffic of their own.
func isHelperMeshIPCContext(parent *shared.Candidate, child *shared.Candidate) bool {
	if parent == nil || parent.Proc == nil {
		return false
	}
	// (1) Parent listeners must all be loopback-bound.
	hasListener := false
	for _, l := range parent.Listeners {
		hasListener = true
		if !shared.IsLoopbackIP(l.LocalAddress) {
			return false
		}
	}
	for _, l := range parent.UDPListeners {
		hasListener = true
		// UDP multicast (e.g. mDNS 224.0.0.251) is not loopback but is
		// also not a remote-relay binding — accept loopback OR multicast
		// (224.0.0.0/4) here to keep mDNS from disqualifying the bypass.
		if !shared.IsLoopbackIP(l.LocalAddress) && !isMulticastIP(l.LocalAddress) {
			return false
		}
	}
	if !hasListener {
		return false
	}
	// (2) Parent has no external connections.
	if parent.OutExternal > 0 {
		return false
	}
	// (3) Child's internal connections are all to loopback.
	if child != nil {
		for _, conn := range child.Conns {
			if !shared.IsInternalIP(conn.RemoteAddress) {
				continue
			}
			if !shared.IsLoopbackIP(conn.RemoteAddress) {
				return false
			}
		}
	}
	// (4) No implant-decisive signal on the parent.
	for _, s := range parent.Signals {
		if helperMeshBlockerSignals[s] {
			return false
		}
	}
	return true
}

// helperMeshBlockerSignals are signals that indicate real C2 / pivot
// activity and must NOT be bypassed by the helper-mesh skip. Subset of
// rescueImplantDecisiveSignals in shared/vendor_fp_shape.go — excludes
// child-tunnel-relay (would block legitimate helper-mesh IPC) and
// beacon-static-crypto-likely (too noisy for this bypass gate).
var helperMeshBlockerSignals = map[string]bool{
	"pivot-ssh-tunnel-flags":      true,
	"pivot-named-pipe-c2-pattern": true,
	"beacon-syn-cycle-cadence":    true,
	"raw-socket":                  true,
	"injection-rwx-external":      true,
	"pivot-anon-exec-memory":      true,
}

// isMulticastIP returns true for IPv4 224.0.0.0/4 (multicast).
// Used to allow mDNS/SSDP listeners on browsers without
// disqualifying the helper-mesh bypass.
func isMulticastIP(ip string) bool {
	if len(ip) < 4 {
		return false
	}
	dot := strings.IndexByte(ip, '.')
	if dot <= 0 {
		return false
	}
	first := ip[:dot]
	switch first {
	case "224", "225", "226", "227", "228", "229",
		"230", "231", "232", "233", "234", "235",
		"236", "237", "238", "239":
		return true
	}
	return false
}

// pcapAdminClientPorts lists destination ports where a client cluster
// connecting to a single internal target is structurally
// indistinguishable from SOCKS-tunneled SSH on the client side. The
// SOCKS-tunnel signature lives on the SERVER side (the listener at the
// target host picks up child-tunnel-relay only when its sshd actually
// spawns concurrent outbound to multiple internal targets) — so the
// client-side cluster should never auto-promote on these ports.
var pcapAdminClientPorts = map[int]bool{
	22:   true, // SSH
	23:   true, // Telnet
	3389: true, // RDP
	5985: true, // WinRM HTTP
	5986: true, // WinRM HTTPS
	135:  true, // RPC
	139:  true, // NetBIOS Session
	445:  true, // SMB
}

// pcapBenignLANDiscoveryPorts lists destination ports used by browsers,
// OSes, and shared peripherals for LAN service discovery. Clusters
// targeting one of these ports with low byte volume are Chrome /
// Edge / OS service discovery — pcap synthesizes a fake parent-child
// linkage (any same-host listener becomes the parent of any same-host
// outbound), which makes the C3 walk fire `child-tunnel-relay` →
// PivotUntil → pivot on harmless LAN probes.
//
// Memory note (feedback_chrome_lan_discovery_fp.md, 2026-05-02):
// pcap:172.16.1.81 → 172.16.0.0/16:8009 was Chromecast discovery, not
// cheerful's tunnel — the rule that promoted it produced 100% FPs.
var pcapBenignLANDiscoveryPorts = map[int]bool{
	80:   true, // HTTP printer / web admin
	631:  true, // IPP printer
	5353: true, // mDNS
	1900: true, // SSDP / UPnP
	8008: true, // Chromecast (HTTP)
	8009: true, // Chromecast (TLS)
	9100: true, // JetDirect printer
	137:  true, // NetBIOS Name
	138:  true, // NetBIOS Datagram
	3702: true, // WS-Discovery
	5355: true, // LLMNR
}

// pcapClientLikeAdminSSH reports whether the candidate looks like a
// benign internal admin client (SSH/RDP/WinRM/SMB) connecting to a
// single internal server.
//
// Conditions (all must hold):
//   - cluster name has the pcap synthetic prefix
//   - no listeners on the candidate (rules out the server side)
//   - OutExternal == 0 (no external destinations)
//   - cluster name is a per-/16 destination form (rules out rollups)
//   - destination port is in pcapAdminClientPorts
//   - candidate carries NO real relay-evidence signals
//     (child-tunnel-relay / pivot-socks-candidate / forward-tunnel-shape /
//     listener-egress-tunnel-shape / host-c2-active-pivot etc.) — those
//     override the heuristic because they're hard packet evidence.
//
// Operator confirmation 2026-05-03: 172.16.1.139→.81:22 with 15.9 MB
// and beacon-syn-cycle-cadence at 100% precision was admin SSH.
// SOCKS-tunneled SSH is detectable only on the SERVER side (.81's sshd
// firing child-tunnel-relay when it spawns concurrent outbound).
func pcapClientLikeAdminSSH(c *shared.Candidate) bool {
	if c == nil || c.Proc == nil {
		return false
	}
	name := c.Proc.Name
	if !strings.HasPrefix(name, "pcap:") {
		return false
	}
	if len(c.Listeners) > 0 || len(c.UDPListeners) > 0 {
		return false
	}
	if c.OutExternal > 0 {
		return false
	}
	for _, s := range c.Signals {
		switch s {
		case "child-tunnel-relay",
			"pivot-socks-candidate",
			"listener-egress-tunnel-shape",
			"listener-inbound-external",
			"forward-tunnel-shape",
			"reverse-beacon-shape",
			"pivot-listener-plus-outbound",
			"pivot-loopback-listener-external-out",
			"host-c2-active-pivot",
			"pivot-ssh-tunnel-flags",
			"pivot-named-pipe-c2-pattern":
			return false
		}
	}
	if strings.Contains(name, " outbound-") {
		return false // host-level rollup, not single-target
	}
	arrowIdx := strings.Index(name, "→")
	if arrowIdx < 0 {
		return false // not a per-/16 destination cluster
	}
	rest := strings.TrimSpace(name[arrowIdx+len("→"):])
	colonIdx := strings.LastIndex(rest, ":")
	if colonIdx < 0 {
		return false
	}
	port, err := strconv.Atoi(rest[colonIdx+1:])
	if err != nil {
		return false
	}
	if pcapAdminClientPorts[port] {
		return true
	}
	// Chrome/Edge/OS LAN service-discovery ports — same suppression
	// rationale, plus a byte-volume guard. Real C2 SOCKS-relayed scans
	// move ≥10 KiB through the cluster within seconds; LAN-discovery
	// probes are single-byte handshakes that barely accumulate to
	// 1 KiB even over an entire session.
	if pcapBenignLANDiscoveryPorts[port] {
		var bytes uint64
		if c.Proc != nil {
			bytes = c.Proc.IOReadBytes + c.Proc.IOWriteBytes
		}
		const benignByteCap uint64 = 10 * 1024
		if bytes < benignByteCap {
			return true
		}
	}
	return false
}
