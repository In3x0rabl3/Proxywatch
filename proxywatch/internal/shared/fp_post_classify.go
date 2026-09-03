package shared

import "strings"

// IsCaptureTool returns true for packet-capture / network-introspection
// processes that operate via raw sockets / AF_PACKET only and have no
// regular TCP/UDP PCB sockets. Their candidates carry the `raw-socket`
// signal which would normally block FP demotion in vendor_fp_shape.go,
// but for these well-known tools the raw socket IS their normal mode
// of operation — any beacon-* role tagged on them is synthetic-
// attribution noise from the orchestrator's PID rollup, not real
// suspicious behaviour.
//
// Strict allowlist by name only. Path-checking deliberately omitted —
// these binaries can live anywhere (system package, snap, homebrew,
// build tree). The ApplyCaptureToolSuppression demote target is benign
// (`outbound`), so even if an attacker renamed their malware to
// `tcpdump` the only thing they buy is benign tagging on a process
// that already has zero real network sockets — they still need real
// connections to do anything, and those would be tagged via the
// normal candidate of whichever real binary owns the sockets.
func IsCaptureTool(p *ProcessInfo) bool {
	if p == nil {
		return false
	}
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p.Name), ".exe"))
	switch name {
	case "tcpdump",
		"tshark",
		"dumpcap",
		"wireshark",
		"wireshark-gtk",
		"wireshark-qt":
		return true
	}
	return false
}

// ApplyCaptureToolSuppression demotes any beacon-* / smb-pipe / tunnel
// role on a packet-capture tool back to outbound. Returns true if a
// demotion was applied.
//
// Runs BEFORE the existing vendor-FP gates so the `raw-socket` blocker
// (which is correct for unknown processes — real attackers using raw
// sockets is suspicious) doesn't prevent the demotion for these
// well-known capture tools.
func ApplyCaptureToolSuppression(c *Candidate) bool {
	if c == nil || c.Proc == nil {
		return false
	}
	if !IsCaptureTool(c.Proc) {
		return false
	}
	role := strings.ToLower(strings.TrimSpace(c.Role))
	switch role {
	case "beacon", "pivot", "smb-pipe", "tunnel":
	default:
		return false
	}
	c.Role = "outbound"
	c.ControlSubtype = ""
	if c.Score > 35 {
		c.Score = 35
	}
	c.Reasons = append(c.Reasons, "capture-tool-no-pcb-sockets")
	return true
}

// ApplyBenignClientHostMaliceGate demotes browser / IDE / API-CLI /
// VPN candidates from beacon-* back to outbound. The benign-client
// family is name-gated (see IsBenignClientFamily) so renamed
// malware (`chrome.exe` dropped in /tmp) does NOT qualify here —
// the upstream rule engine still gates those by trusted path.
//
// Long-lived HTTPS to CDN/API endpoints + periodic beaconing trips
// the cdn-fronted-c2 / persistent-session signals on these
// clients; even browsers' own loopback children spawn the
// child-tunnel-relay signal on chrome's mDNS listener. None of
// those shapes are actually C2 in this process family.
//
// Demotion is unconditional within the family — no host-malice
// escape. Earlier versions tried a "co-located malice keeps the
// tag" rescue, but that's defeated by anything else on the box
// carrying a Tier 2 signal (a single legit ssh tunnel kept every
// chrome/code instance pinned at pivot). If a real attack
// uses one of these binaries as a relay, the upstream gating in
// rank.go / vendor_fp_shape.go is responsible — this gate's job
// is purely to reduce the routine FP wash.
//
// Strictly tightening: only demotes, never promotes. SSH stays
// untouched — its tunneling detection is gated independently.
func ApplyBenignClientHostMaliceGate(candidates []Candidate) {
	if len(candidates) == 0 {
		return
	}
	for i := range candidates {
		c := &candidates[i]
		if c.Proc == nil {
			continue
		}
		if !IsBenignClientFamily(c.Proc) {
			continue
		}
		if !isMaliciousRole(c.Role) {
			continue
		}
		// Never demote processes with beacon-port-rotation signal.
		// This is a high-specificity behavioral signal (3+ connections to same IP
		// on different ports) that indicates tunneling/C2 even in trusted processes.
		hasPortRotation := false
		for _, sig := range c.Signals {
			if sig == "beacon-port-rotation" {
				hasPortRotation = true
				break
			}
		}
		if hasPortRotation {
			continue
		}
		c.Role = "outbound"
		c.ControlSubtype = ""
		if c.Score > 40 {
			c.Score = 40
		}
		c.Reasons = append(c.Reasons, "benign-client-family-demoted")
	}
}

// IsBenignClientFamily delegates to IsKnownNetworkActiveProcess (the
// authoritative project-wide list of "naturally network-active"
// processes: browsers, IDEs, VPN daemons, container runtimes,
// monitoring agents, backup agents, auto-updaters, system services
// like geoclue/ntpd/NetworkManager, Windows system services,
// Electron renderers) and supplements with a small set of AI/CLI/
// chat clients not yet in that list.
//
// The structural FP fix (no name lists at all) lives in
// scoring.AggregateChildTunnelEvidence's helper-mesh-IPC bypass —
// it catches the same shape using listener / external-connection /
// loopback-target topology. This name-based gate exists as a
// lightweight backstop for the cdn-fronted-c2 / persistent-beacon-
// session shape that DOES generate external traffic (so doesn't
// match the structural bypass) but on a process whose entire
// purpose is talking to a vendor CDN.
//
// SSH deliberately omitted from both lists: real operator tunnels
// keep their tags via the tunneling-shape gate.
func IsBenignClientFamily(p *ProcessInfo) bool {
	if p == nil {
		return false
	}
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p.Name), ".exe"))
	switch name {
	// AI / API CLIs not yet in IsKnownNetworkActiveProcess.
	case "claude", "claude-code", "cursor-agent", "copilot",
		"gh", "ghcli", "openai":
		return true
	// Music / streaming.
	case "spotify", "spotify-launcher":
		return true
	// Chat clients beyond the IDE/Electron coverage.
	case "telegram", "signal-desktop", "element", "matrix":
		return true
	}
	return IsKnownNetworkActiveProcess(p)
}

// isMaliciousRole is a local helper so this file doesn't need to
// import the scoring package (which would create a dep cycle).
// Mirrors scoring.IsMaliciousRole's set without importing it.
func isMaliciousRole(role string) bool {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "beacon", "pivot", "smb-pipe", "tunnel":
		return true
	}
	return false
}
