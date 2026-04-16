package shared

// Phase 9 anti-spoof tiering.
//
// The fundamental discriminator between legitimate vendor phone-home and
// real C2 cannot be "what the process claims to be" (name / path /
// cmdline). Those are all spoofable: an attacker drops the beacon in
// Program Files instead of Downloads, uses direct syscalls instead of
// libproxychains, obfuscates the cmdline.
//
// We use three tiers of evidence:
//
//   Tier 1 — Operator label (operator_labels.go)
//     SHA256-keyed human verdict. Always decisive, bidirectional.
//     benign  → force demote regardless of tier 2 / 3.
//     malicious → force preserve control role and boost score.
//
//   Tier 2 — Hard-to-spoof distinguishers (HardDistinguishingSignals +
//            DistinguishingSuspicionRoles + ActiveProxying+non-loopback).
//     Unilaterally preserves control role when any entry fires. Each
//     entry here has an explicit "why hard to spoof" justification —
//     adding items requires the same.
//
//   Tier 3 — Weak identity indicators (WeakIdentityIndicators).
//     Still emitted and shown in /fp-report for operator context, but
//     CANNOT alone save a control role from shape-only demotion.
//     Path, cmdline, loaded libs all live here — each is defeatable by
//     an attacker with minimal effort.
//
// The demotion rule runs in exactly this tier order. The previous flat
// `DistinguishingSuspicionSignals` list is retained as an alias so
// external callers and /fp-report don't break, but new code should use
// the tiered maps directly.

// HardDistinguishingSignals — Tier 2. Signals that are cryptographically
// or behaviorally hard to fake. Emitters are audited:
//
//	grep -rn 'addSignal("X")' internal/detection/
//
// Adding an entry here requires a brief justification in this comment.
var HardDistinguishingSignals = map[string]bool{
	// Cmdline tunnel flags on the actual SSH binary. Attacker renaming
	// ssh still produces these in cmdline when tunneling; to evade,
	// attacker must rewrite SSH from scratch — high cost, low value.
	"pivot-ssh-tunnel-flags": true,

	// Named-pipe C2 pattern match on real handles opened by the process.
	// Pipe name choices are constrained by the C2 framework (Cobalt
	// Strike, Sliver, etc.); spoofing means adopting a non-C2 pipe name
	// which defeats the attacker's own tooling.
	"pivot-named-pipe-c2-pattern": true,

	// Multi-cycle timing analysis of SYN cycles. Attacker can't fake
	// this without also breaking the beacon's function (a beacon that
	// doesn't actually beacon is not a beacon).
	"beacon-syn-cycle-cadence": true,

	// Kernel-level raw-socket activity. OS sees it regardless of process
	// obfuscation. Legitimate vendor apps don't use raw sockets.
	"raw-socket": true,

	// Parent-child tunnel relay — parent listener's children forward
	// internal connections out. Shape is observable in real time and
	// can't be hidden without the attacker's tool losing its relay
	// function.
	"child-tunnel-relay": true,
}

// WeakIdentityIndicators — Tier 3. Signals that identify "looks like
// tooling" based on spoofable attributes. Useful for scoring context but
// NOT for unilateral preservation.
var WeakIdentityIndicators = map[string]bool{
	"suspicious-exe-path":  true, // attacker drops in Program Files
	"cmdline-proxy-flags":  true, // attacker renames flags or obfuscates
	"proxy-library-loaded": true, // attacker uses direct syscalls instead
}

// DistinguishingSuspicionRoles — roles rank.go commits that are themselves
// Tier 2 evidence. Not signal strings; checked against c.Role.
var DistinguishingSuspicionRoles = map[string]bool{
	"smb-pipe":       true, // SMB-pipe C2 genuinely uses pipes at the wire
	"tunnel":         true, // rank.go topology already confirmed tunnel
	"control-tunnel": true, // confirmed tunnel via rank.go
}

// DistinguishingSuspicionSignals is retained as the union of hard +
// weak for back-compat callers. New code should use HardDistinguishingSignals
// for the "unilateral preserve" decision and WeakIdentityIndicators for
// scoring contribution.
var DistinguishingSuspicionSignals = mergeSignalSets(HardDistinguishingSignals, WeakIdentityIndicators)

func mergeSignalSets(sets ...map[string]bool) map[string]bool {
	out := map[string]bool{}
	for _, s := range sets {
		for k, v := range s {
			if v {
				out[k] = true
			}
		}
	}
	return out
}

// HasHardDistinguisher returns true if the candidate carries any Tier 2
// signal, role, or behavioral state. Unilateral preserve.
func HasHardDistinguisher(c *Candidate) (bool, []string) {
	if c == nil || c.Proc == nil {
		return false, nil
	}
	var hits []string
	for _, s := range c.Signals {
		if HardDistinguishingSignals[s] {
			hits = append(hits, s)
		}
	}
	if DistinguishingSuspicionRoles[c.Role] {
		hits = append(hits, "role:"+c.Role)
	}
	// ActiveProxying is set by rank.go only after it observes real relay
	// topology (reverse proxy seen, local-transport forwarding, parent-
	// child tunnel, active clients on a SOCKS bind, etc.). That is already
	// treated as a hard blocker by vendor_fp_shape.go (line 213-215). The
	// previous narrower `ActiveProxying && hasNonLoopbackListener` gate
	// failed on in-band SOCKS beacons (sliver, Cobalt Strike) whose relay
	// is implemented client-side over the C2 channel — no listener bound
	// at all. That caused cheerful_glove.exe / session.exe to demote to
	// outbound despite rank.go + fp-shape both confirming an active relay.
	// Aligning the two predicates keeps ssh/pia/system services behavior
	// identical (they already pass the old gate) while rescuing in-band
	// SOCKS.
	if c.ActiveProxying {
		hits = append(hits, "state:active-proxying")
	}
	// Sleeping-beacon preserve: a process that emitted both
	// `session-control-channel-persistent` (long-held external control
	// channel) AND `pivot-non-loopback-internal` (live connections to
	// internal RFC1918 targets, no current external) is a real sliver/
	// Cobalt session whose external callback isn't open this snapshot
	// cycle. Either signal alone has known FPs (system services to
	// DCs/NTP emit the pivot one; vendor phone-home emits the persistent
	// one), but the combination only fires on real C2 sessions actively
	// reaching internal peers. Verified live on 172.16.1.2 via /fp-report
	// — only session.exe pids emit both, no benign hits.
	if hasSignal(c, "session-control-channel-persistent") &&
		hasSignal(c, "pivot-non-loopback-internal") {
		hits = append(hits, "combo:persistent-control+internal-pivot")
	}
	if len(c.NamedPipes) > 0 {
		hits = append(hits, "state:named-pipes-open")
	}
	if c.Proc.SignatureTrust == SignatureTrustUntrusted {
		hits = append(hits, "online:authenticode-distrust")
	}
	return len(hits) > 0, hits
}

// ShapeOnlyControlDemotedReason is the reason sentinel appended when a
// candidate's control role is demoted by the shape-only guard.
const ShapeOnlyControlDemotedReason = "shape-only-control-demoted"

// DemoteShapeOnlyControlRole applies the 3-tier anti-spoof logic to
// decide whether to keep a candidate's control role.
//
// Returns true when the role was demoted.
//
// Tier 1 — operator label by SHA256 wins over everything:
//   - benign → force demote, append operator-label:benign reason
//   - malicious → force preserve, append operator-label:malicious reason
//
// Tier 2 — hard-to-spoof distinguishers. Any one preserves.
//
// Tier 3 — NOT checked here. Weak identity indicators contribute via
// vendor_fp_shape.Score only.
//
// No hard evidence and no operator label → demote.
func DemoteShapeOnlyControlRole(c *Candidate) bool {
	if c == nil || c.Proc == nil {
		return false
	}
	if !isShapeOnlyCandidateRole(c.Role) {
		return false
	}

	// Tier 1 — operator label.
	if c.Proc.SHA256 != "" {
		if label := LookupOperatorLabel(c.Proc.SHA256); label != nil {
			switch label.Verdict {
			case VerdictBenign:
				demoteToRoleAwareTarget(c)
				appendReasonUnique(c, OperatorLabelBenignReason)
				return true
			case VerdictMalicious:
				appendReasonUnique(c, OperatorLabelMaliciousReason)
				return false
			}
		}
	}

	// Tier 2 — hard distinguishers.
	if has, _ := HasHardDistinguisher(c); has {
		return false
	}

	// No hard evidence. Demote.
	demoteToRoleAwareTarget(c)
	appendReasonUnique(c, ShapeOnlyControlDemotedReason)
	return true
}

// demoteToRoleAwareTarget mutates c.Role to listener (when binds ports)
// or outbound (otherwise). Pivot → listener preserves the "binds ports"
// operator signal; control-channel/session/beacon → outbound since they
// don't inherently bind.
func demoteToRoleAwareTarget(c *Candidate) {
	switch c.Role {
	case "control-pivot":
		if len(c.Listeners) > 0 {
			c.Role = "listener"
		} else {
			c.Role = "outbound"
		}
	default:
		c.Role = "outbound"
	}
}

func appendReasonUnique(c *Candidate, reason string) {
	for _, r := range c.Reasons {
		if r == reason {
			return
		}
	}
	c.Reasons = append(c.Reasons, reason)
}

// hasNonLoopbackListener returns true when the candidate binds at least
// one listener on a non-loopback address (0.0.0.0, internal interface,
// or public). A real pivot needs this so peer machines can connect.
// Legit loopback-only IPC services return false even with ActiveProxying
// set, freeing them for demotion.
func hasNonLoopbackListener(c *Candidate) bool {
	if c == nil {
		return false
	}
	for _, l := range c.Listeners {
		if l.LocalAddress == "" {
			continue
		}
		if !IsLoopbackIP(l.LocalAddress) {
			return true
		}
	}
	return false
}

// IsShapeOnlyCandidateRoleForReport is a read-only accessor exposed for the
// debug API. Wraps the package-private predicate so debug_api.go can report
// whether a candidate's role is subject to shape-only demotion without
// importing anything mutable.
func IsShapeOnlyCandidateRoleForReport(role string) bool {
	return isShapeOnlyCandidateRole(role)
}

// HasNonLoopbackListenerForReport — same read-only exposure pattern for the
// hasNonLoopbackListener predicate. Used by /fp-report tracing.
func HasNonLoopbackListenerForReport(c *Candidate) bool {
	return hasNonLoopbackListener(c)
}

// UpgradeSleepingBeaconProfile promotes a currently-outbound candidate to
// control-channel when it matches the sleeping-beacon profile:
//
//   - `beacon-interval-confirmed` signal present (the burst tracker has
//     measured a periodic callback cadence — persists across cycles
//     even when the beacon is between callbacks).
//   - `suspicious-exe-path` present (binary runs from a user-writable
//     location: Downloads, Desktop, Temp, AppData).
//   - NOT signed (no Authenticode trust).
//   - NOT package-owned (not MSI/MSIX/pkg/deb tracked).
//   - NOT IsKnownVendorProcess (path/name doesn't match vendor allowlist).
//
// The combination only fires on unsigned, unattested binaries with
// measurable beacon cadence from suspicious locations. Benign vendor
// auto-updaters (Slack, OneDrive, etc.) poll on intervals too but run
// from signed vendor paths — this gate excludes them.
//
// Called from classifier.go and agent/server.go AFTER DemoteShapeOnly
// ControlRole so it can re-promote candidates the per-host experience
// model wrongly committed as "outbound" baseline. Sleeping sliver /
// Cobalt beacons (5m-60m intervals) get averaged as quiet-outbound by
// baseline learning; this re-surfaces them.
//
// Returns true when a role change was made.
func UpgradeSleepingBeaconProfile(c *Candidate) bool {
	if c == nil || c.Proc == nil {
		return false
	}
	if c.Role != "outbound" {
		return false
	}
	if !hasSignal(c, "beacon-interval-confirmed") ||
		!hasSignal(c, "suspicious-exe-path") {
		return false
	}
	if c.Proc.Signed {
		return false
	}
	if c.Proc.PkgOwned {
		return false
	}
	if IsKnownVendorProcess(c.Proc) {
		return false
	}
	c.Role = "control-channel"
	appendReasonUnique(c, "sleeping-beacon-upgrade")
	return true
}

// hasSignal reports whether the candidate carries the named signal.
// Linear scan — Signals slice is small per candidate.
func hasSignal(c *Candidate, sig string) bool {
	if c == nil {
		return false
	}
	for _, s := range c.Signals {
		if s == sig {
			return true
		}
	}
	return false
}

func isShapeOnlyCandidateRole(role string) bool {
	switch role {
	case "control-channel", "control-session", "control-beacon", "control-pivot":
		return true
	}
	return false
}
