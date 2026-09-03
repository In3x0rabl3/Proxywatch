package shared

import "strings"

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
	"smb-pipe": true, // SMB-pipe C2 genuinely uses pipes at the wire
	"tunnel":   true, // rank.go topology already confirmed tunnel
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
	// `session-persistent-channel` (long-held external control
	// channel) AND `pivot-non-loopback-internal` (live connections to
	// internal RFC1918 targets, no current external) is a real sliver/
	// Cobalt session whose external callback isn't open this snapshot
	// cycle. Either signal alone has known FPs (system services to
	// DCs/NTP emit the pivot one; vendor phone-home emits the persistent
	// one), but the combination only fires on real C2 sessions actively
	// reaching internal peers. Verified live on 172.16.1.2 via /fp-report
	// — only session.exe pids emit both, no benign hits.
	if hasSignal(c, "session-persistent-channel") &&
		hasSignal(c, "pivot-non-loopback-internal") {
		hits = append(hits, "combo:persistent-control+internal-pivot")
	}
	if len(c.NamedPipes) > 0 {
		hits = append(hits, "state:named-pipes-open")
	}
	if c.Proc.SignatureTrust == SignatureTrustUntrusted {
		hits = append(hits, "online:authenticode-distrust")
	}
	// Vendor-traffic-aligned bypass. The two new gates below
	// (state:strong-evidence and combo:multi-beacon+persistent-session)
	// are powerful enough to over-rescue legit vendor processes that have
	// long-held HTTPS sessions to their own infrastructure — observed
	// 2026-04-29 with svchost.exe "WpnService" (Microsoft Push
	// Notification Service) which carries every beacon-* and
	// session-persistent-channel signal yet is plainly
	// Microsoft-signed talking to MICROSOFT-CORP-MSN-AS-BLOCK.
	//
	// Skip the soft-promote gates (NOT cdn-fronted, NOT named-pipes, NOT
	// active-proxying — those already have their own non-vendor gates)
	// when the candidate has full vendor-trust convergence. The check is
	// purely signal-driven (no name allowlist):
	//   - signature trust = trusted (live OS verification)
	//   - publisher CN present (extracted from signing cert)
	//   - outbound-asn-org-aligned signal fires (destination ASN org
	//     matches publisher CN — proves the destination IS the vendor's
	//     own infrastructure, not a CDN-fronted attacker)
	//
	// Sliver/CS beacons fail this check because they're unsigned drops in
	// Downloads/, so cheerful_glove and LIQUID_MEZZANINE remain
	// preserved. WpnService passes and falls through to demotion.
	vendorAligned := isVendorTrafficAligned(c)
	// rank.go's own strong-evidence verdict is Tier 2. The flag is set in
	// rank.go after surviving multiple gates (controlSecs >= 180s with no
	// benign-suppression match, OR confirmed internal lateral, OR
	// delegated relay, OR the role-aware score-promotion path at
	// rank.go:1585). The downstream demotion previously ignored this
	// and would still wipe the role to outbound — exactly the bug seen on
	// 2026-04-29 with the Sliver beacon "LIQUID_MEZZANINE"
	// (cheerful_glove.exe) which carried the "Sustained session
	// evidence exceeded strong threshold" reason yet got demoted anyway.
	if c.StrongEvidence && !vendorAligned {
		hits = append(hits, "state:strong-evidence")
	}
	// CDN-fronted callback from a non-vendor, non-trusted process is the
	// canonical Sliver / Cobalt-Strike-over-Cloudflare profile. The
	// emitter (behavior/cdn.go) already requires non-vendor +
	// non-signature-trusted + external + CDN ASN + NOT publisher-aligned
	// before firing, so the false-positive risk on Tier 2 is low: a real
	// CDN-using vendor app would either be in the known-vendor list
	// (Slack/Discord/Teams/etc.) or have aligned ASN org metadata.
	if hasSignal(c, "cdn-fronted-c2-candidate") {
		hits = append(hits, "signal:cdn-fronted-c2")
	}
	// Multi-beacon corroboration. Single beacon-* signals fire on enough
	// vendor phone-home traffic (auto-updaters, telemetry) that none is a
	// hard distinguisher alone. But TWO OR MORE distinct beacon signals
	// firing on the same candidate is rare in benign — vendor apps don't
	// typically combine static-crypto + http-channel + no-children +
	// persistent-session simultaneously. Counted across the beacon-*
	// family, threshold ≥2 catches Sliver/CS HTTP-mode beacons whose
	// individual signals would otherwise be soft-blocked.
	beaconHits := 0
	for _, s := range c.Signals {
		switch s {
		case "beacon-http-channel",
			"beacon-static-crypto-likely",
			"beacon-no-children",
			"beacon-thread-minimal",
			"beacon-crypto-lib-loaded",
			"beacon-target-lock",
			"beacon-pattern-confirmed",
			"beacon-interval-confirmed",
			// Operator-confirmed 2026-05-04 on cheerful_glove.exe (live
			// rig): the beacon emits beacon-reconnecting-unknown-vendor
			// and beacon-short-lived-callback alongside beacon-static-
			// crypto-likely. With the prior 8-name list, only 1 of those
			// 3 counted (static-crypto), so multi-beacon corroboration
			// failed and the rescue depended on cdn-fronted-c2-candidate
			// alone — which doesn't stamp on every cycle. Adding these
			// two emitter names to the count brings cheerful's total to
			// 3 and makes the rescue resilient to a single-cycle CDN-
			// classification miss. Both names ARE distinct beacon shapes
			// (reconnecting-unknown-vendor = repeated callback to fresh
			// IP without vendor identity; short-lived-callback = sub-
			// minute connection life cycle) so they corroborate the
			// static-crypto-likely signal rather than overlap it.
			"beacon-reconnecting-unknown-vendor",
			"beacon-short-lived-callback":
			beaconHits++
		}
	}
	if beaconHits >= 2 && hasSignal(c, "session-persistent-channel") && !vendorAligned {
		hits = append(hits, "combo:multi-beacon+persistent-session")
	}
	// Triple-beacon hard distinguisher. Three or more distinct beacon
	// shapes firing on the same candidate is rare in benign — vendor
	// auto-updaters typically emit ONE shape (e.g., http-channel from
	// the polling loop). Sliver/CS implants emit several simultaneously
	// (static-crypto + reconnecting + short-lived + crypto-lib-loaded
	// etc.). Operator-confirmed 2026-05-04: cheerful_glove had three
	// beacon signals firing every cycle but multi-beacon-2 required
	// session-persistent-channel which doesn't stamp on every
	// cycle. The 3-signal threshold is independently load-bearing and
	// gives the rescue chain a stickier anchor than cdn-fronted-c2-
	// candidate (which can miss a cycle when the ASN cache lookups
	// race the classifier).
	if beaconHits >= 3 && !vendorAligned {
		hits = append(hits, "combo:triple-beacon")
	}
	return len(hits) > 0, hits
}

// isVendorTrafficAligned returns true when the candidate exhibits the
// canonical "signed vendor talking to its own infrastructure" pattern:
// Authenticode trust, a publisher CN extracted from the signing cert,
// and a destination ASN whose org name matches that publisher CN (the
// outbound-asn-org-aligned signal). Used as a dynamic bypass for the
// soft-promote hard distinguishers — Sliver/CS implants are unsigned
// drops in user-writable paths so they fail the trust gate and the
// hard distinguishers continue to fire on them. WpnService /
// OneDrive / Slack-style vendor processes pass and lose the
// over-rescue. No name allowlist — every input is a live signal or
// OS-derived identity field.
func isVendorTrafficAligned(c *Candidate) bool {
	if c == nil || c.Proc == nil {
		return false
	}
	if c.Proc.SignatureTrust != SignatureTrustTrusted {
		return false
	}
	if strings.TrimSpace(c.Proc.Publisher) == "" {
		return false
	}
	if !hasSignal(c, "outbound-asn-org-aligned") {
		return false
	}
	return true
}

// ShapeOnlyControlDemotedReason is the reason sentinel appended when a
// candidate's control role is demoted by the shape-only guard.
const ShapeOnlyControlDemotedReason = "shape-only-beacon-demoted"

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

	// Tier 2.5 — sleeping-beacon cooldown preserve. If the same PID was
	// committed to a malicious role within the last MaliciousRoleDemoteCooldown
	// (5 min default), keep the role even when no hard distinguisher fires
	// THIS cycle. Sliver / Cobalt-Strike beacons go fully silent between
	// callbacks — connections close, beacon-* signals stop emitting,
	// cdn-fronted-c2-candidate stops stamping (no active CDN flow to
	// classify). Without this preserve the role flapped Beacon → outbound
	// → Beacon every callback interval. Operator-confirmed 2026-05-04 on
	// cheerful_glove.exe (rig DEMO host): the dormant cycle had only 2
	// signals (outbound-baseline-verified + suspicious-exe-path) — every
	// other cycle's hard-distinguisher evidence was gone, but the process
	// was unambiguously the same beacon.
	//
	// rank.go has the same cooldown at line 1770 but applies BEFORE this
	// function, so its preserve gets overridden here. Adding it here closes
	// that gap — once committed, the role survives quiet cycles for the
	// cooldown window.
	if hist := procHistorySnapshot(c.Proc.Pid); hist != nil &&
		IsMaliciousRoleName(hist.LastRole) &&
		PcapNow().Sub(hist.LastRoleChange) < MaliciousRoleDemoteCooldown {
		appendReasonUnique(c, "preserved-via-recent-malicious-role-cooldown")
		return false
	}

	// No hard evidence. Demote.
	demoteToRoleAwareTarget(c)
	appendReasonUnique(c, ShapeOnlyControlDemotedReason)
	return true
}

// procHistorySnapshot returns the per-PID ProcHistory entry directly
// from the global map. CALLER MUST HOLD ClassifyMu (read or write) —
// detection.Classify holds the write lock for the entire classification
// pass and DemoteShapeOnlyControlRole is invoked under that lock, so
// taking an additional RLock here would deadlock on a pending Write.
// Mirrors the unsafe-read pattern in CandidateStateUnsafe.
func procHistorySnapshot(pid int) *ProcHistory {
	return ProcHistoryByPID[pid]
}

// IsMaliciousRoleName mirrors scoring.IsMaliciousRole at the shared-package
// level so distinguishing.go can ask the same question without an import
// cycle. The list must stay in sync with scoring/rank.go's IsMaliciousRole.
func IsMaliciousRoleName(role string) bool {
	switch role {
	case "beacon", "pivot", "tunnel", "smb-pipe":
		return true
	}
	return false
}

// demoteToRoleAwareTarget mutates c.Role to listener (when binds ports)
// or outbound (otherwise). The listener check applies to ANY shape-only
// control demotion target — a process with an OS-reported bound port is
// observably a listener regardless of which beacon-* shape rank.go
// originally inferred. The previous gating (only pivot consulted
// the listener set) collapsed listening svchost workers like
// `svchost -k NetworkService -p` to "outbound" even though netstat plainly
// shows their bound port — exactly the false negative observed on
// 2026-04-28 with PID 932.
func demoteToRoleAwareTarget(c *Candidate) {
	if len(c.Listeners) > 0 || len(c.UDPListeners) > 0 {
		c.Role = "listener"
		return
	}
	c.Role = "outbound"
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
// beacon when it matches the sleeping-beacon profile:
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
	c.Role = "beacon"
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
	case "beacon", "pivot":
		return true
	}
	return false
}
