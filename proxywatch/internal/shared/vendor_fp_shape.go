package shared

import (
	"os"
	"strconv"
	"strings"
	"sync/atomic"
)

// FPShape is the per-candidate verdict of the vendor-agnostic FP-shape
// evaluator. It reports a score in [0, 100], the indicator reasons that
// contributed, any blockers that zeroed the score, and whether the
// currently-loaded threshold would trigger a demotion to role "outbound".
//
// The evaluator is pure measurement unless WouldDemote is true — even then,
// the caller (classifier.Classify / RemoteScanner.Refresh) is responsible
// for applying the demotion. This keeps the scorer side-effect-free and
// easy to re-run from /fp-report for "what-if" comparison.
//
// Hard vs soft blockers:
//
//   - Hard blockers are architectural incompatibilities with vendor
//     software: tunneling, pivot shapes, raw sockets, SMB pipes, injected
//     code, named-pipe C2, lateral movement. Legitimate vendor software
//     never exhibits these — hard blockers ALWAYS zero the score.
//   - Soft blockers are phone-home-shaped behaviors (persistent-control,
//     beacon-cadence, reconnecting-callback, sustained control session).
//     Legitimate vendor software routinely exhibits these — their presence
//     alone no longer rules out vendor-FP suppression IF a strong
//     convergent vendor-identity signal is present (Authenticode verified,
//     publisher-DNS-aligned, pkg-owned, etc.). See SoftBlockerOverride-
//     Threshold and VendorSignalsCount.
type FPShape struct {
	Score             int
	Reasons           []string
	Blockers          []string // union of hard + soft (back-compat)
	HardBlockers      []string
	SoftBlockers      []string
	SoftOverride      bool // true when soft blockers present but waived by vendor signals
	OverrideReason    string
	VendorSignalCount int
	WouldDemote       bool
}

// DefaultFPShapeThreshold is the minimum score required to trigger a
// demotion when no blocker is present. 75 is conservative: it demands at
// least three indicators or two heavy ones (TrafficVerified + install-path
// trust already totals 55).
const DefaultFPShapeThreshold = 75

// SafeFPShapeThreshold is the "observation only" value. When the loaded
// threshold is >= 101 the demotion path never fires — the evaluator still
// runs and populates FPShape so /fp-report can show what a lower threshold
// would catch. This is the default until an operator explicitly sets the
// env var after reviewing /fp-report output.
const SafeFPShapeThreshold = 101

// VendorFPShapeReason is the sentinel appended to c.Reasons when the
// demotion fires. Matches the Phase 2 VendorUpdateCadenceReason pattern so
// downstream UI/logging can filter on a consistent set.
const VendorFPShapeReason = "vendor-fp-shape-suppressed"

// HardBlockerSignals ALWAYS zero the FP-shape score regardless of vendor
// verification. Each signal here represents a behavior that legitimate
// vendor software does not perform — tunneling, pivot shapes, lateral
// movement, raw sockets. Adding a new decisive signal in behavior/* must
// classify it as hard or soft; the default for control/tunnel families
// is HARD unless specifically phone-home-shaped.
var HardBlockerSignals = map[string]bool{
	// Pivot-style signals (tunnel-flag CLIs, named-pipe C2, explicit pivot roles).
	"pivot-ssh-tunnel-flags":      true,
	"pivot-named-pipe-c2-pattern": true,
	"control-pivot":               true,

	// Lateral-movement shapes.
	"lateral-pivot-shape": true,
	"lateral-host-sweep":  true,
	"lateral-wide-recon":  true,
	"lateral-pivot":       true,

	// Tunneling signals.
	"tunnel":       true,
	"tunneling":    true,
	"child-tunnel": true,

	// Transport-level unusual indicators. A vendor process does not need
	// raw sockets or SMB pipes to perform normal work — their presence
	// signals tooling, not vendor software.
	"raw-socket": true,
	"smb-pipe":   true,
}

// SoftBlockerSignals match the shape of legitimate vendor phone-home:
// persistent control channels, beacon cadence, reconnecting callbacks.
// A real C2 also matches — distinguishing requires convergent vendor-
// identity evidence (Authenticode verified, publisher-DNS-aligned,
// pkg-owned, ASN org match, traffic-verified). When VendorSignalCount
// reaches SoftBlockerOverrideMin, soft blockers are waived.
var SoftBlockerSignals = map[string]bool{
	"persistent-control":             true,
	"control-channel":                true,
	"strong-control-session":         true,
	"beacon-pattern-confirmed":       true,
	"beacon-syn-cycle-cadence":       true,
	"reconnecting-callback-observed": true,

	// Actual signal names emitted by behavior/session.go + beacon.go that
	// indicate phone-home shape. Same semantic as the short-form names
	// above — classified soft because vendor phone-home exhibits them too.
	"session-control-channel-persistent": true,
	"session-single-target-persistence":  true,
	"beacon-target-lock":                 true,
	"beacon-http-channel":                true,
}

// VendorFPBlockerSignals is retained for backward compatibility with code
// that referenced the flat map before the hard/soft split. It's the union
// of the two new sets; new code should use Hard/SoftBlockerSignals.
var VendorFPBlockerSignals = mergeBlockerSets(HardBlockerSignals, SoftBlockerSignals)

// SoftBlockerOverrideMin is the number of independent vendor-identity
// signals required to waive soft blockers. Three signals means roughly:
// "signed AND runs from a legitimate path AND talks to its own vendor".
// Lower would over-suppress; higher would miss m365copilot-like cases
// whose identity is well-attested but behavior is classically control-
// channel-shaped.
const SoftBlockerOverrideMin = 3

func mergeBlockerSets(sets ...map[string]bool) map[string]bool {
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

// fpShapeThreshold is an atomic cache of the loaded threshold so the hot
// evaluator path never calls os.Getenv per candidate. Refreshed on startup
// by LoadedFPThreshold(); operators can force a reload if they export a
// new value at runtime by calling ReloadFPThreshold().
var fpShapeThreshold atomic.Int64

// LoadedFPThreshold returns the currently-effective threshold, reading
// PROXYWATCH_VENDOR_FP_THRESHOLD once and caching the parsed value. The
// default is SafeFPShapeThreshold (101 = unreachable), which means the
// evaluator runs but never demotes — operators opt in explicitly.
func LoadedFPThreshold() int {
	v := fpShapeThreshold.Load()
	if v != 0 {
		return int(v)
	}
	raw := strings.TrimSpace(os.Getenv("PROXYWATCH_VENDOR_FP_THRESHOLD"))
	n := SafeFPShapeThreshold
	if raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 0 && parsed <= 200 {
			n = parsed
		}
	}
	fpShapeThreshold.Store(int64(n))
	return n
}

// ClassifyVendorFPBlockers returns separate hard and soft blocker lists.
// Hard blockers always zero the FP-shape score. Soft blockers only zero
// the score when VendorSignalCount < SoftBlockerOverrideMin.
//
// Behavioral-state checks (ActiveProxying, sustained ControlChannel,
// named pipes, RWX memory, anon-exec, LOLbin, authenticode-distrust) all
// map onto one or the other — see inline comments for the classification
// rationale.
func ClassifyVendorFPBlockers(c *Candidate) (hard []string, soft []string) {
	if c == nil || c.Proc == nil {
		return nil, nil
	}

	for _, s := range c.Signals {
		if HardBlockerSignals[s] {
			hard = append(hard, "signal:"+s)
		} else if SoftBlockerSignals[s] {
			soft = append(soft, "signal:"+s)
		}
	}

	// Behavioral-state blockers. ActiveProxying is hard — it means an
	// actual proxy/relay was observed on the wire (not merely claimed by
	// signal shape). StrongEvidence + sustained control session are soft
	// — they fire for legitimate persistent phone-home as well as C2.
	if c.ActiveProxying {
		hard = append(hard, "state:active-proxying")
	}
	if c.StrongEvidence {
		soft = append(soft, "state:strong-evidence")
	}
	if len(c.NamedPipes) > 0 {
		hard = append(hard, "state:named-pipes-open")
	}
	if c.ControlChannel != nil && c.ControlDurationSeconds >= 60 {
		soft = append(soft, "state:sustained-control-session")
	}

	// ML high-confidence control-role = soft blocker. The model may be
	// right but vendor-identity convergence can override when the binary
	// is cryptographically-verified and talks to its own publisher.
	if c.MLActive && c.MLConfidence >= 0.80 && IsControlRole(c.Role) {
		soft = append(soft, "state:ml-confirmed-control-role")
	}

	// Process-level unusual state. LOLbins never legitimately appear in
	// vendor software that should be FP-suppressed — keep them hard.
	//
	// RWX memory and anonymous executable regions were hard blockers,
	// but JIT-compiled language runtimes (Go, Rust, .NET, JVM, V8) all
	// legitimately allocate RWX/anon-exec memory at startup. Treating
	// those as "definitely-injected-code" FPs every Go binary out there
	// (including this scanner, claude CLI, docker, kubectl, etc.). Moved
	// to soft — they're still strong suspicion markers that count
	// toward soft-override gating, but no longer unilaterally zero the
	// score. A JIT-language vendor process with other identity signals
	// can now be demoted; actual injected code in a non-JIT binary
	// still presents its other hard markers (no pkg owner, suspicious
	// path, LOLbin, raw sockets, etc.).
	if c.Proc.HasRWXMemory {
		soft = append(soft, "proc:rwx-memory")
	}
	if c.Proc.AnonExecCount > 0 {
		soft = append(soft, "proc:anon-exec-regions")
	}
	if IsLOLBinProcess(c.Proc) {
		hard = append(hard, "proc:lolbin")
	}

	// Authenticode distrust is a hard suspicion signal — the OS trust
	// policy explicitly says this binary should NOT be run.
	if c.Proc.SignatureTrust == SignatureTrustUntrusted {
		hard = append(hard, "online:authenticode-distrust")
	}

	return hard, soft
}

// countVendorSignals tallies how many independent vendor-identity signals
// converge on this candidate. Each signal here is a different
// authoritative data source; a match across several is strong evidence
// the binary is what it claims to be. The five signals are chosen to be
// independent from one another — Authenticode is cryptographic, ASN org
// alignment is network-registry-based, publisher DNS is operational,
// pkg-owned is local OS trust, traffic-verified is behavioral baseline.
func countVendorSignals(c *Candidate, signalSet map[string]bool) (int, []string) {
	count := 0
	var tags []string
	if c == nil || c.Proc == nil {
		return 0, nil
	}
	// Signature trust: prefer full Authenticode-OCSP verification when
	// available (Windows, live posture). Fall back to the Unix
	// path+ownership heuristic (signature_unix.go) which also produces
	// SignatureTrustTrusted for a root-owned binary in a distro-trusted
	// prefix. The two are counted as the same weight (1) — both indicate
	// "the OS install context vouches for this binary's integrity" — but
	// are exposed as separate tags so operators can tell which pathway
	// fired.
	switch {
	case c.Proc.AuthenticodeOCSPSeen && c.Proc.SignatureTrust == SignatureTrustTrusted:
		count++
		tags = append(tags, "authenticode-verified")
	case IsLikelyBenignControlClient(c.Proc) && c.Proc.SignatureTrust == SignatureTrustTrusted:
		count++
		tags = append(tags, "install-path-trust")
	}
	// ASN org alignment OR publisher/company match both speak to identity
	// coherence but we count the strongest of the two, not both, so we
	// don't double-weight what is essentially the same data point.
	switch {
	case signalSet["outbound-asn-org-aligned"]:
		count++
		tags = append(tags, "asn-org-aligned")
	case c.Proc.Publisher != "" && c.Proc.Company != "" &&
		strings.EqualFold(strings.TrimSpace(c.Proc.Publisher), strings.TrimSpace(c.Proc.Company)):
		count++
		tags = append(tags, "publisher-company-match")
	}
	if c.Proc.PublisherDNSAligned {
		count++
		tags = append(tags, "publisher-dns-aligned")
	}
	if c.Proc.PkgOwned {
		count++
		tags = append(tags, "pkg-owned")
	}
	if c.TrafficVerified {
		count++
		tags = append(tags, "traffic-verified")
	}
	return count, tags
}

// EvaluateVendorFPShape returns the FP-shape verdict for a candidate. The
// threshold controls whether WouldDemote is ever true; pass
// LoadedFPThreshold() for runtime use, or a test-specific value.
//
// Flow:
//  1. Classify blockers into hard (always zero the score) vs soft
//     (overridable by convergent vendor-identity signals).
//  2. Build the pre-blocker score from indicators and count vendor signals.
//  3. If any hard blocker fires → score 0, return with HardBlockers set.
//  4. If soft blockers fire but VendorSignalCount >= SoftBlockerOverrideMin,
//     record SoftOverride=true and compute the score normally.
//  5. Otherwise, soft blockers fire and score is zero — same as the
//     pre-split behavior.
func EvaluateVendorFPShape(c *Candidate, threshold int) FPShape {
	if c == nil || c.Proc == nil {
		return FPShape{}
	}

	hard, soft := ClassifyVendorFPBlockers(c)

	// Hard blockers always win — vendor identity can never override these.
	if len(hard) > 0 {
		all := append([]string(nil), hard...)
		all = append(all, soft...)
		return FPShape{
			Blockers:     all,
			HardBlockers: hard,
			SoftBlockers: soft,
		}
	}

	score := 0
	var reasons []string

	if c.TrafficVerified {
		score += 30
		reasons = append(reasons, "traffic-verified(+30)")
	}

	// Install-path trust. When the Windows Authenticode verifier confirmed
	// the signature with an actual OCSP response, upgrade the indicator to
	// "authenticode-verified" (still +25 so the score ceiling is unchanged;
	// the distinction is only for the human-readable reason trace). When
	// the verifier hasn't run (Linux/macOS, or Windows cache-only posture)
	// the classic install-path heuristic contributes the same weight.
	switch {
	case c.Proc.AuthenticodeOCSPSeen && c.Proc.SignatureTrust == SignatureTrustTrusted:
		score += 25
		reasons = append(reasons, "authenticode-verified(+25)")
	case IsLikelyBenignControlClient(c.Proc) && c.Proc.SignatureTrust == SignatureTrustTrusted:
		score += 25
		reasons = append(reasons, "install-path-trust+signed(+25)")
	}

	// Publisher/Company match is a strong signal that the signed binary
	// actually belongs to the vendor it claims to be — not a binary
	// planted inside a vendor's install tree. Small additive bump so a
	// genuine vendor process crosses a conservative threshold.
	if c.Proc.Publisher != "" && c.Proc.Company != "" &&
		strings.EqualFold(strings.TrimSpace(c.Proc.Publisher), strings.TrimSpace(c.Proc.Company)) {
		score += 5
		reasons = append(reasons, "publisher-company-match(+5)")
	}

	// Package-manager ownership (Linux dpkg in Phase 6a; rpm/pacman/apk to
	// follow). A dpkg-owned binary is distro-package-signed at install
	// time, which is the strongest non-crypto benign signal available
	// locally.
	if c.Proc.PkgOwned {
		score += 15
		reasons = append(reasons, "pkg-owned(+15)")
	}

	// Publisher → destination DNS alignment. The vendor-agnostic check:
	// this process's outbound destinations actually resolve inside its
	// Authenticode publisher's domain. Evaluated live per-cycle in the
	// classifier/RemoteScanner — see EvaluatePublisherDNSAlignment.
	if c.Proc.PublisherDNSAligned {
		score += 10
		reasons = append(reasons, "publisher-destinations-aligned(+10)")
	}

	signalSet := make(map[string]bool, len(c.Signals))
	for _, s := range c.Signals {
		signalSet[s] = true
	}

	if signalSet["outbound-asn-org-aligned"] {
		score += 20
		reasons = append(reasons, "destination-org-aligned(+20)")
	}

	// Destination cardinality: a CDN signal implies many remotes; absent
	// CDN, we accept >=3 distinct external remotes with no single-remote
	// control channel as evidence of fan-out (client behavior, not C2).
	distinctRemotes := countDistinctExternalRemotes(c)
	if signalSet["outbound-cdn-destination"] ||
		(distinctRemotes >= 3 && c.ControlChannel == nil) {
		score += 15
		reasons = append(reasons, "destination-fanout/cdn(+15)")
	}

	// Long stable history from the persistent ProcessBehavior store.
	if b := lookupProcessBehavior(c); b != nil && b.Observations >= 50 {
		susp := 0.0
		if b.Observations > 0 {
			susp = float64(b.SuspiciousObservations) / float64(b.Observations)
		}
		if susp <= 0.10 {
			score += 10
			reasons = append(reasons, "long-stable-history(+10)")
		}
	}

	// Count independent vendor-identity signals — same signalSet above is
	// reused so we don't double-tokenize.
	vendorCount, vendorTags := countVendorSignals(c, signalSet)

	shape := FPShape{
		Score:             score,
		Reasons:           reasons,
		SoftBlockers:      soft,
		VendorSignalCount: vendorCount,
	}

	// Soft-blocker override: if only soft blockers fired AND the candidate
	// shows enough vendor-identity convergence, waive the soft blockers and
	// let the score contribute normally. This is how m365copilot.exe
	// (signed Microsoft binary, Microsoft ASN, persistent-control shape)
	// escapes the old "all control-channel is decisive" trap.
	if len(soft) > 0 {
		if vendorCount >= SoftBlockerOverrideMin {
			shape.SoftOverride = true
			shape.OverrideReason = "vendor-signals:" + strings.Join(vendorTags, ",")
			reasons = append(reasons, "soft-blocker-override:"+shape.OverrideReason)
			shape.Reasons = reasons
			// Structured observability for FP-threshold tuning: every
			// override fires a single LogInfo with the full vendor-
			// signal set, soft-blocker set, and process identity. When
			// PROXYWATCH_LOG_JSON is set these surface as NDJSON lines
			// consumable by SIEM bridges; otherwise they collect in the
			// in-memory event log visible to the TUI. Over time the
			// population of overrides reveals whether
			// SoftBlockerOverrideMin is tuned correctly per process
			// class — see Track 7 in the enhancement plan.
			pid := 0
			name := ""
			exePath := ""
			if c.Proc != nil {
				pid = c.Proc.Pid
				name = c.Proc.Name
				exePath = c.Proc.ExePath
			}
			LogInfo("fp-shape-override",
				"pid=%d name=%s exe=%s vendor_signals=[%s] soft_blockers=[%s]",
				pid, name, exePath,
				strings.Join(vendorTags, ","),
				strings.Join(soft, ","),
			)
		} else {
			// Not enough vendor evidence to waive. Soft blockers win — zero
			// the score and surface them in Blockers for /fp-report.
			shape.Score = 0
			shape.Reasons = nil
			shape.Blockers = append([]string(nil), soft...)
			return shape
		}
	}

	if threshold > 0 && shape.Score >= threshold {
		shape.WouldDemote = true
	}
	return shape
}

// ApplyVendorFPShape evaluates and, if the current threshold would demote,
// mutates the candidate in place: sets Role to "outbound" and appends the
// VendorFPShapeReason sentinel. Returns true when the candidate was
// actually demoted. Callers use the boolean to set signalOverride or for
// logging; the FPShape itself is recoverable from /fp-report.
func ApplyVendorFPShape(c *Candidate) bool {
	shape := EvaluateVendorFPShape(c, LoadedFPThreshold())
	if !shape.WouldDemote {
		return false
	}
	c.Role = "outbound"
	for _, r := range c.Reasons {
		if r == VendorFPShapeReason {
			return true
		}
	}
	c.Reasons = append(c.Reasons, VendorFPShapeReason)
	return true
}

func countDistinctExternalRemotes(c *Candidate) int {
	if c == nil || len(c.Conns) == 0 {
		return 0
	}
	seen := make(map[string]struct{}, len(c.Conns))
	for _, conn := range c.Conns {
		addr := strings.TrimSpace(conn.RemoteAddress)
		if addr == "" || IsInternalIP(addr) {
			continue
		}
		seen[addr] = struct{}{}
	}
	return len(seen)
}

func lookupProcessBehavior(c *Candidate) *ProcessBehavior {
	if c == nil || c.Proc == nil {
		return nil
	}
	key := CandidateBehaviorKey(c)
	if key == "" {
		return nil
	}
	return ProcessBehaviorByKey[key]
}
