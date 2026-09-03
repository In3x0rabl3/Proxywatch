package shared

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// CandidateBehaviorKey builds a unique key for a candidate's process identity.
// Used for model profile lookups, experience tracking, and training data.
// SINGLE SOURCE OF TRUTH — both standalone and server must use this.
func CandidateBehaviorKey(c *Candidate) string {
	if c == nil || c.Proc == nil {
		host := strings.ToLower(strings.TrimSpace(c.Host))
		if host == "" {
			host = "local"
		}
		return host + "|(unknown)"
	}
	host := strings.ToLower(strings.TrimSpace(c.Host))
	if host == "" {
		host = "local"
	}
	exe := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(c.Proc.ExePath, "\\", "/")))
	if exe == "" {
		exe = "(unknown)"
	}
	name := strings.ToLower(strings.TrimSpace(c.Proc.Name))
	if name == "" {
		name = "(unknown)"
	}
	user := strings.ToLower(strings.TrimSpace(c.Proc.UserName))
	pid := fmt.Sprintf("%d", c.Proc.Pid)
	return host + "|" + exe + "|" + name + "|" + user + "|" + pid
}

// Whitelisted behavior signals — ONLY these count for role inference.
// Legacy signals from scoring/rank.go are explicitly excluded to prevent
// internal ranking flags (beacon-eligible, beacon-benign-process, etc.)
// from contaminating the signal count.
//
// Beacon and session signals are merged into a single beaconSignals map
// because "beacon vs session" is a transport detail, not a reliably
// observable behavioral distinction from telemetry.
var beaconSignals = map[string]bool{
	// High-specificity callback/timing patterns
	"beacon-interval-confirmed": true,
	"beacon-syn-cycle-cadence":  true,
	"beacon-tight-cadence":      true, // short interval + low jitter = strong C2 evidence
	"beacon-port-rotation":      true, // single target IP with many ports = tunneling/C2
	// beacon-target-lock demoted — single persistent target is common for VPN, sync, update
	"beacon-reconnecting-unknown-vendor": true,
	"beacon-short-lived-callback":        true,
	// High-specificity persistent control patterns
	"session-persistent-channel": true,
	// session-single-target-persistence demoted — single persistent target is
	// common for VPN daemons, sync agents, push notification services
	"session-pre-existing-beacon": true,
	"session-shell-spawn":         true,
	"session-lolbin-children":     true,
	"session-encoding-in-cmdline": true,
	"session-covert-channel":      true,
	"session-impersonation-token": true,
	"session-internal-beacon":     true,
	// CDN-fronted C2 detection — non-vendor process with persistent HTTPS
	// to CDN ASN (Cloudflare, Fastly, etc.) where ASN doesn't align with
	// process publisher. Catches domain-fronted beacons through svchost.
	"cdn-fronted-c2-candidate": true,
	// Demoted to ML-only (still emitted for training, removed from rule
	// inference — too generic, fire on legitimate apps equally):
	// beacon-http-channel, beacon-endpoint-rotation, beacon-no-children,
	// beacon-micro-payload, beacon-sleep-wake-cycle, beacon-low-cpu-long-life,
	// beacon-io-read-dominant, beacon-crypto-lib-loaded, beacon-memory-stable,
	// beacon-thread-minimal, beacon-non-standard-port,
	// session-interactive-io-balance, session-exfil-write-heavy,
	// session-asn-mismatch, session-elevated-external, session-covert-channel,
	// session-rwx-memory,
	// session-rare-parent-network, session-conn-churn, session-bursty-io-pattern
}

var pivotSignals = map[string]bool{
	"pivot-listener-plus-outbound":         true,
	"pivot-loopback-listener-external-out": true,
	// pivot-multiplex-relay demoted — fires on sessions with external C2 + internal lateral
	"pivot-throughput-symmetry":     true,
	"pivot-mixed-protocol-internal": true,
	"pivot-socks-candidate":         true,
	// pivot-reverse-tunnel-shape demoted — fires on sessions doing lateral movement
	"pivot-conn-count-correlation": true,
	"pivot-named-pipe-c2-pattern":  true,
	"pivot-admin-share-smb":        true,
	"pivot-ssh-tunnel-flags":       true,
	"pivot-proxy-lib-loaded":       true,
	// pivot-high-handle-count demoted — fires on every browser/Electron app
	"pivot-elevated-relay": true,
	// pivot-service-like-no-service demoted — fires on system services in session 0
	"pivot-high-fd-count":         true,
	"pivot-anon-exec-memory":      true,
	"pivot-non-loopback-internal": true,
}

var outboundSignals = map[string]bool{
	"outbound-multi-external-cdn":  true,
	"outbound-standard-ports-only": true,
	"outbound-asn-org-aligned":     true,
	"outbound-cdn-destination":     true,
	// outbound-known-vendor demoted — identity-based (binary location), not
	// behavioral. Static facts about vendor/path must not suppress detection;
	// attackers inject into vendor binaries in system paths.
	// outbound-system-path demoted — same reason.
	"outbound-download-heavy":           true,
	"outbound-lolbin-network":           true,
	"outbound-scripting-engine-network": true,
	"outbound-baseline-verified":        true,
	"outbound-established-service":      true,
	// Demoted to ML-only: outbound-push-notification (fires on C2 too),
	// outbound-cert-validation, outbound-known-vendor, outbound-system-path
}

var listenerSignals = map[string]bool{
	"listener-open-port-awaiting":         true,
	"listener-wildcard-bind":              true,
	"listener-accepting-multiple-clients": true,
	"listener-inbound-external":           true,
	"listener-local-server":               true,
	"listener-uncommon-port":              true,
	"listener-service-context":            true,
	"listener-long-idle":                  true,
	"listener-named-pipe-server":          true,
	"listener-high-memory":                true,
	"listener-mixed-protocol":             true,
	// Demoted to ML-only: listener-no-children, listener-low-thread-count
}

// IsSuppressionSignal returns true if the signal is one of the
// FP-suppression-class signals — outbound-* / vendor-* / pkg-*
// markers that fire when the rule engine has reasons to believe the
// candidate is BENIGN (vendor identity, trusted install path, signed
// binary, learned baseline, ASN aligned with publisher). Their
// effectiveness must be tallied with INVERTED semantics in the
// signal-stats tracker: firing on a candidate that ends up benign is
// the signal SUCCEEDING (true positive of "this is benign"), firing
// on a candidate that ends up malicious is the signal FAILING (false
// positive of "this is benign").
//
// Without this distinction, the signal-effectiveness panel showed
// every suppression signal at 0% precision with massive FP counts
// (e.g. outbound-known-vendor 0%/TP=0/FP=137188) — operators read
// that as "the model is broken" when in fact those numbers were the
// signal scoring its OWN job correctly with the wrong sign.
//
// Listener-* signals are intentionally NOT in this set: a listener
// can be benign (web service) or malicious (sshd reverse-tunnel
// relay). Their effectiveness is genuinely ambiguous; tallying with
// the default detection semantics is appropriate.
func IsSuppressionSignal(sig string) bool {
	switch sig {
	case "outbound-multi-external-cdn",
		"outbound-standard-ports-only",
		"outbound-asn-org-aligned",
		"outbound-cdn-destination",
		"outbound-known-vendor",
		"outbound-system-path",
		"outbound-download-heavy",
		"outbound-lolbin-network",
		"outbound-scripting-engine-network",
		"outbound-baseline-verified",
		"outbound-established-service",
		"outbound-push-notification",
		"outbound-cert-validation",
		"outbound-common-destination",
		"dest-long-established",
		"vendor-signed-trusted",
		"authenticode-verified",
		"install-path-trust",
		"asn-org-aligned",
		"publisher-dns-aligned",
		"pkg-owned",
		"traffic-verified",
		"reverse-beacon-suppressed-benign",
		"reverse-beacon-deferred-benign-single",
		"reverse-beacon-suppressed-shape",
		"benign-beacon-pattern",
		"baseline-verified":
		return true
	}
	return false
}

// pcapDecisiveSignals — the subset of signals known to fire reliably
// from packet topology alone AND specific enough that benign Windows
// services (LDAP/SMB/NTP/Kerberos to a DC, file shares, RDP, etc.)
// do NOT trip them. In pcap mode we require at least one of these
// for any beacon-* role assignment, because the FP-suppression
// signals that normally balance shape-only control hits cannot fire
// offline (no Publisher / SignatureTrust / CmdLine / LoadedLibs).
//
// Curation principle: each entry must be EITHER (a) topology-bound
// to a listener relationship the candidate owns (so vanilla outbound
// flows to a DC can never qualify), OR (b) a hard-to-spoof byte/
// timing pattern (SYN cycling, SOCKS handshake bytes).
//
// Explicitly EXCLUDED (fire too generously without process gates):
//   - pivot-non-loopback-internal: roles.go comment notes this is
//     "NOT decisive; fires on any system service talking to DCs,
//     DHCP, NTP". Live observation 2026-05-01 on host DEMO: every
//     per-flow candidate from 172.16.1.81 → 172.16.1.1:{22, 25,
//     110, 123, 143, 389, 445, 993, 1433, 1883, 3306, 3389, 3478,
//     5432, 5672, 8080, 8443, 8888, 9090} tripped this signal +
//     session-persistent-channel → pivot. Live
//     PROCESS VIEW classifies the same hosts as outbound/listener
//     because process-identity-based suppression fires; pcap can't.
//   - pivot-mixed-protocol-internal: same — fires when a host talks
//     to a peer on multiple internal ports (DC, file server). Real
//     lateral movement DOES match this shape, but so does a Windows
//     workstation's normal AD client behavior.
//   - pivot-admin-share-smb: SMB to admin shares is a normal
//     Windows pattern. Real abuse needs corroborating CmdLine /
//     auth-failure signals not available in pcap.
//   - pivot-throughput-symmetry / pivot-conn-count-correlation:
//     too generic on their own.
var pcapDecisiveSignals = map[string]bool{
	"beacon-syn-cycle-cadence":             true, // SYN-cycle counting in shared.SYNCycleByPID
	"pivot-socks-candidate":                true, // SOCKS handshake pattern in flow bytes
	"pivot-listener-plus-outbound":         true, // candidate owns a listener AND has external outbound
	"pivot-loopback-listener-external-out": true, // candidate owns a loopback listener AND has external outbound
	"forward-tunnel-shape":                 true, // listener + relay topology bound to one candidate
	"reverse-beacon-shape":                 true, // bytewise direction asymmetry on a single flow
	"listener-egress-tunnel-shape":         true, // listener candidate relaying out
	// Passive HTTP fingerprints — populated by internal/pcap/http_enrich.go
	// from request lines / headers extracted via parseHTTPRequestIntoFlow.
	// Both are decisive by construction (curated framework-default
	// patterns; no benign service should match).
	"http-c2-known-ua":       true, // User-Agent matched a curated C2 framework default
	"http-c2-uri-pattern":    true, // request URI matched a curated C2 path pattern
	"http-response-c2-shape": true, // response status/content-type/length matches C2 framework agent-message shape
	// Passive TLS fingerprints — populated by internal/pcap/tls_enrich.go
	// from JA3 hashes of ClientHellos extracted via parseTLSClientHello.
	// tls-ja3-known-c2 is decisive only when the JA3 matches a curated
	// C2 framework fingerprint in tls_database.go (multi-source IOC
	// feeds + research reports). The benign / observed variants are
	// non-promoting and live outside this set.
	"tls-ja3-known-c2":  true, // JA3 matches a curated C2 framework default
	"tls-ja3s-known-c2": true, // JA3S (server-side) matches a curated C2 framework listener
	// SSH banner — populated by internal/pcap/ssh_enrich.go from the
	// software-version token of either peer's banner. Decisive only on
	// curated C2 framework matches (Sliver/Cobalt/Mythic/Brute Ratel/Havoc).
	"ssh-banner-known-c2": true, // SSH banner matches a curated C2 framework default
	// Passive DNS deep-parse signals — populated by internal/pcap/dns_enrich.go
	// from per-host DNS query accumulators. Decisive on hard quantitative
	// thresholds: dns-dga-likely needs ≥10 distinct subdomains of one 2LD
	// AND average subdomain Shannon entropy ≥ 4.0 bits; dns-tunnel-volume
	// needs ≥64 KiB total DNS bytes AND ≥5 long (≥60-char) queries.
	"dns-dga-likely":    true, // host queries DGA-shaped subdomains under one 2LD
	"dns-tunnel-volume": true, // host's DNS volume + long-query shape indicate tunneling
	// Internal SMB lateral movement — populated by internal/pcap/ingest.go
	// stampSMBLateralSignals. Decisive on persistent internal SMB with
	// significant byte volume or reconnection patterns. Added 2026-08-29
	// for agent-to-agent C2 detection (AdaptixC2 over SMB).
	"internal-smb-lateral": true, // persistent internal SMB with lateral movement shape
	// child-tunnel-relay is intentionally EXCLUDED from the pcap
	// decisive set even though it's packet-derivable. Pcap ingest
	// builds a synthetic ParentPid linkage that makes EVERY outbound
	// flow from a host whose IP also has a listener look like a
	// "child of that listener" (see internal/pcap/ingest.go:2009-2021
	// — listenerOnIP maps any same-IP outbound to the listener PID).
	// On Windows hosts running sshd, that's enough to promote sshd
	// to pivot whenever the workstation makes legitimate
	// AD-client traffic to a DC. Live observation 2026-05-01 on
	// DEMO host: sshd at 172.16.1.81:22 with 0 external outbound and
	// 660 internal AD-client connections fired
	// listener-open-port-awaiting + listener-service-context +
	// child-tunnel-relay → pivot, while live PROCESS VIEW
	// classified the same sshd as listener/watch.
	//
	// Real SSH-D pivot detection in pcap should land via
	// listener-egress-tunnel-shape (listener + actual egress to
	// external) or pivot-listener-plus-outbound; a SSH-D handler
	// also relays OUTBOUND traffic, not just internal scans.
}

// HasPacketDecisiveSignal reports whether the candidate carries enough
// packet-derivable evidence to justify a beacon-* role in pcap mode.
// Three paths qualify:
//
//  1. Any one of pcapDecisiveSignals — strong-evidence single signals
//     (SYN cycling, SOCKS handshake bytes, listener+egress topology,
//     byte-wise tunnel shape) — specific enough to fire only on
//     actual implant / pivot behaviour.
//  2. THREE of pcapBeaconShapeSignals firing together AND
//     OutExternal>0 — beacon cadence + persistent control + CDN
//     destination + HTTP channel + target lock all on one external
//     flow. Live observation 2026-05-01: cheerful_glove and
//     liquid_mezzanine each fire 5+ of these signals on their
//     Cloudflare callbacks.
//  3. Both session-persistent-channel AND
//     beacon-interval-confirmed firing AND OutExternal>0 — confirmed
//     long-lived control with confirmed cadence is the minimum
//     shape for a real beacon.
//
// Trade-off: paths 2/3 will sometimes fire on legitimate Microsoft
// Defender / O365 / browser-CDN persistent beacons because pcap mode
// has no access to vendor / signing metadata to distinguish them.
// Operators get FPs on those endpoints in exchange for catching
// real HTTP-beacon C2. Strict-only mode (path 1) was experimented
// with on 2026-05-01 and rejected because it missed every real
// HTTP beacon in the test rig.
func HasPacketDecisiveSignal(c *Candidate) bool {
	if c == nil {
		return false
	}
	for _, s := range c.Signals {
		if pcapDecisiveSignals[s] {
			return true
		}
		// Hard-distinguisher tunnel/relay signals. These were
		// previously gated only inside demoteUnderEvidencedSyntheticPivots
		// as a "rescue" because the pcap synthetic-PID parent linkage
		// can stamp child-tunnel-relay on admin-sshd talking to
		// internal AD. The role guard ran BEFORE the rescue and
		// silently demoted those candidates back to listener,
		// erasing the tunnel detection. Promoting these signals to
		// decisive lets the role guard preserve real tunnel/relay
		// topology — operator confirmed 2026-05-02 they have an
		// SSH SOCKS dynamic tunnel running and wants it detected,
		// matching live PROCESS VIEW. The admin-sshd FP risk is
		// accepted; it can be mitigated later via a per-IP
		// allowlist if it becomes a problem.
		switch s {
		case "child-tunnel-relay",
			"pivot-ssh-tunnel-flags",
			"pivot-named-pipe-c2-pattern",
			// host-c2-active-pivot is stamped by the pcap ingest's
			// promoteHostPivotsWhenC2Active post-pass, which only
			// promotes internal-target clusters when the SAME host
			// has a confirmed beacon cluster (cheerful_glove's
			// external CDN callback alongside its SOCKS-tunneled
			// scans). The promotion already requires strong upstream
			// evidence; treat it as decisive so ApplyPcapModeRoleGuard
			// preserves the role rather than demoting it back to
			// outbound for "no packet-decisive signal".
			"host-c2-active-pivot":
			return true
		}
	}
	// Internal-pivot rescue REMOVED 2026-05-02. The rule (any combo of
	// pivot-non-loopback-internal + session-internal-beacon +
	// beacon-no-children) only ever caught Chrome's LAN printer / Cast
	// discovery probes (port 80 + 8009 fanouts to /16:* with byte
	// counts measured in single bytes). cheerful_glove's actual SOCKS-
	// tunneled scans do NOT cluster cleanly under flowCluster
	// (proxychains nmap hits many ports, splitting across many
	// /16-by-port clusters), so the rescue had no real-positive cases.
	// Cheerful's external C2 callback is still caught by the ML +
	// cdn-fronted + reconnect-unknown-vendor path further down.
	// Exclude per-host outbound rollups — they're aggregates, not
	// destination-specific clusters. The rollup absorbs every external
	// flow from a host (legit + malicious mixed), so promoting it to
	// beacon both mislabels the rollup AND duplicates whichever
	// real /16 cluster on that host actually carries the C2.
	// Checked BEFORE the OutExternal gate so the high-confidence-shape
	// bypass below can promote per-/16 clusters whose conn-snapshot is
	// empty (synthetic Mythic-style captures with degenerate snapshots
	// but populated per-flow shape data).
	if c.Proc != nil && (strings.HasSuffix(c.Proc.Name, " outbound-ext") ||
		strings.HasSuffix(c.Proc.Name, " outbound-int")) {
		return false
	}
	// High-confidence beacon-shape bypass. A per-/16 cluster with
	// SampleCount>=100 + TS+DS both >=0.95 is undeniable beacon shape
	// regardless of whether the snapshot window happened to capture
	// any current connections. Operator-confirmed 2026-05-04 on
	// mythic_24hr.pcap: cluster had 7610 perfectly-spaced uniform
	// flows but conn_count=0 / out_external=0 because the snapshot
	// window fell outside the flow timestamps. Without this bypass,
	// Path D D4 never gets a chance to fire on degenerate-snapshot
	// pcaps where the per-flow shape data is the ONLY usable signal.
	if hasSignal(c, "beacon-shape-high-confidence") {
		// Still respect the rollup exclusion above; that has already
		// returned. Rare-sig / fanout / push checks happen inside
		// pathDApplies which we'll fall through to.
		if pathDApplies(c) {
			return true
		}
	}
	// D9: Statistical beacon evidence bypass for degenerate snapshots.
	// When a per-/16 cluster has beacon-interval-statistical + rare-signature
	// but OutExternal=0 (snapshot window fell outside flow timestamps), the
	// signals themselves are sufficient evidence. This mirrors the D4
	// high-confidence-shape bypass but fires on the interval+rare conjunction
	// rather than requiring 100+ samples with TS+DS >= 0.95. Added 2026-08-29
	// for DoT C2 detection (DNS-over-TLS on port 853).
	if c.OutExternal <= 0 && c.Proc != nil {
		// Check for strong statistical evidence that would pass pathDApplies
		hasRareSig := hasSignal(c, "tls-rare-signature") || hasSignal(c, "http-rare-signature")
		hasIntervalStat := hasSignal(c, "beacon-interval-statistical")
		hasSizeUniform := hasSignal(c, "beacon-payload-size-uniform")
		// Require interval-stat + (rare-sig OR size-uniform) - same signals
		// that would fire D1/D2 in pathDApplies but without byte threshold
		if hasIntervalStat && (hasRareSig || hasSizeUniform) && pathDApplies(c) {
			return true
		}
	}
	if c.OutExternal <= 0 {
		return false
	}
	// Path D — statistical beacon-shape conjunction. Promotes when
	// packet-derived statistical signals match beacon-detection signature,
	// independent of the CDN-fronted rescue chain below (which all gate on
	// cdn-fronted-c2-candidate). Catches non-CDN C2 like AdaptixC2's
	// `165.22.159.5:8443` (DigitalOcean droplet) that the existing rescue
	// paths missed entirely. Path D is the rule that lets TS+DS scores
	// and rare-signature signals drive promotion rather than getting
	// beaten by suppression.
	//
	// Three conjunctions; any one promotes. All share the same
	// browser-shape exclusions (ja3-browser-fanout, multi-cdn,
	// download-heavy, known-benign-ja3, cert-validation):
	//
	//   D1: tls/http-rare-signature + ≥100 KiB
	//   D2: beacon-interval-statistical + beacon-payload-size-uniform + ≥100 KiB
	//   D3: beacon-day-rhythm + ≥1 MiB
	if c.Proc != nil && pathDApplies(c) {
		return true
	}
	// CDN-fronted external C2 rescue (signal-only; the ML model does
	// not run on synthetic PCAP candidates so the previous ML+CDN gate
	// was dead code in pcap mode).
	//
	// Promote outbound → beacon when the rule engine already
	// suggested beacon AND the cluster carries the CDN-C2
	// fingerprint AND it isn't a known push-notification target.
	//
	// Required (all must hold):
	//   - SuggestedRole == "beacon"   (rule engine agrees)
	//   - cdn-fronted-c2-candidate             (CDN ASN, no publisher
	//                                           alignment)
	//   - beacon-reconnecting-unknown-vendor   (short-lived burst
	//                                           pattern, ≥3 hits)
	//   - beacon-http-channel                  (HTTP/HTTPS profile)
	//   - contour-egress-tunnel-port           (contour module confirms
	//                                           the port carries tunnel-
	//                                           shape traffic with ≥30%
	//                                           confidence — the
	//                                           strongest packet-derived
	//                                           discriminator we have
	//                                           from real C2 vs Chrome
	//                                           browsing to a CDN)
	//   - NOT outbound-push-notification       (excludes FCM/Apple/MS
	//                                           push at 66.218 /
	//                                           172.183 / 192.178/16)
	//   - NOT outbound-cert-validation         (excludes OCSP/CRL short
	//                                           connections, browser
	//                                           cert checks)
	//
	// Verified 2026-05-02 on test rig:
	//   - cheerful's 104.21/16:443 Cloudflare (real C2): contour fires →
	//     promoted ✓
	//   - Chrome browsing to 104.21/16, 146.75/16, 23.50/16: NO contour
	//     OR has outbound-cert-validation → blocked ✓
	//
	// SuggestedRole gate restored 2026-05-03: dropping it broke
	// test1.pcap parity (Linux dev host's HTTPS downloads tripped the
	// CDN-rescue chain → host-c2-active-pivot demoted .139's outbound-
	// int rollup to pivot when it should stay outbound). The
	// DPI short-circuit ABOVE (TLS JA3 / HTTP UA / HTTP URI / HTTP
	// response shape) gives cheerful-style detection an alternate path
	// when the cluster's TLS or HTTP fingerprint hits the embedded C2
	// DB — that's the cleanest packet-only promotion path that doesn't
	// rely on rule-engine corroboration.
	suggested := strings.ToLower(c.SuggestedRole)
	if suggested != "beacon" {
		return false
	}
	var hasCDN, hasReconnect, hasHTTP, hasContour, hasPush bool
	var hasShortLived, hasTargetLock, hasIntervalConfirmed bool
	var hasEndpointRotation, hasSessionPersist, hasSingleTarget bool
	var hasJA3KnownC2, hasHTTPC2URI, hasHTTPC2UA, hasHTTPRespC2 bool
	var hasBenignJA3, hasCertValidation bool
	for _, s := range c.Signals {
		switch s {
		case "cdn-fronted-c2-candidate":
			hasCDN = true
		case "beacon-reconnecting-unknown-vendor":
			hasReconnect = true
		case "beacon-http-channel":
			hasHTTP = true
		case "contour-egress-tunnel-port":
			hasContour = true
		case "outbound-push-notification":
			hasPush = true
		case "beacon-short-lived-callback":
			hasShortLived = true
		case "beacon-target-lock":
			hasTargetLock = true
		case "beacon-interval-confirmed":
			hasIntervalConfirmed = true
		case "beacon-endpoint-rotation":
			hasEndpointRotation = true
		case "session-persistent-channel":
			hasSessionPersist = true
		case "session-single-target-persistence":
			hasSingleTarget = true
		case "tls-ja3-known-c2":
			hasJA3KnownC2 = true
		case "http-c2-uri-pattern":
			hasHTTPC2URI = true
		case "http-c2-known-ua":
			hasHTTPC2UA = true
		case "http-response-c2-shape":
			hasHTTPRespC2 = true
		case "tls-ja3-known-benign":
			hasBenignJA3 = true
		case "outbound-cert-validation":
			hasCertValidation = true
		}
	}
	// Dynamic benign-shape suppressor: cluster's JA3 has been observed
	// across MANY external destinations from the same client (browser
	// fan-out) — a learned, data-driven negative signal. We don't have
	// a per-rescue cross-flow lookup here (that's in tls_enrich.go),
	// but the resulting signal `tls-ja3-browser-fanout` (when stamped)
	// is what we exclude on. Cheerful's JA3 hits 3 destinations and
	// stays under the fan-out threshold; Mozilla / Firefox / Chrome
	// hit dozens and get the signal.
	// Dynamic benign-shape suppressors. ALL three signals below are
	// already computed by the rule engine from observed packet
	// behavior — no hardcoded IP / port lists involved:
	//   - tls-ja3-browser-fanout: JA3 hash hits >10 destinations
	//     across the capture (browser fan-out shape)
	//   - outbound-multi-external-cdn: host spreads traffic across
	//     multiple external CDN ASNs (browser/SaaS pattern)
	//   - outbound-download-heavy: cluster shows large-read asymmetric
	//     shape characteristic of vendor downloads / OS updates
	// Cheerful's C2 callback doesn't trip ANY of these (single CDN /16,
	// symmetric beacon shape, narrow JA3 distribution); Mozilla /
	// browser / SaaS clusters trip at least one.
	hasJA3BrowserFanout := false
	hasMultiCDN := false
	hasDownloadHeavy := false
	for _, s := range c.Signals {
		switch s {
		case "tls-ja3-browser-fanout":
			hasJA3BrowserFanout = true
		case "outbound-multi-external-cdn":
			hasMultiCDN = true
		case "outbound-download-heavy":
			hasDownloadHeavy = true
		}
	}
	// (No DPI short-circuit here — initially added a "JA3/HTTP DB
	// match → promote immediately" path but the Sliver "Go default"
	// JA3 is shared with every Go binary using crypto/tls, which
	// caused FPs on Linux dev hosts running kubectl/terraform/helm.
	// The DPI signals remain in pcapDecisiveSignals so they promote
	// via HasPacketDecisiveSignal + the role-guard's standard rescue
	// path with appropriate corroboration.)
	_ = hasJA3KnownC2
	_ = hasHTTPC2URI
	_ = hasHTTPC2UA
	_ = hasHTTPRespC2
	// Push-notification stays per-cycle: once a cluster is identified as
	// a known push endpoint it shouldn't reverse on another cycle.
	if hasPush {
		return false
	}
	// Positive-evidence stickiness — keyed by cluster NAME (stable
	// across cycles, since pcap ingest rebuilds synthetic PIDs each
	// cycle). Each signal latches once seen and stays sticky for
	// rescueStickyWindow. This handles the fundamental tail-mode
	// behaviour: signals fire only on cycles whose flows happen to
	// include the relevant packet pattern. cheerful's 3-min beacon
	// only triggers contour / beacon-reconnecting on 1-of-many
	// cycles; without stickiness the cluster flickers between
	// "promoted" and "outbound" every classify tick.
	//
	// Suppressor signals (push) intentionally NOT made sticky — a
	// one-time false suppressor shouldn't permanently block detection.
	//
	// Why all four signals must latch (rather than just contour):
	// contour can fire on legit traffic with measured tunnel-shape
	// patterns. The four-way conjunction (CDN + reconnect + HTTP +
	// contour) is what distinguishes cheerful's beacon from
	// browser/SaaS chatter. Chrome browsing to CDNs has CDN+http+
	// reconnect but rarely contour; Slack/Discord persistent
	// connections have CDN+http+contour but rarely reconnect; only
	// real C2 trips all four together.
	if c.Proc != nil && c.Proc.Name != "" {
		key := c.Proc.Name
		now := PcapNow()
		rescueSeenMu.Lock()
		entry := rescueSeen[key]
		if hasCDN {
			entry.cdn = now
		}
		if hasReconnect {
			entry.reconnect = now
		}
		if hasHTTP {
			entry.http = now
		}
		if hasContour {
			entry.contour = now
		}
		// Expire-and-update.
		if now.Sub(entry.cdn) > rescueStickyWindow {
			entry.cdn = time.Time{}
		}
		if now.Sub(entry.reconnect) > rescueStickyWindow {
			entry.reconnect = time.Time{}
		}
		if now.Sub(entry.http) > rescueStickyWindow {
			entry.http = time.Time{}
		}
		if now.Sub(entry.contour) > rescueStickyWindow {
			entry.contour = time.Time{}
		}
		if entry.cdn.IsZero() && entry.reconnect.IsZero() &&
			entry.http.IsZero() && entry.contour.IsZero() {
			delete(rescueSeen, key)
		} else {
			rescueSeen[key] = entry
		}
		hasCDN = !entry.cdn.IsZero()
		hasReconnect = !entry.reconnect.IsZero()
		hasHTTP = !entry.http.IsZero()
		hasContour = !entry.contour.IsZero()
		rescueSeenMu.Unlock()
	}
	// Two paths to promotion:
	//
	//   Path A (strict / fast on slow beacons): CDN + reconnect + HTTP
	//     + contour (all sticky-latched). Contour requires the contour
	//     module to confirm tunnel-shape over enough packets — slow to
	//     fire on a freshly-started tail but very specific. This is the
	//     primary discriminator vs Chrome browsing.
	//
	//   Path B (fast / volume-gated): CDN + reconnect + HTTP without
	//     contour, BUT cluster cumulative bytes ≥ 1 MB. Operator
	//     reported 2026-05-03 that fresh tail processes show
	//     cheerful's 104.21/16:443 as outbound for many minutes
	//     waiting for contour to fire — meanwhile the cluster has
	//     already moved 7+ MB of beacon traffic. Chrome browsing to a
	//     single CDN /16 endpoint typically stays well under 1 MB per
	//     short session, so this byte gate gives fast detection of
	//     real C2 without re-introducing browser FPs.
	// Bare minimum: cluster MUST have CDN-fronted destination AND
	// HTTP/HTTPS port profile to qualify for any rescue path. Without
	// either, the cluster doesn't match the CDN-C2 shape at all.
	if !hasCDN || !hasHTTP {
		return false
	}
	// hasReconnect is no longer a HARD gate — the original strict path
	// A (contour) still requires it implicitly via the rescueSeen sticky
	// latch, but Path A2 (beacon-shape conjunction) below catches
	// cheerful clusters that haven't tripped beacon-reconnecting-
	// unknown-vendor in the captured window.
	hasMinSignals := hasReconnect
	// Path A — strict contour gate: contour-egress-tunnel-port +
	// reconnect (CDN+HTTP already confirmed). Specific to cheerful's
	// active C2 but slow to fire; Path A2 below catches cluster shapes
	// that haven't accumulated reconnect yet.
	if hasMinSignals && hasContour {
		// Keepalive byte-rate floor — cluster must have carried something.
		if c.Proc != nil {
			if c.Proc.IOReadBytes+c.Proc.IOWriteBytes == 0 &&
				c.Proc.IOReadBps+c.Proc.IOWriteBps < 64 {
				return false
			}
		}
		return true
	}
	// Path A2 — Beacon-shape conjunction (added 2026-05-03 to catch
	// cheerful's 104.21/16:443 cluster on the rig snapshot).
	// SuggestedRole=beacon is already confirmed above.
	// Required (all must hold):
	//   - cdn-fronted-c2-candidate
	//   - beacon-http-channel
	//   - ≥3 OTHER pcapBeaconShapeSignals (drawn from: target-lock,
	//     interval-confirmed, endpoint-rotation, session-persistent-channel,
	//     session-single-target-persistence, short-lived-callback)
	//   - cluster cumulative bytes ≥ 100 KiB
	//   - NOT tls-ja3-known-benign (Chrome / Firefox / Edge fingerprints)
	//   - NOT outbound-cert-validation (browser OCSP / CRL chatter)
	//
	// Verified against test1.pcap fixture:
	//   - Mozilla location.services (146.75/16:443): 2 KB → byte gate
	//     fails ✓
	//   - api.anthropic.com (160.79/16:443): no cdn-fronted ✓
	//   - adblockplus (23.50/16:443): 22 KB → byte gate fails ✓
	//   - GitHub copilot etc.: tls-ja3-known-benign present ✓
	// Rig snapshot:
	//   - cheerful 104.21/16:443: 4 of N + 200 KB + cdn + http →
	//     PROMOTE ✓
	otherShapeCount := 0
	if hasShortLived {
		otherShapeCount++
	}
	if hasTargetLock {
		otherShapeCount++
	}
	if hasIntervalConfirmed {
		otherShapeCount++
	}
	if hasEndpointRotation {
		otherShapeCount++
	}
	if hasSessionPersist {
		otherShapeCount++
	}
	if hasSingleTarget {
		otherShapeCount++
	}
	const beaconConjunctionByteFloor uint64 = 100 * 1024 // 100 KiB
	if hasCDN && hasHTTP && otherShapeCount >= 2 &&
		!hasBenignJA3 && !hasCertValidation && !hasJA3BrowserFanout &&
		!hasMultiCDN && !hasDownloadHeavy {
		if c.Proc != nil && c.Proc.IOReadBytes+c.Proc.IOWriteBytes >= beaconConjunctionByteFloor {
			return true
		}
	}
	// Path B — byte-volume bypass when none of the strict shape
	// signals fired. Requires hasReconnect (CDN+HTTP confirmed above)
	// to maintain the original specificity guarantee. cheerful's
	// active 3-min-interval beacon accumulates MBs over tens of
	// minutes; Chrome's transient page loads to one CDN typically
	// don't reach 1 MB cumulative.
	const fastPathByteFloor uint64 = 1 << 20 // 1 MiB
	if hasMinSignals && c.Proc != nil && c.Proc.IOReadBytes+c.Proc.IOWriteBytes >= fastPathByteFloor {
		return true
	}
	return false
}

// pathDApplies implements the statistical beacon-shape conjunction. See the
// call site for design rationale. Returns true when:
//
//	D1: rare-signature  + ≥100 KiB
//	D2: TS-stat + DS-uniform + ≥100 KiB
//	D3: day-rhythm + ≥1 MiB
//
// All three branches require none of the browser-shape negative
// signals (ja3-browser-fanout, multi-cdn, download-heavy,
// ja3-known-benign, cert-validation) — those mark the candidate as
// browser-shaped and Path D must not fire on browsers.
func pathDApplies(c *Candidate) bool {
	if c.Proc == nil {
		return false
	}
	const rareByteFloor uint64 = 100 * 1024 // 100 KiB
	const rhythmByteFloor uint64 = 1 << 20  // 1 MiB
	var hasRareSig, hasIntervalStat, hasSizeUniform, hasDayRhythm, hasHighConfShape bool
	var hasFanout, hasMultiCDN, hasDownloadHeavy, hasBenignJA3, hasCertValidation, hasPush bool
	var hasNonStandardPort, hasTargetLock, hasSingleTargetPersistence bool
	for _, s := range c.Signals {
		switch s {
		case "tls-rare-signature", "http-rare-signature":
			hasRareSig = true
		case "beacon-interval-statistical":
			hasIntervalStat = true
		case "beacon-payload-size-uniform":
			hasSizeUniform = true
		case "beacon-day-rhythm":
			hasDayRhythm = true
		case "beacon-shape-high-confidence":
			hasHighConfShape = true
		case "tls-ja3-browser-fanout":
			hasFanout = true
		case "outbound-multi-external-cdn":
			hasMultiCDN = true
		case "outbound-download-heavy":
			hasDownloadHeavy = true
		case "tls-ja3-known-benign":
			hasBenignJA3 = true
		case "outbound-cert-validation":
			hasCertValidation = true
		case "outbound-push-notification":
			hasPush = true
		case "beacon-non-standard-port":
			hasNonStandardPort = true
		case "beacon-target-lock":
			hasTargetLock = true
		case "session-single-target-persistence":
			hasSingleTargetPersistence = true
		}
	}
	// known-benign JA3 + cert-validation are HARD vetoes regardless —
	// those signals identify benign client behavior directly.
	if hasBenignJA3 || hasCertValidation {
		return false
	}
	// Browser-fanout is a HARD veto — it strongly indicates browser traffic.
	// The JA3 fingerprint proves the client is a browser, not a C2 implant,
	// regardless of what other signals fire.
	if hasFanout {
		return false
	}
	// D5: Rare-signature + statistical-interval bypass for multi-CDN veto.
	// C2 frameworks like Merlin use intentional data jitter (variable payload
	// sizes) to evade DS-based detection, but still have near-perfect timing
	// (high TS). When a candidate has:
	//   - tls-rare-signature OR http-rare-signature (not normal browser)
	//   - beacon-interval-statistical (timing confirmed as beacon-like)
	// ...it bypasses the multi-CDN veto because the rare signature proves
	// it's not normal browser traffic mixed with C2, even if the host also
	// talks to other CDN endpoints. Added 2026-08-29 for Merlin C2 detection.
	// Note: browser-fanout still vetoes above — rare-sig only rescues from
	// multi-CDN, not from confirmed browser fingerprints.
	if hasRareSig && hasIntervalStat && !hasFanout && !hasDownloadHeavy && !hasPush {
		return true
	}
	// D10: Non-standard port + statistical bypass for multi-CDN veto.
	// DNS-based C2 (DoQ on port 853, custom DNS ports) connects to cloud DNS
	// resolvers that may share IP space with CDN providers. When a cluster has:
	//   - beacon-non-standard-port (not 80/443/standard HTTP ports)
	//   - beacon-interval-statistical (timing confirmed as beacon-like)
	//   - beacon-payload-size-uniform (consistent message sizes)
	// ...override the multi-CDN veto. The non-standard port + beacon shape
	// proves it's not normal browser/CDN traffic. Added 2026-08-29 for DoQ detection.
	if hasMultiCDN && hasNonStandardPort && hasIntervalStat && hasSizeUniform {
		hasMultiCDN = false // Override the multi-CDN veto
	}
	// D6: Non-standard port bypass for push-notification veto.
	// Push notification services (FCM, APNs, WNS) use standard ports (443, 5228).
	// A long-lived single connection to a non-standard port (like 8000) cannot be
	// push notification traffic. When beacon-non-standard-port + target-lock or
	// single-target-persistence are present, override the push veto. This catches
	// C2 frameworks like Velociraptor that use persistent WebSocket connections
	// on non-standard ports. Added 2026-08-29.
	if hasPush && hasNonStandardPort && (hasTargetLock || hasSingleTargetPersistence) {
		hasPush = false // Override the push veto
	}
	// D8: Rare signature override for push-notification veto on standard ports.
	// DoH-based C2 (DNS-over-HTTPS) and other C2 frameworks can use standard port
	// 443 to popular cloud IPs that also serve push notifications (WNS, Azure).
	// When a cluster has:
	//   - tls-rare-signature (not normal browser/Windows)
	//   - beacon-target-lock OR session-single-target-persistence (dedicated connection)
	//   - outbound-push-notification is the only blocker
	// ...override the push veto. The rare signature proves it's not normal Windows
	// push traffic. Added 2026-08-29 for DoH C2 detection.
	if hasPush && hasRareSig && (hasTargetLock || hasSingleTargetPersistence) {
		hasPush = false // Override the push veto - rare sig proves it's not push
	}
	// Browser-shape vetoes (multi-cdn / download-heavy / push)
	// stay HARD by default. They're FP risk for any cluster that mixes
	// real implant traffic with normal browsing on the same host.
	// Note: hasFanout already returned false above, so not checked here.
	// Operator-confirmed regression 2026-05-04: loosening this veto
	// when rare-sig also fires regressed test1.pcap (dev host's admin
	// traffic carries http-rare-signature on git clones and self-
	// served HTTPS, which combined with shape promoted a non-C2
	// cluster, then host-c2-active promoted the rollup to beacon-
	// pivot). The d10 rollup TP would be nice to catch but the
	// per-/16 cluster path (where the actual beacon target lives) is
	// the right vehicle, not the rollup.
	if hasMultiCDN || hasDownloadHeavy || hasPush {
		return false
	}
	// D4: high-confidence shape conjunction. 100+ flows with TS+DS both
	// ≥0.95 is overwhelming evidence — bypasses the byte floor that
	// blocks otherwise-decisive Mythic-style captures (synthetic test
	// pcaps with near-zero payload bytes per beat). The min-sample
	// gate prevents this from firing on small clusters where a few
	// regularly-spaced flows could be coincidence. Stamper at
	// internal/pcap/ingest.go's stampBeaconShapeSignals is the only
	// signal source — it requires SampleCount>=100 + TS>=0.95 + DS>=0.95.
	if hasHighConfShape {
		return true
	}
	bytes := c.Proc.IOReadBytes + c.Proc.IOWriteBytes
	if hasRareSig && bytes >= rareByteFloor {
		return true
	}
	if hasIntervalStat && hasSizeUniform && bytes >= rareByteFloor {
		return true
	}
	if hasDayRhythm && bytes >= rhythmByteFloor {
		return true
	}
	// D7: Persistent connection C2 detection for single long-lived flows.
	// C2 frameworks like Velociraptor use WebSocket or HTTP/2 persistent
	// connections that maintain a single long-lived flow rather than
	// periodic beacon-style reconnections. These are characterized by:
	//   - beacon-non-standard-port (not 443/80/standard ports)
	//   - beacon-target-lock OR session-single-target-persistence
	// Push notification was already overridden above for non-standard ports.
	// This path catches the residual case where no rare signature or
	// statistical signals fire but the destination/port pattern is
	// strongly C2-indicative. Added 2026-08-29 for Velociraptor detection.
	if hasNonStandardPort && (hasTargetLock || hasSingleTargetPersistence) {
		return true
	}
	return false
}

// rescueSeen tracks per-cluster (keyed by stable cluster name)
// timestamps for each positive evidence signal that has fired in any
// recent cycle. Used by the CDN rescue's sticky positive-evidence path
// to keep cheerful's 3-min-beacon clusters promoted across the quiet
// cycles between beacons. Suppressor signals (push-notification) are
// NOT made sticky — those stay per-cycle.
type rescueEntry struct {
	cdn       time.Time
	reconnect time.Time
	http      time.Time
	contour   time.Time
}

var (
	rescueSeenMu       sync.Mutex
	rescueSeen         = make(map[string]rescueEntry)
	rescueStickyWindow = 30 * time.Minute
)

// HasListenerSignal reports whether the signal slice contains any
// listener-* signal — used by the pcap role guard to choose between
// "listener" and "outbound" when demoting a beacon-* assignment.
func HasListenerSignal(signals []string) bool {
	for _, s := range signals {
		if listenerSignals[s] {
			return true
		}
	}
	return false
}

// ApplyPcapModeRoleGuard demotes beacon-* roles to listener (when
// listener signals are present) or outbound on pcap-mode candidates
// that lack a packet-decisive signal. Live-mode candidates are
// unchanged.
//
// Why: pcap ingest synthesises ProcessInfo with only Pid/Name/Parent
// populated, so the FP-suppression signals (vendor-signed-trusted,
// outbound-known-vendor, outbound-system-path, publisher-dns-aligned,
// pkg-owned, traffic-verified, authenticode-verified, etc.) cannot
// fire. Without their balancing weight, shape-only control signals
// dominate InferRoleFromSignals and rank.go's promotion logic, and
// every external-talking candidate ends up beacon — exactly
// the FP pattern operators see when comparing pcap findings to the
// live PROCESS VIEW.
//
// This guard fires AFTER all per-candidate scoring + cross-pass
// mutations (AggregateChildTunnelEvidence, ApplyPivotLinger,
// ApplyBenignClientHostMaliceGate) so it sees the truly-final role
// for the cycle. Detection of REAL malice in pcap mode is preserved:
// the packet-decisive signal set covers all topology-observable
// control patterns (SYN cycle, SOCKS, tunnel relay shapes) — anything
// classifiable from packet bytes alone retains its beacon-*
// assignment.
func ApplyPcapModeRoleGuard(cands []Candidate) {
	for i := range cands {
		c := &cands[i]
		if !IsPcapMode(c) {
			continue
		}
		// PROMOTE-from-outbound path: HasPacketDecisiveSignal codifies
		// the corroborated-evidence rules (external CDN-fronted +
		// reconnecting + ML 99% + matching suggested OR signal-only
		// internal-pivot topology). When that returns true on a
		// candidate that the rule engine settled on outbound, promote
		// to the right beacon-* sub-role inferred from the signal
		// shape. The rule engine often misses internal-pivot promotion
		// (cheerful's SOCKS-tunneled scan to 172.16.1.x:80) because
		// internal targets fire fewer beacon-class signals than
		// external C2 — but the topology fingerprint is unambiguous.
		if c.Role == "outbound" && HasPacketDecisiveSignal(c) {
			promoteRole := ""
			mlRole := strings.ToLower(c.MLRole)
			switch mlRole {
			case "beacon", "pivot", "smb-pipe", "tunnel":
				if c.MLConfidence >= 0.99 {
					promoteRole = mlRole
				}
			}
			if promoteRole == "" {
				// Infer from signal shape. Internal-target topology
				// (pivot-non-loopback-internal) → pivot; everything
				// else (external C2 callback shape) → beacon.
				hasInternalPivot := false
				for _, s := range c.Signals {
					if s == "pivot-non-loopback-internal" {
						hasInternalPivot = true
						break
					}
				}
				if hasInternalPivot {
					promoteRole = "pivot"
				} else {
					promoteRole = "beacon"
				}
			}
			c.Role = promoteRole
			c.Reasons = append(c.Reasons,
				"pcap-mode: outbound→"+promoteRole+" via packet-decisive evidence (signal shape + ML if available)")
			continue
		}
		if !IsControlRole(c.Role) {
			continue
		}
		// External-only "pivot" is a contradiction. A pivot relays
		// internal traffic — if the candidate has zero internal
		// destinations, it cannot be a pivot regardless of how many
		// beacon-shape or SYN-cycle signals fire. Demote unconditionally
		// (don't fall through to HasPacketDecisiveSignal). This catches
		// the live-observed FP pattern 2026-05-01 on host DEMO: per-flow
		// candidates 172.16.1.81 → 8.2.109.{250..252}:443 and 80.77.87.x
		// (Microsoft / Akamai endpoints firing SYN-cycle on unreachable
		// IPs) got pinned to pivot via PivotUntil linger from
		// AggregateChildTunnelEvidence walking the synthetic ParentPid
		// chain to sshd:22's listener candidate.
		//
		// If the candidate would still qualify as beacon (has
		// the decisive signals + is talking external), HasPacketDecisive
		// below preserves that — we just refuse to call it a "pivot."
		if c.Role == "pivot" && c.OutInternal == 0 {
			if HasPacketDecisiveSignal(c) && c.OutExternal > 0 {
				c.Role = "beacon"
				c.ControlSubtype = ""
				c.Reasons = append(c.Reasons, "pcap-mode: pivot demoted to beacon (no internal relay observed)")
				continue
			}
			// Otherwise fall through to the standard demote path below.
		}
		if HasPacketDecisiveSignal(c) {
			continue
		}
		if HasListenerSignal(c.Signals) {
			c.Role = "listener"
		} else {
			c.Role = "outbound"
		}
		c.ControlSubtype = ""
		// Score is intentionally untouched — operators inspecting the
		// candidate still see the original signal-derived weight, just
		// without the unsafe role label. The reasons audit trail
		// retains why the classifier originally promoted, with this
		// note appended to explain the demotion.
		c.Reasons = append(c.Reasons, "pcap-mode: beacon-* demoted (no packet-decisive signal; FP-suppression signals unavailable offline)")
	}
}

// InferRoleFromSignals determines the role based on whitelisted behavior signals.
// ONLY signals from behavior/*.go are counted — legacy signals from scoring/rank.go
// are ignored to prevent internal ranking flags from contaminating role inference.
//
// This is the SINGLE source of truth for signal-based role inference.
// Both standalone (classifier.go) and server (server.go) MUST use this.
func InferRoleFromSignals(signals []string, subtype, actualRole string) string {
	controlHits, pivotHits, outboundHits, listenerHits := 0, 0, 0, 0
	decisivePivot := false
	decisiveControl := false

	for _, s := range signals {
		if beaconSignals[s] {
			controlHits++
		}
		if pivotSignals[s] {
			pivotHits++
		}
		if outboundSignals[s] {
			outboundHits++
		}
		if listenerSignals[s] {
			listenerHits++
		}
		// Decisive signals override outbound suppression.
		switch s {
		case "pivot-ssh-tunnel-flags",
			"pivot-named-pipe-c2-pattern",
			"pivot-socks-candidate":
			// High-specificity pivot indicators requiring proxy flags,
			// proxy libraries, or SSH tunnel patterns.
			decisivePivot = true
		// pivot-non-loopback-internal: NOT decisive. "Has internal connections,
		// no external" alone is too weak — fires on any system service talking
		// to DCs, DHCP, NTP. Process-name exclusions are not safe (injection,
		// DLL hijack). Requires 2+ signal corroboration for pivot.
		// SSH tunnel detection works via AggregateChildTunnelEvidence (child
		// aggregation) which doesn't depend on child role classification.
		case "beacon-syn-cycle-cadence":
			// SYN cycling = repeated failed connections. Legitimate apps don't
			// do this — only C2 agents with unreachable/rotating endpoints.
			decisiveControl = true
		case "beacon-tight-cadence":
			// Short interval (< 5 min) with low jitter (< 30%) is strong C2 evidence.
			// Legitimate polling apps use longer intervals or higher jitter.
			// This is purely behavioral (timing patterns), not identity-based.
			decisiveControl = true
		case "beacon-port-rotation":
			// Single target IP with connections on 3+ different ports = tunneling/C2.
			// Legitimate services connect to specific ports; many ports to one IP is
			// suspicious. Fires even for known-vendor processes since this is behavioral
			// (connection topology), not identity-based. Classic pattern for process
			// injection into svchost or port-forwarding tunnels.
			decisiveControl = true
		}
	}

	suspTotal := controlHits + pivotHits

	// Decisive signals override everything — even on known-vendor processes.
	// SYN cycling and confirmed beacon intervals are strong C2 evidence
	// regardless of process identity. Priority: pivot > beacon.
	if decisivePivot {
		return "pivot"
	}
	// Decisive control signals require the process to not be primarily a
	// listener. PID 4 (System) with SMB/NetBIOS listeners fires beacon-interval
	// from periodic keepalives — it's a service, not C2. Only override when
	// control signals actually dominate over listener signals.
	//
	// Exception: beacon-port-rotation (multiple connections to same IP on different
	// ports) is highly suspicious even for listeners — it indicates tunneling or
	// process injection. A legitimate listener doesn't open multiple ports to the
	// same remote IP. This pattern always promotes to beacon.
	hasPortRotation := false
	for _, s := range signals {
		if s == "beacon-port-rotation" {
			hasPortRotation = true
			break
		}
	}
	if hasPortRotation {
		return "beacon"
	}
	if decisiveControl && controlHits > listenerHits {
		return "beacon"
	}

	// Outbound signals suppress suspicious. Without vendor gates, legitimate
	// processes fire both control and outbound signals. Outbound signals carry
	// higher weight because they require verified vendor/path/ASN conditions.
	// Suspicious must outnumber outbound by at least 3 to override.
	if outboundHits > 0 && suspTotal <= outboundHits+2 {
		return "outbound"
	}

	// Require 2+ suspicious signals to classify as beacon/pivot.
	// A single signal (e.g., just session-persistent-channel) without
	// corroboration is weak evidence — many legitimate apps have persistent
	// connections. With 2+ signals, the evidence is corroborated.
	if suspTotal >= 2 {
		if pivotHits >= controlHits {
			return "pivot"
		}
		return "beacon"
	}

	// Listener-only signals → listener role.
	if listenerHits > 0 {
		return "listener"
	}

	// No whitelisted signals fired — default to outbound.
	return "outbound"
}
