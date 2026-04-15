package shared

import (
	"fmt"
	"strings"
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
// Beacon and session signals are merged into a single controlSignals map
// because "beacon vs session" is a transport detail, not a reliably
// observable behavioral distinction from telemetry.
var controlSignals = map[string]bool{
	// High-specificity callback/timing patterns
	"beacon-interval-confirmed":        true,
	"beacon-syn-cycle-cadence":          true,
	// beacon-target-lock demoted — single persistent target is common for VPN, sync, update
	"beacon-reconnecting-unknown-vendor": true,
	"beacon-short-lived-callback":       true,
	// High-specificity persistent control patterns
	"session-control-channel-persistent": true,
	// session-single-target-persistence demoted — single persistent target is
	// common for VPN daemons, sync agents, push notification services
	"session-pre-existing-control":       true,
	"session-shell-spawn":                true,
	"session-lolbin-children":            true,
	"session-encoding-in-cmdline":        true,
	"session-covert-channel":             true,
	"session-impersonation-token":        true,
	"session-internal-control":           true,
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
	"pivot-listener-plus-outbound":       true,
	"pivot-loopback-listener-external-out": true,
	// pivot-multiplex-relay demoted — fires on sessions with external C2 + internal lateral
	"pivot-throughput-symmetry":           true,
	"pivot-mixed-protocol-internal":       true,
	"pivot-socks-candidate":              true,
	// pivot-reverse-tunnel-shape demoted — fires on sessions doing lateral movement
	"pivot-conn-count-correlation":        true,
	"pivot-named-pipe-c2-pattern":         true,
	"pivot-admin-share-smb":              true,
	"pivot-ssh-tunnel-flags":             true,
	"pivot-proxy-lib-loaded":             true,
	// pivot-high-handle-count demoted — fires on every browser/Electron app
	"pivot-elevated-relay":               true,
	// pivot-service-like-no-service demoted — fires on system services in session 0
	"pivot-high-fd-count":                true,
	"pivot-anon-exec-memory":             true,
	"pivot-non-loopback-internal":        true,
}

var outboundSignals = map[string]bool{
	"outbound-multi-external-cdn":      true,
	"outbound-standard-ports-only":     true,
	"outbound-asn-org-aligned":         true,
	"outbound-cdn-destination":         true,
	// outbound-known-vendor demoted — identity-based (binary location), not
	// behavioral. Static facts about vendor/path must not suppress detection;
	// attackers inject into vendor binaries in system paths.
	// outbound-system-path demoted — same reason.
	"outbound-download-heavy":          true,
	"outbound-lolbin-network":          true,
	"outbound-scripting-engine-network": true,
	"outbound-baseline-verified":       true,
	"outbound-established-service":     true,
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

// IsControlSignal returns true if the signal is in the controlSignals or pivotSignals map.
func IsControlSignal(sig string) bool {
	return controlSignals[sig] || pivotSignals[sig]
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
		if controlSignals[s] {
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
		// DLL hijack). Requires 2+ signal corroboration for control-pivot.
		// SSH tunnel detection works via AggregateChildTunnelEvidence (child
		// aggregation) which doesn't depend on child role classification.
		case "beacon-syn-cycle-cadence":
			// SYN cycling = repeated failed connections. Legitimate apps don't
			// do this — only C2 agents with unreachable/rotating endpoints.
			// beacon-interval-confirmed is NOT decisive because legitimate apps
			// (Slack, CloudSync, auto-updaters) also poll on regular intervals.
			decisiveControl = true
		}
	}

	suspTotal := controlHits + pivotHits

	// Decisive signals override everything — even on known-vendor processes.
	// SYN cycling and confirmed beacon intervals are strong C2 evidence
	// regardless of process identity. Priority: pivot > control-channel.
	if decisivePivot {
		return "control-pivot"
	}
	// Decisive control signals require the process to not be primarily a
	// listener. PID 4 (System) with SMB/NetBIOS listeners fires beacon-interval
	// from periodic keepalives — it's a service, not C2. Only override when
	// control signals actually dominate over listener signals.
	if decisiveControl && controlHits > listenerHits {
		return "control-channel"
	}

	// Outbound signals suppress suspicious. Without vendor gates, legitimate
	// processes fire both control and outbound signals. Outbound signals carry
	// higher weight because they require verified vendor/path/ASN conditions.
	// Suspicious must outnumber outbound by at least 3 to override.
	if outboundHits > 0 && suspTotal <= outboundHits+2 {
		return "outbound"
	}

	// Require 2+ suspicious signals to classify as control-channel/pivot.
	// A single signal (e.g., just session-control-channel-persistent) without
	// corroboration is weak evidence — many legitimate apps have persistent
	// connections. With 2+ signals, the evidence is corroborated.
	if suspTotal >= 2 {
		if pivotHits >= controlHits {
			return "control-pivot"
		}
		return "control-channel"
	}

	// Listener-only signals → listener role.
	if listenerHits > 0 {
		return "listener"
	}

	// No whitelisted signals fired — default to outbound.
	return "outbound"
}
