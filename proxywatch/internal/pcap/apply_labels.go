package pcap

import (
	"strings"

	"proxywatch/internal/shared"
)

// applyPcapOperatorLabels runs after the post-pass role pipeline to
// hard-override classifier verdicts with operator-set labels. Three
// label classes apply in priority order (most-specific wins):
//
//  1. Cluster label (PcapOperatorLabel) — keyed on synthetic
//     cluster name. Network-bound; one rig's labels stay on that rig.
//  2. SNI label (PcapTLSLabel kind=sni) — keyed on TLS SNI hostname
//     observed in this cluster's flows. Portable across networks.
//  3. JA3 label (PcapTLSLabel kind=ja3) — keyed on JA3 hash. Most
//     portable but least specific (same JA3 may be used by many
//     processes).
//
// The first matching label wins. Cluster=benign overrides JA3=malicious;
// SNI=malicious overrides JA3=benign.
//
// Runs LAST in the post-pass chain so its verdict can't be undone by
// the role guard, demote, or host-c2-active-pivot promotion.
func applyPcapOperatorLabels(candidates []shared.Candidate) {
	for i := range candidates {
		c := &candidates[i]
		if c.Proc == nil || c.Proc.Name == "" {
			continue
		}
		if !IsSyntheticPID(c.Proc.Pid) {
			continue
		}
		// Resolve label hierarchy: cluster > SNI > JA3.
		match := resolveLabel(c)
		if match == nil {
			continue
		}
		switch match.verdict {
		case shared.VerdictMalicious:
			// Infer family from cluster name + signal shape:
			//   - listener-style ("pcap:<ip>:<port>") → pivot
			//   - rollup ("...outbound-int") → pivot
			//   - internal-prefix /16 cluster → pivot
			//   - everything else (external clusters) → beacon
			c.Role = inferLabeledMaliciousRole(c)
			c.SuggestedRole = c.Role
			c.Signals = appendUniqueSignal(c.Signals, "operator-label-malicious")
			c.Reasons = appendUniqueSignal(c.Reasons, match.maliciousReason())
			if match.reasonText != "" {
				c.Reasons = appendUniqueSignal(c.Reasons, "operator: "+match.reasonText)
			}
		case shared.VerdictBenign:
			c.Role = "outbound"
			c.SuggestedRole = "outbound"
			c.ActiveProxying = false
			// Strip the promotion signals that other code paths key on
			// to re-promote (host-c2-active-pivot, child-tunnel-relay,
			// host-c2-active-pivot, the four CDN-rescue signals). The
			// label is the operator's veto — without stripping these
			// the next cycle would just promote again.
			c.Signals = stripSignals(c.Signals,
				"host-c2-active-pivot",
				"operator-label-malicious",
			)
			c.Reasons = appendUniqueSignal(c.Reasons, match.benignReason())
			if match.reasonText != "" {
				c.Reasons = appendUniqueSignal(c.Reasons, "operator: "+match.reasonText)
			}
		}
	}
}

// labelMatch is the resolved verdict from the priority-ordered lookup
// (cluster > SNI > JA3). The source identifies which label class the
// verdict came from so the reason string can be specific.
type labelMatch struct {
	source     string // "cluster" | "sni" | "ja3"
	verdict    string
	reasonText string
}

func (m *labelMatch) maliciousReason() string {
	switch m.source {
	case "sni":
		return "pcap-tls-label:malicious(sni)"
	case "ja3":
		return "pcap-tls-label:malicious(ja3)"
	default:
		return shared.PcapOperatorLabelMaliciousReason
	}
}

func (m *labelMatch) benignReason() string {
	switch m.source {
	case "sni":
		return "pcap-tls-label:benign(sni)"
	case "ja3":
		return "pcap-tls-label:benign(ja3)"
	default:
		return shared.PcapOperatorLabelBenignReason
	}
}

// resolveLabel walks the label hierarchy for a candidate:
//  1. cluster (most specific) — pcap_operator_labels by cluster_name
//  2. SNI — pcap_tls_labels keyed on a SNI extracted from the
//     candidate's Reasons (the TLS enrich pass stamps "TLS SNI: ...")
//  3. JA3 — pcap_tls_labels keyed on a JA3 hash extracted from the
//     candidate's Reasons (the TLS enrich pass stamps "TLS JA3 ...")
//
// Returns nil when no label matches.
func resolveLabel(c *shared.Candidate) *labelMatch {
	if c == nil || c.Proc == nil {
		return nil
	}
	// 1. cluster
	if cl := shared.LookupPcapOperatorLabel(c.Proc.Name); cl != nil {
		return &labelMatch{source: "cluster", verdict: cl.Verdict, reasonText: cl.Reason}
	}
	// 2. SNI
	for _, sni := range extractSNIs(c) {
		if l := shared.LookupPcapTLSLabel(shared.PcapTLSLabelKindSNI, sni); l != nil {
			return &labelMatch{source: "sni", verdict: l.Verdict, reasonText: l.Reason}
		}
	}
	// 3. JA3
	for _, ja3 := range extractJA3s(c) {
		if l := shared.LookupPcapTLSLabel(shared.PcapTLSLabelKindJA3, ja3); l != nil {
			return &labelMatch{source: "ja3", verdict: l.Verdict, reasonText: l.Reason}
		}
	}
	return nil
}

// extractSNIs pulls SNI hostnames out of the candidate's Reasons.
// The TLS enrich pass stamps "TLS SNI: <hosts comma-separated>" lines.
func extractSNIs(c *shared.Candidate) []string {
	var out []string
	for _, r := range c.Reasons {
		const prefix = "TLS SNI: "
		if !strings.HasPrefix(r, prefix) {
			continue
		}
		body := r[len(prefix):]
		for _, h := range strings.Split(body, ",") {
			h = strings.TrimSpace(h)
			if h != "" {
				out = append(out, h)
			}
		}
	}
	return out
}

// extractJA3s pulls JA3 hashes out of the candidate's Reasons.
// The TLS enrich pass stamps lines like "TLS JA3 matches X (<hash>)" or
// "TLS JA3 <hash> seen across N destinations" — both are 32-hex-char
// MD5 hashes.
func extractJA3s(c *shared.Candidate) []string {
	var out []string
	for _, r := range c.Reasons {
		if !strings.Contains(r, "JA3") {
			continue
		}
		// Look for any 32-hex-char run.
		for i := 0; i+32 <= len(r); i++ {
			if isLowerHex32(r[i : i+32]) {
				// Must be bounded by non-hex (or string edge) on both sides.
				if i > 0 && isHexByte(r[i-1]) {
					continue
				}
				if i+32 < len(r) && isHexByte(r[i+32]) {
					continue
				}
				out = append(out, r[i:i+32])
				break
			}
		}
	}
	return out
}

func isLowerHex32(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < 32; i++ {
		if !isHexByte(s[i]) {
			return false
		}
	}
	return true
}

func isHexByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')
}

// inferLabeledMaliciousRole picks the right beacon-* family for a
// cluster the operator marked malicious. We don't want to mislabel
// every malicious finding as beacon — internal-target
// clusters belong in the pivot lane, listeners in the pivot lane,
// external endpoints in the channel lane.
func inferLabeledMaliciousRole(c *shared.Candidate) string {
	if c.Proc == nil {
		return "beacon"
	}
	name := c.Proc.Name
	if strings.HasSuffix(name, " outbound-int") {
		return "pivot"
	}
	// Listener form "pcap:<ip>:<port>" — single colon after "pcap:".
	if strings.HasPrefix(name, "pcap:") && !strings.Contains(name, " ") && strings.Count(name, ":") >= 2 {
		return "pivot"
	}
	// Per-/16 cluster form "pcap:<ip> → <prefix>.0.0/16:<port>".
	if idx := strings.Index(name, "→"); idx >= 0 {
		rest := strings.TrimSpace(name[idx+len("→"):])
		if i := strings.Index(rest, ":"); i > 0 {
			rest = rest[:i]
		}
		if i := strings.Index(rest, "/"); i >= 0 {
			rest = rest[:i]
		}
		parts := strings.Split(rest, ".")
		if len(parts) >= 2 && isInternalPrefix(parts[0]+"."+parts[1]) {
			return "pivot"
		}
	}
	return "beacon"
}

func stripSignals(signals []string, drop ...string) []string {
	if len(signals) == 0 {
		return signals
	}
	dropSet := make(map[string]struct{}, len(drop))
	for _, s := range drop {
		dropSet[s] = struct{}{}
	}
	out := signals[:0]
	for _, s := range signals {
		if _, skip := dropSet[s]; skip {
			continue
		}
		out = append(out, s)
	}
	return out
}
