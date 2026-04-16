package behavior

import (
	"strings"

	"proxywatch/internal/shared"
)

// saasC2Suffixes lists DNS suffixes of public SaaS platforms that
// have documented C2 profiles (Mythic, Sliver plugins, research
// demonstrators). A persistent connection from an unknown-vendor,
// unsigned process to one of these hostnames is suspicious because
// legitimate users running a native Slack / Discord / Teams client
// are always `IsKnownVendorProcess=true`.
//
// Narrow by design — a short list that catches the actively-abused
// platforms rather than a wide "all SaaS" net. Extend via an on-disk
// override at ~/.proxywatch/saas-endpoints.json (future work); for
// now keep the list in-tree so the signal is deterministic.
var saasC2Suffixes = []string{
	"slack.com",
	"discord.com",
	"discordapp.com",
	"api.github.com",
	"gist.githubusercontent.com",
	"raw.githubusercontent.com",
	"hivemq.cloud",
	"mqtt.hivemq.com",
	"api.telegram.org",
	"cdn.discordapp.com",
	"dropboxapi.com",
	"content.dropboxapi.com",
	"api.notion.com",
	"api.trello.com",
}

// matchesSaaSC2 returns true if host ends in any of saasC2Suffixes.
// Case-insensitive; bare "slack.com" does match, as does "wss://cdn.slack.com".
func matchesSaaSC2(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return false
	}
	for _, suf := range saasC2Suffixes {
		if h == suf || strings.HasSuffix(h, "."+suf) {
			return true
		}
	}
	return false
}

// emitSaaSC2Signal is called from EmitBeaconSignals after the
// static-crypto-likely gate so we only check SaaS endpoints on
// already-suspicious processes. Shadow-only: fires into signals but
// is not in controlSignals / pivotSignals / outboundSignals, so it
// doesn't vote in InferRoleFromSignals. Powers future FP-shape
// override data collection.
func emitSaaSC2Signal(c *shared.Candidate, addSignal func(string)) {
	if c == nil || c.Proc == nil || shared.IsKnownVendorProcess(c.Proc) {
		return
	}
	if c.Proc.SignatureTrust == shared.SignatureTrustTrusted {
		return
	}
	// Need external traffic to bother — zero outbound has nothing to
	// match against.
	if c.OutExternal == 0 {
		return
	}
	hit := ""
	for i := range c.Conns {
		rip := c.Conns[i].RemoteAddress
		if rip == "" || shared.IsLoopbackIP(rip) || shared.IsInternalIP(rip) {
			continue
		}
		host := shared.PTRLookupCached(rip)
		if host == "" {
			continue
		}
		if matchesSaaSC2(host) {
			hit = host
			break
		}
	}
	if hit != "" {
		addSignal("lots-saas-c2-endpoint")
	}
}
