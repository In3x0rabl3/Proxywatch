package behavior

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"proxywatch/internal/safeio"
	"proxywatch/internal/shared"
)

// defaultSaaSC2Suffixes ships with the binary and catches the public
// SaaS platforms currently documented as Mythic / Sliver C2 profiles.
// Operators can extend via ~/.proxywatch/saas-endpoints.json; see
// loadSaaSC2Suffixes below. Intentionally narrow — a short high-
// specificity list beats a broad net that false-flags legitimate
// Slack/Discord/Teams users running unknown-vendor helper processes.
var defaultSaaSC2Suffixes = []string{
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

// Operator override file at ~/.proxywatch/saas-endpoints.json.
// Shape: {"suffixes":["one.com","two.org"],"mode":"replace"} where
// mode is "merge" (default — operator list is added to defaults) or
// "replace" (operator list fully replaces defaults). The file is read
// at signal-evaluation time with a 60-second cache, so changes take
// effect without restart.
type saasConfig struct {
	Suffixes []string `json:"suffixes,omitempty"`
	Mode     string   `json:"mode,omitempty"` // "merge" | "replace"
}

var (
	saasSuffixMu       sync.RWMutex
	saasSuffixList     []string
	saasSuffixLoadedAt time.Time
)

const saasSuffixCacheTTL = 60 * time.Second

// loadSaaSC2Suffixes returns the effective suffix list, merging the
// shipped defaults with any ~/.proxywatch/saas-endpoints.json override.
// Cached for saasSuffixCacheTTL so the hot path doesn't touch disk.
func loadSaaSC2Suffixes() []string {
	saasSuffixMu.RLock()
	fresh := saasSuffixList != nil && time.Since(saasSuffixLoadedAt) < saasSuffixCacheTTL
	list := saasSuffixList
	saasSuffixMu.RUnlock()
	if fresh {
		return list
	}
	return reloadSaaSC2Suffixes()
}

func reloadSaaSC2Suffixes() []string {
	path := filepath.Join(safeio.ProxywatchDataRoot(), "saas-endpoints.json")
	effective := append([]string(nil), defaultSaaSC2Suffixes...)

	if data, err := safeio.ReadFile(path); err == nil {
		var cfg saasConfig
		if jerr := json.Unmarshal(data, &cfg); jerr == nil {
			clean := make([]string, 0, len(cfg.Suffixes))
			for _, s := range cfg.Suffixes {
				s = strings.ToLower(strings.TrimSpace(s))
				if s != "" {
					clean = append(clean, s)
				}
			}
			if strings.EqualFold(cfg.Mode, "replace") && len(clean) > 0 {
				effective = clean
			} else if len(clean) > 0 {
				seen := make(map[string]struct{}, len(effective))
				for _, s := range effective {
					seen[s] = struct{}{}
				}
				for _, s := range clean {
					if _, dup := seen[s]; !dup {
						effective = append(effective, s)
						seen[s] = struct{}{}
					}
				}
			}
		}
	}

	saasSuffixMu.Lock()
	saasSuffixList = effective
	saasSuffixLoadedAt = time.Now()
	saasSuffixMu.Unlock()
	return effective
}

// matchesSaaSC2 returns true if host ends in any of saasC2Suffixes.
// Case-insensitive; bare "slack.com" does match, as does "wss://cdn.slack.com".
func matchesSaaSC2(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return false
	}
	for _, suf := range loadSaaSC2Suffixes() {
		if h == suf || strings.HasSuffix(h, "."+suf) {
			return true
		}
	}
	return false
}

// emitSaaSC2Signal is called from EmitBeaconSignals after the
// static-crypto-likely gate so we only check SaaS endpoints on
// already-suspicious processes. Shadow-only: fires into signals but
// is not in beaconSignals / pivotSignals / outboundSignals, so it
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
