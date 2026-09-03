package features

import (
	"strings"

	"proxywatch/internal/shared"
)

// extractOutbound computes outbound-role features (indices 73-94).
func extractOutbound(c *shared.Candidate, behavior *shared.ProcessBehavior, fv *FeatureVector) {
	// (N) FOutboundExternalRatio — fraction external.
	if c.OutTotal > 0 {
		fv.Values[FOutboundExternalRatio] = float64(c.OutExternal) / float64(c.OutTotal)
	}

	// (N) FOutboundDistinctPrefixes — subnet diversity.
	prefixSet := make(map[string]struct{})
	for _, cn := range c.Conns {
		if cn.RemoteAddress == "" || shared.IsLoopbackIP(cn.RemoteAddress) || shared.IsWildcardIP(cn.RemoteAddress) {
			continue
		}
		if prefix := shared.TargetPrefix(cn.RemoteAddress); prefix != "" {
			prefixSet[prefix] = struct{}{}
		}
	}
	fv.Values[FOutboundDistinctPrefixes] = float64(len(prefixSet))

	// (N) FOutboundShortLivedRatio — fraction short-lived.
	if c.OutTotal > 0 {
		fv.Values[FOutboundShortLivedRatio] = float64(c.OutShortLived) / float64(c.OutTotal)
	}

	// (N) FOutboundLongLivedRatio — fraction long-lived.
	if c.OutTotal > 0 {
		fv.Values[FOutboundLongLivedRatio] = float64(c.OutLongLived) / float64(c.OutTotal)
	}

	// (N) FOutboundWellKnownPortRatio — fraction standard ports.
	wellKnown := 0
	total := 0
	for _, cn := range c.Conns {
		if cn.RemoteAddress == "" || shared.IsWildcardIP(cn.RemoteAddress) {
			continue
		}
		total++
		if cn.RemotePort < 1024 {
			wellKnown++
		}
	}
	if total > 0 {
		fv.Values[FOutboundWellKnownPortRatio] = float64(wellKnown) / float64(total)
	}

	// (N) FOutboundConnDistinctPorts — port diversity.
	fv.Values[FOutboundConnDistinctPorts] = float64(countDistinctOutboundPorts(c.Conns))

	// (N) FOutboundConnOutTotal — total outbound.
	fv.Values[FOutboundConnOutTotal] = float64(c.OutTotal)

	// (N) FOutboundConnOutLoopback — loopback connections.
	fv.Values[FOutboundConnOutLoopback] = float64(c.OutLoopback)

	// (N) FOutboundRareDestPort — unusual port flag.
	for _, cn := range c.Conns {
		if cn.RemotePort > 0 && cn.RemoteAddress != "" &&
			!shared.IsLoopbackIP(cn.RemoteAddress) &&
			!shared.IsWildcardIP(cn.RemoteAddress) {
			if shared.ObservedExternalPortProcessCount[cn.RemotePort] <= 2 {
				fv.Values[FOutboundRareDestPort] = 1
				break
			}
		}
	}

	// (N) FOutboundRareDestPrefix — unusual subnet flag.
	if behavior != nil {
		for _, cn := range c.Conns {
			if cn.RemoteAddress == "" || shared.IsLoopbackIP(cn.RemoteAddress) {
				continue
			}
			prefix := shared.TargetPrefix(cn.RemoteAddress)
			if prefix != "" && behavior.KnownPrefixes[prefix] == 0 {
				fv.Values[FOutboundRareDestPrefix] = 1
				break
			}
		}
	}

	// (N) FOutboundIORateTotal — throughput rate.
	if c.Proc != nil {
		fv.Values[FOutboundIORateTotal] = float64(c.Proc.IOReadBps + c.Proc.IOWriteBps + c.Proc.IOOtherBps)
	}

	// (H) FOutboundIOReadRatio — read/(read+write).
	if c.Proc != nil {
		totalIO := float64(c.Proc.IOReadBytes + c.Proc.IOWriteBytes)
		fv.Values[FOutboundIOReadRatio] = safeDiv(float64(c.Proc.IOReadBytes), totalIO)
	}

	// (H) FOutboundIOTotalBytes — total bytes.
	if c.Proc != nil {
		fv.Values[FOutboundIOTotalBytes] = float64(c.Proc.IOReadBytes + c.Proc.IOWriteBytes + c.Proc.IOOtherBytes)
	}

	// (H) FOutboundKnownVendor — vendor recognition flag.
	if c.Proc != nil {
		fv.Values[FOutboundKnownVendor] = boolFloat(shared.IsKnownVendorProcess(c.Proc))
	}

	// (H) FOutboundKnownNetworkActive — known network app flag.
	if c.Proc != nil {
		fv.Values[FOutboundKnownNetworkActive] = boolFloat(shared.IsKnownNetworkActiveProcess(c.Proc))
	}

	// (H) FOutboundCompanyNetworkAligned — vendor/ASN match.
	if c.Proc != nil {
		fv.Values[FOutboundCompanyNetworkAligned] = boolFloat(
			strings.TrimSpace(c.Proc.Company) != "" && shared.IsKnownNetworkActiveProcess(c.Proc))
	}

	// (H) FOutboundProcessIsLOLBin — LOLBin flag.
	if c.Proc != nil {
		fv.Values[FOutboundProcessIsLOLBin] = boolFloat(shared.IsLOLBinProcess(c.Proc))
	}

	// (H) FOutboundProcessIsScripting — script engine flag.
	if c.Proc != nil {
		fv.Values[FOutboundProcessIsScripting] = boolFloat(shared.IsScriptingEngine(c.Proc))
	}

	// (H) FOutboundSuspiciousPath — user-writable path flag.
	if c.Proc != nil {
		fv.Values[FOutboundSuspiciousPath] = boolFloat(isSuspiciousPath(c.Proc.ExePath))
	}

	// (H) FOutboundProcessNameEntropy — name randomization.
	if c.Proc != nil {
		fv.Values[FOutboundProcessNameEntropy] = shannonEntropy(c.Proc.Name)
	}

	// (H) FOutboundPathDepth — path depth.
	if c.Proc != nil {
		path := strings.ReplaceAll(c.Proc.ExePath, "\\", "/")
		fv.Values[FOutboundPathDepth] = float64(strings.Count(path, "/"))
	}

	// (H) FOutboundBenignClient — trusted directory flag.
	if c.Proc != nil {
		fv.Values[FOutboundBenignClient] = boolFloat(shared.IsLikelyBenignControlClient(c.Proc))
	}
}
