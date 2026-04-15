package behavior

import (
	"strings"

	"proxywatch/internal/shared"
)

// EmitOutboundSignals emits the OUTBOUND signals (12 signals).
func EmitOutboundSignals(c *shared.Candidate, addSignal func(string), ctx SignalContext, cs CommonState) {
	p := c.Proc

	// Behavioral stability check — replaces identity-based gates (vendor/path).
	// Process name and path checks are bypassable via injection/DLL hijacking.
	// Instead, use the learned behavior baseline: a process with 10+ clean
	// observations and low suspicious ratio has earned trust through behavior.
	behaviorStable := false
	if behavior := shared.ProcessBehaviorByKey[ctx.BehaviorKey]; behavior != nil {
		obs := float64(max(1, behavior.Observations))
		behaviorStable = behavior.Observations >= 10 &&
			float64(behavior.SuspiciousObservations)/obs <= 0.25 &&
			float64(behavior.StrongObservations)/obs <= 0.20
	}

	// System path check — used only for ML feature signals (outbound-system-path),
	// NOT for security-critical gating decisions.
	pathLower := strings.ToLower(p.ExePath)
	isSystemPath := strings.HasPrefix(pathLower, "/usr/") || strings.HasPrefix(pathLower, "/bin/") ||
		strings.HasPrefix(pathLower, "/sbin/") || strings.HasPrefix(pathLower, "/lib/") ||
		strings.HasPrefix(pathLower, "c:\\windows\\") || strings.HasPrefix(pathLower, "c:\\program files")

	// outbound-multi-external-cdn: multiple external targets, no internal (CDN/content).
	if c.OutExternal >= 3 && c.OutInternal == 0 {
		addSignal("outbound-multi-external-cdn")
	}

	// outbound-standard-ports-only: all external connections on 80/443.
	// Gated on behavioral stability — C2 implants also use 443 (domain fronting),
	// so only processes with a clean behavioral baseline qualify.
	allStandard := true
	extConns := 0
	for _, conn := range c.Conns {
		if !shared.IsInternalIP(conn.RemoteAddress) && !shared.IsLoopbackIP(conn.RemoteAddress) && conn.RemotePort > 0 {
			extConns++
			if conn.RemotePort != 443 && conn.RemotePort != 80 {
				allStandard = false
			}
		}
	}
	if allStandard && extConns > 0 && behaviorStable {
		addSignal("outbound-standard-ports-only")
	}

	// outbound-push-notification: single long-lived external, no short-lived.
	if c.OutExternal == 1 && c.OutInternal == 0 && c.OutLongLived == 1 &&
		c.OutShortLived == 0 && c.InboundTotal == 0 {
		addSignal("outbound-push-notification")
	}

	// outbound-cert-validation: short HTTPS connections (OCSP/CRL).
	if c.OutShortLived >= 2 && c.OutExternal >= 2 && cs.TotalIO < 50*1024 {
		addSignal("outbound-cert-validation")
	}

	// outbound-asn-org-aligned: external ASN matches process vendor.
	if cs.ASNAligned {
		addSignal("outbound-asn-org-aligned")
	}

	// outbound-cdn-destination: connecting to known CDN.
	// Gated on behavioral stability — C2 uses CDNs for domain fronting.
	if cs.ASNIsCDN && behaviorStable {
		addSignal("outbound-cdn-destination")
	}

	// outbound-known-vendor: process from a known vendor.
	if shared.IsKnownVendorProcess(p) {
		addSignal("outbound-known-vendor")
	}

	// vendor-signed-trusted: OS-native signature verification (or the fallback
	// path+ownership heuristic) says this binary is from a trusted publisher.
	// ML-only — deliberately NOT added to role-inference whitelists; identity
	// must never on its own suppress a decisive behavioral signal. See
	// shared/roles.go for the whitelist policy.
	if p.Signed && p.SignatureTrust == shared.SignatureTrustTrusted {
		addSignal(shared.SignatureTrustedReason)
	}

	// outbound-system-path: executable in system directory.
	if isSystemPath {
		addSignal("outbound-system-path")
	}

	// outbound-download-heavy: 95%+ read = update/sync.
	if cs.TotalIO > 100*1024 && c.OutTotal > 0 {
		readRatio := float64(p.IOReadBytes) / float64(cs.TotalIO)
		if readRatio > 0.95 {
			addSignal("outbound-download-heavy")
		}
	}

	// outbound-lolbin-network: lolbin with outbound network activity.
	if cs.IsLolbin && c.OutTotal > 0 {
		addSignal("outbound-lolbin-network")
	}

	// outbound-scripting-engine-network: scripting engine with network activity.
	if cs.IsScripting && c.OutTotal > 0 {
		addSignal("outbound-scripting-engine-network")
	}

	// outbound-baseline-verified: behavior matches learned baseline.
	// Only for known vendors or system-path processes. Unknown processes from
	// user-writable paths should NOT get baseline verification — their "clean"
	// baseline was learned while being misclassified as outbound.
	// outbound-established-service: process with multiple established external
	// connections and significant IO. Legitimate services (VPN daemons, sync agents,
	// CDN apps) maintain several persistent connections with high throughput.
	// Fires without vendor/path requirement — purely behavioral.
	if c.OutExternal >= 2 && cs.TotalIO > 1024*1024 {
		estExtCount := 0
		for _, conn := range c.Conns {
			if conn.State == "ESTABLISHED" && !shared.IsInternalIP(conn.RemoteAddress) && !shared.IsLoopbackIP(conn.RemoteAddress) {
				estExtCount++
			}
		}
		if estExtCount >= 2 {
			addSignal("outbound-established-service")
		}
	}

	// outbound-baseline-verified: behavior matches learned baseline.
	// Gated on behavioral stability — no vendor/path requirement. Any process
	// that has built a clean baseline earns this signal through behavior.
	if behaviorStable {
		addSignal("outbound-baseline-verified")
	}
}
