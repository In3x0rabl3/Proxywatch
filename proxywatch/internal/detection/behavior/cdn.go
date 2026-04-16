package behavior

import "proxywatch/internal/shared"

// emitCDNFrontedSignal fires cdn-fronted-c2-candidate when a non-vendor,
// non-OS-trusted process holds persistent HTTPS connections whose
// destination IP resolves to a CDN ASN (Cloudflare, Fastly, Akamai,
// CloudFront, Azure Front Door, etc.). Shadow-only signal — it is not
// in controlSignals / pivotSignals / outboundSignals and therefore
// does not vote in InferRoleFromSignals. Used to collect FP data for
// a future hard-distinguisher graduation.
//
// Gates (all must hold):
//  1. Process is not a known vendor (IsKnownVendorProcess false)
//  2. SignatureTrust is not "trusted"
//  3. At least one external outbound connection exists
//  4. Resolved ASN org for any external destination matches IsCDNOrg
//  5. Traffic is on HTTP/HTTPS ports (AllHTTPPorts) — CDN fronting is
//     an HTTPS technique; UDP-only destinations to CDN IPs don't count.
//  6. Destination ASN is NOT aligned with the process publisher /
//     company tokens (legit Electron apps + CDNs would otherwise fire)
func emitCDNFrontedSignal(c *shared.Candidate, addSignal func(string)) {
	if c == nil || c.Proc == nil {
		return
	}
	orgs, pending, _ := shared.ResolveExternalASNOrgs(c.Conns)
	if len(orgs) == 0 && pending > 0 {
		// ASN lookup still resolving; skip this cycle rather than
		// guess — signal will evaluate on the next candidate pass.
		return
	}
	if shouldFireCDNFronted(c, orgs) {
		addSignal("cdn-fronted-c2-candidate")
	}
}

// shouldFireCDNFronted is the pure decision function separated from
// the async ASN lookup so unit tests can feed canned org lists.
func shouldFireCDNFronted(c *shared.Candidate, orgs []string) bool {
	if c == nil || c.Proc == nil {
		return false
	}
	if shared.IsKnownVendorProcess(c.Proc) {
		return false
	}
	if c.Proc.SignatureTrust == shared.SignatureTrustTrusted {
		return false
	}
	if c.OutExternal == 0 {
		return false
	}
	if len(orgs) == 0 {
		return false
	}
	cdnHit := false
	for _, org := range orgs {
		if shared.IsCDNOrg(org) {
			cdnHit = true
			break
		}
	}
	if !cdnHit {
		return false
	}
	// Vendor-aligned destination = legit (e.g. electron app calling its
	// own CDN). Only fire when the process metadata doesn't overlap.
	if shared.ASNOrgAlignedWithProcess(c.Proc, orgs) {
		return false
	}
	// Require HTTP(S)-shape destination ports. A CDN IP reached on a
	// non-HTTP port is unusual and more likely a scan/coincidence.
	for _, cn := range c.Conns {
		switch cn.RemotePort {
		case 80, 443, 8080, 8443:
			return true
		}
	}
	return false
}
