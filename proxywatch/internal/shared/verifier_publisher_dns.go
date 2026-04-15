package shared

import (
	"strings"
)

// EvaluatePublisherDNSAlignment answers: do any of this candidate's external
// destinations resolve inside a domain that the process's publisher is known
// to own? This is the vendor-agnostic check — works for any binary whose
// Authenticode CN (or Company metadata) matches a publisher in
// publisher_domains.go, without enumerating vendor-specific process names.
//
// Three checks, any one positive → returns (true, tags):
//   1. PTR of destination ends in a publisher domain.
//   2. Forward-resolved publisher domain shares a /24 with the destination.
//   3. Connection remote-host field (when populated) has a hostname ending
//      in a publisher domain — this catches pre-resolved TLS SNI-like data.
//
// Returns (false, nil) when:
//   - publisher is unknown / not in the map
//   - no external destinations exist
//   - DNS hasn't populated yet (async refresh triggered; next cycle will
//     have the answer)
//
// All DNS goes through the async cache in dns_cache.go — never blocks the
// classifier.
func EvaluatePublisherDNSAlignment(c *Candidate) (bool, []string) {
	if c == nil || c.Proc == nil {
		return false, nil
	}
	publisher := strings.TrimSpace(c.Proc.Publisher)
	if publisher == "" {
		publisher = strings.TrimSpace(c.Proc.Company)
	}
	if publisher == "" {
		return false, nil
	}
	domains := LookupPublisherDomains(publisher)
	if len(domains) == 0 {
		return false, nil
	}
	if len(c.Conns) == 0 {
		return false, nil
	}

	var tags []string
	seenTag := map[string]bool{}
	addTag := func(t string) {
		if t == "" || seenTag[t] {
			return
		}
		seenTag[t] = true
		tags = append(tags, t)
	}

	for _, conn := range c.Conns {
		addr := strings.TrimSpace(conn.RemoteAddress)
		if addr == "" || IsLoopbackIP(addr) || IsInternalIP(addr) || IsWildcardIP(addr) {
			continue
		}
		ptr := PTRLookupCached(addr)
		if ptr != "" {
			for _, d := range domains {
				if domainSuffixMatch(ptr, d) {
					addTag("dns:ptr-aligned:" + d)
					break
				}
			}
		}
		for _, d := range domains {
			ips := ForwardLookupCached(d)
			if len(ips) == 0 {
				continue
			}
			if ipsShareSlash24(addr, ips) {
				addTag("dns:forward-aligned:" + d)
			}
		}
	}

	return len(tags) > 0, tags
}

// domainSuffixMatch returns true when host ends in domain as a DNS suffix.
// "api.drata.com" matches "drata.com" but "notdrata.com" does not.
func domainSuffixMatch(host, domain string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if host == domain {
		return true
	}
	return strings.HasSuffix(host, "."+domain)
}

// ipsShareSlash24 returns true when target is in the same /24 as any of
// ips. A conservative-but-useful check: cloud vendors often use contiguous
// address space, and a /24 match is strong evidence of same-infrastructure
// hosting. We deliberately avoid a /16 check because too many unrelated
// tenants share a /16 in AWS.
func ipsShareSlash24(target string, ips []string) bool {
	tp := slash24Prefix(target)
	if tp == "" {
		return false
	}
	for _, ip := range ips {
		if slash24Prefix(ip) == tp {
			return true
		}
	}
	return false
}

func slash24Prefix(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	return parts[0] + "." + parts[1] + "." + parts[2]
}
