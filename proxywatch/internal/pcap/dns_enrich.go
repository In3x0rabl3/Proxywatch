package pcap

import (
	"fmt"
	"strings"

	"proxywatch/internal/shared"
)

// dnsHostStats accumulates DNS-related per-host aggregates that the
// post-pass enricher uses to fire DGA / tunneling signals. Keyed by
// client IP (the host MAKING the queries — the DNS server itself is
// not what we're trying to label).
type dnsHostStats struct {
	queries     int
	queryBytes  uint64
	respBytes   uint64
	longQueries int                      // count with name length >= 60
	by2LD       map[string]*dns2LDBucket // grouped by registrable 2LD
}

type dns2LDBucket struct {
	queryCount       int
	distinctSubs     map[string]struct{}
	entropySum       float64
	entropyCount     int
	highEntropyCount int // queries whose subdomain entropy ≥ 4.0
}

// recordDNSPacket folds a parsed DNS packet into a host's accumulator.
// fwd=true means the packet went FROM the client (a query), fwd=false
// means it came BACK to the client (a response). clientIP is the
// initiator IP from the flow key.
func recordDNSPacket(stats *dnsHostStats, dns *DNSPacket, fwd bool) {
	if stats == nil || dns == nil {
		return
	}
	if dns.IsResponse {
		// Response — count bytes only (used for response/query byte
		// ratio in the exfil-shape signal). The QueryName mirrored
		// from the question section in a response is informational;
		// we don't double-count it as a query.
		stats.respBytes += uint64(dns.PayloadSize)
		return
	}
	stats.queries++
	stats.queryBytes += uint64(dns.PayloadSize)
	if len(dns.QueryName) >= 60 {
		stats.longQueries++
	}
	if dns.QueryName == "" {
		return
	}
	tld2 := extract2LD(dns.QueryName)
	if tld2 == "" {
		return
	}
	if stats.by2LD == nil {
		stats.by2LD = make(map[string]*dns2LDBucket)
	}
	bucket, ok := stats.by2LD[tld2]
	if !ok {
		bucket = &dns2LDBucket{
			distinctSubs: make(map[string]struct{}),
		}
		stats.by2LD[tld2] = bucket
	}
	bucket.queryCount++
	if sub := extractSubdomainAboveTLD(dns.QueryName); sub != "" {
		bucket.distinctSubs[sub] = struct{}{}
		ent := shannonEntropy(sub)
		bucket.entropySum += ent
		bucket.entropyCount++
		if ent >= 4.0 {
			bucket.highEntropyCount++
		}
	}
}

// enrichPcapWithDNSSignals scans the per-host DNS accumulator built
// during ingest and stamps signals on synthetic-PID candidates whose
// host IP made the queries. Mirrors the other enrich passes.
//
// Signals emitted (DECISIVE — auto-promote via pcapDecisiveSignals):
//   - dns-dga-likely     — a host queried ≥ 10 distinct subdomains of
//     a single 2LD AND the average subdomain
//     Shannon entropy is ≥ 4.0 bits. Real DGA.
//   - dns-tunnel-volume  — a host's DNS query+response volume exceeds
//     64 KiB AND ≥ 5 queries had name length
//     ≥ 60 chars. DNS tunneling shape.
//
// Stamped on any synthetic candidate whose cluster name starts with
// the host IP. We deliberately stamp on multiple cluster types
// (rollup outbound-ext / outbound-int / per-/16) because DNS activity
// implicates the host as a whole — operators have asked for
// host-level visibility on DGA when a beacon is doing it.
func enrichPcapWithDNSSignals(dns map[string]*dnsHostStats, candidates []shared.Candidate) {
	if len(dns) == 0 || len(candidates) == 0 {
		return
	}

	type verdict struct {
		dgaLikely    bool
		dgaLabel     string
		tunnelVolume bool
		tunnelLabel  string
	}
	hostVerdicts := make(map[string]verdict)
	for host, stats := range dns {
		v := verdict{}
		// dns-dga-likely: any 2LD bucket with ≥10 distinct subdomains
		// AND average entropy ≥ 4.0.
		for tld2, b := range stats.by2LD {
			if len(b.distinctSubs) < 10 || b.entropyCount == 0 {
				continue
			}
			avg := b.entropySum / float64(b.entropyCount)
			if avg >= 4.0 {
				v.dgaLikely = true
				v.dgaLabel = fmt.Sprintf("%s (%d distinct subs, avg-entropy %.2f)", tld2, len(b.distinctSubs), avg)
				break
			}
		}
		// dns-tunnel-volume: ≥64 KiB total DNS bytes AND ≥5 long queries.
		totalBytes := stats.queryBytes + stats.respBytes
		if totalBytes >= 64*1024 && stats.longQueries >= 5 {
			v.tunnelVolume = true
			ratio := 0.0
			if stats.queryBytes > 0 {
				ratio = float64(stats.respBytes) / float64(stats.queryBytes)
			}
			v.tunnelLabel = fmt.Sprintf("%s total DNS, %d long queries, resp/query ratio %.2fx",
				humanBytes(totalBytes), stats.longQueries, ratio)
		}
		if v.dgaLikely || v.tunnelVolume {
			hostVerdicts[host] = v
		}
	}
	if len(hostVerdicts) == 0 {
		return
	}

	for i := range candidates {
		c := &candidates[i]
		if c.Proc == nil || !IsSyntheticPID(c.Proc.Pid) {
			continue
		}
		host := pcapHostFromName(c.Proc.Name)
		v, ok := hostVerdicts[host]
		if !ok {
			continue
		}
		// Stamp ONLY on the host's outbound-int rollup or on a
		// DNS-port cluster (port 53). DNS goes through internal
		// resolvers (RFC1918) or rarely public DNS (8.8.8.8) — never
		// over a /16:443 HTTPS cluster. Operator-confirmed FP storm
		// 2026-05-04: a normal browsing host's heavy DNS made
		// dns-tunnel-volume stamp on ALL of its 28 external HTTPS
		// destinations, then HasPacketDecisiveSignal (which has
		// dns-tunnel-volume in pcapDecisiveSignals) rescued every
		// single one of them to beacon. The host-level
		// signal must apply to the host-level cluster only.
		if !pcapClusterIsDNSScope(c.Proc.Name) {
			continue
		}
		if v.dgaLikely {
			c.Signals = appendUniqueSignal(c.Signals, "dns-dga-likely")
			c.Reasons = appendUniqueSignal(c.Reasons,
				"DNS DGA shape on "+v.dgaLabel)
		}
		if v.tunnelVolume {
			c.Signals = appendUniqueSignal(c.Signals, "dns-tunnel-volume")
			c.Reasons = appendUniqueSignal(c.Reasons,
				"DNS tunneling shape: "+v.tunnelLabel)
		}
	}
}

// pcapClusterIsDNSScope reports whether a cluster name represents a
// scope where DNS-tunnel-volume / dns-dga-likely signals legitimately
// belong: the host's `outbound-int` rollup (catches DNS to internal
// resolvers) or any cluster ending in `:53` (DNS port). Anything
// else — random external HTTPS destinations — must NOT receive
// host-level DNS signals because they have no causal relationship
// to the DNS traffic.
func pcapClusterIsDNSScope(name string) bool {
	if strings.HasSuffix(name, " outbound-int") {
		return true
	}
	if strings.HasSuffix(name, ":53") {
		return true
	}
	return false
}

// humanBytes renders byte counts as KiB / MiB for the Reasons text.
// Kept local to dns_enrich.go so the public render package isn't
// pulled into a low-level package.
func humanBytes(n uint64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/float64(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// uniqueSubs is a tiny helper used in tests to assert distinct
// subdomain bucketing.
func (b *dns2LDBucket) uniqueSubs() int {
	if b == nil {
		return 0
	}
	return len(b.distinctSubs)
}

var _ = strings.Builder{} // keep `strings` import even if reformatting drops it
