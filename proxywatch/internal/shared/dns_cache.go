package shared

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ptrCache and fwdCache are package-level async DNS caches. Lookups called
// from the classifier hot path never block: on miss they return the zero
// value and trigger a background refresh. The next classify cycle sees the
// populated entry.
//
// Negative results (NXDOMAIN, timeout) are cached briefly so we don't retry
// every 250ms for a dead host. Positive results are kept longer but also
// expire — PTR records can change, especially in cloud environments.

const (
	ptrTTLPositive = 10 * time.Minute
	ptrTTLNegative = 90 * time.Second
	fwdTTLPositive = 10 * time.Minute
	fwdTTLNegative = 90 * time.Second

	dnsLookupTimeout = 2 * time.Second
)

type ptrEntry struct {
	ptr       string
	expiresAt time.Time
}

type fwdEntry struct {
	ips       []string
	expiresAt time.Time
}

var (
	ptrMu       sync.RWMutex
	ptrCache    = map[string]ptrEntry{}
	ptrInFlight = map[string]struct{}{}

	fwdMu       sync.RWMutex
	fwdCache    = map[string]fwdEntry{}
	fwdInFlight = map[string]struct{}{}

	// dnsInFlightLimit caps the total number of concurrent DNS
	// resolutions across both ptr and forward lookups. The semaphore
	// back-pressures callers: when the limit is hit, the goroutine
	// that would have dispatched a query simply releases its
	// in-flight slot and returns; the next classify cycle picks up
	// the IP again with the existing per-IP dedup still preventing
	// thrash.
	dnsInFlightLimit = make(chan struct{}, 4)

	// PcapModeActive, when true, disables DNS PTR/forward refresh
	// goroutines entirely. Pcap-replay against a large pcap with
	// hundreds of unique remote IPs would otherwise saturate the
	// Windows DNS API even with a tight semaphore — observed
	// 2026-05-01 on host DEMO: hundreds of "[runnable]" goroutines
	// stuck in syscall.SyscallN → DnsQuery_W crashed the Go runtime.
	// Synthetic pcap candidates do not depend on PTR / forward lookup
	// results for role assignment (the signal evaluator that uses
	// PTR is shadow-only saas.go, which is not in any decisive set
	// for pcap mode), so it's safe to short-circuit. Set by
	// pcap.IngestWithProgress / pcap.IngestTail at start, cleared on
	// return.
	PcapModeActive atomic.Bool
)

// PTRLookupCached returns the cached PTR for ip, or "" if none is cached.
// A cache miss (or stale entry) triggers an async refresh via a goroutine
// with a 2s timeout; the result populates the cache for the next call.
// Returns "" for private / loopback / wildcard IPs — those never have
// meaningful reverse DNS.
func PTRLookupCached(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" || IsLoopbackIP(ip) || IsInternalIP(ip) || IsWildcardIP(ip) {
		return ""
	}
	// Pcap-replay short-circuit. Synthetic candidates don't drive
	// any decisive role assignment off PTR results, so skipping
	// avoids the DNS goroutine storm that crashes Windows under
	// hundreds of unique-IP pcap-replay loads.
	if PcapModeActive.Load() {
		return ""
	}
	now := time.Now()
	ptrMu.RLock()
	entry, ok := ptrCache[ip]
	ptrMu.RUnlock()
	if ok && now.Before(entry.expiresAt) {
		return entry.ptr
	}
	triggerPTRRefresh(ip)
	return ""
}

func triggerPTRRefresh(ip string) {
	ptrMu.Lock()
	if _, busy := ptrInFlight[ip]; busy {
		ptrMu.Unlock()
		return
	}
	ptrInFlight[ip] = struct{}{}
	ptrMu.Unlock()

	// Global concurrency cap. Try to acquire a slot in dnsInFlightLimit;
	// if the limit is saturated, drop this refresh and let a future
	// classify cycle retry. The per-IP dedup prevents thrash; this
	// global cap prevents the goroutine explosion observed on Windows
	// when pcap-replay produces hundreds of unique remote IPs.
	select {
	case dnsInFlightLimit <- struct{}{}:
	default:
		// Saturated. Release the per-IP busy flag so the next cycle
		// can retry, then bail without launching a goroutine.
		ptrMu.Lock()
		delete(ptrInFlight, ip)
		ptrMu.Unlock()
		return
	}

	go func() {
		defer func() { <-dnsInFlightLimit }()
		ctx, cancel := context.WithTimeout(context.Background(), dnsLookupTimeout)
		defer cancel()
		var resolver net.Resolver
		names, err := resolver.LookupAddr(ctx, ip)
		ptr := ""
		if err == nil && len(names) > 0 {
			ptr = strings.TrimSuffix(strings.ToLower(names[0]), ".")
		}
		ttl := ptrTTLPositive
		if ptr == "" {
			ttl = ptrTTLNegative
		}
		ptrMu.Lock()
		ptrCache[ip] = ptrEntry{ptr: ptr, expiresAt: time.Now().Add(ttl)}
		delete(ptrInFlight, ip)
		ptrMu.Unlock()
	}()
}

// ForwardLookupCached resolves domain → IP list, async-filled on cache miss
// like PTRLookupCached. Returns nil when not yet cached; callers treat nil
// as "don't know yet", not "no A records exist".
func ForwardLookupCached(domain string) []string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil
	}
	// Pcap-replay short-circuit (same rationale as PTRLookupCached).
	if PcapModeActive.Load() {
		return nil
	}
	now := time.Now()
	fwdMu.RLock()
	entry, ok := fwdCache[domain]
	fwdMu.RUnlock()
	if ok && now.Before(entry.expiresAt) {
		return entry.ips
	}
	triggerForwardRefresh(domain)
	return nil
}

func triggerForwardRefresh(domain string) {
	fwdMu.Lock()
	if _, busy := fwdInFlight[domain]; busy {
		fwdMu.Unlock()
		return
	}
	fwdInFlight[domain] = struct{}{}
	fwdMu.Unlock()

	// Share the global DNS in-flight cap with PTR lookups — same
	// goroutine-storm risk applies to forward queries too.
	select {
	case dnsInFlightLimit <- struct{}{}:
	default:
		fwdMu.Lock()
		delete(fwdInFlight, domain)
		fwdMu.Unlock()
		return
	}

	go func() {
		defer func() { <-dnsInFlightLimit }()
		ctx, cancel := context.WithTimeout(context.Background(), dnsLookupTimeout)
		defer cancel()
		var resolver net.Resolver
		ips, err := resolver.LookupHost(ctx, domain)
		var out []string
		if err == nil {
			out = ips
		}
		ttl := fwdTTLPositive
		if len(out) == 0 {
			ttl = fwdTTLNegative
		}
		fwdMu.Lock()
		fwdCache[domain] = fwdEntry{ips: out, expiresAt: time.Now().Add(ttl)}
		delete(fwdInFlight, domain)
		fwdMu.Unlock()
	}()
}

// DNSStats returns coarse counters surfaced via /online/status.
type DNSStats struct {
	PTREntries  int `json:"ptr_entries"`
	FwdEntries  int `json:"fwd_entries"`
	PTRInFlight int `json:"ptr_in_flight"`
	FwdInFlight int `json:"fwd_in_flight"`
}

func SnapshotDNSStats() DNSStats {
	ptrMu.RLock()
	pe, pi := len(ptrCache), len(ptrInFlight)
	ptrMu.RUnlock()
	fwdMu.RLock()
	fe, fi := len(fwdCache), len(fwdInFlight)
	fwdMu.RUnlock()
	return DNSStats{PTREntries: pe, FwdEntries: fe, PTRInFlight: pi, FwdInFlight: fi}
}
