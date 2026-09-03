package shared

import (
	"sync/atomic"
	"time"
)

// PcapClockNanos anchors "now" to the pcap's wall-clock end time when
// pcap ingest is active. PcapNow() reads this; scoring code that
// previously called time.Now() directly should use PcapNow() so the
// same pcap file produces identical findings regardless of when it's
// re-analysed.
//
// Without this, every time.Now() in the scoring pipeline (linger
// expiry checks against PivotUntil/TunnelingSeen/BeaconSeen,
// connection-age computation, beacon-cadence freshness gates) would
// drift between runs by the wall-clock seconds elapsed since the
// previous analysis, flipping role assignments on weak-evidence
// candidates.
//
// Set by pcap.IngestWithProgress / pcap.IngestTail at start to the
// last-packet timestamp; cleared (set to 0) on return.
var PcapClockNanos atomic.Int64

// PcapNow returns the pcap-anchored wall-clock time when pcap ingest
// is active, otherwise time.Now(). Use this from scoring / signal
// evaluators that must be deterministic across re-analyses of the
// same pcap file.
func PcapNow() time.Time {
	if v := PcapClockNanos.Load(); v != 0 {
		return time.Unix(0, v)
	}
	return time.Now()
}

// PcapHostScope is the HostScope value detection.Classify is called
// with when ingesting offline pcap traffic. Set in three places inside
// internal/pcap/ingest.go (oneshot replay, oneshot post-pass, tail
// emit) and persisted on each candidate's Host field — the cmd/main
// pcap path skips ScannerAdapter.Refresh's Host overwrite, so this
// value survives all the way to signal emission and rule evaluation.
const PcapHostScope = "pcap-replay"

// PcapSyntheticPIDBase mirrors internal/pcap/ingest.go's SyntheticPIDBase.
// Synthetic PIDs are allocated in [PcapSyntheticPIDBase,
// PcapSyntheticPIDBase+PcapSyntheticPIDRange) so a real /proc PID can
// never collide. We duplicate the constant here (rather than import
// internal/pcap) because shared sits below pcap in the dep graph; the
// values must stay in sync — guarded by TestPcapModeConstantsInSync
// which compares against the pcap package's exported helper.
const (
	PcapSyntheticPIDBase  = 0x7fff_0000
	PcapSyntheticPIDRange = 0x10000
)

// IsPcapMode reports whether a candidate was synthesised from a pcap
// ingest rather than live process telemetry. Two-layer check:
//
//  1. c.Host == PcapHostScope — the canonical signal, set by
//     detection.Classify when invoked from pcap ingest.
//  2. PID falls in the synthetic-PID range — defence in depth in
//     case Host got overwritten by some downstream pass.
//
// Used to gate signals that depend on process metadata pcap ingest
// cannot populate (Publisher, SignatureTrust, ChildCount, Integrity,
// LoadedLibs, etc.). Live-mode safe: a real /proc PID is structurally
// unable to reach the synthetic range.
func IsPcapMode(c *Candidate) bool {
	if c == nil {
		return false
	}
	if c.Host == PcapHostScope {
		return true
	}
	if c.Proc != nil && IsPcapSyntheticPID(c.Proc.Pid) {
		return true
	}
	return false
}

// IsPcapSyntheticPID reports whether a PID falls in the range pcap
// ingest allocates for synthetic per-IP attribution. Mirrors
// internal/pcap/ingest.go's IsSyntheticPID helper but lives in
// shared so signal emitters can call it without an import cycle.
func IsPcapSyntheticPID(pid int) bool {
	return pid >= PcapSyntheticPIDBase && pid < PcapSyntheticPIDBase+PcapSyntheticPIDRange
}

// IsPcapPerDestCluster reports whether the candidate is a pcap-mode
// per-/16 cluster (a single (host → /16:port) destination), as
// opposed to a per-host rollup ("outbound-ext" / "outbound-int") or
// a listener. Cluster names contain the pcap-arrow rune ("→").
//
// Used to gate process-identity-class signals (outbound-baseline-
// verified, outbound-push-notification, outbound-established-service)
// that were designed for LIVE-mode per-process behavior and don't
// translate to a destination-cluster context. Operator-confirmed
// 2026-05-04 across the corpus run: Mythic / d10 / Merlin per-/16
// cluster candidates carried these signals incorrectly and got their
// Path D promotion vetoed even though shape + rare-sig fired.
//
// Live-mode safe: only matches when IsPcapMode AND the synthetic
// cluster name shape is present. Real /proc names can't be confused.
func IsPcapPerDestCluster(c *Candidate) bool {
	if c == nil || c.Proc == nil || !IsPcapMode(c) {
		return false
	}
	for i := 0; i < len(c.Proc.Name); i++ {
		// Look for the multi-byte arrow rune ("→" = U+2192,
		// encoded as 0xE2 0x86 0x92 in UTF-8). A simple byte-pair
		// match avoids importing unicode/utf8 here.
		if c.Proc.Name[i] == 0xE2 && i+2 < len(c.Proc.Name) &&
			c.Proc.Name[i+1] == 0x86 && c.Proc.Name[i+2] == 0x92 {
			return true
		}
	}
	return false
}
