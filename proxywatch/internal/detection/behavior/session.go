package behavior

import (
	"strings"
	"time"

	"proxywatch/internal/shared"
)

// EmitSessionSignals emits persistent control signals for beacon detection.
// No vendor gates — all signals fire for all processes. The outbound suppression
// in InferRoleFromSignals handles the balance via signal counts.
func EmitSessionSignals(c *shared.Candidate, addSignal func(string), ctx SignalContext, cs CommonState) {
	p := c.Proc

	// session-persistent-channel: has a persistent control channel.
	if c.ControlChannel != nil && c.ControlDurationSeconds >= 30 {
		addSignal("session-persistent-channel")
	}

	// session-long-connection: bracketed long-connection score
	// (1h base / 4h low / 8h medium / 12h high). Fires above 0.4 (≥1h)
	// so the existing 30s persistent-control signal still covers shorter
	// cases. Continuous interpolation rather than discrete bands so an
	// 8-hour connection scores noticeably higher than a 1.5-hour
	// connection — operators triaging "long-conn" findings can sort
	// meaningfully.
	if c.ControlDurationSeconds > 0 {
		if shared.LongConnDurationScore(float64(c.ControlDurationSeconds)) >= 0.4 {
			addSignal("session-long-connection")
		}
	}

	// First-seen historical scoring. Looks up the candidate's destination
	// cluster against the persistent
	// DestFirstSeen map. Stamps:
	//   `dest-recently-first-seen` — first observed ≤ 7 days ago
	//   `dest-long-established`     — first observed ≥ 30 days ago
	//                                 (suppression-class — argues
	//                                  AGAINST malice for vendor traffic
	//                                  proxywatch has been watching for
	//                                  weeks).
	//
	// NOTE: ClassifyMu is already held by detection.Classify (write
	// lock) when this function runs — sync.Mutex isn't reentrant, so
	// re-locking here deadlocks the entire classifier and freezes the
	// TUI. Operator-confirmed startup hang 2026-05-04: TUI never
	// rendered when the original code re-locked. Reads from
	// DestFirstSeen are safe under the caller's lock.
	now := shared.PcapNow()
	if !now.IsZero() && c.OutExternal > 0 {
		const recentlyFirstSeenWindow = 7 * 24 * time.Hour
		const longEstablishedThreshold = 30 * 24 * time.Hour
		recent, established := false, false
		for _, conn := range c.Conns {
			if conn.RemoteAddress == "" || conn.RemotePort <= 0 {
				continue
			}
			if shared.IsInternalIP(conn.RemoteAddress) || shared.IsLoopbackIP(conn.RemoteAddress) {
				continue
			}
			first := shared.LookupDestFirstSeen(conn.LocalAddress, conn.RemoteAddress, conn.RemotePort)
			if first.IsZero() {
				continue
			}
			age := now.Sub(first)
			if age <= recentlyFirstSeenWindow {
				recent = true
			} else if age >= longEstablishedThreshold {
				established = true
			}
		}
		if recent {
			addSignal("dest-recently-first-seen")
		}
		// Only stamp dest-long-established when ALL the cluster's
		// external dests are well-established. A mix of long-known +
		// brand-new dests is the "implant pivoting from a normal
		// host" shape — we don't want the suppression to mask the
		// new-dest signal.
		if established && !recent {
			addSignal("dest-long-established")
		}
	}

	// session-single-target-persistence: single external target with long-lived connection.
	if c.OutExternal == 1 && c.OutLongLived >= 1 && c.OutInternal == 0 {
		addSignal("session-single-target-persistence")
	}

	// session-pre-existing-beacon: established connections when first observed.
	if ctx.BehaviorKey != "" {
		if b := shared.ProcessBehaviorByKey[ctx.BehaviorKey]; b != nil && b.Observations <= 5 {
			estExt := 0
			for _, conn := range c.Conns {
				if conn.State == "ESTABLISHED" && !shared.IsInternalIP(conn.RemoteAddress) && !shared.IsLoopbackIP(conn.RemoteAddress) {
					estExt++
				}
			}
			if estExt > 0 && c.OutLongLived > 0 {
				addSignal("session-pre-existing-beacon")
			}
		}
	}

	// session-interactive-io-balance: balanced read/write (commands + output).
	if p.IOReadBytes > 1024 && p.IOWriteBytes > 1024 && c.OutTotal > 0 {
		ratio := float64(p.IOReadBytes) / float64(p.IOWriteBytes)
		if ratio > 0.3 && ratio < 3.0 {
			addSignal("session-interactive-io-balance")
		}
	}

	// session-conn-churn: repeated short-lived connections.
	if c.OutShortLived > 3 && c.SeenSeconds > 60 {
		addSignal("session-conn-churn")
	}

	// session-exfil-write-heavy: write-heavy IO on network-active process.
	if cs.TotalIO > 10*1024 && c.OutTotal > 0 {
		writeRatio := float64(p.IOWriteBytes) / float64(cs.TotalIO)
		if writeRatio > 0.70 {
			addSignal("session-exfil-write-heavy")
		}
	}

	// session-asn-mismatch: external ASN does not match process vendor.
	// Only fire when we have a vendor claim to mismatch AGAINST — if both
	// PE Company and Publisher are empty (common on Linux, or unsigned
	// binaries on Windows), there's no vendor identity to test alignment
	// with, and firing "mismatch" on missing data is always a FP. Pcap
	// mode satisfies the empty-claim condition by construction; the
	// explicit IsPcapMode guard below is defence in depth so the
	// signal stays off if Publisher / Company ever start being
	// synthesised from packet metadata.
	if !shared.IsPcapMode(c) && c.OutExternal > 0 && len(cs.ASNOrgs) > 0 && !cs.ASNAligned {
		hasVendorClaim := strings.TrimSpace(c.Proc.Company) != "" ||
			strings.TrimSpace(c.Proc.Publisher) != ""
		if hasVendorClaim {
			addSignal("session-asn-mismatch")
		}
	}

	// session-shell-spawn: process spawned children with network activity, or is a shell with network.
	// Skip in pcap mode — ChildCount is zero by construction (the first
	// branch never fires) and the second branch (IsShell-by-name)
	// would still trigger on synthesised names that happen to look
	// like a shell, which is a known FP source.
	if !shared.IsPcapMode(c) {
		if c.Proc.ChildCount > 0 && c.OutExternal > 0 {
			addSignal("session-shell-spawn")
		} else if IsShell(cs.NameLower) && c.OutTotal > 0 {
			addSignal("session-shell-spawn")
		}
	}

	// session-lolbin-children: process spawned children with external network activity.
	// Same rationale — ChildCount is unavailable in pcap mode.
	if !shared.IsPcapMode(c) && c.Proc.ChildCount > 0 && c.OutExternal > 0 {
		addSignal("session-lolbin-children")
	}

	// session-elevated-external: SYSTEM/High integrity with external connection.
	// Integrity is unavailable in pcap mode; without it the gate is
	// vacuously false today, but the explicit IsPcapMode guard
	// documents the intent.
	if !shared.IsPcapMode(c) && (p.Integrity == "System" || p.Integrity == "High") && c.OutExternal > 0 {
		addSignal("session-elevated-external")
	}

	// session-encoding-in-cmdline: encoded commands in command line.
	if cs.HasEncodingInCmdLine {
		addSignal("session-encoding-in-cmdline")
	}

	// session-bursty-io-pattern: bursty IO (command-response pattern).
	if cs.TotalIO > 1024 && c.SeenSeconds > 60 && c.OutTotal > 0 {
		avgRate := float64(cs.TotalIO) / float64(c.SeenSeconds)
		currentRate := float64(p.IOReadBps + p.IOWriteBps)
		if avgRate > 0 && (currentRate > avgRate*5 || currentRate == 0) {
			addSignal("session-bursty-io-pattern")
		}
	}

	// session-rare-parent-network: process with rare parent making network connections.
	// Skip in pcap mode — the rareness lookup keys on ExePath which is
	// always empty for synthesised processes, so every pcap candidate
	// with ParentPid > 0 hashes to the same key and trips this signal
	// after one observation. ParentChildFreq has no value in offline
	// classification.
	if !shared.IsPcapMode(c) && cs.RareParentNetwork && c.OutTotal > 0 {
		addSignal("session-rare-parent-network")
	}

	// session-covert-channel: high IO with no visible connections and RWX memory.
	if c.OutTotal == 0 && cs.TotalIO > 1024*1024 && (p.HasRWXMemory || p.AnonExecCount > 0) {
		addSignal("session-covert-channel")
	}

	// session-impersonation-token: Windows impersonation token detected.
	if p.TokenType == "Impersonation" && c.OutExternal > 0 {
		addSignal("session-impersonation-token")
	}

	// session-rwx-memory: has RWX memory (code injection indicator).
	if p.HasRWXMemory && c.OutTotal > 0 {
		addSignal("session-rwx-memory")
	}

	// session-internal-beacon: persistent control to internal target (lateral session).
	if c.OutExternal == 0 && c.OutInternal >= 1 && c.OutLongLived >= 1 &&
		c.ControlChannel != nil && c.ControlDurationSeconds >= 30 {
		addSignal("session-internal-beacon")
	}
}
