package behavior

import (
	"strings"

	"proxywatch/internal/shared"
)

// EmitSessionSignals emits persistent control signals for control-channel detection.
// No vendor gates — all signals fire for all processes. The outbound suppression
// in InferRoleFromSignals handles the balance via signal counts.
func EmitSessionSignals(c *shared.Candidate, addSignal func(string), ctx SignalContext, cs CommonState) {
	p := c.Proc

	// session-control-channel-persistent: has a persistent control channel.
	if c.ControlChannel != nil && c.ControlDurationSeconds >= 30 {
		addSignal("session-control-channel-persistent")
	}

	// session-single-target-persistence: single external target with long-lived connection.
	if c.OutExternal == 1 && c.OutLongLived >= 1 && c.OutInternal == 0 {
		addSignal("session-single-target-persistence")
	}

	// session-pre-existing-control: established connections when first observed.
	if ctx.BehaviorKey != "" {
		if b := shared.ProcessBehaviorByKey[ctx.BehaviorKey]; b != nil && b.Observations <= 5 {
			estExt := 0
			for _, conn := range c.Conns {
				if conn.State == "ESTABLISHED" && !shared.IsInternalIP(conn.RemoteAddress) && !shared.IsLoopbackIP(conn.RemoteAddress) {
					estExt++
				}
			}
			if estExt > 0 && c.OutLongLived > 0 {
				addSignal("session-pre-existing-control")
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
	// with, and firing "mismatch" on missing data is always a FP.
	if c.OutExternal > 0 && len(cs.ASNOrgs) > 0 && !cs.ASNAligned {
		hasVendorClaim := strings.TrimSpace(c.Proc.Company) != "" ||
			strings.TrimSpace(c.Proc.Publisher) != ""
		if hasVendorClaim {
			addSignal("session-asn-mismatch")
		}
	}

	// session-shell-spawn: process spawned children with network activity, or is a shell with network.
	if c.Proc.ChildCount > 0 && c.OutExternal > 0 {
		addSignal("session-shell-spawn")
	} else if IsShell(cs.NameLower) && c.OutTotal > 0 {
		addSignal("session-shell-spawn")
	}

	// session-lolbin-children: process spawned children with external network activity.
	if c.Proc.ChildCount > 0 && c.OutExternal > 0 {
		addSignal("session-lolbin-children")
	}

	// session-elevated-external: SYSTEM/High integrity with external connection.
	if (p.Integrity == "System" || p.Integrity == "High") && c.OutExternal > 0 {
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
	if cs.RareParentNetwork && c.OutTotal > 0 {
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

	// session-internal-control: persistent control to internal target (lateral session).
	if c.OutExternal == 0 && c.OutInternal >= 1 && c.OutLongLived >= 1 &&
		c.ControlChannel != nil && c.ControlDurationSeconds >= 30 {
		addSignal("session-internal-control")
	}
}
