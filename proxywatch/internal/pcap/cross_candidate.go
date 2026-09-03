package pcap

import (
	"proxywatch/internal/shared"
)

// enrichPcapWithCrossCandidatePivotSignals stamps combo network-behavior
// signals on pcap-mode candidates that the live-mode emission path
// cannot fire because pcap splits a single process's listener and
// outbound activity across separate synthetic-PID clusters.
//
// In live mode, a pivot or tunnel binary owns BOTH a listener and its
// own external outbound traffic on a SINGLE Candidate, so signals like
// `pivot-listener-plus-outbound` and `pivot-loopback-listener-external-out`
// fire trivially. In pcap mode, the per-host attribution produces:
//   - `pcap:<ip>:<port>` for each listening socket
//   - `pcap:<ip> outbound-ext` for the host's external rollup
//   - `pcap:<ip> → <prefix>/16:<port>` for each per-/16 outbound cluster
//
// These never co-locate on one candidate, so the combo signals never
// fire — even though the underlying network-behavior pattern is
// identical and clearly visible at the host level.
//
// This pass runs AFTER classify + AggregateChildTunnelEvidence but
// BEFORE the role guard, so the stamped signals participate in the
// existing `pcapDecisiveSignals` gate (both signals are already in
// that set per `internal/shared/roles.go`). No live-mode behavior
// changes — this function only operates on synthetic-PID candidates.
//
// Operator-confirmed 2026-05-03: focus is on existing live-mode
// network rules, not new ML-from-scratch. Goal is to make the same
// rules fire on pcap data.
func enrichPcapWithCrossCandidatePivotSignals(candidates []shared.Candidate) {
	if len(candidates) == 0 {
		return
	}

	// First sweep: index per-host external outbound presence + count
	// distinct internal targets. We only need a pair-of-flags answer
	// per host: "does this host have external outbound" and
	// "does this host have non-loopback internal outbound".
	type hostFlags struct {
		hasExternalOutbound bool
		hasInternalOutbound bool
		extByteVolume       uint64
	}
	hostIndex := make(map[string]*hostFlags)
	for i := range candidates {
		c := &candidates[i]
		if c.Proc == nil || !IsSyntheticPID(c.Proc.Pid) {
			continue
		}
		host := pcapHostFromName(c.Proc.Name)
		if host == "" {
			continue
		}
		hf, ok := hostIndex[host]
		if !ok {
			hf = &hostFlags{}
			hostIndex[host] = hf
		}
		if c.OutExternal > 0 {
			hf.hasExternalOutbound = true
			if c.Proc != nil {
				hf.extByteVolume += c.Proc.IOReadBytes + c.Proc.IOWriteBytes
			}
		}
		if c.OutInternal > 0 {
			hf.hasInternalOutbound = true
		}
	}

	// Second sweep: index host → has-listener-with-inbound and
	// host → has-loopback-listener so we can stamp the combo signals
	// on BOTH sides (listener candidate AND outbound candidate). Both
	// sides need the signal because ApplyPivotLinger's pcap-mode gate
	// checks HasPacketDecisiveSignal on each candidate independently.
	//
	// hasRelayListener tracks whether the host has at least one listener
	// candidate with REAL relay evidence (child-tunnel-relay,
	// listener-inbound-external, or pivot-socks-candidate). Only such
	// hosts are eligible to have their outbound clusters stamped — a
	// host with admin SSH or a Chromecast service listener but NO real
	// relay shape must not have its benign LAN/outbound traffic
	// promoted to pivot. Operator confirmation 2026-05-03:
	// Chrome's 172.16.1.81 → 172.16.1.72:8009 (Chromecast discovery)
	// was tripping pivot-listener-plus-outbound + linger because the
	// outbound side gating only checked pivot-non-loopback-internal,
	// which fires trivially on any internal-target cluster.
	hasSig := func(c *shared.Candidate, name string) bool {
		for _, s := range c.Signals {
			if s == name {
				return true
			}
		}
		return false
	}
	type hostListenerInfo struct {
		hasListener         bool
		hasInboundListener  bool
		hasLoopbackListener bool
		hasRelayListener    bool
	}
	hostListenerIndex := make(map[string]*hostListenerInfo)
	// hasServicePortListener returns true when the candidate has at
	// least one listener on a service-class port (< 49152). Ports in
	// the ephemeral range (Windows: 49152-65535, Linux: 32768-60999)
	// are CLIENT-side OS-allocated ports — a "listener" on one is
	// almost always pcap synthesis fudge or a transient TIME_WAIT,
	// not a real service. Operator-confirmed FP 2026-05-04:
	// 172.16.1.6:55965 ←→ 150.171.28.16:443 was firing
	// pivot-listener-plus-outbound at 100% because the same ephemeral
	// port appeared both as a "listener" and as an outbound client
	// flow. A real pivot listens on 22/80/443/1080/8080 etc., not
	// random 5-digit ports.
	const ephemeralPortFloor = 49152
	hasServicePortListener := func(c *shared.Candidate) bool {
		for _, l := range c.Listeners {
			if l.LocalPort > 0 && l.LocalPort < ephemeralPortFloor {
				return true
			}
		}
		for _, l := range c.UDPListeners {
			if l.LocalPort > 0 && l.LocalPort < ephemeralPortFloor {
				return true
			}
		}
		return false
	}
	for i := range candidates {
		c := &candidates[i]
		if c.Proc == nil || !IsSyntheticPID(c.Proc.Pid) {
			continue
		}
		if len(c.Listeners) == 0 && len(c.UDPListeners) == 0 {
			continue
		}
		// Skip ephemeral-port-only listeners — they're not real
		// services. This stops cross-candidate pivot stamps from
		// firing on every host that happens to have a transient
		// listener on a high port.
		if !hasServicePortListener(c) {
			continue
		}
		host := pcapHostFromName(c.Proc.Name)
		if host == "" {
			continue
		}
		hli, ok := hostListenerIndex[host]
		if !ok {
			hli = &hostListenerInfo{}
			hostListenerIndex[host] = hli
		}
		hli.hasListener = true
		if c.InboundTotal > 0 {
			hli.hasInboundListener = true
		}
		for _, l := range c.Listeners {
			if l.LocalPort >= ephemeralPortFloor {
				continue
			}
			if shared.IsLoopbackIP(l.LocalAddress) {
				hli.hasLoopbackListener = true
				break
			}
		}
		if hasSig(c, "child-tunnel-relay") ||
			hasSig(c, "listener-inbound-external") ||
			hasSig(c, "pivot-socks-candidate") {
			hli.hasRelayListener = true
		}
	}

	// Third sweep: stamp combo signals on the listener AND on outbound
	// clusters that carry the `pivot-non-loopback-internal` marker.
	//
	// In live mode these signals attach to a single process that owns
	// both a listener and an outbound. In pcap mode that link is gone,
	// so we narrow stamping to two cases that preserve live-mode parity
	// without over-firing:
	//
	//   - listener candidate (always stamped when host topology matches;
	//     allows the listener itself, e.g. sshd:22, to promote to
	//     pivot via the role guard / linger).
	//   - outbound cluster that carries `pivot-non-loopback-internal`
	//     (relay-shape evidence: OutExternal==0, NonLoopbackInternal>0).
	//     This is the C3-walk path the pivot-shape tests exercise — a
	//     child process forwarding to internal targets while the parent
	//     listener takes inbound. It does NOT fire for outbound CDN
	//     destinations (Microsoft/Akamai/Cloudflare from a Windows host),
	//     which is the FP we hit when the stamp was unconditional.
	// Cross-candidate stamping is gated on POSITIVE relay evidence
	// already on the host's listener candidate(s). Without process
	// attribution we cannot link a listener to an outbound, so "host has
	// a listener AND has external outbound" is not enough — that's the
	// admin-SSH-on-a-busy-Windows-host pattern (operator confirmed
	// 2026-05-03: pcap:172.16.1.81:22 with internal-only inbound +
	// cheerful's MBs of external traffic) AND the Chrome-Chromecast-
	// discovery pattern (172.16.1.81 → 172.16.1.72:8009 promoted to
	// pivot because pivot-non-loopback-internal fires trivially
	// on any internal-target cluster).
	//
	// Required listener evidence on the SAME HOST (any one of):
	//   - child-tunnel-relay     — AggregateChildTunnelEvidence found
	//                              children forwarding to internal
	//                              targets through this listener.
	//   - listener-inbound-external — listener accepts inbound from
	//                              external IPs (sshd-z attacker pattern).
	//   - pivot-socks-candidate — SOCKS handshake bytes observed on the
	//                              listener's flows.
	//
	// Both listener and outbound candidates require this gate. Without
	// it, ANY internal-target cluster on a host that has any listener
	// of any kind gets stamped, producing the FPs above.

	for i := range candidates {
		c := &candidates[i]
		if c.Proc == nil || !IsSyntheticPID(c.Proc.Pid) {
			continue
		}
		isListener := len(c.Listeners) > 0 || len(c.UDPListeners) > 0
		isRelayOutbound := !isListener && hasSig(c, "pivot-non-loopback-internal")
		if !isListener && !isRelayOutbound {
			continue
		}
		host := pcapHostFromName(c.Proc.Name)
		hf := hostIndex[host]
		hli := hostListenerIndex[host]
		// Gate: host MUST have a listener with real relay evidence.
		// Without this, admin SSH on a busy host and Chrome's LAN
		// service discovery both trip the cross-candidate stamps.
		if hli == nil || !hli.hasRelayListener {
			continue
		}

		// pivot-listener-plus-outbound: host has BOTH a listener AND
		// outbound activity.
		if hli != nil && hli.hasListener && hf != nil &&
			(hf.hasExternalOutbound || hf.hasInternalOutbound) {
			c.Signals = appendUniqueSignal(c.Signals, "pivot-listener-plus-outbound")
		}

		// pivot-loopback-listener-external-out: host has loopback
		// listener AND external outbound. Listener-only — this signal
		// only makes sense paired with a listener candidate.
		if isListener && hli != nil && hli.hasLoopbackListener && hf != nil && hf.hasExternalOutbound {
			c.Signals = appendUniqueSignal(c.Signals, "pivot-loopback-listener-external-out")
		}

		// listener-egress-tunnel-shape: listener with inbound + host has
		// ≥64 KiB external bytes. Listener-only stamp.
		if isListener && hli != nil && hli.hasInboundListener && hf != nil && hf.extByteVolume >= 64*1024 {
			c.Signals = appendUniqueSignal(c.Signals, "listener-egress-tunnel-shape")
		}
	}
}
