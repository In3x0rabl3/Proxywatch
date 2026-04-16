package behavior

import (
	"strings"

	"proxywatch/internal/shared"
)

// EmitPivotSignals emits the CONTROL-PIVOT signals (17 signals).
func EmitPivotSignals(c *shared.Candidate, addSignal func(string), ctx SignalContext, cs CommonState) {
	p := c.Proc

	// pivot-listener-plus-outbound: listener with outbound connections.
	// Known vendors with listeners + outbound are normal (Chrome, Zoom, Slack).
	if len(c.Listeners) > 0 && c.OutTotal > 0 {
		addSignal("pivot-listener-plus-outbound")
	}

	// pivot-loopback-listener-external-out: loopback listener + external outbound.
	loopbackListener := false
	for _, l := range c.Listeners {
		if shared.IsLoopbackIP(l.LocalAddress) {
			loopbackListener = true
			break
		}
	}
	if loopbackListener && c.OutExternal > 0 {
		addSignal("pivot-loopback-listener-external-out")
	}

	// pivot-multiplex-relay: many internal through one external.
	// Known vendors with external + internal connections are doing normal app behavior.
	if c.OutExternal >= 1 && c.OutInternal >= 3 {
		addSignal("pivot-multiplex-relay")
	}

	// pivot-throughput-symmetry: read approx equals write (relay symmetry).
	if p.IOReadBytes > 10*1024 && p.IOWriteBytes > 10*1024 && cs.TotalIO > 100*1024 && c.OutTotal > 0 && c.InboundTotal > 0 {
		ratio := float64(p.IOReadBytes) / float64(p.IOWriteBytes)
		if ratio > 0.5 && ratio < 2.0 {
			addSignal("pivot-throughput-symmetry")
		}
	}

	// pivot-mixed-protocol-internal: different ports on internal targets.
	if len(cs.InternalPorts) >= 3 {
		addSignal("pivot-mixed-protocol-internal")
	}

	// pivot-non-loopback-internal: connections to non-loopback internal IPs
	// (RFC1918: 10.x, 172.16-31.x, 192.168.x). Excludes 127.0.0.1 (IPC).
	// Only fires when process has NO external connections — a pure relay child
	// (sshd -z SOCKS handler) only makes internal connections. A session with
	// both external (C2) and internal (commands) is NOT a pivot — those internal
	// connections are its own lateral movement, not proxied tunnel traffic.
	if cs.NonLoopbackInternalCount > 0 && c.OutExternal == 0 {
		addSignal("pivot-non-loopback-internal")
	}

	// pivot-socks-candidate: SOCKS proxy indicators (port, library, flags).
	if shared.HasProxyFlags(p.CmdLine) || cs.HasProxyLib {
		addSignal("pivot-socks-candidate")
	}

	// pivot-reverse-tunnel-shape: external control + internal connections.
	// Known vendors with external + internal are normal (sync apps, browsers).
	if c.OutExternal > 0 && c.OutInternal > 0 {
		addSignal("pivot-reverse-tunnel-shape")
	}

	// pivot-conn-count-correlation: connection count in/out roughly balanced (relay).
	if c.InboundTotal > 0 && c.OutTotal > 0 {
		ratio := float64(c.InboundTotal) / float64(c.OutTotal)
		if ratio > 0.3 && ratio < 3.0 {
			addSignal("pivot-conn-count-correlation")
		}
	}

	// pivot-named-pipe-c2-pattern: C2-like named pipe detected.
	namedPipeHardMatch := false
	for _, pipe := range c.NamedPipes {
		if IsC2PipeName(pipe) {
			addSignal("pivot-named-pipe-c2-pattern")
			namedPipeHardMatch = true
			break
		}
	}

	// pivot-named-pipe-random-name: broader fallback for Mythic / custom
	// implant pipe names the hard-pattern list can't catch. Shadow-only
	// — not in pivotSignals, so it doesn't vote in InferRoleFromSignals.
	// Only considered when the hard match missed, the process is
	// non-vendor, and the pipe shape actually looks random.
	if !namedPipeHardMatch && !shared.IsKnownVendorProcess(p) {
		for _, pipe := range c.NamedPipes {
			if IsSuspiciousRandomPipeName(pipe) {
				addSignal("pivot-named-pipe-random-name")
				break
			}
		}
	}

	// pivot-admin-share-smb: SMB connections to internal targets (port 445).
	if cs.InternalPorts[445] > 0 {
		addSignal("pivot-admin-share-smb")
	}

	// pivot-ssh-tunnel-flags: SSH tunnel flags in command line.
	if p.CmdLine != "" {
		cmdLower := strings.ToLower(p.CmdLine)
		nameLower := cs.NameLower
		if (strings.Contains(nameLower, "ssh") || strings.Contains(nameLower, "plink")) &&
			(strings.Contains(cmdLower, " -l ") || strings.Contains(cmdLower, " -r ") || strings.Contains(cmdLower, " -d ")) {
			addSignal("pivot-ssh-tunnel-flags")
		}
	}

	// pivot-proxy-lib-loaded: proxy/tunnel library loaded.
	if cs.HasProxyLib {
		addSignal("pivot-proxy-lib-loaded")
	}

	// pivot-high-handle-count: high handle/FD count with network activity.
	// Browsers and WebView2 naturally hold many handles — only meaningful
	// for unknown processes.
	if (p.HandleCount > 200 || p.FDCount > 200) && c.OutTotal > 0 {
		addSignal("pivot-high-handle-count")
	}

	// pivot-elevated-relay: elevated privilege with internal+external connections.
	if (p.Integrity == "System" || p.Integrity == "High") && c.OutInternal > 0 && c.OutExternal > 0 {
		addSignal("pivot-elevated-relay")
	}

	// pivot-service-like-no-service: session 0 process with network activity that
	// hasn't established a stable benign baseline. Uses behavioral stability
	// (observation count + low suspicious ratio) instead of process name checks
	// — name-based gates are bypassable via injection/DLL hijacking.
	if p.SessionID == 0 && c.OutTotal > 0 {
		stableService := false
		if behavior := shared.ProcessBehaviorByKey[ctx.BehaviorKey]; behavior != nil {
			stableService = behavior.Observations >= 10 &&
				float64(behavior.SuspiciousObservations)/float64(max(1, behavior.Observations)) <= 0.25
		}
		if !stableService {
			addSignal("pivot-service-like-no-service")
		}
	}

	// pivot-high-fd-count: many file descriptors (socket broker).
	if p.FDCount > 100 && c.InboundTotal > 0 {
		addSignal("pivot-high-fd-count")
	}

	// pivot-anon-exec-memory: anonymous executable memory (reflective loading).
	if p.AnonExecCount > 0 && c.OutInternal > 0 {
		addSignal("pivot-anon-exec-memory")
	}

	// injection-rwx-external: shadow-only signal for reflective-loaded /
	// injected implants (Kharon-Mtc, CS spawnto, Sliver migrate). Fires
	// when a non-vendor process has anonymous RWX memory regions AND
	// external outbound traffic. Existing pivot-anon-exec-memory only
	// covers the lateral (internal) case; this extends the same idea to
	// beacon-style external C2. Not in pivotSignals — it doesn't vote
	// yet. Gate on unknown-vendor so JIT runtimes (CoreCLR, V8) don't
	// trip it every time they touch the internet.
	if (p.HasRWXMemory || p.AnonExecCount > 0) &&
		c.OutExternal > 0 &&
		!shared.IsKnownVendorProcess(p) &&
		p.SignatureTrust != shared.SignatureTrustTrusted {
		addSignal("injection-rwx-external")
	}

	// wg-udp-shape: shadow-only signal for WireGuard-style C2 transport
	// (Sliver `wg`). Fires when a non-vendor process owns a UDP listener
	// on the WireGuard default port (51820) or on a high-port UDP
	// listener with no TCP activity — the classic WG implant shape. UDP
	// outbound isn't tracked yet, so we only pattern-match listeners.
	// Not in pivotSignals.
	if len(c.UDPListeners) > 0 && !shared.IsKnownVendorProcess(p) &&
		p.SignatureTrust != shared.SignatureTrustTrusted {
		for _, ul := range c.UDPListeners {
			if ul.LocalPort == 51820 {
				addSignal("wg-udp-shape")
				break
			}
			// High-port UDP listener + no TCP listeners + minimal TCP
			// outbound: UDP-only implant shape.
			if ul.LocalPort >= 40000 && len(c.Listeners) == 0 && c.OutTotal <= 1 {
				addSignal("wg-udp-shape")
				break
			}
		}
	}
}
