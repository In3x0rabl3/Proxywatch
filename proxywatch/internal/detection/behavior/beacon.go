package behavior

import "proxywatch/internal/shared"

// EmitBeaconSignals emits callback/timing signals for control-channel detection.
// No vendor gates — all signals fire for all processes. The outbound suppression
// in InferRoleFromSignals handles the balance via signal counts.
func EmitBeaconSignals(c *shared.Candidate, addSignal func(string), ctx SignalContext, cs CommonState) {
	p := c.Proc

	// beacon-interval-confirmed: confirmed beacon cadence from burst tracker.
	if c.BeaconIntervalMs > 0 {
		addSignal("beacon-interval-confirmed")
	}

	// beacon-syn-cycle-cadence: SYN_SENT cycling reveals callback cadence.
	// Require few external targets — a process with many connections (Chrome, browsers)
	// may SYN cycle on one target while connecting to many others normally. C2 beacons
	// have 1-3 targets.
	if synHist := shared.SYNCycleByPID[ctx.ScopedPID]; synHist != nil && synHist.Cycles >= 2 && c.OutExternal <= 3 {
		addSignal("beacon-syn-cycle-cadence")
	}

	// beacon-target-lock: single persistent external target, no internal/inbound.
	if c.OutExternal == 1 && c.OutInternal == 0 && c.InboundTotal == 0 && c.OutLongLived >= 1 {
		addSignal("beacon-target-lock")
	}

	// beacon-http-channel: all external connections use HTTP/HTTPS ports only.
	if cs.AllHTTPPorts && c.OutTotal > 0 && c.OutExternal > 0 {
		addSignal("beacon-http-channel")
	}

	// beacon-endpoint-rotation: multiple external IPs on same port (C2 rotation).
	for _, count := range cs.ExtPortCounts {
		if count >= 2 && c.OutExternal >= 2 {
			addSignal("beacon-endpoint-rotation")
			break
		}
	}

	// beacon-non-standard-port: external connection on non-standard port.
	if cs.HasNonStandardPort && c.OutTotal > 0 {
		addSignal("beacon-non-standard-port")
	}

	// beacon-reconnecting-unknown-vendor: unknown-vendor process with recurring callbacks.
	if shared.ShortLivedBurstHits[ctx.ScopedPID] >= 3 &&
		c.OutExternal > 0 && c.OutInternal == 0 {
		addSignal("beacon-reconnecting-unknown-vendor")
	}

	// beacon-sleep-wake-cycle: old process, very few connections (long sleep intervals).
	if c.SeenSeconds > 1800 && c.OutTotal <= 1 && c.OutTotal >= 0 {
		addSignal("beacon-sleep-wake-cycle")
	}

	// beacon-micro-payload: tiny data exchange for process age.
	if c.SeenSeconds > 120 && cs.TotalIO > 0 && cs.IOPerSec < 50 && c.OutTotal > 0 {
		addSignal("beacon-micro-payload")
	}

	// beacon-low-cpu-long-life: long-running process with minimal CPU usage.
	if c.SeenSeconds > 600 && p.CpuTime.Seconds() < 5.0 && c.OutTotal > 0 {
		addSignal("beacon-low-cpu-long-life")
	}

	// beacon-io-read-dominant: IO shape dominated by reads (fetching commands).
	if cs.TotalIO > 1024 && cs.TotalIO < 5*1024*1024 && c.OutTotal > 0 {
		readRatio := float64(p.IOReadBytes) / float64(cs.TotalIO)
		if readRatio > 0.55 && readRatio < 0.90 {
			addSignal("beacon-io-read-dominant")
		}
	}

	// beacon-no-children: no child processes spawned.
	if c.Proc.ChildCount == 0 && c.OutTotal > 0 {
		addSignal("beacon-no-children")
	}

	// beacon-crypto-lib-loaded: crypto/TLS library loaded.
	if cs.HasCryptoLib && c.OutTotal > 0 {
		addSignal("beacon-crypto-lib-loaded")
	}

	// beacon-static-crypto-likely: external traffic (typically HTTPS) with
	// ZERO dynamic crypto libraries loaded. Classic fingerprint of
	// statically-linked Go / Rust / Nim / Zig beacons — Sliver, Merlin,
	// Poseidon, Thanatos, Nimplant, Freyja all bundle crypto/tls into the
	// binary instead of linking schannel / bcrypt / libssl. Legitimate
	// Windows apps making HTTPS calls go through one of those system DLLs
	// and fire beacon-crypto-lib-loaded; an unknown-vendor, unsigned
	// process with external traffic and no crypto DLLs is suspicious.
	//
	// Gated on:
	//   1. OutExternal > 0 — external traffic exists.
	//   2. !HasCryptoLib — no schannel/bcrypt/openssl etc. observed.
	//   3. !IsKnownVendorProcess — known-vendor Electron / Slack / Teams
	//      / VS Code bundle their own crypto but are NOT a threat.
	//   4. SignatureTrust != trusted — OS-signed binaries from
	//      unrecognized vendors are also excluded. Only unsigned or
	//      distrusted binaries trip the signal.
	if c.OutExternal > 0 &&
		!cs.HasCryptoLib &&
		!shared.IsKnownVendorProcess(p) &&
		p.SignatureTrust != shared.SignatureTrustTrusted {
		addSignal("beacon-static-crypto-likely")
	}

	// lots-saas-c2-endpoint: persistent connection to a Slack/Discord/
	// GitHub/MQTT/Telegram/Dropbox API endpoint from an unknown-vendor
	// unsigned process. Mythic ships C2 profiles for each of these.
	// Shadow-only: see behavior/saas.go for the full endpoint list.
	emitSaaSC2Signal(c, addSignal)

	// cdn-fronted-c2-candidate: shadow-only signal for CDN domain
	// fronting (Cobalt Strike / Sliver / custom implants relaying
	// through Cloudflare, Azure, CloudFront, Fastly, Akamai). Fires
	// when an unknown-vendor unsigned process maintains persistent
	// HTTPS traffic to a destination whose ASN belongs to a CDN.
	// Legitimate vendor apps that use CDN infrastructure are
	// whitelisted via IsKnownVendorProcess; this signal specifically
	// targets the "random binary dropped in user-writable path that
	// happens to talk to a CDN" pattern.
	//
	// Not in controlSignals / outboundSignals / pivotSignals — ship
	// as shadow, measure FP rate, graduate to role-promotion later.
	emitCDNFrontedSignal(c, addSignal)

	// beacon-memory-stable: stable low memory footprint over time.
	if c.OutTotal > 0 {
		if hist := shared.ProcHistoryByPID[ctx.ScopedPID]; hist != nil && len(hist.MemSamples) >= 5 {
			mean := uint64(0)
			for _, s := range hist.MemSamples {
				mean += s
			}
			mean /= uint64(len(hist.MemSamples))
			variance := uint64(0)
			for _, s := range hist.MemSamples {
				diff := int64(s) - int64(mean)
				variance += uint64(diff * diff)
			}
			variance /= uint64(len(hist.MemSamples))
			if mean > 0 && float64(variance) < float64(mean)*float64(mean)*0.01 {
				addSignal("beacon-memory-stable")
			}
		}
	}

	// beacon-thread-minimal: very few threads (pure callback, no thread pool).
	if p.ThreadCount > 0 && p.ThreadCount <= 3 && c.OutTotal > 0 {
		addSignal("beacon-thread-minimal")
	}

	// beacon-short-lived-callback: connects briefly then disconnects (beacon sleep pattern).
	if c.OutShortLived > 0 && c.OutLongLived == 0 && c.OutExternal > 0 {
		addSignal("beacon-short-lived-callback")
	}
}
