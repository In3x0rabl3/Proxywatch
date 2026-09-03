package behavior

import "proxywatch/internal/shared"

// emitRichLocalIPCSignal fires rich-local-ipc-shape when a process
// exhibits the desktop / Electron-app IPC pattern: two or more bound
// loopback listener ports (TCP + UDP combined) AND two or more
// established loopback flows.
//
// Shadow-only — this signal is NOT in beaconSignals / pivotSignals /
// outboundSignals and therefore does not vote in
// InferRoleFromSignals. It surfaces in /candidates and /fp-report so
// operators can measure how reliably it distinguishes the legitimate
// Zoom / Slack / CloudSync / Docker / IDE-plus-language-server
// pattern from a process impersonating that shape. Graduation to a
// vendor-signal-count contributor in the FP-shape demotion path
// depends on that FP-rate data.
//
// A sophisticated implant can fake this pattern (spin up dummy
// loopback listeners, generate synthetic loopback traffic), so this
// signal is never the sole gate for any role decision. Intended as
// one input to a multi-signal identity stack that also requires
// valid Authenticode signature, trusted install path, publisher DNS
// alignment, and absence of injection markers.
func emitRichLocalIPCSignal(c *shared.Candidate, addSignal func(string)) {
	if c == nil {
		return
	}

	loopbackListeners := 0
	for _, l := range c.Listeners {
		if shared.IsLoopbackIP(l.LocalAddress) {
			loopbackListeners++
		}
	}
	for _, ul := range c.UDPListeners {
		if shared.IsLoopbackIP(ul.LocalAddress) {
			loopbackListeners++
		}
	}
	if loopbackListeners < 2 {
		return
	}

	loopbackFlows := 0
	for _, cn := range c.Conns {
		if cn.State != "ESTABLISHED" {
			continue
		}
		if shared.IsLoopbackIP(cn.RemoteAddress) {
			loopbackFlows++
		}
	}

	// Two firing shapes:
	//
	//   a) listeners >= 2 AND flows >= 2 — classic Electron helper
	//      mesh actively servicing multiple clients right now
	//      (Zoom + helpers, VS Code + LSPs).
	//   b) listeners >= 3 AND flows >= 1 — idle-between-polls shape
	//      common to Electron apps like CloudSync that hold three
	//      or more bound loopback ports but only have one active
	//      flow between polling bursts. The >= 3 listener bar keeps
	//      the shape tight enough that trivial two-socket implant
	//      impersonation still fails; the flow requirement ensures
	//      the listeners are alive and servicing real clients
	//      rather than being dummy sockets.
	switch {
	case loopbackFlows >= 2:
		// path (a) — classic.
	case loopbackListeners >= 3 && loopbackFlows >= 1:
		// path (b) — idle helper mesh.
	default:
		return
	}

	addSignal("rich-local-ipc-shape")
}
