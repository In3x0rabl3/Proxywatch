package behavior

import "proxywatch/internal/shared"

// EmitListenerSignals emits the LISTENER signals (13 signals).
// Returns early if the candidate has no listeners.
func EmitListenerSignals(c *shared.Candidate, addSignal func(string), ctx SignalContext, cs CommonState) {
	p := c.Proc

	if len(c.Listeners) == 0 && len(c.UDPListeners) == 0 {
		return
	}

	// listener-open-port-awaiting: has TCP listener(s).
	if len(c.Listeners) > 0 {
		addSignal("listener-open-port-awaiting")
	}

	// listener-wildcard-bind: listener bound to wildcard address.
	for _, l := range c.Listeners {
		if shared.IsWildcardIP(l.LocalAddress) {
			addSignal("listener-wildcard-bind")
			break
		}
	}

	// listener-accepting-multiple-clients: multiple inbound connections.
	if c.InboundTotal >= 2 {
		addSignal("listener-accepting-multiple-clients")
	}

	// listener-inbound-external: accepting connections from outside.
	for _, conn := range c.Conns {
		if conn.State == "ESTABLISHED" && !shared.IsInternalIP(conn.RemoteAddress) && !shared.IsLoopbackIP(conn.RemoteAddress) {
			for _, l := range c.Listeners {
				if l.LocalPort == conn.LocalPort {
					addSignal("listener-inbound-external")
					goto doneInboundExternal
				}
			}
		}
	}
doneInboundExternal:

	// listener-local-server: listener serving local clients, no external.
	if len(c.Listeners) > 0 && c.InboundTotal > 0 && c.OutExternal == 0 {
		addSignal("listener-local-server")
	}

	// listener-uncommon-port: listening on uncommon port.
	commonPorts := map[int]bool{22: true, 80: true, 443: true, 3389: true, 8080: true, 8443: true, 53: true, 25: true, 445: true}
	for _, l := range c.Listeners {
		if l.LocalPort > 0 && !commonPorts[l.LocalPort] {
			addSignal("listener-uncommon-port")
			break
		}
	}

	// listener-service-context: listener running in session 0 (service context).
	if p.SessionID == 0 && len(c.Listeners) > 0 {
		addSignal("listener-service-context")
	}

	// listener-long-idle: listener open but no recent activity.
	if len(c.Listeners) > 0 && c.InboundTotal == 0 && c.OutTotal == 0 && c.SeenSeconds > 120 {
		addSignal("listener-long-idle")
	}

	// listener-named-pipe-server: named pipe handles present with listener.
	if len(c.NamedPipes) > 0 && len(c.Listeners) > 0 {
		addSignal("listener-named-pipe-server")
	}

	// listener-high-memory: high memory usage with listener.
	if p.MemUsage > 100*1024*1024 && len(c.Listeners) > 0 {
		addSignal("listener-high-memory")
	}

	// listener-no-children: listener with no child processes.
	if len(c.Listeners) > 0 && c.Proc.ChildCount == 0 {
		addSignal("listener-no-children")
	}

	// listener-mixed-protocol: listener on multiple ports or UDP+TCP.
	if (len(c.Listeners) >= 2) || (len(c.Listeners) > 0 && len(c.UDPListeners) > 0) {
		addSignal("listener-mixed-protocol")
	}

	// listener-low-thread-count: few threads (simple daemon).
	if p.ThreadCount > 0 && p.ThreadCount <= 5 && len(c.Listeners) > 0 {
		addSignal("listener-low-thread-count")
	}
}
