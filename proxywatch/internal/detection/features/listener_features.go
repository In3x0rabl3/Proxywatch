package features

import (
	"time"

	"proxywatch/internal/shared"
)

// extractListener computes listener-role features (indices 95-116).
func extractListener(c *shared.Candidate, fv *FeatureVector) {
	// (N) FListenerPortCount — distinct listener ports.
	fv.Values[FListenerPortCount] = float64(len(c.Listeners))

	// (N) FListenerPortMin, FListenerPortMax — port range.
	if len(c.Listeners) > 0 {
		minP, maxP := listenerPortRange(c.Listeners)
		fv.Values[FListenerPortMin] = float64(minP)
		fv.Values[FListenerPortMax] = float64(maxP)
	}

	// (N) FListenerWildcardCount — 0.0.0.0 bindings.
	wildcardCount := 0
	loopbackCount := 0
	for _, l := range c.Listeners {
		if shared.IsWildcardIP(l.LocalAddress) {
			wildcardCount++
		}
		if shared.IsLoopbackIP(l.LocalAddress) {
			loopbackCount++
		}
	}
	fv.Values[FListenerWildcardCount] = float64(wildcardCount)

	// (N) FListenerLoopbackCount — 127.0.0.1 bindings.
	fv.Values[FListenerLoopbackCount] = float64(loopbackCount)

	// (N) FListenerUDPCount — UDP listeners.
	fv.Values[FListenerUDPCount] = float64(len(c.UDPListeners))

	// (N) FListenerInboundTotal — inbound connections.
	fv.Values[FListenerInboundTotal] = float64(c.InboundTotal)

	// (N) FListenerInboundExternal, FListenerInboundInternal — scope breakdown.
	inExt, inInt, inLoop := countInboundByScope(c.Conns, c.Listeners)
	fv.Values[FListenerInboundExternal] = float64(inExt)
	fv.Values[FListenerInboundInternal] = float64(inInt)

	// (N) FListenerDistinctClients — unique inbound sources.
	fv.Values[FListenerDistinctClients] = float64(countDistinctSources(c.Conns, c.Listeners))

	// (N) FListenerNoOutbound — zero outbound flag.
	fv.Values[FListenerNoOutbound] = boolFloat(c.OutTotal == 0)

	// (H) FListenerIsServiceContext — service account flag.
	if c.Proc != nil {
		fv.Values[FListenerIsServiceContext] = boolFloat(shared.IsServiceLikeContext(c.Proc))
	}

	// (H) FListenerProcessAgeSec — process age.
	if c.Proc != nil && !c.Proc.StartTime.IsZero() {
		fv.Values[FListenerProcessAgeSec] = time.Since(c.Proc.StartTime).Seconds()
	}

	// (H) FListenerIOTotalRate — throughput rate.
	if c.Proc != nil {
		fv.Values[FListenerIOTotalRate] = float64(c.Proc.IOReadBps + c.Proc.IOWriteBps + c.Proc.IOOtherBps)
	}

	// (H) FListenerProcessMemMB — working set MB.
	if c.Proc != nil {
		fv.Values[FListenerProcessMemMB] = float64(c.Proc.MemUsage) / (1024 * 1024)
	}

	// (H) FListenerHasRawSocket — raw socket flag.
	fv.Values[FListenerHasRawSocket] = boolFloat(c.RawSocket)

	// (H) FListenerHasNamedPipes — has named pipes.
	fv.Values[FListenerHasNamedPipes] = boolFloat(len(c.NamedPipes) > 0)

	// (H) FListenerChildCount — child process count.
	if c.Proc != nil {
		fv.Values[FListenerChildCount] = float64(c.Proc.ChildCount)
	}

	// (H) FListenerHighPort — all ports >1024 flag.
	allHigh := len(c.Listeners) > 0
	for _, l := range c.Listeners {
		if l.LocalPort <= 1024 {
			allHigh = false
			break
		}
	}
	fv.Values[FListenerHighPort] = boolFloat(allHigh)

	// (H) FListenerConnSamePortRatio — traffic on primary port.
	if len(c.Listeners) > 0 && c.InboundTotal > 0 {
		// Find port with most inbound connections.
		portCount := make(map[int]int)
		listenerPorts := make(map[int]struct{})
		for _, l := range c.Listeners {
			listenerPorts[l.LocalPort] = struct{}{}
		}
		for _, cn := range c.Conns {
			if _, ok := listenerPorts[cn.LocalPort]; ok {
				portCount[cn.LocalPort]++
			}
		}
		maxCount := 0
		for _, count := range portCount {
			if count > maxCount {
				maxCount = count
			}
		}
		fv.Values[FListenerConnSamePortRatio] = safeDiv(float64(maxCount), float64(c.InboundTotal))
	}

	// (H) FListenerInboundLoopback — loopback inbound count.
	fv.Values[FListenerInboundLoopback] = float64(inLoop)

	// (H) FListenerEstablishedOnListenerPorts — ESTABLISHED on listener ports.
	if len(c.Listeners) > 0 {
		listenerPorts := make(map[int]struct{})
		for _, l := range c.Listeners {
			listenerPorts[l.LocalPort] = struct{}{}
		}
		estCount := 0
		for _, cn := range c.Conns {
			if cn.State == "ESTABLISHED" {
				if _, ok := listenerPorts[cn.LocalPort]; ok {
					estCount++
				}
			}
		}
		fv.Values[FListenerEstablishedOnListenerPorts] = float64(estCount)
	}
}
