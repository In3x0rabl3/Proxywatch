package features

import (
	"strings"

	"proxywatch/internal/shared"
)

// extractPivot computes pivot-role features (indices 48-72).
func extractPivot(c *shared.Candidate, fv *FeatureVector) {
	hasListener := len(c.Listeners) > 0
	hasInbound := c.InboundTotal > 0

	// (N) FPivotInboundOutboundRatio — inbound/outbound balance.
	if c.OutTotal > 0 {
		fv.Values[FPivotInboundOutboundRatio] = safeDiv(float64(c.InboundTotal), float64(c.OutTotal))
	}

	// (N) FPivotThroughputSymmetry — BPS rate symmetry.
	if c.Proc != nil {
		r := float64(c.Proc.IOReadBps)
		w := float64(c.Proc.IOWriteBps)
		maxRW := r
		if w > maxRW {
			maxRW = w
		}
		if maxRW > 0 {
			minRW := r
			if w < minRW {
				minRW = w
			}
			fv.Values[FPivotThroughputSymmetry] = minRW / maxRW
		}
	}

	// (N) FPivotIOBalance — cumulative read/write balance.
	if c.Proc != nil {
		totalIO := float64(c.Proc.IOReadBytes + c.Proc.IOWriteBytes)
		if totalIO > 0 {
			diff := float64(c.Proc.IOReadBytes) - float64(c.Proc.IOWriteBytes)
			if diff < 0 {
				diff = -diff
			}
			fv.Values[FPivotIOBalance] = 1.0 - diff/totalIO
		}
	}

	// (N) FPivotMultiplexRatio — clients per listener.
	if hasListener && c.InboundTotal > 0 {
		fv.Values[FPivotMultiplexRatio] = float64(c.InboundTotal) / float64(len(c.Listeners))
	}

	// (N) FPivotFanOutFromListener — outbound when has listener.
	if hasListener {
		fv.Values[FPivotFanOutFromListener] = float64(c.OutTotal)
	}

	// (N) FPivotPortDiversityThruProcess — distinct outbound ports through listener.
	if hasListener {
		fv.Values[FPivotPortDiversityThruProcess] = float64(countDistinctOutboundPorts(c.Conns))
	}

	// (N) FPivotLoopbackRelayToExternal — loopback in -> external out.
	hasLoopbackIn := false
	for _, cn := range c.Conns {
		if shared.IsLoopbackIP(cn.RemoteAddress) && isInboundConn(cn, c.Listeners) {
			hasLoopbackIn = true
			break
		}
	}
	fv.Values[FPivotLoopbackRelayToExternal] = boolFloat(hasLoopbackIn && c.OutExternal > 0)

	// (N) FPivotExternalRelayToLoopback — external in -> loopback out.
	fv.Values[FPivotExternalRelayToLoopback] = boolFloat(!hasLoopbackIn && hasInbound && c.OutLoopback > 0)

	// (N) FPivotConcurrentBidirectional — min(inbound, outbound).
	fv.Values[FPivotConcurrentBidirectional] = float64(minInt(c.InboundTotal, c.OutTotal))

	// (N) FPivotSOCKSCandidate — loopback listener + diverse ports.
	fv.Values[FPivotSOCKSCandidate] = boolFloat(
		hasListener && allListenersLoopback(c.Listeners) &&
			c.OutExternal > 0 && countDistinctOutboundPorts(c.Conns) >= 3)

	// (N) FPivotIOPerClient — bytes per inbound client.
	if c.InboundTotal > 0 && c.Proc != nil {
		totalIO := float64(c.Proc.IOReadBytes + c.Proc.IOWriteBytes)
		fv.Values[FPivotIOPerClient] = totalIO / float64(c.InboundTotal)
	}

	// (N) FPivotSMBConnCount — SMB connections.
	smbConns := 0
	smbTargetSet := make(map[string]struct{})
	allSMBInternal := true
	for _, cn := range c.Conns {
		if cn.RemotePort == 445 || cn.RemotePort == 139 {
			smbConns++
			smbTargetSet[cn.RemoteAddress] = struct{}{}
			if !shared.IsInternalIP(cn.RemoteAddress) {
				allSMBInternal = false
			}
		}
	}
	fv.Values[FPivotSMBConnCount] = float64(smbConns)

	// (N) FPivotSMBDistinctTargets — unique SMB targets.
	fv.Values[FPivotSMBDistinctTargets] = float64(len(smbTargetSet))

	// (N) FPivotSMBAllInternal — all SMB internal flag.
	fv.Values[FPivotSMBAllInternal] = boolFloat(allSMBInternal && smbConns > 0)

	// (H) FPivotNamedPipeCount — named pipes owned.
	fv.Values[FPivotNamedPipeCount] = float64(len(c.NamedPipes))

	// (H) FPivotNamedPipeC2Pattern — C2-like pipe name flag.
	for _, pipe := range c.NamedPipes {
		if isC2PipeName(pipe) {
			fv.Values[FPivotNamedPipeC2Pattern] = 1
			break
		}
	}

	// (H) FPivotNamedPipeAdmin — admin pipe name flag.
	for _, pipe := range c.NamedPipes {
		if isWellKnownAdminPipe(pipe) {
			fv.Values[FPivotNamedPipeAdmin] = 1
			break
		}
	}

	// (H) FPivotCmdHasTunnelFlags — tunnel flags in cmdline.
	if c.Proc != nil {
		cmd := strings.ToLower(c.Proc.CmdLine)
		fv.Values[FPivotCmdHasTunnelFlags] = boolFloat(
			strings.Contains(cmd, " -l ") || strings.Contains(cmd, " -r ") ||
				strings.Contains(cmd, " -d ") || strings.Contains(cmd, " -w ") ||
				strings.Contains(cmd, "--connect") || strings.Contains(cmd, "--proxy") ||
				strings.Contains(cmd, "--socks"))
	}

	// (H) FPivotHasProxyLib — proxy/tunnel library loaded.
	if c.Proc != nil {
		for _, lib := range c.Proc.LoadedLibs {
			l := strings.ToLower(lib)
			if strings.Contains(l, "proxy") || strings.Contains(l, "socks") || strings.Contains(l, "tunnel") {
				fv.Values[FPivotHasProxyLib] = 1
				break
			}
		}
	}

	// (H) FPivotListenerCount — listener port count.
	fv.Values[FPivotListenerCount] = float64(len(c.Listeners))

	// (H) FPivotListenerLoopbackOnly — all listeners on loopback.
	fv.Values[FPivotListenerLoopbackOnly] = boolFloat(hasListener && allListenersLoopback(c.Listeners))

	// (H) FPivotListenerEphemeral — listener on high port.
	for _, l := range c.Listeners {
		if l.LocalPort > 49152 {
			fv.Values[FPivotListenerEphemeral] = 1
			break
		}
	}

	// (H) FPivotListenerPortSpread — port range spread.
	if hasListener {
		minP, maxP := listenerPortRange(c.Listeners)
		fv.Values[FPivotListenerPortSpread] = float64(maxP - minP)
	}

	// (H) FPivotIntegrityLevel — integrity level.
	if c.Proc != nil {
		fv.Values[FPivotIntegrityLevel] = integrityToFloat(c.Proc.Integrity)
	}

	// (H) FPivotIsServiceContext — runs as service flag.
	if c.Proc != nil {
		fv.Values[FPivotIsServiceContext] = boolFloat(shared.IsServiceLikeContext(c.Proc))
	}
}
