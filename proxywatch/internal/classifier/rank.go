package classifier

import (
	"fmt"
	"math"
	"strings"
	"time"

	"proxywatch/internal/shared"
)

func ScoreCandidate(c *shared.Candidate) {
	scoreVal := 0
	reasons := []string{}
	signals := []string{}
	addSignal := func(s string) {
		for _, existing := range signals {
			if existing == s {
				return
			}
		}
		signals = append(signals, s)
	}

	p := c.Proc
	now := time.Now()
	benignClient := shared.IsLikelyBenignControlClient(p)
	delegatedReason := ""
	if c.DelegatedEgress {
		addSignal("delegated-egress")
		if c.DelegatedStrong {
			addSignal("delegated-egress-strong")
		}
		owner := c.DelegatedOwner
		if owner == "" {
			owner = "(unknown)"
		}
		if c.DelegatedOwnerPID > 0 {
			delegatedReason = fmt.Sprintf(
				"No direct socket ownership observed; likely delegated via %s (PID %d)",
				owner,
				c.DelegatedOwnerPID,
			)
		} else {
			delegatedReason = "No direct socket ownership observed; likely delegated via proxy broker process"
		}
	}
	hist := getHistory(p.Pid, now)
	updateConnHistory(p.Pid, c.Conns, now)
	updateParentFreq(p)
	parentKey := fmt.Sprintf("%d|%s|%s", p.ParentPid, p.Name, p.ExePath)
	rareParent := shared.ParentChildFreq[parentKey] <= 1

	ports, loopbackOnly, anyWildcard := socksListenerPorts(c.Listeners)
	hasListener := len(ports) > 0

	activeClients, _ := countActiveClientSessions(c.Conns, ports)
	outTotal, outExternal, outInternal, outLoopback := outboundTargets(c.Conns, ports)
	outLongLived, outShortLived := outboundConnAgeStats(c.Conns, ports, now)

	c.OutTotal = outTotal
	c.OutExternal = outExternal
	c.OutInternal = outInternal
	c.OutLoopback = outLoopback
	c.OutLongLived = outLongLived
	c.OutShortLived = outShortLived
	c.InboundTotal = activeClients

	// Shape drift detection
	totalNet := c.OutTotal + c.InboundTotal + c.OutLoopback
	if totalNet > 0 {
		curOut := float64(c.OutTotal) / float64(totalNet)
		curIn := float64(c.InboundTotal) / float64(totalNet)
		curLoop := float64(c.OutLoopback) / float64(totalNet)
		if hist.ShapeSamples > 0 {
			if shapeDelta(curOut, hist.LastOutRatio) > shared.ShapeDeltaThreshold ||
				shapeDelta(curIn, hist.LastInRatio) > shared.ShapeDeltaThreshold ||
				shapeDelta(curLoop, hist.LastLoopRatio) > shared.ShapeDeltaThreshold {
				addSignal("shape-drift")
			}
		}
		hist.LastOutRatio = curOut
		hist.LastInRatio = curIn
		hist.LastLoopRatio = curLoop
		hist.ShapeSamples++
	}

	if activeClients > 0 {
		addSignal("inbound-active")
		shared.RecentClientSeen[p.Pid] = now
	}
	inboundBurst := updateInboundBurst(p.Pid, activeClients, now)
	if inboundBurst > 0 {
		addSignal("inbound-burst")
	}
	if outTotal > 0 {
		addSignal("outbound-active")
		shared.RecentOutboundSeen[p.Pid] = now
	}
	if outInternal > 0 {
		addSignal("outbound-internal")
	}
	if outExternal > 0 {
		addSignal("outbound-external")
	}
	if outLoopback > 0 {
		addSignal("outbound-loopback")
	}
	if outLongLived > 0 {
		addSignal("outbound-long-lived")
	}
	if outShortLived > 0 && outLongLived == 0 {
		addSignal("outbound-bursty")
	}
	burstCount := 0
	switch {
	case outShortLived > 0:
		burstCount = outShortLived
	case outTotal > 0 && outLongLived == 0:
		burstCount = outTotal
	}

	inboundRecent := activeClients > 0
	if t, ok := shared.RecentClientSeen[p.Pid]; ok && now.Sub(t) <= shared.ActiveWindow {
		inboundRecent = true
	}

	outboundRecent := outTotal > 0
	if t, ok := shared.RecentOutboundSeen[p.Pid]; ok && now.Sub(t) <= shared.ActiveWindow {
		outboundRecent = true
	}

	forwardActiveNow := hasListener && inboundRecent && outboundRecent

	controlConn, controlSecs := findPersistentControl(p.Pid, c.Conns, now)
	if controlConn != nil {
		addSignal("control-channel")
		c.ControlChannel = controlConn
		c.ControlDurationSeconds = controlSecs
	}

	reverseProxyNow := false

	outboundActive, distinctTargets, distinctTargetPorts, targetPrefixes := outboundActivity(c.Conns, ports)
	internalTargets, internalPorts, internalLateral := outboundInternalSummary(c.Conns, ports)
	internalFanoutScore := internalFanoutBoost(internalTargets, internalPorts)
	reverseTunnelEligible := internalLateral ||
		(len(internalTargets) >= shared.MinInternalTargetsForRev &&
			len(internalPorts) >= shared.MinInternalPortsForRev)
	if benignClient && !internalLateral {
		reverseTunnelEligible = false
		addSignal("reverse-tunnel-shape-suppressed-benign")
	}

	// Cross-proc rare tuple tracking (remote prefix + port) to surface repeated rare C2 patterns.
	for pref := range targetPrefixes {
		key := pref
		shared.RareTupleCount[key]++
		if shared.RareTupleCount[key] > 1 {
			addSignal("rare-target-repeat")
		}
	}

	updateBurstHistory(p.Pid, burstCount, now)
	internalScanNow := reverseTunnelEligible
	if internalScanNow {
		shared.RecentInternalScanSeen[p.Pid] = now
	}

	localTransport, localCount := localTransportActivity(c.Conns)
	localTransportForwarding := localTransport && (hasListener || activeClients > 0)
	if localTransportForwarding {
		addSignal("loopback-transport")
		shared.LocalTransportLast[p.Pid] = now
	}
	localServiceProxyLikely := isLikelyLocalServiceProxy(controlConn, ports, c.Conns)
	if localServiceProxyLikely {
		addSignal("local-service-proxy-shape")
	}
	forwardTunnelLikely := isLikelyForwardTunnel(hasListener, loopbackOnly, controlConn, ports, outTotal, len(distinctTargets), activeClients, inboundRecent) && !localServiceProxyLikely
	if forwardTunnelLikely {
		addSignal("forward-tunnel-shape")
	}

	if controlConn != nil && !hasListener {
		controlKey := connKeyFromConn(p.Pid, *controlConn)
		proxyOutTotal, _, _ := outboundTargetsExcluding(c.Conns, ports, &controlKey)
		if proxyOutTotal > 0 && reverseTunnelEligible {
			reverseProxyNow = true
		}
	}

	if !reverseProxyNow && !hasListener && outInternal > 0 && reverseTunnelEligible {
		reverseProxyNow = true
	}
	if reverseProxyNow && benignClient && !internalLateral && outExternal > 0 {
		reverseProxyNow = false
		addSignal("reverse-proxy-suppressed-benign-fanout")
	}
	singleControlNoProxy := isLikelySingleControlNoProxy(controlConn, hasListener, outTotal, outInternal, internalTargets, localTransportForwarding, inboundBurst)
	if singleControlNoProxy {
		reverseProxyNow = false
		addSignal("single-control-no-proxy")
	}

	if reverseProxyNow {
		addSignal("reverse-proxy-active")
	}

	if forwardActiveNow || reverseProxyNow {
		hist.LastActive = now
	}

	if reverseProxyNow {
		hist.LastSuspicious = now
		hist.SuspicionKind = shared.SuspicionProxy
		if hist.StickyScore < shared.ReverseStickyScore {
			hist.StickyScore = shared.ReverseStickyScore
		}
	} else if forwardActiveNow {
		if hist.StickyScore < shared.ForwardStickyScore {
			hist.StickyScore = shared.ForwardStickyScore
		}
	}

	suspiciousRecent := !hist.LastSuspicious.IsZero() && now.Sub(hist.LastSuspicious) <= shared.SuspicionWindow

	activeProxying := forwardActiveNow || reverseProxyNow || localTransportForwarding

	burstRecent := burstCount > 0
	if !burstRecent {
		if t, ok := shared.ShortLivedBurstLast[p.Pid]; ok && now.Sub(t) <= shared.SlowScanWindow {
			burstRecent = true
			burstCount = shared.ShortLivedBurstCount[p.Pid]
		}
	}
	beaconConfirmed, beaconInterval, beaconJitter, beaconHits := beaconPatternConfirmed(p.Pid, now)

	localTransportRecent := localTransportForwarding
	if !localTransportRecent {
		if t, ok := shared.LocalTransportLast[p.Pid]; ok && now.Sub(t) <= shared.LocalTransportWindow {
			localTransportRecent = true
		}
	}

	internalScanRecent := internalScanNow
	if !internalScanRecent {
		if t, ok := shared.RecentInternalScanSeen[p.Pid]; ok && now.Sub(t) <= shared.SlowScanWindow {
			internalScanRecent = true
		}
	}

	strongEvidence := reverseProxyNow ||
		localTransportRecent ||
		internalScanRecent ||
		internalLateral ||
		inboundBurst > 0
	if strongEvidence {
		addSignal("strong-evidence")
	}

	outboundForVerification := outboundConnsForVerification(c.Conns, ports)
	trafficVerified := trafficVerifiedByDest(outboundForVerification, outExternal, internalLateral)
	if trafficVerified {
		addSignal("traffic-verified")
	}

	suspTunEligible := controlConn != nil && (localTransportRecent || internalScanRecent || inboundBurst > 0 || forwardTunnelLikely)
	if suspTunEligible {
		addSignal("susp-tun-eligible")
	}
	beaconRecent := false
	if t, ok := shared.BeaconSeen[p.Pid]; ok && now.Sub(t) <= shared.SuspicionWindow {
		beaconRecent = true
		addSignal("beacon-recent")
	}
	beaconCadenceEvidence := burstRecent || beaconRecent || beaconConfirmed
	beaconLongLivedOK := outLongLived == 0 || beaconConfirmed || beaconRecent
	beaconEligible := !reverseProxyNow &&
		!localTransportRecent &&
		!internalScanRecent &&
		beaconLongLivedOK &&
		beaconCadenceEvidence &&
		!shared.IsLikelyBenignBeacon(p)
	if beaconEligible {
		addSignal("beacon-eligible")
	}
	if beaconConfirmed {
		addSignal("beacon-confirmed")
	}
	benignOnlyExternal := outboundUsesOnlyBenignControlPorts(outboundForVerification)
	beaconBlockedByVerified := beaconEligible && outExternal > 0 && trafficVerified && !strongEvidence
	beaconBlockedByBenignExternal := beaconEligible && benignClient && outExternal > 0 && benignOnlyExternal && !strongEvidence
	beaconBlockedByStaleBenign := beaconEligible && benignClient && !outboundRecent && outTotal == 0
	beaconBlockedByStaleUnconfirmed := beaconEligible && !beaconConfirmed && !outboundRecent && outTotal == 0
	if beaconBlockedByVerified {
		addSignal("beacon-blocked-verified")
	}
	if beaconBlockedByBenignExternal {
		addSignal("beacon-blocked-benign-external")
	}
	if beaconBlockedByStaleBenign {
		addSignal("beacon-blocked-stale-benign")
	}
	if beaconBlockedByStaleUnconfirmed {
		addSignal("beacon-blocked-stale-unconfirmed")
	}
	beaconBlocked := beaconBlockedByVerified ||
		beaconBlockedByBenignExternal ||
		beaconBlockedByStaleBenign ||
		beaconBlockedByStaleUnconfirmed

	// ---------------- Reverse control detection ----------------
	reverseControl := false
	reverseControlSuppressed := false
	reverseControlShape := !hasListener && outTotal == 1 && len(distinctTargets) == 1 && controlConn != nil
	if reverseControlShape {
		addSignal("reverse-control-shape")
		reverseControlSuppressed = suppressReverseControlForBenignChannel(controlConn, p, internalLateral, outInternal)
		if reverseControlSuppressed {
			addSignal("reverse-control-suppressed-benign")
			reverseControl = false
		} else {
			reverseControl = true
			addSignal("reverse-control")
		}
		if reverseControl && !shouldPromoteReverseControl(controlConn, outInternal, strongEvidence) {
			reverseControl = false
			addSignal("reverse-control-weak-shape")
		}
		if reverseControl {
			if localTransportForwarding && outboundRecent {
				scoreVal = 60 + min((controlSecs/10)*5, 40)
				if localCount > 0 {
					scoreVal += 20
					if localCount > 3 {
						scoreVal += 20
					}
				}

				c.Score = scoreVal
				c.Role = "reverse-transport"
				c.ActiveProxying = true
				c.ControlChannel = controlConn
				c.ControlDurationSeconds = controlSecs
				c.Reasons = []string{
					"Persistent reverse control channel with local transport activity",
				}
				addSignal("reverse-transport")
				c.Signals = signals
				c.Confidence = confidenceFor(c.Role, c.Score, c.ActiveProxying)
				return
			}
		}
	}
	if singleControlNoProxy && benignClient {
		reverseControl = false
		reverseControlSuppressed = true
		addSignal("reverse-control-suppressed-shape")
	}
	if reverseControl &&
		outLongLived == 0 &&
		(beaconConfirmed || (beaconRecent && burstRecent)) &&
		!hasListener &&
		!localTransportRecent &&
		!internalScanRecent &&
		!reverseProxyNow {
		reverseControl = false
		reverseControlSuppressed = true
		addSignal("reverse-control-suppressed-beacon-shape")
	}
	if reverseControl {
		addSignal("reverse-control")
	}

	// ---------------- Heuristics ----------------

	if hasListener {
		scoreVal += 5
		addSignal("listener")
		reasons = append(reasons, "Process has TCP listener(s)")
		if loopbackOnly {
			addSignal("listener-loopback")
			reasons = append(reasons, "Listener is loopback-only")
		}
		if anyWildcard {
			addSignal("listener-wildcard")
			reasons = append(reasons, "Listener bound to wildcard address")
		}
	}

	if outboundActive >= 2 {
		scoreVal += 15
	}
	if outboundActive >= 4 {
		scoreVal += 25
	}
	if outboundActive >= 8 {
		scoreVal += 40
	}
	if internalFanoutScore > 0 {
		scoreVal += internalFanoutScore
		addSignal("internal-fanout")
	}

	if outLongLived > 0 {
		scoreVal += 10
		reasons = append(reasons, "Long-lived outbound connection(s)")
	}

	if outTotal > 0 {
		scoreVal += 20
	}
	if outTotal >= 3 {
		scoreVal += 30
	}
	if outTotal >= 6 {
		scoreVal += 50
	}

	if len(distinctTargets) >= 2 {
		scoreVal += 20
	}
	if len(distinctTargets) >= 5 {
		scoreVal += 40
	}

	if len(distinctTargetPorts) >= 3 {
		scoreVal += 25
	}

	if activeClients > 0 {
		scoreVal += 25
	}
	if rareParent {
		scoreVal += 10
		addSignal("rare-parent")
	}

	if internalLateral {
		addSignal("internal-lateral")
		scoreVal += 25
	}

	if hasListener && activeClients == 0 && outTotal == 0 {
		scoreVal -= 10
	}

	if scoreVal < 0 {
		scoreVal = 0
	}

	c.Score = scoreVal
	c.Reasons = reasons
	c.ActiveProxying = activeProxying
	c.Role = deriveRole(hasListener, activeClients, outTotal, reverseTunnelEligible)

	if c.Role == "outbound-only" &&
		outInternal == 0 &&
		!hasListener &&
		!reverseProxyNow &&
		!reverseControl {
		if c.Score > shared.OutboundOnlyExternalCap {
			c.Score = shared.OutboundOnlyExternalCap
			c.Reasons = append(c.Reasons, "External-only outbound traffic de-emphasized")
		}
	}

	if reverseProxyNow || (suspiciousRecent && hist.SuspicionKind == shared.SuspicionProxy && !singleControlNoProxy) {
		c.Role = "reverse-proxy"
		if hist.StickyScore > c.Score {
			c.Score = hist.StickyScore
		}
		if reverseProxyNow {
			c.Reasons = append(c.Reasons, "Persistent control channel with proxied outbound activity")
		}
		addSignal("reverse-proxy")
	} else if reverseControl || (suspiciousRecent && hist.SuspicionKind == shared.SuspicionControl && controlConn != nil && !reverseControlSuppressed) {
		c.Role = "reverse-control"
		c.ActiveProxying = false
		c.Reasons = []string{
			"Persistent reverse control channel detected",
		}

		if reverseControl {
			base := controlStickyScore(controlSecs)
			if hist.StickyScore < base {
				hist.StickyScore = base
			}
			hist.LastSuspicious = now
			hist.SuspicionKind = shared.SuspicionControl
		}
		if hist.StickyScore > c.Score {
			c.Score = hist.StickyScore
		}
		addSignal("reverse-control")
	}

	promoteSuspTun := suspTunEligible && (reverseProxyNow || reverseControl)
	if promoteSuspTun && !outboundRecent && !activeProxying {
		promoteSuspTun = false
	}

	if promoteSuspTun {
		c.Role = "susp-tun"
		c.ActiveProxying = forwardActiveNow || reverseProxyNow || localTransportForwarding
		addSignal("susp-tun")

		base := 55
		if burstRecent && burstCount > 0 {
			base += min(burstCount*5, 20)
			c.Reasons = append(c.Reasons,
				fmt.Sprintf("Recent short-lived outbound activity (%d)", burstCount))
		}
		if localTransportRecent {
			base += 10
			c.Reasons = append(c.Reasons, "Recent loopback transport activity")
		}
		if internalScanRecent {
			base += 10
			c.Reasons = append(c.Reasons, "Recent internal scan activity")
		}

		if c.Score < base {
			c.Score = base
		}

		hist.LastSuspicious = now
		hist.SuspicionKind = shared.SuspicionControl
		if hist.StickyScore < c.Score {
			hist.StickyScore = c.Score
		}
	} else if reverseControl {
		c.Role = "susp-session"
		c.ActiveProxying = false
		addSignal("susp-session")
		c.Reasons = []string{
			"Persistent control session without proxying evidence",
		}
		base := controlStickyScore(controlSecs)
		if c.Score < base {
			c.Score = base
		}
		hist.LastSuspicious = now
		hist.SuspicionKind = shared.SuspicionControl
		if hist.StickyScore < c.Score {
			hist.StickyScore = c.Score
		}
	}
	if forwardTunnelLikely &&
		c.Role != "reverse-proxy" &&
		c.Role != "reverse-transport" &&
		c.Role != "reverse-control" &&
		c.Role != "susp-session" {
		c.Role = "susp-tun"
		c.ActiveProxying = activeClients > 0 || localTransportRecent
		addSignal("forward-tunnel")
		c.Reasons = append(c.Reasons, "Loopback forward-listener with persistent control channel")
		if c.Score < 65 {
			c.Score = 65
		}
	}

	if c.DelegatedStrong &&
		c.Role == "outbound-only" &&
		controlConn != nil &&
		!hasListener &&
		!localTransportRecent &&
		!internalScanRecent {
		c.Role = "susp-session"
		c.ActiveProxying = false
		addSignal("susp-session")
		c.Reasons = append(c.Reasons, "Delegated control-channel shape is consistent with a reverse session")
		if c.Score < 45 {
			c.Score = 45
		}
	}

	if canPromoteBeaconRole(
		c.Role,
		reverseControl,
		controlConn,
		beaconConfirmed,
		beaconRecent,
		hasListener,
		localTransportRecent,
		internalScanRecent,
		outLongLived,
	) {
		if beaconBlocked {
			addSignal("beacon-promotion-blocked")
		}
		if !beaconBlocked && beaconEligible && (beaconConfirmed || beaconRecent) {
			c.Role = "susp-beacon"
			c.ActiveProxying = false
			addSignal("susp-beacon")
			if beaconConfirmed {
				shared.BeaconSeen[p.Pid] = now
				if beaconInterval > 0 {
					interval := beaconInterval.Round(time.Second)
					if beaconJitter > 0 {
						c.Reasons = []string{
							fmt.Sprintf("Recurring outbound callback pattern (~%s cadence, jitter CoV %.2f)", interval, beaconJitter),
						}
					} else {
						c.Reasons = []string{
							fmt.Sprintf("Recurring outbound callback pattern (~%s cadence)", interval),
						}
					}
				} else {
					c.Reasons = []string{
						"Recurring short-lived outbound callback activity",
					}
				}
			} else if len(c.Reasons) == 0 {
				c.Reasons = []string{
					"Recent recurring outbound callback activity",
				}
			}

			base := 60 + min(burstCount*4, 20) + min(beaconHits*5, 15)
			if c.Score < base {
				c.Score = base
			}

			hist.LastSuspicious = now
			hist.SuspicionKind = shared.SuspicionControl
			if hist.StickyScore < c.Score {
				hist.StickyScore = c.Score
			}
		}
	}

	c.TrafficVerified = trafficVerified
	c.StrongEvidence = strongEvidence
	if delegatedReason != "" {
		c.Reasons = append(c.Reasons, delegatedReason)
	}
	if trafficVerified && !strongEvidence {
		c.Reasons = append(c.Reasons, "Traffic matches verified destinations (de-emphasized)")
	}
	applyASNRankAssist(c, p, addSignal)

	c.Signals = signals
	c.Confidence = confidenceFor(c.Role, c.Score, c.ActiveProxying)

	purgeHistory(now)
}

/* ---------------- helpers ---------------- */

func deriveRole(hasListener bool, clients int, out int, reverseTunnelEligible bool) string {
	switch {
	case hasListener && clients > 0 && out > 0:
		return "proxy-listener"
	case hasListener && clients > 0:
		return "listener-with-clients"
	case hasListener && out > 0:
		return "listener-with-outbound"
	case hasListener:
		return "listener-only"
	case out >= 3 && reverseTunnelEligible:
		return "reverse-tunnel"
	case out > 0:
		return "outbound-only"
	default:
		return "outbound-only"
	}
}

func socksListenerPorts(listeners []shared.ListenerInfo) (map[int]struct{}, bool, bool) {
	ports := make(map[int]struct{})
	loopbackOnly := true
	anyWildcard := false

	for _, l := range listeners {
		ports[l.LocalPort] = struct{}{}
		if shared.IsWildcardIP(l.LocalAddress) {
			anyWildcard = true
			loopbackOnly = false
		} else if !shared.IsLoopbackIP(l.LocalAddress) {
			loopbackOnly = false
		}
	}
	return ports, loopbackOnly, anyWildcard
}

func countActiveClientSessions(
	conns []shared.ConnectionInfo,
	ports map[int]struct{},
) (int, map[string]int) {

	ips := make(map[string]int)
	count := 0

	for _, c := range conns {
		if !isActiveConnState(c.State) {
			continue
		}
		if _, ok := ports[c.LocalPort]; !ok {
			continue
		}
		if c.RemoteAddress == "" || shared.IsWildcardIP(c.RemoteAddress) {
			continue
		}
		count++
		ips[c.RemoteAddress]++
	}
	return count, ips
}

func outboundTargets(
	conns []shared.ConnectionInfo,
	ports map[int]struct{},
) (total, external, internal, loopback int) {

	for _, c := range conns {
		if !isActiveConnState(c.State) {
			continue
		}
		if c.RemoteAddress == "" ||
			shared.IsWildcardIP(c.RemoteAddress) {
			continue
		}
		if shared.IsLoopbackIP(c.RemoteAddress) {
			loopback++
			continue
		}
		if _, ok := ports[c.LocalPort]; ok {
			continue
		}

		total++
		if shared.IsInternalIP(c.RemoteAddress) {
			internal++
		} else {
			external++
		}
	}
	return
}

func outboundActivity(
	conns []shared.ConnectionInfo,
	ports map[int]struct{},
) (total int, distinctTargets map[string]struct{}, distinctPorts map[int]struct{}, targetPrefixes map[string]struct{}) {
	distinctTargets = make(map[string]struct{})
	distinctPorts = make(map[int]struct{})
	targetPrefixes = make(map[string]struct{})

	for _, c := range conns {
		if !isActiveConnState(c.State) {
			continue
		}
		if c.RemoteAddress == "" ||
			shared.IsWildcardIP(c.RemoteAddress) ||
			shared.IsLoopbackIP(c.RemoteAddress) {
			continue
		}
		if _, ok := ports[c.LocalPort]; ok {
			continue
		}

		total++
		key := fmt.Sprintf("%s:%d", c.RemoteAddress, c.RemotePort)
		distinctTargets[key] = struct{}{}
		if c.RemotePort > 0 {
			distinctPorts[c.RemotePort] = struct{}{}
		}
		if prefix := shared.TargetPrefix(c.RemoteAddress); prefix != "" {
			targetPrefixes[prefix] = struct{}{}
		}
	}
	return
}

func outboundConnAgeStats(
	conns []shared.ConnectionInfo,
	ports map[int]struct{},
	now time.Time,
) (longLived int, shortLived int) {
	for _, c := range conns {
		if !isEstablishedState(c.State) {
			continue
		}
		if c.RemoteAddress == "" ||
			shared.IsWildcardIP(c.RemoteAddress) ||
			shared.IsLoopbackIP(c.RemoteAddress) {
			continue
		}
		if _, ok := ports[c.LocalPort]; ok {
			continue
		}

		key := connKeyFromConn(c.Pid, c)
		first, ok := shared.ConnFirstSeen[key]
		if !ok {
			continue
		}
		age := now.Sub(first)
		if age >= shared.LongLivedOutboundMinAge {
			longLived++
		}
		if age <= shared.ShortLivedOutboundMaxAge {
			shortLived++
		}
	}
	return
}

func outboundConnsForVerification(
	conns []shared.ConnectionInfo,
	ports map[int]struct{},
) []shared.ConnectionInfo {
	out := make([]shared.ConnectionInfo, 0, len(conns))
	for _, c := range conns {
		if !isActiveConnState(c.State) {
			continue
		}
		if c.RemoteAddress == "" ||
			shared.IsWildcardIP(c.RemoteAddress) ||
			shared.IsLoopbackIP(c.RemoteAddress) {
			continue
		}
		if _, ok := ports[c.LocalPort]; ok {
			continue
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func outboundUsesOnlyBenignControlPorts(conns []shared.ConnectionInfo) bool {
	if len(conns) == 0 {
		return false
	}
	hasExternal := false
	for _, c := range conns {
		if shared.IsInternalIP(c.RemoteAddress) || shared.IsLoopbackIP(c.RemoteAddress) {
			continue
		}
		hasExternal = true
		if !shared.BenignControlPorts[c.RemotePort] {
			return false
		}
	}
	return hasExternal
}

func trafficVerifiedByDest(
	conns []shared.ConnectionInfo,
	outExternal int,
	internalLateral bool,
) bool {
	if len(conns) == 0 {
		return false
	}
	if outExternal == 0 && !internalLateral {
		return true
	}

	benignExternal := true
	externalPrefixes := make(map[string]struct{})
	for _, c := range conns {
		if shared.IsInternalIP(c.RemoteAddress) || shared.IsLoopbackIP(c.RemoteAddress) {
			continue
		}
		if !shared.BenignControlPorts[c.RemotePort] {
			benignExternal = false
		}
		if prefix := shared.TargetPrefix(c.RemoteAddress); prefix != "" {
			externalPrefixes[prefix] = struct{}{}
		}
	}
	if !benignExternal {
		return false
	}
	return len(externalPrefixes) >= shared.VerifiedExternalMinPrefixes
}

func updateInboundBurst(pid int, activeClients int, now time.Time) int {
	if activeClients <= 0 {
		last := shared.InboundBurstLast[pid]
		if last.IsZero() || now.Sub(last) > shared.ShortLivedBurstWindow {
			shared.InboundBurstCount[pid] = 0
			return 0
		}
		return shared.InboundBurstCount[pid]
	}

	last := shared.InboundBurstLast[pid]
	if last.IsZero() || now.Sub(last) > shared.ShortLivedBurstWindow {
		shared.InboundBurstCount[pid] = activeClients
	} else {
		shared.InboundBurstCount[pid] += activeClients
	}
	shared.InboundBurstLast[pid] = now
	return shared.InboundBurstCount[pid]
}

func outboundInternalSummary(
	conns []shared.ConnectionInfo,
	ports map[int]struct{},
) (internalTargets map[string]struct{}, internalPorts map[int]struct{}, internalLateral bool) {
	internalTargets = make(map[string]struct{})
	internalPorts = make(map[int]struct{})

	for _, c := range conns {
		if !isActiveConnState(c.State) {
			continue
		}
		if c.RemoteAddress == "" ||
			shared.IsWildcardIP(c.RemoteAddress) ||
			shared.IsLoopbackIP(c.RemoteAddress) {
			continue
		}
		if _, ok := ports[c.LocalPort]; ok {
			continue
		}
		if !shared.IsInternalIP(c.RemoteAddress) {
			continue
		}

		internalTargets[c.RemoteAddress] = struct{}{}
		if c.RemotePort > 0 {
			internalPorts[c.RemotePort] = struct{}{}
			if shared.LateralPorts[c.RemotePort] {
				internalLateral = true
			}
		}
	}
	return
}

func outboundTargetsExcluding(
	conns []shared.ConnectionInfo,
	ports map[int]struct{},
	exclude *shared.ConnKey,
) (total, external, internal int) {

	for _, c := range conns {
		if !isActiveConnState(c.State) {
			continue
		}
		if exclude != nil && *exclude == connKeyFromConn(c.Pid, c) {
			continue
		}
		if c.RemoteAddress == "" ||
			shared.IsWildcardIP(c.RemoteAddress) ||
			shared.IsLoopbackIP(c.RemoteAddress) {
			continue
		}
		if _, ok := ports[c.LocalPort]; ok {
			continue
		}

		total++
		if shared.IsInternalIP(c.RemoteAddress) {
			internal++
		} else {
			external++
		}
	}
	return
}

func hasInternalLateral(conns []shared.ConnectionInfo) bool {
	for _, c := range conns {
		if !isActiveConnState(c.State) ||
			!shared.IsInternalIP(c.RemoteAddress) {
			continue
		}
		if shared.LateralPorts[c.RemotePort] {
			return true
		}
	}
	return false
}

func localTransportActivity(conns []shared.ConnectionInfo) (bool, int) {
	count := 0
	for _, c := range conns {
		if !isActiveConnState(c.State) {
			continue
		}
		if shared.IsLoopbackIP(c.LocalAddress) &&
			shared.IsLoopbackIP(c.RemoteAddress) &&
			c.LocalPort != c.RemotePort {
			count++
		}
	}
	return count > 0, count
}

func connKeyFromConn(pid int, cn shared.ConnectionInfo) shared.ConnKey {
	return shared.ConnKey{
		Pid:        pid,
		LocalAddr:  cn.LocalAddress,
		LocalPort:  cn.LocalPort,
		RemoteAddr: cn.RemoteAddress,
		RemotePort: cn.RemotePort,
	}
}

func updateConnHistory(pid int, conns []shared.ConnectionInfo, now time.Time) {
	current := make(map[shared.ConnKey]struct{})
	for _, cn := range conns {
		if !isEstablishedState(cn.State) {
			continue
		}
		key := connKeyFromConn(pid, cn)
		current[key] = struct{}{}
		if _, ok := shared.ConnFirstSeen[key]; !ok {
			shared.ConnFirstSeen[key] = now
		}
	}

	for k := range shared.ConnFirstSeen {
		if k.Pid == pid {
			if _, ok := current[k]; !ok {
				delete(shared.ConnFirstSeen, k)
			}
		}
	}
}

func findPersistentControl(pid int, conns []shared.ConnectionInfo, now time.Time) (*shared.ConnectionInfo, int) {
	var best *shared.ConnectionInfo
	var bestAge time.Duration

	for _, cn := range conns {
		if !isEstablishedState(cn.State) {
			continue
		}
		if cn.RemoteAddress == "" ||
			shared.IsWildcardIP(cn.RemoteAddress) ||
			shared.IsLoopbackIP(cn.RemoteAddress) {
			continue
		}

		key := connKeyFromConn(pid, cn)
		first, ok := shared.ConnFirstSeen[key]
		if !ok {
			continue
		}
		age := now.Sub(first)
		if age >= shared.ReverseControlMinDuration && age > bestAge {
			tmp := cn
			best = &tmp
			bestAge = age
		}
	}

	if best == nil {
		return nil, 0
	}
	return best, int(bestAge.Seconds())
}

func getHistory(pid int, now time.Time) *shared.ProcHistory {
	h := shared.ProcHistoryByPID[pid]
	if h == nil {
		h = &shared.ProcHistory{}
		shared.ProcHistoryByPID[pid] = h
	}
	h.LastSeen = now

	// Track shape drift (ratios of in/out/loopback) to flag sudden behavioral changes.
	// Ratios are updated by callers after computing candidate scores.
	return h
}

func purgeHistory(now time.Time) {
	if !shared.LastHistoryCleanup.IsZero() && now.Sub(shared.LastHistoryCleanup) < shared.CleanupInterval {
		return
	}
	shared.LastHistoryCleanup = now

	for pid, h := range shared.ProcHistoryByPID {
		if now.Sub(h.LastSeen) <= shared.HistoryTTL {
			continue
		}

		delete(shared.ProcHistoryByPID, pid)
		delete(shared.RecentClientSeen, pid)
		delete(shared.RecentOutboundSeen, pid)
		delete(shared.RecentInternalScanSeen, pid)
		delete(shared.ShortLivedBurstLast, pid)
		delete(shared.ShortLivedBurstCount, pid)
		delete(shared.ShortLivedBurstInterval, pid)
		delete(shared.ShortLivedBurstHits, pid)
		delete(shared.BeaconSeen, pid)
		delete(shared.LocalTransportLast, pid)

		for k := range shared.ConnFirstSeen {
			if k.Pid == pid {
				delete(shared.ConnFirstSeen, k)
			}
		}
	}
}

func controlStickyScore(controlSecs int) int {
	switch {
	case controlSecs >= 300:
		return 85
	case controlSecs >= 120:
		return 70
	case controlSecs >= 60:
		return 60
	default:
		return shared.ReverseControlBaseScore
	}
}

func confidenceFor(role string, score int, active bool) int {
	base := 10
	switch role {
	case "reverse-transport":
		base = 85
	case "reverse-proxy":
		base = 80
	case "susp-tun":
		base = 70
	case "susp-session":
		base = 72
	case "susp-beacon":
		base = 68
	case "reverse-control":
		base = 75
	case "proxy-listener":
		base = 60
	case "reverse-tunnel":
		base = 55
	case "listener-with-clients":
		base = 50
	case "listener-with-outbound":
		base = 45
	case "listener-only":
		base = 35
	case "outbound-only":
		base = 30
	}

	if active {
		base += 5
	}

	conf := base + (score / 4)
	if conf > 100 {
		return 100
	}
	if conf < 0 {
		return 0
	}
	return conf
}

func isEstablishedState(state string) bool {
	return state == "ESTABLISHED"
}

func isActiveConnState(state string) bool {
	switch state {
	case "ESTABLISHED",
		"SYN_SENT",
		"SYN_RECEIVED",
		"FIN_WAIT_1",
		"FIN_WAIT_2",
		"CLOSE_WAIT",
		"CLOSING",
		"LAST_ACK",
		"TIME_WAIT":
		return true
	default:
		return false
	}
}

func isLikelyBenignControlPort(port int) bool {
	return shared.BenignControlPorts[port]
}

func suppressReverseControlForBenignChannel(cn *shared.ConnectionInfo, proc *shared.ProcessInfo, internalLateral bool, outInternal int) bool {
	if cn == nil || internalLateral {
		return false
	}
	if !shared.IsLikelyBenignControlClient(proc) {
		return false
	}

	// Suppress common benign control channels for system/client binaries when traffic is purely external.
	if !isLikelyBenignControlPort(cn.RemotePort) {
		return false
	}
	if shared.IsInternalIP(cn.RemoteAddress) || outInternal > 0 {
		return false
	}
	return true
}

func shouldPromoteReverseControl(cn *shared.ConnectionInfo, outInternal int, strongEvidence bool) bool {
	if cn == nil {
		return false
	}
	if outInternal > 0 || shared.IsInternalIP(cn.RemoteAddress) {
		return true
	}
	if !isLikelyBenignControlPort(cn.RemotePort) {
		return true
	}
	// External control-looking channels on common ports need extra evidence.
	return strongEvidence
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func applyASNRankAssist(c *shared.Candidate, p *shared.ProcessInfo, addSignal func(string)) {
	if c == nil || p == nil || addSignal == nil {
		return
	}
	if c.ControlChannel == nil || c.OutExternal == 0 {
		return
	}

	orgs, pending, _ := shared.ResolveExternalASNOrgs(c.Conns)
	if len(orgs) == 0 {
		if pending > 0 {
			addSignal("asn-org-pending")
		}
		return
	}

	aligned := shared.ASNOrgAlignedWithProcess(p, orgs)
	companyKnown := strings.TrimSpace(p.Company) != ""
	if aligned {
		addSignal("asn-org-aligned")
		c.Reasons = append(c.Reasons, "ASN organization aligns with process publisher/path context")
		if c.StrongEvidence {
			return
		}
		penalty := 6
		if companyKnown {
			penalty = 10
		}
		c.Score = max(0, c.Score-penalty)
		return
	}

	if !companyKnown || c.StrongEvidence {
		return
	}

	family := shared.RoleFamily(c.Role)
	switch family {
	case "session", "beacon", "tunnel":
		c.Score += 8
		addSignal("asn-org-mismatch")
		c.Reasons = append(c.Reasons, "ASN organization does not align with process publisher context")
	case "outbound":
		c.Score += 4
		addSignal("asn-org-mismatch")
		c.Reasons = append(c.Reasons, "ASN organization does not align with process publisher context")
	}
}

func shapeDelta(cur, prev float64) float64 {
	if prev == 0 && cur == 0 {
		return 0
	}
	diff := cur - prev
	if diff < 0 {
		diff = -diff
	}
	return diff
}

func intervalCoV(intervals []time.Duration) float64 {
	if len(intervals) < 2 {
		return 0
	}
	var sum float64
	for _, iv := range intervals {
		sum += float64(iv)
	}
	mean := sum / float64(len(intervals))
	if mean == 0 {
		return 0
	}
	var variance float64
	for _, iv := range intervals {
		d := float64(iv) - mean
		variance += d * d
	}
	variance /= float64(len(intervals))
	stddev := math.Sqrt(variance)
	return stddev / mean
}

func beaconPatternConfirmed(pid int, now time.Time) (confirmed bool, interval time.Duration, jitter float64, hits int) {
	last, ok := shared.ShortLivedBurstLast[pid]
	if !ok || now.Sub(last) > shared.SlowScanWindow {
		return false, 0, 0, 0
	}

	interval = shared.ShortLivedBurstInterval[pid]
	hits = shared.ShortLivedBurstHits[pid]
	intervals := shared.ShortLivedIntervals[pid]
	jitter = intervalCoV(intervals)

	// For highly jittered callbacks we only require broad cadence recurrence.
	if hits < shared.BeaconMinIntervals || interval < shared.BeaconSleepThreshold {
		return false, interval, jitter, hits
	}
	if len(intervals) >= 2 && jitter > shared.BeaconJitterCoVMax {
		return false, interval, jitter, hits
	}
	return true, interval, jitter, hits
}

func canPromoteBeaconRole(
	role string,
	reverseControl bool,
	controlConn *shared.ConnectionInfo,
	beaconConfirmed bool,
	beaconRecent bool,
	hasListener bool,
	localTransportRecent bool,
	internalScanRecent bool,
	outLongLived int,
) bool {
	switch role {
	case "susp-tun", "reverse-proxy", "reverse-transport":
		return false
	case "reverse-control", "susp-session":
		// Active long-lived control channels should stay session/tunnel roles.
		if reverseControl || controlConn != nil || outLongLived > 0 {
			return false
		}
		// Allow strong beacon evidence to override session labels when there is no tunnel shape.
		if (beaconConfirmed || beaconRecent) &&
			!hasListener &&
			!localTransportRecent &&
			!internalScanRecent {
			return true
		}
		// Otherwise beacon can only take over stale session labels with no current control channel.
		return !reverseControl && controlConn == nil
	default:
		return true
	}
}

func internalFanoutBoost(targets map[string]struct{}, ports map[int]struct{}) int {
	score := 0
	if len(targets) >= 3 {
		score += 15
	}
	if len(ports) >= 2 {
		score += 10
	}
	for p := range ports {
		if shared.LateralPorts[p] {
			score += 10
			break
		}
	}
	return score
}

func isLikelySingleControlNoProxy(
	controlConn *shared.ConnectionInfo,
	hasListener bool,
	outTotal int,
	outInternal int,
	internalTargets map[string]struct{},
	localTransportForwarding bool,
	inboundBurst int,
) bool {
	if controlConn == nil {
		return false
	}
	if hasListener || outTotal != 1 || outInternal != 1 {
		return false
	}
	if len(internalTargets) > 1 || localTransportForwarding {
		return false
	}
	return inboundBurst == 0
}

func isLikelyLocalServiceProxy(
	controlConn *shared.ConnectionInfo,
	listenerPorts map[int]struct{},
	conns []shared.ConnectionInfo,
) bool {
	if controlConn == nil || !shared.IsInternalIP(controlConn.RemoteAddress) {
		return false
	}
	if _, ok := listenerPorts[controlConn.RemotePort]; !ok {
		return false
	}

	for _, cn := range conns {
		if !isEstablishedState(cn.State) {
			continue
		}
		if !shared.IsLoopbackIP(cn.LocalAddress) || !shared.IsLoopbackIP(cn.RemoteAddress) {
			continue
		}
		if cn.LocalPort == cn.RemotePort {
			continue
		}
		if _, ok := listenerPorts[cn.LocalPort]; ok {
			return true
		}
		if _, ok := listenerPorts[cn.RemotePort]; ok {
			return true
		}
	}
	return false
}

func isLikelyForwardTunnel(
	hasListener bool,
	loopbackOnly bool,
	controlConn *shared.ConnectionInfo,
	listenerPorts map[int]struct{},
	outTotal int,
	distinctTargets int,
	activeClients int,
	inboundRecent bool,
) bool {
	if !hasListener ||
		controlConn == nil ||
		outTotal != 1 ||
		distinctTargets != 1 {
		return false
	}
	nonControlListener := 0
	for port := range listenerPorts {
		if port != controlConn.LocalPort {
			nonControlListener++
		}
	}
	if nonControlListener == 0 {
		return false
	}
	// Strong shape: loopback listener plus persistent control channel.
	if loopbackOnly {
		return true
	}

	// Internal control channels with listener shape are commonly operator tunnels.
	if shared.IsInternalIP(controlConn.RemoteAddress) {
		return true
	}

	// Non-loopback listeners must have real client activity to be considered tunnels.
	return activeClients > 0 || inboundRecent
}

func updateParentFreq(p *shared.ProcessInfo) {
	if p == nil {
		return
	}
	key := fmt.Sprintf("%d|%s|%s", p.ParentPid, p.Name, p.ExePath)
	shared.ParentChildFreq[key]++
}

func updateBurstHistory(pid int, burstCount int, now time.Time) {
	if burstCount <= 0 {
		return
	}

	shared.ShortLivedBurstCount[pid] = burstCount
	prevTime, hasPrev := shared.ShortLivedBurstLast[pid]
	shared.ShortLivedBurstLast[pid] = now

	if hasPrev {
		interval := now.Sub(prevTime)
		if interval < shared.ShortLivedBurstWindow {
			return
		}
		shared.ShortLivedBurstInterval[pid] = interval
		intervals := shared.ShortLivedIntervals[pid]
		intervals = append(intervals, interval)
		if len(intervals) > 6 {
			intervals = intervals[len(intervals)-6:]
		}
		shared.ShortLivedIntervals[pid] = intervals
		if interval >= shared.BeaconSleepThreshold {
			shared.ShortLivedBurstHits[pid]++
		} else if shared.ShortLivedBurstHits[pid] > 0 {
			shared.ShortLivedBurstHits[pid]--
		}
	} else {
		shared.ShortLivedBurstHits[pid] = 0
	}
}
