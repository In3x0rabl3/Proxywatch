package classifier

import (
	"fmt"
	"hash/fnv"
	"math"
	"strconv"
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
	scopedPID := historyPIDForCandidate(c)
	behaviorKey := processBehaviorKey(c)
	behavior := getOrCreateProcessBehavior(behaviorKey, now)
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
	hist := getHistory(scopedPID, now)
	updateConnHistory(scopedPID, c.Conns, now)
	updateParentFreq(historyHostScope(c), p)
	parentKey := fmt.Sprintf("%s|%d|%s|%s", historyHostScope(c), p.ParentPid, p.Name, p.ExePath)
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
		shared.RecentClientSeen[scopedPID] = now
	}
	inboundBurst := updateInboundBurst(scopedPID, activeClients, now)
	if inboundBurst > 0 {
		addSignal("inbound-burst")
	}
	if outTotal > 0 {
		addSignal("outbound-active")
		shared.RecentOutboundSeen[scopedPID] = now
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
	if t, ok := shared.RecentClientSeen[scopedPID]; ok && now.Sub(t) <= shared.ActiveWindow {
		inboundRecent = true
	}

	outboundRecent := outTotal > 0
	if t, ok := shared.RecentOutboundSeen[scopedPID]; ok && now.Sub(t) <= shared.ActiveWindow {
		outboundRecent = true
	}

	forwardActiveNow := hasListener && inboundRecent && outboundRecent

	controlConn, controlSecs := findPersistentControl(scopedPID, c.Conns, now)
	if controlConn != nil {
		addSignal("control-channel")
		c.ControlChannel = controlConn
		c.ControlDurationSeconds = controlSecs
	}
	pendingControlConn, pendingControlSecs, pendingControlObs, pendingControlRepeated := pendingControlAttempt(scopedPID, c.Conns, ports, now)
	if controlConn == nil && pendingControlConn != nil {
		addSignal("control-attempt")
		if pendingControlRepeated {
			addSignal("control-attempt-repeated")
			if c.ControlChannel == nil {
				c.ControlChannel = pendingControlConn
				c.ControlDurationSeconds = pendingControlSecs
			}
			reasons = append(reasons, fmt.Sprintf("Repeated pending outbound control attempts (%d observations) to stable target", pendingControlObs))
		}
	}

	reverseProxyNow := false

	outboundActive, distinctTargets, distinctTargetPorts, targetPrefixes := outboundActivity(c.Conns, ports)
	internalTargets, internalPorts, internalLateral := outboundInternalSummary(c.Conns, ports)
	smbConns, smbTargets, smbLongLived, smbExternal, smbMaxAgeSecs := smbPipeActivity(c.Conns, ports, now)
	smbListener := hasSMBListenerPort(ports)
	smbPivotShape := smbListener && activeClients > 0 && outInternal > 0
	smbPipeLikely := smbConns > 0 && (smbLongLived > 0 || controlConn != nil || c.DelegatedStrong || internalLateral || outInternal > 0)
	if smbPivotShape {
		smbPipeLikely = true
		addSignal("smb-pivot-shape")
		reasons = append(reasons, "Simultaneous inbound SMB clients and outbound internal SMB flow")
	}
	if smbConns > 0 {
		addSignal("smb-445-activity")
		reasons = append(reasons, fmt.Sprintf("SMB channel activity over TCP/445 (%d connection(s), %d target(s))", smbConns, smbTargets))
	}
	if smbLongLived > 0 {
		addSignal("smb-445-long-lived")
	}
	if smbExternal {
		addSignal("smb-445-external")
	}
	if smbPipeLikely {
		addSignal("smb-pipe-likely")
	}
	internalFanoutScore := internalFanoutBoost(internalTargets, internalPorts)
	controlTargetStable := controlConn != nil &&
		!hasListener &&
		outTotal > 0 &&
		outTotal <= 6 &&
		len(distinctTargets) <= 2
	if controlTargetStable {
		addSignal("control-target-stable")
	}
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

	updateBurstHistory(scopedPID, burstCount, now)
	internalScanNow := reverseTunnelEligible
	if internalScanNow {
		shared.RecentInternalScanSeen[scopedPID] = now
	}

	localTransport, localCount, localDistinctPorts := localTransportActivity(c.Conns)
	loopbackProxyFanout := controlConn != nil &&
		!hasListener &&
		localTransport &&
		localCount >= 3 &&
		localDistinctPorts >= 3
	localTransportForwarding := localTransport && (hasListener || activeClients > 0 || loopbackProxyFanout)
	if localTransportForwarding {
		addSignal("loopback-transport")
		shared.LocalTransportLast[scopedPID] = now
	}
	if loopbackProxyFanout {
		addSignal("loopback-proxy-fanout")
		reasons = append(reasons, fmt.Sprintf("Control channel plus loopback fanout (%d flows, %d target ports)", localCount, localDistinctPorts))
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
		controlKey := connKeyFromConn(scopedPID, *controlConn)
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
		if t, ok := shared.ShortLivedBurstLast[scopedPID]; ok && now.Sub(t) <= shared.SlowScanWindow {
			burstRecent = true
			burstCount = shared.ShortLivedBurstCount[scopedPID]
		}
	}
	beaconConfirmed, beaconInterval, beaconJitter, beaconHits := beaconPatternConfirmed(scopedPID, now)

	localTransportRecent := localTransportForwarding
	if !localTransportRecent {
		if t, ok := shared.LocalTransportLast[scopedPID]; ok && now.Sub(t) <= shared.LocalTransportWindow {
			localTransportRecent = true
		}
	}

	internalScanRecent := internalScanNow
	if !internalScanRecent {
		if t, ok := shared.RecentInternalScanSeen[scopedPID]; ok && now.Sub(t) <= shared.SlowScanWindow {
			internalScanRecent = true
		}
	}

	strongEvidence := reverseProxyNow ||
		localTransportRecent ||
		internalScanRecent ||
		internalLateral ||
		inboundBurst > 0 ||
		(smbPipeLikely && (smbLongLived > 0 || smbTargets >= 2))
	if strongEvidence {
		addSignal("strong-evidence")
	}

	outboundForVerification := outboundConnsForVerification(c.Conns, ports)
	externalPrefixes := outboundExternalPrefixes(outboundForVerification)
	trafficVerified := trafficVerifiedByDest(outboundForVerification, outExternal, internalLateral, behavior, externalPrefixes)
	if trafficVerified {
		addSignal("traffic-verified")
	}
	benignControlPattern := likelyBenignControlPattern(controlConn, behavior, externalPrefixes, outExternal, outInternal, len(distinctTargets), controlSecs)
	if benignControlPattern {
		addSignal("benign-control-pattern")
	}

	suspTunEligible := controlConn != nil && (localTransportRecent || internalScanRecent || inboundBurst > 0 || forwardTunnelLikely)
	if suspTunEligible {
		addSignal("susp-tun-eligible")
	}
	beaconRecent := false
	if t, ok := shared.BeaconSeen[scopedPID]; ok && now.Sub(t) <= shared.SuspicionWindow {
		beaconRecent = true
	}
	suppressStaleBeaconMemory := benignClient &&
		trafficVerified &&
		!outboundRecent &&
		outTotal == 0 &&
		outExternal == 0 &&
		outInternal == 0 &&
		outLoopback == 0 &&
		activeClients == 0 &&
		inboundBurst == 0 &&
		controlConn == nil &&
		pendingControlConn == nil &&
		!localTransportRecent &&
		!internalScanRecent
	if suppressStaleBeaconMemory {
		if beaconRecent || beaconConfirmed {
			addSignal("beacon-memory-suppressed-idle-benign")
		}
		beaconRecent = false
		beaconConfirmed = false
	} else if beaconRecent {
		addSignal("beacon-recent")
	}
	beaconCadenceEvidence := burstRecent || beaconRecent || beaconConfirmed
	beaconLongLivedOK := outLongLived == 0 || beaconConfirmed || beaconRecent
	benignBeaconClient := shared.IsLikelyBenignBeacon(p)
	beaconEligible := !reverseProxyNow &&
		!localTransportRecent &&
		!internalScanRecent &&
		beaconLongLivedOK &&
		beaconCadenceEvidence
	if beaconEligible {
		addSignal("beacon-eligible")
	}
	if benignBeaconClient {
		addSignal("beacon-benign-process")
	}
	if beaconConfirmed {
		addSignal("beacon-confirmed")
	}
	beaconBlockedByVerified := beaconEligible && outExternal > 0 && trafficVerified && !strongEvidence
	beaconBlockedByBenignExternal := beaconEligible &&
		benignClient &&
		benignBeaconClient &&
		outExternal > 0 &&
		benignControlPattern &&
		!strongEvidence &&
		!beaconConfirmed &&
		!pendingControlRepeated
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
	reverseControlShape := isReverseControlShape(controlConn, hasListener, outTotal, len(distinctTargets), controlSecs)
	if reverseControlShape {
		addSignal("reverse-control-shape")
		reverseControlSuppressed = suppressReverseControlForBenignChannel(controlConn, p, internalLateral, outInternal, benignControlPattern)
		if reverseControlSuppressed {
			addSignal("reverse-control-suppressed-benign")
			reverseControl = false
		} else {
			reverseControl = true
			addSignal("reverse-control")
		}
		// Avoid false positives on trusted system/application clients that only
		// maintain a single external established channel without corroboration.
		if reverseControl &&
			benignClient &&
			!hasListener &&
			outTotal == 1 &&
			outExternal == 1 &&
			outInternal == 0 &&
			len(distinctTargets) <= 1 &&
			!pendingControlRepeated &&
			!c.DelegatedStrong &&
			!internalLateral &&
			inboundBurst == 0 &&
			!localTransportRecent &&
			!internalScanRecent &&
			!suspiciousRecent &&
			controlSecs < 300 {
			reverseControl = false
			reverseControlSuppressed = true
			addSignal("reverse-control-deferred-benign-single")
		}
		if reverseControl && !shouldPromoteReverseControl(
			controlConn,
			outInternal,
			strongEvidence,
			benignControlPattern,
			controlSecs,
			pendingControlRepeated,
			c.DelegatedStrong,
		) {
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
	// Guardrail: trusted external-only clients with a single long-lived channel
	// should not be auto-promoted to reverse-control/session without corroboration.
	if reverseControl &&
		benignClient &&
		!hasListener &&
		outExternal > 0 &&
		outInternal == 0 &&
		outTotal <= 2 &&
		len(distinctTargets) <= 2 &&
		!pendingControlRepeated &&
		!c.DelegatedStrong &&
		!internalLateral &&
		inboundBurst == 0 &&
		!localTransportRecent &&
		!internalScanRecent {
		reverseControl = false
		reverseControlSuppressed = true
		addSignal("reverse-control-suppressed-benign-external")
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
	if controlTargetStable {
		scoreVal += 18
		reasons = append(reasons, "Outbound control traffic remains pinned to a stable remote target")
		if controlSecs >= 120 {
			scoreVal += 8
		}
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
	if smbPipeLikely {
		scoreVal += 20
	}
	if smbTargets >= 2 {
		scoreVal += 10
		addSignal("smb-pipe-fanout")
	}
	if smbExternal {
		scoreVal += 10
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

	// Promote persistent control-channel shapes to session even when reverse-control
	// strict shape matching does not trigger (prevents collapsing into plain outbound).
	controlSessionConn := controlConn
	controlSessionSecs := controlSecs
	if controlSessionConn == nil && pendingControlRepeated {
		controlSessionConn = pendingControlConn
		controlSessionSecs = pendingControlSecs
	}
	if c.Role == "outbound-only" &&
		shouldPromoteControlSession(
			controlSessionConn,
			benignClient,
			benignControlPattern,
			reverseControlSuppressed,
			hasListener,
			reverseProxyNow,
			reverseControl,
			localTransportRecent,
			internalScanRecent,
			activeProxying,
			outTotal,
			outExternal,
			outInternal,
			len(distinctTargets),
			controlSessionSecs,
			pendingControlRepeated,
			c.DelegatedStrong,
			internalLateral,
			inboundBurst,
		) {
		c.Role = "susp-session"
		c.ActiveProxying = false
		addSignal("control-session")
		addSignal("susp-session")
		if reverseControlSuppressed {
			addSignal("control-session-override")
		}
		c.Reasons = append(c.Reasons, "Persistent reverse control channel detected")
		if reverseControlSuppressed {
			c.Reasons = append(c.Reasons, "Control-session promotion overrode benign-channel suppression due corroborating evidence")
		}
		base := controlSessionBaseScore(controlSessionSecs, outInternal, len(distinctTargets), c.DelegatedStrong, internalLateral)
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

	// Promote listener+egress control shapes to tunnel even when strict forward-tunnel
	// matching cannot be proven in a single refresh.
	if (c.Role == "listener-with-outbound" || c.Role == "listener-with-clients" || c.Role == "listener-only") &&
		hasListener &&
		outTotal > 0 &&
		(activeClients > 0 || outInternal > 0 || internalLateral || localTransportForwarding || c.DelegatedStrong) {
		c.Role = "susp-tun"
		c.ActiveProxying = activeClients > 0 || localTransportRecent || internalScanRecent
		addSignal("listener-egress-tunnel-shape")
		c.Reasons = append(c.Reasons, "Listener + outbound control shape indicates likely tunnel behavior")
		if c.Score < 58 {
			c.Score = 58
		}
		hist.LastSuspicious = now
		hist.SuspicionKind = shared.SuspicionProxy
		if hist.StickyScore < c.Score {
			hist.StickyScore = c.Score
		}
	}

	// Promote recurring reconnect-style control callbacks to session when no persistent
	// socket is visible long enough in a single sample.
	if c.Role == "outbound-only" &&
		!hasListener &&
		outTotal > 0 &&
		outTotal <= 3 &&
		outExternal > 0 &&
		outInternal == 0 &&
		len(distinctTargets) <= 2 &&
		!trafficVerified &&
		(burstRecent || shared.ShortLivedBurstHits[scopedPID] >= 1) {
		holdBenignReconnectingPromotion := benignClient &&
			controlConn != nil &&
			outLongLived > 0 &&
			!pendingControlRepeated &&
			!c.DelegatedStrong &&
			!internalLateral &&
			inboundBurst == 0 &&
			!localTransportRecent &&
			!internalScanRecent
		pureCallbackShape := controlConn == nil &&
			!pendingControlRepeated &&
			outLongLived == 0 &&
			inboundBurst == 0
		if pureCallbackShape {
			addSignal("reconnecting-callback-observed")
		} else if holdBenignReconnectingPromotion {
			addSignal("reconnecting-control-session-suppressed-benign-external")
		} else {
			c.Role = "susp-session"
			c.ActiveProxying = false
			addSignal("reconnecting-control-session")
			c.Reasons = append(c.Reasons, "Recurring reconnecting control callback pattern detected")
			if c.Score < 52 {
				c.Score = 52
			}
			hist.LastSuspicious = now
			hist.SuspicionKind = shared.SuspicionControl
			if hist.StickyScore < c.Score {
				hist.StickyScore = c.Score
			}
		}
	}

	sessionCue := sessionCueForBeaconPromotion(
		signals,
		pendingControlRepeated,
		c.DelegatedStrong,
		outInternal,
		internalLateral,
		inboundBurst,
	) ||
		reverseControl ||
		controlConn != nil ||
		pendingControlConn != nil ||
		outLongLived > 0 ||
		controlSecs >= 20 ||
		pendingControlObs >= 2

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
		sessionCue,
	) {
		provisionalBeacon := !beaconBlocked &&
			beaconEligible &&
			!hasListener &&
			!localTransportRecent &&
			!internalScanRecent &&
			outLongLived == 0 &&
			outExternal > 0 &&
			outInternal == 0 &&
			len(distinctTargets) <= 2 &&
			(burstRecent || shared.ShortLivedBurstHits[scopedPID] >= 1)
		if beaconBlocked {
			addSignal("beacon-promotion-blocked")
		}
		if !beaconBlocked && beaconEligible && (beaconConfirmed || beaconRecent || provisionalBeacon) {
			c.Role = "susp-beacon"
			c.ActiveProxying = false
			addSignal("susp-beacon")
			if provisionalBeacon && !beaconConfirmed && !beaconRecent {
				addSignal("beacon-provisional")
			}
			if beaconConfirmed {
				shared.BeaconSeen[scopedPID] = now
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
			} else if provisionalBeacon {
				c.Reasons = []string{
					"Recurring short-lived outbound callback activity (early beacon pattern)",
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
			hist.SuspicionKind = shared.SuspicionBeacon
			if hist.StickyScore < c.Score {
				hist.StickyScore = c.Score
			}
		}
	}

	// SMB pipe-like behavior should not remain plain outbound/listener.
	smbBaseRole := c.Role == "outbound-only" || shared.RoleFamily(c.Role) == "listener"
	if smbBaseRole && smbPipeLikely && !reverseProxyNow && !forwardTunnelLikely {
		promoteTunnel := smbTargets >= 2 || internalLateral || outInternal > 0 || activeClients > 0 || (hasListener && activeClients > 0)
		if promoteTunnel {
			c.Role = "smb-pipe"
			c.ActiveProxying = activeClients > 0 || localTransportRecent || internalScanRecent
			addSignal("smb-pipe-tunnel")
			c.Reasons = append(c.Reasons, "SMB pipe-like relay/lateral channel behavior detected")
			if c.Score < 62 {
				c.Score = 62
			}
		} else {
			c.Role = "smb-pipe"
			c.ActiveProxying = false
			addSignal("smb-pipe-session")
			c.Reasons = append(c.Reasons, "SMB pipe-like control channel detected")
			if c.Score < 52 {
				c.Score = 52
			}
		}
		hist.LastSuspicious = now
		hist.SuspicionKind = shared.SuspicionControl
		if hist.StickyScore < c.Score {
			hist.StickyScore = c.Score
		}
	}

	// Normalize all SMB pipe detections to explicit role label.
	if smbPipeLikely {
		c.Role = "smb-pipe"
		addSignal("smb-pipe-role")
	}

	// Keep recently suspicious labels from collapsing to plain outbound immediately
	// when callbacks go quiet between refreshes.
	if c.Role == "outbound-only" && suspiciousRecent && !benignControlPattern {
		holdBenignExternalMemory := benignClient &&
			outExternal > 0 &&
			outInternal == 0 &&
			outTotal <= 2 &&
			!pendingControlRepeated &&
			!c.DelegatedStrong &&
			!internalLateral &&
			inboundBurst == 0 &&
			!localTransportRecent &&
			!internalScanRecent &&
			!hasListener
		holdBeaconMemory := hist.SuspicionKind == shared.SuspicionBeacon && suppressStaleBeaconMemory
		if holdBeaconMemory {
			hist.LastSuspicious = time.Time{}
			hist.SuspicionKind = 0
			addSignal("suspicion-memory-beacon-suppressed-idle-benign")
		} else if holdBenignExternalMemory {
			addSignal("suspicion-memory-suppressed-benign-external")
		} else {
			switch hist.SuspicionKind {
			case shared.SuspicionProxy:
				c.Role = "susp-tun"
				if c.Score < 48 {
					c.Score = 48
				}
				addSignal("suspicion-memory-tunnel")
			case shared.SuspicionBeacon:
				c.Role = "susp-beacon"
				if c.Score < 46 {
					c.Score = 46
				}
				addSignal("suspicion-memory-beacon")
			case shared.SuspicionControl:
				c.Role = "susp-session"
				if c.Score < 46 {
					c.Score = 46
				}
				addSignal("suspicion-memory-session")
			}
		}
	}

	observedConnAgeSecs := maxEstablishedConnectionAgeSeconds(scopedPID, c.Conns, now)
	beaconAgeSecs := beaconObservationAgeSeconds(scopedPID, now)
	if applyRoleWarmupGates(
		c,
		hasListener,
		activeClients,
		outTotal,
		controlSecs,
		pendingControlSecs,
		observedConnAgeSecs,
		smbMaxAgeSecs,
		beaconAgeSecs,
		addSignal,
	) {
		strongEvidence = false
	}

	c.TrafficVerified = trafficVerified
	c.StrongEvidence = strongEvidence
	if !c.StrongEvidence && c.Role == "susp-session" && controlConn != nil {
		suppressStrongExternalSession := benignClient &&
			outExternal > 0 &&
			outInternal == 0 &&
			outTotal <= 2 &&
			!pendingControlRepeated &&
			!c.DelegatedStrong &&
			!internalLateral &&
			inboundBurst == 0 &&
			!localTransportRecent &&
			!internalScanRecent &&
			!hasListener
		if outInternal > 0 || internalLateral || c.DelegatedStrong || (controlSecs >= 180 && !suppressStrongExternalSession) {
			c.StrongEvidence = true
			addSignal("strong-control-session")
			c.Reasons = append(c.Reasons, "Sustained control-session evidence exceeded strong threshold")
		} else if suppressStrongExternalSession {
			addSignal("strong-control-session-suppressed-benign-external")
		}
	}
	if !c.ActiveProxying && !c.StrongEvidence {
		roleFamily := shared.RoleFamily(c.Role)
		threshold := 88
		switch roleFamily {
		case "session":
			threshold = 72
		case "beacon":
			threshold = 68
		case "tunnel":
			threshold = 74
		case "listener":
			threshold = 84
		case "outbound":
			threshold = 86
		}

		corroboration := 0
		if controlConn != nil {
			corroboration++
		}
		if outInternal > 0 {
			corroboration++
		}
		if outExternal > 0 {
			corroboration++
		}
		if activeClients > 0 || inboundBurst > 0 {
			corroboration++
		}
		if internalLateral || internalScanRecent || localTransportRecent {
			corroboration += 2
		}
		if beaconConfirmed || beaconRecent {
			corroboration++
		}
		if c.DelegatedStrong {
			corroboration++
		}
		if smbConns > 0 {
			corroboration++
		}
		if smbLongLived > 0 || smbTargets >= 2 {
			corroboration++
		}
		if smbExternal {
			corroboration++
		}

		// Dynamic role-aware state promotion:
		// any role can become strong when score and corroboration support it.
		if c.Score >= threshold && corroboration > 0 {
			c.StrongEvidence = true
			addSignal("strong-role-dynamic")
			c.Reasons = append(c.Reasons, fmt.Sprintf("Role-aware strong state promotion (%s, score=%d, corroboration=%d)", roleFamily, c.Score, corroboration))
		}
	}
	applyBehaviorAwareAdjustments(
		c,
		behavior,
		controlConn,
		len(distinctTargets),
		outExternal,
		outInternal,
		internalLateral,
		strongEvidence,
		benignControlPattern,
		benignClient,
		addSignal,
	)
	if delegatedReason != "" {
		c.Reasons = append(c.Reasons, delegatedReason)
	}
	if trafficVerified && !strongEvidence {
		c.Reasons = append(c.Reasons, "Traffic matches verified destinations (de-emphasized)")
	}
	applyASNRankAssist(c, p, addSignal)
	applySignalFusionAdjustments(
		c,
		signals,
		controlConn,
		pendingControlRepeated,
		benignClient,
		trafficVerified,
		benignControlPattern,
		addSignal,
	)
	updateProcessBehaviorProfile(
		behavior,
		c,
		outExternal,
		outInternal,
		len(distinctTargets),
		controlSecs,
		externalPrefixes,
		now,
	)
	hist.LastScoreEval = now

	c.Signals = signals
	c.Confidence = confidenceFor(c.Role, c.Score, c.ActiveProxying)

	purgeHistory(now)
}

/* ---------------- helpers ---------------- */

func historyHostScope(c *shared.Candidate) string {
	if c == nil {
		return "local"
	}
	host := strings.ToLower(strings.TrimSpace(c.Host))
	if host == "" {
		return "local"
	}
	return host
}

func historyPIDForCandidate(c *shared.Candidate) int {
	if c == nil || c.Proc == nil {
		return 0
	}
	return scopedRuntimePID(historyHostScope(c), c.Proc.Pid)
}

func scopedRuntimePID(host string, pid int) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(host))
	_, _ = h.Write([]byte("|"))
	_, _ = h.Write([]byte(strconv.Itoa(pid)))
	out := int(h.Sum32() & 0x7fffffff)
	if out == 0 {
		if pid < 0 {
			return -pid
		}
		if pid == 0 {
			return 1
		}
		return pid
	}
	return out
}

func processBehaviorKey(c *shared.Candidate) string {
	if c == nil || c.Proc == nil {
		return historyHostScope(c) + "|(unknown)"
	}
	p := c.Proc
	exe := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(p.ExePath, "\\", "/")))
	name := strings.ToLower(strings.TrimSpace(p.Name))
	user := strings.ToLower(strings.TrimSpace(p.UserName))
	if exe == "" {
		exe = "(unknown)"
	}
	if name == "" {
		name = "(unknown)"
	}
	return historyHostScope(c) + "|" + exe + "|" + name + "|" + user
}

func getOrCreateProcessBehavior(key string, now time.Time) *shared.ProcessBehavior {
	if shared.ProcessBehaviorByKey == nil {
		shared.ProcessBehaviorByKey = make(map[string]*shared.ProcessBehavior)
	}
	behavior := shared.ProcessBehaviorByKey[key]
	if behavior == nil {
		behavior = &shared.ProcessBehavior{
			KnownPrefixes: make(map[string]int),
			LastRoles:     make(map[string]int),
		}
		shared.ProcessBehaviorByKey[key] = behavior
	}
	if behavior.KnownPrefixes == nil {
		behavior.KnownPrefixes = make(map[string]int)
	}
	if behavior.LastRoles == nil {
		behavior.LastRoles = make(map[string]int)
	}
	if behavior.LastSeen.IsZero() {
		behavior.LastSeen = now
	}
	return behavior
}

func applyBehaviorAwareAdjustments(
	c *shared.Candidate,
	behavior *shared.ProcessBehavior,
	controlConn *shared.ConnectionInfo,
	distinctTargets int,
	outExternal int,
	outInternal int,
	internalLateral bool,
	strongEvidence bool,
	benignControlPattern bool,
	benignClient bool,
	addSignal func(string),
) {
	if c == nil || behavior == nil || behavior.Observations < 6 {
		return
	}
	obs := float64(max(1, behavior.Observations))
	suspiciousRatio := float64(behavior.SuspiciousObservations) / obs
	strongRatio := float64(behavior.StrongObservations) / obs
	stableBenign := behavior.Observations >= 10 && suspiciousRatio <= 0.25 && strongRatio <= 0.20

	drift := 0.0
	if behavior.AvgOutExternal > 0 {
		ratio := float64(outExternal) / behavior.AvgOutExternal
		if ratio > 3 {
			drift += (ratio - 3) * 0.5
		}
	}
	if behavior.AvgOutInternal > 0 {
		ratio := float64(outInternal) / behavior.AvgOutInternal
		if ratio > 3 {
			drift += (ratio - 3) * 0.6
		}
	}
	if behavior.AvgDistinctTargets > 0 {
		ratio := float64(distinctTargets) / behavior.AvgDistinctTargets
		if ratio > 3 {
			drift += (ratio - 3) * 0.4
		}
	}
	if drift >= 1.0 && !c.StrongEvidence {
		boost := min(14, int(drift*8))
		c.Score += boost
		addSignal("baseline-drift")
		c.Reasons = append(c.Reasons, "Process network behavior deviates from learned host baseline")
	}

	if stableBenign && !strongEvidence && !c.StrongEvidence && !c.ActiveProxying {
		c.TrafficVerified = true
		addSignal("baseline-verified")
		c.Reasons = append(c.Reasons, "Behavior matches learned host baseline for this process identity")
	}

	if stableBenign &&
		c.Role == "susp-session" &&
		controlConn != nil &&
		benignControlPattern &&
		!c.StrongEvidence &&
		!c.ActiveProxying &&
		outInternal == 0 &&
		!internalLateral &&
		distinctTargets <= 2 &&
		c.ControlDurationSeconds < 600 &&
		!c.DelegatedStrong {
		c.Role = "outbound-only"
		if c.Score > 30 {
			c.Score = 30
		}
		addSignal("baseline-suppress-session")
		c.Reasons = append(c.Reasons, "Control-session label suppressed by learned benign baseline")
	}

	// Guardrail against weak one-off session labels on common system clients.
	if benignClient &&
		c.Role == "susp-session" &&
		controlConn != nil &&
		!c.StrongEvidence &&
		!c.ActiveProxying &&
		!internalLateral &&
		outInternal == 0 &&
		distinctTargets <= 1 &&
		c.OutLongLived == 0 &&
		c.OutTotal <= 2 &&
		c.ControlDurationSeconds < 45 &&
		c.Score < 55 {
		c.Role = "outbound-only"
		if c.Score > 35 {
			c.Score = 35
		}
		addSignal("weak-session-downgraded")
		c.Reasons = append(c.Reasons, "Weak external-only session shape downgraded pending stronger corroboration")
	}
}

func updateProcessBehaviorProfile(
	behavior *shared.ProcessBehavior,
	c *shared.Candidate,
	outExternal int,
	outInternal int,
	distinctTargets int,
	controlSecs int,
	externalPrefixes map[string]struct{},
	now time.Time,
) {
	if behavior == nil || c == nil {
		return
	}
	behavior.Observations++
	behavior.LastSeen = now
	behavior.LastUpdated = now
	behavior.AvgOutExternal = ewma(behavior.AvgOutExternal, float64(outExternal), behavior.Observations)
	behavior.AvgOutInternal = ewma(behavior.AvgOutInternal, float64(outInternal), behavior.Observations)
	behavior.AvgDistinctTargets = ewma(behavior.AvgDistinctTargets, float64(distinctTargets), behavior.Observations)
	behavior.AvgControlSeconds = ewma(behavior.AvgControlSeconds, float64(controlSecs), behavior.Observations)

	roleFamily := shared.RoleFamily(c.Role)
	suspiciousRole := roleFamily == "session" || roleFamily == "beacon" || roleFamily == "tunnel"
	if suspiciousRole && (c.StrongEvidence || c.ActiveProxying || c.Score >= 70) {
		behavior.SuspiciousObservations++
	}
	if c.StrongEvidence {
		behavior.StrongObservations++
	}
	if c.ActiveProxying {
		behavior.ActiveObservations++
	}
	behavior.LastRoles[c.Role]++
	for prefix := range externalPrefixes {
		behavior.KnownPrefixes[prefix]++
	}
	pruneStringCount(behavior.KnownPrefixes, 128)
	pruneStringCount(behavior.LastRoles, 8)
}

func ewma(current float64, sample float64, observations int) float64 {
	if observations <= 1 || current == 0 {
		return sample
	}
	alpha := 0.15
	return current*(1-alpha) + sample*alpha
}

func pruneStringCount(in map[string]int, maxItems int) {
	if len(in) <= maxItems || maxItems <= 0 {
		return
	}
	type item struct {
		key string
		val int
	}
	items := make([]item, 0, len(in))
	for k, v := range in {
		items = append(items, item{key: k, val: v})
	}
	// Small bounded maps; insertion-sort style stability is unnecessary.
	for i := 0; i < len(items); i++ {
		for j := i + 1; j < len(items); j++ {
			if items[j].val > items[i].val || (items[j].val == items[i].val && items[j].key < items[i].key) {
				items[i], items[j] = items[j], items[i]
			}
		}
	}
	keep := map[string]struct{}{}
	for i := 0; i < maxItems && i < len(items); i++ {
		keep[items[i].key] = struct{}{}
	}
	for k := range in {
		if _, ok := keep[k]; !ok {
			delete(in, k)
		}
	}
}

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

func hasSMBListenerPort(ports map[int]struct{}) bool {
	if len(ports) == 0 {
		return false
	}
	if _, ok := ports[445]; ok {
		return true
	}
	if _, ok := ports[139]; ok {
		return true
	}
	return false
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

func outboundExternalPrefixes(conns []shared.ConnectionInfo) map[string]struct{} {
	prefixes := make(map[string]struct{})
	for _, c := range conns {
		if shared.IsInternalIP(c.RemoteAddress) || shared.IsLoopbackIP(c.RemoteAddress) {
			continue
		}
		if prefix := shared.TargetPrefix(c.RemoteAddress); prefix != "" {
			prefixes[prefix] = struct{}{}
		}
	}
	return prefixes
}

func trafficVerifiedByDest(
	conns []shared.ConnectionInfo,
	outExternal int,
	internalLateral bool,
	behavior *shared.ProcessBehavior,
	externalPrefixes map[string]struct{},
) bool {
	if len(conns) == 0 {
		return false
	}
	if outExternal == 0 && !internalLateral {
		return true
	}
	if behavior == nil || behavior.Observations < 6 {
		return false
	}
	if len(externalPrefixes) == 0 {
		return false
	}

	known := 0
	for prefix := range externalPrefixes {
		if behavior.KnownPrefixes[prefix] > 0 {
			known++
		}
	}
	knownRatio := float64(known) / float64(len(externalPrefixes))
	if knownRatio < 0.65 {
		return false
	}

	allowedExternal := behavior.AvgOutExternal*2.5 + 2
	if float64(outExternal) > allowedExternal {
		return false
	}

	if behavior.Observations > 0 {
		suspiciousRatio := float64(behavior.SuspiciousObservations) / float64(behavior.Observations)
		if suspiciousRatio > 0.35 {
			return false
		}
	}
	return true
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
		}
	}
	internalLateral = len(internalTargets) >= 3 || (len(internalTargets) >= 2 && len(internalPorts) >= 2)
	return
}

func smbPipeActivity(
	conns []shared.ConnectionInfo,
	ports map[int]struct{},
	now time.Time,
) (connCount int, targetCount int, longLived int, external bool, maxAgeSecs int) {
	targets := make(map[string]struct{})

	for _, c := range conns {
		if !isActiveConnState(c.State) {
			continue
		}
		if c.RemotePort != 445 && c.RemotePort != 139 {
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

		connCount++
		targets[c.RemoteAddress] = struct{}{}
		if !shared.IsInternalIP(c.RemoteAddress) {
			external = true
		}

		key := connKeyFromConn(c.Pid, c)
		first, ok := shared.ConnFirstSeen[key]
		if !ok {
			continue
		}
		age := now.Sub(first)
		if age >= shared.ReverseControlMinDuration {
			longLived++
		}
		ageSecs := int(age.Seconds())
		if ageSecs > maxAgeSecs {
			maxAgeSecs = ageSecs
		}
	}

	targetCount = len(targets)
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

func localTransportActivity(conns []shared.ConnectionInfo) (bool, int, int) {
	count := 0
	remotePorts := make(map[int]struct{})
	for _, c := range conns {
		if !isActiveConnState(c.State) {
			continue
		}
		if shared.IsLoopbackIP(c.LocalAddress) &&
			shared.IsLoopbackIP(c.RemoteAddress) &&
			c.LocalPort != c.RemotePort {
			count++
			if c.RemotePort > 0 {
				remotePorts[c.RemotePort] = struct{}{}
			}
		}
	}
	return count > 0, count, len(remotePorts)
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
		shared.ConnLastSeen[key] = now
	}

	for k, last := range shared.ConnLastSeen {
		if k.Pid != pid {
			continue
		}
		if _, ok := current[k]; ok {
			continue
		}
		if now.Sub(last) > shared.ConnMissingGrace {
			delete(shared.ConnFirstSeen, k)
			delete(shared.ConnLastSeen, k)
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
	behaviorTTL := shared.HistoryTTL * 4
	if behaviorTTL < 30*time.Minute {
		behaviorTTL = 30 * time.Minute
	}
	for key, behavior := range shared.ProcessBehaviorByKey {
		if behavior == nil || behavior.LastSeen.IsZero() || now.Sub(behavior.LastSeen) > behaviorTTL {
			delete(shared.ProcessBehaviorByKey, key)
		}
	}

	for pid, h := range shared.ProcHistoryByPID {
		if now.Sub(h.LastSeen) <= shared.HistoryTTL {
			continue
		}

		delete(shared.ProcHistoryByPID, pid)
		delete(shared.RecentClientSeen, pid)
		delete(shared.RecentOutboundSeen, pid)
		delete(shared.RecentInternalScanSeen, pid)
		delete(shared.ShortLivedBurstLast, pid)
		delete(shared.ShortLivedBurstFirst, pid)
		delete(shared.ShortLivedBurstCount, pid)
		delete(shared.ShortLivedBurstInterval, pid)
		delete(shared.ShortLivedBurstHits, pid)
		delete(shared.BeaconSeen, pid)
		delete(shared.LocalTransportLast, pid)
		delete(shared.PendingControlByPID, pid)

		for k := range shared.ConnFirstSeen {
			if k.Pid == pid {
				delete(shared.ConnFirstSeen, k)
				delete(shared.ConnLastSeen, k)
			}
		}
	}
}

func pendingControlAttempt(
	pid int,
	conns []shared.ConnectionInfo,
	ports map[int]struct{},
	now time.Time,
) (*shared.ConnectionInfo, int, int, bool) {
	var best *shared.ConnectionInfo
	for _, cn := range conns {
		if !isPendingControlState(cn.State) {
			continue
		}
		if cn.RemoteAddress == "" ||
			shared.IsWildcardIP(cn.RemoteAddress) ||
			shared.IsLoopbackIP(cn.RemoteAddress) {
			continue
		}
		if _, ok := ports[cn.LocalPort]; ok {
			continue
		}
		tmp := cn
		best = &tmp
		break
	}

	hist := shared.PendingControlByPID[pid]
	if best == nil {
		if hist != nil && now.Sub(hist.LastSeen) > shared.PendingControlGapReset {
			delete(shared.PendingControlByPID, pid)
		}
		return nil, 0, 0, false
	}

	target := fmt.Sprintf("%s:%d", best.RemoteAddress, best.RemotePort)
	if hist == nil ||
		hist.Target != target ||
		hist.LastSeen.IsZero() ||
		now.Sub(hist.LastSeen) > shared.PendingControlGapReset {
		hist = &shared.PendingControlHistory{
			Target:       target,
			FirstSeen:    now,
			LastSeen:     now,
			Observations: 1,
		}
		shared.PendingControlByPID[pid] = hist
	} else {
		if now.Sub(hist.LastSeen) >= time.Second {
			hist.Observations++
		}
		hist.LastSeen = now
	}

	ageSecs := max(0, int(now.Sub(hist.FirstSeen).Seconds()))
	repeated := hist.Observations >= shared.PendingControlMinObs &&
		now.Sub(hist.FirstSeen) >= shared.PendingControlMinDuration
	return best, ageSecs, hist.Observations, repeated
}

func isPendingControlState(state string) bool {
	switch state {
	case "SYN_SENT", "SYN_RECEIVED":
		return true
	default:
		return false
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
	case "smb-pipe":
		base = 78
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

func likelyBenignControlPattern(
	cn *shared.ConnectionInfo,
	behavior *shared.ProcessBehavior,
	externalPrefixes map[string]struct{},
	outExternal int,
	outInternal int,
	distinctTargets int,
	controlSecs int,
) bool {
	if cn == nil || behavior == nil || behavior.Observations < 8 {
		return false
	}
	if outInternal > 0 || shared.IsInternalIP(cn.RemoteAddress) {
		return false
	}
	if behavior.Observations == 0 {
		return false
	}
	suspiciousRatio := float64(behavior.SuspiciousObservations) / float64(behavior.Observations)
	if suspiciousRatio > 0.35 {
		return false
	}
	knownPrefixRatio := 0.0
	if len(externalPrefixes) > 0 {
		matches := 0
		for prefix := range externalPrefixes {
			if behavior.KnownPrefixes[prefix] > 0 {
				matches++
			}
		}
		knownPrefixRatio = float64(matches) / float64(len(externalPrefixes))
	}
	if knownPrefixRatio < 0.65 {
		return false
	}

	allowedTargets := behavior.AvgDistinctTargets*2.5 + 2
	allowedExternal := behavior.AvgOutExternal*2.5 + 2
	if float64(distinctTargets) > allowedTargets || float64(outExternal) > allowedExternal {
		return false
	}
	if controlSecs > 0 && behavior.AvgControlSeconds > 0 && float64(controlSecs) > behavior.AvgControlSeconds*4+120 {
		return false
	}
	return true
}

func suppressReverseControlForBenignChannel(cn *shared.ConnectionInfo, proc *shared.ProcessInfo, internalLateral bool, outInternal int, benignControlPattern bool) bool {
	if cn == nil || internalLateral {
		return false
	}
	if !shared.IsLikelyBenignControlClient(proc) {
		return false
	}
	if !benignControlPattern {
		return false
	}
	if shared.IsInternalIP(cn.RemoteAddress) || outInternal > 0 {
		return false
	}
	return true
}

func shouldPromoteReverseControl(
	cn *shared.ConnectionInfo,
	outInternal int,
	strongEvidence bool,
	benignControlPattern bool,
	controlSecs int,
	pendingControlRepeated bool,
	delegatedStrong bool,
) bool {
	if cn == nil {
		return false
	}
	if outInternal > 0 || shared.IsInternalIP(cn.RemoteAddress) {
		return true
	}
	if !benignControlPattern {
		return true
	}
	// External control-looking channels that match learned benign patterns
	// still promote if they show persistent duration or corroborating control cues.
	if strongEvidence || pendingControlRepeated || delegatedStrong {
		return true
	}
	return controlSecs >= 45
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

func warmupFallbackRole(hasListener bool, clients int, out int) string {
	switch {
	case hasListener && clients > 0 && out > 0:
		return "proxy-listener"
	case hasListener && clients > 0:
		return "listener-with-clients"
	case hasListener && out > 0:
		return "listener-with-outbound"
	case hasListener:
		return "listener-only"
	case out > 0:
		return "outbound-only"
	default:
		return "outbound-only"
	}
}

func applyRoleWarmupGates(
	c *shared.Candidate,
	hasListener bool,
	activeClients int,
	outTotal int,
	controlSecs int,
	pendingControlSecs int,
	observedConnAgeSecs int,
	smbMaxAgeSecs int,
	beaconAgeSecs int,
	addSignal func(string),
) bool {
	if c == nil {
		return false
	}

	family := shared.RoleFamily(c.Role)
	sessionAge := max(controlSecs, pendingControlSecs)
	tunnelAge := max(observedConnAgeSecs, sessionAge)
	smbAge := max(smbMaxAgeSecs, tunnelAge)
	fallbackRole := warmupFallbackRole(hasListener, activeClients, outTotal)
	blocked := false

	switch {
	case c.Role == "smb-pipe":
		minSecs := int(shared.SMBPipeMinLabelDuration.Seconds())
		if smbAge < minSecs {
			c.Role = fallbackRole
			addSignal("warmup-smb-pipe")
			c.Reasons = append(c.Reasons, fmt.Sprintf("SMB-pipe candidate warming up (%ds/%ds)", smbAge, minSecs))
			blocked = true
		}
	case family == "tunnel":
		minSecs := int(shared.TunnelMinLabelDuration.Seconds())
		if tunnelAge < minSecs {
			c.Role = fallbackRole
			addSignal("warmup-tunnel")
			c.Reasons = append(c.Reasons, fmt.Sprintf("Tunnel candidate warming up (%ds/%ds)", tunnelAge, minSecs))
			blocked = true
		}
	case family == "session":
		minSecs := int(shared.SessionMinLabelDuration.Seconds())
		if sessionAge < minSecs {
			c.Role = fallbackRole
			addSignal("warmup-session")
			c.Reasons = append(c.Reasons, fmt.Sprintf("Session candidate warming up (%ds/%ds)", sessionAge, minSecs))
			blocked = true
		}
	case family == "beacon":
		minSecs := int(shared.BeaconMinLabelDuration.Seconds())
		if beaconAgeSecs < minSecs {
			c.Role = fallbackRole
			addSignal("warmup-beacon")
			c.Reasons = append(c.Reasons, fmt.Sprintf("Beacon candidate warming up (%ds/%ds)", beaconAgeSecs, minSecs))
			blocked = true
		}
	}

	if blocked {
		if shared.RoleFamily(c.Role) == "outbound" {
			c.ActiveProxying = false
		}
		c.StrongEvidence = false
		if c.Role == "outbound-only" && c.Score > shared.OutboundOnlyExternalCap {
			c.Score = shared.OutboundOnlyExternalCap
		}
		if shared.RoleFamily(c.Role) == "listener" && c.Score > 50 {
			c.Score = 50
		}
	}
	return blocked
}

func maxEstablishedConnectionAgeSeconds(pid int, conns []shared.ConnectionInfo, now time.Time) int {
	maxAge := 0
	for _, cn := range conns {
		if !isEstablishedState(cn.State) {
			continue
		}
		key := connKeyFromConn(pid, cn)
		first, ok := shared.ConnFirstSeen[key]
		if !ok {
			continue
		}
		age := int(now.Sub(first).Seconds())
		if age > maxAge {
			maxAge = age
		}
	}
	return maxAge
}

func beaconObservationAgeSeconds(pid int, now time.Time) int {
	first, ok := shared.ShortLivedBurstFirst[pid]
	if !ok || first.IsZero() {
		return 0
	}
	age := int(now.Sub(first).Seconds())
	if age < 0 {
		return 0
	}
	return age
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

func applySignalFusionAdjustments(
	c *shared.Candidate,
	signals []string,
	controlConn *shared.ConnectionInfo,
	pendingControlRepeated bool,
	benignClient bool,
	trafficVerified bool,
	benignControlPattern bool,
	addSignal func(string),
) {
	if c == nil {
		return
	}
	hasSignal := func(needle string) bool {
		for _, sig := range signals {
			if sig == needle {
				return true
			}
		}
		return false
	}
	countSignals := func(keys ...string) int {
		n := 0
		for _, key := range keys {
			if hasSignal(key) {
				n++
			}
		}
		return n
	}

	suspiciousFusion := countSignals(
		"control-channel",
		"control-attempt-repeated",
		"control-target-stable",
		"reverse-control-shape",
		"reconnecting-control-session",
		"listener-egress-tunnel-shape",
		"forward-tunnel-shape",
		"susp-tun-eligible",
		"inbound-burst",
		"internal-lateral",
		"loopback-transport",
		"delegated-egress-strong",
		"rare-target-repeat",
		"smb-pipe-likely",
	)
	benignFusion := countSignals(
		"traffic-verified",
		"benign-control-pattern",
		"baseline-verified",
		"asn-org-aligned",
		"reverse-control-suppressed-benign",
		"reverse-control-deferred-benign-single",
		"reverse-control-suppressed-shape",
	)

	// Downgrade weak benign-looking sessions that lack corroboration.
	if shared.RoleFamily(c.Role) == "session" &&
		!c.StrongEvidence &&
		!c.ActiveProxying &&
		benignClient &&
		!pendingControlRepeated &&
		c.ControlDurationSeconds < 45 &&
		benignFusion >= 2 &&
		suspiciousFusion <= 1 {
		c.Role = "outbound-only"
		if c.Score > 34 {
			c.Score = 34
		}
		addSignal("signal-fusion-session-downgrade")
		c.Reasons = append(c.Reasons, "Signal fusion downgraded weak benign-looking session pattern")
		return
	}

	// Promote strong multi-trigger control behavior that still sits in outbound-only.
	if c.Role == "outbound-only" &&
		(controlConn != nil || pendingControlRepeated) &&
		!trafficVerified &&
		(!benignControlPattern || benignFusion == 0) &&
		suspiciousFusion >= 3 {
		holdBenignExternalPromotion := benignClient &&
			c.OutExternal > 0 &&
			c.OutInternal == 0 &&
			c.OutTotal <= 2 &&
			!pendingControlRepeated &&
			!c.DelegatedStrong &&
			!c.ActiveProxying &&
			c.InboundTotal == 0 &&
			c.OutLoopback == 0
		if holdBenignExternalPromotion {
			addSignal("signal-fusion-session-hold-benign-external")
		} else {
			c.Role = "susp-session"
			if c.Score < 50 {
				c.Score = 50
			}
			addSignal("signal-fusion-session-promote")
			c.Reasons = append(c.Reasons, "Signal fusion promoted multi-trigger control behavior to session")
		}
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
	sessionCue bool,
) bool {
	switch role {
	case "susp-tun", "reverse-proxy", "reverse-transport":
		return false
	case "reverse-control", "susp-session":
		// Keep explicit session/tunnel shapes as session/tunnel.
		if sessionCue || reverseControl || controlConn != nil || outLongLived > 0 {
			return false
		}
		// Allow beacon to reclaim stale/weak session labels only when cleanly beacon-shaped.
		return (beaconConfirmed || beaconRecent) &&
			!hasListener &&
			!localTransportRecent &&
			!internalScanRecent
	case "outbound-only":
		// If outbound currently carries session-like control cues, keep it out of beacon.
		if sessionCue || reverseControl || controlConn != nil || outLongLived > 0 {
			return false
		}
		// Keep tunnel/listener-adjacent behavior out of beacon promotion.
		if hasListener || localTransportRecent || internalScanRecent {
			return false
		}
		return true
	default:
		return false
	}
}

func sessionCueForBeaconPromotion(
	signals []string,
	pendingControlRepeated bool,
	delegatedStrong bool,
	outInternal int,
	internalLateral bool,
	inboundBurst int,
) bool {
	// Internal-only callback traffic can still be beacon-shaped in lab/private
	// ranges, so internal egress alone should not block beacon promotion.
	_ = outInternal
	if pendingControlRepeated || delegatedStrong || internalLateral || inboundBurst > 0 {
		return true
	}
	for _, sig := range signals {
		switch sig {
		case "control-attempt-repeated", "control-target-stable":
			return true
		}
	}
	return false
}

func internalFanoutBoost(targets map[string]struct{}, ports map[int]struct{}) int {
	score := 0
	if len(targets) >= 3 {
		score += 15
	}
	if len(ports) >= 2 {
		score += 10
	}
	if len(targets) >= 2 && len(ports) >= 3 {
		score += 10
	}
	return score
}

func isReverseControlShape(
	controlConn *shared.ConnectionInfo,
	hasListener bool,
	outTotal int,
	distinctTargets int,
	controlSecs int,
) bool {
	if controlConn == nil || hasListener {
		return false
	}
	if outTotal <= 0 || outTotal > 2 {
		return false
	}
	if distinctTargets <= 0 || distinctTargets > 2 {
		return false
	}
	return controlSecs >= int(shared.ReverseControlMinDuration.Seconds())
}

func shouldPromoteControlSession(
	controlConn *shared.ConnectionInfo,
	benignClient bool,
	benignControlPattern bool,
	reverseControlSuppressed bool,
	hasListener bool,
	reverseProxyNow bool,
	reverseControl bool,
	localTransportRecent bool,
	internalScanRecent bool,
	activeProxying bool,
	outTotal int,
	outExternal int,
	outInternal int,
	distinctTargets int,
	controlSecs int,
	pendingControlRepeated bool,
	delegatedStrong bool,
	internalLateral bool,
	inboundBurst int,
) bool {
	if controlConn == nil ||
		hasListener ||
		reverseProxyNow ||
		reverseControl ||
		localTransportRecent ||
		internalScanRecent ||
		activeProxying {
		return false
	}
	if outTotal <= 0 || outTotal > 8 {
		return false
	}
	if distinctTargets <= 0 || distinctTargets > 4 {
		return false
	}

	evidence := 0
	if outInternal > 0 || shared.IsInternalIP(controlConn.RemoteAddress) {
		evidence += 3
	}
	if !benignControlPattern {
		evidence += 2
	}
	if controlSecs >= 60 {
		evidence++
	}
	if controlSecs >= 180 {
		evidence++
	}
	if distinctTargets <= 2 {
		evidence++
	}
	if outExternal <= 2 {
		evidence++
	}
	if delegatedStrong {
		evidence++
	}
	if internalLateral || inboundBurst > 0 {
		evidence += 2
	}
	if reverseControlSuppressed {
		if controlSecs >= 45 && distinctTargets <= 2 && outTotal <= 4 {
			evidence += 2
		} else {
			evidence--
		}
	}

	// Benign clients on learned-benign control patterns require stronger corroboration.
	if benignClient && benignControlPattern && outInternal == 0 {
		if controlSecs < 45 || distinctTargets > 2 || outTotal > 4 {
			return false
		}
		if controlSecs < 120 {
			evidence--
		}
	}
	// Trusted clients with only external egress must show corroboration before
	// becoming session to reduce false positives on common service/app traffic.
	if benignClient && outInternal == 0 {
		if !pendingControlRepeated && !delegatedStrong && !internalLateral && inboundBurst == 0 {
			return false
		}
	}

	return evidence >= 4
}

func controlSessionBaseScore(
	controlSecs int,
	outInternal int,
	distinctTargets int,
	delegatedStrong bool,
	internalLateral bool,
) int {
	base := 50
	if controlSecs >= 60 {
		base += 8
	}
	if controlSecs >= 180 {
		base += 6
	}
	if controlSecs >= 300 {
		base += 4
	}
	if outInternal > 0 {
		base += 8
	}
	if distinctTargets == 1 {
		base += 4
	}
	if delegatedStrong {
		base += 4
	}
	if internalLateral {
		base += 6
	}
	if base > 82 {
		return 82
	}
	return base
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

func updateParentFreq(hostScope string, p *shared.ProcessInfo) {
	if p == nil {
		return
	}
	if strings.TrimSpace(hostScope) == "" {
		hostScope = "local"
	}
	key := fmt.Sprintf("%s|%d|%s|%s", hostScope, p.ParentPid, p.Name, p.ExePath)
	shared.ParentChildFreq[key]++
}

func updateBurstHistory(pid int, burstCount int, now time.Time) {
	if burstCount <= 0 {
		return
	}

	if _, ok := shared.ShortLivedBurstFirst[pid]; !ok {
		shared.ShortLivedBurstFirst[pid] = now
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
