package classifier

import (
	"fmt"
	"strings"
	"time"

	"proxywatch/internal/model"
	"proxywatch/internal/shared"
)

// proxyPorts is the set of well-known proxy ports checked during scoring.
// Declared at package level to avoid re-allocating on every ScoreCandidate call.
var proxyPorts = map[int]struct{}{3128: {}, 8080: {}, 8118: {}, 8888: {}}

func ScoreCandidate(c *shared.Candidate) {
	scoreVal := 0
	reasons := make([]string, 0, 16)
	signals := make([]string, 0, 16)
	addSignal := func(s string) {
		for _, existing := range signals {
			if existing == s {
				return
			}
		}
		signals = append(signals, s)
	}

	p := c.Proc
	if p == nil {
		c.Score = 0
		return
	}
	now := time.Now()
	benignClient := shared.IsLikelyBenignControlClient(p)
	if benignClient && shared.BenignOverriddenByBehavior(c) {
		benignClient = false
		addSignal("benign-override")
	}
	scopedPID := historyPIDForCandidate(c)
	behaviorKey := ProcessBehaviorKey(c)
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

	// Parent-child chain scoring — if this process is delegated egress with a
	// strong link and the parent process itself has an elevated detection score,
	// the chain is more suspicious.
	if c.DelegatedEgress && c.DelegatedStrong && c.DelegatedOwnerPID > 0 {
		if parentHist, ok := shared.ProcHistoryByPID[c.DelegatedOwnerPID]; ok && parentHist != nil {
			if parentHist.StickyScore >= 60 {
				addSignal("suspicious-parent-chain")
				scoreVal += 4
				reasons = append(reasons, fmt.Sprintf("Parent process (PID %d) also has elevated detection score", c.DelegatedOwnerPID))
			}
		}
	}

	hist := getHistory(scopedPID, now)
	updateConnHistory(scopedPID, c.Conns, now)
	updateParentFreq(historyHostScope(c), p)
	parentKey := fmt.Sprintf("%s|%d|%s|%s", historyHostScope(c), p.ParentPid, p.Name, p.ExePath)
	rareParent := shared.ParentChildFreq[parentKey] <= 1

	// Command line analysis: detect SSH tunnels (-L, -R, -D flags).
	if p.CmdLine != "" {
		cmdLower := strings.ToLower(p.CmdLine)
		nameLower := strings.ToLower(p.Name)
		if nameLower == "ssh" || nameLower == "ssh.exe" || strings.Contains(nameLower, "plink") {
			if strings.Contains(cmdLower, " -r ") || strings.Contains(cmdLower, " -r:") || strings.HasSuffix(cmdLower, " -r") {
				scoreVal += 30
				addSignal("ssh-reverse-tunnel")
				reasons = append(reasons, "SSH reverse port forward detected (-R flag in command line)")
			}
			if strings.Contains(cmdLower, " -l ") || strings.Contains(cmdLower, " -l:") {
				scoreVal += 25
				addSignal("ssh-local-tunnel")
				reasons = append(reasons, "SSH local port forward detected (-L flag in command line)")
			}
			if strings.Contains(cmdLower, " -d ") || strings.Contains(cmdLower, " -d:") {
				scoreVal += 35
				addSignal("ssh-dynamic-socks")
				reasons = append(reasons, "SSH dynamic SOCKS proxy detected (-D flag in command line)")
			}
		}
	}

	ports, loopbackOnly, anyWildcard := socksListenerPorts(c.Listeners)
	hasListener := len(ports) > 0

	// Model intelligence: check for generalized training patterns early.
	// If the model has learned a pattern from 3+ operator labels that matches
	// this process, apply it as a signal.
	if c.Proc != nil {
		if verdict, desc := model.MatchTrainingPattern(c.Proc, 0, 0, 0, hasListener); verdict != "" {
			addSignal("model-training-pattern")
			reasons = append(reasons, "model: training pattern — "+desc)
			if verdict == "benign" {
				scoreVal -= 10
			} else if verdict == "malicious" {
				scoreVal += 15
			}
		}
	}

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

	// Command-line proxy/tunnel flag detection
	if shared.HasProxyFlags(p.CmdLine) {
		addSignal("cmdline-proxy-flags")
		scoreVal += 12
		reasons = append(reasons, "Command line contains proxy/tunnel flags")
	}

	// Raw socket detection — process has open raw/packet sockets that
	// bypass the kernel TCP stack (nmap SYN scan, ping, packet capture, etc.).
	if c.RawSocket {
		addSignal("raw-socket")
		scoreVal += 20
		reasons = append(reasons, "Raw socket open (bypasses TCP stack)")
	}

	// Loaded library detection — match behavioral patterns (socks, proxy,
	// tunnel functionality) rather than specific library names.
	if len(p.LoadedLibs) > 0 {
		for _, lib := range p.LoadedLibs {
			base := strings.ToLower(lib)
			if idx := strings.LastIndexAny(base, "/\\"); idx >= 0 {
				base = base[idx+1:]
			}
			if hasProxyTunnelLibPattern(base) {
				addSignal("proxy-library-loaded")
				scoreVal += 5
				reasons = append(reasons, fmt.Sprintf("Proxy/tunnel library loaded: %s", lib))
				break
			}
		}
	}

	// User-writable path detection — processes running from Downloads, Desktop,
	// Temp, or other user-writable directories are more suspicious. This signal
	// counteracts benign/verified suppression for processes in these locations.
	suspiciousPath := isSuspiciousExePath(p.ExePath)
	if suspiciousPath {
		addSignal("suspicious-exe-path")
		scoreVal += 8
		reasons = append(reasons, "Executable runs from user-writable path ("+shared.NormalizeExePath(p.ExePath)+")")
	}

	// Time-of-day awareness: connections from user-session processes outside
	// business hours (before 6am or after 10pm local time) get a small boost.
	hour := time.Now().Hour()
	offHours := hour < 6 || hour >= 22
	if offHours && outTotal > 0 && !benignClient {
		// Only apply to non-service processes (those with a user session).
		if c.Proc != nil && c.Proc.SessionID > 0 {
			addSignal("off-hours-activity")
			scoreVal += 3
			reasons = append(reasons, fmt.Sprintf("Network activity during off-hours (%02d:00 local time)", hour))
		}
	}

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

	// DNS volume anomaly detection — high DNS query volume may indicate
	// DNS tunneling or domain generation algorithm (DGA) activity.
	{
		dnsConnCount := 0
		for i := range c.Conns {
			if c.Conns[i].RemotePort == 53 {
				dnsConnCount++
			}
		}
		if dnsConnCount >= 5 {
			addSignal("dns-volume-anomaly")
			scoreVal += 6
			reasons = append(reasons, fmt.Sprintf("High DNS query volume (%d connections to port 53) may indicate DNS tunneling or DGA", dnsConnCount))
		}
	}

	// Port hopping detection — a process connecting to the same remote IP
	// on many different ports is consistent with port rotation / scanning.
	{
		ipPorts := make(map[string]map[int]struct{})
		for i := range c.Conns {
			rip := c.Conns[i].RemoteAddress
			rport := c.Conns[i].RemotePort
			if rip == "" || rport == 0 {
				continue
			}
			if _, ok := ipPorts[rip]; !ok {
				ipPorts[rip] = make(map[int]struct{})
			}
			ipPorts[rip][rport] = struct{}{}
		}
		for ip, portSet := range ipPorts {
			if len(portSet) >= 3 {
				addSignal("port-hopping")
				scoreVal += 5
				reasons = append(reasons, fmt.Sprintf("Process connects to %s on %d different ports, consistent with port rotation", ip, len(portSet)))
				break
			}
		}
	}

	// Proxy-assisted egress detection — a process connecting to known proxy
	// ports on internal hosts while also maintaining external connections
	// suggests it is routing traffic through an internal proxy.
	{
		hasInternalProxy := false
		var internalProxyPort int
		hasExternalConn := false
		for i := range c.Conns {
			rip := c.Conns[i].RemoteAddress
			rport := c.Conns[i].RemotePort
			if rip == "" {
				continue
			}
			if _, isProxy := proxyPorts[rport]; isProxy && shared.IsInternalIP(rip) {
				hasInternalProxy = true
				internalProxyPort = rport
			}
			if !shared.IsInternalIP(rip) && !shared.IsLoopbackIP(rip) && !shared.IsWildcardIP(rip) {
				hasExternalConn = true
			}
		}
		if hasInternalProxy && hasExternalConn {
			addSignal("proxy-assisted-egress")
			scoreVal += 6
			reasons = append(reasons, fmt.Sprintf("Process connects to internal proxy port (%d) and maintains external connections", internalProxyPort))
		}
	}

	// Contour egress intelligence: check if this process uses known tunnel/exfil ports.
	{
		egressSigs, egressReasons, egressBoost := model.EgressSignals(c.Conns)
		for _, sig := range egressSigs {
			addSignal(sig)
		}
		reasons = append(reasons, egressReasons...)
		scoreVal += egressBoost
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

	// Track SYN_SENT cycling — detects beacon callbacks when C2 is down.
	synCycleBeacon, synCycles, synAvgInterval := updateSYNCycleTracking(scopedPID, c.Conns, ports, now)
	if synCycleBeacon {
		addSignal("syn-cycle-beacon")
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

	// Cross-PID beacon recognition: if in-memory tracking didn't confirm,
	// check if the model knows this process identity as a beacon.
	if !beaconConfirmed {
		if modelKnown, modelInterval, modelJitter := beaconFromModel(behaviorKey); modelKnown {
			beaconConfirmed = true
			beaconInterval = modelInterval
			beaconJitter = modelJitter
			beaconHits = 3 // minimum for confirmation
			addSignal("beacon-model-recalled")
			reasons = append(reasons, fmt.Sprintf("Known beacon from model: %s interval, %.0f%% jitter", beaconInterval, modelJitter*100))
		}
	}

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
	beaconBlockedByVerified := beaconEligible && outExternal > 0 && trafficVerified && !strongEvidence && !suspiciousPath
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
			addSignal("session")
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
				c.Role = "tunnel"
				c.ActiveProxying = true
				c.ControlChannel = controlConn
				c.ControlDurationSeconds = controlSecs
				c.Reasons = []string{
					"Persistent reverse control channel with local transport activity",
				}
				addSignal("tunnel")
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
		addSignal("session")
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

	if c.Role == "outbound" &&
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
		c.Role = "tunnel"
		if hist.StickyScore > c.Score {
			c.Score = hist.StickyScore
		}
		if reverseProxyNow {
			c.Reasons = append(c.Reasons, "Persistent control channel with proxied outbound activity")
		}
		addSignal("tunnel")
	} else if reverseControl || (suspiciousRecent && hist.SuspicionKind == shared.SuspicionControl && controlConn != nil && !reverseControlSuppressed) {
		c.Role = "control-channel"
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
		addSignal("session")
	}

	promoteSuspTun := suspTunEligible && (reverseProxyNow || reverseControl)
	if promoteSuspTun && !outboundRecent && !activeProxying {
		promoteSuspTun = false
	}

	if promoteSuspTun {
		c.Role = "tunnel"
		c.ActiveProxying = forwardActiveNow || reverseProxyNow || localTransportForwarding
		addSignal("tunnel")

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
		c.Role = "control-channel"
		c.ActiveProxying = false
		addSignal("session")
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
	if c.Role == "outbound" &&
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
		c.Role = "control-channel"
		c.ActiveProxying = false
		addSignal("control-session")
		addSignal("session")
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
		c.Role != "tunnel" &&
		c.Role != "control-channel" {
		c.Role = "tunnel"
		c.ActiveProxying = activeClients > 0 || localTransportRecent
		addSignal("forward-tunnel")
		c.Reasons = append(c.Reasons, "Loopback forward-listener with persistent control channel")
		if c.Score < 65 {
			c.Score = 65
		}
	}

	if c.DelegatedStrong &&
		c.Role == "outbound" &&
		controlConn != nil &&
		!hasListener &&
		!localTransportRecent &&
		!internalScanRecent {
		c.Role = "control-channel"
		c.ActiveProxying = false
		addSignal("session")
		c.Reasons = append(c.Reasons, "Delegated control-channel shape is consistent with a reverse session")
		if c.Score < 45 {
			c.Score = 45
		}
	}

	// Promote listener+egress control shapes to tunnel even when strict forward-tunnel
	// matching cannot be proven in a single refresh.
	if c.Role == "listen" &&
		hasListener &&
		outTotal > 0 &&
		(activeClients > 0 || outInternal > 0 || internalLateral || localTransportForwarding || c.DelegatedStrong) {
		c.Role = "tunnel"
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

	// Promote processes from suspicious paths (Downloads, Temp, Desktop) with pending
	// control attempts to internal targets. These are strong C2 indicators even when
	// the control server is offline and connections are SYN_SENT.
	if c.Role == "outbound" &&
		suspiciousPath &&
		pendingControlConn != nil &&
		!hasListener &&
		outTotal <= 3 &&
		len(distinctTargets) <= 2 &&
		(shared.IsInternalIP(pendingControlConn.RemoteAddress) || pendingControlRepeated) {
		c.Role = "control-channel"
		c.ActiveProxying = false
		addSignal("suspicious-path-control-attempt")
		c.Reasons = append(c.Reasons, "Process from user-writable path has pending control connection to internal target")
		if c.ControlChannel == nil {
			c.ControlChannel = pendingControlConn
			c.ControlDurationSeconds = pendingControlSecs
		}
		if c.Score < 68 {
			c.Score = 68
		}
		hist.LastSuspicious = now
		hist.SuspicionKind = shared.SuspicionControl
		if hist.StickyScore < c.Score {
			hist.StickyScore = c.Score
		}
	}

	// Promote to beacon when SYN_SENT cycling is detected — the process
	// repeatedly attempts connections that appear and disappear, revealing a
	// callback interval even when the C2 server is offline.
	if synCycleBeacon && pendingControlConn != nil &&
		!hasListener && outTotal <= 3 && len(distinctTargets) <= 2 {
		c.Role = "control-channel"
		c.ActiveProxying = false
		addSignal("syn-cycle-promoted")
		c.Reasons = append(c.Reasons, fmt.Sprintf("SYN_SENT cycling detected (%d cycles, ~%.0fs interval) to %s:%d",
			synCycles, synAvgInterval, pendingControlConn.RemoteAddress, pendingControlConn.RemotePort))
		if c.ControlChannel == nil {
			c.ControlChannel = pendingControlConn
			c.ControlDurationSeconds = pendingControlSecs
		}
		if c.Score < 72 {
			c.Score = 72
		}
		hist.LastSuspicious = now
		hist.SuspicionKind = shared.SuspicionControl
		if hist.StickyScore < c.Score {
			hist.StickyScore = c.Score
		}
	}

	// Promote recurring reconnect-style control callbacks to session when no persistent
	// socket is visible long enough in a single sample.
	if c.Role == "outbound" &&
		!hasListener &&
		outTotal > 0 &&
		outTotal <= 3 &&
		outExternal > 0 &&
		outInternal == 0 &&
		len(distinctTargets) <= 2 &&
		(!trafficVerified || suspiciousPath) &&
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
			c.Role = "control-channel"
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
			c.Role = "control-channel"
			c.ActiveProxying = false
			addSignal("beacon")
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
	smbBaseRole := c.Role == "outbound" || c.Role == "listen"
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
	if c.Role == "outbound" && suspiciousRecent && !benignControlPattern {
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
				c.Role = "tunnel"
				if c.Score < 48 {
					c.Score = 48
				}
				addSignal("suspicion-memory-tunnel")
			case shared.SuspicionBeacon:
				c.Role = "control-channel"
				if c.Score < 46 {
					c.Score = 46
				}
				addSignal("suspicion-memory-beacon")
			case shared.SuspicionControl:
				c.Role = "control-channel"
				if c.Score < 46 {
					c.Score = 46
				}
				addSignal("suspicion-memory-session")
			}
		}
	}

	observedConnAgeSecs := maxEstablishedConnectionAgeSeconds(scopedPID, c.Conns, now)
	beaconAgeSecs := beaconObservationAgeSeconds(scopedPID, now)
	preWarmupRole := c.Role
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
		suspiciousPath,
		addSignal,
	) {
		strongEvidence = false
	}

	// Model intelligence: if warmup held the process in "analyzing" but the
	// model has strong prior evidence, commit immediately.
	if c.Role == "analyzing" && preWarmupRole != "analyzing" {
		knownVendor := shared.IsKnownVendorProcess(c.Proc)
		decision := model.ShouldAnalyze(behaviorKey, hist.ShapeSamples, c.SeenSeconds, benignClient, knownVendor, c.Proc)
		if !decision.ShouldAnalyze {
			c.Role = preWarmupRole
			addSignal("model-fast-commit")
			c.Reasons = append(c.Reasons, decision.Reason)
		}
	}

	c.TrafficVerified = trafficVerified
	c.StrongEvidence = strongEvidence
	if !c.StrongEvidence && c.Role == "control-channel" && controlConn != nil {
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
		threshold := 88
		switch c.Role {
		case "session":
			threshold = 70
		case "beacon":
			threshold = 68
		case "tunnel", "smb-pipe":
			threshold = 74
		case "listen":
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
			c.Reasons = append(c.Reasons, fmt.Sprintf("Role-aware strong state promotion (%s, score=%d, corroboration=%d)", c.Role, c.Score, corroboration))
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
		suspiciousPath,
		addSignal,
	)
	if delegatedReason != "" {
		c.Reasons = append(c.Reasons, delegatedReason)
	}
	if trafficVerified && !strongEvidence {
		c.Reasons = append(c.Reasons, "Traffic matches verified destinations (de-emphasized)")
	}
	applyASNRankAssist(c, p, addSignal)
	// CDN destination detection — flag processes connecting to CDN infrastructure.
	// Combined with beacon/control signals, this indicates domain fronting.
	{
		orgs, _, _ := shared.ResolveExternalASNOrgs(c.Conns)
		cdnDetected := false
		for _, org := range orgs {
			if shared.IsCDNOrg(org) {
				cdnDetected = true
				break
			}
		}
		if cdnDetected {
			addSignal("cdn-destination")
			c.Reasons = append(c.Reasons, "External traffic routes through CDN infrastructure (possible domain fronting)")
			// Only boost score if combined with other suspicious signals
			if c.Role == "control-channel" || c.Role == "control-beacon" || c.Role == "control-tunnel" {
				scoreVal += 10
				addSignal("cdn-control-channel")
				c.Reasons = append(c.Reasons, "Control channel through CDN — high confidence domain fronting")
			}
		}
	}
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

	// Enforce role stability — prevent rapid role flipping.
	// Only apply AFTER warmup has had its say. If the warmup gate demoted
	// the role (e.g., beacon→outbound), do NOT revert that demotion.
	warmupDemoted := false
	for _, sig := range c.Signals {
		if sig == "warmup-command" || sig == "warmup-tunnel" || sig == "warmup-smb-pipe" {
			warmupDemoted = true
			break
		}
	}
	if !warmupDemoted && hist != nil && hist.LastRole != "" && c.Role != hist.LastRole {
		prevMalicious := isMaliciousRole(hist.LastRole)
		newMalicious := isMaliciousRole(c.Role)

		if prevMalicious && !newMalicious {
			// Demotion from malicious to non-malicious (e.g., session→outbound):
			// block for a long cooldown — the process must prove it's clean.
			if now.Sub(hist.LastRoleChange) < shared.MaliciousRoleDemoteCooldown {
				c.Role = hist.LastRole
			}
		} else if !prevMalicious && !newMalicious {
			// Non-malicious to non-malicious (e.g., outbound→listen):
			// short cooldown to prevent thrashing.
			if now.Sub(hist.LastRoleChange) < shared.RoleChangeCooldown {
				if !isRoleUpgrade(hist.LastRole, c.Role) {
					c.Role = hist.LastRole
				}
			}
		}
		// Malicious→malicious transitions (session→beacon, beacon→tunnel, etc.)
		// are always allowed immediately — the classification is refining, not demoting.
	}
	// Model intelligence: let the accumulated model override the signal-based role
	// when it has strong evidence from training labels, operator feedback,
	// experience history, or calibration verdicts.
	{
		decision := model.DecideRole(behaviorKey, c.Role, scoreVal, c.Proc, outExternal, outInternal, c.InboundTotal, hasListener)
		if decision.Override {
			c.Role = decision.Role
			addSignal("model-role-override")
			c.Reasons = append(c.Reasons, decision.Reason)
		}
	}

	if hist != nil {
		if hist.LastRole != c.Role {
			hist.LastRoleChange = now
		}
		hist.LastRole = c.Role
	}

	// Determine control-channel subtype from signals.
	if c.Role == "control-channel" {
		hasBeaconSig := false
		hasSessionSig := false
		for _, sig := range signals {
			if sig == "beacon" || sig == "beacon-cadence" || sig == "beacon-pattern-confirmed" || sig == "reconnecting-callback-observed" {
				hasBeaconSig = true
			}
			if sig == "session" || sig == "persistent-control" || sig == "reverse-control" || sig == "strong-control-session" {
				hasSessionSig = true
			}
		}
		if hasBeaconSig && !hasSessionSig {
			c.ControlSubtype = "beacon"
		} else {
			c.ControlSubtype = "session"
		}
	}

	c.Signals = signals
	c.Confidence = confidenceFor(c.Role, c.Score, c.ActiveProxying)

	purgeHistory(now)
}

/* ---------------- helpers ---------------- */
