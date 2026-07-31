package scoring

import (
	"fmt"
	"strings"
	"time"

	bhv "proxywatch/internal/detection/behavior"
	"proxywatch/internal/detection/model"
	"proxywatch/internal/shared"
)

// ProxyPorts is the set of well-known proxy ports checked during scoring.
// Declared at package level to avoid re-allocating on every ScoreCandidate call.
var ProxyPorts = map[int]struct{}{3128: {}, 8080: {}, 8118: {}, 8888: {}}

func ScoreCandidate(c *shared.Candidate, now time.Time) {
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
	// Detection treats ALL processes equally — no benign suppression.
	wasBenignClient := shared.IsLikelyBenignControlClient(p)
	benignClient := false

	scopedPID := HistoryPIDForCandidate(c)
	behaviorKey := ProcessBehaviorKey(c)
	behavior := GetOrCreateProcessBehavior(behaviorKey, now)

	// Behavior signals emitted AFTER scoring populates all candidate fields
	// (ControlChannel, ControlDurationSeconds, BeaconIntervalMs, OutTotal, etc.)
	// See the emit block near the end of this function.

	// Pre-existing tunnel/session detection — catch C2 channels that were
	// established BEFORE proxywatch started observing this specific process.
	// A process seen for the first time with both external + internal
	// ESTABLISHED connections is suspicious.
	//
	// Gated on proxywatch startup grace period: when proxywatch itself just
	// started (e.g., service restart, state reset via deleting .proxywatch,
	// initial install), EVERY existing process looks "first observed" and
	// would otherwise get the suspicion boost. Only apply this detection for
	// processes that appear AFTER proxywatch has been observing the system
	// for StartupGracePeriod — those are genuinely-new processes that started
	// while proxywatch was watching.
	pwUptime := now.Sub(shared.ProxywatchStartedAt)
	if behavior != nil && behavior.Observations <= 5 && pwUptime >= shared.StartupGracePeriod {
		establishedExternal := 0
		establishedInternal := 0
		for _, conn := range c.Conns {
			if conn.State != "ESTABLISHED" {
				continue
			}
			if shared.IsInternalIP(conn.RemoteAddress) {
				establishedInternal++
			} else if !shared.IsLoopbackIP(conn.RemoteAddress) {
				establishedExternal++
			}
		}
		if establishedExternal > 0 && establishedInternal > 0 {
			scoreVal += 25
			reasons = append(reasons, "Process had external + internal connections when first observed")
		}
		if establishedExternal > 0 && c.OutLongLived > 0 && !wasBenignClient {
			scoreVal += 20
			reasons = append(reasons, "Process had established long-lived external connection when first observed")
		}
	}
	delegatedReason := ""
	if c.DelegatedEgress {
		if c.DelegatedStrong {
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
				scoreVal += 4
				reasons = append(reasons, fmt.Sprintf("Parent process (PID %d) also has elevated detection score", c.DelegatedOwnerPID))
			}
		}
	}

	hist := GetHistory(scopedPID, now)
	UpdateConnHistory(scopedPID, c.Conns, now)
	UpdateParentFreq(HistoryHostScope(c), p)
	parentKey := fmt.Sprintf("%s|%d|%s|%s", HistoryHostScope(c), p.ParentPid, p.Name, p.ExePath)
	rareParent := shared.ParentChildFreq[parentKey] <= 1

	// Command line analysis: detect SSH tunnels (-L, -R, -D flags).
	if p.CmdLine != "" {
		cmdLower := strings.ToLower(p.CmdLine)
		nameLower := strings.ToLower(p.Name)
		if nameLower == "ssh" || nameLower == "ssh.exe" || strings.Contains(nameLower, "plink") {
			if strings.Contains(cmdLower, " -r ") || strings.Contains(cmdLower, " -r:") || strings.HasSuffix(cmdLower, " -r") {
				scoreVal += 30
				reasons = append(reasons, "SSH reverse port forward detected (-R flag in command line)")
			}
			if strings.Contains(cmdLower, " -l ") || strings.Contains(cmdLower, " -l:") {
				scoreVal += 25
				reasons = append(reasons, "SSH local port forward detected (-L flag in command line)")
			}
			if strings.Contains(cmdLower, " -d ") || strings.Contains(cmdLower, " -d:") {
				scoreVal += 35
				reasons = append(reasons, "SSH dynamic SOCKS proxy detected (-D flag in command line)")
			}
		}
	}

	ports, loopbackOnly, anyWildcard := SocksListenerPorts(c.Listeners)
	hasListener := HasAnyListener(c)

	// Model intelligence: check for generalized training patterns early.
	// If the model has learned a pattern from 3+ operator labels that matches
	// this process, apply it as a signal.
	if c.Proc != nil {
		if verdict, desc := model.MatchTrainingPattern(c.Proc, 0, 0, 0, hasListener); verdict != "" {
			reasons = append(reasons, "model: training pattern — "+desc)
			if verdict == "benign" {
				scoreVal -= 10
			} else if verdict == "malicious" {
				scoreVal += 15
			}
		}
	}

	activeClients, _ := CountActiveClientSessions(c.Conns, ports)
	outTotal, outExternal, outInternal, outLoopback := OutboundTargets(c.Conns, ports)
	outLongLived, outShortLived := OutboundConnAgeStats(c.Conns, ports, now)

	c.OutTotal = outTotal
	c.OutExternal = outExternal
	c.OutInternal = outInternal
	c.OutLoopback = outLoopback
	c.OutLongLived = outLongLived
	c.OutShortLived = outShortLived
	c.InboundTotal = activeClients

	// Command-line proxy/tunnel flag detection
	if shared.HasProxyFlags(p.CmdLine) {
		scoreVal += 12
		reasons = append(reasons, "Command line contains proxy/tunnel flags")
	}

	// Raw socket detection — process has open raw/packet sockets that
	// bypass the kernel TCP stack (nmap SYN scan, ping, packet capture, etc.).
	if c.RawSocket {
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
			if bhv.HasProxyTunnelLibPattern(base) {
				scoreVal += 5
				reasons = append(reasons, fmt.Sprintf("Proxy/tunnel library loaded: %s", lib))
				break
			}
		}
	}

	// User-writable path detection — processes running from Downloads, Desktop,
	// Temp, or other user-writable directories are more suspicious. This signal
	// counteracts benign/verified suppression for processes in these locations.
	suspiciousPath := IsSuspiciousExePath(p.ExePath)
	if suspiciousPath {
		scoreVal += 2 // low weight — path alone is weak evidence, APTs use legitimate paths
		// Do NOT add to reasons/evidence — path is a signal, not evidence.
		// APTs use system paths, signed bins, etc. Path alone proves nothing.
	}

	// Time-of-day awareness: connections from user-session processes outside
	// business hours (before 6am or after 10pm local time) get a small boost.
	// Shape drift detection
	totalNet := c.OutTotal + c.InboundTotal + c.OutLoopback
	if totalNet > 0 {
		curOut := float64(c.OutTotal) / float64(totalNet)
		curIn := float64(c.InboundTotal) / float64(totalNet)
		curLoop := float64(c.OutLoopback) / float64(totalNet)
		if hist.ShapeSamples > 0 {
			if ShapeDelta(curOut, hist.LastOutRatio) > shared.ShapeDeltaThreshold ||
				ShapeDelta(curIn, hist.LastInRatio) > shared.ShapeDeltaThreshold ||
				ShapeDelta(curLoop, hist.LastLoopRatio) > shared.ShapeDeltaThreshold {
			}
		}
		hist.LastOutRatio = curOut
		hist.LastInRatio = curIn
		hist.LastLoopRatio = curLoop
		hist.ShapeSamples++
	}

	// Track memory over time for variance computation.
	if p.MemUsage > 0 {
		hist.MemSamples = append(hist.MemSamples, p.MemUsage)
		if len(hist.MemSamples) > 20 {
			hist.MemSamples = hist.MemSamples[len(hist.MemSamples)-20:]
		}
	}

	if activeClients > 0 {
		shared.RecentClientSeen[scopedPID] = now
	}
	inboundBurst := UpdateInboundBurst(scopedPID, activeClients, now)
	if inboundBurst > 0 {
	}
	if outTotal > 0 {
		shared.RecentOutboundSeen[scopedPID] = now
	}
	if outInternal > 0 {
	}
	if outExternal > 0 {
	}
	if outLoopback > 0 {
	}
	if outLongLived > 0 {
	}
	if outShortLived > 0 && outLongLived == 0 {
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
			if _, isProxy := ProxyPorts[rport]; isProxy && shared.IsInternalIP(rip) {
				hasInternalProxy = true
				internalProxyPort = rport
			}
			if !shared.IsInternalIP(rip) && !shared.IsLoopbackIP(rip) && !shared.IsWildcardIP(rip) {
				hasExternalConn = true
			}
		}
		if hasInternalProxy && hasExternalConn {
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

	controlConn, controlSecs := FindPersistentControl(scopedPID, c.Conns, ports, now)
	if controlConn != nil {
		c.ControlChannel = controlConn
		c.ControlDurationSeconds = controlSecs
	}
	pendingControlConn, pendingControlSecs, pendingControlObs, pendingControlRepeated := PendingControlAttempt(scopedPID, c.Conns, ports, now)
	if controlConn == nil && pendingControlConn != nil {
		if pendingControlRepeated {
			if c.ControlChannel == nil {
				c.ControlChannel = pendingControlConn
				c.ControlDurationSeconds = pendingControlSecs
			}
			reasons = append(reasons, fmt.Sprintf("Repeated pending outbound control attempts (%d observations) to stable target", pendingControlObs))
		}
	}

	// Track SYN_SENT cycling — detects beacon callbacks when C2 is down.
	synCycleBeacon, synCycles, synAvgInterval := UpdateSYNCycleTracking(scopedPID, c.Conns, ports, now)
	if synCycleBeacon {
	}

	reverseProxyNow := false

	outboundActive, distinctTargets, distinctTargetPorts, targetPrefixes := OutboundActivity(c.Conns, ports)
	internalTargets, internalPorts, internalLateral := OutboundInternalSummary(c.Conns, ports)
	smbConns, smbTargets, smbLongLived, smbExternal, smbMaxAgeSecs := SmbPipeActivity(c.Conns, ports, now)
	smbListener := HasSMBListenerPort(ports)
	smbPivotShape := smbListener && activeClients > 0 && smbConns > 0
	// Don't flag SMB pipe when the process has a listener — the SMB connections
	// are likely proxied traffic (SOCKS/SSH tunnel), not the process's own behavior.
	smbPipeLikely := smbConns > 0 && !hasListener && (smbLongLived > 0 || controlConn != nil || c.DelegatedStrong || internalLateral || outInternal > 0)
	if smbPivotShape {
		smbPipeLikely = true
		reasons = append(reasons, "Simultaneous inbound SMB clients and outbound internal SMB flow")
	}
	if smbConns > 0 {
		reasons = append(reasons, fmt.Sprintf("SMB channel activity over TCP/445 (%d connection(s), %d target(s))", smbConns, smbTargets))
	}
	if smbLongLived > 0 {
	}
	if smbExternal {
	}
	// SMB pipe detection is sticky — once detected, remember it across cycles
	// just like beacon detection. SMB connections are transient but the pivot
	// behavior persists.
	if smbPipeLikely {
		shared.SMBPipeSeen[scopedPID] = now
	} else if t, ok := shared.SMBPipeSeen[scopedPID]; ok && now.Sub(t) <= shared.SuspicionWindow {
		smbPipeLikely = true
	}
	internalFanoutScore := InternalFanoutBoost(internalTargets, internalPorts)
	controlTargetStable := controlConn != nil &&
		!hasListener &&
		outTotal > 0 &&
		outTotal <= 6 &&
		len(distinctTargets) <= 2
	if controlTargetStable {
	}
	reverseTunnelEligible := internalLateral ||
		(len(internalTargets) >= shared.MinInternalTargetsForRev &&
			len(internalPorts) >= shared.MinInternalPortsForRev)
	// Benign clients suppress tunnel eligibility ONLY when they have no
	// outbound internal connections. A benign process (e.g., sshd.exe) making
	// outbound connections to internal targets on distinct ports is tunnel
	// behavior — legitimate servers accept inbound, not initiate outbound.
	if benignClient && !internalLateral && outInternal == 0 {
		reverseTunnelEligible = false
	}

	// Cross-proc rare tuple tracking (remote prefix + port) to surface repeated rare C2 patterns.
	for pref := range targetPrefixes {
		key := pref
		shared.RareTupleCount[key]++
		if shared.RareTupleCount[key] > 1 {
		}
	}

	UpdateBurstHistory(scopedPID, burstCount, now)
	internalScanNow := reverseTunnelEligible
	if internalScanNow {
		shared.RecentInternalScanSeen[scopedPID] = now
	}

	localTransport, localCount, localDistinctPorts := LocalTransportActivity(c.Conns)
	loopbackProxyFanout := controlConn != nil &&
		!hasListener &&
		localTransport &&
		localCount >= 3 &&
		localDistinctPorts >= 3
	localTransportForwarding := localTransport && (hasListener || activeClients > 0 || loopbackProxyFanout)
	if localTransportForwarding {
		shared.LocalTransportLast[scopedPID] = now
	}
	if loopbackProxyFanout {
		reasons = append(reasons, fmt.Sprintf("Control channel plus loopback fanout (%d flows, %d target ports)", localCount, localDistinctPorts))
	}
	localServiceProxyLikely := IsLikelyLocalServiceProxy(controlConn, ports, c.Conns)
	if localServiceProxyLikely {
	}
	forwardTunnelLikely := IsLikelyForwardTunnel(hasListener, loopbackOnly, controlConn, ports, outTotal, len(distinctTargets), activeClients, inboundRecent) && !localServiceProxyLikely
	if forwardTunnelLikely {
	}

	if controlConn != nil && !hasListener {
		controlKey := ConnKeyFromConn(scopedPID, *controlConn)
		proxyOutTotal, _, _ := OutboundTargetsExcluding(c.Conns, ports, &controlKey)
		if proxyOutTotal > 0 && reverseTunnelEligible {
			reverseProxyNow = true
		}
	}

	if !reverseProxyNow && !hasListener && outInternal > 0 && reverseTunnelEligible {
		reverseProxyNow = true
	}
	if reverseProxyNow && benignClient && !internalLateral && outExternal > 0 {
		reverseProxyNow = false
	}
	singleControlNoProxy := IsLikelySingleControlNoProxy(controlConn, hasListener, outTotal, outInternal, internalTargets, localTransportForwarding, inboundBurst)
	if singleControlNoProxy {
		reverseProxyNow = false
	}

	if reverseProxyNow {
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
	beaconConfirmed, beaconInterval, beaconJitter, beaconHits := BeaconPatternConfirmed(scopedPID, now)

	// Cross-PID beacon recognition: if in-memory tracking didn't confirm,
	// check if the model knows this process identity as a beacon.
	if !beaconConfirmed {
		if modelKnown, modelInterval, modelJitter := BeaconFromModel(behaviorKey); modelKnown {
			beaconConfirmed = true
			beaconInterval = modelInterval
			beaconJitter = modelJitter
			beaconHits = 3 // minimum for confirmation
			reasons = append(reasons, fmt.Sprintf("Known beacon from model: %s interval, %.0f%% jitter", beaconInterval, modelJitter*100))
		}
	}
	// Persist confirmed beacon interval on the candidate so the model can
	// store it even when the role is blocked (warmup, trafficVerified).
	if beaconConfirmed && beaconInterval > 0 {
		c.BeaconIntervalMs = int(beaconInterval.Milliseconds())
		c.BeaconJitter = beaconJitter
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
	}

	outboundForVerification := OutboundConnsForVerification(c.Conns, ports)
	externalPrefixes := OutboundExternalPrefixes(outboundForVerification)
	// Traffic verification is informational only — it must NEVER suppress
	// detection. A C2 channel connecting to the same server will always
	// have "verified" traffic because the baseline learns its destinations.
	// Compute for signal emission only — these must NEVER gate detection.
	if TrafficVerifiedByDest(outboundForVerification, outExternal, internalLateral, behavior, externalPrefixes) {
	}
	if LikelyBenignControlPattern(controlConn, behavior, externalPrefixes, outExternal, outInternal, len(distinctTargets), controlSecs) {
	}

	// These variables are always false — traffic verification and benign control
	// patterns must never suppress detection. Signals are emitted above for stats.
	trafficVerified := false
	benignControlPattern := false
	_ = trafficVerified
	_ = benignControlPattern

	suspTunEligible := controlConn != nil && (localTransportRecent || internalScanRecent || inboundBurst > 0 || forwardTunnelLikely)
	if suspTunEligible {
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
		}
		beaconRecent = false
		beaconConfirmed = false
	} else if beaconRecent {
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
	}
	if benignBeaconClient {
	}
	if beaconConfirmed {
	}
	// Traffic verification and benign status must NEVER block beacon detection.
	// A beacon connecting to the same C2 server will always have "verified" traffic.
	// Only block beacons when they are stale (no active connections) and unconfirmed.
	beaconBlockedByVerified := false       // removed — trafficVerified must not suppress beacons
	beaconBlockedByBenignExternal := false // removed — benignClient is always false
	beaconBlockedByStaleBenign := false    // removed — benignClient is always false
	beaconBlockedByStaleUnconfirmed := beaconEligible && !beaconConfirmed && !outboundRecent && outTotal == 0
	if beaconBlockedByVerified {
	}
	if beaconBlockedByBenignExternal {
	}
	if beaconBlockedByStaleBenign {
	}
	if beaconBlockedByStaleUnconfirmed {
	}
	beaconBlocked := beaconBlockedByVerified ||
		beaconBlockedByBenignExternal ||
		beaconBlockedByStaleBenign ||
		beaconBlockedByStaleUnconfirmed

	// ---------------- Reverse control detection ----------------
	reverseControl := false
	reverseControlSuppressed := false
	reverseControlShape := IsReverseControlShape(controlConn, hasListener, outTotal, len(distinctTargets), controlSecs)
	if reverseControlShape {
		reverseControlSuppressed = SuppressReverseControlForBenignChannel(controlConn, p, internalLateral, outInternal, benignControlPattern)
		if reverseControlSuppressed {
			reverseControl = false
		} else {
			reverseControl = true
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
		}
		if reverseControl && !ShouldPromoteReverseControl(
			controlConn,
			outInternal,
			strongEvidence,
			benignControlPattern,
			controlSecs,
			pendingControlRepeated,
			c.DelegatedStrong,
		) {
			reverseControl = false
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
				c.Role = "control-channel"
				c.ActiveProxying = true
				shared.TunnelingSeen[scopedPID] = now
				shared.TunnelingSeen[c.Proc.Pid] = now
				c.ControlChannel = controlConn
				c.ControlDurationSeconds = controlSecs
				c.Reasons = []string{
					"Persistent reverse control channel with local transport activity",
				}
				c.Signals = signals
				c.Confidence = ConfidenceFor(c.Role, c.Score, c.ActiveProxying)
				return
			}
		}
	}
	if singleControlNoProxy && benignClient {
		reverseControl = false
		reverseControlSuppressed = true
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
	}
	if reverseControl {
	}

	// ---------------- Heuristics ----------------

	if hasListener {
		scoreVal += 5
		reasons = append(reasons, "Process has TCP listener(s)")
		if loopbackOnly {
			reasons = append(reasons, "Listener is loopback-only")
		}
		if anyWildcard {
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
	}

	if internalLateral {
		scoreVal += 25
	}
	if smbPipeLikely {
		scoreVal += 20
	}
	if smbTargets >= 2 {
		scoreVal += 10
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
	c.Role = DeriveRole(hasListener, activeClients, outTotal, reverseTunnelEligible)

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

	// Compute corroboration once — used by ALL promotion paths (beacon, session, SYN cycle, memory).
	// NOTE: the actual emitted signal name is "outbound-known-vendor" (see
	// behavior/outbound.go). Earlier this checked "known-vendor" which never
	// fired, making promoIsKnownVendor permanently false — every process was
	// treated as "unknown vendor", causing rank.go to over-promote known
	// signed binaries (OneDrive sync, etc.) via the unknown-vendor branches
	// at sessionCorroboration=3 and beaconCorroboration+=2 below.
	promoIsKnownVendor := false
	for _, sig := range signals {
		if sig == "outbound-known-vendor" {
			promoIsKnownVendor = true
			break
		}
	}
	sessionCorroboration := 0
	if promoIsKnownVendor && outInternal == 0 {
		for _, sig := range signals {
			switch sig {
			case "internal-lateral", "internal-fanout", "lateral-pivot-shape",
				"raw-socket", "delegated-egress-strong",
				"cmdline-proxy-flags", "proxy-library-loaded",
				"asn-org-mismatch", "c2-non-standard-port",
				"lateral-host-sweep", "lateral-wide-recon":
				sessionCorroboration++
			}
		}
	} else if promoIsKnownVendor && outInternal > 0 {
		sessionCorroboration = 3
	} else {
		sessionCorroboration = 3 // unknown vendor = always promote
	}

	// Beacon corroboration — same logic, shared across beacon/SYN-cycle paths.
	beaconCorroboration := 0
	for _, sig := range signals {
		switch sig {
		// Beacon corroboration: BEHAVIORAL signals only.
		// suspicious-exe-path is included because user-writable staging
		// directories (Downloads, Temp, Desktop) are strong indicators —
		// legitimate software does not run from these locations.
		case "asn-org-mismatch", "c2-non-standard-port":
			beaconCorroboration++
		case "raw-socket", "cmdline-proxy-flags", "proxy-library-loaded", "benign-override":
			beaconCorroboration++
		case "suspicious-exe-path":
			beaconCorroboration++
		}
	}
	// Listener processes are servers, not beacons — reduce corroboration.
	if hasListener && activeClients > 0 {
		beaconCorroboration -= 2
	}
	if !promoIsKnownVendor {
		beaconCorroboration += 2 // unknown process = inherently suspicious
	}

	// Detect SSH/tunnel multiplexing: a listener receiving many inbound
	// connections from a single internal source on distinct ports. Normal
	// SSH = 1-2 connections. SOCKS/SSH tunneling produces 5+ connections
	// from the same source. Runs BEFORE the SuspicionProxy memory check
	// below so it can claim the control-pivot role even when the process
	// was previously marked as a proxy.
	if (c.Role == "listen" || c.Role == "listener") && hasListener && activeClients >= 5 {
		inboundSources := make(map[string]int)
		for _, cn := range c.Conns {
			if cn.RemoteAddress == "" || shared.IsLoopbackIP(cn.RemoteAddress) {
				continue
			}
			if !shared.IsInternalIP(cn.RemoteAddress) {
				continue
			}
			if _, isListener := ports[cn.LocalPort]; isListener {
				inboundSources[cn.RemoteAddress]++
			}
		}
		for _, count := range inboundSources {
			if count >= 5 {
				c.Role = "control-pivot"
				c.ActiveProxying = true
				shared.TunnelingSeen[scopedPID] = now
				shared.TunnelingSeen[c.Proc.Pid] = now
				c.Reasons = append(c.Reasons, fmt.Sprintf("Listener with multiplexed inbound from single internal source (%d connections) — tunnel multiplexing pattern", count))
				if c.Score < 62 {
					c.Score = 62
				}
				hist.LastSuspicious = now
				hist.SuspicionKind = shared.SuspicionProxy
				if hist.StickyScore < c.Score {
					hist.StickyScore = c.Score
				}
				break
			}
		}
	}

	if reverseProxyNow || (suspiciousRecent && hist.SuspicionKind == shared.SuspicionProxy && !singleControlNoProxy) {
		// Don't downgrade control-pivot (more specific) to control-channel.
		if c.Role != "control-pivot" {
			c.Role = "control-channel"
		}
		c.ActiveProxying = true
		if hist.StickyScore > c.Score {
			c.Score = hist.StickyScore
		}
		if reverseProxyNow {
			c.Reasons = append(c.Reasons, "Persistent control channel with proxied outbound activity")
		}
	} else if reverseControl || (suspiciousRecent && hist.SuspicionKind == shared.SuspicionControl && controlConn != nil && !reverseControlSuppressed) {
		if sessionCorroboration < 3 {
			// Skip session promotion — likely legitimate vendor process.
		} else {
			c.Role = "control-channel"
			c.ActiveProxying = false
			c.Reasons = []string{
				"Persistent reverse control channel detected",
			}

			if reverseControl {
				base := ControlStickyScore(controlSecs)
				if hist.StickyScore < base {
					hist.StickyScore = base
				}
				hist.LastSuspicious = now
				hist.SuspicionKind = shared.SuspicionControl
			}
			if hist.StickyScore > c.Score {
				c.Score = hist.StickyScore
			}
		}
	}

	promoteSuspTun := suspTunEligible && (reverseProxyNow || reverseControl)
	if promoteSuspTun && !outboundRecent && !activeProxying {
		promoteSuspTun = false
	}

	if promoteSuspTun {
		c.Role = "control-channel"
		c.ActiveProxying = forwardActiveNow || reverseProxyNow || localTransportForwarding

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
	} else if reverseControl && sessionCorroboration >= 3 {
		c.Role = "control-channel"
		c.ActiveProxying = false
		c.Reasons = []string{
			"Persistent control session without proxying evidence",
		}
		base := ControlStickyScore(controlSecs)
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
		ShouldPromoteControlSession(
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
		if reverseControlSuppressed {
		}
		c.Reasons = append(c.Reasons, "Persistent reverse control channel detected")
		if reverseControlSuppressed {
			c.Reasons = append(c.Reasons, "Control-session promotion overrode benign-channel suppression due corroborating evidence")
		}
		base := ControlSessionBaseScore(controlSessionSecs, outInternal, len(distinctTargets), c.DelegatedStrong, internalLateral)
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
		c.Role = "control-channel"
		c.ActiveProxying = true
		c.ActiveProxying = activeClients > 0 || localTransportRecent
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
		c.Reasons = append(c.Reasons, "Delegated control-channel shape is consistent with a reverse session")
		if c.Score < 45 {
			c.Score = 45
		}
	}

	// Promote listener+egress control shapes to tunnel even when strict forward-tunnel
	// matching cannot be proven in a single refresh.
	// Require non-loopback relay evidence — loopback clients on loopback listeners
	// are local IPC (Electron apps), not tunnel traffic.
	hasNonLoopbackRelay := outInternal > 0 || internalLateral || localTransportForwarding || c.DelegatedStrong
	if c.Role == "listen" &&
		hasListener &&
		outTotal > 0 &&
		hasNonLoopbackRelay {
		c.Role = "control-channel"
		c.ActiveProxying = activeClients > 0 || localTransportRecent || internalScanRecent
		shared.TunnelingSeen[scopedPID] = now
		shared.TunnelingSeen[c.Proc.Pid] = now
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

	// Promote processes with repeated pending control attempts to internal targets.
	// Requires repeated connection attempts — a single pending connection from a
	// user-writable path alone is not sufficient (too many false positives from
	// admin tools and dev software).
	if c.Role == "outbound" &&
		pendingControlConn != nil &&
		pendingControlRepeated &&
		!hasListener &&
		outTotal <= 3 &&
		len(distinctTargets) <= 2 &&
		(shared.IsInternalIP(pendingControlConn.RemoteAddress) || pendingControlRepeated) {
		c.Role = "control-channel"
		c.ActiveProxying = false
		c.Reasons = append(c.Reasons, "Pending control connection to internal target")
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
	// Skip promotion for known-vendor processes with verified traffic — these
	// are typically benign reconnection attempts to unreachable internal resources.
	// SYN_SENT cycling = beacon behavior. No connection count or pending conn gate.
	// Injected processes (explorer.exe, svchost.exe) have legitimate traffic mixed
	// with C2 traffic. Repeated SYN cycling to a target is a beacon pattern.
	// Threshold is >= 2 (not 3) because SYN cycling to a dead target is strong
	// evidence by itself — unlike periodic successful callbacks, failing to
	// connect repeatedly is not normal application behavior.
	if synCycleBeacon && !hasListener && beaconCorroboration >= 2 {
		if c.Role == "outbound" || c.Role == "listen" {
			c.Role = "control-channel"
			c.ControlSubtype = "beacon"
		}
		c.ActiveProxying = false
		if pendingControlConn != nil {
			c.Reasons = append(c.Reasons, fmt.Sprintf("SYN_SENT cycling detected (%d cycles, ~%.0fs interval) to %s:%d",
				synCycles, synAvgInterval, pendingControlConn.RemoteAddress, pendingControlConn.RemotePort))
			if c.ControlChannel == nil {
				c.ControlChannel = pendingControlConn
				c.ControlDurationSeconds = pendingControlSecs
			}
		} else {
			c.Reasons = append(c.Reasons, fmt.Sprintf("SYN_SENT cycling detected (%d cycles, ~%.0fs interval)",
				synCycles, synAvgInterval))
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
		if pureCallbackShape && !promoIsKnownVendor && shared.ShortLivedBurstHits[scopedPID] >= 3 {
			// Offline-C2 disambiguation (plan Track 5): if the recurring
			// target resolves to a CDN / major vendor ASN or a vendor
			// domain, this is almost certainly a benign service that's
			// temporarily offline — not a C2 server. Skip the C2 promotion
			// and emit a shadow signal instead so /fp-report captures the
			// decision for post-hoc review.
			offlineBenign := false
			if pch := shared.PendingControlByPID[scopedPID]; pch != nil {
				if shared.IsLikelyBenignOfflineTarget(pch.Target) {
					offlineBenign = true
				}
			}
			if !offlineBenign {
				if sch := shared.SYNCycleByPID[scopedPID]; sch != nil {
					if shared.IsLikelyBenignOfflineTarget(sch.Target) {
						offlineBenign = true
					}
				}
			}
			if offlineBenign {
				c.Signals = append(c.Signals, "benign-offline-service-shape")
			} else {
				// Unknown process with 3+ recurring short-lived callback bursts
				// but no persistent control channel — consistent with C2 implant
				// when the C2 server is down or connections drop quickly.
				c.Role = "control-channel"
				c.ControlSubtype = "beacon"
				c.ActiveProxying = false
				c.Reasons = append(c.Reasons, "Unknown process with recurring failed callback pattern (C2 may be offline)")
				if c.Score < 48 {
					c.Score = 48
				}
				hist.LastSuspicious = now
				hist.SuspicionKind = shared.SuspicionControl
				if hist.StickyScore < c.Score {
					hist.StickyScore = c.Score
				}
			}
		} else if pureCallbackShape {
		} else if holdBenignReconnectingPromotion {
		} else {
			c.Role = "control-channel"
			c.ActiveProxying = false
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

	sessionCue := SessionCueForBeaconPromotion(
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

	if CanPromoteBeaconRole(
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
		// Provisional beacon: process with callback-like connection pattern.
		// Allow both internal AND external C2 targets — beacons can call back
		// to internal C2 servers (e.g., HTTP beacon to 172.16.1.130:80).
		provisionalBeacon := !beaconBlocked &&
			beaconEligible &&
			!hasListener &&
			!localTransportRecent &&
			!internalScanRecent &&
			outLongLived == 0 &&
			outTotal > 0 &&
			len(distinctTargets) <= 2 &&
			(burstRecent || shared.ShortLivedBurstHits[scopedPID] >= 1)
		if beaconBlocked {
		}
		// Beacon promotion requires cadence PLUS 3+ corroborating signals.
		// Cadence alone is not enough — legitimate apps have periodic callbacks.
		// Each corroboration adds evidence that this is real C2, not an update check.
		// Uses beaconCorroboration computed in outer scope.
		if !beaconBlocked && beaconEligible && (beaconConfirmed || beaconRecent || provisionalBeacon) && beaconCorroboration >= 3 {
			c.Role = "control-channel"
			c.ActiveProxying = false
			if provisionalBeacon && !beaconConfirmed && !beaconRecent {
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

	// Detect tunnel shape: external C2 + internal connections = tunnel proxy.
	// C2 implants route SOCKS traffic through the C2 channel. The internal
	// connections may be transient (CLOSE_WAIT between scan bursts), so use
	// a low threshold. Port diversity on internal targets is a strong signal.
	isTunnelShape := outExternal > 0 && outInternal >= 1 && len(distinctTargetPorts) >= 2
	// Also match with higher internal count regardless of port diversity.
	if outExternal > 0 && outInternal >= 3 {
		isTunnelShape = true
	}
	// Traditional tunnel: listener + external + internal.
	if (c.Role == "tunnel" || c.Role == "control-channel" || forwardTunnelLikely || reverseProxyNow) &&
		hasListener && outExternal > 0 {
		isTunnelShape = true
	}

	// SMB pipe-like behavior should not remain plain outbound/listener.
	// But don't override tunnel/control-channel — SOCKS tunnels have internal
	// connections that look like SMB pipe but are actually tunnel traffic.
	smbBaseRole := c.Role == "outbound" || c.Role == "listen"
	if smbBaseRole && smbPipeLikely && !reverseProxyNow && !forwardTunnelLikely && !isTunnelShape {
		promoteTunnel := smbTargets >= 2 || internalLateral || outInternal > 0 || activeClients > 0 || (hasListener && activeClients > 0)
		if promoteTunnel {
			c.Role = "smb-pipe"
			c.ActiveProxying = activeClients > 0 || localTransportRecent || internalScanRecent
			shared.TunnelingSeen[scopedPID] = now
			shared.TunnelingSeen[c.Proc.Pid] = now
			c.Reasons = append(c.Reasons, "SMB pipe-like relay/lateral channel behavior detected")
			if c.Score < 62 {
				c.Score = 62
			}
		} else {
			c.Role = "smb-pipe"
			c.ActiveProxying = false
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

	// Re-evaluate tunnel shape after role changes above.
	isTunnelShape = (outExternal > 0 && outInternal >= 1 && len(distinctTargetPorts) >= 2) ||
		(outExternal > 0 && outInternal >= 3) ||
		((c.Role == "tunnel" || c.Role == "control-channel" || forwardTunnelLikely || reverseProxyNow) &&
			hasListener && outExternal > 0)
	// If tunnel shape detected, set ActiveProxying (shows as "tunneling" state).
	// Normally tunneling is a STATE, not a ROLE — the role stays as whatever
	// it was detected as. EXCEPTION: when topology shows an UNAMBIGUOUS tunnel
	// pattern (significant internal relay through external C2) but the role
	// is still benign (model committed "outbound" early, or rule-engine
	// promotion didn't fire because corroboration was insufficient), promote
	// to control-channel so the user sees "tunneling" in the state column
	// (CandidateState requires a suspicious role family to surface tunneling).
	if isTunnelShape {
		c.ActiveProxying = true
		shared.TunnelingSeen[scopedPID] = now
		shared.TunnelingSeen[c.Proc.Pid] = now
		if c.Score < 75 {
			c.Score = 75
		}
		// Unambiguous tunnel topology: external C2 + heavy internal relay
		// (5+ outbound internal connections). Promote benign role so the
		// tunneling state surfaces. Conservative threshold avoids FP on
		// browsers/IDEs (which use external connections, not internal relay).
		if !IsMaliciousRole(c.Role) && outExternal >= 1 && outInternal >= 5 {
			c.Role = "control-channel"
			c.Reasons = append(c.Reasons, fmt.Sprintf("Tunnel shape: %d internal relay connection(s) through %d external channel(s)", outInternal, outExternal))
			hist.LastSuspicious = now
			hist.SuspicionKind = shared.SuspicionProxy
			if hist.StickyScore < c.Score {
				hist.StickyScore = c.Score
			}
		}
	}
	if smbPipeLikely && !isTunnelShape {
		c.Role = "smb-pipe"
	}

	// Keep recently suspicious labels from collapsing to plain outbound immediately
	// when callbacks go quiet between refreshes.
	// Clear suspicion memory when corroboration is insufficient.
	// Prevents FP loops where an early false detection persists via memory.
	if suspiciousRecent && sessionCorroboration < 3 && beaconCorroboration < 3 {
		hist.LastSuspicious = time.Time{}
		hist.SuspicionKind = 0
		suspiciousRecent = false
	}
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
		} else if holdBenignExternalMemory {
		} else if sessionCorroboration >= 3 {
			// Suspicion memory re-promotion also requires corroboration.
			switch hist.SuspicionKind {
			case shared.SuspicionProxy:
				c.Role = "control-channel"
				c.ActiveProxying = true
				if c.Score < 48 {
					c.Score = 48
				}
			case shared.SuspicionBeacon:
				c.Role = "control-channel"
				if c.Score < 46 {
					c.Score = 46
				}
			case shared.SuspicionControl:
				c.Role = "control-channel"
				if c.Score < 46 {
					c.Score = 46
				}
			}
		}
	}

	observedConnAgeSecs := MaxEstablishedConnectionAgeSeconds(scopedPID, c.Conns, now)
	// For listener-only processes (e.g., System on port 445), connection ages
	// are 0 because there are no outbound connections to measure. Fall back to
	// the time since the process first showed suspicious signals.
	if observedConnAgeSecs == 0 && !hist.LastSuspicious.IsZero() {
		observedConnAgeSecs = int(now.Sub(hist.LastSuspicious).Seconds())
	}
	beaconAgeSecs := BeaconObservationAgeSeconds(scopedPID, now)
	preWarmupRole := c.Role
	if ApplyRoleWarmupGates(
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
			c.Reasons = append(c.Reasons, "Sustained control-session evidence exceeded strong threshold")
		} else if suppressStrongExternalSession {
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
			c.Reasons = append(c.Reasons, fmt.Sprintf("Role-aware strong state promotion (%s, score=%d, corroboration=%d)", c.Role, c.Score, corroboration))
		}
	}
	ApplyBehaviorAwareAdjustments(
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
	)
	if delegatedReason != "" {
		c.Reasons = append(c.Reasons, delegatedReason)
	}
	if trafficVerified && !strongEvidence {
		c.Reasons = append(c.Reasons, "Traffic matches verified destinations (de-emphasized)")
	}
	ApplyASNRankAssist(c, p)

	// FP reduction signals — emitted for the ML model to learn from.
	// No hardcoded score changes.
	if c.OutExternal == 1 && c.OutInternal == 0 && c.InboundTotal == 0 &&
		outLongLived == 1 && outShortLived == 0 {
	}
	if p.IOReadBytes > 0 && p.IOWriteBytes > 0 {
		readRatio := float64(p.IOReadBytes) / float64(p.IOReadBytes+p.IOWriteBytes)
		if readRatio > 0.95 && p.IOReadBytes > 1024*1024 {
		}
	}

	// CDN/ASN signals are emitted by ApplyASNRankAssist — no hardcoded
	// score changes here. The ML model learns from these signals.
	ApplySignalFusionAdjustments(
		c,
		signals,
		controlConn,
		pendingControlRepeated,
		benignClient,
		trafficVerified,
		benignControlPattern,
	)
	UpdateProcessBehaviorProfile(
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
		prevMalicious := IsMaliciousRole(hist.LastRole)
		newMalicious := IsMaliciousRole(c.Role)

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
				if !IsRoleUpgrade(hist.LastRole, c.Role) {
					c.Role = hist.LastRole
				}
			}
		}
		// Malicious→malicious transitions (session→beacon, beacon→tunnel, etc.)
		// are always allowed immediately — the classification is refining, not demoting.
	}
	// Pivot-shape escalation — a process that is actively relaying traffic
	// AND reaching internal (RFC1918) targets while accepting inbound
	// connections is behaving as a pivot by definition, not just a
	// control channel. Catches two specific cases reported from the live
	// lab on 172.16.1.2:
	//
	//   - Per-session sshd children handling SSH -D port-forwarding:
	//     ActiveProxying=true + pivot-non-loopback-internal + inbound from
	//     the parent listener. Classic SSH SOCKS tunnel pivot.
	//   - system pid 4 handling SMB named-pipe relays: ActiveProxying=true
	//     + pivot-non-loopback-internal + inbound pipe requests. Same
	//     pivot shape, different transport.
	//
	// Gate: only promotes from control-channel / listen / listener so we
	// never touch outbound or session roles. Requires all three preconds
	// so system services idly chatting to DCs (which have pivot-non-
	// loopback-internal on their own) don't get false-promoted without
	// ActiveProxying actually firing.
	{
		hasPivotInternal := false
		for _, sig := range c.Signals {
			if sig == "pivot-non-loopback-internal" {
				hasPivotInternal = true
				break
			}
		}
		// Record the pivot-signal sighting for temporal bridging. Scan
		// cycles don't always line up: a sshd child forwarding SOCKS
		// traffic flips out_internal>0 (fires signal) and ap=true on
		// different polling ticks because topology evidence and signal
		// evaluation look at different sub-windows.
		if c.Proc != nil && hasPivotInternal {
			shared.PivotInternalSeen[c.Proc.Pid] = now
		}

		pivotRecent := hasPivotInternal
		if !pivotRecent && c.Proc != nil {
			if t, ok := shared.PivotInternalSeen[c.Proc.Pid]; ok && now.Sub(t) < 60*time.Second {
				pivotRecent = true
			}
		}
		tunnelingRecent := c.ActiveProxying
		if !tunnelingRecent && c.Proc != nil {
			if t, ok := shared.TunnelingSeen[c.Proc.Pid]; ok && now.Sub(t) < 60*time.Second {
				tunnelingRecent = true
			}
		}
		// sshd per-session children handling SSH -D port-forwarding come in
		// as role=outbound (no listener on the child, low outTotal below the
		// reverseTunnelEligible + out>=3 threshold in DeriveRole). Parent
		// sshd owns the :22 listener + the operator's inbound connection.
		// Include outbound in the escalation gate so pivot forwarders with
		// no direct listener but active internal-only relay still surface
		// as control-pivot. The (tunnelingRecent && pivotRecent) combination
		// with OutExternal == 0 (required by pivot-non-loopback-internal)
		// and ActiveProxying (set only on real relay topology by rank.go)
		// is narrow enough that benign outbound processes won't false-promote:
		// browsers/update clients/telemetry have OutExternal > 0 and so
		// never fire the pivot signal at all.
		if (c.Role == "control-channel" || c.Role == "listen" || c.Role == "listener" || c.Role == "outbound") &&
			tunnelingRecent &&
			pivotRecent {
			c.Role = "control-pivot"
			c.Reasons = append(c.Reasons, "Pivot shape: active relay with internal-only forwarding")
		}
	}

	// Model intelligence: let the accumulated model override the signal-based role
	// when it has strong evidence from training labels, operator feedback,
	// experience history, or calibration verdicts.
	{
		// Save rank.go's suggestion before model override — experience should
		// learn from signal analysis, not from the model's own suppressions.
		c.SuggestedRole = c.Role

		decision := model.DecideRole(behaviorKey, c.Role, scoreVal, c.Proc, outExternal, outInternal, c.InboundTotal, hasListener)
		if decision.Override {
			c.Role = decision.Role
			c.Reasons = append(c.Reasons, decision.Reason)
		}
	}

	// Populate ControlChannel from history when the role is suspicious but
	// no connection is currently visible (e.g., between SYN_SENT cycles).
	// This prevents the ANALYSIS box from flickering in the inspector.
	if IsMaliciousRole(c.Role) && c.ControlChannel == nil {
		if pch := shared.PendingControlByPID[scopedPID]; pch != nil && now.Sub(pch.LastSeen) < shared.PendingControlGapReset {
			if idx := strings.LastIndex(pch.Target, ":"); idx > 0 {
				port := 0
				fmt.Sscanf(pch.Target[idx+1:], "%d", &port)
				c.ControlChannel = &shared.ConnectionInfo{
					RemoteAddress: pch.Target[:idx],
					RemotePort:    port,
					State:         "SYN_SENT",
				}
				c.ControlDurationSeconds = int(now.Sub(pch.FirstSeen).Seconds())
			}
		} else if sch := shared.SYNCycleByPID[scopedPID]; sch != nil && now.Sub(sch.LastSeen) < shared.PendingControlGapReset {
			if idx := strings.LastIndex(sch.Target, ":"); idx > 0 {
				port := 0
				fmt.Sscanf(sch.Target[idx+1:], "%d", &port)
				c.ControlChannel = &shared.ConnectionInfo{
					RemoteAddress: sch.Target[:idx],
					RemotePort:    port,
					State:         "SYN_SENT",
				}
				c.ControlDurationSeconds = int(now.Sub(sch.FirstSeen).Seconds())
			}
		}
	}

	if hist != nil {
		// Track LastRole for the malicious-role demotion cooldown that
		// runs later in the classifier — but DO NOT touch
		// RoleStableStreak here. Streak updates belong at the final
		// role-commit point (classifier.go + agent/server.go) because
		// the role can still change after rank.go via ML prediction or
		// signal override.
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

	// ActiveProxying = tunneling state. Preserve earlier strong-indicator
	// decisions (multiplexed inbound, isTunnelShape, reverseControl etc. that
	// already set ActiveProxying = true based on direct topology evidence).
	// Otherwise compute based on relay topology + suspicious role.
	//
	// CRITICAL: don't blanket-override ActiveProxying to false here. Earlier
	// passes set it based on strong topology signals (e.g. listener with
	// multiplexed SSH inbound, external+internal tunnel shape, persistent
	// reverse control) — those decisions should stand even when this final
	// outbound-relay heuristic doesn't match.
	if !c.ActiveProxying {
		// Outbound/benign processes with many connections (Chrome, IDEs) are
		// just busy applications — gate on suspicious role to avoid FPs.
		isSuspicious := IsMaliciousRole(c.Role)
		hasActiveRelay := false
		if isSuspicious {
			if outTotal >= 4 && len(distinctTargetPorts) >= 2 {
				hasActiveRelay = true
			} else if outInternal >= 2 && len(distinctTargetPorts) >= 2 {
				hasActiveRelay = true
			} else if outTotal >= 3 && len(distinctTargets) >= 3 {
				hasActiveRelay = true
			} else if outInternal >= 3 && len(distinctTargets) >= 2 {
				// Same port to multiple hosts = credential spray / service scan through proxy.
				hasActiveRelay = true
			}
		}
		if hasActiveRelay {
			c.ActiveProxying = true
		}
	}

	// Emit role-specific behavior signals AFTER all candidate fields are populated.
	// This ensures signals can check ControlChannel, BeaconIntervalMs, OutTotal, etc.
	{
		bctx := bhv.SignalContext{
			ScopedPID:   scopedPID,
			BehaviorKey: behaviorKey,
			HostScope:   HistoryHostScope(c),
		}
		bcs := bhv.PrepareCommonState(c, bctx)
		bhv.EmitBeaconSignals(c, addSignal, bctx, bcs)
		bhv.EmitSessionSignals(c, addSignal, bctx, bcs)
		bhv.EmitPivotSignals(c, addSignal, bctx, bcs)
		bhv.EmitOutboundSignals(c, addSignal, bctx, bcs)
		bhv.EmitListenerSignals(c, addSignal, bctx, bcs)
		bhv.EmitDistinguishingSignals(c, addSignal, bctx, bcs)
	}

	c.Signals = signals
	c.Confidence = ConfidenceFor(c.Role, c.Score, c.ActiveProxying)

	PurgeHistory(now)
}

/* ---------------- helpers ---------------- */
