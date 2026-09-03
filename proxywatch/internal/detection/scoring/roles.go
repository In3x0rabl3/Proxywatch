package scoring

import (
	"fmt"
	"proxywatch/internal/shared"
)

func DeriveRole(hasListener bool, clients int, out int, reverseTunnelEligible bool) string {
	switch {
	case hasListener:
		return "listen"
	case out >= 3 && reverseTunnelEligible:
		return "tunnel"
	default:
		return "outbound"
	}
}

// IsMaliciousRole returns true for roles that indicate active threat behavior.
func IsMaliciousRole(role string) bool {
	switch role {
	case "beacon", "pivot", "tunnel", "smb-pipe", "session":
		return true
	}
	return false
}

// IsRoleUpgrade returns true if changing from oldRole to newRole is a
// severity upgrade (more suspicious).
func IsRoleUpgrade(oldRole, newRole string) bool {
	order := map[string]int{
		"outbound": 0,
		"listener": 1,
		"listen":   1,
		"beacon":   3,
		"session":  3,
		"pivot":    4,
		"tunnel":   4,
		"smb-pipe": 4,
	}
	return order[newRole] > order[oldRole]
}

func ConfidenceFor(role string, score int, active bool) int {
	base := 10
	switch role {
	case "tunnel":
		base = 85
	case "smb-pipe":
		base = 78
		base = 75
	case "beacon":
		base = 68
	case "listen":
		base = 55
	case "outbound":
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

func ControlStickyScore(controlSecs int) int {
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

func WarmupFallbackRole(hasListener bool, clients int, out int) string {
	if hasListener {
		return "listen"
	}
	return "outbound"
}

func ApplyRoleWarmupGates(
	c *shared.Candidate,
	hasListener bool,
	activeClients int,
	outTotal int,
	controlSecs int,
	pendingControlSecs int,
	observedConnAgeSecs int,
	smbMaxAgeSecs int,
	beaconAgeSecs int,
	suspiciousPath bool,
) bool {
	if c == nil {
		return false
	}
	// Suspicious paths (Downloads, Temp, Desktop) get a shorter warmup
	// but are NOT exempted entirely — evidence still needs time to accumulate.
	warmupReduction := 0
	if suspiciousPath {
		warmupReduction = 30
	}

	sessionAge := max(controlSecs, pendingControlSecs)
	tunnelAge := max(observedConnAgeSecs, sessionAge)
	smbAge := max(smbMaxAgeSecs, tunnelAge)
	fallbackRole := WarmupFallbackRole(hasListener, activeClients, outTotal)
	blocked := false

	switch c.Role {
	case "smb-pipe":
		minSecs := max(30, int(shared.SMBPipeMinLabelDuration.Seconds())-warmupReduction)
		if smbAge < minSecs {
			c.Role = fallbackRole
			c.Reasons = append(c.Reasons, fmt.Sprintf("SMB-pipe candidate warming up (%ds/%ds)", smbAge, minSecs))
			blocked = true
		}
	case "tunnel":
		minSecs := max(30, int(shared.TunnelMinLabelDuration.Seconds())-warmupReduction)
		if tunnelAge < minSecs {
			c.Role = fallbackRole
			c.Reasons = append(c.Reasons, fmt.Sprintf("Tunnel candidate warming up (%ds/%ds)", tunnelAge, minSecs))
			blocked = true
		}
	case "beacon":
		minSecs := max(60, int(shared.BeaconMinLabelDuration.Seconds())-warmupReduction)
		// Use the best available age: beacon burst observation, session
		// control duration, or observed connection age. Persistent-connection
		// beacons (keep-alive C2) won't have burst observations, so we must
		// also consider the connection age and control seconds.
		age := max(beaconAgeSecs, max(sessionAge, observedConnAgeSecs))
		if age < minSecs {
			c.Role = fallbackRole
			c.Reasons = append(c.Reasons, fmt.Sprintf("Command candidate warming up (%ds/%ds)", age, minSecs))
			blocked = true
		}
	}

	if blocked {
		if c.Role == "listen" || c.Role == "outbound" {
			c.ActiveProxying = false
		}
		c.StrongEvidence = false
		if c.Role == "outbound" && c.Score > shared.OutboundOnlyExternalCap {
			c.Score = shared.OutboundOnlyExternalCap
		}
		if c.Role == "listen" && c.Score > 50 {
			c.Score = 50
		}
	}
	return blocked
}

func CanPromoteBeaconRole(
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
	// When beacon pattern is confirmed with periodic intervals, always
	// allow promotion regardless of session-like cues.  C2 beacons
	// inherently create beacon-like connections on each callback.
	if beaconConfirmed && !hasListener && !localTransportRecent {
		return true
	}

	switch role {
	case "tunnel":
		// Allow beacon to reclaim session labels when beacon-shaped.
		if beaconRecent && !hasListener && !localTransportRecent && !internalScanRecent {
			return true
		}
		if sessionCue || reverseControl || controlConn != nil || outLongLived > 0 {
			return false
		}
		return false
	case "outbound":
		if beaconRecent && !hasListener {
			return true
		}
		if sessionCue || reverseControl || controlConn != nil || outLongLived > 0 {
			return false
		}
		if hasListener || localTransportRecent || internalScanRecent {
			return false
		}
		return true
	default:
		return false
	}
}

func SessionCueForBeaconPromotion(
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
		case "beacon-attempt-repeated", "beacon-target-stable":
			return true
		}
	}
	return false
}

func ShouldPromoteControlSession(
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

func ShouldPromoteReverseControl(
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
	// External beacon-looking channels that match learned benign patterns
	// still promote if they show persistent duration or corroborating control cues.
	if strongEvidence || pendingControlRepeated || delegatedStrong {
		return true
	}
	return controlSecs >= 45
}

func ControlSessionBaseScore(
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

func IsLikelySingleControlNoProxy(
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

func IsLikelyLocalServiceProxy(
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
		if !IsEstablishedState(cn.State) {
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

func IsReverseControlShape(
	controlConn *shared.ConnectionInfo,
	hasListener bool,
	outTotal int,
	distinctTargets int,
	controlSecs int,
) bool {
	if controlConn == nil || hasListener {
		return false
	}
	// Long-lived connection alone is NOT sufficient — legitimate apps (OneDrive,
	// Edge, Chrome) hold persistent HTTPS connections for hours.
	// Require focused connection profile: few total connections, few targets.
	if controlSecs >= 60 && outTotal <= 3 && distinctTargets <= 2 {
		return true
	}
	if outTotal <= 0 || outTotal > 2 {
		return false
	}
	if distinctTargets <= 0 || distinctTargets > 2 {
		return false
	}
	return controlSecs >= int(shared.ReverseControlMinDuration.Seconds())
}

func SuppressReverseControlForBenignChannel(cn *shared.ConnectionInfo, proc *shared.ProcessInfo, internalLateral bool, outInternal int, benignControlPattern bool) bool {
	// Never suppress reverse control detection — any process can be compromised.
	return false
}

func LikelyBenignControlPattern(
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

func IsLikelyForwardTunnel(
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
