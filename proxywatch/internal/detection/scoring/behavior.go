package scoring

import (
	"math"
	"strings"
	"time"

	"proxywatch/internal/detection/model"
	"proxywatch/internal/shared"
)

func GetOrCreateProcessBehavior(key string, now time.Time) *shared.ProcessBehavior {
	if shared.ProcessBehaviorByKey == nil {
		shared.ProcessBehaviorByKey = make(map[string]*shared.ProcessBehavior)
	}
	behavior := shared.ProcessBehaviorByKey[key]
	if behavior == nil {
		behavior = &shared.ProcessBehavior{
			KnownPrefixes: make(map[string]int),
			LastRoles:     make(map[string]int),
			Generation:    shared.ModelGeneration,
		}
		shared.ProcessBehaviorByKey[key] = behavior
	}
	// Model was reset — re-analyze by resetting observation count.
	if behavior.Generation != shared.ModelGeneration {
		behavior.Observations = 0
		behavior.SuspiciousObservations = 0
		behavior.StrongObservations = 0
		behavior.ActiveObservations = 0
		behavior.Generation = shared.ModelGeneration
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

func ApplyBehaviorAwareAdjustments(
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
	suspiciousPath bool,
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
		c.Reasons = append(c.Reasons, "Process network behavior deviates from learned host baseline")
	}

	if stableBenign && !strongEvidence && !c.StrongEvidence && !c.ActiveProxying {
		c.TrafficVerified = true
		c.Reasons = append(c.Reasons, "Behavior matches learned host baseline for this process identity")
	}

	if stableBenign &&
		c.Role == "control-channel" &&
		controlConn != nil &&
		benignControlPattern &&
		!c.StrongEvidence &&
		!c.ActiveProxying &&
		outInternal == 0 &&
		!internalLateral &&
		distinctTargets <= 2 &&
		c.ControlDurationSeconds < 600 &&
		!c.DelegatedStrong &&
		!suspiciousPath {
		c.Role = "outbound"
		if c.Score > 30 {
			c.Score = 30
		}
		c.Reasons = append(c.Reasons, "Control-channel label suppressed by learned benign baseline")
	}

	// Guardrail against weak one-off session labels on common system clients.
	if benignClient &&
		c.Role == "control-channel" &&
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
		c.Role = "outbound"
		if c.Score > 35 {
			c.Score = 35
		}
		c.Reasons = append(c.Reasons, "Weak external-only control-channel shape downgraded pending stronger corroboration")
	}
}

func UpdateProcessBehaviorProfile(
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
	behavior.AvgOutExternal = Ewma(behavior.AvgOutExternal, float64(outExternal), behavior.Observations)
	behavior.AvgOutInternal = Ewma(behavior.AvgOutInternal, float64(outInternal), behavior.Observations)
	behavior.AvgDistinctTargets = Ewma(behavior.AvgDistinctTargets, float64(distinctTargets), behavior.Observations)
	behavior.AvgControlSeconds = Ewma(behavior.AvgControlSeconds, float64(controlSecs), behavior.Observations)

	suspiciousRole := IsMaliciousRole(c.Role)
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
	shared.TrimStringIntMap(behavior.KnownPrefixes, 128)
	shared.TrimStringIntMap(behavior.LastRoles, 8)
}

func Ewma(current float64, sample float64, observations int) float64 {
	if observations <= 1 || current == 0 {
		return sample
	}
	alpha := 0.15
	return current*(1-alpha) + sample*alpha
}

func ApplyASNRankAssist(c *shared.Candidate, p *shared.ProcessInfo) {
	if c == nil || p == nil {
		return
	}
	if c.OutExternal == 0 {
		return
	}

	// Emit signals only — no score changes, no role demotion.
	// The ML model learns from these signals to handle FP reduction dynamically.
	orgs, pending, _ := shared.ResolveExternalASNOrgs(c.Conns)
	if len(orgs) == 0 {
		if pending > 0 {
		}
		return
	}

	aligned := shared.ASNOrgAlignedWithProcess(p, orgs)
	if aligned {
	} else if strings.TrimSpace(p.Company) != "" {
	}

	for _, org := range orgs {
		if shared.IsCDNOrg(org) {
			break
		}
	}
}

func ApplySignalFusionAdjustments(
	c *shared.Candidate,
	signals []string,
	controlConn *shared.ConnectionInfo,
	pendingControlRepeated bool,
	benignClient bool,
	trafficVerified bool,
	benignControlPattern bool,
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
	if c.Role == "control-channel" &&
		!c.StrongEvidence &&
		!c.ActiveProxying &&
		benignClient &&
		!pendingControlRepeated &&
		c.ControlDurationSeconds < 45 &&
		benignFusion >= 2 &&
		suspiciousFusion <= 1 {
		c.Role = "outbound"
		if c.Score > 34 {
			c.Score = 34
		}
		c.Reasons = append(c.Reasons, "Signal fusion downgraded weak benign-looking control-channel pattern")
		return
	}

	// Promote strong multi-trigger control behavior that still sits in outbound-only.
	if c.Role == "outbound" &&
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
		} else {
			c.Role = "control-channel"
			if c.Score < 50 {
				c.Score = 50
			}
			c.Reasons = append(c.Reasons, "Signal fusion promoted multi-trigger control behavior to control-channel")
		}
	}
}

func BeaconPatternConfirmed(pid int, now time.Time) (confirmed bool, interval time.Duration, jitter float64, hits int) {
	last, ok := shared.ShortLivedBurstLast[pid]
	if !ok || now.Sub(last) > shared.SlowScanWindow {
		return false, 0, 0, 0
	}

	interval = shared.ShortLivedBurstInterval[pid]
	hits = shared.ShortLivedBurstHits[pid]
	intervals := shared.ShortLivedIntervals[pid]

	// Merge SYN cycle intervals when burst-based intervals are insufficient.
	// SYN cycling detects cadence when C2 is unreachable (SYN_SENT appears
	// and disappears periodically) — this is valuable jitter data that was
	// previously ignored.
	if synHist := shared.SYNCycleByPID[pid]; synHist != nil && len(synHist.Intervals) > 0 {
		if len(intervals) < 2 {
			// No burst intervals — use SYN cycle intervals entirely.
			synDurations := make([]time.Duration, len(synHist.Intervals))
			for i, secs := range synHist.Intervals {
				synDurations[i] = time.Duration(secs * float64(time.Second))
			}
			intervals = synDurations
		}
		// Use SYN cycle data to supplement hits if burst hits are low.
		if synHist.Cycles > hits {
			hits = synHist.Cycles
		}
		// Use SYN cycle interval if burst interval is zero.
		if interval == 0 && len(synHist.Intervals) > 0 {
			var sum float64
			for _, s := range synHist.Intervals {
				sum += s
			}
			avg := sum / float64(len(synHist.Intervals))
			interval = time.Duration(avg * float64(time.Second))
		}
	}

	jitter = IntervalCoV(intervals)

	// For highly jittered callbacks we only require broad cadence recurrence.
	if hits < shared.BeaconMinIntervals || interval < shared.BeaconSleepThreshold {
		return false, interval, jitter, hits
	}
	if len(intervals) >= 2 {
		// Adaptive jitter tolerance: longer intervals allow more jitter.
		// Sub-minute beacons: tight (30% CoV) — timing precision expected.
		// Multi-minute beacons: moderate (50% CoV) — normal C2 jitter.
		// Hour-scale beacons: loose (75% CoV) — deliberate jitter tradecraft.
		var maxCoV float64
		intervalSecs := interval.Seconds()
		if intervalSecs >= 3600 { // 1 hour+
			maxCoV = 0.75
		} else if intervalSecs >= 600 { // 10 min+
			maxCoV = 0.60
		} else if intervalSecs >= 120 { // 2 min+
			maxCoV = 0.50
		} else {
			maxCoV = 0.30
		}
		if jitter > maxCoV {
			return false, interval, jitter, hits
		}
	}
	return true, interval, jitter, hits
}

func IntervalCoV(intervals []time.Duration) float64 {
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

func ShapeDelta(cur, prev float64) float64 {
	if prev == 0 && cur == 0 {
		return 0
	}
	diff := cur - prev
	if diff < 0 {
		diff = -diff
	}
	return diff
}

// BeaconFromModel checks if the model has a persisted beacon interval for this process identity.
// This enables instant beacon recognition across PID changes and restarts.
func BeaconFromModel(processKey string) (known bool, interval time.Duration, jitter float64) {
	profile := model.ResolveProfile(processKey)
	if profile == nil || profile.BeaconIntervalMs == 0 {
		return false, 0, 0
	}
	// Only trust beacon data less than 7 days old.
	if profile.BeaconConfirmedAt.IsZero() || time.Since(profile.BeaconConfirmedAt) > 7*24*time.Hour {
		return false, 0, 0
	}
	return true, time.Duration(profile.BeaconIntervalMs) * time.Millisecond, profile.BeaconJitter
}
