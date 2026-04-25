package model

import (
	"sync"
	"sync/atomic"
	"time"

	"proxywatch/internal/shared"
)

// Maturity states.
const (
	MaturityCold       = "COLD"
	MaturityLearning   = "LEARNING"
	MaturityStable     = "STABLE"
	MaturityCalibrated = "CALIBRATED"
)

// ModelMaturity tracks how reliable the ML model is.
type ModelMaturity struct {
	Score             int       `json:"score"`     // 0-100
	State             string    `json:"state"`     // COLD/LEARNING/STABLE/CALIBRATED
	LocalObservations int       `json:"local_obs"` // observations since model load
	StabilityRatio    float64   `json:"stability"` // prediction stability (0-1)
	MeanConfidence    float64   `json:"mean_conf"` // mean top-class probability
	LastComputed      time.Time `json:"last_computed"`
}

// maturityStats collects per-cycle statistics for maturity computation.
// Updated atomically from the scoring goroutine.
var (
	maturityLocalObs      atomic.Int64 // resets after each training attempt
	maturityLifetimeObs   atomic.Int64 // never resets — true lifetime counter
	maturityPredictions   atomic.Int64
	maturityConfidenceSum atomic.Int64 // sum of (confidence * 1000) for integer atomics
	maturityStableCount   atomic.Int64 // predictions that match committed role
	maturityNewLabels     atomic.Int64 // operator labels since last retrain
	maturityLastRetrain   atomic.Int64 // unix timestamp of last retrain
	shadowAgree           atomic.Int64 // ML agrees with rule-based (lifetime)
	shadowDisagree        atomic.Int64 // ML disagrees with rule-based (lifetime)
	mlQualified           atomic.Bool  // true when ML model meets quality gate
	mlDemoted             atomic.Bool  // true when ML was qualified then dropped below degrade floor
)

// Shadow-agreement gates. Exported so the Training UI can show the same
// numbers the runtime actually enforces (previously the view lied about
// 60%/100 while the code gated at 70%/200).
const (
	// ShadowQualifyAgreement is the minimum fraction of ML predictions that
	// must match the rule engine's verdict before ML takes over role
	// assignment. Measured on the rolling shadow window.
	//
	// Raised from 0.70 → 0.85: 70% agreement leaves the model wrong on
	// nearly a third of predictions, which on a busy host translates to
	// dozens of misclassified candidates per cycle. 85% means the
	// predictor must consistently match the rule engine before it gets
	// to override it. Raises the bar without changing what counts as
	// "agreement" or what the ML output looks like.
	ShadowQualifyAgreement = 0.85

	// ShadowQualifyPredictions is the minimum number of shadow-mode
	// predictions that must be accumulated before ML can qualify.
	//
	// Raised from 200 → 1000. 200 was the retrain-buffer floor (enough
	// observations to attempt retraining), but ML qualification —
	// taking over role assignment globally — needs orders of magnitude
	// more evidence. On a busy host, 200 predictions accumulate within
	// a couple of hours; ML was overriding the rule engine before any
	// meaningful diversity of process behavior had been observed.
	// 1000 ≈ a working day of observations.
	ShadowQualifyPredictions int64 = 1000

	// ShadowDegradeFloor is the rolling-window agreement rate below which a
	// previously-qualified model is un-qualified and reverts to shadow.
	// Lower than the qualify threshold so we don't flip-flop on noise.
	// Raised from 0.60 → 0.70 to track the new qualify threshold.
	ShadowDegradeFloor = 0.70

	// shadowWindow caps how many shadow outcomes are tracked. When the
	// running total exceeds this, counters halve — same sliding-window
	// pattern used for the prediction/confidence counters below. Without
	// this, an early run of good agreement masks later degradation
	// indefinitely (thousands of stale "agree" votes drowning current
	// "disagree" votes).
	shadowWindow = 2000
)

// MLQualified returns true when the ML model has proven reliable enough
// to take over role assignment. See ShadowQualifyAgreement /
// ShadowQualifyPredictions for the thresholds.
func MLQualified() bool {
	return mlQualified.Load()
}

// MLDemoted returns true when the ML model was once qualified but its
// rolling shadow agreement has since dropped below ShadowDegradeFloor.
// Cleared when the model re-qualifies (typically after a retrain) or when
// the buffer drops below ShadowQualifyPredictions on the rolling window.
func MLDemoted() bool {
	return mlDemoted.Load()
}

// ResetShadowForRetrain is called after a fresh predictor is hot-swapped
// in via the retrain pipeline. Zeros the shadow counters and clears the
// demoted latch so the new model starts from a clean slate — otherwise
// a previously-degraded lifetime history poisons the rolling rate before
// the new model gets enough predictions to prove itself.
func ResetShadowForRetrain() {
	shadowAgree.Store(0)
	shadowDisagree.Store(0)
	mlDemoted.Store(false)
	mlQualified.Store(false)
}

// maturityWindow caps how many predictions are tracked for stability/confidence.
// Once predictions exceed this, halve all counters to approximate a sliding
// window. This prevents stability from degrading over long sessions.
const maturityWindow = 10000

// RecordMLPrediction tracks a single ML prediction for maturity computation.
func RecordMLPrediction(confidence float64, matchesCommitted bool) {
	maturityPredictions.Add(1)
	maturityConfidenceSum.Add(int64(confidence * 1000))
	if matchesCommitted {
		maturityStableCount.Add(1)
	}
	decayMaturityCountersIfNeeded()
}

// RecordObservationForMaturity increments both the cycle and lifetime counters.
func RecordObservationForMaturity() {
	maturityLocalObs.Add(1)
	maturityLifetimeObs.Add(1)
}

// LiveObservationCount returns the lifetime observation count. Never resets.
func LiveObservationCount() int64 {
	return maturityLifetimeObs.Load()
}

// CycleObservationCount returns observations since last training attempt.
func CycleObservationCount() int64 {
	return maturityLocalObs.Load()
}

// RecordRoleAssignment tracks a role assignment for maturity stability/confidence
// computation. Called only for processes with a prior committed role (not first-
// observation). matchesCommitted indicates whether the current role matches
// the previously committed role.
func RecordRoleAssignment(matchesCommitted bool, score int) {
	maturityPredictions.Add(1)
	// Confidence for rule-based assignments: use role stability as the signal.
	// A matching committed role = high confidence (0.8), mismatch = low (0.2).
	// Raw detection scores are near 0 for benign traffic, making them useless
	// as a confidence proxy.
	conf := 0.2
	if matchesCommitted {
		conf = 0.8
		maturityStableCount.Add(1)
	}
	maturityConfidenceSum.Add(int64(conf * 1000))
	decayMaturityCountersIfNeeded()
}

// decayMaturityCountersIfNeeded halves stability/confidence counters when
// predictions exceed the window. Preserves the ratio while keeping the
// denominator bounded so recent data has more influence.
func decayMaturityCountersIfNeeded() {
	if maturityPredictions.Load() > maturityWindow {
		// Atomic halving — not perfectly synchronized but close enough
		// for a rolling estimate. Ratios are preserved.
		preds := maturityPredictions.Load()
		stable := maturityStableCount.Load()
		confSum := maturityConfidenceSum.Load()
		maturityPredictions.Store(preds / 2)
		maturityStableCount.Store(stable / 2)
		maturityConfidenceSum.Store(confSum / 2)
	}
}

// RecordShadowComparison tracks ML vs rule agreement.
// Counters decay when the running total exceeds shadowWindow so the
// rolling rate reflects *recent* agreement instead of lifetime — that's
// the signal we need to detect model degradation between retrains.
func RecordShadowComparison(agree bool) {
	if agree {
		shadowAgree.Add(1)
	} else {
		shadowDisagree.Add(1)
	}
	if shadowAgree.Load()+shadowDisagree.Load() > shadowWindow {
		// Halving preserves the ratio while bounding the denominator.
		// Not perfectly synchronized across atomics but acceptable — one
		// decayed sample out of ~thousand doesn't move the rolling rate.
		a := shadowAgree.Load()
		d := shadowDisagree.Load()
		shadowAgree.Store(a / 2)
		shadowDisagree.Store(d / 2)
	}
}

// ShadowDisagreement is a single captured event where the ML predictor
// disagreed with the rule engine's verdict. Surfaced via the
// /ml/disagreements debug API so operators can tune the model from the
// actual disagreement population without needing to tail logs.
type ShadowDisagreement struct {
	Timestamp    time.Time `json:"timestamp"`
	Host         string    `json:"host"`
	PID          int       `json:"pid"`
	Name         string    `json:"name"`
	ExePath      string    `json:"exe_path,omitempty"`
	SHA256       string    `json:"sha256,omitempty"`
	RuleRole     string    `json:"rule_role"`
	MLRole       string    `json:"ml_role"`
	MLConfidence float64   `json:"ml_confidence"`
}

const shadowDisagreementBufferSize = 100

var (
	shadowDisagreementsMu  sync.Mutex
	shadowDisagreementsBuf [shadowDisagreementBufferSize]ShadowDisagreement
	shadowDisagreementsN   int // next write index (wraps)
	shadowDisagreementsLen int // how many valid entries (≤ buffer size)
)

// RecordShadowDisagreement captures a single ML-vs-rule disagreement for
// the /ml/disagreements debug endpoint. Ring buffer of the last 100 —
// cheap to call from the hot path, and the snapshot getter returns a
// copy so callers don't hold the lock while they read.
func RecordShadowDisagreement(d ShadowDisagreement) {
	if d.Timestamp.IsZero() {
		d.Timestamp = time.Now().UTC()
	}
	shadowDisagreementsMu.Lock()
	shadowDisagreementsBuf[shadowDisagreementsN] = d
	shadowDisagreementsN = (shadowDisagreementsN + 1) % shadowDisagreementBufferSize
	if shadowDisagreementsLen < shadowDisagreementBufferSize {
		shadowDisagreementsLen++
	}
	shadowDisagreementsMu.Unlock()
}

// ShadowDisagreements returns a snapshot of up to the last 100 ML-vs-rule
// disagreements in chronological order (oldest first).
func ShadowDisagreements() []ShadowDisagreement {
	shadowDisagreementsMu.Lock()
	defer shadowDisagreementsMu.Unlock()
	if shadowDisagreementsLen == 0 {
		return nil
	}
	out := make([]ShadowDisagreement, shadowDisagreementsLen)
	// The ring buffer may have wrapped. Walk from the oldest entry
	// forward so the caller sees chronological order.
	start := (shadowDisagreementsN - shadowDisagreementsLen + shadowDisagreementBufferSize) % shadowDisagreementBufferSize
	for i := 0; i < shadowDisagreementsLen; i++ {
		out[i] = shadowDisagreementsBuf[(start+i)%shadowDisagreementBufferSize]
	}
	return out
}

// ShadowAgreementRate returns the fraction of predictions where ML agrees with rules.
func ShadowAgreementRate() float64 {
	a := shadowAgree.Load()
	d := shadowDisagree.Load()
	total := a + d
	if total == 0 {
		return 0
	}
	return float64(a) / float64(total)
}

// ShadowCounts returns the raw agree/disagree counters for the ML shadow comparison.
func ShadowCounts() (agree, disagree int64) {
	return shadowAgree.Load(), shadowDisagree.Load()
}

// RecordNewLabel increments the operator label counter (for retrain triggers).
func RecordNewLabel() {
	maturityNewLabels.Add(1)
}

// GetOperatorLabelCount returns the total number of operator training labels
// persisted in the detection model. Counts from model profiles rather than
// the in-memory atomic so the value survives restarts.
func GetOperatorLabelCount() int64 {
	// Use the in-memory counter (fast).
	// Avoid iterating all profiles on every UI render — that causes freezes.
	return maturityNewLabels.Load()
}

// ResetRetrainTriggers resets only the counters that gate retrain triggers
// (observations and labels since last retrain). Stability, confidence, and
// prediction counters are session-level metrics and must NOT be reset —
// doing so destroys the maturity bars.
func ResetRetrainTriggers() {
	maturityLocalObs.Store(0)
	maturityNewLabels.Store(0)
	maturityLastRetrain.Store(time.Now().Unix())
}

// ResetAllMaturityCounters resets everything — only used when the operator
// explicitly resets to baseline or loads a new baseline snapshot.
func ResetAllMaturityCounters() {
	maturityLocalObs.Store(0)
	maturityNewLabels.Store(0)
	maturityPredictions.Store(0)
	maturityStableCount.Store(0)
	maturityConfidenceSum.Store(0)
	maturityLastRetrain.Store(time.Now().Unix())
}

// ComputeMaturity calculates the current maturity score and state.
var (
	cachedMaturity     ModelMaturity
	cachedMaturityTime time.Time
)

func ComputeMaturity() ModelMaturity {
	if time.Since(cachedMaturityTime) < 2*time.Second {
		return cachedMaturity
	}

	mu.RLock()
	defer mu.RUnlock()

	m := ModelMaturity{
		LastComputed: time.Now().UTC(),
	}

	localObs := int(maturityLocalObs.Load())
	m.LocalObservations = localObs

	// Component 1: Data volume (25%).
	// Linear scale: 0% at 0 obs, 100% at 20,000 obs. Simple and predictable.
	volumeScore := float64(localObs) / 20000.0
	if volumeScore > 1.0 {
		volumeScore = 1.0
	}

	// Component 2: Prediction stability (30%).
	// Raw ratio of predictions matching the committed role.
	// Light dampening: require at least 100 predictions before full credit.
	preds := maturityPredictions.Load()
	stable := maturityStableCount.Load()
	rawStability := 0.0
	if preds > 0 {
		rawStability = float64(stable) / float64(preds)
	}
	m.StabilityRatio = rawStability
	stabilityCredit := rawStability
	if preds < 100 {
		stabilityCredit *= float64(preds) / 100.0
	}

	// Component 3: Confidence (25%).
	// With ML model: actual top-class probability from predictions.
	// Without ML: use stability as a confidence proxy since rule scores
	// are heavily skewed toward 0 for benign traffic.
	confSum := maturityConfidenceSum.Load()
	meanConf := 0.0
	if preds > 0 {
		meanConf = float64(confSum) / float64(preds) / 1000.0
	}
	if !mlQualified.Load() && meanConf < 0.30 && rawStability > 0 {
		meanConf = 0.3*meanConf + 0.7*rawStability
	}
	m.MeanConfidence = meanConf
	confCredit := meanConf
	if preds < 100 {
		confCredit *= float64(preds) / 100.0
	}

	// Component 4: Operator agreement (20%).
	agreementScore := 0.0
	if current != nil && current.Quality.TotalFeedback > 0 {
		agreementScore = current.Quality.ConfirmationRate
	}

	// Maturity is for the ML model only. If no ML model is loaded,
	// maturity is 0% — the rule engine's stability/confidence don't count.
	score := 0.0
	if mlQualified.Load() {
		// ML model is active and qualified — full maturity computation.
		score = volumeScore*25 + stabilityCredit*30 + confCredit*25 + agreementScore*20
	} else if shadowAgree.Load()+shadowDisagree.Load() > 0 {
		// ML model is loaded but shadowing — partial maturity from shadow agreement.
		shadowTotal := float64(shadowAgree.Load() + shadowDisagree.Load())
		shadowRate := float64(shadowAgree.Load()) / shadowTotal
		score = shadowRate * 50 // 0-50% while shadowing
	}
	// No ML model loaded → score stays 0.
	if score > 100 {
		score = 100
	}
	m.Score = int(score)

	// State derivation.
	switch {
	case localObs < 500:
		m.State = MaturityCold
	case localObs < 2000 || m.Score < 50:
		m.State = MaturityLearning
	case localObs < 5000 || m.Score < 75:
		m.State = MaturityStable
	default:
		m.State = MaturityCalibrated
	}

	// Persist in model and check baseline lifecycle.
	if current != nil {
		current.Maturity = m
		markDirty()
	}

	// Evaluate ML qualification + degradation on the rolling shadow window.
	//
	//   - Qualify when ≥ ShadowQualifyPredictions predictions have been
	//     accumulated AND rolling agreement ≥ ShadowQualifyAgreement.
	//   - Once qualified, demote back to shadow if rolling agreement drops
	//     below ShadowDegradeFloor (hysteresis band so we don't flip-flop
	//     on noise). Demotion latches an mlDemoted flag the UI surfaces;
	//     the flag clears when the model re-qualifies (usually after a
	//     retrain swaps in a fresh predictor).
	//
	// Without the degrade check, a model that was qualified early keeps
	// primary status forever even as its rolling agreement rots, because
	// the lifetime agree counter drowns recent disagree votes. The decay
	// in RecordShadowComparison + this demote gate together make that
	// visible and recoverable.
	wasQualified := mlQualified.Load()
	agree := shadowAgree.Load()
	disagree := shadowDisagree.Load()
	shadowTotal := agree + disagree

	var rollingRate float64
	if shadowTotal > 0 {
		rollingRate = float64(agree) / float64(shadowTotal)
	}

	qualified := false
	switch {
	case wasQualified:
		// Hysteresis: stay qualified until rolling rate crosses the floor.
		if shadowTotal >= ShadowQualifyPredictions && rollingRate < ShadowDegradeFloor {
			qualified = false
			mlDemoted.Store(true)
		} else {
			qualified = true
		}
	default:
		// Fresh qualification path: need full bar, not just the floor.
		qualified = shadowTotal >= ShadowQualifyPredictions && rollingRate >= ShadowQualifyAgreement
		if qualified {
			mlDemoted.Store(false)
		}
	}
	mlQualified.Store(qualified)

	// Check baseline state transition (needs write lock, so defer to separate call).
	go updateBaselineState()

	cachedMaturity = m
	cachedMaturityTime = time.Now()
	return m
}

// GetMaturity returns the last computed maturity.
func GetMaturity() ModelMaturity {
	mu.RLock()
	defer mu.RUnlock()
	if current != nil {
		return current.Maturity
	}
	return ModelMaturity{State: MaturityCold}
}

// ShouldRetrain checks if automatic retraining should be triggered.
// The sole gate is buffer >= 50 (checked by attemptRetrain). This function
// only enforces a cooldown between attempts to prevent rapid-fire loops.
func ShouldRetrain() (bool, string) {
	newLabels := maturityNewLabels.Load()
	lastRetrain := maturityLastRetrain.Load()
	minutesSinceRetrain := 0.0
	if lastRetrain > 0 {
		minutesSinceRetrain = time.Since(time.Unix(lastRetrain, 0)).Minutes()
	} else {
		minutesSinceRetrain = 999 // never retrained
	}

	// Minimum cooldown after any retrain attempt.
	if minutesSinceRetrain < 2 {
		return false, ""
	}

	// Operator labels always trigger immediately (new ground truth).
	if newLabels >= 1 {
		return true, "operator label added"
	}

	// Otherwise just check cooldown. The buffer gate (>= 50 records)
	// is enforced by attemptRetrain — not here.
	mu.RLock()
	state := MaturityCold
	if current != nil {
		state = current.Maturity.State
	}
	mu.RUnlock()

	switch state {
	case MaturityCold, MaturityLearning:
		if minutesSinceRetrain >= 2 {
			return true, "collection check"
		}
	case MaturityStable:
		if minutesSinceRetrain >= 5 {
			return true, "collection check"
		}
	default:
		if minutesSinceRetrain >= 10 {
			return true, "collection check"
		}
	}

	return false, ""
}

// Baseline lifecycle thresholds.
const (
	BaselineMinObservations  = 5000
	BaselineMinStability     = 0.70
	BaselineMinMaturity      = 70
	BaselineDegradeStability = 0.50
	BaselineDegradeMaturity  = 50
)

// BaselineInfo holds the computed baseline state for the UI.
type BaselineInfo struct {
	State             string  // "none", "building", "ready", "degraded"
	Type              string  // "shipped", "user", "none"
	Observations      int     // current local observations
	Stability         float64 // current stability ratio (0-1)
	MaturityScore     int     // current maturity score
	CertifiedMaturity int     // maturity score at certification
	ReadyAt           time.Time
	Version           string
}

// GetBaselineInfo returns baseline lifecycle state for the dashboard.
func GetBaselineInfo() BaselineInfo {
	mu.RLock()
	defer mu.RUnlock()
	if current == nil {
		return BaselineInfo{State: "none", Type: "none"}
	}
	info := BaselineInfo{
		Observations:      current.Maturity.LocalObservations,
		Stability:         current.Maturity.StabilityRatio,
		MaturityScore:     current.Maturity.Score,
		CertifiedMaturity: int(current.BaselineAccuracy * 100), // repurposed field
		ReadyAt:           current.BaselineReadyAt,
		Version:           current.BaselineVersion,
	}
	info.Type = current.BaselineType
	if info.Type == "" {
		info.Type = "none"
	}
	info.State = computeBaselineStateLocked()
	return info
}

func computeBaselineStateLocked() string {
	if current == nil {
		return "none"
	}
	obs := current.Maturity.LocalObservations
	stability := current.Maturity.StabilityRatio

	// If previously certified as ready, check for degradation.
	// Only use stability — maturity score has different semantics now
	// (ML-only) and shouldn't gate baseline lifecycle.
	if current.BaselineState == "ready" {
		if stability < BaselineDegradeStability {
			return "degraded"
		}
		return "ready"
	}
	// If previously degraded, check for recovery.
	if current.BaselineState == "degraded" {
		if stability >= BaselineMinStability {
			return "ready"
		}
		return "degraded"
	}

	// Not yet certified — check automated criteria.
	// Only use observations + stability. Maturity score is ML-only.
	if obs < 100 {
		return "none"
	}
	if obs >= BaselineMinObservations && stability >= BaselineMinStability {
		return "ready"
	}
	return "building"
}

// updateBaselineState checks for baseline state transitions and certifies
// when all criteria are met. Called from ComputeMaturity via goroutine.
func updateBaselineState() {
	mu.Lock()
	defer mu.Unlock()
	if current == nil {
		return
	}

	newState := computeBaselineStateLocked()
	oldState := current.BaselineState

	if newState == oldState {
		return
	}

	switch {
	case newState == "ready" && oldState != "ready":
		current.BaselineState = "ready"
		current.BaselineReadyAt = time.Now().UTC()
		current.BaselineAccuracy = float64(current.Maturity.Score) / 100.0
		current.BaselineDataSize = current.Maturity.LocalObservations
		if current.BaselineType == "" {
			current.BaselineType = "user"
		}
		if current.BaselineVersion == "" {
			current.BaselineVersion = "v1-user-" + time.Now().UTC().Format("2006-01-02")
		}
		shared.LogInfo("model", "baseline ready — maturity %d%%, stability %.0f%%, %d observations",
			current.Maturity.Score, current.Maturity.StabilityRatio*100, current.Maturity.LocalObservations)
		markDirty()

	case newState == "degraded" && oldState == "ready":
		current.BaselineState = "degraded"
		shared.LogWarn("model", "baseline degraded — performance dropped below threshold")
		markDirty()

	case newState == "building" && oldState == "none":
		current.BaselineState = "building"
		markDirty()

	default:
		current.BaselineState = newState
		markDirty()
	}
}
