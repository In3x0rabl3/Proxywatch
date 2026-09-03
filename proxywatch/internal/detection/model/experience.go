package model

import (
	"sync"
	"time"

	"proxywatch/internal/shared"
)

// ExperienceRecord captures what the model observed from a single scoring cycle.
type ExperienceRecord struct {
	ProcessKey     string
	Name           string
	Role           string
	Score          int
	Signals        []string
	BeaconInterval int
	BeaconJitter   float64
	IOReadBytes    uint64
	IOWriteBytes   uint64
}

var (
	experienceBuffer    []ExperienceRecord
	experienceBufferMu  sync.Mutex
	lastExperienceFlush time.Time
	// lastSignalStatsDecay tracks when applySignalStatsDecay last ran.
	// Decay is the recovery mechanism for the SignalStats precision
	// counters: without it, FP counts grow monotonically and a signal
	// that briefly mis-fires stays [low] forever in the TUI even after
	// it stops mis-firing. EMA decay applied periodically gives clean
	// signals a path back to [mid]/[high].
	lastSignalStatsDecay time.Time
)

// signalStatsDecayInterval controls how often applySignalStatsDecay runs.
// 30 min cadence keeps decay slow enough that a real C2 signal that
// briefly mis-classifies doesn't get rehabilitated by accident, but
// fast enough that a noisy signal that gets fixed (e.g. a vendor IPC
// rescue rule landed) recovers within a few hours.
const signalStatsDecayInterval = 30 * time.Minute

// signalStatsDecayFactor is multiplied against TP/FP each decay cycle.
// 0.95 per 30 min ≈ 80% retained per hour. After 6 hours of zero
// firing, a signal's counters are ~74% of their original values; a
// signal that's been correctly firing all along holds steady because
// new TP/FP increments outpace the decay.
const signalStatsDecayFactor = 0.95

// RecordExperience buffers experience records and flushes them periodically
// to avoid taking a write lock on every scoring cycle.
func RecordExperience(records []ExperienceRecord) {
	if len(records) == 0 {
		return
	}
	experienceBufferMu.Lock()
	experienceBuffer = append(experienceBuffer, records...)
	if len(experienceBuffer) > 500 {
		experienceBuffer = experienceBuffer[len(experienceBuffer)-500:]
	}
	shouldFlush := time.Since(lastExperienceFlush) >= 10*time.Second
	experienceBufferMu.Unlock()
	if shouldFlush {
		FlushExperience()
	}
}

// FlushExperience writes buffered experience records to the model.
func FlushExperience() {
	experienceBufferMu.Lock()
	records := experienceBuffer
	experienceBuffer = nil
	lastExperienceFlush = time.Now()
	experienceBufferMu.Unlock()
	if len(records) == 0 {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	if current == nil {
		return
	}

	now := time.Now().UTC()
	changed := false

	for _, rec := range records {
		if rec.ProcessKey == "" {
			continue
		}
		profile := resolveOrCreateProcessProfile(current, rec.ProcessKey, rec.Name)
		if profile == nil {
			profile = &ProcessProfile{Name: rec.Name}
		}

		profile.ExperienceObservations++
		if profile.ExperienceRoles == nil {
			profile.ExperienceRoles = make(map[string]int)
		}
		profile.ExperienceRoles[rec.Role]++

		// Track signal frequency for this process.
		if profile.ExperienceSignals == nil {
			profile.ExperienceSignals = make(map[string]int)
		}
		for _, sig := range rec.Signals {
			profile.ExperienceSignals[sig]++
		}

		// Running average score.
		n := float64(profile.ExperienceObservations)
		profile.ExperienceAvgScore = profile.ExperienceAvgScore*(n-1)/n + float64(rec.Score)/n
		if rec.Score > profile.ExperienceMaxScore {
			profile.ExperienceMaxScore = rec.Score
		}
		profile.ExperienceLastRole = rec.Role
		profile.ExperienceLastScore = rec.Score
		profile.ExperienceLastUpdate = now

		// Persist beacon interval to model — survives restarts.
		if rec.BeaconInterval > 0 {
			profile.BeaconIntervalMs = rec.BeaconInterval
			profile.BeaconJitter = rec.BeaconJitter
			profile.BeaconConfirmedAt = now
			changed = true
		}

		// Recompute dominant role and stability from experience.
		totalObs := 0
		maxCount := 0
		maxRole := ""
		for role, count := range profile.ExperienceRoles {
			totalObs += count
			if count > maxCount {
				maxCount = count
				maxRole = role
			}
		}
		// When an operator training label exists, it is ground truth —
		// the dominant role is the label's role, not the statistical majority.
		if profile.TrainingLabel != "" {
			labelRole := trainingLabelToRole(profile.TrainingLabel)
			if labelRole != "" {
				profile.DominantRole = labelRole
				profile.RoleStability = 1.0
			}
		} else if totalObs > 0 {
			profile.DominantRole = maxRole
			profile.RoleStability = float64(maxCount) / float64(totalObs)
		}

		// Auto-derive calibration verdict from experience (no calibration needed).
		// Suspicious: >60% of observations in suspicious roles (strong majority).
		// Benign: 500+ observations with <5% suspicious (sustained clean behavior).
		// Between 5-60%: "unknown" — the detection is flip-flopping, not confirming.
		// Re-evaluate existing verdicts (without user override) as evidence changes.
		if profile.ExperienceObservations >= 100 && profile.UserVerdict == "" {
			suspCount := 0
			for role, count := range profile.ExperienceRoles {
				switch role {
				case "beacon", "pivot", "tunnel", "smb-pipe":
					suspCount += count
				}
			}
			suspRatio := float64(suspCount) / float64(max(1, totalObs))
			newVerdict := profile.CalibrationVerdict
			if suspRatio > 0.60 {
				newVerdict = "suspicious"
			} else if profile.ExperienceObservations >= 100 && suspRatio < 0.05 {
				newVerdict = "benign"
			} else if suspRatio >= 0.05 && suspRatio <= 0.60 {
				newVerdict = "unknown"
			}
			if newVerdict != profile.CalibrationVerdict {
				profile.CalibrationVerdict = newVerdict
				changed = true
			}
		}

		profile.OverallConfidence = computeConfidence(profile)
		profile.LastUpdated = now

		// Cap signal history to prevent unbounded growth.
		if len(profile.ExperienceSignals) > 50 {
			trimSignalMap(profile.ExperienceSignals, 50)
		}
		if len(profile.ExperienceRoles) > 10 {
			trimRoleMap(profile.ExperienceRoles, 10)
		}
	}

	// Update signal effectiveness from experience-confirmed processes.
	// Signals from processes with stable roles (50+ obs, 70%+ stability)
	// provide ground truth without requiring operator feedback.
	updateSignalStatsFromExperience(current, records)

	// Apply EMA decay to signal counters periodically. Keeps the panel
	// honest: signals that stop firing lose weight; signals still firing
	// stay near their current TP/FP because new increments outpace the
	// decay.
	if time.Since(lastSignalStatsDecay) >= signalStatsDecayInterval {
		applySignalStatsDecay(current, signalStatsDecayFactor)
		lastSignalStatsDecay = time.Now()
		changed = true
	}

	if changed || len(records) > 0 {
		markDirty()
	}

	// Periodically self-validate predictions from accumulated experience.
	selfValidateModel(current)
}

// applySignalStatsDecay multiplies every per-signal TP/FP counter by
// `factor` (0 < factor < 1) and recomputes Precision. Caller must hold
// mu.Lock.
//
// The decay gives noisy signals a path back to higher precision once
// the underlying mis-firing condition is fixed: without it, every FP
// ever recorded sticks to the denominator forever. With factor=0.95
// applied every 30 min, ~6 hours of zero firing leaves a signal at
// ~26% of its original counters; a signal that *is* firing correctly
// holds steady because incoming TP/FP arrive faster than the decay.
//
// Counters that round down to zero get evicted from the map so the
// SIGNAL EFFECTIVENESS panel doesn't accumulate dead rows over long
// runtimes.
func applySignalStatsDecay(det *DetectionModel, factor float64) {
	if det == nil || len(det.SignalStats) == 0 || factor <= 0 || factor >= 1 {
		return
	}
	// Permanent-filter thresholds: same gate ml/buffer.go pruneNoiseSignals
	// applies to training records (≥500 obs + <5% precision = persistent
	// noise). Without this, the SignalStats panel keeps showing [low]
	// rows for signals the trainer has long since stopped accepting.
	const (
		permanentFilterMinSamples = 500
		permanentFilterPrecision  = 0.05
	)
	for sig, st := range det.SignalStats {
		// Permanently-filtered signal: drop the stat entirely so the
		// [low] row doesn't crowd out useful entries in the EFFECTIVENESS
		// panel. The training-side filter in buffer.go strips records
		// independently; deleting the stat here just stops the panel
		// display.
		if st.Total >= permanentFilterMinSamples && st.Precision < permanentFilterPrecision {
			delete(det.SignalStats, sig)
			continue
		}
		tp := int(float64(st.TruePositive) * factor)
		fp := int(float64(st.FalsePositive) * factor)
		if tp == 0 && fp == 0 {
			delete(det.SignalStats, sig)
			continue
		}
		st.TruePositive = tp
		st.FalsePositive = fp
		st.Total = tp + fp
		if st.Total > 0 {
			st.Precision = float64(tp) / float64(st.Total)
		} else {
			st.Precision = 0
		}
	}
}

// updateSignalStatsFromExperience updates signal effectiveness stats from
// processes with confirmed roles. A process is "confirmed" when it has 50+
// observations and 70%+ role stability — its signals become ground truth.
// Suspicious-role signals count as TP, benign-role signals as FP.
// This supplements kill/whitelist feedback with continuous passive learning.
// Caller must hold mu.Lock.
func updateSignalStatsFromExperience(det *DetectionModel, records []ExperienceRecord) {
	if det.SignalStats == nil {
		det.SignalStats = make(map[string]*SignalStat)
	}

	for _, rec := range records {
		if rec.ProcessKey == "" || len(rec.Signals) == 0 {
			continue
		}
		profile := resolveProcessProfile(det, rec.ProcessKey)
		if profile == nil {
			continue
		}
		// Learn from processes with moderate stability and enough evidence.
		if profile.ExperienceObservations < 20 || profile.RoleStability < 0.50 {
			continue
		}

		// Use the role from THIS observation, not the overall dominant role.
		// This allows signals that appear on both suspicious and benign observations
		// to accumulate both TP and FP counts, producing intermediate precision values.
		suspicious := isSuspiciousRole(rec.Role)

		for _, sig := range rec.Signals {
			ss := det.SignalStats[sig]
			if ss == nil {
				ss = &SignalStat{}
				det.SignalStats[sig] = ss
			}
			ss.Total++
			// Detection-class signals (beacon-*, beacon-*, pivot-*,
			// session-*) and listener-* signals: firing on a malicious
			// role = TP, on a benign role = FP. Standard detection
			// semantics.
			//
			// Suppression-class signals (outbound-known-vendor,
			// vendor-signed-trusted, outbound-baseline-verified, etc.)
			// have INVERTED semantics: their job is to confirm a
			// candidate is benign, so firing on a benign role is the
			// signal SUCCEEDING (TP of the benign-confirmation rule),
			// and firing on a malicious role is the suppression
			// FAILING (FP). Without this branch, every successful
			// suppression got tallied as an FP, producing absurd
			// precision numbers like outbound-known-vendor 0% / TP=0
			// / FP=137188 — operators read that as model brokenness
			// when in fact those numbers reflected the signal doing
			// its own job correctly with the wrong sign.
			if shared.IsSuppressionSignal(sig) {
				if suspicious {
					ss.FalsePositive++
				} else {
					ss.TruePositive++
				}
			} else {
				if suspicious {
					ss.TruePositive++
				} else {
					ss.FalsePositive++
				}
			}
			if ss.TruePositive+ss.FalsePositive > 0 {
				ss.Precision = float64(ss.TruePositive) / float64(ss.TruePositive+ss.FalsePositive)
			}
		}
	}
}

// SetTrainingLabel allows an operator to explicitly label a process identity
// for training purposes. This is stronger than kill/whitelist because it
// specifies the exact expected role.
func SetTrainingLabel(processKey string, label string, context string) {
	mu.Lock()
	defer mu.Unlock()
	if current == nil {
		return
	}
	profile := resolveOrCreateProcessProfile(current, processKey, "")
	profile.TrainingLabel = label
	profile.TrainingContext = context
	profile.TrainingLabelAt = time.Now().UTC()
	profile.LastUpdated = profile.TrainingLabelAt

	// Align calibration verdict with the training label so they don't
	// contradict each other. The operator's explicit label is ground truth.
	switch label {
	case "beacon", "pivot", "tunnel", "malicious":
		if profile.CalibrationVerdict == "benign" || profile.CalibrationVerdict == "" || profile.CalibrationVerdict == "unknown" {
			profile.CalibrationVerdict = "suspicious"
		}
	case "outbound", "listener", "benign":
		if profile.CalibrationVerdict == "suspicious" || profile.CalibrationVerdict == "" || profile.CalibrationVerdict == "unknown" {
			profile.CalibrationVerdict = "benign"
		}
	}

	// Operator label is ground truth — reset experience role history so the
	// new role becomes dominant immediately. Old accumulated counts from idle
	// periods (dormant beacons, quiet tunnels) bury the correct classification.
	labelRole := trainingLabelToRole(label)
	if labelRole != "" {
		profile.ExperienceRoles = map[string]int{labelRole: 1}
		profile.DominantRole = labelRole
		profile.RoleStability = 1.0
		profile.ExperienceLastRole = labelRole
	}

	profile.OverallConfidence = computeConfidence(profile)
	markDirty()

	// Track label count for maturity metrics.
	if label != "" {
		RecordNewLabel()
	}

	// Re-extract patterns after every label change (lock already released).
	go extractPatterns()
}

// GetTrainingLabel returns the training label for a process, if set.
func GetTrainingLabel(processKey string) string {
	mu.RLock()
	defer mu.RUnlock()
	if current == nil {
		return ""
	}
	profile := resolveProcessProfile(current, processKey)
	if profile == nil {
		return ""
	}
	return profile.TrainingLabel
}

func trimSignalMap(m map[string]int, maxItems int) {
	if len(m) <= maxItems {
		return
	}
	// Keep highest-count entries.
	type kv struct {
		k string
		v int
	}
	items := make([]kv, 0, len(m))
	for k, v := range m {
		items = append(items, kv{k, v})
	}
	// Simple selection: remove lowest count entries.
	for len(m) > maxItems {
		minIdx := 0
		for i := 1; i < len(items); i++ {
			if items[i].v < items[minIdx].v {
				minIdx = i
			}
		}
		delete(m, items[minIdx].k)
		items[minIdx] = items[len(items)-1]
		items = items[:len(items)-1]
	}
}

func trimRoleMap(m map[string]int, maxItems int) {
	trimSignalMap(m, maxItems)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
