package model

import (
	"sync"
	"time"
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
)

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
				case "control-channel", "control-tunnel", "control-pivot", "tunnel", "smb-pipe":
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

	if changed || len(records) > 0 {
		markDirty()
	}

	// Periodically self-validate predictions from accumulated experience.
	selfValidateModel(current)
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
			if suspicious {
				ss.TruePositive++
			} else {
				ss.FalsePositive++
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
	case "control-channel", "control-session", "control-beacon", "control-pivot",
		"malicious", "beacon", "session", "tunnel", "pivot":
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
