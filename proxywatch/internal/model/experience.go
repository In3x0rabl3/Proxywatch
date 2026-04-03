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
		if totalObs > 0 {
			profile.DominantRole = maxRole
			profile.RoleStability = float64(maxCount) / float64(totalObs)
		}

		// Auto-derive calibration verdict from experience (no calibration needed).
		if profile.ExperienceObservations >= 30 && (profile.CalibrationVerdict == "" || profile.CalibrationVerdict == "unknown") {
			suspCount := 0
			benignCount := 0
			for role, count := range profile.ExperienceRoles {
				switch role {
				case "control-session", "control-beacon", "control-tunnel", "control-pivot":
					suspCount += count
				case "outbound", "listen":
					benignCount += count
				}
			}
			suspRatio := float64(suspCount) / float64(max(1, totalObs))
			if suspRatio < 0.05 {
				profile.CalibrationVerdict = "benign"
				changed = true
			} else if suspRatio > 0.5 && profile.ExperienceObservations >= 50 {
				profile.CalibrationVerdict = "suspicious"
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

	if changed || len(records) > 0 {
		markDirty()
	}

	// Periodically self-validate predictions from accumulated experience.
	selfValidateModel(current)
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
	profile.OverallConfidence = computeConfidence(profile)
	markDirty()

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
