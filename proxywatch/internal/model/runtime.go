package model

import (
	"time"

	"proxywatch/internal/shared"
)

// RefreshRuntimeProfiles updates process profiles from in-memory ProcessBehavior data.
// Called periodically (every 60s) to let the model learn from runtime experience
// without requiring explicit calibration runs.
func RefreshRuntimeProfiles() {
	mu.Lock()
	defer mu.Unlock()
	if current == nil {
		return
	}
	now := time.Now().UTC()
	if !lastRefresh.IsZero() && now.Sub(lastRefresh) < runtimeRefreshRate {
		return
	}
	lastRefresh = now

	changed := false
	for key, behavior := range shared.ProcessBehaviorByKey {
		if behavior == nil || behavior.Observations < 10 {
			continue
		}
		profile := resolveOrCreateProcessProfile(current, key, extractNameFromKey(key))

		profile.RuntimeObservations = behavior.Observations

		// Compute dominant role and stability from runtime observations.
		if len(behavior.LastRoles) > 0 {
			totalObs := 0
			maxCount := 0
			maxRole := ""
			for role, count := range behavior.LastRoles {
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
		}

		// Auto-learn benign verdict from sustained runtime experience.
		if behavior.Observations >= 50 && (profile.CalibrationVerdict == "" || profile.CalibrationVerdict == "unknown") {
			suspRatio := float64(behavior.SuspiciousObservations) / float64(behavior.Observations)
			if suspRatio < 0.05 {
				profile.CalibrationVerdict = "benign"
				changed = true
			}
		}

		profile.OverallConfidence = computeConfidence(profile)
		profile.LastRuntimeUpdate = now
		profile.LastUpdated = now
	}

	if changed {
		markDirty()
	}
}

// SyncCalibrationStats mirrors aggregate stats from the calibration learning model
// into the detection model so there's a single source of truth.
func SyncCalibrationStats(runs int, weightedSamples float64, contaminationPct int) {
	mu.Lock()
	defer mu.Unlock()
	if current == nil {
		return
	}
	current.CalibrationRuns = runs
	current.CalibrationSamples = weightedSamples
	current.CalibrationContamination = contaminationPct
	markDirty()
}

// IngestCalibrationRun updates process profiles from calibration sample data.
func IngestCalibrationRun(samples []shared.Candidate) {
	mu.Lock()
	defer mu.Unlock()
	if current == nil || len(samples) == 0 {
		return
	}
	now := time.Now().UTC()

	for _, sample := range samples {
		if sample.Proc == nil {
			continue
		}
		key := calibrationProcessKey(sample)
		if key == "" {
			continue
		}
		profile := resolveOrCreateProcessProfile(current, key, sample.Proc.Name)

		profile.CalibrationRuns++
		family := shared.RoleFamily(sample.Role)
		if profile.RoleDistribution == nil {
			profile.RoleDistribution = make(map[string]float64)
		}
		profile.RoleDistribution[family]++
		profile.LastCalibration = now

		profile.CalibrationVerdict = deriveCalibrationVerdict(profile)
		profile.OverallConfidence = computeConfidence(profile)
		profile.LastUpdated = now
	}
	markDirty()
}

func deriveCalibrationVerdict(p *ProcessProfile) string {
	if p.CalibrationRuns < 2 {
		return "unknown"
	}
	suspiciousCount := 0.0
	benignCount := 0.0
	totalCount := 0.0
	for role, count := range p.RoleDistribution {
		totalCount += count
		switch role {
		case "control-session", "control-beacon", "control-tunnel", "control-pivot":
			suspiciousCount += count
		case "outbound", "listen":
			benignCount += count
		}
	}
	if totalCount == 0 {
		return "unknown"
	}
	if suspiciousCount/totalCount >= 0.5 {
		return "suspicious"
	}
	if benignCount/totalCount >= 0.7 && p.CalibrationRuns >= 3 {
		return "benign"
	}
	return "unknown"
}

func calibrationProcessKey(c shared.Candidate) string {
	if c.Proc == nil {
		return ""
	}
	host := shared.DisplayHost(c.Host)
	return host + "|" + shared.NormalizeExePath(c.Proc.ExePath) + "|" + c.Proc.Name + "|" + c.Proc.UserName
}

func extractNameFromKey(key string) string {
	// Key format: host|path|name|user — extract name (3rd field)
	fields := 0
	start := 0
	for i, ch := range key {
		if ch == '|' {
			fields++
			if fields == 2 {
				start = i + 1
			}
			if fields == 3 {
				return key[start:i]
			}
		}
	}
	return ""
}
