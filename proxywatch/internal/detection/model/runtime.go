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
		// Requires substantial observation history AND very low suspicious ratio
		// to prevent premature benign labeling of processes that haven't been
		// observed long enough for beacon/C2 patterns to emerge.
		if behavior.Observations >= 500 && (profile.CalibrationVerdict == "" || profile.CalibrationVerdict == "unknown") {
			suspRatio := float64(behavior.SuspiciousObservations) / float64(behavior.Observations)
			if suspRatio < 0.02 {
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
