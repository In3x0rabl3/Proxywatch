package model

import (
	"time"
)

// RecordFeedback records a user action (kill or whitelist) and updates
// the corresponding process profile and quality metrics.
func RecordFeedback(entry FeedbackEntry) {
	mu.Lock()
	defer mu.Unlock()
	if current == nil {
		return
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	current.Feedback = append(current.Feedback, entry)
	if len(current.Feedback) > maxFeedbackEntries {
		current.Feedback = current.Feedback[len(current.Feedback)-maxFeedbackEntries:]
	}

	key := entry.ProcessKey
	if key == "" {
		markDirty()
		return
	}
	profile := resolveOrCreateProcessProfile(current, key, entry.ProcessName)

	switch entry.Action {
	case "kill":
		profile.KillCount++
		profile.LastKill = entry.Timestamp
	case "whitelist":
		profile.WhitelistCount++
		profile.LastWhitelist = entry.Timestamp
	}

	profile.UserVerdict = deriveUserVerdict(profile)
	profile.OverallConfidence = computeConfidence(profile)
	profile.LastUpdated = entry.Timestamp

	// Update signal effectiveness from the signals present at time of action.
	if current.SignalStats == nil {
		current.SignalStats = make(map[string]*SignalStat)
	}
	for _, sig := range entry.Signals {
		ss := current.SignalStats[sig]
		if ss == nil {
			ss = &SignalStat{}
			current.SignalStats[sig] = ss
		}
		ss.Total++
		switch entry.Action {
		case "kill":
			ss.TruePositive++
		case "whitelist":
			ss.FalsePositive++
		}
		if ss.TruePositive+ss.FalsePositive > 0 {
			ss.Precision = float64(ss.TruePositive) / float64(ss.TruePositive+ss.FalsePositive)
		}
	}

	updateQualityMetrics(current, entry)
	markDirty()
}

func deriveUserVerdict(p *ProcessProfile) string {
	if p.KillCount > 0 && p.WhitelistCount == 0 {
		return "malicious"
	}
	if p.WhitelistCount > 0 && p.KillCount == 0 {
		return "benign"
	}
	if p.KillCount > 0 && p.WhitelistCount > 0 {
		return "contested"
	}
	return ""
}

// ProcessVerdict returns the user verdict and overall confidence for a process key.
// Returns ("", 0) if the process has no profile.
func ProcessVerdict(key string) (userVerdict string, calibrationVerdict string, confidence float64) {
	mu.RLock()
	defer mu.RUnlock()
	if current == nil {
		return
	}
	profile := resolveProcessProfile(current, key)
	if profile == nil {
		return
	}
	return profile.UserVerdict, profile.CalibrationVerdict, profile.OverallConfidence
}
