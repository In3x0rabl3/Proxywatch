package model

import (
	"strings"
	"time"
)

func updateQualityMetrics(m *DetectionModel, entry FeedbackEntry) {
	m.Quality.TotalFeedback++

	role := strings.ToLower(entry.Role)
	isSuspicious := strings.HasPrefix(role, "control-")

	switch entry.Action {
	case "kill":
		if isSuspicious {
			m.Quality.ConfirmedCorrect++
		} else {
			m.Quality.Contradictions++
		}
	case "whitelist":
		if !isSuspicious || entry.Score < 50 {
			m.Quality.ConfirmedCorrect++
		} else {
			m.Quality.Contradictions++
		}
	}

	recalcConfirmationRate(m)
}

func selfValidateModel(m *DetectionModel) {
	changed := false

	totalProfiles := len(m.Processes)
	for _, overlay := range m.HostOverlays {
		if overlay != nil {
			totalProfiles += len(overlay.Processes)
		}
	}
	maxSelfConfirm := totalProfiles / 4
	if maxSelfConfirm < 1 {
		maxSelfConfirm = 1
	}
	if m.Quality.SelfConfirmed >= maxSelfConfirm {
		return
	}

	validate := func(profiles map[string]*ProcessProfile) {
		for key, profile := range profiles {
			if m.Quality.SelfConfirmed >= maxSelfConfirm {
				return
			}
			if profile == nil || profile.SelfValidated {
				continue
			}
			if profile.ExperienceObservations < 10000 || profile.RoleStability < 0.95 {
				continue
			}
			dominant := strings.ToLower(profile.DominantRole)
			if !strings.HasPrefix(dominant, "control-") {
				continue
			}
			if profile.ExperienceAvgScore < 70 || profile.CalibrationVerdict != "suspicious" {
				continue
			}
			distinctSignals := 0
			for _, count := range profile.ExperienceSignals {
				if count >= 5 {
					distinctSignals++
				}
			}
			if distinctSignals < 3 {
				continue
			}
			profile.SelfValidated = true
			profile.SelfValidatedAt = time.Now().UTC()
			m.Quality.SelfConfirmed++
			if m.SelfValidations == nil {
				m.SelfValidations = make(map[string]SelfValidation)
			}
			m.SelfValidations[key] = SelfValidation{
				ProcessKey:   key,
				Role:         profile.DominantRole,
				Stability:    profile.RoleStability,
				Observations: profile.ExperienceObservations,
				AvgScore:     profile.ExperienceAvgScore,
				ValidatedAt:  profile.SelfValidatedAt,
			}
			changed = true
		}
	}

	validate(m.Processes)
	for _, overlay := range m.HostOverlays {
		if overlay != nil {
			validate(overlay.Processes)
		}
	}
	if changed {
		recalcConfirmationRate(m)
	}
}

func recalcConfirmationRate(m *DetectionModel) {
	// Accuracy is based on operator feedback only — self-confirmations
	// are tracked separately and don't inflate the accuracy metric.
	total := m.Quality.ConfirmedCorrect + m.Quality.Contradictions
	if total > 0 {
		m.Quality.ConfirmationRate = float64(m.Quality.ConfirmedCorrect) / float64(total)
	}
	m.Quality.RoleStabilityScore = computeRoleStability(m)
	m.Quality.LastRecalculated = time.Now().UTC()
}

func computeRoleStability(m *DetectionModel) float64 {
	if len(m.Processes) == 0 {
		return 0
	}
	stableCount := 0
	totalProfiles := 0
	for _, profile := range m.Processes {
		if profile.CalibrationRuns < 2 && profile.RuntimeObservations < 20 {
			continue
		}
		totalProfiles++
		if profile.RoleStability > 0.6 {
			stableCount++
		}
	}
	if totalProfiles == 0 {
		return 0
	}
	return float64(stableCount) / float64(totalProfiles)
}
