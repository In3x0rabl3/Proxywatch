package model

import (
	"fmt"

	"proxywatch/internal/shared"
)

// analyzeDecision represents the model's decision on whether to commit
// to a role or continue analyzing.
type analyzeDecision struct {
	ShouldAnalyze bool   // true = hold in "analyzing", false = commit to role
	Reason        string // why the model made this decision
}

// ShouldAnalyze determines whether a process should remain in the "analyzing"
// state or can be committed to its classified role. The model uses all
// available intelligence to make this decision:
//   - User feedback (kill/whitelist history)
//   - Calibration history (prior role distribution)
//   - Runtime experience (observation count, role stability)
//   - Process identity (known vendor, known network-active)
//
// The model errs on the side of caution: unknown processes are analyzed
// longer, while processes with strong prior intelligence commit quickly.
func ShouldAnalyze(
	processKey string,
	observations int,
	seenSeconds int,
	benignClient bool,
	knownVendor bool,
	p *shared.ProcessInfo,
) analyzeDecision {
	mu.RLock()
	defer mu.RUnlock()

	// Time-based fallback: never hold a process in analyzing for more than
	// 5 minutes regardless of observation count. This prevents rare-running
	// processes from getting stuck indefinitely.
	if seenSeconds > 300 {
		return analyzeDecision{ShouldAnalyze: false, Reason: "model: maximum analysis time reached (5m)"}
	}

	// If model isn't loaded, fall back to simple observation threshold.
	if current == nil {
		if observations >= shared.AnalyzingMinObservations {
			return analyzeDecision{ShouldAnalyze: false, Reason: "minimum observations reached"}
		}
		return analyzeDecision{ShouldAnalyze: true, Reason: "collecting initial observations"}
	}

	profile := resolveProcessProfile(current, processKey)

	// 0. Training label is the strongest signal — commit immediately.
	if profile != nil && profile.TrainingLabel != "" {
		return analyzeDecision{ShouldAnalyze: false, Reason: "model: training label set by operator (" + profile.TrainingLabel + ")"}
	}

	// 0b. Training pattern match — generalized rule from multiple labels.
	if p != nil && current != nil {
		verdict, desc := matchTrainingPatternLocked(current, p, 0, 0, false)
		if verdict != "" {
			return analyzeDecision{ShouldAnalyze: false, Reason: "model: training pattern — " + desc}
		}
	}

	// 1. User verdict is authoritative — commit immediately.
	if profile != nil && profile.UserVerdict == "malicious" {
		return analyzeDecision{ShouldAnalyze: false, Reason: "model: previously confirmed malicious by operator"}
	}
	if profile != nil && profile.UserVerdict == "benign" {
		return analyzeDecision{ShouldAnalyze: false, Reason: "model: previously confirmed benign by operator"}
	}

	// 1b. Strong experience — if model has observed this process 30+ times
	// with stable role, commit quickly.
	if profile != nil && profile.ExperienceObservations >= 30 && profile.RoleStability > 0.85 {
		return analyzeDecision{ShouldAnalyze: false, Reason: "model: strong experience — stable role across " + fmt.Sprintf("%d", profile.ExperienceObservations) + " observations"}
	}

	// 2. Calibration history with strong consensus — commit after fewer observations.
	if profile != nil && profile.CalibrationRuns >= 3 {
		if profile.CalibrationVerdict == "suspicious" {
			// Model has seen this process as suspicious before — commit quickly.
			if observations >= 2 {
				return analyzeDecision{ShouldAnalyze: false, Reason: "model: calibration history indicates suspicious"}
			}
		}
		if profile.CalibrationVerdict == "benign" {
			return analyzeDecision{ShouldAnalyze: false, Reason: "model: calibration history indicates benign"}
		}
	}

	// 3. High runtime stability from prior sessions — the model has strong experience.
	if profile != nil && profile.RuntimeObservations >= 50 && profile.RoleStability > 0.9 {
		if observations >= 2 {
			return analyzeDecision{ShouldAnalyze: false, Reason: "model: high runtime stability from prior experience"}
		}
	}

	// 4. Known vendor processes get accelerated analysis.
	if knownVendor {
		if observations >= 3 {
			return analyzeDecision{ShouldAnalyze: false, Reason: "model: known vendor process, accelerated analysis"}
		}
		return analyzeDecision{ShouldAnalyze: true, Reason: "analyzing known vendor process"}
	}

	// 5. Known network-active processes (svchost SYSTEM, browsers, etc.) — fast track.
	if benignClient && p != nil && shared.IsKnownNetworkActiveProcess(p) {
		if observations >= 2 {
			return analyzeDecision{ShouldAnalyze: false, Reason: "model: known network-active process"}
		}
		return analyzeDecision{ShouldAnalyze: true, Reason: "analyzing known network-active process"}
	}

	// 6. Unknown process with some calibration history.
	if profile != nil && profile.CalibrationRuns >= 1 {
		if observations >= 3 {
			return analyzeDecision{ShouldAnalyze: false, Reason: "model: some calibration history available"}
		}
		return analyzeDecision{ShouldAnalyze: true, Reason: "analyzing process with limited history"}
	}

	// 7. Completely unknown process — require full observation window.
	minObs := shared.AnalyzingMinObservations
	if observations >= minObs {
		return analyzeDecision{ShouldAnalyze: false, Reason: "model: minimum observations reached for unknown process"}
	}

	return analyzeDecision{ShouldAnalyze: true, Reason: "analyzing unknown process identity"}
}
