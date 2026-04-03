package model

import (
	"fmt"

	"proxywatch/internal/shared"
)

// roleDecision is the model's final decision on a process role.
type roleDecision struct {
	Role     string // final role (may differ from suggested)
	Override bool   // true if model changed the role
	Reason   string // why the model made this decision
}

// DecideRole is the model's final authority on role assignment. It receives
// the role suggested by rank.go's signal-based analysis and can override it
// based on accumulated intelligence: training labels, user feedback,
// experience history, and calibration verdicts.
//
// The model only overrides when it has HIGH confidence from prior evidence.
// If the model has no strong opinion, it defers to the signal-based suggestion.
func DecideRole(processKey string, suggestedRole string, score int, p *shared.ProcessInfo, outExternal, outInternal, inboundTotal int, hasListener bool) roleDecision {
	mu.RLock()
	defer mu.RUnlock()

	if current == nil {
		return roleDecision{Role: suggestedRole}
	}

	// Check training patterns (generalized rules from multiple labels).
	if p != nil && len(current.TrainingPatterns) > 0 {
		verdict, desc := matchTrainingPatternLocked(current, p, outExternal, outInternal, hasListener)
		if verdict != "" {
			role := patternVerdictToRole(verdict, suggestedRole)
			if role != suggestedRole {
				return roleDecision{
					Role:     role,
					Override: true,
					Reason:   "model: training pattern — " + desc,
				}
			}
		}
	}

	profile := resolveProcessProfile(current, processKey)
	if profile == nil {
		return roleDecision{Role: suggestedRole}
	}

	// 1. Training label is absolute authority.
	if profile.TrainingLabel != "" {
		labelRole := trainingLabelToRole(profile.TrainingLabel)
		if labelRole != "" && labelRole != suggestedRole {
			return roleDecision{
				Role:     labelRole,
				Override: true,
				Reason:   "model: operator training label (" + profile.TrainingLabel + ")",
			}
		}
		if labelRole != "" {
			return roleDecision{Role: labelRole, Reason: "model: matches training label"}
		}
	}

	// 2. User kill verdict — if operator killed this process identity before,
	// and rank.go is trying to call it benign, override.
	if profile.UserVerdict == "malicious" && !isSuspiciousRole(suggestedRole) {
		// The model remembers this was malicious. If current signals are weak
		// (outbound/listen/analyzing), promote back to the last known bad role.
		if profile.DominantRole != "" && isSuspiciousRole(profile.DominantRole) {
			return roleDecision{
				Role:     profile.DominantRole,
				Override: true,
				Reason:   "model: previously killed — restoring to " + profile.DominantRole,
			}
		}
		return roleDecision{
			Role:     "control-session",
			Override: true,
			Reason:   "model: previously killed by operator",
		}
	}

	// 3. User whitelist verdict — if operator whitelisted and rank.go is
	// flagging it as suspicious, suppress (but NEVER suppress strong evidence).
	if profile.UserVerdict == "benign" && isSuspiciousRole(suggestedRole) && score < 70 {
		return roleDecision{
			Role:     "outbound",
			Override: true,
			Reason:   "model: previously whitelisted by operator",
		}
	}

	// 4. Experience-derived benign verdict — if the model has accumulated
	// enough evidence to conclude this process is benign, demote suspicious
	// roles back to outbound. This is the model learning without hardcoded
	// name lists: after observing a process behave benignly for long enough,
	// it suppresses false positives automatically.
	if profile.CalibrationVerdict == "benign" &&
		isSuspiciousRole(suggestedRole) &&
		!isSuspiciousRole(profile.DominantRole) &&
		profile.ExperienceObservations >= 100 &&
		profile.RoleStability > 0.85 &&
		score < 80 {
		return roleDecision{
			Role:     "outbound",
			Override: true,
			Reason:   fmt.Sprintf("model: learned benign from %d observations (%.0f%% stable as %s)", profile.ExperienceObservations, profile.RoleStability*100, profile.DominantRole),
		}
	}

	// 5. Strong experience consensus — if the model has observed this process
	// 50+ times and 90%+ agree on a role, use that for same-family corrections
	// (e.g., tunnel vs session within suspicious, or outbound vs listen within benign).
	if profile.ExperienceObservations >= 50 && profile.RoleStability > 0.90 {
		expRole := profile.DominantRole
		if expRole != "" && expRole != suggestedRole {
			if isSuspiciousRole(expRole) == isSuspiciousRole(suggestedRole) {
				return roleDecision{
					Role:     expRole,
					Override: true,
					Reason:   "model: experience consensus (" + expRole + " in " + fmt.Sprintf("%d/%d", int(float64(profile.ExperienceObservations)*profile.RoleStability), profile.ExperienceObservations) + " observations)",
				}
			}
		}
	}

	// 6. No strong opinion — defer to signal-based suggestion.
	return roleDecision{Role: suggestedRole}
}

func trainingLabelToRole(label string) string {
	switch label {
	case "malicious", "session":
		return "control-session"
	case "beacon":
		return "control-beacon"
	case "tunnel":
		return "control-tunnel"
	case "benign":
		return "outbound"
	default:
		return ""
	}
}

func patternVerdictToRole(verdict string, suggestedRole string) string {
	switch verdict {
	case "benign":
		return "outbound"
	case "malicious":
		if isSuspiciousRole(suggestedRole) {
			return suggestedRole // keep the specific malicious role
		}
		return "control-session"
	default:
		return suggestedRole
	}
}

func isSuspiciousRole(role string) bool {
	switch role {
	case "control-session", "control-beacon", "control-tunnel", "control-pivot", "analyzing":
		return true
	}
	return false
}
