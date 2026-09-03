package model

import (
	"fmt"
	"strings"

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

	// Check training patterns — but NEVER let a "benign" pattern override
	// a suspicious detection. Detection signals must always win.
	if !isSuspiciousRole(suggestedRole) {
		if d, ok := applyTrainingPatterns(suggestedRole, p, outExternal, outInternal, hasListener); ok {
			return d
		}
	}

	profile := resolveProcessProfile(current, processKey)
	if profile == nil {
		// Brand new process with no profile — analyze before classifying.
		return roleDecision{
			Role:     "analyzing",
			Override: true,
			Reason:   "model: new process — collecting initial data",
		}
	}

	// 0. Brief analysis period — hold new processes as "analyzing" for a few
	// observations before committing a role. But if the rule engine already
	// detects a suspicious role, skip the hold — speed matters for active threats.
	if profile.ExperienceObservations < 5 &&
		profile.TrainingLabel == "" &&
		profile.UserVerdict == "" &&
		!isSuspiciousRole(suggestedRole) {
		return roleDecision{
			Role:     "analyzing",
			Override: true,
			Reason:   fmt.Sprintf("model: collecting evidence (%d/5 observations)", profile.ExperienceObservations),
		}
	}

	// 1-3. Training label, kill verdict, whitelist verdict (shared with ApplyOperatorOverrides).
	if d, ok := applyOperatorVerdicts(profile, suggestedRole, score); ok {
		return d
	}

	// 4. Role commitment — once the model has committed a role, hold it to
	// prevent flip-flop. BUT: never suppress a suspicious role when the rule
	// engine has strong evidence. A committed "outbound" must NOT block
	// detection of a beacon/session/tunnel — APTs can inject into any process.
	if profile.ExperienceObservations >= 30 && profile.ExperienceLastRole != "" {
		committed := profile.ExperienceLastRole
		if committed != "analyzing" && committed != "" {
			// Always allow the rule engine's role through when:
			// - Committed benign but suggested suspicious (detection found something)
			// - Both suspicious but different (classification refining)
			// - Committed suspicious but suggested benign (corroboration failed)
			if isSuspiciousRole(suggestedRole) {
				// Don't hold — let suspicious detection through.
			} else if isSuspiciousRole(committed) && !isSuspiciousRole(suggestedRole) {
				// Don't hold — rule engine demoted (corroboration failed).
			} else {
				// Both committed and suggested are benign — hold committed role
				// UNLESS current behavior clearly contradicts it.
				//
				// Listener presence is OS-level ground truth: if the kernel
				// reports a bound port for this PID, the process IS listening,
				// regardless of whether anyone has connected yet. A committed
				// "outbound" process that suddenly has a listener (`nc -lnvp`,
				// `python -m http.server`, ssh -D, etc.) must surface as
				// listen / beacon-* — the rule engine already classified it
				// from the live network state, and overriding that with stale
				// memory hides legitimate role transitions.
				behaviorContradicts := false
				if committed == "outbound" && hasListener {
					behaviorContradicts = true
				}
				// Conversely, a committed "listener" process that no longer
				// has any listener is no longer a listener. Drop the committed
				// role regardless of outbound activity (a process can stop
				// listening without ever making external connections).
				if (committed == "listener" || committed == "listen") && !hasListener {
					behaviorContradicts = true
				}
				// Tunnel shape: a committed-benign process now showing
				// external + heavy internal connection topology is exhibiting
				// pivot behavior (e.g. a beacon multiplexing lateral movement
				// through its C2 channel). Don't let the model hold "outbound"
				// when the live network shape is clearly a relay.
				if committed == "outbound" && outExternal > 0 && outInternal >= 5 {
					behaviorContradicts = true
				}
				dominantChanged := profile.DominantRole != "" &&
					profile.DominantRole != committed &&
					profile.RoleStability > 0.50
				if !dominantChanged && !behaviorContradicts {
					return roleDecision{
						Role:     committed,
						Override: true,
						Reason:   fmt.Sprintf("model: holding committed role (%s)", committed),
					}
				}
			}
		}
	}

	// 5. No auto-demotion of suspicious roles. If the rule engine detects
	// suspicious behavior, the model must NOT suppress it based on past
	// "benign" observations. APTs can inject into any process at any time.
	// Only operator verdicts (kill/whitelist/label) can override detection.
	if false { // removed — benign calibration must never suppress detection
	}

	// 5. Analyzing hold — when the model hasn't collected enough evidence,
	// hold as "analyzing" with NO exceptions. No score bypasses, no shortcuts.
	// The model must earn its confidence through sustained observation.
	if profile.CalibrationVerdict != "suspicious" &&
		profile.UserVerdict == "" &&
		profile.TrainingLabel == "" {
		minObs := 200
		if p != nil && strings.TrimSpace(p.Company) != "" {
			minObs = 500
		}
		if isSuspiciousRole(suggestedRole) && profile.ExperienceObservations < minObs {
			return roleDecision{
				Role:     "analyzing",
				Override: true,
				Reason:   fmt.Sprintf("model: collecting evidence (%d/%d observations)", profile.ExperienceObservations, minObs),
			}
		}
	}

	// 6. Experience-derived suspicious promotion — if rank.go suggests a
	// non-suspicious role but the model has accumulated evidence this process
	// is suspicious, promote to the dominant suspicious role.
	//
	// Guard: requires calibration verdict "suspicious" OR 200+ observations
	// to prevent self-reinforcing FP loops where early false detections
	// accumulate in experience and then promote indefinitely.
	//
	// Three promotion paths (first match wins):
	// (a) Confirmed beacon in model — immediate promotion regardless of ratio.
	// (b) Ratio-based — 30%+ suspicious observations (50% if whitelisted).
	// (c) Absolute count — 5+ suspicious observations regardless of ratio.
	canPromote := profile.UserVerdict == "malicious"
	// Experience-based promotion only when operator confirmed malicious.
	// Automatic experience promotion creates self-reinforcing FP loops
	// where early false detections lock in forever.
	if canPromote && !isSuspiciousRole(suggestedRole) && profile.UserVerdict != "benign" {
		suspCount := 0
		for role, count := range profile.ExperienceRoles {
			if isSuspiciousRole(role) {
				suspCount += count
			}
		}

		// (a) Confirmed beacon — the cadence was validated, low ratio is expected.
		if profile.BeaconIntervalMs > 0 &&
			!profile.BeaconConfirmedAt.IsZero() &&
			suspCount > 0 {
			beaconRole := "beacon"
			if profile.DominantRole != "" && isSuspiciousRole(profile.DominantRole) {
				beaconRole = profile.DominantRole
			}
			return roleDecision{
				Role:     beaconRole,
				Override: true,
				Reason:   fmt.Sprintf("model: confirmed beacon (interval %s) — %d suspicious observations", fmtInterval(profile.BeaconIntervalMs), suspCount),
			}
		}

		// (b) Ratio-based promotion.
		minObs := 100
		if score >= 50 {
			minObs = 20
		} else if score >= 30 {
			minObs = 50
		}
		if isSuspiciousRole(profile.DominantRole) &&
			profile.ExperienceObservations >= minObs &&
			profile.ExperienceObservations > 0 {
			suspRatio := float64(suspCount) / float64(profile.ExperienceObservations)
			minRatio := 0.30
			if profile.UserVerdict == "benign" {
				minRatio = 0.50
			}
			if suspRatio > minRatio {
				return roleDecision{
					Role:     profile.DominantRole,
					Override: true,
					Reason:   fmt.Sprintf("model: experience-derived — %d%% of %d observations as %s", int(suspRatio*100), profile.ExperienceObservations, profile.DominantRole),
				}
			}
		}

		// (c) Absolute count — catches intermittent/long-interval patterns.
		if suspCount >= 5 && isSuspiciousRole(profile.DominantRole) {
			return roleDecision{
				Role:     profile.DominantRole,
				Override: true,
				Reason:   fmt.Sprintf("model: recurring suspicious activity — %d observations as %s", suspCount, profile.DominantRole),
			}
		}
	}

	// 7. Model authority — the model's dominant role overrides rank.go's
	// suggestion when the model has enough data. The model is the final
	// authority on role assignment, not signal-based analysis.
	// Within-family corrections (e.g., session vs beacon) need a simple
	// majority (>50%). Cross-family corrections need stronger evidence (>70%).
	//
	// CRITICAL: Never let the model downgrade a suspicious suggestion to a
	// benign role based on historical observations. APTs can inject into
	// previously-benign processes at any time — the rule engine's live
	// topology analysis must always be trusted over stale benign history.
	// Upgrade from benign → suspicious is allowed (experience promotion).
	if profile.ExperienceObservations >= 50 && profile.DominantRole != "" && profile.DominantRole != suggestedRole {
		expRole := profile.DominantRole
		suggestedSuspicious := isSuspiciousRole(suggestedRole)
		expSuspicious := isSuspiciousRole(expRole)
		// Listener-state transitions are OS-level ground truth, not
		// historical inference. If the kernel reports a bound port and
		// the rule engine suggested listen / beacon-* accordingly, the
		// model's stale dominant role (e.g. an outbound history from
		// before this PID started binding a port, or a PID-reuse
		// transition) must not override. Same in reverse for a process
		// that has stopped listening. Without these gates, a process
		// like `nc -lnvp 666` whose past 200+ observations were
		// recorded as outbound stays locked at outbound forever even
		// while it actively listens — a self-reinforcing FP loop.
		listenerStateContradicts := false
		if hasListener && (suggestedRole == "listen" || suggestedRole == "listener") &&
			(expRole == "outbound") {
			listenerStateContradicts = true
		}
		if !hasListener && (expRole == "listen" || expRole == "listener") &&
			suggestedRole == "outbound" {
			listenerStateContradicts = true
		}
		// Block downgrade: rule engine says suspicious, history says benign.
		if suggestedSuspicious && !expSuspicious {
			// Skip model authority — trust the live suspicious detection.
		} else if listenerStateContradicts {
			// Skip model authority — listener state is observable now.
		} else {
			sameFamily := expSuspicious == suggestedSuspicious
			minStability := 0.70 // cross-family needs stronger evidence
			if sameFamily {
				minStability = 0.50 // within-family just needs majority
			}
			if profile.RoleStability > minStability {
				return roleDecision{
					Role:     expRole,
					Override: true,
					Reason:   fmt.Sprintf("model: %s (%d%% of %d observations)", expRole, int(profile.RoleStability*100), profile.ExperienceObservations),
				}
			}
		}
	}

	// 9. No strong opinion — defer to signal-based suggestion.
	return roleDecision{Role: suggestedRole}
}

func trainingLabelToRole(label string) string {
	switch label {
	// New taxonomy — label IS the role.
	case "outbound", "listener", "beacon", "pivot":
		return label
	// Legacy label names — map to new roles.
	case "benign":
		return "outbound"
	case "malicious", "session":
		return "beacon"
	case "tunnel":
		return "pivot"
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
		return "beacon"
	default:
		return suggestedRole
	}
}

func fmtInterval(ms int) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	secs := ms / 1000
	if secs < 60 {
		return fmt.Sprintf("%ds", secs)
	}
	if secs < 3600 {
		return fmt.Sprintf("%dm%ds", secs/60, secs%60)
	}
	return fmt.Sprintf("%dh%dm", secs/3600, (secs%3600)/60)
}

func isSuspiciousRole(role string) bool {
	switch role {
	case "beacon", "pivot", "tunnel", "smb-pipe", "session":
		return true
	}
	return false
}

// ApplyOperatorOverrides applies operator-authority overrides on top of an
// ML-assigned role. This is the simplified version of DecideRole used when
// the ML model is the primary role assigner. It only applies:
//   - Training patterns (generalized from 3+ operator labels)
//   - Training labels (operator-assigned, absolute authority)
//   - Kill verdict (previously killed → restore malicious role)
//   - Whitelist verdict (previously whitelisted → suppress if score < 70)
//
// Experience-derived promotions, analyzing holds, and calibration overrides
// are the ML model's responsibility and are NOT applied here.
func ApplyOperatorOverrides(processKey string, assignedRole string, score int, p *shared.ProcessInfo, outExternal, outInternal int, hasListener bool) roleDecision {
	mu.RLock()
	defer mu.RUnlock()

	if current == nil {
		return roleDecision{Role: assignedRole}
	}

	// Training patterns.
	// Training patterns must not override suspicious ML assignments.
	if !isSuspiciousRole(assignedRole) {
		if d, ok := applyTrainingPatterns(assignedRole, p, outExternal, outInternal, hasListener); ok {
			return d
		}
	}

	profile := resolveProcessProfile(current, processKey)
	if profile == nil {
		// No profile yet — model classifies immediately, no analyzing hold.
		return roleDecision{Role: assignedRole}
	}

	// Operator overrides: training labels, kill/whitelist verdicts.
	// These are the ONLY things that override the model's prediction.
	if d, ok := applyOperatorVerdicts(profile, assignedRole, score); ok {
		return d
	}

	return roleDecision{Role: assignedRole}
}

// applyTrainingPatterns checks generalized rules from operator labels.
// Returns (decision, true) if a pattern matched, or (_, false) to continue.
// Caller must hold mu.RLock.
func applyTrainingPatterns(role string, p *shared.ProcessInfo, outExternal, outInternal int, hasListener bool) (roleDecision, bool) {
	if p == nil || len(current.TrainingPatterns) == 0 {
		return roleDecision{}, false
	}
	verdict, desc := matchTrainingPatternLocked(current, p, outExternal, outInternal, hasListener)
	if verdict == "" {
		return roleDecision{}, false
	}
	mapped := patternVerdictToRole(verdict, role)
	if mapped != role {
		return roleDecision{
			Role:     mapped,
			Override: true,
			Reason:   "model: training pattern — " + desc,
		}, true
	}
	return roleDecision{}, false
}

// applyOperatorVerdicts applies training labels, kill, and whitelist verdicts.
// Returns (decision, true) if an override applied, or (_, false) to continue.
func applyOperatorVerdicts(profile *ProcessProfile, role string, score int) (roleDecision, bool) {
	// Training label — absolute operator authority.
	if profile.TrainingLabel != "" {
		labelRole := trainingLabelToRole(profile.TrainingLabel)
		if labelRole != "" && labelRole != role {
			return roleDecision{
				Role:     labelRole,
				Override: true,
				Reason:   "model: operator training label (" + profile.TrainingLabel + ")",
			}, true
		}
		if labelRole != "" {
			return roleDecision{Role: labelRole, Reason: "model: matches training label"}, true
		}
	}

	// Kill verdict — operator killed this process identity before.
	if profile.UserVerdict == "malicious" && !isSuspiciousRole(role) {
		if profile.DominantRole != "" && isSuspiciousRole(profile.DominantRole) {
			return roleDecision{
				Role:     profile.DominantRole,
				Override: true,
				Reason:   "model: previously killed — restoring to " + profile.DominantRole,
			}, true
		}
		return roleDecision{
			Role:     "beacon",
			Override: true,
			Reason:   "model: previously killed by operator",
		}, true
	}

	// Whitelist verdict — operator whitelisted, suppress if not strong evidence.
	if profile.UserVerdict == "benign" && isSuspiciousRole(role) && score < 70 {
		return roleDecision{
			Role:     "outbound",
			Override: true,
			Reason:   "model: previously whitelisted by operator",
		}, true
	}

	return roleDecision{}, false
}
