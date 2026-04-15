package model

import (
	"fmt"
	"strings"
	"time"

	"proxywatch/internal/shared"
)

const (
	minLabelsForPattern = 3  // need 3+ agreeing labels to form a pattern
	maxTrainingPatterns = 50 // cap total patterns
	patternMaxAgeDays   = 90 // prune patterns not matched in 90 days
)

type patternLabelInfo struct {
	key     string
	profile *ProcessProfile
}

// MatchTrainingPattern checks if a process matches any training pattern.
// Returns the verdict and pattern description if matched, empty string if not.
// Acquires read lock — do NOT call from code that already holds the lock.
func MatchTrainingPattern(p *shared.ProcessInfo, outExternal, outInternal, inboundTotal int, hasListener bool) (verdict string, description string) {
	mu.RLock()
	defer mu.RUnlock()
	if current == nil || len(current.TrainingPatterns) == 0 || p == nil {
		return "", ""
	}
	return matchTrainingPatternLocked(current, p, outExternal, outInternal, hasListener)
}

// matchTrainingPatternLocked is the lock-free internal version.
// Caller must already hold mu.RLock or mu.Lock.
func matchTrainingPatternLocked(m *DetectionModel, p *shared.ProcessInfo, outExternal, outInternal int, hasListener bool) (verdict string, description string) {
	if m == nil || len(m.TrainingPatterns) == 0 || p == nil {
		return "", ""
	}

	path := shared.NormalizeExePath(p.ExePath)
	company := strings.ToLower(strings.TrimSpace(p.Company))
	userCtx := "user"
	if shared.IsServiceLikeContext(p) {
		userCtx = "system"
	}
	externalOnly := outExternal > 0 && outInternal == 0

	for i := range m.TrainingPatterns {
		pat := &m.TrainingPatterns[i]
		if pat.Confidence < 0.5 {
			continue
		}
		if !patternMatches(pat, path, company, userCtx, hasListener, externalOnly) {
			continue
		}
		pat.LastMatched = time.Now().UTC()
		return pat.Verdict, pat.Description
	}
	return "", ""
}

func patternMatches(pat *TrainingPattern, path, company, userCtx string, hasListener, externalOnly bool) bool {
	if pat.PathPrefix != "" && !strings.HasPrefix(path, pat.PathPrefix) {
		return false
	}
	if pat.UserContext != "" && pat.UserContext != userCtx {
		return false
	}
	if pat.Company != "" && !strings.Contains(company, pat.Company) {
		return false
	}
	if pat.HasListener != nil && *pat.HasListener != hasListener {
		return false
	}
	if pat.ExternalOnly != nil && *pat.ExternalOnly != externalOnly {
		return false
	}
	return true
}

// extractPatterns analyzes all training labels in the model and creates
// generalized patterns from common traits. Called after every training label
// change and periodically during runtime.
func extractPatterns() {
	mu.Lock()
	defer mu.Unlock()
	if current == nil {
		return
	}

	// Group training labels by verdict.
	benignLabels := make([]patternLabelInfo, 0)
	maliciousLabels := make([]patternLabelInfo, 0)

	for key, profile := range current.Processes {
		if profile == nil || profile.TrainingLabel == "" {
			continue
		}
		info := patternLabelInfo{key: key, profile: profile}
		switch profile.TrainingLabel {
		case "benign":
			benignLabels = append(benignLabels, info)
		case "malicious", "session", "beacon", "tunnel", "pivot":
			maliciousLabels = append(maliciousLabels, info)
		}
	}

	var patterns []TrainingPattern

	// Extract patterns from operator labels.
	if bp := extractVerdictPatterns(benignLabels, "benign"); len(bp) > 0 {
		patterns = append(patterns, bp...)
	}
	if mp := extractVerdictPatterns(maliciousLabels, "malicious"); len(mp) > 0 {
		patterns = append(patterns, mp...)
	}

	// Extract patterns from experience-derived verdicts (automated).
	// Profiles with high stability and consistent dominant role can generate
	// patterns without operator labels — the model learns from observation.
	if ep := extractExperiencePatterns(current); len(ep) > 0 {
		patterns = append(patterns, ep...)
	}

	// Prune old patterns and cap.
	now := time.Now().UTC()
	cutoff := now.Add(-patternMaxAgeDays * 24 * time.Hour)
	var kept []TrainingPattern
	for _, p := range patterns {
		if !p.LastMatched.IsZero() && p.LastMatched.Before(cutoff) {
			continue
		}
		kept = append(kept, p)
	}
	if len(kept) > maxTrainingPatterns {
		kept = kept[:maxTrainingPatterns]
	}

	current.TrainingPatterns = kept
	markDirty()
}

func extractVerdictPatterns(labels []patternLabelInfo, verdict string) []TrainingPattern {
	if len(labels) < minLabelsForPattern {
		return nil
	}

	var patterns []TrainingPattern

	// Find common path prefixes and user contexts.
	type prefixInfo struct {
		count int
	}
	prefixCounts := make(map[string]*prefixInfo)
	userCtxCounts := make(map[string]int)

	for _, li := range labels {
		// Extract path prefix (directory portion).
		path := shared.NormalizeExePath(li.profile.Name)
		// Use the key which has the full path.
		parts := strings.SplitN(li.key, "|", 4)
		if len(parts) >= 2 {
			path = parts[1] // host|PATH|name|user
		}
		if idx := strings.LastIndex(path, "/"); idx > 0 {
			prefix := path[:idx+1]
			pi := prefixCounts[prefix]
			if pi == nil {
				pi = &prefixInfo{}
				prefixCounts[prefix] = pi
			}
			pi.count++
		}

		userCtx := "user"
		if len(parts) >= 4 {
			user := strings.ToLower(parts[3])
			if strings.Contains(user, "system") || strings.Contains(user, "local service") || strings.Contains(user, "network service") {
				userCtx = "system"
			}
		}
		userCtxCounts[userCtx]++
	}

	now := time.Now().UTC()

	// Pattern from common path prefix.
	for prefix, pi := range prefixCounts {
		if pi.count < minLabelsForPattern {
			continue
		}
		confidence := float64(pi.count) / float64(len(labels))
		if confidence < 0.6 {
			continue
		}
		patterns = append(patterns, TrainingPattern{
			ID:          fmt.Sprintf("path-%s-%s", verdict, sanitizePatternID(prefix)),
			Verdict:     verdict,
			Confidence:  confidence,
			MatchCount:  pi.count,
			CreatedAt:   now,
			LastMatched: now,
			PathPrefix:  prefix,
			Description: fmt.Sprintf("Processes from %s labeled %s by operator (%d examples)", prefix, verdict, pi.count),
		})
	}

	// Pattern from common user context.
	for ctx, count := range userCtxCounts {
		if count < minLabelsForPattern || count < len(labels) {
			continue // only create pattern if ALL labels share this context
		}
		patterns = append(patterns, TrainingPattern{
			ID:          fmt.Sprintf("ctx-%s-%s", verdict, ctx),
			Verdict:     verdict,
			Confidence:  0.7,
			MatchCount:  count,
			CreatedAt:   now,
			LastMatched: now,
			UserContext: ctx,
			Description: fmt.Sprintf("Processes running as %s labeled %s by operator (%d examples)", ctx, verdict, count),
		})
	}

	return patterns
}

// extractExperiencePatterns creates patterns from profiles that have been
// auto-classified with high stability through observation — no operator labels
// required. This allows the model to learn and generalize from its own experience.
func extractExperiencePatterns(m *DetectionModel) []TrainingPattern {
	if m == nil {
		return nil
	}

	// Group profiles by dominant role, only for suspicious roles with
	// high stability and enough observations.
	type expInfo struct {
		key     string
		profile *ProcessProfile
	}
	roleGroups := make(map[string][]expInfo)

	for key, profile := range m.Processes {
		if profile == nil || profile.TrainingLabel != "" {
			continue // skip labeled profiles — handled by extractVerdictPatterns
		}
		if profile.ExperienceObservations < 100 || profile.RoleStability < 0.80 {
			continue // not enough data or not stable enough
		}
		dominant := profile.DominantRole
		if dominant == "" || !isSuspiciousRole(dominant) {
			continue // only create patterns for suspicious roles
		}
		roleGroups[dominant] = append(roleGroups[dominant], expInfo{key: key, profile: profile})
	}

	now := time.Now().UTC()
	var patterns []TrainingPattern

	for role, group := range roleGroups {
		if len(group) < minLabelsForPattern {
			continue
		}

		// Find common path prefixes.
		prefixCounts := make(map[string]int)
		for _, ei := range group {
			parts := strings.SplitN(ei.key, "|", 4)
			if len(parts) >= 2 {
				path := parts[1]
				if idx := strings.LastIndex(path, "/"); idx > 0 {
					prefixCounts[path[:idx+1]]++
				}
			}
		}

		for prefix, count := range prefixCounts {
			if count < minLabelsForPattern {
				continue
			}
			confidence := float64(count) / float64(len(group)) * 0.6 // lower confidence than operator labels
			if confidence < 0.3 {
				continue
			}
			patterns = append(patterns, TrainingPattern{
				ID:          fmt.Sprintf("exp-%s-%s", role, sanitizePatternID(prefix)),
				Verdict:     "malicious",
				Confidence:  confidence,
				MatchCount:  count,
				CreatedAt:   now,
				LastMatched: now,
				PathPrefix:  prefix,
				Description: fmt.Sprintf("Experience: %d processes from %s consistently classified as %s", count, prefix, role),
			})
		}
	}

	return patterns
}

func sanitizePatternID(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, "\\", "-")
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, " ", "-")
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}
