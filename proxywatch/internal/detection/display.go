package classifier

import (
	"strings"
	"time"

	"proxywatch/internal/shared"
)

const (
	stableDisplayMinScans = 2
	stableDisplayResetGap = 2 * time.Second
)

func shouldDisplayCandidate(c *shared.Candidate, now time.Time) bool {
	if c == nil || c.Proc == nil {
		return false
	}

	hist := getHistory(historyPIDForCandidate(c), now)
	if (c.Role == "control-session" || c.Role == "control-beacon") && shouldDelayWeakSession(c) {
		if !hist.LastDisplayEval.IsZero() && now.Sub(hist.LastDisplayEval) > stableDisplayResetGap {
			hist.DisplayStreak = 0
		}
		hist.LastDisplayEval = now
		hist.DisplayStreak++
		return hist.DisplayStreak >= stableDisplayMinScans
	}
	if shared.IsControlRole(c.Role) {
		hist.DisplayStreak = 0
		hist.LastDisplayEval = now
		return true
	}

	// Keep high-signal process views responsive.
	if c.Score >= 55 || c.ActiveProxying || c.DelegatedEgress || c.DelegatedStrong {
		hist.DisplayStreak = 0
		hist.LastDisplayEval = now
		return true
	}
	if shouldShowImmediateUserEgress(c) {
		hist.DisplayStreak = 0
		hist.LastDisplayEval = now
		return true
	}

	if !hist.LastDisplayEval.IsZero() && now.Sub(hist.LastDisplayEval) > stableDisplayResetGap {
		hist.DisplayStreak = 0
	}
	hist.LastDisplayEval = now
	hist.DisplayStreak++
	return hist.DisplayStreak >= stableDisplayMinScans
}

func shouldDelayWeakSession(c *shared.Candidate) bool {
	if c == nil {
		return false
	}
	if c.DelegatedStrong || c.StrongEvidence || c.ActiveProxying {
		return false
	}
	if c.OutInternal > 0 {
		return false
	}
	// Mature control channels are likely real sessions; show immediately.
	if c.ControlDurationSeconds >= 20 {
		return false
	}
	return true
}

func shouldShowImmediateUserEgress(c *shared.Candidate) bool {
	if c == nil || c.Proc == nil {
		return false
	}
	if shared.IsLikelyBenignControlClient(c.Proc) {
		return false
	}
	if c.OutTotal <= 0 && !c.DelegatedEgress {
		return false
	}

	path := shared.NormalizeExePath(c.Proc.ExePath)
	if path == "" {
		return false
	}
	if strings.HasPrefix(path, "c:/users/") ||
		strings.HasPrefix(path, "/home/") ||
		strings.Contains(path, "/downloads/") ||
		strings.Contains(path, "/desktop/") ||
		strings.Contains(path, "/appdata/local/temp/") ||
		strings.Contains(path, "/appdata/roaming/") ||
		strings.Contains(path, "/tmp/") ||
		strings.Contains(path, "/var/tmp/") {
		return true
	}
	return false
}
