package detection

import (
	"time"

	"proxywatch/internal/detection/scoring"
	"proxywatch/internal/shared"
)

const (
	// Minimum scoring cycles before a process appears in the dashboard.
	// Set to 1 so processes show on the first scan — the role filter
	// already excludes uninteresting processes.
	minDisplayObservations = 1
)

// shouldDisplayCandidate returns true when a process has been observed
// enough times to be worth showing. Prevents transient system processes
// (service workers, update checks) from popping up for a single frame.
func shouldDisplayCandidate(c *shared.Candidate, _ time.Time) bool {
	if c == nil || c.Proc == nil {
		return false
	}

	// Exited/lingering processes always show.
	if c.Exited {
		return true
	}

	// Require a few observations before displaying.
	hist := scoring.GetHistory(scoring.HistoryPIDForCandidate(c), time.Now())
	hist.DisplayStreak++
	return hist.DisplayStreak >= minDisplayObservations
}
