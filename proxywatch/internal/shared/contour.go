package shared

import "strings"

// ContourHint is a contour-derived signal mapped to a process candidate.
// Calibration can consume these hints to bias tuning toward observed
// exfiltration and egress-escape patterns.
type ContourHint struct {
	CandidateKey string `json:"candidate_key,omitempty"`
	Host         string `json:"host,omitempty"`
	PID          int    `json:"pid,omitempty"`
	Process      string `json:"process,omitempty"`
	Category     string `json:"category,omitempty"`
	Signal       string `json:"signal,omitempty"`
	Reason       string `json:"reason,omitempty"`
	Severity     string `json:"severity,omitempty"`
}

func NormalizeContourSeverity(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "active", "critical", "high":
		return "active"
	case "strong", "medium":
		return "strong"
	default:
		return "watch"
	}
}
