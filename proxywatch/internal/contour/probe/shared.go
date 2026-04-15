package probe

import (
	"sort"
	"strings"

	"proxywatch/internal/shared"
)

// Finding represents a single contour finding.
type Finding struct {
	CandidateKey string         `json:"candidate_key"`
	Host         string         `json:"host"`
	PID          int            `json:"pid"`
	Process      string         `json:"process"`
	Role         string         `json:"role"`
	Category     string         `json:"category"`
	Technique    string         `json:"technique"`
	Severity     string         `json:"severity"`
	Signal       string         `json:"signal"`
	Reason       string         `json:"reason"`
	Evidence     map[string]any `json:"evidence,omitempty"`
}

// Plural returns "s" when n != 1.
func Plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// NonEmpty returns v if non-blank, else fallback.
func NonEmpty(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

// SeverityPriority returns an integer priority for a severity string.
func SeverityPriority(severity string) int {
	switch shared.NormalizeContourSeverity(severity) {
	case "active":
		return 3
	case "strong":
		return 2
	default:
		return 1
	}
}

// NormalizeFindings deduplicates and sorts findings by severity.
func NormalizeFindings(findings []Finding) []Finding {
	if len(findings) <= 1 {
		return findings
	}
	sort.SliceStable(findings, func(i, j int) bool {
		si := SeverityPriority(findings[i].Severity)
		sj := SeverityPriority(findings[j].Severity)
		if si != sj {
			return si > sj
		}
		if findings[i].Host != findings[j].Host {
			return findings[i].Host < findings[j].Host
		}
		if findings[i].Process != findings[j].Process {
			return findings[i].Process < findings[j].Process
		}
		if findings[i].PID != findings[j].PID {
			return findings[i].PID < findings[j].PID
		}
		return findings[i].Signal < findings[j].Signal
	})
	return dedupeFindings(findings)
}

func dedupeFindings(findings []Finding) []Finding {
	if len(findings) <= 1 {
		return findings
	}
	out := make([]Finding, 0, len(findings))
	seen := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		key := finding.CandidateKey + "|" + finding.Signal
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, finding)
	}
	return out
}
