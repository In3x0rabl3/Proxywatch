package classifier

import (
	"sort"

	"proxywatch/internal/shared"
)

// ClassifyAllForCalibration scores every buildable candidate from a snapshot,
// without display-gating/min-score filtering used by interactive views.
func ClassifyAllForCalibration(snap *shared.Snapshot) []shared.Candidate {
	if snap == nil {
		return nil
	}
	candidates := buildCandidates(snap)
	refreshObservedExternalPortProfile(candidates)
	for i := range candidates {
		ScoreCandidate(&candidates[i])
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return shared.CandidateLess(candidates[i], candidates[j])
	})
	return candidates
}
