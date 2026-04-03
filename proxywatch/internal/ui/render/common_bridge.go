package render

import (
	"proxywatch/internal/shared"
	"proxywatch/internal/ui/common"
)

// commonSortedCandidates delegates to common.SortedCandidates.
func commonSortedCandidates(cands []shared.Candidate, preset string) []shared.Candidate {
	return common.SortedCandidates(cands, preset)
}
