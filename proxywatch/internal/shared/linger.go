package shared

import (
	"sort"
	"time"
)

type LingerEntry struct {
	Candidate Candidate
	LastSeen  time.Time
}

// ApplyCandidateLinger keeps recently seen candidates visible for keepFor.
// This preserves short-lived process visibility in the UI without altering classifier output.
func ApplyCandidateLinger(current []Candidate, now time.Time, keepFor time.Duration, cache *map[string]LingerEntry) []Candidate {
	if keepFor <= 0 || cache == nil {
		sort.Slice(current, func(i, j int) bool { return CandidateLess(current[i], current[j]) })
		return current
	}

	if *cache == nil {
		*cache = make(map[string]LingerEntry, len(current))
	}

	out := make([]Candidate, 0, len(current)+len(*cache))
	seen := make(map[string]struct{}, len(current))

	for _, c := range current {
		key := CandidateKey(c)
		seen[key] = struct{}{}
		(*cache)[key] = LingerEntry{
			Candidate: c,
			LastSeen:  now,
		}
		out = append(out, c)
	}

	for key, entry := range *cache {
		if _, ok := seen[key]; ok {
			continue
		}
		if now.Sub(entry.LastSeen) > keepFor {
			delete(*cache, key)
			continue
		}

		stale := entry.Candidate
		if stale.Proc != nil {
			stale.Proc.IOReadBps = 0
			stale.Proc.IOWriteBps = 0
			stale.Proc.IOOtherBps = 0
		}
		stale.ActiveProxying = false
		out = append(out, stale)
	}

	sort.Slice(out, func(i, j int) bool { return CandidateLess(out[i], out[j]) })
	return out
}
