package shared

import (
	"sort"
	"time"
)

type LingerEntry struct {
	Candidate Candidate
	FirstSeen time.Time
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
		if IsProxywatchProcess(c.Proc) {
			delete(*cache, key)
			continue
		}
		seen[key] = struct{}{}
		firstSeen := now
		if entry, ok := (*cache)[key]; ok && !entry.FirstSeen.IsZero() {
			firstSeen = entry.FirstSeen
		}
		c.SeenSeconds = max(0, int(now.Sub(firstSeen).Seconds()))
		(*cache)[key] = LingerEntry{
			Candidate: c,
			FirstSeen: firstSeen,
			LastSeen:  now,
		}
		out = append(out, c)
	}

	for key, entry := range *cache {
		if _, ok := seen[key]; ok {
			continue
		}
		if IsProxywatchProcess(entry.Candidate.Proc) {
			delete(*cache, key)
			continue
		}
		if now.Sub(entry.LastSeen) > lingerKeepFor(entry.Candidate, keepFor) {
			delete(*cache, key)
			continue
		}

		stale := entry.Candidate
		stale.SeenSeconds = max(0, int(now.Sub(entry.FirstSeen).Seconds()))
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

func lingerKeepFor(c Candidate, base time.Duration) time.Duration {
	keep := base
	if keep <= 0 {
		keep = CandidateLingerTTL
	}
	if c.StrongEvidence && CandidateStrongLingerTTL > keep {
		keep = CandidateStrongLingerTTL
	}
	if IsControlChannelRole(c.Role) && CandidateSuspiciousLingerTTL > keep {
		keep = CandidateSuspiciousLingerTTL
	}
	return keep
}

