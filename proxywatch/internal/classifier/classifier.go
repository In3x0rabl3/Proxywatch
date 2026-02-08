package classifier

import (
	"sort"
	"time"

	"proxywatch/internal/shared"
)

// Classify converts a telemetry snapshot into classified candidates.
func Classify(
	snap *shared.Snapshot,
	opts shared.ClassifyOptions,
	cache *shared.ClassifierCache,
) []shared.Candidate {

	candidates := buildCandidates(snap)
	now := time.Now()

	var (
		nextCandidates map[int]shared.Candidate
		nextSignatures map[int]shared.CandidateSignature
	)
	if opts.Incremental && cache != nil {
		nextCandidates = make(map[int]shared.Candidate, len(candidates))
		nextSignatures = make(map[int]shared.CandidateSignature, len(candidates))
	}

	var interesting []shared.Candidate
	for i := range candidates {
		c := &candidates[i]
		if opts.Incremental && cache != nil {
			sig := candidateSignature(*c)
			prevCands := cache.Candidates
			prevSigs := cache.Signatures
			if prevCands != nil && prevSigs != nil {
				if prev, ok := prevCands[c.Proc.Pid]; ok {
					if prevSig, ok := prevSigs[c.Proc.Pid]; ok && prevSig == sig {
						reuseCandidate(c, &prev)
						touchHistoryFromCandidate(c, now)
					} else {
						ScoreCandidate(c)
					}
				} else {
					ScoreCandidate(c)
				}
			} else {
				ScoreCandidate(c)
			}

			nextSignatures[c.Proc.Pid] = sig
			nextCandidates[c.Proc.Pid] = *c
		} else {
			ScoreCandidate(c)
		}

		if !shouldDisplayCandidate(c, now) {
			continue
		}

		if !shared.RoleMatchesFilter(c.Role, opts.RoleFilter) {
			continue
		}

		if c.Score >= opts.MinScore || shared.IsControlChannelRole(c.Role) {
			interesting = append(interesting, *c)
		}
	}

	if opts.Incremental && cache != nil {
		cache.Candidates = nextCandidates
		cache.Signatures = nextSignatures
	}

	sort.Slice(interesting, func(i, j int) bool {
		return shared.CandidateLess(interesting[i], interesting[j])
	})

	return interesting
}

func buildCandidates(snap *shared.Snapshot) []shared.Candidate {
	now := snap.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}

	lmap := make(map[int][]shared.ListenerInfo)
	for _, l := range snap.Listeners {
		lmap[l.Pid] = append(lmap[l.Pid], l)
	}

	cmap := make(map[int][]shared.ConnectionInfo)
	for _, c := range snap.Connections {
		cmap[c.Pid] = append(cmap[c.Pid], c)
	}

	umap := make(map[int][]shared.UDPListenerInfo)
	for _, u := range snap.UDPListeners {
		umap[u.Pid] = append(umap[u.Pid], u)
	}

	seen := make(map[int]bool)
	for pid := range lmap {
		seen[pid] = true
	}
	for pid := range cmap {
		seen[pid] = true
	}
	for pid := range umap {
		seen[pid] = true
	}
	seedConnHistoryFromSnapshot(cmap, now)
	delegated := correlateDelegatedEgress(snap, cmap, seen, now)

	for pid, t := range shared.BeaconSeen {
		if now.Sub(t) <= shared.SuspicionWindow {
			seen[pid] = true
		}
	}

	var out []shared.Candidate
	for pid := range seen {
		proc := snap.Processes[pid]
		if proc == nil {
			continue
		}

		out = append(out, shared.Candidate{
			Proc:              proc,
			Listeners:         lmap[pid],
			Conns:             cmap[pid],
			UDPListeners:      umap[pid],
			DelegatedEgress:   delegated[pid].ownerPID > 0,
			DelegatedStrong:   delegated[pid].strong,
			DelegatedOwnerPID: delegated[pid].ownerPID,
			DelegatedOwner:    delegated[pid].ownerName,
		})
	}

	return out
}
