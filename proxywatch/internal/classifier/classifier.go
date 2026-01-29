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

		if len(opts.RoleFilter) > 0 {
			if _, ok := opts.RoleFilter[c.Role]; !ok {
				continue
			}
		}

		if c.Score >= opts.MinScore || c.Role == "reverse-control" || c.Role == "reverse-transport" || c.Role == "susp-tun" || c.Role == "susp-session" || c.Role == "susp-beacon" {
			interesting = append(interesting, *c)
		}
	}

	if opts.Incremental && cache != nil {
		cache.Candidates = nextCandidates
		cache.Signatures = nextSignatures
	}

	sort.Slice(interesting, func(i, j int) bool {
		pri := rolePriority(interesting[i].Role)
		prj := rolePriority(interesting[j].Role)
		if pri != prj {
			return pri > prj
		}
		if interesting[i].ActiveProxying != interesting[j].ActiveProxying {
			return interesting[i].ActiveProxying && !interesting[j].ActiveProxying
		}
		if interesting[i].OutInternal != interesting[j].OutInternal {
			return interesting[i].OutInternal > interesting[j].OutInternal
		}
		if interesting[i].OutTotal != interesting[j].OutTotal {
			return interesting[i].OutTotal > interesting[j].OutTotal
		}
		if interesting[i].Score == interesting[j].Score {
			return interesting[i].Proc.Pid < interesting[j].Proc.Pid
		}
		return interesting[i].Score > interesting[j].Score
	})

	return interesting
}

func rolePriority(role string) int {
	switch role {
	case "reverse-transport":
		return 90
	case "reverse-proxy":
		return 80
	case "proxy-listener":
		return 70
	case "susp-tun":
		return 68
	case "susp-session":
		return 66
	case "susp-beacon":
		return 65
	case "listener-with-clients":
		return 60
	case "listener-with-outbound":
		return 50
	case "reverse-control":
		return 40
	case "reverse-tunnel":
		return 35
	case "listener-only":
		return 30
	case "outbound-only":
		return 10
	case "no-network-activity":
		return 0
	default:
		return 0
	}
}

func buildCandidates(snap *shared.Snapshot) []shared.Candidate {
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
	now := time.Now()
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
			Proc:         proc,
			Listeners:    lmap[pid],
			Conns:        cmap[pid],
			UDPListeners: umap[pid],
		})
	}

	return out
}
