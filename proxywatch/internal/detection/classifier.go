package classifier

import (
	"sort"
	"strings"
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
	refreshObservedExternalPortProfile(candidates)
	hostScope := strings.TrimSpace(opts.HostScope)
	if hostScope == "" {
		hostScope = "local"
	}

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
		if c.Proc == nil {
			continue
		}
		if strings.TrimSpace(c.Host) == "" {
			c.Host = hostScope
		}
		if opts.Incremental && cache != nil {
			sig := candidateSignature(*c)
			prevCands := cache.Candidates
			prevSigs := cache.Signatures
			if prevCands != nil && prevSigs != nil {
				if prev, ok := prevCands[c.Proc.Pid]; ok {
					if prevSig, ok := prevSigs[c.Proc.Pid]; ok && prevSig == sig {
						if shouldRescoreUnchangedCandidate(c, &prev, now) {
							ScoreCandidate(c)
						} else {
							reuseCandidate(c, &prev)
							touchHistoryFromCandidate(c, now)
						}
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
	emitDetectionOutputs(now.UTC(), hostScope, candidates, interesting, opts)
	shared.MaybeSaveClassifierMemory("", now.UTC())

	return interesting
}

func refreshObservedExternalPortProfile(candidates []shared.Candidate) {
	procPorts := make(map[int]map[int]struct{})
	portPrefixes := make(map[int]map[string]struct{})
	portConnCount := make(map[int]int)

	for _, c := range candidates {
		if c.Proc == nil {
			continue
		}
		seenForProc := make(map[int]struct{})
		for _, cn := range c.Conns {
			if !isActiveConnState(cn.State) {
				continue
			}
			if cn.RemotePort <= 0 ||
				cn.RemoteAddress == "" ||
				shared.IsWildcardIP(cn.RemoteAddress) ||
				shared.IsLoopbackIP(cn.RemoteAddress) ||
				shared.IsInternalIP(cn.RemoteAddress) {
				continue
			}

			portConnCount[cn.RemotePort]++
			if _, ok := seenForProc[cn.RemotePort]; !ok {
				if procPorts[cn.RemotePort] == nil {
					procPorts[cn.RemotePort] = make(map[int]struct{})
				}
				procPorts[cn.RemotePort][c.Proc.Pid] = struct{}{}
				seenForProc[cn.RemotePort] = struct{}{}
			}
			if prefix := shared.TargetPrefix(cn.RemoteAddress); prefix != "" {
				if portPrefixes[cn.RemotePort] == nil {
					portPrefixes[cn.RemotePort] = make(map[string]struct{})
				}
				portPrefixes[cn.RemotePort][prefix] = struct{}{}
			}
		}
	}

	shared.ObservedExternalPortProcessCount = make(map[int]int, len(procPorts))
	for port, procs := range procPorts {
		shared.ObservedExternalPortProcessCount[port] = len(procs)
	}

	shared.ObservedExternalPortPrefixCount = make(map[int]int, len(portPrefixes))
	for port, prefixes := range portPrefixes {
		shared.ObservedExternalPortPrefixCount[port] = len(prefixes)
	}

	shared.ObservedExternalPortConnCount = make(map[int]int, len(portConnCount))
	for port, count := range portConnCount {
		shared.ObservedExternalPortConnCount[port] = count
	}
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

	rmap := make(map[int][]shared.RawSocketConn)
	for _, r := range snap.RawConns {
		rmap[r.Pid] = append(rmap[r.Pid], r)
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
	for pid := range snap.RawSocketPIDs {
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
		if shared.IsProxywatchProcess(proc) {
			continue
		}

		out = append(out, shared.Candidate{
			Proc:              proc,
			Listeners:         lmap[pid],
			Conns:             cmap[pid],
			UDPListeners:      umap[pid],
			RawConns:          rmap[pid],
			DelegatedEgress:   delegated[pid].ownerPID > 0,
			DelegatedStrong:   delegated[pid].strong,
			DelegatedOwnerPID: delegated[pid].ownerPID,
			DelegatedOwner:    delegated[pid].ownerName,
			RawSocket:         snap.RawSocketPIDs[pid],
		})
	}

	return out
}

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
