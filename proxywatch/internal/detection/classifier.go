package classifier

import (
	"sort"
	"strings"
	"time"

	"proxywatch/internal/model"
	"proxywatch/internal/shared"
)

// Classify converts a telemetry snapshot into classified candidates.
func Classify(
	snap *shared.Snapshot,
	opts shared.ClassifyOptions,
	cache *shared.ClassifierCache,
) []shared.Candidate {
	// Protect global classifier state maps from concurrent access.
	// The background refresh goroutine runs Classify in parallel with the UI.
	shared.ClassifyMu.Lock()
	defer shared.ClassifyMu.Unlock()

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

		if c.Score >= opts.MinScore || shared.IsControlRole(c.Role) {
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

	// Feed ALL scored candidates into the detection model as experience.
	// This ensures every process gets a profile, not just high-scoring ones.
	{
		expRecords := make([]model.ExperienceRecord, 0, len(candidates))
		for i := range candidates {
			c := &candidates[i]
			if c.Proc == nil {
				continue
			}
			rec := model.ExperienceRecord{
				ProcessKey:   ProcessBehaviorKey(c),
				Name:         c.Proc.Name,
				Role:         c.Role,
				Score:        c.Score,
				Signals:      c.Signals,
				IOReadBytes:  c.Proc.IOReadBytes,
				IOWriteBytes: c.Proc.IOWriteBytes,
			}
			if c.ControlSubtype == "beacon" {
				for _, sig := range c.Signals {
					if sig == "beacon-confirmed" {
						rec.BeaconInterval = c.ControlDurationSeconds * 1000
						break
					}
				}
			}
			expRecords = append(expRecords, rec)
		}
		if len(expRecords) > 0 {
			model.RecordExperience(expRecords)
		}
	}

	shared.MaybeSaveClassifierMemory("", now.UTC())
	model.RefreshRuntimeProfiles()
	model.MaybeSave(now.UTC())

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

	pipemap := make(map[int][]string)
	for _, p := range snap.NamedPipes {
		pipemap[p.Pid] = append(pipemap[p.Pid], p.PipeName)
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

	// Keep PIDs with recent connection history visible even when they
	// currently have no active connections. This catches beacons between
	// callback intervals and processes that briefly close connections.
	for key, t := range shared.ConnFirstSeen {
		if now.Sub(t) <= shared.SuspicionWindow {
			seen[key.Pid] = true
		}
	}

	// Also keep PIDs with short-lived burst history (beacon candidates).
	for pid, t := range shared.ShortLivedBurstLast {
		if now.Sub(t) <= shared.SlowScanWindow {
			seen[pid] = true
		}
	}

	// Keep processes from suspicious staging paths visible when they have
	// significant IO activity — these may be long-interval C2 beacons
	// (hours between callbacks) that have no current TCP connections.
	for pid, proc := range snap.Processes {
		if seen[pid] || proc == nil {
			continue
		}
		if !isSuspiciousStagingPathForVisibility(proc.ExePath) {
			continue
		}
		if shared.IsLikelyBenignControlClient(proc) {
			continue
		}
		ioTotal := proc.IOReadBytes + proc.IOWriteBytes + proc.IOOtherBytes
		if ioTotal >= 500*1024 {
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
			NamedPipes:        pipemap[pid],
		})
	}

	return out
}

// isSuspiciousStagingPathForVisibility returns true for user-writable staging
// locations where implants are commonly dropped. Used to keep long-interval
// beacons visible even when they have no current TCP connections.
func isSuspiciousStagingPathForVisibility(exePath string) bool {
	p := shared.NormalizeExePath(exePath)
	if p == "" {
		return false
	}
	markers := []string{
		"/downloads/",
		"/desktop/",
		"/tmp/",
		"/var/tmp/",
		"/appdata/local/temp/",
		"/public/",
	}
	for _, m := range markers {
		if strings.Contains(p, m) {
			return true
		}
	}
	return false
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
