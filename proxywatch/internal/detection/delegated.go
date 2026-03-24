package classifier

import (
	"strings"
	"time"

	"proxywatch/internal/shared"
)

const (
	delegatedProcessFreshWindow = 2 * time.Minute
	delegatedProcessCPUCeiling  = 2 * time.Minute
	delegatedConnFreshWindow    = 90 * time.Second
	delegatedPairWindow         = 20 * time.Second
	delegatedStateTTL           = 10 * time.Minute
	delegatedCleanupInterval    = 30 * time.Second
)

type delegatedAttribution struct {
	ownerPID  int
	ownerName string
	strong    bool
}

type delegatedBroker struct {
	pid       int
	name      string
	user      string
	sessionID uint32
	conn      shared.ConnectionInfo
	firstSeen time.Time
}

var (
	procFirstSeenByPID = make(map[int]time.Time)
	procLastSeenByPID  = make(map[int]time.Time)
	lastDelegatedSweep time.Time
)

func seedConnHistoryFromSnapshot(cmap map[int][]shared.ConnectionInfo, now time.Time) {
	if now.IsZero() {
		now = time.Now()
	}

	current := make(map[shared.ConnKey]struct{})
	for pid, conns := range cmap {
		for _, cn := range conns {
			if !isEstablishedState(cn.State) {
				continue
			}
			key := connKeyFromConn(pid, cn)
			current[key] = struct{}{}
			if _, ok := shared.ConnFirstSeen[key]; !ok {
				shared.ConnFirstSeen[key] = now
			}
			shared.ConnLastSeen[key] = now
		}
	}

	for key, last := range shared.ConnLastSeen {
		if _, ok := current[key]; ok {
			continue
		}
		if now.Sub(last) > shared.ConnMissingGrace {
			delete(shared.ConnFirstSeen, key)
			delete(shared.ConnLastSeen, key)
		}
	}
}

func correlateDelegatedEgress(
	snap *shared.Snapshot,
	cmap map[int][]shared.ConnectionInfo,
	seen map[int]bool,
	now time.Time,
) map[int]delegatedAttribution {
	if snap == nil || len(snap.Processes) == 0 {
		return nil
	}
	if now.IsZero() {
		now = time.Now()
	}

	touchProcessTracking(snap.Processes, now)
	sweepDelegatedTracking(now)

	brokers := collectDelegatedBrokers(snap, cmap, now)
	if len(brokers) == 0 {
		return nil
	}

	usedBroker := make(map[int]bool)
	out := make(map[int]delegatedAttribution)

	for pid, proc := range snap.Processes {
		if proc == nil {
			continue
		}
		if seen[pid] {
			continue
		}
		if !isDelegatedClientCandidate(pid, proc, now) {
			continue
		}

		firstSeen := procFirstSeenByPID[pid]
		matchIdx, strong, ok := bestDelegatedBroker(proc, firstSeen, brokers, usedBroker)
		if !ok {
			continue
		}

		b := brokers[matchIdx]
		usedBroker[matchIdx] = true

		synthetic := b.conn
		synthetic.Pid = pid
		key := connKeyFromConn(pid, synthetic)
		if _, ok := shared.ConnFirstSeen[key]; !ok {
			shared.ConnFirstSeen[key] = b.firstSeen
		}
		shared.ConnLastSeen[key] = now
		cmap[pid] = append(cmap[pid], synthetic)
		seen[pid] = true
		out[pid] = delegatedAttribution{
			ownerPID:  b.pid,
			ownerName: b.name,
			strong:    strong,
		}
	}

	if len(out) == 0 {
		return nil
	}
	return out
}

func collectDelegatedBrokers(
	snap *shared.Snapshot,
	cmap map[int][]shared.ConnectionInfo,
	now time.Time,
) []delegatedBroker {
	brokers := make([]delegatedBroker, 0)

	for pid, conns := range cmap {
		proc := snap.Processes[pid]
		if proc == nil || !shared.IsLikelyBenignControlClient(proc) {
			continue
		}

		for _, cn := range conns {
			if !isEstablishedState(cn.State) {
				continue
			}
			if cn.RemoteAddress == "" ||
				shared.IsWildcardIP(cn.RemoteAddress) ||
				shared.IsLoopbackIP(cn.RemoteAddress) ||
				shared.IsInternalIP(cn.RemoteAddress) {
				continue
			}

			first := shared.ConnFirstSeen[connKeyFromConn(pid, cn)]
			if first.IsZero() {
				first = now
			}
			if now.Sub(first) > delegatedConnFreshWindow {
				continue
			}

			brokers = append(brokers, delegatedBroker{
				pid:       pid,
				name:      proc.Name,
				user:      normalizedUser(proc.UserName),
				sessionID: proc.SessionID,
				conn:      cn,
				firstSeen: first,
			})
		}
	}
	return brokers
}

func bestDelegatedBroker(
	proc *shared.ProcessInfo,
	firstSeen time.Time,
	brokers []delegatedBroker,
	used map[int]bool,
) (index int, strong bool, ok bool) {
	bestIdx := -1
	bestScore := -999
	bestDelta := time.Duration(1<<63 - 1)
	user := normalizedUser(proc.UserName)

	for i, b := range brokers {
		if used[i] {
			continue
		}
		delta := absDuration(firstSeen.Sub(b.firstSeen))
		if delta > delegatedPairWindow {
			continue
		}

		score := 0
		switch {
		case delta <= 3*time.Second:
			score += 4
		case delta <= 10*time.Second:
			score += 2
		default:
			score++
		}

		if proc.SessionID != 0 {
			switch {
			case b.sessionID != 0 && proc.SessionID == b.sessionID:
				score += 4
			case b.sessionID == 0 && isServicePrincipal(b.user):
				score += 2
			case b.sessionID != 0:
				score -= 2
			}
		}

		if user != "" && b.user != "" {
			if user == b.user {
				score += 3
			} else if isServicePrincipal(b.user) {
				score++
			} else {
				score -= 2
			}
		}

		if score < 4 {
			continue
		}
		if score > bestScore || (score == bestScore && delta < bestDelta) {
			bestScore = score
			bestDelta = delta
			bestIdx = i
		}
	}

	if bestIdx < 0 {
		return 0, false, false
	}
	return bestIdx, bestScore >= 7, true
}

func isDelegatedClientCandidate(pid int, proc *shared.ProcessInfo, now time.Time) bool {
	if proc == nil || shared.IsLikelyBenignControlClient(proc) {
		return false
	}
	if isKernelThreadLike(proc.Name) {
		return false
	}
	firstSeen, ok := procFirstSeenByPID[pid]
	if !ok {
		return false
	}
	if now.Sub(firstSeen) > delegatedProcessFreshWindow {
		return false
	}
	if proc.CpuTime > delegatedProcessCPUCeiling {
		return false
	}
	if proc.ParentPid > 0 && proc.ParentPid <= 2 {
		return false
	}

	path := normalizeDelegatedPath(proc.ExePath)
	if path == "" {
		return false
	}
	return isLikelyUserWritablePath(path)
}

func touchProcessTracking(processes map[int]*shared.ProcessInfo, now time.Time) {
	for pid := range processes {
		if _, ok := procFirstSeenByPID[pid]; !ok {
			procFirstSeenByPID[pid] = now
		}
		procLastSeenByPID[pid] = now
	}
}

func sweepDelegatedTracking(now time.Time) {
	if !lastDelegatedSweep.IsZero() && now.Sub(lastDelegatedSweep) < delegatedCleanupInterval {
		return
	}
	lastDelegatedSweep = now

	for pid, last := range procLastSeenByPID {
		if now.Sub(last) <= delegatedStateTTL {
			continue
		}
		delete(procLastSeenByPID, pid)
		delete(procFirstSeenByPID, pid)
		for key := range shared.ConnFirstSeen {
			if key.Pid == pid {
				delete(shared.ConnFirstSeen, key)
				delete(shared.ConnLastSeen, key)
			}
		}
	}
}

func normalizeDelegatedPath(path string) string {
	path = strings.ToLower(strings.TrimSpace(path))
	return strings.ReplaceAll(path, "\\", "/")
}

func normalizedUser(user string) string {
	user = strings.ToLower(strings.TrimSpace(user))
	if user == "" || user == "(unknown)" {
		return ""
	}
	return user
}

func isServicePrincipal(user string) bool {
	return strings.Contains(user, "nt authority\\") ||
		strings.Contains(user, "local service") ||
		strings.Contains(user, "network service") ||
		strings.HasSuffix(user, "\\system")
}

func isLikelyUserWritablePath(path string) bool {
	return strings.HasPrefix(path, "c:/users/") ||
		strings.HasPrefix(path, "/home/") ||
		strings.Contains(path, "/downloads/") ||
		strings.Contains(path, "/desktop/") ||
		strings.Contains(path, "/appdata/") ||
		strings.Contains(path, "/tmp/") ||
		strings.Contains(path, "/var/tmp/")
}

func isKernelThreadLike(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	prefixes := []string{
		"kworker",
		"ksoftirqd",
		"migration/",
		"rcu_",
		"watchdog/",
		"cpuhp/",
		"idle_inject/",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

func absDuration(v time.Duration) time.Duration {
	if v < 0 {
		return -v
	}
	return v
}
