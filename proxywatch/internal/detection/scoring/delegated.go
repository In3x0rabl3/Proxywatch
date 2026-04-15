package scoring

import (
	"strings"
	"time"

	"proxywatch/internal/shared"
)

const (
	DelegatedProcessFreshWindow = 2 * time.Minute
	DelegatedProcessCPUCeiling  = 2 * time.Minute
	DelegatedConnFreshWindow    = 90 * time.Second
	DelegatedPairWindow         = 20 * time.Second
	DelegatedStateTTL           = 10 * time.Minute
	DelegatedCleanupInterval    = 30 * time.Second
)

type DelegatedAttribution struct {
	OwnerPID  int
	OwnerName string
	Strong    bool
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
	ProcFirstSeenByPID = make(map[int]time.Time)
	ProcLastSeenByPID  = make(map[int]time.Time)
	LastDelegatedSweep time.Time
)

func SeedConnHistoryFromSnapshot(cmap map[int][]shared.ConnectionInfo, now time.Time) {
	if now.IsZero() {
		now = time.Now()
	}

	current := make(map[shared.ConnKey]struct{})
	for pid, conns := range cmap {
		for _, cn := range conns {
			if !IsEstablishedState(cn.State) {
				continue
			}
			key := ConnKeyFromConn(pid, cn)
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

func CorrelateDelegatedEgress(
	snap *shared.Snapshot,
	cmap map[int][]shared.ConnectionInfo,
	seen map[int]bool,
	now time.Time,
) map[int]DelegatedAttribution {
	if snap == nil || len(snap.Processes) == 0 {
		return nil
	}
	if now.IsZero() {
		now = time.Now()
	}

	TouchProcessTracking(snap.Processes, now)
	SweepDelegatedTracking(now)

	brokers := CollectdelegatedBrokers(snap, cmap, now)
	if len(brokers) == 0 {
		return nil
	}

	usedBroker := make(map[int]bool)
	out := make(map[int]DelegatedAttribution)

	for pid, proc := range snap.Processes {
		if proc == nil {
			continue
		}
		if seen[pid] {
			continue
		}
		if !IsDelegatedClientCandidate(pid, proc, now) {
			continue
		}

		firstSeen := ProcFirstSeenByPID[pid]
		matchIdx, strong, ok := BestdelegatedBroker(proc, firstSeen, brokers, usedBroker)
		if !ok {
			continue
		}

		b := brokers[matchIdx]
		usedBroker[matchIdx] = true

		synthetic := b.conn
		synthetic.Pid = pid
		key := ConnKeyFromConn(pid, synthetic)
		if _, ok := shared.ConnFirstSeen[key]; !ok {
			shared.ConnFirstSeen[key] = b.firstSeen
		}
		shared.ConnLastSeen[key] = now
		cmap[pid] = append(cmap[pid], synthetic)
		seen[pid] = true
		out[pid] = DelegatedAttribution{
			OwnerPID:  b.pid,
			OwnerName: b.name,
			Strong:    strong,
		}
	}

	if len(out) == 0 {
		return nil
	}
	return out
}

func CollectdelegatedBrokers(
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
			if !IsEstablishedState(cn.State) {
				continue
			}
			if cn.RemoteAddress == "" ||
				shared.IsWildcardIP(cn.RemoteAddress) ||
				shared.IsLoopbackIP(cn.RemoteAddress) ||
				shared.IsInternalIP(cn.RemoteAddress) {
				continue
			}

			first := shared.ConnFirstSeen[ConnKeyFromConn(pid, cn)]
			if first.IsZero() {
				first = now
			}
			if now.Sub(first) > DelegatedConnFreshWindow {
				continue
			}

			brokers = append(brokers, delegatedBroker{
				pid:       pid,
				name:      proc.Name,
				user:      NormalizedUser(proc.UserName),
				sessionID: proc.SessionID,
				conn:      cn,
				firstSeen: first,
			})
		}
	}
	return brokers
}

func BestdelegatedBroker(
	proc *shared.ProcessInfo,
	firstSeen time.Time,
	brokers []delegatedBroker,
	used map[int]bool,
) (index int, strong bool, ok bool) {
	bestIdx := -1
	bestScore := -999
	bestDelta := time.Duration(1<<63 - 1)
	user := NormalizedUser(proc.UserName)

	for i, b := range brokers {
		if used[i] {
			continue
		}
		delta := firstSeen.Sub(b.firstSeen).Abs()
		if delta > DelegatedPairWindow {
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
			case b.sessionID == 0 && IsServicePrincipal(b.user):
				score += 2
			case b.sessionID != 0:
				score -= 2
			}
		}

		if user != "" && b.user != "" {
			if user == b.user {
				score += 3
			} else if IsServicePrincipal(b.user) {
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

func IsDelegatedClientCandidate(pid int, proc *shared.ProcessInfo, now time.Time) bool {
	if proc == nil || shared.IsLikelyBenignControlClient(proc) {
		return false
	}
	if IsKernelThreadLike(proc) {
		return false
	}
	firstSeen, ok := ProcFirstSeenByPID[pid]
	if !ok {
		return false
	}
	if now.Sub(firstSeen) > DelegatedProcessFreshWindow {
		return false
	}
	if proc.CpuTime > DelegatedProcessCPUCeiling {
		return false
	}
	if proc.ParentPid > 0 && proc.ParentPid <= 2 {
		return false
	}

	path := shared.NormalizeExePath(proc.ExePath)
	if path == "" {
		return false
	}
	return IsLikelyUserWritablePath(path)
}

func TouchProcessTracking(processes map[int]*shared.ProcessInfo, now time.Time) {
	for pid := range processes {
		if _, ok := ProcFirstSeenByPID[pid]; !ok {
			ProcFirstSeenByPID[pid] = now
		}
		ProcLastSeenByPID[pid] = now
	}
}

func SweepDelegatedTracking(now time.Time) {
	if !LastDelegatedSweep.IsZero() && now.Sub(LastDelegatedSweep) < DelegatedCleanupInterval {
		return
	}
	LastDelegatedSweep = now

	for pid, last := range ProcLastSeenByPID {
		if now.Sub(last) <= DelegatedStateTTL {
			continue
		}
		delete(ProcLastSeenByPID, pid)
		delete(ProcFirstSeenByPID, pid)
		for key := range shared.ConnFirstSeen {
			if key.Pid == pid {
				delete(shared.ConnFirstSeen, key)
				delete(shared.ConnLastSeen, key)
			}
		}
	}
}

func NormalizedUser(user string) string {
	user = strings.ToLower(strings.TrimSpace(user))
	if user == "" || user == "(unknown)" {
		return ""
	}
	return user
}

func IsServicePrincipal(user string) bool {
	return strings.Contains(user, "nt authority\\") ||
		strings.Contains(user, "local service") ||
		strings.Contains(user, "network service") ||
		strings.HasSuffix(user, "\\system")
}

func IsLikelyUserWritablePath(path string) bool {
	return strings.HasPrefix(path, "c:/users/") ||
		strings.HasPrefix(path, "/home/") ||
		strings.Contains(path, "/downloads/") ||
		strings.Contains(path, "/desktop/") ||
		strings.Contains(path, "/appdata/") ||
		strings.Contains(path, "/tmp/") ||
		strings.Contains(path, "/var/tmp/")
}

// IsKernelThreadLike detects kernel threads behaviorally: they have no
// executable on disk and descend from the kernel thread daemon (PID <= 2).
// No process names are hardcoded.
func IsKernelThreadLike(proc *shared.ProcessInfo) bool {
	if proc == nil {
		return false
	}
	// Kernel threads have no executable path and are spawned by init (1) or
	// kthreadd (2).
	return strings.TrimSpace(proc.ExePath) == "" && proc.ParentPid >= 0 && proc.ParentPid <= 2
}
