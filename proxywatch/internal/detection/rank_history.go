package classifier

import (
	"fmt"
	"proxywatch/internal/shared"
	"sort"
	"strings"
	"time"
)

func updateInboundBurst(pid int, activeClients int, now time.Time) int {
	if activeClients <= 0 {
		last := shared.InboundBurstLast[pid]
		if last.IsZero() || now.Sub(last) > shared.ShortLivedBurstWindow {
			shared.InboundBurstCount[pid] = 0
			return 0
		}
		return shared.InboundBurstCount[pid]
	}

	last := shared.InboundBurstLast[pid]
	if last.IsZero() || now.Sub(last) > shared.ShortLivedBurstWindow {
		shared.InboundBurstCount[pid] = activeClients
	} else {
		shared.InboundBurstCount[pid] += activeClients
	}
	shared.InboundBurstLast[pid] = now
	return shared.InboundBurstCount[pid]
}

func connKeyFromConn(pid int, cn shared.ConnectionInfo) shared.ConnKey {
	return shared.ConnKey{
		Pid:        pid,
		LocalAddr:  cn.LocalAddress,
		LocalPort:  cn.LocalPort,
		RemoteAddr: cn.RemoteAddress,
		RemotePort: cn.RemotePort,
	}
}

func updateConnHistory(pid int, conns []shared.ConnectionInfo, now time.Time) {
	current := make(map[shared.ConnKey]struct{})
	for _, cn := range conns {
		if !isEstablishedState(cn.State) {
			continue
		}
		key := connKeyFromConn(pid, cn)
		current[key] = struct{}{}
		if _, ok := shared.ConnFirstSeen[key]; !ok {
			shared.ConnFirstSeen[key] = now
			shared.ConnKeysByPID[pid] = append(shared.ConnKeysByPID[pid], key)
		}
		shared.ConnLastSeen[key] = now
	}

	for k, last := range shared.ConnLastSeen {
		if k.Pid != pid {
			continue
		}
		if _, ok := current[k]; ok {
			continue
		}
		if now.Sub(last) > shared.ConnMissingGrace {
			delete(shared.ConnFirstSeen, k)
			delete(shared.ConnLastSeen, k)
		}
	}
}

func findPersistentControl(pid int, conns []shared.ConnectionInfo, now time.Time) (*shared.ConnectionInfo, int) {
	var best *shared.ConnectionInfo
	var bestAge time.Duration

	for _, cn := range conns {
		if !isEstablishedState(cn.State) {
			continue
		}
		if cn.RemoteAddress == "" ||
			shared.IsWildcardIP(cn.RemoteAddress) ||
			shared.IsLoopbackIP(cn.RemoteAddress) {
			continue
		}

		key := connKeyFromConn(pid, cn)
		first, ok := shared.ConnFirstSeen[key]
		if !ok {
			continue
		}
		age := now.Sub(first)
		if age >= shared.ReverseControlMinDuration && age > bestAge {
			tmp := cn
			best = &tmp
			bestAge = age
		}
	}

	if best == nil {
		return nil, 0
	}
	return best, int(bestAge.Seconds())
}

func getHistory(pid int, now time.Time) *shared.ProcHistory {
	h := shared.ProcHistoryByPID[pid]
	if h == nil {
		h = &shared.ProcHistory{}
		shared.ProcHistoryByPID[pid] = h
	}
	h.LastSeen = now

	// Track shape drift (ratios of in/out/loopback) to flag sudden behavioral changes.
	// Ratios are updated by callers after computing candidate scores.
	return h
}

func purgeHistory(now time.Time) {
	if !shared.LastHistoryCleanup.IsZero() && now.Sub(shared.LastHistoryCleanup) < shared.CleanupInterval {
		return
	}
	shared.LastHistoryCleanup = now
	behaviorTTL := shared.HistoryTTL * 4
	if behaviorTTL < 30*time.Minute {
		behaviorTTL = 30 * time.Minute
	}
	for key, behavior := range shared.ProcessBehaviorByKey {
		if behavior == nil || behavior.LastSeen.IsZero() || now.Sub(behavior.LastSeen) > behaviorTTL {
			delete(shared.ProcessBehaviorByKey, key)
		}
	}

	for pid, h := range shared.ProcHistoryByPID {
		if now.Sub(h.LastSeen) <= shared.HistoryTTL {
			continue
		}

		delete(shared.ProcHistoryByPID, pid)
		delete(shared.RecentClientSeen, pid)
		delete(shared.RecentOutboundSeen, pid)
		delete(shared.RecentInternalScanSeen, pid)
		delete(shared.ShortLivedBurstLast, pid)
		delete(shared.ShortLivedBurstFirst, pid)
		delete(shared.ShortLivedBurstCount, pid)
		delete(shared.ShortLivedBurstInterval, pid)
		delete(shared.ShortLivedBurstHits, pid)
		delete(shared.BeaconSeen, pid)
		delete(shared.LocalTransportLast, pid)
		delete(shared.PendingControlByPID, pid)

		for _, k := range shared.ConnKeysByPID[pid] {
			delete(shared.ConnFirstSeen, k)
			delete(shared.ConnLastSeen, k)
		}
		delete(shared.ConnKeysByPID, pid)
	}

	// Prune unbounded tracking maps to prevent memory growth.
	if len(shared.RareTupleCount) > 5000 {
		shared.RareTupleCount = make(map[string]int)
	}
	if len(shared.ParentChildFreq) > 2000 {
		shared.ParentChildFreq = make(map[string]int)
	}
	if len(shared.ProcessBehaviorByKey) > 500 {
		// Keep most recently seen 300 entries.
		type entry struct {
			key  string
			last time.Time
		}
		entries := make([]entry, 0, len(shared.ProcessBehaviorByKey))
		for k, v := range shared.ProcessBehaviorByKey {
			entries = append(entries, entry{k, v.LastSeen})
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].last.After(entries[j].last) })
		newMap := make(map[string]*shared.ProcessBehavior, 300)
		for i := 0; i < 300 && i < len(entries); i++ {
			newMap[entries[i].key] = shared.ProcessBehaviorByKey[entries[i].key]
		}
		shared.ProcessBehaviorByKey = newMap
	}
}

func pendingControlAttempt(
	pid int,
	conns []shared.ConnectionInfo,
	ports map[int]struct{},
	now time.Time,
) (*shared.ConnectionInfo, int, int, bool) {
	var best *shared.ConnectionInfo
	for _, cn := range conns {
		if !isPendingControlState(cn.State) {
			continue
		}
		if cn.RemoteAddress == "" ||
			shared.IsWildcardIP(cn.RemoteAddress) ||
			shared.IsLoopbackIP(cn.RemoteAddress) {
			continue
		}
		if _, ok := ports[cn.LocalPort]; ok {
			continue
		}
		tmp := cn
		best = &tmp
		break
	}

	hist := shared.PendingControlByPID[pid]
	if best == nil {
		if hist != nil && now.Sub(hist.LastSeen) > shared.PendingControlGapReset {
			delete(shared.PendingControlByPID, pid)
		}
		return nil, 0, 0, false
	}

	target := fmt.Sprintf("%s:%d", best.RemoteAddress, best.RemotePort)
	if hist == nil ||
		hist.Target != target ||
		hist.LastSeen.IsZero() ||
		now.Sub(hist.LastSeen) > shared.PendingControlGapReset {
		hist = &shared.PendingControlHistory{
			Target:       target,
			FirstSeen:    now,
			LastSeen:     now,
			Observations: 1,
		}
		shared.PendingControlByPID[pid] = hist
	} else {
		if now.Sub(hist.LastSeen) >= time.Second {
			hist.Observations++
		}
		hist.LastSeen = now
	}

	ageSecs := max(0, int(now.Sub(hist.FirstSeen).Seconds()))
	repeated := hist.Observations >= shared.PendingControlMinObs &&
		now.Sub(hist.FirstSeen) >= shared.PendingControlMinDuration
	return best, ageSecs, hist.Observations, repeated
}

// updateSYNCycleTracking detects beacon-like SYN_SENT cycling patterns.
// When a C2 server is down, the implant's reconnection attempts show as
// SYN_SENT that appears, times out (disappears), then reappears on the
// next callback. Tracking these cycles reveals the beacon interval.
func updateSYNCycleTracking(pid int, conns []shared.ConnectionInfo, ports map[int]struct{}, now time.Time) (beaconLikeCycle bool, cycles int, avgInterval float64) {
	// Find current SYN_SENT target (if any).
	var currentTarget string
	for _, cn := range conns {
		if !isPendingControlState(cn.State) {
			continue
		}
		if cn.RemoteAddress == "" || shared.IsWildcardIP(cn.RemoteAddress) || shared.IsLoopbackIP(cn.RemoteAddress) {
			continue
		}
		if _, ok := ports[cn.LocalPort]; ok {
			continue
		}
		currentTarget = cn.RemoteAddress + ":" + fmt.Sprintf("%d", cn.RemotePort)
		break
	}

	hist := shared.SYNCycleByPID[pid]
	present := currentTarget != ""

	// No SYN_SENT and no history — nothing to track.
	if !present && hist == nil {
		return false, 0, 0
	}

	// Target changed or gap too long — reset tracking.
	if hist != nil && (currentTarget != hist.Target && present) {
		hist = nil
	}
	if hist != nil && now.Sub(hist.LastSeen) > 10*time.Minute {
		hist = nil
	}

	if hist == nil {
		if !present {
			return false, 0, 0
		}
		shared.SYNCycleByPID[pid] = &shared.SYNCycleHistory{
			Target:      currentTarget,
			Cycles:      0,
			LastPresent: true,
			LastSeen:    now,
			FirstSeen:   now,
		}
		return false, 0, 0
	}

	hist.LastSeen = now

	// Detect transition: was absent, now present → new cycle.
	if present && !hist.LastPresent {
		hist.Cycles++
		if hist.Cycles >= 2 && len(hist.Intervals) > 0 {
			// Record interval since last cycle start.
		}
		// Track interval from first seen to now, divided by cycles.
		elapsed := now.Sub(hist.FirstSeen).Seconds()
		if hist.Cycles > 0 && elapsed > 0 {
			avg := elapsed / float64(hist.Cycles)
			// Keep a rolling window of up to 8 intervals.
			if len(hist.Intervals) >= 8 {
				hist.Intervals = hist.Intervals[1:]
			}
			hist.Intervals = append(hist.Intervals, avg)
		}
	}
	hist.LastPresent = present

	if hist.Cycles < 2 {
		return false, hist.Cycles, 0
	}

	// Compute average interval.
	if len(hist.Intervals) > 0 {
		sum := 0.0
		for _, v := range hist.Intervals {
			sum += v
		}
		avgInterval = sum / float64(len(hist.Intervals))
	}

	// Consider it beacon-like if we've seen 2+ cycles.
	return true, hist.Cycles, avgInterval
}

func maxEstablishedConnectionAgeSeconds(pid int, conns []shared.ConnectionInfo, now time.Time) int {
	maxAge := 0
	for _, cn := range conns {
		if !isEstablishedState(cn.State) {
			continue
		}
		key := connKeyFromConn(pid, cn)
		first, ok := shared.ConnFirstSeen[key]
		if !ok {
			continue
		}
		age := int(now.Sub(first).Seconds())
		if age > maxAge {
			maxAge = age
		}
	}
	return maxAge
}

func beaconObservationAgeSeconds(pid int, now time.Time) int {
	first, ok := shared.ShortLivedBurstFirst[pid]
	if !ok || first.IsZero() {
		return 0
	}
	age := int(now.Sub(first).Seconds())
	if age < 0 {
		return 0
	}
	return age
}

func updateParentFreq(hostScope string, p *shared.ProcessInfo) {
	if p == nil {
		return
	}
	if strings.TrimSpace(hostScope) == "" {
		hostScope = "local"
	}
	key := fmt.Sprintf("%s|%d|%s|%s", hostScope, p.ParentPid, p.Name, p.ExePath)
	shared.ParentChildFreq[key]++
}

func updateBurstHistory(pid int, burstCount int, now time.Time) {
	if burstCount <= 0 {
		return
	}

	if _, ok := shared.ShortLivedBurstFirst[pid]; !ok {
		shared.ShortLivedBurstFirst[pid] = now
	}
	shared.ShortLivedBurstCount[pid] = burstCount
	prevTime, hasPrev := shared.ShortLivedBurstLast[pid]
	shared.ShortLivedBurstLast[pid] = now

	if hasPrev {
		interval := now.Sub(prevTime)
		if interval < shared.ShortLivedBurstWindow {
			return
		}
		shared.ShortLivedBurstInterval[pid] = interval
		intervals := shared.ShortLivedIntervals[pid]
		intervals = append(intervals, interval)
		if len(intervals) > 20 {
			intervals = intervals[len(intervals)-20:]
		}
		shared.ShortLivedIntervals[pid] = intervals
		if interval >= shared.BeaconSleepThreshold {
			shared.ShortLivedBurstHits[pid]++
		} else if shared.ShortLivedBurstHits[pid] > 0 {
			shared.ShortLivedBurstHits[pid]--
		}
	} else {
		shared.ShortLivedBurstHits[pid] = 0
	}
}
