package shared

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// InspectorConnStickyWindow is how long a connection stays visible in
// the Inspector's CONNECTIONS panel after it disappears from the live
// snapshot. Operator request 2026-05-02: closed/transient connections
// must remain visible long enough for triage rather than vanishing on
// the next scanner refresh — covers slow beaconers (smb_pivot at
// 17m intervals, liquid_mezzanine at 7m) whose connection lifetime
// is shorter than the typical inspector dwell time.
const InspectorConnStickyWindow = 10 * time.Minute

type stickyConnEntry struct {
	info     ConnectionInfo
	lastSeen time.Time
}

var (
	inspectorConnMu      sync.Mutex
	inspectorConnHistory = make(map[int]map[string]stickyConnEntry) // pid → tuple-key → entry
)

func stickyConnKey(cn ConnectionInfo) string {
	return fmt.Sprintf("%s:%d|%s:%d", cn.LocalAddress, cn.LocalPort, cn.RemoteAddress, cn.RemotePort)
}

// RecordCandidateConnsForInspector merges all candidates' current
// connections into the per-PID sticky cache. Called from
// ApplySelection on every scanner refresh so closed connections are
// remembered for the full sticky window even when the operator
// hasn't opened the Inspector for that PID yet — without this hook
// the cache only fills while the user is actively viewing a
// candidate, missing connections for slow beaconers (every callback
// happens between inspector visits).
func RecordCandidateConnsForInspector(cands []Candidate) {
	if len(cands) == 0 {
		return
	}
	inspectorConnMu.Lock()
	defer inspectorConnMu.Unlock()
	now := time.Now()
	for i := range cands {
		c := &cands[i]
		if c.Proc == nil {
			continue
		}
		pid := c.Proc.Pid
		perPID, ok := inspectorConnHistory[pid]
		if !ok {
			if len(c.Conns) == 0 {
				continue // nothing to record yet
			}
			perPID = make(map[string]stickyConnEntry)
			inspectorConnHistory[pid] = perPID
		}
		for _, cn := range c.Conns {
			k := stickyConnKey(cn)
			perPID[k] = stickyConnEntry{info: cn, lastSeen: now}
		}
		// Expire stale entries for this PID.
		for k, e := range perPID {
			if now.Sub(e.lastSeen) > InspectorConnStickyWindow {
				delete(perPID, k)
			}
		}
		if len(perPID) == 0 {
			delete(inspectorConnHistory, pid)
		}
	}
}

// InspectorStickyConns returns the full sticky-cached connection set
// for `pid`, ordered by remote address then local port for stable
// display. Returned entries may be older than the live snapshot but
// no older than InspectorConnStickyWindow. Dedup is keyed by
// (local, remote) tuple — same flow appears once even if state
// changed (ESTABLISHED → CLOSE_WAIT → vanished).
func InspectorStickyConns(pid int, live []ConnectionInfo) []ConnectionInfo {
	inspectorConnMu.Lock()
	defer inspectorConnMu.Unlock()
	now := time.Now()
	perPID, ok := inspectorConnHistory[pid]
	if !ok {
		perPID = make(map[string]stickyConnEntry)
		inspectorConnHistory[pid] = perPID
	}
	for _, cn := range live {
		k := stickyConnKey(cn)
		perPID[k] = stickyConnEntry{info: cn, lastSeen: now}
	}
	for k, e := range perPID {
		if now.Sub(e.lastSeen) > InspectorConnStickyWindow {
			delete(perPID, k)
		}
	}
	out := make([]ConnectionInfo, 0, len(perPID))
	for _, e := range perPID {
		out = append(out, e.info)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].RemoteAddress != out[j].RemoteAddress {
			return out[i].RemoteAddress < out[j].RemoteAddress
		}
		if out[i].RemotePort != out[j].RemotePort {
			return out[i].RemotePort < out[j].RemotePort
		}
		if out[i].LocalAddress != out[j].LocalAddress {
			return out[i].LocalAddress < out[j].LocalAddress
		}
		return out[i].LocalPort < out[j].LocalPort
	})
	return out
}
