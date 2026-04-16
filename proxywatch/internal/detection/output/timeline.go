package output

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"proxywatch/internal/shared"
)

// TimelineEntry is one cycle-level change record for a single PID —
// appended when the candidate's role, signal set, score band, or
// confidence changes between successive cycles. Plan Track 10: lets
// an operator see *when* and *why* a candidate escalated, without
// tailing log files.
type TimelineEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	Cycle       uint64    `json:"cycle"`
	Role        string    `json:"role"`
	Score       int       `json:"score"`
	Confidence  int       `json:"confidence"`
	Signals     []string  `json:"signals,omitempty"`
	Added       []string  `json:"signals_added,omitempty"`
	Removed     []string  `json:"signals_removed,omitempty"`
	Change      string    `json:"change"` // "initial" | "role" | "signals" | "score"
	StrongEvid  bool      `json:"strong_evidence,omitempty"`
	ActiveProxy bool      `json:"active_proxying,omitempty"`
}

// timelineEntry caps per-PID history to N entries. Long deployments
// with a stable process still only keep the deltas; no-change cycles
// don't append. Cap prevents unbounded memory growth under pathological
// cases (a single PID flipping state every cycle).
const (
	maxTimelineEntriesPerPID = 50
	maxTimelineTrackedPIDs   = 500
)

var (
	timelineMu   sync.RWMutex
	timelineData = make(map[string][]TimelineEntry) // host|pid → entries
	timelineSeen = make(map[string]time.Time)       // host|pid → last-seen
)

// recordTimeline appends an entry for a candidate when its observable
// state has changed since the last recorded cycle. Called from
// UpdateDebugAPISnapshot. host is the scope of the candidate set
// (either the local host in local mode or the remote host when
// invoked from the per-host agent path).
func recordTimeline(host string, cycle uint64, scored []shared.Candidate) {
	if len(scored) == 0 {
		return
	}
	now := time.Now().UTC()
	timelineMu.Lock()
	defer timelineMu.Unlock()

	// Track seen keys to purge stale entries after the loop.
	seenThisCycle := make(map[string]struct{}, len(scored))

	for i := range scored {
		c := &scored[i]
		if c.Proc == nil {
			continue
		}
		scope := host
		if c.Host != "" {
			scope = c.Host
		}
		key := scope + "|" + strconv.Itoa(c.Proc.Pid)
		seenThisCycle[key] = struct{}{}
		timelineSeen[key] = now

		current := TimelineEntry{
			Timestamp:   now,
			Cycle:       cycle,
			Role:        c.Role,
			Score:       c.Score,
			Confidence:  c.Confidence,
			Signals:     append([]string(nil), c.Signals...),
			StrongEvid:  c.StrongEvidence,
			ActiveProxy: c.ActiveProxying,
		}
		sort.Strings(current.Signals)

		entries := timelineData[key]
		if len(entries) == 0 {
			current.Change = "initial"
			timelineData[key] = []TimelineEntry{current}
			continue
		}
		prev := entries[len(entries)-1]
		roleChanged := prev.Role != current.Role
		added, removed := diffSignals(prev.Signals, current.Signals)
		signalChanged := len(added) > 0 || len(removed) > 0
		scoreBandChanged := scoreBand(prev.Score) != scoreBand(current.Score)
		if !roleChanged && !signalChanged && !scoreBandChanged {
			continue
		}
		current.Added = added
		current.Removed = removed
		switch {
		case roleChanged:
			current.Change = "role"
		case signalChanged:
			current.Change = "signals"
		case scoreBandChanged:
			current.Change = "score"
		}
		entries = append(entries, current)
		if len(entries) > maxTimelineEntriesPerPID {
			entries = entries[len(entries)-maxTimelineEntriesPerPID:]
		}
		timelineData[key] = entries
	}

	// Stop tracking keys that have disappeared from the live set and
	// have been stale for over 10 minutes — frees memory for PIDs
	// that exited without blowing away recent history.
	staleCutoff := now.Add(-10 * time.Minute)
	for k, ts := range timelineSeen {
		if _, alive := seenThisCycle[k]; alive {
			continue
		}
		if ts.Before(staleCutoff) {
			delete(timelineData, k)
			delete(timelineSeen, k)
		}
	}

	// Cap total tracked keys: evict the oldest by last-seen when we
	// exceed the budget. Pathological upper bound protection.
	if len(timelineData) > maxTimelineTrackedPIDs {
		type oldest struct {
			key string
			ts  time.Time
		}
		sorted := make([]oldest, 0, len(timelineSeen))
		for k, ts := range timelineSeen {
			sorted = append(sorted, oldest{k, ts})
		}
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].ts.Before(sorted[j].ts) })
		toDrop := len(timelineData) - maxTimelineTrackedPIDs
		for i := 0; i < toDrop && i < len(sorted); i++ {
			delete(timelineData, sorted[i].key)
			delete(timelineSeen, sorted[i].key)
		}
	}
}

// diffSignals returns (added, removed) between two sorted signal lists.
func diffSignals(prev, cur []string) (added, removed []string) {
	i, j := 0, 0
	for i < len(prev) && j < len(cur) {
		switch {
		case prev[i] == cur[j]:
			i++
			j++
		case prev[i] < cur[j]:
			removed = append(removed, prev[i])
			i++
		default:
			added = append(added, cur[j])
			j++
		}
	}
	for ; i < len(prev); i++ {
		removed = append(removed, prev[i])
	}
	for ; j < len(cur); j++ {
		added = append(added, cur[j])
	}
	return added, removed
}

// scoreBand quantizes raw score into coarse buckets so small jitter
// doesn't flood the timeline. Buckets: [0,20), [20,40), [40,60),
// [60,80), [80,100]. Matches the rough role-assignment bands used
// elsewhere.
func scoreBand(score int) int {
	switch {
	case score < 20:
		return 0
	case score < 40:
		return 1
	case score < 60:
		return 2
	case score < 80:
		return 3
	default:
		return 4
	}
}

// TimelineFor returns the current entries for a host|pid key, or nil
// if no history exists. Exported only for tests.
func TimelineFor(host string, pid int) []TimelineEntry {
	timelineMu.RLock()
	defer timelineMu.RUnlock()
	key := host + "|" + strconv.Itoa(pid)
	entries := timelineData[key]
	out := make([]TimelineEntry, len(entries))
	copy(out, entries)
	return out
}

// ResetTimelineForTest clears the timeline store. Exported for tests.
func ResetTimelineForTest() {
	timelineMu.Lock()
	timelineData = make(map[string][]TimelineEntry)
	timelineSeen = make(map[string]time.Time)
	timelineMu.Unlock()
}

// handleTimeline serves GET /timeline/<pid>. pid is required and must
// be a positive integer. Returns 404 when no history exists for the
// requested PID. The host is inferred from the current debug-API
// scope (local mode) or the path prefix (server mode not supported
// yet — falls back to any host match if multiple scopes share the
// pid, which is fine for single-host deployments).
func handleTimeline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/timeline")
	rest = strings.TrimPrefix(rest, "/")
	rest = strings.TrimSpace(rest)
	if rest == "" {
		// Bare /timeline — return a list of known PIDs with entry counts.
		timelineMu.RLock()
		summary := make([]map[string]interface{}, 0, len(timelineData))
		for key, entries := range timelineData {
			host, pidStr, ok := strings.Cut(key, "|")
			if !ok {
				continue
			}
			pid, _ := strconv.Atoi(pidStr)
			summary = append(summary, map[string]interface{}{
				"host":    host,
				"pid":     pid,
				"entries": len(entries),
				"latest":  entries[len(entries)-1].Timestamp,
			})
		}
		timelineMu.RUnlock()
		sort.Slice(summary, func(i, j int) bool {
			return summary[i]["pid"].(int) < summary[j]["pid"].(int)
		})
		writeJSON(w, map[string]interface{}{
			"count":     len(summary),
			"processes": summary,
		})
		return
	}
	pid, err := strconv.Atoi(rest)
	if err != nil || pid <= 0 {
		http.Error(w, "invalid pid", http.StatusBadRequest)
		return
	}
	timelineMu.RLock()
	var entries []TimelineEntry
	for key, recs := range timelineData {
		_, pidStr, ok := strings.Cut(key, "|")
		if !ok {
			continue
		}
		if p, err := strconv.Atoi(pidStr); err == nil && p == pid {
			entries = append(entries, recs...)
		}
	}
	timelineMu.RUnlock()
	if len(entries) == 0 {
		http.Error(w, "no timeline for pid", http.StatusNotFound)
		return
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Timestamp.Before(entries[j].Timestamp) })
	writeJSON(w, map[string]interface{}{
		"pid":     pid,
		"count":   len(entries),
		"entries": entries,
	})
}
