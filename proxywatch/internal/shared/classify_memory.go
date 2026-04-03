package shared

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"proxywatch/internal/safeio"
)

const (
	classifierMemoryVersion       = 1
	defaultClassifierMemoryPath   = "~/.proxywatch/runtime/classifier-memory.json"
	classifierMemorySaveInterval  = 15 * time.Second
	classifierMemoryFileMode      = 0o600
	classifierMemoryDirMode       = 0o700
	classifierMemoryMaxCountItems = 4096
	classifierBehaviorMaxItems    = 2048
	classifierBehaviorMaxPrefixes = 128
)

var lastClassifierMemorySave time.Time

type classifierMemoryDisk struct {
	Version              int                         `json:"version"`
	SavedAt              time.Time                   `json:"saved_at"`
	LastHistoryCleanup   time.Time                   `json:"last_history_cleanup"`
	ProcHistoryByPID     map[int]*ProcHistory        `json:"proc_history_by_pid,omitempty"`
	ProcessBehaviorByKey map[string]*ProcessBehavior `json:"process_behavior_by_key,omitempty"`
	RecentClientSeen     map[int]time.Time           `json:"recent_client_seen,omitempty"`
	RecentOutboundSeen   map[int]time.Time           `json:"recent_outbound_seen,omitempty"`
	RecentInternalScan   map[int]time.Time           `json:"recent_internal_scan_seen,omitempty"`
	ShortLivedBurstLast  map[int]time.Time           `json:"short_lived_burst_last,omitempty"`
	ShortLivedBurstFirst map[int]time.Time           `json:"short_lived_burst_first,omitempty"`
	ShortLivedBurstCount map[int]int                 `json:"short_lived_burst_count,omitempty"`
	ShortLivedBurstIntv  map[int]time.Duration       `json:"short_lived_burst_interval,omitempty"`
	ShortLivedBurstHits  map[int]int                 `json:"short_lived_burst_hits,omitempty"`
	ShortLivedIntervals  map[int][]time.Duration     `json:"short_lived_intervals,omitempty"`
	InboundBurstLast     map[int]time.Time           `json:"inbound_burst_last,omitempty"`
	InboundBurstCount    map[int]int                 `json:"inbound_burst_count,omitempty"`
	BeaconSeen           map[int]time.Time           `json:"beacon_seen,omitempty"`
	LocalTransportLast   map[int]time.Time           `json:"local_transport_last,omitempty"`
	ConnFirstSeen        []connFirstSeenRecord       `json:"conn_first_seen,omitempty"`
	ParentChildFreq      map[string]int              `json:"parent_child_freq,omitempty"`
	RareTupleCount       map[string]int              `json:"rare_tuple_count,omitempty"`
}

type connFirstSeenRecord struct {
	PID        int       `json:"pid"`
	LocalAddr  string    `json:"local_addr"`
	LocalPort  int       `json:"local_port"`
	RemoteAddr string    `json:"remote_addr"`
	RemotePort int       `json:"remote_port"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen,omitempty"`
}

func NormalizeClassifierMemoryPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		path = defaultClassifierMemoryPath
	}
	path = safeio.ExpandHomePath(path)
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	rel := safeio.SanitizeRelativePath(path, "classifier-memory.json")
	return filepath.Join(safeio.ProxywatchDataRoot(), "runtime", rel)
}

func LoadClassifierMemory(path string) error {
	path = NormalizeClassifierMemoryPath(path)
	raw, err := safeio.ReadFile(path)
	if err != nil {
		return err
	}
	// Treat empty or corrupt (null-byte prefix) files as fresh state.
	if len(raw) == 0 || raw[0] == 0x00 {
		return nil
	}

	var disk classifierMemoryDisk
	if err := json.Unmarshal(raw, &disk); err != nil {
		// Corrupt file — start fresh rather than failing.
		return nil
	}
	if disk.Version <= 0 {
		disk.Version = classifierMemoryVersion
	}
	if disk.Version != classifierMemoryVersion {
		return fmt.Errorf("unsupported classifier memory version: %d", disk.Version)
	}

	ensureClassifierRuntimeMaps()
	cutoff := time.Now().UTC().Add(-classifierTimeRetention())
	connCutoff := time.Now().UTC().Add(-classifierConnRetention())

	ProcHistoryByPID = cloneProcHistoryMap(disk.ProcHistoryByPID, cutoff)
	ProcessBehaviorByKey = cloneProcessBehaviorMap(disk.ProcessBehaviorByKey, cutoff)
	RecentClientSeen = cloneIntTimeMap(disk.RecentClientSeen, cutoff)
	RecentOutboundSeen = cloneIntTimeMap(disk.RecentOutboundSeen, cutoff)
	RecentInternalScanSeen = cloneIntTimeMap(disk.RecentInternalScan, cutoff)
	ShortLivedBurstLast = cloneIntTimeMap(disk.ShortLivedBurstLast, cutoff)
	ShortLivedBurstFirst = cloneIntTimeMap(disk.ShortLivedBurstFirst, cutoff)
	ShortLivedBurstCount = cloneIntIntMap(disk.ShortLivedBurstCount)
	ShortLivedBurstInterval = cloneIntDurationMap(disk.ShortLivedBurstIntv)
	ShortLivedBurstHits = cloneIntIntMap(disk.ShortLivedBurstHits)
	ShortLivedIntervals = cloneIntDurationsMap(disk.ShortLivedIntervals)
	InboundBurstLast = cloneIntTimeMap(disk.InboundBurstLast, cutoff)
	InboundBurstCount = cloneIntIntMap(disk.InboundBurstCount)
	BeaconSeen = cloneIntTimeMap(disk.BeaconSeen, cutoff)
	LocalTransportLast = cloneIntTimeMap(disk.LocalTransportLast, cutoff)
	ParentChildFreq = cloneStringIntMap(disk.ParentChildFreq)
	RareTupleCount = cloneStringIntMap(disk.RareTupleCount)
	TrimStringIntMap(ParentChildFreq, classifierMemoryMaxCountItems)
	TrimStringIntMap(RareTupleCount, classifierMemoryMaxCountItems)

	ConnFirstSeen = make(map[ConnKey]time.Time, len(disk.ConnFirstSeen))
	ConnLastSeen = make(map[ConnKey]time.Time, len(disk.ConnFirstSeen))
	for _, item := range disk.ConnFirstSeen {
		if item.PID <= 0 || item.FirstSeen.IsZero() {
			continue
		}
		key := ConnKey{
			Pid:        item.PID,
			LocalAddr:  item.LocalAddr,
			LocalPort:  item.LocalPort,
			RemoteAddr: item.RemoteAddr,
			RemotePort: item.RemotePort,
		}
		ConnFirstSeen[key] = item.FirstSeen
		last := item.LastSeen
		if last.IsZero() || last.Before(connCutoff) {
			last = item.FirstSeen
		}
		if last.Before(connCutoff) {
			continue
		}
		ConnLastSeen[key] = last
	}

	if !disk.LastHistoryCleanup.IsZero() && disk.LastHistoryCleanup.After(cutoff) {
		LastHistoryCleanup = disk.LastHistoryCleanup
	} else {
		LastHistoryCleanup = time.Time{}
	}

	lastClassifierMemorySave = time.Now().UTC()
	return nil
}

func SaveClassifierMemory(path string) error {
	return saveClassifierMemory(path, time.Now().UTC())
}

func MaybeSaveClassifierMemory(path string, now time.Time) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if !lastClassifierMemorySave.IsZero() && now.Sub(lastClassifierMemorySave) < classifierMemorySaveInterval {
		return
	}
	_ = saveClassifierMemory(path, now)
}

func saveClassifierMemory(path string, now time.Time) error {
	path = NormalizeClassifierMemoryPath(path)
	ensureClassifierRuntimeMaps()
	pruneClassifierRuntimeMemory(now)

	disk := classifierMemoryDisk{
		Version:              classifierMemoryVersion,
		SavedAt:              now,
		LastHistoryCleanup:   LastHistoryCleanup,
		ProcHistoryByPID:     cloneProcHistoryMap(ProcHistoryByPID, time.Time{}),
		ProcessBehaviorByKey: cloneProcessBehaviorMap(ProcessBehaviorByKey, time.Time{}),
		RecentClientSeen:     cloneIntTimeMap(RecentClientSeen, time.Time{}),
		RecentOutboundSeen:   cloneIntTimeMap(RecentOutboundSeen, time.Time{}),
		RecentInternalScan:   cloneIntTimeMap(RecentInternalScanSeen, time.Time{}),
		ShortLivedBurstLast:  cloneIntTimeMap(ShortLivedBurstLast, time.Time{}),
		ShortLivedBurstFirst: cloneIntTimeMap(ShortLivedBurstFirst, time.Time{}),
		ShortLivedBurstCount: cloneIntIntMap(ShortLivedBurstCount),
		ShortLivedBurstIntv:  cloneIntDurationMap(ShortLivedBurstInterval),
		ShortLivedBurstHits:  cloneIntIntMap(ShortLivedBurstHits),
		ShortLivedIntervals:  cloneIntDurationsMap(ShortLivedIntervals),
		InboundBurstLast:     cloneIntTimeMap(InboundBurstLast, time.Time{}),
		InboundBurstCount:    cloneIntIntMap(InboundBurstCount),
		BeaconSeen:           cloneIntTimeMap(BeaconSeen, time.Time{}),
		LocalTransportLast:   cloneIntTimeMap(LocalTransportLast, time.Time{}),
		ParentChildFreq:      cloneStringIntMap(ParentChildFreq),
		RareTupleCount:       cloneStringIntMap(RareTupleCount),
	}
	TrimStringIntMap(disk.ParentChildFreq, classifierMemoryMaxCountItems)
	TrimStringIntMap(disk.RareTupleCount, classifierMemoryMaxCountItems)

	disk.ConnFirstSeen = make([]connFirstSeenRecord, 0, len(ConnFirstSeen))
	for key, first := range ConnFirstSeen {
		if first.IsZero() {
			continue
		}
		last := ConnLastSeen[key]
		if last.IsZero() {
			last = first
		}
		disk.ConnFirstSeen = append(disk.ConnFirstSeen, connFirstSeenRecord{
			PID:        key.Pid,
			LocalAddr:  key.LocalAddr,
			LocalPort:  key.LocalPort,
			RemoteAddr: key.RemoteAddr,
			RemotePort: key.RemotePort,
			FirstSeen:  first,
			LastSeen:   last,
		})
	}
	sort.Slice(disk.ConnFirstSeen, func(i, j int) bool {
		if disk.ConnFirstSeen[i].PID != disk.ConnFirstSeen[j].PID {
			return disk.ConnFirstSeen[i].PID < disk.ConnFirstSeen[j].PID
		}
		if disk.ConnFirstSeen[i].LocalAddr != disk.ConnFirstSeen[j].LocalAddr {
			return disk.ConnFirstSeen[i].LocalAddr < disk.ConnFirstSeen[j].LocalAddr
		}
		if disk.ConnFirstSeen[i].LocalPort != disk.ConnFirstSeen[j].LocalPort {
			return disk.ConnFirstSeen[i].LocalPort < disk.ConnFirstSeen[j].LocalPort
		}
		if disk.ConnFirstSeen[i].RemoteAddr != disk.ConnFirstSeen[j].RemoteAddr {
			return disk.ConnFirstSeen[i].RemoteAddr < disk.ConnFirstSeen[j].RemoteAddr
		}
		return disk.ConnFirstSeen[i].RemotePort < disk.ConnFirstSeen[j].RemotePort
	})

	data, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, classifierMemoryDirMode); err != nil {
			return err
		}
	}
	if err := os.WriteFile(path, data, classifierMemoryFileMode); err != nil {
		return err
	}
	lastClassifierMemorySave = now
	return nil
}

func ensureClassifierRuntimeMaps() {
	if ConnFirstSeen == nil {
		ConnFirstSeen = make(map[ConnKey]time.Time)
	}
	if ConnLastSeen == nil {
		ConnLastSeen = make(map[ConnKey]time.Time)
	}
	if RecentClientSeen == nil {
		RecentClientSeen = make(map[int]time.Time)
	}
	if RecentOutboundSeen == nil {
		RecentOutboundSeen = make(map[int]time.Time)
	}
	if RecentInternalScanSeen == nil {
		RecentInternalScanSeen = make(map[int]time.Time)
	}
	if ShortLivedBurstLast == nil {
		ShortLivedBurstLast = make(map[int]time.Time)
	}
	if ShortLivedBurstFirst == nil {
		ShortLivedBurstFirst = make(map[int]time.Time)
	}
	if ShortLivedBurstCount == nil {
		ShortLivedBurstCount = make(map[int]int)
	}
	if ShortLivedBurstInterval == nil {
		ShortLivedBurstInterval = make(map[int]time.Duration)
	}
	if ShortLivedBurstHits == nil {
		ShortLivedBurstHits = make(map[int]int)
	}
	if ShortLivedIntervals == nil {
		ShortLivedIntervals = make(map[int][]time.Duration)
	}
	if InboundBurstLast == nil {
		InboundBurstLast = make(map[int]time.Time)
	}
	if InboundBurstCount == nil {
		InboundBurstCount = make(map[int]int)
	}
	if BeaconSeen == nil {
		BeaconSeen = make(map[int]time.Time)
	}
	if LocalTransportLast == nil {
		LocalTransportLast = make(map[int]time.Time)
	}
	if ParentChildFreq == nil {
		ParentChildFreq = make(map[string]int)
	}
	if RareTupleCount == nil {
		RareTupleCount = make(map[string]int)
	}
	if ProcHistoryByPID == nil {
		ProcHistoryByPID = make(map[int]*ProcHistory)
	}
	if ProcessBehaviorByKey == nil {
		ProcessBehaviorByKey = make(map[string]*ProcessBehavior)
	}
}

func pruneClassifierRuntimeMemory(now time.Time) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	cutoff := now.Add(-classifierTimeRetention())
	connCutoff := now.Add(-classifierConnRetention())

	for pid, h := range ProcHistoryByPID {
		if h == nil || h.LastSeen.IsZero() || h.LastSeen.Before(cutoff) {
			dropPIDMemory(pid)
		}
	}
	for key, behavior := range ProcessBehaviorByKey {
		if behavior == nil {
			delete(ProcessBehaviorByKey, key)
			continue
		}
		if behavior.LastSeen.IsZero() || behavior.LastSeen.Before(cutoff) {
			delete(ProcessBehaviorByKey, key)
			continue
		}
		if len(behavior.KnownPrefixes) > classifierBehaviorMaxPrefixes {
			TrimStringIntMap(behavior.KnownPrefixes, classifierBehaviorMaxPrefixes)
		}
		if len(behavior.LastRoles) > 8 {
			TrimStringIntMap(behavior.LastRoles, 8)
		}
	}
	pruneIntTimeMap(RecentClientSeen, cutoff)
	pruneIntTimeMap(RecentOutboundSeen, cutoff)
	pruneIntTimeMap(RecentInternalScanSeen, cutoff)
	pruneIntTimeMap(ShortLivedBurstLast, cutoff)
	pruneIntTimeMap(ShortLivedBurstFirst, cutoff)
	pruneIntTimeMap(InboundBurstLast, cutoff)
	pruneIntTimeMap(BeaconSeen, cutoff)
	pruneIntTimeMap(LocalTransportLast, cutoff)

	for key, first := range ConnFirstSeen {
		last := ConnLastSeen[key]
		if last.IsZero() {
			last = first
		}
		if first.IsZero() || first.Before(connCutoff) || last.Before(connCutoff) {
			delete(ConnFirstSeen, key)
			delete(ConnLastSeen, key)
		}
	}

	TrimStringIntMap(ParentChildFreq, classifierMemoryMaxCountItems)
	TrimStringIntMap(RareTupleCount, classifierMemoryMaxCountItems)
	if len(ProcessBehaviorByKey) > classifierBehaviorMaxItems {
		trimProcessBehaviorMap(ProcessBehaviorByKey, classifierBehaviorMaxItems)
	}

	// Prune advanced behavioral trackers.
	for pid, tracker := range IOBurstHistory {
		if tracker == nil || tracker.LastUpdate.Before(cutoff) {
			delete(IOBurstHistory, pid)
		}
	}
	for pid, tracker := range ConnCountHistory {
		if tracker == nil || tracker.LastUpdate.Before(cutoff) {
			delete(ConnCountHistory, pid)
		}
	}
}

func dropPIDMemory(pid int) {
	delete(ProcHistoryByPID, pid)
	delete(RecentClientSeen, pid)
	delete(RecentOutboundSeen, pid)
	delete(RecentInternalScanSeen, pid)
	delete(ShortLivedBurstLast, pid)
	delete(ShortLivedBurstFirst, pid)
	delete(ShortLivedBurstCount, pid)
	delete(ShortLivedBurstInterval, pid)
	delete(ShortLivedBurstHits, pid)
	delete(ShortLivedIntervals, pid)
	delete(InboundBurstLast, pid)
	delete(InboundBurstCount, pid)
	delete(BeaconSeen, pid)
	delete(LocalTransportLast, pid)
	delete(IOBurstHistory, pid)
	delete(ConnCountHistory, pid)
	for key := range ConnFirstSeen {
		if key.Pid == pid {
			delete(ConnFirstSeen, key)
			delete(ConnLastSeen, key)
		}
	}
}

func classifierTimeRetention() time.Duration {
	retention := HistoryTTL
	windows := []time.Duration{
		ReverseControlMinDuration,
		SessionMinLabelDuration,
		TunnelMinLabelDuration,
		SMBPipeMinLabelDuration,
		BeaconMinLabelDuration,
		LongLivedOutboundMinAge,
		ShortLivedOutboundMaxAge,
		ShortLivedBurstWindow,
		SlowScanWindow,
		BeaconSleepThreshold,
		LocalTransportWindow,
		ActiveWindow,
		SuspicionWindow,
	}
	for _, w := range windows {
		if w > retention {
			retention = w
		}
	}
	if retention < 10*time.Minute {
		retention = 10 * time.Minute
	}
	return retention
}

func classifierConnRetention() time.Duration {
	retention := 2 * classifierTimeRetention()
	if retention < 30*time.Minute {
		retention = 30 * time.Minute
	}
	if retention > 24*time.Hour {
		retention = 24 * time.Hour
	}
	return retention
}

func cloneProcHistoryMap(in map[int]*ProcHistory, cutoff time.Time) map[int]*ProcHistory {
	out := make(map[int]*ProcHistory, len(in))
	for pid, h := range in {
		if h == nil {
			continue
		}
		hcopy := *h
		if !cutoff.IsZero() && !hcopy.LastSeen.IsZero() && hcopy.LastSeen.Before(cutoff) {
			continue
		}
		out[pid] = &hcopy
	}
	return out
}

func cloneIntTimeMap(in map[int]time.Time, cutoff time.Time) map[int]time.Time {
	out := make(map[int]time.Time, len(in))
	for k, v := range in {
		if !cutoff.IsZero() && !v.IsZero() && v.Before(cutoff) {
			continue
		}
		out[k] = v
	}
	return out
}

func cloneIntIntMap(in map[int]int) map[int]int {
	out := make(map[int]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneIntDurationMap(in map[int]time.Duration) map[int]time.Duration {
	out := make(map[int]time.Duration, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneIntDurationsMap(in map[int][]time.Duration) map[int][]time.Duration {
	out := make(map[int][]time.Duration, len(in))
	for k, vals := range in {
		if len(vals) == 0 {
			out[k] = nil
			continue
		}
		dst := make([]time.Duration, len(vals))
		copy(dst, vals)
		out[k] = dst
	}
	return out
}

func cloneStringIntMap(in map[string]int) map[string]int {
	out := make(map[string]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneProcessBehaviorMap(in map[string]*ProcessBehavior, cutoff time.Time) map[string]*ProcessBehavior {
	out := make(map[string]*ProcessBehavior, len(in))
	for key, behavior := range in {
		if behavior == nil {
			continue
		}
		copyBehavior := *behavior
		if !cutoff.IsZero() && !copyBehavior.LastSeen.IsZero() && copyBehavior.LastSeen.Before(cutoff) {
			continue
		}
		copyBehavior.KnownPrefixes = cloneStringIntMap(behavior.KnownPrefixes)
		copyBehavior.LastRoles = cloneStringIntMap(behavior.LastRoles)
		if len(copyBehavior.KnownPrefixes) > classifierBehaviorMaxPrefixes {
			TrimStringIntMap(copyBehavior.KnownPrefixes, classifierBehaviorMaxPrefixes)
		}
		if len(copyBehavior.LastRoles) > 8 {
			TrimStringIntMap(copyBehavior.LastRoles, 8)
		}
		out[key] = &copyBehavior
	}
	return out
}

func pruneIntTimeMap(in map[int]time.Time, cutoff time.Time) {
	for key, value := range in {
		if value.IsZero() || value.Before(cutoff) {
			delete(in, key)
		}
	}
}

// TrimStringIntMap prunes a string→int map to at most maxItems entries,
// keeping the highest-count keys (stable by key on ties).
func TrimStringIntMap(in map[string]int, maxItems int) {
	if len(in) <= maxItems || maxItems <= 0 {
		return
	}
	type item struct {
		key string
		val int
	}
	items := make([]item, 0, len(in))
	for key, val := range in {
		items = append(items, item{key: key, val: val})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].val != items[j].val {
			return items[i].val > items[j].val
		}
		return items[i].key < items[j].key
	})
	keep := make(map[string]struct{}, maxItems)
	for idx := 0; idx < maxItems && idx < len(items); idx++ {
		keep[items[idx].key] = struct{}{}
	}
	for key := range in {
		if _, ok := keep[key]; !ok {
			delete(in, key)
		}
	}
}

func trimProcessBehaviorMap(in map[string]*ProcessBehavior, maxItems int) {
	if len(in) <= maxItems || maxItems <= 0 {
		return
	}
	type item struct {
		key      string
		lastSeen time.Time
		count    int
	}
	items := make([]item, 0, len(in))
	for key, behavior := range in {
		if behavior == nil {
			continue
		}
		items = append(items, item{
			key:      key,
			lastSeen: behavior.LastSeen,
			count:    behavior.Observations,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if !items[i].lastSeen.Equal(items[j].lastSeen) {
			return items[i].lastSeen.After(items[j].lastSeen)
		}
		if items[i].count != items[j].count {
			return items[i].count > items[j].count
		}
		return items[i].key < items[j].key
	})
	keep := make(map[string]struct{}, maxItems)
	for idx := 0; idx < maxItems && idx < len(items); idx++ {
		keep[items[idx].key] = struct{}{}
	}
	for key := range in {
		if _, ok := keep[key]; !ok {
			delete(in, key)
		}
	}
}
