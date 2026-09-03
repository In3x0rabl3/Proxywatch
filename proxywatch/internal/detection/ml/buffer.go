package ml

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"proxywatch/internal/detection/features"
	"proxywatch/internal/detection/gbdt"
	"proxywatch/internal/detection/model"
)

// TrainingBuffer collects feature snapshots for continuous learning.
// It deduplicates by (process_key, 5-minute window) and persists
// overflow to disk.
type TrainingBuffer struct {
	mu       sync.Mutex
	records  []gbdt.TrainingRecord
	seen     map[string]int // dedup_key → index in records
	maxSize  int
	diskPath string
}

const (
	DefaultBufferSize  = 10000
	BufferDiskMaxBytes = 50 * 1024 * 1024 // 50MB
)

// NewTrainingBuffer creates a buffer that persists overflow to diskPath.
func NewTrainingBuffer(diskPath string) *TrainingBuffer {
	return &TrainingBuffer{
		records:  make([]gbdt.TrainingRecord, 0, 1024),
		seen:     make(map[string]int, 1024),
		maxSize:  DefaultBufferSize,
		diskPath: diskPath,
	}
}

// Add inserts a training record, deduplicating by process key + 5-minute window.
func (b *TrainingBuffer) Add(rec gbdt.TrainingRecord) {
	b.mu.Lock()
	defer b.mu.Unlock()

	dk := dedupKey(rec.ProcessKey, rec.Timestamp)

	if idx, ok := b.seen[dk]; ok {
		// Keep the higher-weight version.
		// (We don't have weight on TrainingRecord, so keep the newer one.)
		if idx < len(b.records) {
			b.records[idx] = rec
		}
		return
	}

	if len(b.records) >= b.maxSize {
		// Evict oldest 20%.
		evict := b.maxSize / 5
		b.records = b.records[evict:]
		// Rebuild seen map.
		b.seen = make(map[string]int, len(b.records))
		for i, r := range b.records {
			b.seen[dedupKey(r.ProcessKey, r.Timestamp)] = i
		}
	}

	b.seen[dk] = len(b.records)
	b.records = append(b.records, rec)
}

// Clear removes all buffered records and truncates the disk file.
func (b *TrainingBuffer) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.records = b.records[:0]
	b.seen = make(map[string]int, 1024)
	if b.diskPath != "" {
		_ = os.Truncate(b.diskPath, 0)
	}
}

// Len returns the number of buffered records.
func (b *TrainingBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.records)
}

// Snapshot returns a copy of all buffered records.
func (b *TrainingBuffer) Snapshot() []gbdt.TrainingRecord {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]gbdt.TrainingRecord, len(b.records))
	copy(out, b.records)
	return out
}

// PersistToDisk writes the buffer to a NDJSON file for offline training.
func (b *TrainingBuffer) PersistToDisk() error {
	b.mu.Lock()
	records := make([]gbdt.TrainingRecord, len(b.records))
	copy(records, b.records)
	b.mu.Unlock()

	if b.diskPath == "" {
		return nil
	}
	if len(records) == 0 {
		// Buffer was cleared — truncate the disk file so stale data
		// doesn't reload on next startup.
		_ = os.Truncate(b.diskPath, 0)
		return nil
	}

	dir := filepath.Dir(b.diskPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create buffer dir: %w", err)
	}

	// Check size limit.
	if info, err := os.Stat(b.diskPath); err == nil && info.Size() >= BufferDiskMaxBytes {
		// Truncate: keep only the recent half.
		half := len(records) / 2
		records = records[half:]
	}

	f, err := os.OpenFile(b.diskPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, rec := range records {
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	return nil
}

// PersistTo writes all buffered records to the given path.
func (b *TrainingBuffer) PersistTo(path string) error {
	records := b.Snapshot()
	if len(records) == 0 {
		return nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, rec := range records {
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	return nil
}

// LoadFromDisk reads persisted records back into the buffer.
// Records older than maxAge are skipped — they may reflect stale process
// behavior (the box was reconfigured, a vendor app got updated and now
// behaves differently, an operator labeled a binary maliciously) so we
// don't want them to dominate a fresh training run. maxAge<=0 means no
// recency filter (load everything).
//
// Each record's Signals slice is re-filtered through the same noise-prune
// rule the live training pipeline applies (signals with proven 0% precision
// over ≥500 samples get stripped). This recovers a polluted historical
// buffer — without this step, the existing 21K+ records on disk continue
// dragging maturity / shadow-agreement metrics down even after the
// write-side filter is in place.
func (b *TrainingBuffer) LoadFromDisk(maxAge time.Duration) error {
	if b.diskPath == "" {
		return nil
	}

	f, err := os.Open(b.diskPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	cutoff := time.Time{}
	if maxAge > 0 {
		cutoff = time.Now().Add(-maxAge)
	}

	dec := json.NewDecoder(f)
	b.mu.Lock()
	defer b.mu.Unlock()

	pruned := 0
	for dec.More() {
		var rec gbdt.TrainingRecord
		if err := dec.Decode(&rec); err != nil {
			break
		}
		if !cutoff.IsZero() && rec.Timestamp.Before(cutoff) {
			continue
		}
		// Re-apply the noise-prune filter at load time so already-
		// persisted training records lose their proven-noise signals.
		// Same precision floor / sample threshold as the write-side
		// filter in classifier.go.
		before := len(rec.Signals)
		rec.Signals = pruneNoiseSignals(rec.Signals)
		if len(rec.Signals) < before {
			pruned++
		}
		dk := dedupKey(rec.ProcessKey, rec.Timestamp)
		if _, ok := b.seen[dk]; !ok && len(b.records) < b.maxSize {
			b.seen[dk] = len(b.records)
			b.records = append(b.records, rec)
		}
	}
	if pruned > 0 {
		// Single info line — caller can log via shared.LogInfo if it
		// wants, but ml/ doesn't import shared/ to keep dep graph clean.
		_ = pruned
	}
	return nil
}

// pruneNoiseSignals strips signals with proven low precision from a
// training-record signal slice. Mirrors filterLowPrecisionTrainingSignals
// in detection/classifier.go — duplicated here to avoid a cycle (the
// classifier already imports ml). Uses the global model.LookupSignalStat.
//
// Thresholds match the write-side filter: ≥500 samples to count as
// "proven", <5% precision to count as "noise", ≥30% precision to
// always keep regardless of sample size.
func pruneNoiseSignals(signals []string) []string {
	if len(signals) == 0 {
		return signals
	}
	const (
		minSamples     = 500
		precisionFloor = 0.05
		decisiveFloor  = 0.30
	)
	out := signals[:0:len(signals)]
	for _, s := range signals {
		stat := model.LookupSignalStat(s)
		if stat != nil && stat.Total >= minSamples &&
			stat.Precision < precisionFloor &&
			stat.Precision < decisiveFloor {
			continue
		}
		out = append(out, s)
	}
	if len(out) == len(signals) {
		dup := make([]string, len(signals))
		copy(dup, signals)
		return dup
	}
	dup := make([]string, len(out))
	copy(dup, out)
	return dup
}

// FeatureMatrix returns the feature values and labels for training.
func (b *TrainingBuffer) FeatureMatrix() ([]features.FeatureVector, []string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	fvs := make([]features.FeatureVector, 0, len(b.records))
	labels := make([]string, 0, len(b.records))

	for _, rec := range b.records {
		var fv features.FeatureVector
		fv.Valid = true
		for i, name := range features.FeatureNames() {
			if v, ok := rec.Features[name]; ok {
				fv.Values[i] = v
			}
		}
		label := rec.RuleRole
		if rec.OperatorLabel != nil {
			label = *rec.OperatorLabel
		}
		if label == "" {
			label = "outbound"
		}
		fvs = append(fvs, fv)
		labels = append(labels, label)
	}
	return fvs, labels
}

func dedupKey(processKey string, ts time.Time) string {
	// 5-minute window.
	window := ts.Truncate(5 * time.Minute).Unix()
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%d", processKey, window)))
	return hex.EncodeToString(h[:8])
}
