package ml

import (
	"path/filepath"
	"testing"
	"time"

	"proxywatch/internal/detection/gbdt"
)

func rec(procKey string, ts time.Time) gbdt.TrainingRecord {
	return gbdt.TrainingRecord{
		ProcessKey: procKey,
		Timestamp:  ts,
		RuleRole:   "outbound",
	}
}

func TestTrainingBuffer_AddLenSnapshot(t *testing.T) {
	b := NewTrainingBuffer("")
	if b.Len() != 0 {
		t.Errorf("new buffer Len = %d, want 0", b.Len())
	}
	now := time.Now()
	b.Add(rec("host|/bin/a", now))
	b.Add(rec("host|/bin/b", now))
	if b.Len() != 2 {
		t.Errorf("Len after 2 adds = %d, want 2", b.Len())
	}
	snap := b.Snapshot()
	if len(snap) != 2 {
		t.Errorf("Snapshot = %d, want 2", len(snap))
	}
	// Snapshot returns a copy — mutating it doesn't affect the buffer.
	snap[0].ProcessKey = "mutated"
	snap2 := b.Snapshot()
	if snap2[0].ProcessKey == "mutated" {
		t.Errorf("Snapshot returned a reference, not a copy")
	}
}

func TestTrainingBuffer_DedupSameWindow(t *testing.T) {
	b := NewTrainingBuffer("")
	// Two records for the same process within the 5-minute window →
	// second should replace, not append.
	t0 := time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)
	b.Add(rec("host|/bin/sshd", t0))
	b.Add(rec("host|/bin/sshd", t0.Add(30*time.Second)))
	if b.Len() != 1 {
		t.Errorf("dedup within window: Len = %d, want 1", b.Len())
	}
}

func TestTrainingBuffer_NewWindowAddsNewEntry(t *testing.T) {
	b := NewTrainingBuffer("")
	t0 := time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)
	// 5-minute windows bucket on a Truncate(5 * time.Minute), so 12:04
	// shares a window with 12:00, but 12:05 is the next bucket.
	b.Add(rec("host|/bin/x", t0))
	b.Add(rec("host|/bin/x", t0.Add(5*time.Minute)))
	if b.Len() != 2 {
		t.Errorf("different windows: Len = %d, want 2", b.Len())
	}
}

func TestTrainingBuffer_Clear(t *testing.T) {
	b := NewTrainingBuffer("")
	now := time.Now()
	b.Add(rec("a", now))
	b.Add(rec("b", now))
	b.Clear()
	if b.Len() != 0 {
		t.Errorf("after Clear: Len = %d, want 0", b.Len())
	}
	// After clear, can still add new entries (seen map rebuilt).
	b.Add(rec("c", now))
	if b.Len() != 1 {
		t.Errorf("Add after Clear: Len = %d, want 1", b.Len())
	}
}

func TestTrainingBuffer_PersistAndLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "buffer.ndjson")

	// Write buffer with 3 records.
	b1 := NewTrainingBuffer(path)
	now := time.Now()
	for i, key := range []string{"host|/a", "host|/b", "host|/c"} {
		b1.Add(rec(key, now.Add(time.Duration(i)*6*time.Minute)))
	}
	if err := b1.PersistToDisk(); err != nil {
		t.Fatalf("PersistToDisk: %v", err)
	}

	// Load into fresh buffer.
	b2 := NewTrainingBuffer(path)
	if err := b2.LoadFromDisk(); err != nil {
		t.Fatalf("LoadFromDisk: %v", err)
	}
	if b2.Len() != 3 {
		t.Errorf("round-trip Len = %d, want 3", b2.Len())
	}
	// Verify content.
	snap := b2.Snapshot()
	keys := map[string]bool{}
	for _, r := range snap {
		keys[r.ProcessKey] = true
	}
	for _, want := range []string{"host|/a", "host|/b", "host|/c"} {
		if !keys[want] {
			t.Errorf("loaded buffer missing %q", want)
		}
	}
}

func TestTrainingBuffer_LoadMissingFileNoError(t *testing.T) {
	dir := t.TempDir()
	b := NewTrainingBuffer(filepath.Join(dir, "does-not-exist.ndjson"))
	if err := b.LoadFromDisk(); err != nil {
		t.Errorf("missing file should be silent no-op, got %v", err)
	}
	if b.Len() != 0 {
		t.Errorf("buffer should be empty, got %d", b.Len())
	}
}

func TestTrainingBuffer_ClearTruncatesDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "buffer.ndjson")

	b := NewTrainingBuffer(path)
	now := time.Now()
	b.Add(rec("a", now))
	b.Add(rec("b", now.Add(6*time.Minute)))
	_ = b.PersistToDisk()

	b.Clear()

	// Reload on a fresh buffer — should be empty because Clear
	// truncated the file.
	b2 := NewTrainingBuffer(path)
	_ = b2.LoadFromDisk()
	if b2.Len() != 0 {
		t.Errorf("after Clear+Reload, Len = %d, want 0", b2.Len())
	}
}

func TestDedupKey_SameWindowSameKey(t *testing.T) {
	t0 := time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)
	k1 := dedupKey("host|/bin/x", t0)
	k2 := dedupKey("host|/bin/x", t0.Add(30*time.Second))
	if k1 != k2 {
		t.Errorf("same window should share dedup key: %q != %q", k1, k2)
	}
	k3 := dedupKey("host|/bin/x", t0.Add(5*time.Minute))
	if k1 == k3 {
		t.Errorf("different window should produce different dedup key")
	}
	k4 := dedupKey("host|/bin/y", t0)
	if k1 == k4 {
		t.Errorf("different process should produce different dedup key")
	}
}
