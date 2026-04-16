package shared

import (
	"strings"
	"sync"
	"testing"
)

// resetOperatorLabels is a test helper that clears the global label
// state so each test starts from a clean slate. Safe because tests
// don't run concurrently within the same package by default, and the
// globals are all guarded by opLabelMu.
func resetOperatorLabels(t *testing.T) {
	t.Helper()
	opLabelMu.Lock()
	opLabelStore = map[string]OperatorLabel{}
	opLabelInit = sync.Once{}
	opLabelMu.Unlock()
}

func TestOperatorLabel_SetLookupClear(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	resetOperatorLabels(t)

	hash := "deadbeef0000000000000000000000000000000000000000000000000000beef"

	// Lookup before set → nil.
	if l := LookupOperatorLabel(hash); l != nil {
		t.Errorf("before set: got %+v, want nil", l)
	}

	// Set benign.
	if err := SetOperatorLabel(hash, VerdictBenign, "review passed"); err != nil {
		t.Fatalf("SetOperatorLabel: %v", err)
	}
	l := LookupOperatorLabel(hash)
	if l == nil {
		t.Fatal("after set: Lookup returned nil")
	}
	if l.Verdict != VerdictBenign {
		t.Errorf("verdict = %q, want %q", l.Verdict, VerdictBenign)
	}
	if l.Reason != "review passed" {
		t.Errorf("reason = %q, want %q", l.Reason, "review passed")
	}
	if l.SetAt.IsZero() {
		t.Errorf("SetAt not populated")
	}

	// Upsert to malicious.
	if err := SetOperatorLabel(hash, VerdictMalicious, "confirmed c2"); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	l2 := LookupOperatorLabel(hash)
	if l2.Verdict != VerdictMalicious {
		t.Errorf("after upsert verdict = %q, want %q", l2.Verdict, VerdictMalicious)
	}

	// Clear.
	if err := ClearOperatorLabel(hash); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if l := LookupOperatorLabel(hash); l != nil {
		t.Errorf("after clear: got %+v, want nil", l)
	}
}

func TestOperatorLabel_InputValidation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	resetOperatorLabels(t)

	// Missing hash → error.
	if err := SetOperatorLabel("", VerdictBenign, ""); err == nil {
		t.Errorf("empty hash should error")
	}
	if err := SetOperatorLabel("  ", VerdictBenign, ""); err == nil {
		t.Errorf("whitespace hash should error")
	}

	// Invalid verdict → error.
	if err := SetOperatorLabel("abc", "maybe", ""); err == nil {
		t.Errorf("invalid verdict should error")
	}

	// Valid values accepted.
	if err := SetOperatorLabel("abc123", VerdictBenign, ""); err != nil {
		t.Errorf("valid verdict should not error: %v", err)
	}
	if err := SetOperatorLabel("abc123", VerdictMalicious, ""); err != nil {
		t.Errorf("valid verdict should not error: %v", err)
	}
}

func TestOperatorLabel_CaseInsensitiveLookup(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	resetOperatorLabels(t)

	if err := SetOperatorLabel("DEADBEEF", VerdictBenign, ""); err != nil {
		t.Fatalf("Set: %v", err)
	}
	// Lookup with different casing should find the label.
	for _, q := range []string{"deadbeef", "DeadBeef", "DEADBEEF", "  deadbeef  "} {
		if LookupOperatorLabel(q) == nil {
			t.Errorf("case/whitespace mismatch: %q didn't find label", q)
		}
	}
}

func TestOperatorLabel_ClearMissing_Idempotent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	resetOperatorLabels(t)

	// Clearing a non-existent label is a no-op.
	if err := ClearOperatorLabel("neverset0000000000"); err != nil {
		t.Errorf("clear-missing should be idempotent, got %v", err)
	}
	// Missing hash still errors.
	if err := ClearOperatorLabel(""); err == nil {
		t.Errorf("empty hash should error on clear")
	}
}

func TestOperatorLabel_ListSortedByVerdictThenHash(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	resetOperatorLabels(t)

	_ = SetOperatorLabel("bbb", VerdictMalicious, "")
	_ = SetOperatorLabel("aaa", VerdictMalicious, "")
	_ = SetOperatorLabel("ccc", VerdictBenign, "")

	labels := ListOperatorLabels()
	if len(labels) != 3 {
		t.Fatalf("got %d labels, want 3", len(labels))
	}
	// Expected order: benign first, then malicious; within each, SHA ascending.
	wantOrder := []struct {
		verdict string
		sha     string
	}{
		{VerdictBenign, "ccc"},
		{VerdictMalicious, "aaa"},
		{VerdictMalicious, "bbb"},
	}
	for i, w := range wantOrder {
		if labels[i].Verdict != w.verdict || labels[i].SHA256 != w.sha {
			t.Errorf("order[%d] = {%s, %s}, want {%s, %s}",
				i, labels[i].Verdict, labels[i].SHA256, w.verdict, w.sha)
		}
	}
}

func TestOperatorLabel_PersistsAcrossReload(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	resetOperatorLabels(t)

	hash := strings.Repeat("a", 64)
	if err := SetOperatorLabel(hash, VerdictBenign, "persisted"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Simulate process restart: reset the once+store, then Lookup
	// should re-hydrate from disk via loadOperatorLabelsFromDisk.
	resetOperatorLabels(t)

	l := LookupOperatorLabel(hash)
	if l == nil {
		t.Fatal("after reload: Lookup returned nil; persistence broken")
	}
	if l.Verdict != VerdictBenign {
		t.Errorf("after reload: verdict = %q, want %q", l.Verdict, VerdictBenign)
	}
	if l.Reason != "persisted" {
		t.Errorf("after reload: reason = %q, want %q", l.Reason, "persisted")
	}
}
