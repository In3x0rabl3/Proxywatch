package ml

import (
	"testing"

	"proxywatch/internal/detection/features"
)

// fakePredictor is a tiny Predictor implementation for testing the
// atomicPredictor swap + Close semantics without needing a trained model.
type fakePredictor struct {
	version   string
	classes   []string
	closeHits int
}

func (f *fakePredictor) PredictRole(fv features.FeatureVector) RolePrediction {
	return RolePrediction{TopRole: "outbound", TopProb: 0.99}
}
func (f *fakePredictor) ModelVersion() string { return f.version }
func (f *fakePredictor) RoleClasses() []string {
	if f.classes != nil {
		return f.classes
	}
	return []string{"outbound", "listener", "control-channel", "control-pivot"}
}
func (f *fakePredictor) Close() error {
	f.closeHits++
	return nil
}

func TestAtomicPredictor_GetSwapClose(t *testing.T) {
	initial := &fakePredictor{version: "v1"}
	ap := &atomicPredictor{pred: initial}

	// Get returns the initial predictor.
	got := ap.Get()
	if got.ModelVersion() != "v1" {
		t.Errorf("initial Get version = %q, want v1", got.ModelVersion())
	}

	// Swap in a new predictor — the old one should be Closed.
	replacement := &fakePredictor{version: "v2"}
	ap.Swap(replacement)
	if initial.closeHits != 1 {
		t.Errorf("old predictor Close not called on swap, closeHits = %d", initial.closeHits)
	}

	// Get now returns the new one.
	if ap.Get().ModelVersion() != "v2" {
		t.Errorf("after swap, Get version = %q, want v2", ap.Get().ModelVersion())
	}

	// Nil swap — accepted; no Close on nil.
	ap.Swap(nil)
	if replacement.closeHits != 1 {
		t.Errorf("v2 Close not called on nil swap, closeHits = %d", replacement.closeHits)
	}
	if ap.Get() != nil {
		t.Errorf("after nil swap, Get should return nil")
	}
}

func TestContinuousLearner_PredictorSwap(t *testing.T) {
	initial := &fakePredictor{version: "v1"}
	cl := NewContinuousLearner(initial)

	if cl.Predictor().ModelVersion() != "v1" {
		t.Errorf("initial predictor = %q, want v1", cl.Predictor().ModelVersion())
	}

	replacement := &fakePredictor{version: "v2"}
	cl.SwapPredictor(replacement)
	if cl.Predictor().ModelVersion() != "v2" {
		t.Errorf("after swap, predictor = %q, want v2", cl.Predictor().ModelVersion())
	}

	// SwapPredictor(nil) clears lastModelMod (so CheckForNewModel reloads
	// from disk after the next training cycle) and Closes the old one.
	cl.SwapPredictor(nil)
	if cl.Predictor() != nil {
		t.Errorf("after nil swap, Predictor should be nil")
	}
	if !cl.lastModelMod.IsZero() {
		t.Errorf("after nil swap, lastModelMod should be zero-time")
	}
}

func TestContinuousLearner_BufferAccessor(t *testing.T) {
	cl := NewContinuousLearner(&fakePredictor{version: "v1"})
	// Buffer() returns the learner's buffer — non-nil, initially empty.
	buf := cl.Buffer()
	if buf == nil {
		t.Fatal("Buffer() returned nil")
	}
	if buf.Len() != 0 {
		t.Errorf("new learner buffer Len = %d, want 0", buf.Len())
	}
}

func TestContinuousLearner_NotifyTrainingDoneNonBlocking(t *testing.T) {
	// NotifyTrainingDone uses a buffered channel with capacity 1 and a
	// non-blocking send — calling it when nobody's reading must not hang.
	cl := NewContinuousLearner(&fakePredictor{version: "v1"})
	// Fill the channel.
	cl.NotifyTrainingDone()
	// Second call — must also return immediately even though the channel
	// is already full.
	cl.NotifyTrainingDone()
	// If we got here, the non-blocking semantics held.
}
