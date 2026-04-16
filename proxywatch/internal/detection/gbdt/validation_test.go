package gbdt

import (
	"math"
	"testing"

	"proxywatch/internal/detection/features"
)

// makeDataset builds a small valid dataset for validation tests.
// classCounts[i] = how many samples of class i to include.
func makeDataset(classCounts [NumClasses]int) *Dataset {
	ds := &Dataset{
		NumClasses:  NumClasses,
		NumFeatures: features.MaxFeatures,
		ClassCounts: make([]int, NumClasses),
	}
	for class, n := range classCounts {
		for i := 0; i < n; i++ {
			ds.X = append(ds.X, make([]float64, features.MaxFeatures))
			ds.Y = append(ds.Y, class)
			ds.ClassCounts[class]++
		}
	}
	return ds
}

func TestValidateDataset_Nil(t *testing.T) {
	r := ValidateDataset(nil, 0)
	if r.Valid {
		t.Errorf("nil dataset should fail validation")
	}
}

func TestValidateDataset_Empty(t *testing.T) {
	r := ValidateDataset(&Dataset{NumFeatures: features.MaxFeatures}, 0)
	if r.Valid {
		t.Errorf("empty dataset should fail")
	}
}

func TestValidateDataset_InsufficientSamples(t *testing.T) {
	ds := makeDataset([4]int{100, 10, 10, 10})
	r := ValidateDataset(ds, DefaultMinTrainingSamples)
	if r.Valid {
		t.Errorf("130 samples is below 200 default floor; should fail")
	}
	// Manual floor (20) — same dataset passes on sample count.
	r2 := ValidateDataset(ds, ManualMinTrainingSamples)
	// Will still need other checks to pass — verify the specific error is gone.
	for _, e := range r2.Errors {
		if contains(e, "insufficient samples") {
			t.Errorf("manual floor: insufficient-samples error should be gone; got %v", r2.Errors)
		}
	}
}

func TestValidateDataset_MissingOutbound(t *testing.T) {
	// Dataset with no outbound class samples → validation error.
	ds := makeDataset([4]int{0, 100, 100, 100})
	r := ValidateDataset(ds, 0)
	if r.Valid {
		t.Errorf("dataset with no outbound should fail validation")
	}
	found := false
	for _, e := range r.Errors {
		if contains(e, "outbound") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected outbound-related error, got %v", r.Errors)
	}
}

func TestValidateDataset_SchemaMismatch(t *testing.T) {
	ds := makeDataset([4]int{100, 50, 50, 50})
	ds.NumFeatures = 99 // wrong
	r := ValidateDataset(ds, 0)
	if r.Valid {
		t.Errorf("wrong feature count should fail")
	}
}

func TestValidateDataset_SmallClassWarning(t *testing.T) {
	// Class with < 5 samples → warning, not error (still valid).
	ds := makeDataset([4]int{250, 3, 100, 100}) // listener has only 3
	r := ValidateDataset(ds, 0)
	if !r.Valid {
		t.Errorf("small class should warn but pass; got %v", r.Errors)
	}
	if len(r.Warnings) == 0 {
		t.Errorf("expected small-class warning")
	}
}

func TestValidateDataset_OutboundDominanceWarning(t *testing.T) {
	// Outbound at >99% → warning.
	ds := makeDataset([4]int{1000, 1, 1, 1})
	r := ValidateDataset(ds, 0)
	if !r.Valid {
		t.Errorf("dominant-outbound should warn but pass; got %v", r.Errors)
	}
	found := false
	for _, w := range r.Warnings {
		if contains(w, "outbound dominates") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected outbound-dominance warning, got %v", r.Warnings)
	}
}

func TestValidateDataset_NaNInFeatures(t *testing.T) {
	ds := makeDataset([NumClasses]int{100, 50, 50, 50})
	// Inject NaN into one feature of one sample.
	ds.X[0][0] = math.NaN()
	r := ValidateDataset(ds, 0)
	// NaN currently generates a warning (values are replaced with 0),
	// not an error — validation still passes.
	if !r.Valid {
		t.Errorf("NaN should warn but not fail; got errors %v", r.Errors)
	}
	found := false
	for _, w := range r.Warnings {
		if contains(w, "NaN") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected NaN warning in %v", r.Warnings)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
