package gbdt

import (
	"fmt"
	"math"

	"proxywatch/internal/detection/features"
)

// Default and manual-trigger sample floors. Automated retrains use the
// higher floor so the pipeline doesn't burn compute on sparse buffers;
// operator-initiated retrains use the lower floor so manual "train now"
// works even when the buffer hasn't filled to the auto threshold.
const (
	DefaultMinTrainingSamples = 200
	ManualMinTrainingSamples  = 20
)

// ValidateDataset checks a dataset before training begins.
// If Valid is false, training must not proceed. minSamples is the hard
// floor on len(ds.Y); pass 0 to use DefaultMinTrainingSamples.
func ValidateDataset(ds *Dataset, minSamples int) ValidationResult {
	var r ValidationResult
	r.Valid = true

	if minSamples <= 0 {
		minSamples = DefaultMinTrainingSamples
	}

	if ds == nil || len(ds.Y) == 0 {
		r.Errors = append(r.Errors, "dataset is empty")
		r.Valid = false
		return r
	}

	// Minimum total samples.
	if len(ds.Y) < minSamples {
		r.Errors = append(r.Errors, fmt.Sprintf("insufficient samples: %d (need at least %d)", len(ds.Y), minSamples))
		r.Valid = false
	}

	// Signal count must match schema.
	if ds.NumFeatures != features.MaxFeatures {
		r.Errors = append(r.Errors, fmt.Sprintf("signal count mismatch: got %d, want %d", ds.NumFeatures, features.MaxFeatures))
		r.Valid = false
	}

	// Class distribution checks.
	hasAnyLabel := false
	for c := 0; c < NumClasses; c++ {
		if ds.ClassCounts[c] > 0 {
			hasAnyLabel = true
		}
		// Outbound class must exist (baseline for "normal" traffic).
		if c == 0 && ds.ClassCounts[c] == 0 {
			r.Errors = append(r.Errors, "no outbound (benign) samples — cannot establish baseline")
			r.Valid = false
		}
		// Warn on very small classes.
		if ds.ClassCounts[c] > 0 && ds.ClassCounts[c] < 5 {
			r.Warnings = append(r.Warnings, fmt.Sprintf("class %s has only %d samples", RoleClasses[c], ds.ClassCounts[c]))
		}
	}

	if !hasAnyLabel {
		r.Errors = append(r.Errors, "insufficient labels: no labeled samples found")
		r.Valid = false
	}

	// Warn if outbound dominates so heavily the model may underfit rare classes.
	if len(ds.Y) > 0 {
		outboundRatio := float64(ds.ClassCounts[0]) / float64(len(ds.Y))
		if outboundRatio > 0.99 {
			r.Warnings = append(r.Warnings, fmt.Sprintf("outbound dominates at %.1f%% — model may underfit control classes", outboundRatio*100))
		}
	}

	// Spot-check for NaN/Inf in features (sample first 100 rows).
	limit := len(ds.X)
	if limit > 100 {
		limit = 100
	}
	nanCount := 0
	for i := 0; i < limit; i++ {
		for j := 0; j < len(ds.X[i]); j++ {
			if math.IsNaN(ds.X[i][j]) || math.IsInf(ds.X[i][j], 0) {
				nanCount++
			}
		}
	}
	if nanCount > 0 {
		r.Warnings = append(r.Warnings, fmt.Sprintf("found %d NaN/Inf values in first %d rows — replaced with 0", nanCount, limit))
	}

	return r
}
