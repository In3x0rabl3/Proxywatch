// Package gbdt implements a pure-Go gradient boosted decision tree trainer
// for multiclass role classification. It provides a fully self-contained
// training system that outputs the proxywatch-lgbm-v1 JSON model format
// consumed by inference/native.go.
package gbdt

import "fmt"

// ErrorKind categorises training pipeline failures.
type ErrorKind int

const (
	ErrDataset    ErrorKind = iota // dataset loading failures
	ErrValidation                  // pre-training validation failures
	ErrTraining                    // algorithm failures (NaN, divergence, cancellation)
	ErrExport                      // model serialisation failures
	ErrEvaluation                  // evaluation / quality-gate failures
)

// TrainingError is a structured error returned by every stage of the pipeline.
type TrainingError struct {
	Kind    ErrorKind
	Op      string // operation: "ingest", "validate", "train", "export", "evaluate"
	Detail  string // human-readable detail shown in the training dashboard
	Wrapped error  // underlying error, if any
}

func (e *TrainingError) Error() string {
	if e.Wrapped != nil {
		return fmt.Sprintf("%s: %s: %v", e.Op, e.Detail, e.Wrapped)
	}
	return fmt.Sprintf("%s: %s", e.Op, e.Detail)
}

func (e *TrainingError) Unwrap() error { return e.Wrapped }

// ValidationResult summarises pre-training dataset checks.
type ValidationResult struct {
	Valid    bool
	Errors   []string // blocking — training must not proceed
	Warnings []string // non-blocking — shown in dashboard
}
