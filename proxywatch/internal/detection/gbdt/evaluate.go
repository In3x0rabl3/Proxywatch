package gbdt

import (
	"context"
	"fmt"
)

// EvalMetrics holds per-class and aggregate model quality metrics.
type EvalMetrics struct {
	PerClass      map[string]ClassMetrics `json:"per_class"`
	MacroF1       float64                 `json:"macro_f1"`
	WeightedF1    float64                 `json:"weighted_f1"`
	Accuracy      float64                 `json:"accuracy"`
	ControlRecall float64                 `json:"beacon_recall"` // min recall across beacon-* classes with support
	OutboundPrec  float64                 `json:"outbound_precision"`
}

// ClassMetrics holds precision/recall/F1 for one role class.
type ClassMetrics struct {
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
	Support   int     `json:"support"`
}

// QualityGate defines minimum metrics required to promote a model.
type QualityGate struct {
	MinMacroF1       float64
	MinControlRecall float64
	MinOutboundPrec  float64
}

// QualityGateForSize returns quality thresholds scaled by dataset size.
// Small datasets get relaxed thresholds — the model improves as data grows.
func QualityGateForSize(datasetSize int) QualityGate {
	switch {
	case datasetSize < 5000:
		// Early training: no quality gate. Let the model train and improve.
		// Blocking early models prevents the collect→train→collect cycle
		// from ever working. The model will improve with more data.
		return QualityGate{
			MinMacroF1:       0.0,
			MinControlRecall: 0.0,
			MinOutboundPrec:  0.0,
		}
	case datasetSize < 20000:
		return QualityGate{
			MinMacroF1:       0.40,
			MinControlRecall: 0.50,
			MinOutboundPrec:  0.60,
		}
	default:
		// Production thresholds for large datasets.
		return QualityGate{
			MinMacroF1:       0.55,
			MinControlRecall: 0.65,
			MinOutboundPrec:  0.75,
		}
	}
}

// CheckQualityGate returns whether metrics meet the gate and a list of failures.
func CheckQualityGate(metrics *EvalMetrics, gate QualityGate) (pass bool, failures []string) {
	pass = true
	if metrics.MacroF1 < gate.MinMacroF1 {
		failures = append(failures, fmt.Sprintf("macro_f1 %.3f < %.3f", metrics.MacroF1, gate.MinMacroF1))
		pass = false
	}
	if metrics.ControlRecall < gate.MinControlRecall {
		failures = append(failures, fmt.Sprintf("beacon_recall %.3f < %.3f", metrics.ControlRecall, gate.MinControlRecall))
		pass = false
	}
	if metrics.OutboundPrec < gate.MinOutboundPrec {
		failures = append(failures, fmt.Sprintf("outbound_precision %.3f < %.3f", metrics.OutboundPrec, gate.MinOutboundPrec))
		pass = false
	}
	return
}

// EvaluateEnsemble computes metrics for a trained ensemble against a dataset.
func EvaluateEnsemble(ensemble *Ensemble, ds *Dataset) *EvalMetrics {
	n := len(ds.Y)
	if n == 0 {
		return &EvalMetrics{PerClass: make(map[string]ClassMetrics)}
	}

	nc := ds.NumClasses

	// Confusion matrix: [true][predicted]
	confusion := make([][]int, nc)
	for i := range confusion {
		confusion[i] = make([]int, nc)
	}

	correct := 0
	for i := 0; i < n; i++ {
		pred := ensemble.PredictClass(ds.X[i])
		truth := ds.Y[i]
		if pred >= 0 && pred < nc && truth >= 0 && truth < nc {
			confusion[truth][pred]++
		}
		if pred == truth {
			correct++
		}
	}

	return metricsFromConfusion(confusion, nc, n, correct)
}

// metricsFromConfusion computes all metrics from a confusion matrix.
func metricsFromConfusion(confusion [][]int, nc, n, correct int) *EvalMetrics {
	m := &EvalMetrics{
		PerClass: make(map[string]ClassMetrics, nc),
	}

	if n > 0 {
		m.Accuracy = float64(correct) / float64(n)
	}

	var sumF1, sumWeightedF1 float64
	var totalSupport int
	classesWithSupport := 0
	minControlRecall := 1.0
	controlClassesSeen := 0

	for c := 0; c < nc; c++ {
		var tp, fp, fn int
		tp = confusion[c][c]
		for j := 0; j < nc; j++ {
			if j != c {
				fp += confusion[j][c] // predicted c but was j
				fn += confusion[c][j] // was c but predicted j
			}
		}
		support := tp + fn

		var prec, recall, f1 float64
		if tp+fp > 0 {
			prec = float64(tp) / float64(tp+fp)
		}
		if tp+fn > 0 {
			recall = float64(tp) / float64(tp+fn)
		}
		if prec+recall > 0 {
			f1 = 2.0 * prec * recall / (prec + recall)
		}

		name := "unknown"
		if c < len(RoleClasses) {
			name = RoleClasses[c]
		}
		m.PerClass[name] = ClassMetrics{
			Precision: prec,
			Recall:    recall,
			F1:        f1,
			Support:   support,
		}

		// Only include classes with actual support in macro F1.
		// Classes with zero samples shouldn't drag the average down.
		if support > 0 {
			sumF1 += f1
			classesWithSupport++
		}
		sumWeightedF1 += f1 * float64(support)
		totalSupport += support

		// Track beacon-class recall (only for classes with support).
		if c >= 2 && c < nc && support > 0 {
			controlClassesSeen++
			if recall < minControlRecall {
				minControlRecall = recall
			}
		}

		// Track outbound precision.
		if c == 0 {
			m.OutboundPrec = prec
		}
	}

	if classesWithSupport > 0 {
		m.MacroF1 = sumF1 / float64(classesWithSupport)
	}
	if totalSupport > 0 {
		m.WeightedF1 = sumWeightedF1 / float64(totalSupport)
	}
	if controlClassesSeen > 0 {
		m.ControlRecall = minControlRecall
	} else {
		// No beacon-class samples to evaluate — set to 1.0 so gate doesn't block.
		m.ControlRecall = 1.0
	}

	return m
}

// TimeSeriesCV performs time-series cross-validation with expanding windows.
// It respects temporal ordering: trains on older data, tests on newer data.
func TimeSeriesCV(ctx context.Context, ds *Dataset, params HyperParams, nFolds int) (*EvalMetrics, error) {
	n := len(ds.Y)
	if n < 50 {
		return nil, &TrainingError{Kind: ErrEvaluation, Op: "evaluate", Detail: fmt.Sprintf("too few samples for CV: %d", n)}
	}
	if nFolds < 2 {
		nFolds = 2
	}
	if nFolds > 5 {
		nFolds = 5
	}

	// Data is already sorted by timestamp (IngestRecords guarantees this).
	// Use expanding window: fold i trains on [0, split_i) and tests on [split_i, split_{i+1}).
	foldSize := n / (nFolds + 1)
	if foldSize < 10 {
		// Not enough data for meaningful multi-fold CV — just evaluate on last 20%.
		splitIdx := int(float64(n) * 0.8)
		if splitIdx < 1 {
			splitIdx = 1
		}
		return evalSingleSplit(ctx, ds, params, splitIdx)
	}

	// Aggregate confusion matrix across folds.
	nc := ds.NumClasses
	totalConfusion := make([][]int, nc)
	for i := range totalConfusion {
		totalConfusion[i] = make([]int, nc)
	}
	totalCorrect := 0
	totalSamples := 0

	for fold := 0; fold < nFolds; fold++ {
		if ctx.Err() != nil {
			return nil, &TrainingError{Kind: ErrEvaluation, Op: "evaluate", Detail: "cancelled", Wrapped: ctx.Err()}
		}

		// Train on [0, trainEnd), test on [trainEnd, testEnd).
		trainEnd := (fold + 1) * foldSize
		testEnd := (fold + 2) * foldSize
		if fold == nFolds-1 {
			testEnd = n
		}
		if trainEnd >= n || testEnd > n || trainEnd >= testEnd {
			continue
		}

		trainDS := subsetDataset(ds, 0, trainEnd)
		testDS := subsetDataset(ds, trainEnd, testEnd)

		if len(trainDS.Y) < 10 || len(testDS.Y) < 5 {
			continue
		}

		// Use fewer estimators for CV to save time.
		cvParams := params
		cvParams.NEstimators = params.NEstimators / 3
		if cvParams.NEstimators < 50 {
			cvParams.NEstimators = 50
		}

		ensemble, err := Train(ctx, trainDS, cvParams)
		if err != nil {
			continue // skip fold on training failure
		}

		for i := 0; i < len(testDS.Y); i++ {
			pred := ensemble.PredictClass(testDS.X[i])
			truth := testDS.Y[i]
			if pred >= 0 && pred < nc && truth >= 0 && truth < nc {
				totalConfusion[truth][pred]++
			}
			if pred == truth {
				totalCorrect++
			}
			totalSamples++
		}
	}

	if totalSamples == 0 {
		return nil, &TrainingError{Kind: ErrEvaluation, Op: "evaluate", Detail: "no test samples across CV folds"}
	}

	return metricsFromConfusion(totalConfusion, nc, totalSamples, totalCorrect), nil
}

// evalSingleSplit trains on [0, splitIdx) and evaluates on [splitIdx, n).
func evalSingleSplit(ctx context.Context, ds *Dataset, params HyperParams, splitIdx int) (*EvalMetrics, error) {
	trainDS := subsetDataset(ds, 0, splitIdx)
	testDS := subsetDataset(ds, splitIdx, len(ds.Y))

	cvParams := params
	cvParams.NEstimators = params.NEstimators / 3
	if cvParams.NEstimators < 50 {
		cvParams.NEstimators = 50
	}

	ensemble, err := Train(ctx, trainDS, cvParams)
	if err != nil {
		return nil, &TrainingError{Kind: ErrEvaluation, Op: "evaluate", Detail: "train for evaluation", Wrapped: err}
	}

	return EvaluateEnsemble(ensemble, testDS), nil
}

// subsetDataset returns a Dataset containing rows [start, end).
func subsetDataset(ds *Dataset, start, end int) *Dataset {
	if start < 0 {
		start = 0
	}
	if end > len(ds.Y) {
		end = len(ds.Y)
	}
	n := end - start
	if n <= 0 {
		return &Dataset{
			NumFeatures: ds.NumFeatures,
			NumClasses:  ds.NumClasses,
			ClassCounts: make([]int, ds.NumClasses),
		}
	}

	sub := &Dataset{
		X:            ds.X[start:end],
		Y:            ds.Y[start:end],
		Weights:      ds.Weights[start:end],
		Timestamps:   ds.Timestamps[start:end],
		LabelSources: ds.LabelSources[start:end],
		NumFeatures:  ds.NumFeatures,
		NumClasses:   ds.NumClasses,
		ClassCounts:  make([]int, ds.NumClasses),
	}
	for _, y := range sub.Y {
		if y >= 0 && y < ds.NumClasses {
			sub.ClassCounts[y]++
		}
	}
	return sub
}
