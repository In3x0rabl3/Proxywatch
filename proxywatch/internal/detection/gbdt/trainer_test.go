package gbdt

import (
	"context"
	"math/rand"
	"testing"

	"proxywatch/internal/detection/features"
)

func TestDefaultHyperParams(t *testing.T) {
	p := DefaultHyperParams()
	// Sanity-check the defaults: positive counts, LearningRate in (0,1],
	// subsample ratio in (0,1].
	if p.NEstimators <= 0 {
		t.Errorf("NEstimators must be positive, got %d", p.NEstimators)
	}
	if p.MaxDepth <= 0 {
		t.Errorf("MaxDepth must be positive, got %d", p.MaxDepth)
	}
	if p.LearningRate <= 0 || p.LearningRate > 1 {
		t.Errorf("LearningRate out of range (0,1], got %f", p.LearningRate)
	}
	if p.SubsampleRatio <= 0 || p.SubsampleRatio > 1 {
		t.Errorf("SubsampleRatio out of range (0,1], got %f", p.SubsampleRatio)
	}
	if p.MinSamplesLeaf <= 0 {
		t.Errorf("MinSamplesLeaf must be positive, got %d", p.MinSamplesLeaf)
	}
}

// makeSyntheticDataset creates a small learnable dataset where each class
// is distinguishable by a single marker feature. A tiny GBDT trained on
// this should achieve well above random accuracy on held-out samples.
func makeSyntheticDataset(samplesPerClass int, seed int64) *Dataset {
	rng := rand.New(rand.NewSource(seed))
	ds := &Dataset{
		NumClasses:  NumClasses,
		NumFeatures: features.MaxFeatures,
		ClassCounts: make([]int, NumClasses),
	}
	// Marker feature per class: class k has feature k = strong signal,
	// plus noise across other features.
	for class := 0; class < NumClasses; class++ {
		for i := 0; i < samplesPerClass; i++ {
			row := make([]float64, features.MaxFeatures)
			// Marker feature.
			row[class] = 1.0 + rng.Float64()*0.3
			// Noise on a few other features.
			for j := 0; j < 5; j++ {
				idx := rng.Intn(features.MaxFeatures)
				if idx != class {
					row[idx] = rng.Float64() * 0.1
				}
			}
			ds.X = append(ds.X, row)
			ds.Y = append(ds.Y, class)
			ds.Weights = append(ds.Weights, 1.0)
			ds.ClassCounts[class]++
		}
	}
	return ds
}

func TestTrain_EndToEnd(t *testing.T) {
	// Train a tiny GBDT on the synthetic separable dataset and verify
	// it can recover the class marker.
	ds := makeSyntheticDataset(50, 42)

	params := HyperParams{
		NEstimators:    20, // small for fast test
		MaxDepth:       3,
		LearningRate:   0.3,
		MinSamplesLeaf: 5,
		Lambda:         1.0,
		SubsampleRatio: 1.0,
	}
	ensemble, err := Train(context.Background(), ds, params)
	if err != nil {
		t.Fatalf("Train failed: %v", err)
	}
	if ensemble == nil {
		t.Fatal("Train returned nil ensemble")
	}
	if ensemble.NumClasses != NumClasses {
		t.Errorf("ensemble NumClasses = %d, want %d", ensemble.NumClasses, NumClasses)
	}

	// Held-out accuracy check. Each held-out sample has the same marker
	// shape as training — a correctly-fitted model should hit every one.
	rng := rand.New(rand.NewSource(999))
	correct := 0
	total := 0
	for class := 0; class < NumClasses; class++ {
		for i := 0; i < 25; i++ {
			row := make([]float64, features.MaxFeatures)
			row[class] = 1.0 + rng.Float64()*0.3
			pred := ensemble.PredictClass(row)
			if pred == class {
				correct++
			}
			total++
		}
	}
	accuracy := float64(correct) / float64(total)
	// Synthetic separable task — a model that trains correctly hits near 100%.
	if accuracy < 0.80 {
		t.Errorf("synthetic accuracy too low: %.2f%% (%d/%d)", accuracy*100, correct, total)
	}
}

func TestEnsemble_PredictProbs_SumsToOne(t *testing.T) {
	ds := makeSyntheticDataset(20, 1)
	params := HyperParams{
		NEstimators:    10,
		MaxDepth:       3,
		LearningRate:   0.3,
		MinSamplesLeaf: 3,
		Lambda:         1.0,
		SubsampleRatio: 1.0,
	}
	ensemble, err := Train(context.Background(), ds, params)
	if err != nil {
		t.Fatalf("Train failed: %v", err)
	}

	row := make([]float64, features.MaxFeatures)
	row[0] = 1.0
	probs := ensemble.PredictProbs(row)
	if len(probs) != NumClasses {
		t.Fatalf("PredictProbs returned %d, want %d", len(probs), NumClasses)
	}
	sum := 0.0
	for _, p := range probs {
		if p < 0 || p > 1 {
			t.Errorf("prob out of [0,1]: %f", p)
		}
		sum += p
	}
	// Softmax: sum should be ~1.0.
	if sum < 0.99 || sum > 1.01 {
		t.Errorf("softmax sum = %f, want ~1.0", sum)
	}
}

func TestEnsemble_PredictClass_MatchesTopProb(t *testing.T) {
	ds := makeSyntheticDataset(20, 2)
	params := HyperParams{
		NEstimators:    10,
		MaxDepth:       3,
		LearningRate:   0.3,
		MinSamplesLeaf: 3,
		Lambda:         1.0,
		SubsampleRatio: 1.0,
	}
	ensemble, err := Train(context.Background(), ds, params)
	if err != nil {
		t.Fatalf("Train failed: %v", err)
	}

	// PredictClass must return argmax(PredictProbs).
	for class := 0; class < NumClasses; class++ {
		row := make([]float64, features.MaxFeatures)
		row[class] = 1.0
		probs := ensemble.PredictProbs(row)
		pred := ensemble.PredictClass(row)
		best := 0
		for i, p := range probs {
			if p > probs[best] {
				best = i
			}
		}
		if pred != best {
			t.Errorf("class %d: PredictClass=%d, but argmax(probs)=%d (probs=%v)",
				class, pred, best, probs)
		}
	}
}
