package gbdt

import (
	"context"
	"math"
	"math/rand/v2"

	"proxywatch/internal/detection/features"
)

// HyperParams controls the GBDT training algorithm.
type HyperParams struct {
	NEstimators    int     // boosting rounds (default 300)
	MaxDepth       int     // max tree depth (default 6)
	LearningRate   float64 // shrinkage factor (default 0.1)
	MinSamplesLeaf int     // minimum samples per leaf (default 10)
	Lambda         float64 // L2 regularisation on leaf values (default 1.0)
	SubsampleRatio float64 // row subsampling per round (default 0.8)
}

// DefaultHyperParams returns production defaults matching the original pipeline.
func DefaultHyperParams() HyperParams {
	return HyperParams{
		NEstimators:    300,
		MaxDepth:       6,
		LearningRate:   0.1,
		MinSamplesLeaf: 10,
		Lambda:         1.0,
		SubsampleRatio: 0.8,
	}
}

// Ensemble is a trained GBDT model (collection of trees).
type Ensemble struct {
	Trees       []Tree
	NumClasses  int
	RoleClasses []string
	Params      HyperParams
}

// PredictProbs returns softmax probabilities for a single sample.
func (e *Ensemble) PredictProbs(sample []float64) []float64 {
	rawScores := make([]float64, e.NumClasses)
	for i := range e.Trees {
		t := &e.Trees[i]
		if t.ClassIdx >= 0 && t.ClassIdx < e.NumClasses {
			rawScores[t.ClassIdx] += t.Predict(sample)
		}
	}
	return softmax(rawScores)
}

// PredictClass returns the argmax class for a single sample.
func (e *Ensemble) PredictClass(sample []float64) int {
	probs := e.PredictProbs(sample)
	best := 0
	for i := 1; i < len(probs); i++ {
		if probs[i] > probs[best] {
			best = i
		}
	}
	return best
}

// Train runs the full GBDT training loop using multiclass softmax cross-entropy.
// It supports cancellation via ctx.
func Train(ctx context.Context, ds *Dataset, params HyperParams) (*Ensemble, error) {
	n := len(ds.Y)
	if n == 0 {
		return nil, &TrainingError{Kind: ErrTraining, Op: "train", Detail: "empty dataset"}
	}

	numClasses := ds.NumClasses
	numFeatures := ds.NumFeatures

	// Initialise raw scores to zero.
	F := make([][]float64, n)
	for i := range F {
		F[i] = make([]float64, numClasses)
	}

	ensemble := &Ensemble{
		NumClasses:  numClasses,
		RoleClasses: RoleClasses,
		Params:      params,
	}

	// Pre-allocate gradient/hessian arrays.
	gradients := make([]float64, n)
	hessians := make([]float64, n)
	probs := make([][]float64, n)
	for i := range probs {
		probs[i] = make([]float64, numClasses)
	}

	// Deterministic RNG for subsampling.
	rng := rand.New(rand.NewPCG(42, 0))

	allIndices := make([]int, n)
	for i := range allIndices {
		allIndices[i] = i
	}

	treeCfg := TreeConfig{
		MaxDepth:       params.MaxDepth,
		MinSamplesLeaf: params.MinSamplesLeaf,
		NumFeatures:    numFeatures,
		Lambda:         params.Lambda,
	}

	for round := 0; round < params.NEstimators; round++ {
		// Check for cancellation.
		if ctx.Err() != nil {
			return nil, &TrainingError{Kind: ErrTraining, Op: "train", Detail: "cancelled", Wrapped: ctx.Err()}
		}

		// Compute softmax probabilities from current scores.
		for i := 0; i < n; i++ {
			probs[i] = softmax(F[i])
		}

		// Subsample rows.
		sampleIndices := allIndices
		if params.SubsampleRatio < 1.0 {
			sampleIndices = subsample(allIndices, params.SubsampleRatio, rng)
		}

		// For each class, compute gradients/hessians and build a tree.
		for c := 0; c < numClasses; c++ {
			// Compute weighted gradients and hessians.
			for _, i := range sampleIndices {
				target := 0.0
				if ds.Y[i] == c {
					target = 1.0
				}
				g := ds.Weights[i] * (probs[i][c] - target)
				h := ds.Weights[i] * probs[i][c] * (1.0 - probs[i][c])
				// Clamp hessian to avoid numerical issues.
				if h < 1e-8 {
					h = 1e-8
				}
				gradients[i] = g
				hessians[i] = h
			}

			// Build regression tree.
			tree := buildTree(treeCfg, ds.X, sampleIndices, gradients, hessians)
			tree.ClassIdx = c

			// Update scores.
			for _, i := range sampleIndices {
				F[i][c] += params.LearningRate * tree.Predict(ds.X[i])
			}

			ensemble.Trees = append(ensemble.Trees, tree)
		}
	}

	return ensemble, nil
}

// subsample selects a random fraction of indices.
func subsample(indices []int, ratio float64, rng *rand.Rand) []int {
	n := len(indices)
	k := int(math.Ceil(float64(n) * ratio))
	if k >= n {
		return indices
	}

	// Fisher-Yates partial shuffle.
	perm := make([]int, n)
	copy(perm, indices)
	for i := 0; i < k; i++ {
		j := i + rng.IntN(n-i)
		perm[i], perm[j] = perm[j], perm[i]
	}
	return perm[:k]
}

// softmax computes numerically-stable softmax.
// Matches the implementation in inference/native.go.
func softmax(raw []float64) []float64 {
	if len(raw) == 0 {
		return nil
	}
	maxVal := raw[0]
	for _, v := range raw[1:] {
		if v > maxVal {
			maxVal = v
		}
	}
	exps := make([]float64, len(raw))
	sum := 0.0
	for i, v := range raw {
		exps[i] = math.Exp(v - maxVal)
		sum += exps[i]
	}
	out := make([]float64, len(raw))
	for i := range exps {
		out[i] = exps[i] / sum
	}
	return out
}

// featureCount is a compile-time anchor ensuring we match the schema.
var _ = features.MaxFeatures
