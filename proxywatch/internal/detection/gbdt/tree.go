package gbdt

import (
	"math"
	"sort"
)

// TreeNode is a single node in a decision tree.
// JSON tags match the format expected by inference/native.go exactly.
type TreeNode struct {
	Idx          int     `json:"idx"`
	Leaf         bool    `json:"leaf"`
	Value        float64 `json:"value"`
	Feature      int     `json:"feature"`
	Threshold    float64 `json:"threshold"`
	DecisionType string  `json:"decision_type"`
	Left         int     `json:"left"`
	Right        int     `json:"right"`
}

// Tree is a single decision tree that predicts for one class.
type Tree struct {
	ClassIdx int
	Nodes    []TreeNode
}

// Predict traverses the tree for a single sample and returns the leaf value.
func (t *Tree) Predict(sample []float64) float64 {
	if len(t.Nodes) == 0 {
		return 0
	}
	idx := 0
	for {
		if idx < 0 || idx >= len(t.Nodes) {
			return 0
		}
		n := t.Nodes[idx]
		if n.Leaf {
			return n.Value
		}
		if n.Feature < 0 || n.Feature >= len(sample) {
			return 0
		}
		if sample[n.Feature] <= n.Threshold {
			idx = n.Left
		} else {
			idx = n.Right
		}
	}
}

// TreeConfig controls tree construction.
type TreeConfig struct {
	MaxDepth       int
	MinSamplesLeaf int
	NumFeatures    int
	Lambda         float64 // L2 regularisation on leaf values
}

// treeBuilder accumulates nodes during recursive construction.
type treeBuilder struct {
	cfg        TreeConfig
	X          [][]float64
	gradients  []float64
	hessians   []float64
	nodes      []TreeNode
	sortedIdxs [][]int // pre-sorted sample indices per feature
}

// buildTree constructs a regression tree fitting the given gradients/hessians.
// sampleIndices selects which rows of X to use.
func buildTree(cfg TreeConfig, X [][]float64, sampleIndices []int, gradients, hessians []float64) Tree {
	b := &treeBuilder{
		cfg:       cfg,
		X:         X,
		gradients: gradients,
		hessians:  hessians,
	}

	// Pre-sort sample indices by each feature value for efficient split finding.
	b.sortedIdxs = make([][]int, cfg.NumFeatures)
	for f := 0; f < cfg.NumFeatures; f++ {
		sorted := make([]int, len(sampleIndices))
		copy(sorted, sampleIndices)
		feat := f // capture for closure
		sort.Slice(sorted, func(i, j int) bool {
			return X[sorted[i]][feat] < X[sorted[j]][feat]
		})
		b.sortedIdxs[f] = sorted
	}

	// Build membership set for quick lookups.
	memberSet := make(map[int]struct{}, len(sampleIndices))
	for _, idx := range sampleIndices {
		memberSet[idx] = struct{}{}
	}

	b.buildNode(sampleIndices, memberSet, 0)

	return Tree{Nodes: b.nodes}
}

// buildNode recursively builds a tree node and returns its index in b.nodes.
func (b *treeBuilder) buildNode(indices []int, memberSet map[int]struct{}, depth int) int {
	nodeIdx := len(b.nodes)
	b.nodes = append(b.nodes, TreeNode{Idx: nodeIdx})

	// Leaf conditions: max depth, insufficient samples, or no data.
	if depth >= b.cfg.MaxDepth || len(indices) < 2*b.cfg.MinSamplesLeaf || len(indices) == 0 {
		b.nodes[nodeIdx].Leaf = true
		b.nodes[nodeIdx].Value = b.leafValue(indices)
		return nodeIdx
	}

	split := b.findBestSplit(indices, memberSet)
	if split.gain <= 0 {
		b.nodes[nodeIdx].Leaf = true
		b.nodes[nodeIdx].Value = b.leafValue(indices)
		return nodeIdx
	}

	leftIndices, rightIndices := b.partition(indices, split)
	if len(leftIndices) < b.cfg.MinSamplesLeaf || len(rightIndices) < b.cfg.MinSamplesLeaf {
		b.nodes[nodeIdx].Leaf = true
		b.nodes[nodeIdx].Value = b.leafValue(indices)
		return nodeIdx
	}

	b.nodes[nodeIdx].Feature = split.feature
	b.nodes[nodeIdx].Threshold = split.threshold
	b.nodes[nodeIdx].DecisionType = "<="

	// Build left and right subtrees.
	leftSet := make(map[int]struct{}, len(leftIndices))
	for _, idx := range leftIndices {
		leftSet[idx] = struct{}{}
	}
	rightSet := make(map[int]struct{}, len(rightIndices))
	for _, idx := range rightIndices {
		rightSet[idx] = struct{}{}
	}

	leftIdx := b.buildNode(leftIndices, leftSet, depth+1)
	rightIdx := b.buildNode(rightIndices, rightSet, depth+1)

	b.nodes[nodeIdx].Left = leftIdx
	b.nodes[nodeIdx].Right = rightIdx
	return nodeIdx
}

// leafValue computes the optimal leaf value: -sum(grad) / (sum(hess) + lambda).
func (b *treeBuilder) leafValue(indices []int) float64 {
	var sumGrad, sumHess float64
	for _, i := range indices {
		sumGrad += b.gradients[i]
		sumHess += b.hessians[i]
	}
	denom := sumHess + b.cfg.Lambda
	if math.Abs(denom) < 1e-10 {
		return 0
	}
	return -sumGrad / denom
}

// splitCandidate describes a potential split point.
type splitCandidate struct {
	feature   int
	threshold float64
	gain      float64
}

// findBestSplit scans all features for the split with maximum gain.
func (b *treeBuilder) findBestSplit(indices []int, memberSet map[int]struct{}) splitCandidate {
	// Total gradient/hessian sums.
	var totalGrad, totalHess float64
	for _, i := range indices {
		totalGrad += b.gradients[i]
		totalHess += b.hessians[i]
	}

	best := splitCandidate{gain: -1}

	for f := 0; f < b.cfg.NumFeatures; f++ {
		b.scanFeature(f, memberSet, totalGrad, totalHess, &best)
	}

	return best
}

// scanFeature evaluates all candidate thresholds for one feature using pre-sorted indices.
func (b *treeBuilder) scanFeature(f int, memberSet map[int]struct{}, totalGrad, totalHess float64, best *splitCandidate) {
	sorted := b.sortedIdxs[f]

	// Filter to only members of current node.
	active := make([]int, 0, len(memberSet))
	for _, idx := range sorted {
		if _, ok := memberSet[idx]; ok {
			active = append(active, idx)
		}
	}

	if len(active) < 2*b.cfg.MinSamplesLeaf {
		return
	}

	var leftGrad, leftHess float64
	leftCount := 0

	for i := 0; i < len(active)-1; i++ {
		idx := active[i]
		leftGrad += b.gradients[idx]
		leftHess += b.hessians[idx]
		leftCount++

		// Only evaluate split between distinct feature values.
		if b.X[active[i]][f] == b.X[active[i+1]][f] {
			continue
		}

		rightCount := len(active) - leftCount
		if leftCount < b.cfg.MinSamplesLeaf || rightCount < b.cfg.MinSamplesLeaf {
			continue
		}

		rightGrad := totalGrad - leftGrad
		rightHess := totalHess - leftHess

		gain := 0.5 * (leftGrad*leftGrad/(leftHess+b.cfg.Lambda) +
			rightGrad*rightGrad/(rightHess+b.cfg.Lambda) -
			totalGrad*totalGrad/(totalHess+b.cfg.Lambda))

		if gain > best.gain {
			best.feature = f
			best.threshold = (b.X[active[i]][f] + b.X[active[i+1]][f]) / 2.0
			best.gain = gain
		}
	}
}

// partition splits indices into left (<= threshold) and right (> threshold).
func (b *treeBuilder) partition(indices []int, split splitCandidate) (left, right []int) {
	for _, i := range indices {
		if b.X[i][split.feature] <= split.threshold {
			left = append(left, i)
		} else {
			right = append(right, i)
		}
	}
	return
}
