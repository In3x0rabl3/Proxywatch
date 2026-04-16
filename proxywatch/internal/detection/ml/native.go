package ml

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"

	"proxywatch/internal/detection/features"
)

// nativeModel implements Predictor using pure-Go leaf-walk inference
// over a JSON-exported LightGBM tree ensemble.
type nativeModel struct {
	format      string
	numClasses  int
	numTrees    int
	roleClasses []string
	trees       []tree
	version     string
}

type tree struct {
	classIdx int
	nodes    []node
}

type node struct {
	Idx          int     `json:"idx"`
	Leaf         bool    `json:"leaf"`
	Value        float64 `json:"value"`
	Feature      int     `json:"feature"`
	Threshold    float64 `json:"threshold"`
	DecisionType string  `json:"decision_type"`
	Left         int     `json:"left"`
	Right        int     `json:"right"`
}

type modelJSON struct {
	Format      string     `json:"format"`
	NumClasses  int        `json:"num_classes"`
	NumFeatures int        `json:"num_features"`
	NumTrees    int        `json:"num_trees"`
	RoleClasses []string   `json:"role_classes"`
	Trees       []treeJSON `json:"trees"`
}

type treeJSON struct {
	Class int    `json:"class"`
	Nodes []node `json:"nodes"`
}

// LoadNative loads a pure-Go JSON model from the given path.
func LoadNative(path string) (Predictor, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read model: %w", err)
	}

	var raw modelJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse model: %w", err)
	}

	if raw.Format != "proxywatch-lgbm-v1" {
		return nil, fmt.Errorf("unsupported model format: %s", raw.Format)
	}

	// Reject models trained on a different feature schema.
	// Old models without num_features field (0) or with wrong count are incompatible.
	if raw.NumFeatures != features.MaxFeatures {
		return nil, fmt.Errorf("model has %d features (need %d) — retrain required", raw.NumFeatures, features.MaxFeatures)
	}

	m := &nativeModel{
		format:      raw.Format,
		numClasses:  raw.NumClasses,
		numTrees:    raw.NumTrees,
		roleClasses: raw.RoleClasses,
		version:     "native-v1",
	}

	for _, tj := range raw.Trees {
		m.trees = append(m.trees, tree{
			classIdx: tj.Class,
			nodes:    tj.Nodes,
		})
	}

	return m, nil
}

// PredictRole traverses all trees and produces softmax probabilities.
func (m *nativeModel) PredictRole(fv features.FeatureVector) RolePrediction {
	if !fv.Valid || m.numClasses == 0 {
		return RolePrediction{TopRole: "outbound", TopProb: 0}
	}

	// Accumulate raw leaf values per class.
	rawScores := make([]float64, m.numClasses)
	for _, t := range m.trees {
		leafVal := m.walkTree(t, fv.Values[:])
		if t.classIdx < m.numClasses {
			rawScores[t.classIdx] += leafVal
		}
	}

	// Softmax to get probabilities.
	probs := softmax(rawScores)

	// Build prediction.
	pred := RolePrediction{
		Probabilities: make(map[string]float64, m.numClasses),
	}

	topIdx := 0
	for i, p := range probs {
		if i < len(m.roleClasses) {
			pred.Probabilities[m.roleClasses[i]] = p
		}
		if p > probs[topIdx] {
			topIdx = i
		}
	}

	if topIdx < len(m.roleClasses) {
		pred.TopRole = m.roleClasses[topIdx]
	}
	pred.TopProb = probs[topIdx]
	pred.Confident = pred.TopProb >= DefaultConfidenceThreshold

	// Top-N.
	type indexed struct {
		idx  int
		prob float64
	}
	ranked := make([]indexed, len(probs))
	for i, p := range probs {
		ranked[i] = indexed{i, p}
	}
	sort.Slice(ranked, func(i, j int) bool { return ranked[i].prob > ranked[j].prob })

	n := 3
	if n > len(ranked) {
		n = len(ranked)
	}
	for _, r := range ranked[:n] {
		name := "unknown"
		if r.idx < len(m.roleClasses) {
			name = m.roleClasses[r.idx]
		}
		pred.TopN = append(pred.TopN, RoleProb{Role: name, Prob: r.prob})
	}

	return pred
}

func (m *nativeModel) walkTree(t tree, feats []float64) float64 {
	if len(t.nodes) == 0 {
		return 0
	}

	idx := 0
	for {
		if idx < 0 || idx >= len(t.nodes) {
			return 0
		}
		n := t.nodes[idx]
		if n.Leaf {
			return n.Value
		}

		featIdx := n.Feature
		if featIdx < 0 || featIdx >= len(feats) {
			return 0
		}

		val := feats[featIdx]
		if val <= n.Threshold {
			idx = n.Left
		} else {
			idx = n.Right
		}
	}
}

func (m *nativeModel) ModelVersion() string {
	return m.version
}

func (m *nativeModel) RoleClasses() []string {
	return m.roleClasses
}

func (m *nativeModel) Close() error {
	return nil
}

func softmax(raw []float64) []float64 {
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

	probs := make([]float64, len(raw))
	for i := range exps {
		probs[i] = exps[i] / sum
	}
	return probs
}
