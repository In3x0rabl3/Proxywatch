package gbdt

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"time"

	"proxywatch/internal/detection/features"
)

// RoleClasses is the canonical class ordering.
// Index position maps to the class index used in tree nodes and softmax output.
var RoleClasses = []string{
	"outbound",
	"listener",
	"beacon",
	"pivot",
}

const NumClasses = 4

// Dataset holds prepared training data ready for the GBDT trainer.
type Dataset struct {
	X            [][]float64 // [n_samples][117] feature matrix
	Y            []int       // class index per sample
	Weights      []float64   // per-sample weight
	Timestamps   []time.Time // for time-series CV splits
	LabelSources []LabelSource
	NumFeatures  int
	NumClasses   int
	ClassCounts  []int // samples per class
}

// LabelSource encodes the provenance of a training label for weighting.
type LabelSource int

const (
	LabelOperator    LabelSource = iota // operator-assigned: highest trust
	LabelUserVerdict                    // kill / whitelist action
	LabelExperience                     // stable behavioural consensus
	LabelRule                           // baseline rule suggestion
	LabelDefault                        // fallback (outbound)
)

// sourceWeight returns the sample weight multiplier for a label source.
func sourceWeight(s LabelSource) float64 {
	switch s {
	case LabelOperator:
		return 5.0
	case LabelUserVerdict:
		return 3.0
	case LabelExperience:
		return 2.0
	case LabelRule:
		return 1.0
	default:
		return 0.5
	}
}

// roleIndex maps a role string to its class index, or -1 if unknown.
func roleIndex(role string) int {
	for i, r := range RoleClasses {
		if r == role {
			return i
		}
	}
	return -1
}

// labelToRole maps operator label strings to canonical role names.
func labelToRole(label string) string {
	lower := strings.ToLower(label)
	switch lower {
	case "malicious", "session":
		return "beacon"
	case "beacon":
		return "beacon"
	case "tunnel", "pivot":
		return "pivot"
	case "benign":
		return "outbound"
	case "listen", "listener":
		return "listener"
	default:
		// Try direct match against role classes.
		for _, r := range RoleClasses {
			if strings.EqualFold(label, r) {
				return r
			}
		}
		// Check for role name as substring (e.g., "CONTROL-PIVOT" -> "pivot")
		for _, r := range RoleClasses {
			if strings.Contains(lower, r) {
				return r
			}
		}
		return "outbound"
	}
}

// verdictToRole maps user verdicts to canonical role names.
func verdictToRole(verdict string) string {
	switch strings.ToLower(verdict) {
	case "kill", "malicious":
		return "beacon"
	case "whitelist", "benign":
		return "outbound"
	default:
		return "outbound"
	}
}

// resolveLabel determines the class index and label source for a training record
// using the full priority chain: operator > user verdict > experience > rule > default.
func resolveLabel(rec TrainingRecord) (int, LabelSource) {
	// Priority 1: Operator label (highest trust).
	if rec.OperatorLabel != nil && *rec.OperatorLabel != "" {
		role := labelToRole(*rec.OperatorLabel)
		if idx := roleIndex(role); idx >= 0 {
			return idx, LabelOperator
		}
	}

	// Priority 2: User verdict (kill / whitelist).
	if rec.UserVerdict != "" {
		role := verdictToRole(rec.UserVerdict)
		if idx := roleIndex(role); idx >= 0 {
			return idx, LabelUserVerdict
		}
	}

	// Priority 3: Experience (stable behavioural consensus).
	if rec.ExperienceRole != "" && rec.ExperienceObservations >= 10 && rec.ExperienceStability >= 0.5 {
		if idx := roleIndex(rec.ExperienceRole); idx >= 0 {
			return idx, LabelExperience
		}
	}

	// Priority 4: Rule-based suggestion.
	if rec.RuleRole != "" {
		if idx := roleIndex(rec.RuleRole); idx >= 0 {
			return idx, LabelRule
		}
	}

	// Priority 5: Default to outbound.
	return 0, LabelDefault
}

// dedupKey produces a deduplication key from process key and a 1-minute time window.
// Shorter windows preserve more temporal variation for training.
func dedupKey(processKey string, ts time.Time) string {
	window := ts.Unix() / 60 // 1-minute buckets
	return fmt.Sprintf("%s|%d", processKey, window)
}

// IngestNDJSON reads training records from an NDJSON file, deduplicates,
// resolves labels, and builds a dense feature matrix.
func IngestNDJSON(path string) (*Dataset, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, &TrainingError{Kind: ErrDataset, Op: "ingest", Detail: "open file", Wrapped: err}
	}
	defer f.Close()

	var records []TrainingRecord
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20) // 1 MB line buffer
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec TrainingRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			continue // skip malformed lines
		}
		records = append(records, rec)
	}
	if err := scanner.Err(); err != nil {
		return nil, &TrainingError{Kind: ErrDataset, Op: "ingest", Detail: "read file", Wrapped: err}
	}
	if len(records) == 0 {
		return nil, &TrainingError{Kind: ErrDataset, Op: "ingest", Detail: "dataset is empty"}
	}

	return IngestRecords(records)
}

// IngestRecords converts in-memory training records into a Dataset.
func IngestRecords(records []TrainingRecord) (*Dataset, error) {
	if len(records) == 0 {
		return nil, &TrainingError{Kind: ErrDataset, Op: "ingest", Detail: "no records provided"}
	}

	featureNames := features.FeatureNames()
	nameIndex := make(map[string]int, len(featureNames))
	for i, name := range featureNames {
		nameIndex[name] = i
	}

	// Deduplicate: keep the record with the highest-priority label source per key.
	type dedupEntry struct {
		rec    TrainingRecord
		cls    int
		source LabelSource
	}
	seen := make(map[string]dedupEntry, len(records))

	for _, rec := range records {
		key := dedupKey(rec.ProcessKey, rec.Timestamp)
		cls, source := resolveLabel(rec)
		if existing, ok := seen[key]; ok {
			// Keep the one with higher-priority (lower ordinal) label source.
			if source < existing.source {
				seen[key] = dedupEntry{rec, cls, source}
			}
		} else {
			seen[key] = dedupEntry{rec, cls, source}
		}
	}

	// Build dense matrices.
	n := len(seen)
	ds := &Dataset{
		X:            make([][]float64, 0, n),
		Y:            make([]int, 0, n),
		Weights:      make([]float64, 0, n),
		Timestamps:   make([]time.Time, 0, n),
		LabelSources: make([]LabelSource, 0, n),
		NumFeatures:  features.MaxFeatures,
		NumClasses:   NumClasses,
		ClassCounts:  make([]int, NumClasses),
	}

	for _, entry := range seen {
		// Convert feature map to dense vector.
		row := make([]float64, features.MaxFeatures)
		for name, val := range entry.rec.Features {
			if idx, ok := nameIndex[name]; ok {
				if !math.IsNaN(val) && !math.IsInf(val, 0) {
					row[idx] = val
				}
			}
		}

		ds.X = append(ds.X, row)
		ds.Y = append(ds.Y, entry.cls)
		ds.LabelSources = append(ds.LabelSources, entry.source)
		ds.Timestamps = append(ds.Timestamps, entry.rec.Timestamp)
		ds.ClassCounts[entry.cls]++
	}

	// Sort by timestamp for time-series CV.
	indices := make([]int, len(ds.Y))
	for i := range indices {
		indices[i] = i
	}
	sort.Slice(indices, func(i, j int) bool {
		return ds.Timestamps[indices[i]].Before(ds.Timestamps[indices[j]])
	})
	sortedX := make([][]float64, len(ds.Y))
	sortedY := make([]int, len(ds.Y))
	sortedW := make([]float64, len(ds.Y))
	sortedT := make([]time.Time, len(ds.Y))
	sortedS := make([]LabelSource, len(ds.Y))
	for i, idx := range indices {
		sortedX[i] = ds.X[idx]
		sortedY[i] = ds.Y[idx]
		sortedT[i] = ds.Timestamps[idx]
		sortedS[i] = ds.LabelSources[idx]
	}
	ds.X = sortedX
	ds.Y = sortedY
	ds.Timestamps = sortedT
	ds.LabelSources = sortedS

	// Compute weights: label source × class imbalance.
	computeWeights(ds)
	ds.Weights = sortedW
	computeWeights(ds)

	return ds, nil
}

// computeWeights sets per-sample weights combining label source trust and
// inverse class frequency to handle class imbalance.
//
// Operator-reported 2026-05-02: model degraded with shadow agreement at
// 63%. Live training data is severely imbalanced — beacon-* classes
// (cheerful_glove, tcp-pivot, smb_pivot, liquid_mezzanine, sshd) are
// typically 0.5-1% of the dataset (~1000 of 207K records), while
// outbound + listener dominate at 80%+. The previous 20× weight cap
// was too restrictive: the true inverse-frequency would be ~50× for
// rare classes, so the cap dampened the rare-class gradient by 60%
// every retrain, pulling the model toward the "everything is outbound"
// solution. Raised cap to 100× — still bounded (prevents divergence
// from a single outlier rare-class sample) but lets actual imbalanced
// training data produce meaningful gradient signal for beacon-*.
func computeWeights(ds *Dataset) {
	total := float64(len(ds.Y))
	classWeight := make([]float64, NumClasses)
	for c := 0; c < NumClasses; c++ {
		if ds.ClassCounts[c] > 0 {
			classWeight[c] = total / (float64(NumClasses) * float64(ds.ClassCounts[c]))
		} else {
			classWeight[c] = 1.0
		}
		// Cap class weight to prevent extreme values from a single
		// outlier sample, but not so low that real imbalance gets
		// dampened (see comment above for the 20→100 raise rationale).
		if classWeight[c] > 100.0 {
			classWeight[c] = 100.0
		}
	}

	ds.Weights = make([]float64, len(ds.Y))
	for i := range ds.Y {
		ds.Weights[i] = sourceWeight(ds.LabelSources[i]) * classWeight[ds.Y[i]]
	}
}

// ── SMOTE-like Oversampling ─────────────────────────────────────────────────

// OversampleMinorityClasses applies SMOTE-like synthetic oversampling to
// balance class distribution. This creates synthetic samples by interpolating
// between existing minority class samples.
//
// targetRatio: desired ratio of minority:majority (e.g., 0.5 = minority is 50% of majority)
// Returns a new Dataset with synthetic samples added.
func OversampleMinorityClasses(ds *Dataset, targetRatio float64) *Dataset {
	if ds == nil || len(ds.Y) == 0 || targetRatio <= 0 {
		return ds
	}

	// Find majority class count
	maxCount := 0
	for _, c := range ds.ClassCounts {
		if c > maxCount {
			maxCount = c
		}
	}
	targetCount := int(float64(maxCount) * targetRatio)

	// Group samples by class
	classSamples := make(map[int][]int) // class -> sample indices
	for i, y := range ds.Y {
		classSamples[y] = append(classSamples[y], i)
	}

	// Create new dataset with original + synthetic samples
	newX := make([][]float64, len(ds.X))
	copy(newX, ds.X)
	newY := make([]int, len(ds.Y))
	copy(newY, ds.Y)
	newW := make([]float64, len(ds.Weights))
	copy(newW, ds.Weights)
	newT := make([]time.Time, len(ds.Timestamps))
	copy(newT, ds.Timestamps)
	newS := make([]LabelSource, len(ds.LabelSources))
	copy(newS, ds.LabelSources)
	newCounts := make([]int, len(ds.ClassCounts))
	copy(newCounts, ds.ClassCounts)

	// Oversample minority classes
	for cls := 0; cls < NumClasses; cls++ {
		samples := classSamples[cls]
		if len(samples) == 0 || len(samples) >= targetCount {
			continue
		}

		// Generate synthetic samples
		needed := targetCount - len(samples)
		for i := 0; i < needed; i++ {
			// Pick two random samples from this class
			idx1 := samples[i%len(samples)]
			idx2 := samples[(i+7)%len(samples)] // offset to get different sample
			if idx1 == idx2 && len(samples) > 1 {
				idx2 = samples[(i+1)%len(samples)]
			}

			// Interpolate between them (SMOTE-style)
			synth := make([]float64, ds.NumFeatures)
			alpha := 0.5 // midpoint interpolation
			for f := 0; f < ds.NumFeatures; f++ {
				synth[f] = ds.X[idx1][f] + alpha*(ds.X[idx2][f]-ds.X[idx1][f])
			}

			newX = append(newX, synth)
			newY = append(newY, cls)
			newW = append(newW, 1.0)        // synthetic samples get base weight
			newT = append(newT, time.Now()) // no meaningful timestamp
			newS = append(newS, LabelDefault)
			newCounts[cls]++
		}
	}

	return &Dataset{
		X:            newX,
		Y:            newY,
		Weights:      newW,
		Timestamps:   newT,
		LabelSources: newS,
		NumFeatures:  ds.NumFeatures,
		NumClasses:   ds.NumClasses,
		ClassCounts:  newCounts,
	}
}
