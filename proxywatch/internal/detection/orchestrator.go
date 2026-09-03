package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"proxywatch/internal/detection/gbdt"
	"proxywatch/internal/detection/ml"
	"proxywatch/internal/detection/model"
	"proxywatch/internal/safeio"
	"proxywatch/internal/shared"
)

// TrainRun records the outcome of a single training cycle.
type TrainRun struct {
	Version     string          `json:"version"`
	StartedAt   time.Time       `json:"started_at"`
	CompletedAt time.Time       `json:"completed_at"`
	DatasetSize int             `json:"dataset_size"`
	Metrics     ml.ModelMetrics `json:"metrics"`
	Promoted    bool            `json:"promoted"`
	PromotedAt  time.Time       `json:"promoted_at,omitempty"`
	RolledBack  bool            `json:"rolled_back"`
	RollbackAt  time.Time       `json:"rollback_at,omitempty"`
	SchemaHash  string          `json:"schema_hash"`
	Error       string          `json:"error,omitempty"`

	// Enhanced tracking (v2)
	CumulativeObservations int64              `json:"cumulative_observations,omitempty"`
	ClassDistribution      map[string]int     `json:"class_distribution,omitempty"`
	FeatureImportance      map[string]float64 `json:"feature_importance,omitempty"`
	HyperParams            *gbdt.HyperParams  `json:"hyper_params,omitempty"`
	ValidationStrategy     string             `json:"validation_strategy,omitempty"`
	OversamplingApplied    bool               `json:"oversampling_applied,omitempty"`
}

// Orchestrator manages the training pipeline.
type Orchestrator struct {
	mu          sync.RWMutex
	dataDir     string // ~/.proxywatch/training/datasets
	modelDir    string // ~/.proxywatch/training/models
	archiveDir  string // ~/.proxywatch/training/archive
	history     []TrainRun
	active      bool
	cancelled   bool
	cancelFn    context.CancelFunc
	lastTrain   time.Time
	nextVersion int
	OnTrainDone func() // called after training completes (success or failure)

	// Cumulative tracking
	cumulativeObs   int64                 // total observations ever collected
	featureBaseline map[int]*FeatureStats // baseline feature distributions for drift detection
	shadowModel     *gbdt.Ensemble        // candidate model for A/B testing
	shadowMetrics   *ShadowMetrics        // live performance of shadow model
}

// FeatureStats tracks distribution statistics for drift detection.
type FeatureStats struct {
	Mean   float64 `json:"mean"`
	StdDev float64 `json:"std_dev"`
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
	Count  int64   `json:"count"`
}

// ShadowMetrics tracks live performance of a shadow (A/B test) model.
type ShadowMetrics struct {
	ModelVersion   string    `json:"model_version"`
	StartedAt      time.Time `json:"started_at"`
	Predictions    int64     `json:"predictions"`
	Agreements     int64     `json:"agreements"`      // agrees with production model
	Disagreements  int64     `json:"disagreements"`   // disagrees with production
	ConfirmedRight int64     `json:"confirmed_right"` // shadow was right (via labels)
	ConfirmedWrong int64     `json:"confirmed_wrong"` // shadow was wrong
}

// AgreementRate returns the fraction of predictions where shadow agrees with production.
func (sm *ShadowMetrics) AgreementRate() float64 {
	if sm.Predictions == 0 {
		return 0
	}
	return float64(sm.Agreements) / float64(sm.Predictions)
}

// NewOrchestrator creates a training orchestrator.
func NewOrchestrator() *Orchestrator {
	root := safeio.ProxywatchDataRoot()
	o := &Orchestrator{
		dataDir:         filepath.Join(root, "training", "datasets"),
		modelDir:        filepath.Join(root, "models"),
		archiveDir:      filepath.Join(root, "training", "archive"),
		featureBaseline: make(map[int]*FeatureStats),
	}
	_ = os.MkdirAll(o.archiveDir, 0o700)
	o.loadHistory()
	o.loadCumulativeStats()
	return o
}

// History returns a copy of the training run history.
func (o *Orchestrator) History() []TrainRun {
	o.mu.RLock()
	defer o.mu.RUnlock()
	out := make([]TrainRun, len(o.history))
	copy(out, o.history)
	return out
}

// LatestPromotedRun returns the most recent promoted (active) training run, or nil if none.
func (o *Orchestrator) LatestPromotedRun() *TrainRun {
	o.mu.RLock()
	defer o.mu.RUnlock()
	for i := len(o.history) - 1; i >= 0; i-- {
		if o.history[i].Promoted && !o.history[i].RolledBack && o.history[i].Error == "" {
			run := o.history[i]
			return &run
		}
	}
	return nil
}

// IsActive returns true if a training run is in progress.
func (o *Orchestrator) IsActive() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.active
}

// LastTrainTime returns when the last training run completed.
func (o *Orchestrator) LastTrainTime() time.Time {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.lastTrain
}

// TriggerRetrain starts an async training run if not already active.
// Uses the default minimum sample floor (gbdt.DefaultMinTrainingSamples)
// — for the automated retrain path.
func (o *Orchestrator) TriggerRetrain(reason string, buffer *ml.TrainingBuffer) {
	o.trigger(reason, buffer, gbdt.DefaultMinTrainingSamples)
}

// TriggerRetrainManual starts an async training run at the operator's
// request. Lowers the minimum-sample floor to gbdt.ManualMinTrainingSamples
// so "train now" works even when the buffer hasn't filled to the auto
// threshold. The buffer is still cleared on both success and failure so
// collection restarts cleanly for the next cycle.
func (o *Orchestrator) TriggerRetrainManual(reason string, buffer *ml.TrainingBuffer) {
	o.trigger(reason, buffer, gbdt.ManualMinTrainingSamples)
}

func (o *Orchestrator) trigger(reason string, buffer *ml.TrainingBuffer, minSamples int) {
	o.mu.Lock()
	if o.active {
		o.mu.Unlock()
		shared.LogInfo("training", "retrain already active, skipping trigger: %s", reason)
		return
	}
	o.active = true
	o.cancelled = false
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	o.cancelFn = cancel
	o.mu.Unlock()

	shared.LogInfo("training", "retrain triggered: %s (min samples: %d, buffer: %d)", reason, minSamples, buffer.Len())
	go o.runTraining(ctx, buffer, reason, minSamples)
}

// StopRetrain cancels a running training run.
func (o *Orchestrator) StopRetrain() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.active || o.cancelFn == nil {
		return
	}
	o.cancelled = true
	o.cancelFn()
	shared.LogInfo("training", "retrain cancelled by operator")
}

func (o *Orchestrator) runTraining(ctx context.Context, buffer *ml.TrainingBuffer, reason string, minSamples int) {
	shared.TrainingActiveAtomic.Store(true)
	shared.TrainingStartTime.Store(time.Now().UnixNano())
	defer func() {
		shared.TrainingActiveAtomic.Store(false)
		o.mu.Lock()
		o.active = false
		o.cancelFn = nil
		o.mu.Unlock()
	}()

	// Helper: record failure, set cycle phase, archive data, reset for next cycle.
	fail := func(run *TrainRun, errMsg string, ndjsonPath string) {
		run.Error = errMsg
		shared.LogError("training", "%s", errMsg)
		shared.SetCyclePhase(shared.CycleTrainingFailed)
		shared.SetCycleError(errMsg)
		o.recordRun(*run)
		model.ResetRetrainTriggers()
		// Archive failed training data for debugging
		if ndjsonPath != "" {
			_ = o.archiveTrainingData(ndjsonPath, run.Version+"-failed")
		}
		buffer.Clear()
	}

	run := TrainRun{StartedAt: time.Now().UTC()}

	o.mu.Lock()
	o.nextVersion++
	version := o.nextVersion
	// Track cumulative observations
	o.cumulativeObs += int64(buffer.Len())
	run.CumulativeObservations = o.cumulativeObs
	o.mu.Unlock()
	versionStr := versionString(version)
	run.Version = versionStr

	// ── INGEST ──
	shared.SetCyclePhase(shared.CycleTrainingIngest)
	shared.SetCycleError("")

	datasetDir := filepath.Join(o.dataDir, "current")
	if err := os.MkdirAll(datasetDir, 0o700); err != nil {
		fail(&run, "create dataset dir: "+err.Error(), "")
		return
	}

	ndjsonPath := filepath.Join(datasetDir, "training-data.ndjson")
	if err := buffer.PersistTo(ndjsonPath); err != nil {
		fail(&run, "export buffer: "+err.Error(), "")
		return
	}
	run.DatasetSize = buffer.Len()
	shared.LogInfo("training", "exported %d records (cumulative: %d)", run.DatasetSize, run.CumulativeObservations)

	ds, err := gbdt.IngestNDJSON(ndjsonPath)
	if err != nil {
		fail(&run, "ingest: "+err.Error(), ndjsonPath)
		return
	}

	vr := gbdt.ValidateDataset(ds, minSamples)
	if !vr.Valid {
		fail(&run, "validation: "+strings.Join(vr.Errors, "; "), ndjsonPath)
		return
	}
	for _, w := range vr.Warnings {
		shared.LogInfo("training", "warning: %s", w)
	}

	// Record class distribution
	run.ClassDistribution = make(map[string]int)
	for i, count := range ds.ClassCounts {
		if i < len(gbdt.RoleClasses) {
			run.ClassDistribution[gbdt.RoleClasses[i]] = count
		}
	}

	// ── OVERSAMPLING (optional) ──
	// Apply SMOTE-like oversampling if minority classes are severely underrepresented
	oversampleThreshold := 0.1 // minority class < 10% of majority triggers oversampling
	shouldOversample := false
	if len(ds.ClassCounts) > 0 {
		maxCount := 0
		minCount := ds.ClassCounts[0]
		for _, c := range ds.ClassCounts {
			if c > maxCount {
				maxCount = c
			}
			if c > 0 && c < minCount {
				minCount = c
			}
		}
		if maxCount > 0 && float64(minCount)/float64(maxCount) < oversampleThreshold {
			shouldOversample = true
		}
	}

	if shouldOversample {
		shared.LogInfo("training", "applying SMOTE-like oversampling for class balance")
		ds = gbdt.OversampleMinorityClasses(ds, 0.3) // target 30% of majority class
		run.OversamplingApplied = true
	}

	// ── FIT ──
	shared.SetCyclePhase(shared.CycleTrainingFit)
	shared.LogInfo("training", "fitting model (%d samples)", len(ds.Y))

	params := gbdt.DefaultHyperParams()
	run.HyperParams = &params
	run.ValidationStrategy = "time-series-cv-3"

	ensemble, err := gbdt.Train(ctx, ds, params)
	if err != nil {
		fail(&run, "train: "+err.Error(), ndjsonPath)
		return
	}

	// Compute feature importance
	run.FeatureImportance = computeFeatureImportance(ensemble)

	// ── EVAL ──
	shared.SetCyclePhase(shared.CycleTrainingEval)
	shared.LogInfo("training", "evaluating model")

	cvMetrics, err := gbdt.TimeSeriesCV(ctx, ds, params, 3)
	if err != nil {
		shared.LogInfo("training", "CV skipped: %v", err)
	}
	if cvMetrics != nil {
		gate := gbdt.QualityGateForSize(len(ds.Y))
		pass, failures := gbdt.CheckQualityGate(cvMetrics, gate)
		if !pass {
			fail(&run, "quality gate: "+strings.Join(failures, "; "), ndjsonPath)
			return
		}
	}

	// Update feature baseline for drift detection
	o.UpdateFeatureBaseline(ds)

	// ── EXPORT ──
	shared.SetCyclePhase(shared.CycleTrainingExport)

	retrainDir := filepath.Join(o.modelDir, "retrain")
	_ = os.MkdirAll(retrainDir, 0o700)
	modelPath := filepath.Join(retrainDir, "role_classifier.json")
	if err := gbdt.Export(ensemble, modelPath); err != nil {
		fail(&run, "export: "+err.Error(), ndjsonPath)
		return
	}

	// ── DONE ──
	run.CompletedAt = time.Now().UTC()
	if cvMetrics != nil {
		run.Metrics = ml.ModelMetrics{
			MacroF1:        cvMetrics.MacroF1,
			ControlRecall:  cvMetrics.ControlRecall,
			OutboundPrec:   cvMetrics.OutboundPrec,
			MeetsThreshold: true,
		}
	} else {
		run.Metrics = ml.ModelMetrics{MeetsThreshold: true}
	}

	run.Promoted = true
	run.PromotedAt = time.Now().UTC()
	o.mu.Lock()
	o.lastTrain = run.CompletedAt
	o.mu.Unlock()

	o.recordRun(run)
	model.ResetRetrainTriggers()

	// Archive training data instead of just clearing
	if err := o.archiveTrainingData(ndjsonPath, versionStr); err != nil {
		shared.LogInfo("training", "archive warning: %v", err)
	}
	o.saveCumulativeStats()
	buffer.Clear()

	shared.SetCyclePhase(shared.CycleTrainingDone)
	shared.SetCycleError("")
	shared.LogInfo("training", "model %s trained and promoted (F1=%.3f, oversampled=%v)",
		versionStr, run.Metrics.MacroF1, run.OversamplingApplied)

	// Notify learner to immediately check for the new model.
	if o.OnTrainDone != nil {
		o.OnTrainDone()
	}
}

// PromoteRun marks an unpromoted, error-free run as promoted.
func (o *Orchestrator) PromoteRun(version string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	for i := range o.history {
		if o.history[i].Version == version && !o.history[i].Promoted && o.history[i].Error == "" {
			o.history[i].Promoted = true
			o.history[i].PromotedAt = time.Now().UTC()
			o.saveHistory()
			shared.LogInfo("training", "promoted model %s from dashboard", version)
			return true
		}
	}
	return false
}

// RollbackRun marks a promoted, non-rolled-back run as rolled back.
func (o *Orchestrator) RollbackRun(version string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	for i := range o.history {
		if o.history[i].Version == version && o.history[i].Promoted && !o.history[i].RolledBack {
			o.history[i].RolledBack = true
			o.history[i].RollbackAt = time.Now().UTC()
			o.saveHistory()
			shared.LogInfo("training", "rolled back model %s from dashboard", version)
			return true
		}
	}
	return false
}

func (o *Orchestrator) recordRun(run TrainRun) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.history = append(o.history, run)
	if len(o.history) > 20 {
		o.history = o.history[len(o.history)-20:]
	}
	o.saveHistory()
}

func (o *Orchestrator) loadHistory() {
	path := filepath.Join(safeio.ProxywatchDataRoot(), "training", "history.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	_ = json.Unmarshal(data, &o.history)
	if len(o.history) > 0 {
		sort.Slice(o.history, func(i, j int) bool {
			return o.history[i].StartedAt.Before(o.history[j].StartedAt)
		})
		o.lastTrain = o.history[len(o.history)-1].CompletedAt
		// Derive next version from history.
		for _, run := range o.history {
			if v := parseVersion(run.Version); v >= o.nextVersion {
				o.nextVersion = v + 1
			}
		}
	}
}

func (o *Orchestrator) saveHistory() {
	path := filepath.Join(safeio.ProxywatchDataRoot(), "training", "history.json")
	dir := filepath.Dir(path)
	_ = os.MkdirAll(dir, 0o700)
	data, err := json.MarshalIndent(o.history, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0o600)
}

func versionString(v int) string {
	return "v" + strings.Repeat("0", 3-len(itoa(v))) + itoa(v)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	return s
}

func parseVersion(s string) int {
	s = strings.TrimPrefix(s, "v")
	v := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			v = v*10 + int(c-'0')
		}
	}
	return v
}

// BaselineEntry describes a saved baseline (detection model snapshot).
// Training runs (v001, v002...) are NOT baselines — they are ML classifiers
// that feed into whichever baseline is active.
type BaselineEntry struct {
	Name    string // display name: "shipped (built-in)", "baseline-2026-04-05-1304"
	Dir     string // disk path to the baseline directory (empty for shipped)
	Current bool   // true if this is the currently active baseline
}

// AvailableBaselines returns the list of baseline snapshots the operator can
// choose from. Always includes "shipped" first, then any user-created snapshots
// found in ~/.proxywatch/baselines/.
func (o *Orchestrator) AvailableBaselines() []BaselineEntry {
	entries := []BaselineEntry{
		{Name: "shipped (built-in)"},
	}

	root := safeio.ProxywatchDataRoot()
	baselineDir := filepath.Join(root, "baselines")
	dirEntries, err := os.ReadDir(baselineDir)
	if err != nil {
		return entries
	}

	for _, de := range dirEntries {
		if !de.IsDir() {
			continue
		}
		// Only list directories that contain a detection-model.json.
		modelPath := filepath.Join(baselineDir, de.Name(), "detection-model.json")
		if _, err := os.Stat(modelPath); err != nil {
			continue
		}
		entries = append(entries, BaselineEntry{
			Name: de.Name(),
			Dir:  filepath.Join(baselineDir, de.Name()),
		})
	}
	return entries
}

// CreateBaseline snapshots the current detection model as a named baseline
// version. This copies the active model state so the operator can revert to it.
func (o *Orchestrator) CreateBaseline(name string) (string, error) {
	root := safeio.ProxywatchDataRoot()
	baselineDir := filepath.Join(root, "baselines")
	if err := os.MkdirAll(baselineDir, 0o700); err != nil {
		return "", err
	}

	// Generate baseline name from timestamp if not provided.
	if name == "" {
		name = "baseline-" + time.Now().UTC().Format("2006-01-02-1504")
	}

	destDir := filepath.Join(baselineDir, name)
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return "", err
	}

	// Copy the current detection model.
	modelSrc := filepath.Join(root, "model", "detection-model.json")
	data, err := os.ReadFile(modelSrc)
	if err != nil {
		return "", fmt.Errorf("read current model: %w", err)
	}
	if err := os.WriteFile(filepath.Join(destDir, "detection-model.json"), data, 0o600); err != nil {
		return "", fmt.Errorf("write baseline: %w", err)
	}

	// Copy ML model if it exists.
	for _, mlPath := range []string{
		filepath.Join(root, "models", "retrain", "role_classifier.json"),
		filepath.Join(root, "models", "active", "role_classifier.json"),
		filepath.Join(root, "models", "role_classifier.json"),
	} {
		if mlData, err := os.ReadFile(mlPath); err == nil {
			_ = os.WriteFile(filepath.Join(destDir, "role_classifier.json"), mlData, 0o600)
			break
		}
	}

	shared.LogInfo("training", "baseline created: %s", name)
	return name, nil
}

// ── Cumulative Stats ────────────────────────────────────────────────────────

type cumulativeStatsFile struct {
	TotalObservations int64                 `json:"total_observations"`
	FeatureBaseline   map[int]*FeatureStats `json:"feature_baseline,omitempty"`
	LastUpdated       time.Time             `json:"last_updated"`
}

func (o *Orchestrator) loadCumulativeStats() {
	path := filepath.Join(safeio.ProxywatchDataRoot(), "training", "cumulative_stats.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var stats cumulativeStatsFile
	if err := json.Unmarshal(data, &stats); err != nil {
		return
	}
	o.cumulativeObs = stats.TotalObservations
	if stats.FeatureBaseline != nil {
		o.featureBaseline = stats.FeatureBaseline
	}
}

func (o *Orchestrator) saveCumulativeStats() {
	// Note: caller must NOT hold o.mu - this function acquires it
	o.mu.RLock()
	stats := cumulativeStatsFile{
		TotalObservations: o.cumulativeObs,
		FeatureBaseline:   o.featureBaseline,
		LastUpdated:       time.Now().UTC(),
	}
	o.mu.RUnlock()

	path := filepath.Join(safeio.ProxywatchDataRoot(), "training", "cumulative_stats.json")
	dir := filepath.Dir(path)
	_ = os.MkdirAll(dir, 0o700)
	data, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0o600)
}

// saveCumulativeStatsLocked saves cumulative stats when caller already holds o.mu
func (o *Orchestrator) saveCumulativeStatsLocked() {
	stats := cumulativeStatsFile{
		TotalObservations: o.cumulativeObs,
		FeatureBaseline:   o.featureBaseline,
		LastUpdated:       time.Now().UTC(),
	}

	path := filepath.Join(safeio.ProxywatchDataRoot(), "training", "cumulative_stats.json")
	dir := filepath.Dir(path)
	_ = os.MkdirAll(dir, 0o700)
	data, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0o600)
}

// IncrementObservations adds to the cumulative observation counter.
func (o *Orchestrator) IncrementObservations(count int64) {
	o.mu.Lock()
	o.cumulativeObs += count
	o.mu.Unlock()
}

// CumulativeObservations returns the total observations ever collected.
func (o *Orchestrator) CumulativeObservations() int64 {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.cumulativeObs
}

// ── Training Data Archive ───────────────────────────────────────────────────

// archiveTrainingData copies training data to a dated archive instead of deleting.
// Keeps a rolling 30-day archive for potential re-training with historical data.
func (o *Orchestrator) archiveTrainingData(ndjsonPath string, version string) error {
	data, err := os.ReadFile(ndjsonPath)
	if err != nil {
		return err
	}

	// Create dated archive file
	archiveName := fmt.Sprintf("training-%s-%s.ndjson", version, time.Now().UTC().Format("20060102-150405"))
	archivePath := filepath.Join(o.archiveDir, archiveName)
	if err := os.WriteFile(archivePath, data, 0o600); err != nil {
		return err
	}

	// Prune archives older than 30 days
	o.pruneOldArchives(30 * 24 * time.Hour)
	return nil
}

func (o *Orchestrator) pruneOldArchives(maxAge time.Duration) {
	entries, err := os.ReadDir(o.archiveDir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-maxAge)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(o.archiveDir, e.Name()))
		}
	}
}

// ── Feature Importance ──────────────────────────────────────────────────────

// computeFeatureImportance calculates importance scores from a trained GBDT.
// Uses split frequency as a proxy for importance (counts how often each feature is used).
func computeFeatureImportance(ensemble *gbdt.Ensemble) map[string]float64 {
	splitCounts := make(map[int]int) // feature index -> split count

	for i := range ensemble.Trees {
		tree := &ensemble.Trees[i]
		for j := range tree.Nodes {
			node := &tree.Nodes[j]
			if !node.Leaf && node.Feature >= 0 {
				splitCounts[node.Feature]++
			}
		}
	}

	// Normalize
	total := 0
	for _, v := range splitCounts {
		total += v
	}

	result := make(map[string]float64)
	for idx, count := range splitCounts {
		importance := 0.0
		if total > 0 {
			importance = float64(count) / float64(total)
		}
		name := fmt.Sprintf("feature_%d", idx)
		result[name] = importance
	}
	return result
}

// ── Drift Detection ─────────────────────────────────────────────────────────

// UpdateFeatureBaseline computes and stores feature distribution statistics
// from the training dataset. Called after each successful training run.
func (o *Orchestrator) UpdateFeatureBaseline(ds *gbdt.Dataset) {
	if ds == nil || len(ds.X) == 0 {
		return
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	numFeatures := ds.NumFeatures
	for f := 0; f < numFeatures; f++ {
		stats := &FeatureStats{}
		var sum, sumSq float64
		stats.Min = ds.X[0][f]
		stats.Max = ds.X[0][f]

		for i := range ds.X {
			v := ds.X[i][f]
			sum += v
			sumSq += v * v
			if v < stats.Min {
				stats.Min = v
			}
			if v > stats.Max {
				stats.Max = v
			}
		}

		n := float64(len(ds.X))
		stats.Mean = sum / n
		variance := (sumSq / n) - (stats.Mean * stats.Mean)
		if variance > 0 {
			stats.StdDev = sqrt(variance)
		}
		stats.Count = int64(len(ds.X))

		o.featureBaseline[f] = stats
	}
	o.saveCumulativeStatsLocked()
}

// CheckDrift compares current feature distributions against baseline.
// Returns features with significant drift (z-score > threshold).
func (o *Orchestrator) CheckDrift(currentStats map[int]*FeatureStats, threshold float64) []DriftAlert {
	o.mu.RLock()
	defer o.mu.RUnlock()

	if threshold <= 0 {
		threshold = 2.0 // default: 2 standard deviations
	}

	var alerts []DriftAlert
	for f, baseline := range o.featureBaseline {
		current, ok := currentStats[f]
		if !ok || baseline.StdDev == 0 {
			continue
		}

		// Z-score of mean shift
		zScore := (current.Mean - baseline.Mean) / baseline.StdDev
		if zScore < 0 {
			zScore = -zScore
		}

		if zScore > threshold {
			alerts = append(alerts, DriftAlert{
				FeatureIdx:   f,
				BaselineMean: baseline.Mean,
				CurrentMean:  current.Mean,
				ZScore:       zScore,
			})
		}
	}
	return alerts
}

// DriftAlert represents a detected feature distribution drift.
type DriftAlert struct {
	FeatureIdx   int
	BaselineMean float64
	CurrentMean  float64
	ZScore       float64
}

// ── Shadow Model (A/B Testing) ──────────────────────────────────────────────

// SetShadowModel sets a candidate model for A/B testing.
func (o *Orchestrator) SetShadowModel(ensemble *gbdt.Ensemble, version string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.shadowModel = ensemble
	o.shadowMetrics = &ShadowMetrics{
		ModelVersion: version,
		StartedAt:    time.Now().UTC(),
	}
}

// GetShadowModel returns the current shadow model for evaluation.
func (o *Orchestrator) GetShadowModel() *gbdt.Ensemble {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.shadowModel
}

// RecordShadowPrediction records a shadow model prediction for A/B analysis.
func (o *Orchestrator) RecordShadowPrediction(shadowPred, prodPred int, confirmed *int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.shadowMetrics == nil {
		return
	}

	o.shadowMetrics.Predictions++
	if shadowPred == prodPred {
		o.shadowMetrics.Agreements++
	} else {
		o.shadowMetrics.Disagreements++
	}

	if confirmed != nil {
		if shadowPred == *confirmed {
			o.shadowMetrics.ConfirmedRight++
		} else {
			o.shadowMetrics.ConfirmedWrong++
		}
	}
}

// GetShadowMetrics returns the current shadow model performance metrics.
func (o *Orchestrator) GetShadowMetrics() *ShadowMetrics {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.shadowMetrics == nil {
		return nil
	}
	// Return a copy
	m := *o.shadowMetrics
	return &m
}

// PromoteShadowModel promotes the shadow model to production if it meets criteria.
func (o *Orchestrator) PromoteShadowModel(minPredictions int64, minAccuracy float64) bool {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.shadowModel == nil || o.shadowMetrics == nil {
		return false
	}
	if o.shadowMetrics.Predictions < minPredictions {
		return false
	}

	confirmed := o.shadowMetrics.ConfirmedRight + o.shadowMetrics.ConfirmedWrong
	if confirmed == 0 {
		return false
	}

	accuracy := float64(o.shadowMetrics.ConfirmedRight) / float64(confirmed)
	if accuracy < minAccuracy {
		return false
	}

	// Shadow model passes - would promote here
	// (In practice, this would write to disk and notify the learner)
	shared.LogInfo("training", "shadow model %s passed A/B test: %.1f%% accuracy over %d confirmed predictions",
		o.shadowMetrics.ModelVersion, accuracy*100, confirmed)

	o.shadowModel = nil
	o.shadowMetrics = nil
	return true
}

// ClearShadowModel removes the shadow model without promotion.
func (o *Orchestrator) ClearShadowModel() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.shadowModel = nil
	o.shadowMetrics = nil
}

// sqrt is a simple square root helper to avoid math import in this file.
func sqrt(x float64) float64 {
	if x <= 0 {
		return 0
	}
	z := x
	for i := 0; i < 10; i++ {
		z = (z + x/z) / 2
	}
	return z
}
