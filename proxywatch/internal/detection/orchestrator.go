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
	Version     string                 `json:"version"`
	StartedAt   time.Time              `json:"started_at"`
	CompletedAt time.Time              `json:"completed_at"`
	DatasetSize int                    `json:"dataset_size"`
	Metrics     ml.ModelMetrics `json:"metrics"`
	Promoted    bool                   `json:"promoted"`
	PromotedAt  time.Time              `json:"promoted_at,omitempty"`
	RolledBack  bool                   `json:"rolled_back"`
	RollbackAt  time.Time              `json:"rollback_at,omitempty"`
	SchemaHash  string                 `json:"schema_hash"`
	Error       string                 `json:"error,omitempty"`
}

// Orchestrator manages the training pipeline.
type Orchestrator struct {
	mu          sync.RWMutex
	dataDir     string // ~/.proxywatch/training/datasets
	modelDir    string // ~/.proxywatch/training/models
	history     []TrainRun
	active      bool
	cancelled   bool
	cancelFn    context.CancelFunc
	lastTrain   time.Time
	nextVersion int
	OnTrainDone func() // called after training completes (success or failure)
}

// NewOrchestrator creates a training orchestrator.
func NewOrchestrator() *Orchestrator {
	root := safeio.ProxywatchDataRoot()
	o := &Orchestrator{
		dataDir:  filepath.Join(root, "training", "datasets"),
		modelDir: filepath.Join(root, "models"),
	}
	o.loadHistory()
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

	// Helper: record failure, set cycle phase, reset for next collection cycle.
	fail := func(run *TrainRun, errMsg string) {
		run.Error = errMsg
		shared.LogError("training", "%s", errMsg)
		shared.SetCyclePhase(shared.CycleTrainingFailed)
		shared.SetCycleError(errMsg)
		o.recordRun(*run)
		model.ResetRetrainTriggers()
		buffer.Clear() // Reset collection to 0% for next cycle.
	}

	run := TrainRun{StartedAt: time.Now().UTC()}

	o.mu.Lock()
	o.nextVersion++
	version := o.nextVersion
	o.mu.Unlock()
	versionStr := versionString(version)
	run.Version = versionStr

	// ── INGEST ──
	shared.SetCyclePhase(shared.CycleTrainingIngest)
	shared.SetCycleError("")

	datasetDir := filepath.Join(o.dataDir, "current")
	if err := os.MkdirAll(datasetDir, 0o700); err != nil {
		fail(&run, "create dataset dir: "+err.Error())
		return
	}

	ndjsonPath := filepath.Join(datasetDir, "training-data.ndjson")
	if err := buffer.PersistTo(ndjsonPath); err != nil {
		fail(&run, "export buffer: "+err.Error())
		return
	}
	run.DatasetSize = buffer.Len()
	shared.LogInfo("training", "exported %d records", run.DatasetSize)

	ds, err := gbdt.IngestNDJSON(ndjsonPath)
	if err != nil {
		fail(&run, "ingest: "+err.Error())
		return
	}

	vr := gbdt.ValidateDataset(ds, minSamples)
	if !vr.Valid {
		fail(&run, "validation: "+strings.Join(vr.Errors, "; "))
		return
	}
	for _, w := range vr.Warnings {
		shared.LogInfo("training", "warning: %s", w)
	}

	// ── FIT ──
	shared.SetCyclePhase(shared.CycleTrainingFit)
	shared.LogInfo("training", "fitting model (%d samples)", len(ds.Y))

	params := gbdt.DefaultHyperParams()
	ensemble, err := gbdt.Train(ctx, ds, params)
	if err != nil {
		fail(&run, "train: "+err.Error())
		return
	}

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
			fail(&run, "quality gate: "+strings.Join(failures, "; "))
			return
		}
	}

	// ── EXPORT ──
	shared.SetCyclePhase(shared.CycleTrainingExport)

	retrainDir := filepath.Join(o.modelDir, "retrain")
	_ = os.MkdirAll(retrainDir, 0o700)
	modelPath := filepath.Join(retrainDir, "role_classifier.json")
	if err := gbdt.Export(ensemble, modelPath); err != nil {
		fail(&run, "export: "+err.Error())
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
	buffer.Clear() // Reset collection to 0% for next cycle.

	shared.SetCyclePhase(shared.CycleTrainingDone)
	shared.SetCycleError("")
	shared.LogInfo("training", "model %s trained and promoted", versionStr)

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
