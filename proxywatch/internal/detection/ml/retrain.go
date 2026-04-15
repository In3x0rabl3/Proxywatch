package ml

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"proxywatch/internal/detection/model"
	"proxywatch/internal/safeio"
	"proxywatch/internal/shared"
)

// ContinuousLearner manages the background retraining loop.
type ContinuousLearner struct {
	buffer          *TrainingBuffer
	modelDir        string
	predictor       *atomicPredictor
	stopCh          chan struct{}
	trainDoneCh     chan struct{} // signaled when training completes — triggers immediate model check
	wg              sync.WaitGroup
	lastModelMod    time.Time    // mod time of last loaded model file
	OnModelSwapped  func()       // called after a successful model hot-swap
	TriggerTrain    func(string) // called to invoke the training orchestrator
}

// atomicPredictor allows hot-swapping the active predictor.
type atomicPredictor struct {
	mu   sync.RWMutex
	pred Predictor
}

func (a *atomicPredictor) Get() Predictor {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.pred
}

func (a *atomicPredictor) Swap(p Predictor) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pred != nil {
		a.pred.Close()
	}
	a.pred = p
}

// NewContinuousLearner creates the continuous learning system.
func NewContinuousLearner(initialPredictor Predictor) *ContinuousLearner {
	root := safeio.ProxywatchDataRoot()
	bufferPath := filepath.Join(root, "training", "buffer.ndjson")
	modelDir := filepath.Join(root, "models")

	cl := &ContinuousLearner{
		buffer:      NewTrainingBuffer(bufferPath),
		modelDir:    modelDir,
		predictor:   &atomicPredictor{pred: initialPredictor},
		stopCh:      make(chan struct{}),
		trainDoneCh: make(chan struct{}, 1),
	}

	// Start with a clean buffer each session. Persisted buffer from a previous
	// session may contain stale data from failed training attempts. Each collection
	// cycle starts fresh — collect → train → clear → repeat.
	cl.buffer.Clear()

	return cl
}

// NotifyTrainingDone signals the learner to check for a new model immediately.
func (cl *ContinuousLearner) NotifyTrainingDone() {
	select {
	case cl.trainDoneCh <- struct{}{}:
	default:
	}
}

// Buffer returns the training data buffer for adding observations.
func (cl *ContinuousLearner) Buffer() *TrainingBuffer {
	return cl.buffer
}

// Predictor returns the current active predictor (may change via hot-swap).
func (cl *ContinuousLearner) Predictor() Predictor {
	return cl.predictor.Get()
}

// SwapPredictor atomically replaces the active predictor with a new one.
// When p is nil (reset), lastModelMod is cleared so CheckForNewModel
// will reload the model from disk after the next training cycle.
func (cl *ContinuousLearner) SwapPredictor(p Predictor) {
	cl.predictor.Swap(p)
	if p == nil {
		cl.lastModelMod = time.Time{}
	}
}

// Start begins the background retraining check loop.
func (cl *ContinuousLearner) Start() {
	cl.wg.Add(1)
	go cl.loop()
}

// Stop shuts down the background loop and persists the buffer.
func (cl *ContinuousLearner) Stop() {
	close(cl.stopCh)
	cl.wg.Wait()
	_ = cl.buffer.PersistToDisk()
}

func (cl *ContinuousLearner) loop() {
	defer cl.wg.Done()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// Compute initial maturity.
	model.ComputeMaturity()

	for {
		select {
		case <-cl.stopCh:
			return
		case <-cl.trainDoneCh:
			// Training completed — immediately check for new model.
			cl.CheckForNewModel()
			model.ComputeMaturity()
		case <-ticker.C:
			// Recompute maturity.
			model.ComputeMaturity()

			// Persist buffer periodically.
			_ = cl.buffer.PersistToDisk()

			// Check for new model from orchestrator (hot-swap).
			cl.CheckForNewModel()

			// Check retrain triggers (gated by dashboard toggle).
			if !shared.AutoRetrainEnabled.Load() {
				continue
			}
			shouldRetrain, reason := model.ShouldRetrain()
			if shouldRetrain {
				shared.SetCyclePhase(shared.CycleThresholdMet)
				shared.LogInfo("ml", "retrain triggered: %s (buffer: %d)", reason, cl.buffer.Len())
				cl.attemptRetrain(reason)
			} else {
				// If not training and not already in a training phase, ensure we show collecting.
				phase := shared.GetCyclePhase()
				if phase == shared.CycleTrainingDone || phase == shared.CycleTrainingFailed {
					shared.SetCyclePhase(shared.CycleCollecting)
				}
			}
		}
	}
}

func (cl *ContinuousLearner) attemptRetrain(reason string) {
	bufferSize := cl.buffer.Len()
	if bufferSize < 200 {
		shared.SetCyclePhase(shared.CycleWaitingBuffer)
		shared.LogInfo("ml", "waiting for buffer: %d/200 records", bufferSize)
		return
	}

	// Invoke the training orchestrator if wired.
	if cl.TriggerTrain != nil {
		cl.TriggerTrain(reason)
		return
	}

	// Fallback: export buffer only (no orchestrator available).
	exportPath := filepath.Join(cl.modelDir, "retrain-buffer.ndjson")
	if err := cl.exportBuffer(exportPath); err != nil {
		shared.LogError("ml", "retrain export failed: %v", err)
		return
	}
	shared.LogInfo("ml", "exported %d records to %s (no orchestrator)", bufferSize, exportPath)
	cl.CheckForNewModel()
	model.ResetRetrainTriggers()
}

func (cl *ContinuousLearner) exportBuffer(path string) error {
	records := cl.buffer.Snapshot()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, rec := range records {
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	return nil
}

// CheckForNewModel looks for a retrained model and hot-swaps if found.
func (cl *ContinuousLearner) CheckForNewModel() {
	// Check for a retrained model that's newer than the current one.
	candidates := []string{
		filepath.Join(cl.modelDir, "retrain", "role_classifier.json"),
		filepath.Join(cl.modelDir, "active", "role_classifier.json"),
	}

	for _, path := range candidates {
		info, err := os.Stat(path)
		if err != nil || info.Size() == 0 {
			continue
		}

		// Skip if the file hasn't changed since last load.
		if !cl.lastModelMod.IsZero() && !info.ModTime().After(cl.lastModelMod) {
			continue
		}

		newPred, err := LoadNative(path)
		if err != nil {
			continue
		}

		// Validate: ensure the new model has the same role classes.
		current := cl.predictor.Get()
		if current != nil && len(newPred.RoleClasses()) != len(current.RoleClasses()) {
			newPred.Close()
			continue
		}

		// Hot-swap.
		cl.predictor.Swap(newPred)
		cl.lastModelMod = info.ModTime()
		// Reset shadow counters so the new model is judged on its own
		// predictions, not inherited from the previous one. If the prior
		// model had been demoted, clearing the mlDemoted latch lets the
		// new model go through qualification cleanly.
		model.ResetShadowForRetrain()
		shared.LogInfo("ml", "hot-swapped to model: %s (%s) — shadow counters reset", path, newPred.ModelVersion())
		if cl.OnModelSwapped != nil {
			cl.OnModelSwapped()
		}
		return
	}
}
