package keys

import (
	"time"

	"proxywatch/internal/detection/ml"
	"proxywatch/internal/detection/model"
	"proxywatch/internal/shared"
	"proxywatch/internal/detection"

	"github.com/gdamore/tcell/v2"
)

// Training field constants (mirrored in views/bridge.go).
const (
	TrainingFieldAutoLearn = iota
	TrainingFieldRetrain
	TrainingFieldReset
)

const TrainingFieldMax = TrainingFieldReset

// HandleTrainingKey processes keyboard input for the model dashboard.
func HandleTrainingKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if app.TrainingShowHelp {
		return handleTrainingHelpKey(app, tev)
	}

	switch tev.Key() {
	case tcell.KeyUp:
		cycleField(&app.TrainingField, TrainingFieldAutoLearn, TrainingFieldMax, true)
		return false
	case tcell.KeyDown:
		cycleField(&app.TrainingField, TrainingFieldAutoLearn, TrainingFieldMax, false)
		return false

	case tcell.KeyEnter:
		return handleTrainingAction(app)

	case tcell.KeyEscape:
		app.Mode = shared.ModeDashboard
		return false

	case tcell.KeyLeft:
		StepWorkflowMenu(app, -1)
		return false
	case tcell.KeyRight:
		StepWorkflowMenu(app, 1)
		return false
	}

	switch tev.Rune() {
	case '?':
		app.TrainingShowHelp = !app.TrainingShowHelp
		return false
	case 'q':
		return requestQuit(app)
	}

	if JumpToWorkflow(app, tev.Rune()) {
		return false
	}

	return false
}

// cycleBaselineSelection moves the baseline list selection forward or backward.
func handleTrainingHelpKey(app *shared.AppState, tev *tcell.EventKey) bool {
	switch tev.Key() {
	case tcell.KeyEscape:
		app.TrainingShowHelp = false
	}
	switch tev.Rune() {
	case '?':
		app.TrainingShowHelp = false
	}
	return false
}

func handleTrainingAction(app *shared.AppState) bool {
	switch app.TrainingField {
	case TrainingFieldAutoLearn:
		app.TrainingAutoRetrain = !app.TrainingAutoRetrain
		shared.AutoRetrainEnabled.Store(app.TrainingAutoRetrain)
		if app.TrainingAutoRetrain {
			shared.LogInfo("model", "continuous learning enabled")
		} else {
			shared.LogInfo("model", "continuous learning paused")
		}

	case TrainingFieldRetrain:
		orch, orchOK := app.TrainingOrchestrator.(*detection.Orchestrator)
		if !orchOK || orch == nil {
			shared.LogWarn("model", "training pipeline not configured")
			return false
		}
		if app.TrainingRetraining {
			// Already running — stop it.
			orch.StopRetrain()
			app.TrainingRetraining = false
			return false
		}
		learner, learnerOK := app.TrainingLearner.(*ml.ContinuousLearner)
		if !learnerOK || learner == nil {
			shared.LogWarn("model", "training pipeline not configured")
			return false
		}
		app.TrainingRetraining = true
		app.TrainingRetrainStart = time.Now()
		orch.TriggerRetrainManual("manual (dashboard)", learner.Buffer())
		if app.StartTrainingRetrain != nil {
			app.StartTrainingRetrain()
		}

	case TrainingFieldReset:
		if app.TrainingRetraining {
			shared.LogWarn("model", "cannot reset while retraining is in progress")
			return false
		}
		if app.TrainingResetConfirm && time.Now().Before(app.TrainingResetDeadline) {
			app.TrainingResetConfirm = false
			model.ResetToBaseline()
			// Clear the training buffer and drop the active predictor so the
			// classifier falls back to rules until the model is retrained.
			if learner, ok := app.TrainingLearner.(*ml.ContinuousLearner); ok && learner != nil {
				learner.SwapPredictor(nil)
				learner.Buffer().Clear()
				shared.TrainingBufferSizeAtomic.Store(0)
			}
			detection.MLPrimary = false
			shared.LogInfo("model", "reset to baseline — all learned experience cleared")
		} else {
			app.TrainingResetConfirm = true
			app.TrainingResetDeadline = time.Now().Add(5 * time.Second)
			shared.LogWarn("model", "press ENTER again within 5s to confirm baseline reset")
		}
	}

	return false
}

