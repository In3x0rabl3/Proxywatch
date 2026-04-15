// Package shared provides a structured event log that captures runtime
// messages without printing to stderr. The TUI reads from this buffer
// to display status messages in a controlled panel.
package shared

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// TrainingBufferSizeAtomic is updated by the classifier and read by the training dashboard.
// Uses atomic to avoid lock contention between scoring goroutine and UI.
var TrainingBufferSizeAtomic atomic.Int64

// AutoRetrainEnabled controls whether the ContinuousLearner triggers automatic
// retraining. Toggled from the training dashboard; checked in the retrain loop.
var AutoRetrainEnabled atomic.Bool

// TrainingActiveAtomic is set to true by the orchestrator while training is
// in progress. Read by the UI to show training status regardless of whether
// the retrain was triggered manually or automatically.
var TrainingActiveAtomic atomic.Bool

// TrainingStartTime stores when the current training run started (unix nanos).
var TrainingStartTime atomic.Int64

// Training cycle phase — drives the UI state machine.
// Updated by the orchestrator and retrain loop. Read by the dashboard.
const (
	CycleCollecting      = "collecting"       // gathering observations
	CycleThresholdMet    = "threshold_met"    // obs threshold reached, waiting for buffer
	CycleWaitingBuffer   = "waiting_buffer"   // obs threshold met but buffer < 50
	CycleTrainingIngest  = "training_ingest"  // exporting + ingesting data
	CycleTrainingFit     = "training_fit"     // fitting GBDT model
	CycleTrainingEval    = "training_eval"    // evaluating with CV
	CycleTrainingExport  = "training_export"  // exporting model
	CycleTrainingDone    = "training_done"    // training completed, awaiting hot-swap
	CycleTrainingFailed  = "training_failed"  // training failed
	CycleWaitingLabels   = "waiting_labels"   // need operator labels
)

// TrainingCyclePhase holds the current phase of the training cycle.
var TrainingCyclePhase atomic.Value // stores string

// TrainingCycleError holds the last training error message (empty if none).
var TrainingCycleError atomic.Value // stores string

func init() {
	TrainingCyclePhase.Store(CycleCollecting)
	TrainingCycleError.Store("")
}

// SetCyclePhase updates the training cycle phase and logs the transition.
func SetCyclePhase(phase string) {
	TrainingCyclePhase.Store(phase)
}

// GetCyclePhase returns the current training cycle phase.
func GetCyclePhase() string {
	if v, ok := TrainingCyclePhase.Load().(string); ok {
		return v
	}
	return CycleCollecting
}

// SetCycleError stores the last training error.
func SetCycleError(err string) {
	TrainingCycleError.Store(err)
}

// GetCycleError returns the last training error.
func GetCycleError() string {
	if v, ok := TrainingCycleError.Load().(string); ok {
		return v
	}
	return ""
}

// EventSeverity indicates the importance of a log event.
type EventSeverity int

const (
	EventInfo EventSeverity = iota
	EventWarn
	EventError
)

// LogEvent is a structured runtime message.
type LogEvent struct {
	Time     time.Time
	Severity EventSeverity
	Source   string // "ml", "model", "agent", "detection"
	Message  string
}

const maxEventLogSize = 50

var (
	eventLogMu sync.Mutex
	eventLog   []LogEvent
)

// LogInfo logs an informational runtime event.
func LogInfo(source, format string, args ...interface{}) {
	addEvent(EventInfo, source, fmt.Sprintf(format, args...))
}

// LogWarn logs a warning runtime event.
func LogWarn(source, format string, args ...interface{}) {
	addEvent(EventWarn, source, fmt.Sprintf(format, args...))
}

// LogError logs an error runtime event.
func LogError(source, format string, args ...interface{}) {
	addEvent(EventError, source, fmt.Sprintf(format, args...))
}

func addEvent(sev EventSeverity, source, msg string) {
	eventLogMu.Lock()
	defer eventLogMu.Unlock()

	ev := LogEvent{
		Time:     time.Now().UTC(),
		Severity: sev,
		Source:   source,
		Message:  msg,
	}
	eventLog = append(eventLog, ev)
	if len(eventLog) > maxEventLogSize {
		eventLog = eventLog[len(eventLog)-maxEventLogSize:]
	}
}

// EventLogSnapshot returns a copy of the recent event log.
func EventLogSnapshot() []LogEvent {
	eventLogMu.Lock()
	defer eventLogMu.Unlock()
	out := make([]LogEvent, len(eventLog))
	copy(out, eventLog)
	return out
}

