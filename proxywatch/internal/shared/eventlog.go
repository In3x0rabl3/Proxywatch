// Package shared provides a structured event log that captures runtime
// messages without printing to stderr. The TUI reads from this buffer
// to display status messages in a controlled panel.
package shared

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// jsonLoggingEnabled is set once at init based on PROXYWATCH_LOG_JSON.
// When true, addEvent also emits each event as a single-line JSON
// object to stderr — one record per line, NDJSON — for SIEM ingestion.
// Never enable this while running the TUI (the stderr writes would
// corrupt the screen). Intended for headless / service-mode deployments
// where the process stdout/stderr is being consumed by a log collector.
var jsonLoggingEnabled atomic.Bool

func init() {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("PROXYWATCH_LOG_JSON")))
	switch raw {
	case "1", "true", "on", "yes", "enable", "enabled":
		jsonLoggingEnabled.Store(true)
	}
}

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
	CycleCollecting     = "collecting"      // gathering observations
	CycleThresholdMet   = "threshold_met"   // obs threshold reached, waiting for buffer
	CycleWaitingBuffer  = "waiting_buffer"  // obs threshold met but buffer < 50
	CycleTrainingIngest = "training_ingest" // exporting + ingesting data
	CycleTrainingFit    = "training_fit"    // fitting GBDT model
	CycleTrainingEval   = "training_eval"   // evaluating with CV
	CycleTrainingExport = "training_export" // exporting model
	CycleTrainingDone   = "training_done"   // training completed, awaiting hot-swap
	CycleTrainingFailed = "training_failed" // training failed
	CycleWaitingLabels  = "waiting_labels"  // need operator labels
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
	ev := LogEvent{
		Time:     time.Now().UTC(),
		Severity: sev,
		Source:   source,
		Message:  msg,
	}

	eventLogMu.Lock()
	eventLog = append(eventLog, ev)
	if len(eventLog) > maxEventLogSize {
		eventLog = eventLog[len(eventLog)-maxEventLogSize:]
	}
	eventLogMu.Unlock()

	// Optional NDJSON emission to stderr for SIEM ingestion. Gated on
	// PROXYWATCH_LOG_JSON so the TUI default stays quiet. The lock is
	// released before the write so a slow stderr (e.g. blocked pipe)
	// doesn't stall classification.
	if jsonLoggingEnabled.Load() {
		emitEventJSON(ev)
	}
}

// severityString maps the internal enum to lowercase labels matching
// common log-aggregator conventions (info / warn / error).
func severityString(s EventSeverity) string {
	switch s {
	case EventInfo:
		return "info"
	case EventWarn:
		return "warn"
	case EventError:
		return "error"
	}
	return "info"
}

func emitEventJSON(ev LogEvent) {
	record := map[string]string{
		"ts":     ev.Time.Format(time.RFC3339Nano),
		"level":  severityString(ev.Severity),
		"source": ev.Source,
		"msg":    ev.Message,
	}
	b, err := json.Marshal(record)
	if err != nil {
		return
	}
	b = append(b, '\n')
	_, _ = os.Stderr.Write(b)
}

// EventLogSnapshot returns a copy of the recent event log.
func EventLogSnapshot() []LogEvent {
	eventLogMu.Lock()
	defer eventLogMu.Unlock()
	out := make([]LogEvent, len(eventLog))
	copy(out, eventLog)
	return out
}
