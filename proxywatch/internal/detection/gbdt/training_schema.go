// Package schema defines the telemetry export format for ML training data.
package gbdt

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const SchemaVersion = "proxywatch-training-v1"

// TrainingRecord is one observation of a process for ML training.
type TrainingRecord struct {
	Schema    string    `json:"schema"`
	Timestamp time.Time `json:"timestamp"`
	Host      string    `json:"host"`
	Cycle     uint64    `json:"cycle"`

	ProcessKey  string `json:"process_key"`
	ProcessName string `json:"process_name"`
	ProcessPath string `json:"process_path"`
	User        string `json:"user"`
	Company     string `json:"company"`

	Features map[string]float64 `json:"features"`
	Signals  []string           `json:"signals"`

	RuleRole  string `json:"rule_role"`
	RuleScore int    `json:"rule_score"`

	ModelRole       *string  `json:"model_role"`
	ModelConfidence *float64 `json:"model_confidence"`

	OperatorLabel      *string `json:"operator_label,omitempty"`
	UserVerdict        string  `json:"user_verdict,omitempty"`
	CalibrationVerdict string  `json:"calibration_verdict,omitempty"`

	ExperienceRole         string  `json:"experience_role,omitempty"`
	ExperienceObservations int     `json:"experience_observations"`
	ExperienceStability    float64 `json:"experience_stability"`

	StrongEvidence  bool `json:"strong_evidence"`
	TrafficVerified bool `json:"traffic_verified"`
}

// Exporter writes training records as NDJSON to a daily file.
type Exporter struct {
	mu      sync.Mutex
	dir     string
	file    *os.File
	encoder *json.Encoder
	day     string
	cycle   uint64
}

// NewExporter creates an exporter writing to the given directory.
func NewExporter(dir string) (*Exporter, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create training dir: %w", err)
	}
	return &Exporter{dir: dir}, nil
}

// Emit writes a single training record. Rotates the output file daily.
func (e *Exporter) Emit(rec TrainingRecord) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	rec.Schema = SchemaVersion
	e.cycle++
	rec.Cycle = e.cycle

	day := time.Now().UTC().Format("2006-01-02")
	if day != e.day || e.file == nil {
		if e.file != nil {
			e.file.Close()
		}
		path := filepath.Join(e.dir, "training-"+day+".ndjson")
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("open training file: %w", err)
		}
		e.file = f
		e.encoder = json.NewEncoder(f)
		e.day = day
	}

	return e.encoder.Encode(rec)
}

// Close flushes and closes the current output file.
func (e *Exporter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.file != nil {
		err := e.file.Close()
		e.file = nil
		return err
	}
	return nil
}
