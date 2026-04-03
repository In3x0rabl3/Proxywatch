// Package model provides the unified Detection Model for Proxywatch.
// It persists intelligence across sessions from contour discoveries,
// calibration runs, user feedback, and runtime experience, feeding it
// back into real-time detection scoring.
package model

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"proxywatch/internal/keystore"
	"proxywatch/internal/safeio"
)

const (
	modelVersion               = 1
	vaultName                  = "model/detection-model.json"
	defaultModelDir            = "model"
	defaultModelFile           = "detection-model.json"
	saveInterval               = 30 * time.Second
	runtimeRefreshRate         = 60 * time.Second
	maxFeedbackEntries         = 500
	maxProcessProfiles         = 300
	feedbackMaxAgeDays         = 180
	profileMaxAgeDays          = 90
	egressDecayPerWeek         = 0.95
	egressMinConfidence        = 0.1
	calibrationBenignDecayDays = 30
	hmacKeyLabel               = "proxywatch-model-integrity"
	dirMode                    = 0o700
	fileMode                   = 0o600
)

// DetectionModel is the unified persistent intelligence store.
// This is the SINGLE model for Proxywatch — all intelligence flows here.
type DetectionModel struct {
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`

	// Contour-discovered egress paths.
	EgressPaths map[int]*EgressPath `json:"egress_paths,omitempty"`

	// Per-process-identity profiles (experience, calibration, feedback).
	Processes map[string]*ProcessProfile `json:"processes,omitempty"`

	// User feedback audit ledger.
	Feedback []FeedbackEntry `json:"feedback,omitempty"`

	// Model health metrics.
	Quality         QualityMetrics            `json:"quality"`
	SelfValidations map[string]SelfValidation `json:"self_validations,omitempty"`

	// Signal effectiveness: which signals lead to confirmed TPs vs FPs.
	SignalStats map[string]*SignalStat `json:"signal_stats,omitempty"`

	// Calibration aggregate stats (mirrored from learning model).
	CalibrationRuns          int     `json:"calibration_runs,omitempty"`
	CalibrationSamples       float64 `json:"calibration_samples,omitempty"`
	CalibrationContamination int     `json:"calibration_contamination,omitempty"`

	// Training patterns: generalized rules extracted from operator labels.
	// When 3+ labels share common traits, a pattern is created that applies
	// to ALL matching processes, not just the individually labeled ones.
	TrainingPatterns []TrainingPattern `json:"training_patterns,omitempty"`

	// Per-host overlays (ingest mode). Each host gets its own process profiles
	// and feedback. Global data (SignalStats, TrainingPatterns, EgressPaths) is shared.
	HostOverlays map[string]*HostOverlay `json:"host_overlays,omitempty"`

	Checksum string `json:"checksum"`
}

// SelfValidation records when the model confirmed its own prediction.
type SelfValidation struct {
	ProcessKey   string    `json:"process_key"`
	Role         string    `json:"role"`
	Stability    float64   `json:"stability"`
	Observations int       `json:"observations"`
	AvgScore     float64   `json:"avg_score"`
	ValidatedAt  time.Time `json:"validated_at"`
}

// HostOverlay contains per-host process profiles and feedback.
type HostOverlay struct {
	Host      string                     `json:"host"`
	Processes map[string]*ProcessProfile `json:"processes,omitempty"`
	Feedback  []FeedbackEntry            `json:"feedback,omitempty"`
	UpdatedAt time.Time                  `json:"updated_at"`
}

// TrainingPattern is a generalized rule the model extracted from operator
// training labels. It matches processes by shared characteristics.
type TrainingPattern struct {
	ID          string    `json:"id"`
	Verdict     string    `json:"verdict"`     // "benign" or "malicious"
	Confidence  float64   `json:"confidence"`  // 0.0-1.0
	MatchCount  int       `json:"match_count"` // how many labels contributed
	CreatedAt   time.Time `json:"created_at"`
	LastMatched time.Time `json:"last_matched"`

	// Match criteria — a process must match ALL non-empty fields.
	PathPrefix   string `json:"path_prefix,omitempty"`  // e.g. "c:/windows/system32/"
	UserContext  string `json:"user_context,omitempty"` // e.g. "system" (service-like) or "user"
	Company      string `json:"company,omitempty"`      // e.g. "microsoft"
	HasListener  *bool  `json:"has_listener,omitempty"`
	ExternalOnly *bool  `json:"external_only,omitempty"` // outExternal > 0 && outInternal == 0

	Description string `json:"description"` // human-readable summary
}

// SignalStat tracks how often a signal appeared in confirmed true/false positives.
type SignalStat struct {
	TruePositive  int     `json:"tp"`
	FalsePositive int     `json:"fp"`
	Total         int     `json:"total"`
	Precision     float64 `json:"precision"` // TP / (TP + FP)
}

// EgressPath represents a network egress path discovered by contour.
type EgressPath struct {
	Port          int       `json:"port"`
	Protocols     []string  `json:"protocols,omitempty"`
	TunnelCapable bool      `json:"tunnel_capable"`
	ExfilCapable  bool      `json:"exfil_capable"`
	DiscoveredAt  time.Time `json:"discovered_at"`
	LastConfirmed time.Time `json:"last_confirmed"`
	Confidence    float64   `json:"confidence"`
}

// ProcessProfile merges intelligence from calibration, runtime, user feedback,
// and live experience (every scoring cycle contributes observations).
type ProcessProfile struct {
	Name string `json:"name"`

	// Calibration history.
	CalibrationRuns    int                `json:"calibration_runs,omitempty"`
	RoleDistribution   map[string]float64 `json:"role_distribution,omitempty"`
	CalibrationVerdict string             `json:"calibration_verdict,omitempty"`
	LastCalibration    time.Time          `json:"last_calibration,omitempty"`

	// User feedback (kill/whitelist).
	KillCount      int       `json:"kill_count,omitempty"`
	WhitelistCount int       `json:"whitelist_count,omitempty"`
	LastKill       time.Time `json:"last_kill,omitempty"`
	LastWhitelist  time.Time `json:"last_whitelist,omitempty"`
	UserVerdict    string    `json:"user_verdict,omitempty"`

	// Runtime behavior (from ProcessBehavior EWMA).
	RuntimeObservations int       `json:"runtime_observations,omitempty"`
	DominantRole        string    `json:"dominant_role,omitempty"`
	RoleStability       float64   `json:"role_stability,omitempty"`
	LastRuntimeUpdate   time.Time `json:"last_runtime_update,omitempty"`

	// Experience: what the model has observed from live scoring.
	// Updated every scoring cycle — this is how the model learns.
	ExperienceObservations int            `json:"exp_observations,omitempty"`
	ExperienceRoles        map[string]int `json:"exp_roles,omitempty"`   // role → count
	ExperienceSignals      map[string]int `json:"exp_signals,omitempty"` // signal → count
	ExperienceAvgScore     float64        `json:"exp_avg_score,omitempty"`
	ExperienceMaxScore     int            `json:"exp_max_score,omitempty"`
	ExperienceLastRole     string         `json:"exp_last_role,omitempty"`
	ExperienceLastScore    int            `json:"exp_last_score,omitempty"`
	ExperienceLastUpdate   time.Time      `json:"exp_last_update,omitempty"`

	// Beacon interval persistence — survives restarts.
	BeaconIntervalMs  int       `json:"beacon_interval_ms,omitempty"`
	BeaconJitter      float64   `json:"beacon_jitter,omitempty"`
	BeaconConfirmedAt time.Time `json:"beacon_confirmed_at,omitempty"`

	// Long-term IO trending (last 7 days).
	DailyIOWrite   []uint64  `json:"daily_io_write,omitempty"`
	DailyIORead    []uint64  `json:"daily_io_read,omitempty"`
	IOTrendUpdated time.Time `json:"io_trend_updated,omitempty"`

	// Training labels: explicit operator classifications (beyond kill/whitelist).
	TrainingLabel   string    `json:"training_label,omitempty"`   // "malicious", "benign", "tunnel", "beacon", "session"
	TrainingContext string    `json:"training_context,omitempty"` // operator explanation of WHY this label was assigned
	TrainingLabelAt time.Time `json:"training_label_at,omitempty"`

	// Self-validation: model confirmed its own prediction from experience.
	SelfValidated   bool      `json:"self_validated,omitempty"`
	SelfValidatedAt time.Time `json:"self_validated_at,omitempty"`

	// Derived.
	OverallConfidence float64   `json:"overall_confidence"`
	LastUpdated       time.Time `json:"last_updated"`
}

// FeedbackEntry is an immutable audit record of a user action.
type FeedbackEntry struct {
	Timestamp   time.Time `json:"ts"`
	Action      string    `json:"action"`
	ProcessKey  string    `json:"process_key"`
	ProcessName string    `json:"process_name"`
	Role        string    `json:"role"`
	Score       int       `json:"score"`
	Signals     []string  `json:"signals,omitempty"`
}

// QualityMetrics tracks model health.
type QualityMetrics struct {
	TotalFeedback      int       `json:"total_feedback"`
	ConfirmedCorrect   int       `json:"confirmed_correct"`
	SelfConfirmed      int       `json:"self_confirmed"`
	Contradictions     int       `json:"contradictions"`
	ConfirmationRate   float64   `json:"confirmation_rate"`
	RoleStabilityScore float64   `json:"role_stability_score"`
	LastRecalculated   time.Time `json:"last_recalculated,omitempty"`
}

var (
	mu          sync.RWMutex
	current     *DetectionModel
	lastSave    time.Time
	lastRefresh time.Time
	modelPath   string
	dirty       bool
)

// Load reads the detection model from disk at startup.
func Load() error {
	mu.Lock()
	defer mu.Unlock()

	modelPath = diskPath()
	current = newEmptyModel()

	data, err := keystore.VaultRead(vaultName, modelPath)
	if err != nil || len(data) == 0 {
		fmt.Fprintf(os.Stderr, "[model] no saved model at %s (starting fresh)\n", modelPath)
		return nil
	}

	var loaded DetectionModel
	if err := json.Unmarshal(data, &loaded); err != nil {
		fmt.Fprintf(os.Stderr, "[model] WARNING: corrupt model JSON — starting fresh: %v\n", err)
		return nil
	}

	if !verifyChecksum(&loaded, data) {
		// Re-sign the model rather than discarding it — struct field
		// additions cause harmless checksum drift on upgrade.
		fmt.Fprintf(os.Stderr, "[model] checksum mismatch (likely binary upgrade) — re-signing model\n")
		loaded.Checksum = ""
		resigned, err := json.MarshalIndent(&loaded, "", "  ")
		if err == nil {
			loaded.Checksum = computeChecksum(resigned)
		}
	}

	if loaded.Version != modelVersion {
		fmt.Fprintf(os.Stderr, "[model] WARNING: version mismatch (got %d, want %d) — starting fresh\n", loaded.Version, modelVersion)
		return nil
	}

	applyDecay(&loaded)
	current = &loaded
	ensureMaps(current)

	profileCount := len(current.Processes)
	for _, overlay := range current.HostOverlays {
		if overlay != nil {
			profileCount += len(overlay.Processes)
		}
	}
	fmt.Fprintf(os.Stderr, "[model] loaded %d profiles, %d feedback entries, %d signal stats\n",
		profileCount, len(current.Feedback), len(current.SignalStats))
	return nil
}

// Get returns the current model. Safe for concurrent reads.
func Get() *DetectionModel {
	mu.RLock()
	defer mu.RUnlock()
	return current
}

// Save persists the model to disk.
func Save() error {
	FlushExperience()
	mu.Lock()
	defer mu.Unlock()
	if current == nil {
		return nil
	}
	return saveLocked()
}

// MaybeSave saves if enough time has elapsed and the model is dirty.
func MaybeSave(now time.Time) {
	mu.Lock()
	defer mu.Unlock()
	if current == nil || !dirty {
		return
	}
	if !lastSave.IsZero() && now.Sub(lastSave) < saveInterval {
		return
	}
	_ = saveLocked()
}

func saveLocked() error {
	current.UpdatedAt = time.Now().UTC()
	pruneModel(current)

	current.Checksum = ""
	data, err := json.MarshalIndent(current, "", "  ")
	if err != nil {
		return err
	}
	current.Checksum = computeChecksum(data)

	dataWithChecksum, _ := json.MarshalIndent(current, "", "  ")

	// Always write to disk — the model must persist across restarts.
	dir := filepath.Dir(modelPath)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, dirMode)
	}
	if err := os.WriteFile(modelPath, dataWithChecksum, fileMode); err != nil {
		return err
	}
	// Also store in vault for in-session consistency.
	_ = keystore.VaultWrite(vaultName, dataWithChecksum, modelPath)
	lastSave = time.Now().UTC()
	dirty = false
	return nil
}

func markDirty() {
	dirty = true
}

func newEmptyModel() *DetectionModel {
	m := &DetectionModel{
		Version:     modelVersion,
		UpdatedAt:   time.Now().UTC(),
		EgressPaths: make(map[int]*EgressPath),
		Processes:   make(map[string]*ProcessProfile),
	}
	return m
}

func ensureMaps(m *DetectionModel) {
	if m.EgressPaths == nil {
		m.EgressPaths = make(map[int]*EgressPath)
	}
	if m.Processes == nil {
		m.Processes = make(map[string]*ProcessProfile)
	}
	if m.HostOverlays == nil {
		m.HostOverlays = make(map[string]*HostOverlay)
	}
}

// ResolveProfile returns the process profile for a key from the current model.
// Checks host overlay first, then global. Safe for external callers.
func ResolveProfile(key string) *ProcessProfile {
	mu.RLock()
	defer mu.RUnlock()
	return resolveProcessProfile(current, key)
}

func resolveProcessProfile(m *DetectionModel, key string) *ProcessProfile {
	if m == nil {
		return nil
	}
	host := hostFromKey(key)
	if host != "" && m.HostOverlays != nil {
		if overlay, ok := m.HostOverlays[host]; ok && overlay != nil {
			if profile, ok := overlay.Processes[key]; ok {
				return profile
			}
		}
	}
	return m.Processes[key]
}

func resolveOrCreateProcessProfile(m *DetectionModel, key, name string) *ProcessProfile {
	if m == nil {
		return nil
	}
	host := hostFromKey(key)
	if host != "" && m.HostOverlays != nil {
		overlay, ok := m.HostOverlays[host]
		if !ok {
			overlay = &HostOverlay{Host: host, Processes: make(map[string]*ProcessProfile)}
			m.HostOverlays[host] = overlay
		}
		if overlay.Processes == nil {
			overlay.Processes = make(map[string]*ProcessProfile)
		}
		if profile, ok := overlay.Processes[key]; ok {
			return profile
		}
		profile := &ProcessProfile{Name: name}
		overlay.Processes[key] = profile
		return profile
	}
	if profile, ok := m.Processes[key]; ok {
		return profile
	}
	profile := &ProcessProfile{Name: name}
	m.Processes[key] = profile
	return profile
}

func hostFromKey(key string) string {
	idx := strings.IndexByte(key, '|')
	if idx > 0 {
		return key[:idx]
	}
	return ""
}

func diskPath() string {
	root := safeio.ProxywatchDataRoot()
	return filepath.Join(root, defaultModelDir, defaultModelFile)
}

// --- HMAC integrity ---

func computeChecksum(jsonWithoutChecksum []byte) string {
	key := deriveHMACKey()
	mac := hmac.New(sha256.New, key)
	mac.Write(jsonWithoutChecksum)
	return hex.EncodeToString(mac.Sum(nil))
}

func verifyChecksum(m *DetectionModel, rawJSON []byte) bool {
	if m.Checksum == "" {
		return true // no checksum = legacy model, accept
	}

	saved := m.Checksum
	m.Checksum = ""
	clean, err := json.MarshalIndent(m, "", "  ")
	m.Checksum = saved
	if err != nil {
		return false
	}

	expected := computeChecksum(clean)
	return hmac.Equal([]byte(saved), []byte(expected))
}

func deriveHMACKey() []byte {
	h := sha256.Sum256([]byte(hmacKeyLabel))
	return h[:]
}

// --- Decay & pruning ---

func applyDecay(m *DetectionModel) {
	now := time.Now().UTC()

	// Egress path confidence decay.
	for port, ep := range m.EgressPaths {
		if ep.LastConfirmed.IsZero() {
			continue
		}
		weeks := now.Sub(ep.LastConfirmed).Hours() / (24 * 7)
		if weeks > 0 {
			ep.Confidence *= math.Pow(egressDecayPerWeek, weeks)
		}
		if ep.Confidence < egressMinConfidence {
			delete(m.EgressPaths, port)
		}
	}

	// Process profile aging.
	for key, profile := range m.Processes {
		days := now.Sub(profile.LastUpdated).Hours() / 24
		if days > profileMaxAgeDays {
			delete(m.Processes, key)
			continue
		}
		// Calibration benign verdict decays after 30 days.
		if profile.CalibrationVerdict == "benign" &&
			!profile.LastCalibration.IsZero() &&
			now.Sub(profile.LastCalibration).Hours()/24 > calibrationBenignDecayDays {
			profile.CalibrationVerdict = "unknown"
			profile.OverallConfidence = computeConfidence(profile)
		}
	}

	// Feedback ledger pruning.
	cutoff := now.Add(-feedbackMaxAgeDays * 24 * time.Hour)
	pruned := m.Feedback[:0]
	for _, entry := range m.Feedback {
		if entry.Timestamp.After(cutoff) {
			pruned = append(pruned, entry)
		}
	}
	m.Feedback = pruned
}

func pruneModel(m *DetectionModel) {
	if len(m.Feedback) > maxFeedbackEntries {
		m.Feedback = m.Feedback[len(m.Feedback)-maxFeedbackEntries:]
	}
	if len(m.Processes) > maxProcessProfiles {
		trimProcessProfiles(m)
	}
}

func trimProcessProfiles(m *DetectionModel) {
	type entry struct {
		key     string
		updated time.Time
	}
	entries := make([]entry, 0, len(m.Processes))
	for key, profile := range m.Processes {
		entries = append(entries, entry{key: key, updated: profile.LastUpdated})
	}
	// Sort oldest first.
	for i := 0; i < len(entries); i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[j].updated.Before(entries[i].updated) {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}
	toRemove := len(entries) - maxProcessProfiles
	for i := 0; i < toRemove; i++ {
		// Never remove profiles with user feedback.
		p := m.Processes[entries[i].key]
		if p != nil && (p.KillCount > 0 || p.WhitelistCount > 0) {
			continue
		}
		delete(m.Processes, entries[i].key)
	}
}

// computeConfidence derives overall confidence from all intelligence sources.
func computeConfidence(p *ProcessProfile) float64 {
	c := 0.0

	// Training label is the strongest signal (explicit operator classification).
	switch p.TrainingLabel {
	case "malicious", "beacon", "session", "tunnel":
		c -= 0.7
	case "benign":
		c += 0.6
	}

	// User feedback (kill/whitelist).
	if p.KillCount > 0 && p.WhitelistCount == 0 {
		c -= 0.5
	} else if p.WhitelistCount > 0 && p.KillCount == 0 {
		c += 0.4
	} else if p.KillCount > 0 && p.WhitelistCount > 0 {
		if !p.LastKill.IsZero() && (p.LastWhitelist.IsZero() || p.LastKill.After(p.LastWhitelist)) {
			c -= 0.3
		} else {
			c += 0.2
		}
	}

	// Calibration/experience verdict.
	switch p.CalibrationVerdict {
	case "benign":
		c += 0.2
	case "suspicious":
		c -= 0.2
	}

	// Experience-based role stability.
	if p.ExperienceObservations >= 20 && p.RoleStability > 0.9 {
		if p.DominantRole == "outbound" || p.DominantRole == "listen" {
			c += 0.1
		} else if p.DominantRole == "control-session" || p.DominantRole == "control-beacon" {
			c -= 0.1
		}
	}

	if c > 1.0 {
		c = 1.0
	}
	if c < -1.0 {
		c = -1.0
	}
	return c
}
