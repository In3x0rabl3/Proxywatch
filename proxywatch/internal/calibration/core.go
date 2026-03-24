package calibration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"proxywatch/internal/keystore"
	"proxywatch/internal/safeio"
	"proxywatch/internal/shared"
)

const (
	defaultOutputPath     = "~/.proxywatch/calibration/latest.json"
	defaultCalibrationDir = "~/.proxywatch/calibration"
	maxPromptTargetBytes  = 12000
	maxPromptHardBytes    = 22000
)

var (
	providerLabels  = []string{"OpenAI", "Anthropic", "Local"}
	durationOptions = []string{"10s", "30s", "1m", "5m", "15m", "30m", "1h", "2h", "4h"}
)

type ProviderAccess struct {
	OpenAIKey    bool
	AnthropicKey bool
	LocalLLMURL  bool
	LocalLLMKey  bool
}

type TuningSettings struct {
	ReverseControlMinDuration string `json:"reverse_control_min_duration"`
	LongLivedOutboundMinAge   string `json:"long_lived_outbound_min_age"`
	ShortLivedOutboundMaxAge  string `json:"short_lived_outbound_max_age"`
	BeaconSleepThreshold      string `json:"beacon_sleep_threshold"`
	ActiveWindow              string `json:"active_window"`
	SuspicionWindow           string `json:"suspicion_window"`

	BeaconMinIntervals       int     `json:"beacon_min_intervals"`
	ReverseStickyScore       int     `json:"reverse_sticky_score"`
	ForwardStickyScore       int     `json:"forward_sticky_score"`
	ReverseControlBaseScore  int     `json:"reverse_control_base_score"`
	MinInternalTargetsForRev int     `json:"min_internal_targets_for_rev"`
	MinInternalPortsForRev   int     `json:"min_internal_ports_for_rev"`
	OutboundOnlyExternalCap  int     `json:"outbound_only_external_cap"`
	TrafficVerifiedPenalty   int     `json:"traffic_verified_penalty"`
	VerifiedExternalPrefixes int     `json:"verified_external_min_prefixes"`
	ShapeDeltaThreshold      float64 `json:"shape_delta_threshold"`
	BeaconJitterCoVMax       float64 `json:"beacon_jitter_cov_max"`
}

type ProcessSummary struct {
	Host    string `json:"host"`
	PID     int    `json:"pid"`
	Process string `json:"process"`
	Role    string `json:"role"`
	Age     string `json:"age"`
	State   string `json:"state"`
}

type Report struct {
	ID                    string                `json:"id"`
	GeneratedAt           time.Time             `json:"generated_at"`
	Provider              string                `json:"provider"`
	Model                 string                `json:"model"`
	Scope                 string                `json:"scope"`
	Duration              string                `json:"duration"`
	AnalysisMode          string                `json:"analysis_mode,omitempty"`
	AnalysisError         string                `json:"analysis_error,omitempty"`
	CandidateCount        int                   `json:"candidate_count"`
	RoleCounts            map[string]int        `json:"role_counts"`
	StateCounts           map[string]int        `json:"state_counts"`
	TopProcesses          []ProcessSummary      `json:"top_processes"`
	Summary               string                `json:"summary"`
	Recommendations       []string              `json:"recommendations"`
	Risks                 []string              `json:"risks,omitempty"`
	Reasoning             []string              `json:"reasoning,omitempty"`
	Settings              TuningSettings        `json:"settings"`
	ProfileName           string                `json:"profile_name"`
	OutputPath            string                `json:"output_path"`
	DatasetPath           string                `json:"dataset_path,omitempty"`
	Confidence            int                   `json:"confidence,omitempty"`
	SampleEvery           string                `json:"sample_every,omitempty"`
	RecommendationSource  string                `json:"recommendation_source,omitempty"`
	LearningModelPath     string                `json:"learning_model_path,omitempty"`
	LearningRuns          int                   `json:"learning_runs,omitempty"`
	LearningSamples       float64               `json:"learning_samples,omitempty"`
	LearningContamination int                   `json:"learning_contamination_pct,omitempty"`
	LearningTopNormal     []string              `json:"learning_top_normal,omitempty"`
	LearningNotes         []string              `json:"learning_notes,omitempty"`
	RecommendedSettings   []string              `json:"recommended_settings,omitempty"`
	Validation            CalibrationValidation `json:"validation,omitempty"`
	Memory                CalibrationMemory     `json:"memory,omitempty"`
	SimilarPast           []SimilarCalibration  `json:"similar_past,omitempty"`
	ContourHintsApplied   int                   `json:"contour_hints_applied,omitempty"`
	ReportLines           []string              `json:"report_lines,omitempty"`
}

type Profile struct {
	Name            string         `json:"name"`
	CreatedAt       time.Time      `json:"created_at"`
	Provider        string         `json:"provider"`
	Model           string         `json:"model"`
	Scope           string         `json:"scope"`
	SourceReport    string         `json:"source_report"`
	CandidateCount  int            `json:"candidate_count"`
	RoleCounts      map[string]int `json:"role_counts"`
	StateCounts     map[string]int `json:"state_counts"`
	Recommendations []string       `json:"recommendations"`
	Settings        TuningSettings `json:"settings"`
}

type ActiveConfig struct {
	Profile   string         `json:"profile"`
	AppliedAt time.Time      `json:"applied_at"`
	Provider  string         `json:"provider"`
	Model     string         `json:"model"`
	Scope     string         `json:"scope"`
	Settings  TuningSettings `json:"settings"`
}

type RunInput struct {
	Provider     string
	Model        string
	Scope        string
	Duration     time.Duration
	Output       string
	SampleEvery  time.Duration
	Samples      []shared.Candidate
	ContourHints []shared.ContourHint
}

type RunResult struct {
	Report      Report
	ReportPath  string
	Profile     Profile
	ProfilePath string
}

type aiCalibrationResult struct {
	Summary         string         `json:"summary"`
	Recommendations []string       `json:"recommendations"`
	Risks           []string       `json:"risks"`
	Reasoning       []string       `json:"reasoning"`
	Settings        TuningSettings `json:"settings"`
}

type processFeature struct {
	Host       string   `json:"host"`
	Process    string   `json:"process"`
	PID        int      `json:"pid"`
	RoleFamily string   `json:"role_family"`
	State      string   `json:"state"`
	AgeSeconds int      `json:"age_seconds"`
	Inbound    int      `json:"inbound"`
	Outbound   int      `json:"outbound"`
	Reasons    []string `json:"reasons,omitempty"`
	Signals    []string `json:"signals,omitempty"`
}

func Providers() []string {
	out := make([]string, len(providerLabels))
	copy(out, providerLabels)
	return out
}

func ProviderLabel(provider string) string {
	switch normalizeProvider(provider) {
	case "openai":
		return "OpenAI"
	case "anthropic":
		return "Anthropic"
	case "local":
		return "Local"
	default:
		return "OpenAI"
	}
}

func ProviderKey(provider string) string {
	return normalizeProvider(provider)
}

func DurationOptions() []string {
	out := make([]string, len(durationOptions))
	copy(out, durationOptions)
	return out
}

func ModelOptions(provider string) []string {
	switch normalizeProvider(provider) {
	case "openai":
		return []string{"gpt-5", "gpt-5-mini", "gpt-5-nano"}
	case "anthropic":
		return []string{"claude-sonnet-4.5", "claude-opus-4.1", "claude-haiku-4.5"}
	case "local":
		return []string{"(local-default)", "llama3.1:8b", "qwen2.5:14b", "deepseek-r1:32b"}
	default:
		return []string{"gpt-5", "gpt-5-mini", "gpt-5-nano"}
	}
}

func DefaultModel(provider string) string {
	opts := ModelOptions(provider)
	if len(opts) == 0 {
		return "(default)"
	}
	return opts[0]
}

func DefaultOutputPath() string {
	return defaultOutputPath
}

func DetectProviderAccess() ProviderAccess {
	return ProviderAccess{
		OpenAIKey:    keystore.RuntimeSet("OPENAI_API_KEY"),
		AnthropicKey: keystore.RuntimeSet("ANTHROPIC_API_KEY"),
		LocalLLMURL:  keystore.RuntimeSet("LOCAL_LLM_URL"),
		LocalLLMKey:  keystore.RuntimeSet("LOCAL_LLM_API_KEY"),
	}
}

func ProviderReady(provider string, access ProviderAccess) (bool, string) {
	switch normalizeProvider(provider) {
	case "openai":
		if !access.OpenAIKey {
			return false, "missing OPENAI_API_KEY"
		}
	case "anthropic":
		if !access.AnthropicKey {
			return false, "missing ANTHROPIC_API_KEY"
		}
	case "local":
		if !access.LocalLLMURL {
			return false, "missing LOCAL_LLM_URL"
		}
		if !access.LocalLLMKey {
			return false, "missing LOCAL_LLM_API_KEY"
		}
	}
	return true, ""
}

func CurrentSettings() TuningSettings {
	return TuningSettings{
		ReverseControlMinDuration: shared.ReverseControlMinDuration.String(),
		LongLivedOutboundMinAge:   shared.LongLivedOutboundMinAge.String(),
		ShortLivedOutboundMaxAge:  shared.ShortLivedOutboundMaxAge.String(),
		BeaconSleepThreshold:      shared.BeaconSleepThreshold.String(),
		ActiveWindow:              shared.ActiveWindow.String(),
		SuspicionWindow:           shared.SuspicionWindow.String(),
		BeaconMinIntervals:        shared.BeaconMinIntervals,
		ReverseStickyScore:        shared.ReverseStickyScore,
		ForwardStickyScore:        shared.ForwardStickyScore,
		ReverseControlBaseScore:   shared.ReverseControlBaseScore,
		MinInternalTargetsForRev:  shared.MinInternalTargetsForRev,
		MinInternalPortsForRev:    shared.MinInternalPortsForRev,
		OutboundOnlyExternalCap:   shared.OutboundOnlyExternalCap,
		TrafficVerifiedPenalty:    shared.TrafficVerifiedPenalty,
		VerifiedExternalPrefixes:  shared.VerifiedExternalMinPrefixes,
		ShapeDeltaThreshold:       shared.ShapeDeltaThreshold,
		BeaconJitterCoVMax:        shared.BeaconJitterCoVMax,
	}
}

func (s TuningSettings) Apply() error {
	if err := validateTuningSettings(s); err != nil {
		return err
	}
	cur := CurrentSettings()

	reverseControl, err := parseDurationOrDefault(s.ReverseControlMinDuration, cur.ReverseControlMinDuration)
	if err != nil {
		return fmt.Errorf("reverse control min duration: %w", err)
	}
	longLived, err := parseDurationOrDefault(s.LongLivedOutboundMinAge, cur.LongLivedOutboundMinAge)
	if err != nil {
		return fmt.Errorf("long lived outbound min age: %w", err)
	}
	shortLived, err := parseDurationOrDefault(s.ShortLivedOutboundMaxAge, cur.ShortLivedOutboundMaxAge)
	if err != nil {
		return fmt.Errorf("short lived outbound max age: %w", err)
	}
	beaconSleep, err := parseDurationOrDefault(s.BeaconSleepThreshold, cur.BeaconSleepThreshold)
	if err != nil {
		return fmt.Errorf("beacon sleep threshold: %w", err)
	}
	activeWindow, err := parseDurationOrDefault(s.ActiveWindow, cur.ActiveWindow)
	if err != nil {
		return fmt.Errorf("active window: %w", err)
	}
	suspWindow, err := parseDurationOrDefault(s.SuspicionWindow, cur.SuspicionWindow)
	if err != nil {
		return fmt.Errorf("suspicion window: %w", err)
	}

	shared.ReverseControlMinDuration = reverseControl
	shared.LongLivedOutboundMinAge = longLived
	shared.ShortLivedOutboundMaxAge = shortLived
	shared.BeaconSleepThreshold = beaconSleep
	shared.ActiveWindow = activeWindow
	shared.SuspicionWindow = suspWindow

	shared.BeaconMinIntervals = maxInt(1, defaultInt(s.BeaconMinIntervals, cur.BeaconMinIntervals))
	shared.ReverseStickyScore = clampInt(defaultInt(s.ReverseStickyScore, cur.ReverseStickyScore), 10, 250)
	shared.ForwardStickyScore = clampInt(defaultInt(s.ForwardStickyScore, cur.ForwardStickyScore), 10, 250)
	shared.ReverseControlBaseScore = clampInt(defaultInt(s.ReverseControlBaseScore, cur.ReverseControlBaseScore), 1, 200)
	shared.MinInternalTargetsForRev = clampInt(defaultInt(s.MinInternalTargetsForRev, cur.MinInternalTargetsForRev), 1, 100)
	shared.MinInternalPortsForRev = clampInt(defaultInt(s.MinInternalPortsForRev, cur.MinInternalPortsForRev), 1, 100)
	shared.OutboundOnlyExternalCap = clampInt(defaultInt(s.OutboundOnlyExternalCap, cur.OutboundOnlyExternalCap), 1, 500)
	shared.TrafficVerifiedPenalty = clampInt(defaultInt(s.TrafficVerifiedPenalty, cur.TrafficVerifiedPenalty), 1, 500)
	shared.VerifiedExternalMinPrefixes = clampInt(defaultInt(s.VerifiedExternalPrefixes, cur.VerifiedExternalPrefixes), 1, 200)
	shared.ShapeDeltaThreshold = clampFloat(defaultFloat(s.ShapeDeltaThreshold, cur.ShapeDeltaThreshold), 0.05, 1.5)
	shared.BeaconJitterCoVMax = clampFloat(defaultFloat(s.BeaconJitterCoVMax, cur.BeaconJitterCoVMax), 0.2, 5.0)

	return nil
}

func validateTuningSettings(s TuningSettings) error {
	cur := CurrentSettings()
	reverseControl, err := parseDurationOrDefault(s.ReverseControlMinDuration, cur.ReverseControlMinDuration)
	if err != nil {
		return fmt.Errorf("reverse control min duration: %w", err)
	}
	longLived, err := parseDurationOrDefault(s.LongLivedOutboundMinAge, cur.LongLivedOutboundMinAge)
	if err != nil {
		return fmt.Errorf("long lived outbound min age: %w", err)
	}
	shortLived, err := parseDurationOrDefault(s.ShortLivedOutboundMaxAge, cur.ShortLivedOutboundMaxAge)
	if err != nil {
		return fmt.Errorf("short lived outbound max age: %w", err)
	}
	activeWindow, err := parseDurationOrDefault(s.ActiveWindow, cur.ActiveWindow)
	if err != nil {
		return fmt.Errorf("active window: %w", err)
	}
	suspicionWindow, err := parseDurationOrDefault(s.SuspicionWindow, cur.SuspicionWindow)
	if err != nil {
		return fmt.Errorf("suspicion window: %w", err)
	}

	if shortLived >= longLived {
		return fmt.Errorf("short lived outbound max age must be less than long lived outbound min age")
	}
	if activeWindow > suspicionWindow {
		return fmt.Errorf("active window must be less than or equal to suspicion window")
	}
	if reverseControl > suspicionWindow {
		return fmt.Errorf("reverse control min duration must be less than or equal to suspicion window")
	}
	return nil
}

func Execute(input RunInput) (RunResult, error) {
	return ExecuteContext(context.Background(), input)
}

func ExecuteContext(ctx context.Context, input RunInput) (RunResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	provider := normalizeProvider(input.Provider)
	model := strings.TrimSpace(input.Model)
	if model == "" {
		model = DefaultModel(provider)
	}
	scope := strings.TrimSpace(input.Scope)
	if scope == "" {
		scope = "recommended"
	}
	if input.Duration <= 0 {
		return RunResult{}, fmt.Errorf("duration must be greater than 0")
	}

	access := DetectProviderAccess()
	if ready, reason := ProviderReady(provider, access); !ready {
		return RunResult{}, fmt.Errorf("provider unavailable: %s", reason)
	}

	outputPath := normalizeOutputPath(input.Output)
	now := time.Now().UTC()
	runID := fmt.Sprintf("%s-%06d", now.Format("20060102-150405"), now.UnixNano()%1_000_000)
	scopedSamples := filterSamplesByScope(input.Samples, scope)
	scopedSamples, contourHintsApplied := applyContourHints(scopedSamples, input.ContourHints)
	uniqueSamples, roleCounts, stateCounts, topProcesses := analyzeSamples(scopedSamples)
	current := CurrentSettings()
	learningModel, learningErr := loadLearningModel()
	if learningErr != nil {
		learningModel = defaultLearningModel()
	}
	learningCtx := buildLearningContext(learningModel)
	learningNotes := make([]string, 0, 4)
	if learningErr != nil {
		learningNotes = append(learningNotes, "Learning model load failed: "+trimCalibrationError(learningErr.Error(), 220))
	}

	analysisMode := "ai"
	analysisError := ""
	aiResult, err := calibrateWithAI(ctx, provider, model, scope, input.Duration, current, uniqueSamples, roleCounts, stateCounts, topProcesses, learningCtx)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return RunResult{}, context.Canceled
		}
		analysisMode = "fallback"
		analysisError = trimCalibrationError(err.Error(), 320)
		tuned, recs, summary := recommendTuning(current, roleCounts, stateCounts, len(uniqueSamples), input.Duration, learningCtx)
		recs = append(recs, "AI analysis was unavailable for this run; heuristic fallback recommendations were generated from collected telemetry.")
		aiResult = aiCalibrationResult{
			Summary:         summary,
			Recommendations: recs,
			Risks: []string{
				"AI calibration request failed and fallback mode was used.",
			},
			Reasoning: []string{
				"Collected telemetry was still analyzed to produce conservative recommendations.",
				"AI provider error: " + analysisError,
			},
			Settings: tuned,
		}
	}
	tuned := aiResult.Settings
	recommendations := sanitizeRecommendations(aiResult.Recommendations)
	risks := sanitizeRecommendations(aiResult.Risks)
	reasoning := sanitizeRecommendations(aiResult.Reasoning)
	summary := strings.TrimSpace(aiResult.Summary)
	if summary == "" {
		if analysisMode == "ai" {
			summary = fmt.Sprintf(
				"AI calibration analyzed %d unique processes in %s (session=%d beacon=%d tunnel=%d outbound=%d).",
				len(uniqueSamples),
				input.Duration.Round(time.Second),
				roleCounts["session"],
				roleCounts["beacon"],
				roleCounts["tunnel"],
				roleCounts["outbound"],
			)
		} else {
			summary = fmt.Sprintf(
				"Fallback calibration analyzed %d unique processes in %s (session=%d beacon=%d tunnel=%d outbound=%d).",
				len(uniqueSamples),
				input.Duration.Round(time.Second),
				roleCounts["session"],
				roleCounts["beacon"],
				roleCounts["tunnel"],
				roleCounts["outbound"],
			)
		}
	}

	profileName := fmt.Sprintf("profile-%s-%s.json", sanitizeName(provider), runID)
	recommendationSource := "proxywatch-learning:" + provider
	if analysisMode != "ai" {
		recommendationSource = "proxywatch-learning:fallback"
	}
	report := Report{
		ID:                   runID,
		GeneratedAt:          now,
		Provider:             provider,
		Model:                model,
		Scope:                scope,
		Duration:             input.Duration.String(),
		AnalysisMode:         analysisMode,
		AnalysisError:        analysisError,
		CandidateCount:       len(uniqueSamples),
		RoleCounts:           roleCounts,
		StateCounts:          stateCounts,
		TopProcesses:         topProcesses,
		Summary:              summary,
		Recommendations:      recommendations,
		Risks:                risks,
		Reasoning:            reasoning,
		Settings:             tuned,
		ProfileName:          profileName,
		OutputPath:           outputPath,
		RecommendationSource: recommendationSource,
		ContourHintsApplied:  contourHintsApplied,
	}

	learningModel = updateLearningModel(learningModel, scopedSamples, now)
	if err := saveLearningModel(learningModel); err != nil {
		learningNotes = append(learningNotes, "Learning model save failed: "+trimCalibrationError(err.Error(), 220))
	}
	learningAfter := buildLearningContext(learningModel)
	report.LearningModelPath = learningAfter.ModelPath
	report.LearningRuns = learningAfter.Runs
	report.LearningSamples = learningAfter.WeightedSamples
	report.LearningContamination = learningAfter.ContaminationPct
	report.LearningTopNormal = limitStrings(learningAfter.TopNormalProcesses, 6)
	report.LearningNotes = limitStrings(append(learningAfter.Notes, learningNotes...), 6)
	if err := ctx.Err(); err != nil {
		return RunResult{}, err
	}

	if err := BuildReportArtifacts(&report, current, uniqueSamples, input.SampleEvery); err != nil {
		return RunResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return RunResult{}, err
	}
	if err := writeJSONFile(outputPath, report); err != nil {
		return RunResult{}, err
	}

	profile := Profile{
		Name:            profileName,
		CreatedAt:       now,
		Provider:        provider,
		Model:           model,
		Scope:           scope,
		SourceReport:    outputPath,
		CandidateCount:  len(uniqueSamples),
		RoleCounts:      roleCounts,
		StateCounts:     stateCounts,
		Recommendations: recommendations,
		Settings:        tuned,
	}
	profilePath := filepath.Join(profilesPath(), profileName)
	if err := ctx.Err(); err != nil {
		return RunResult{}, err
	}
	if err := writeJSONFile(profilePath, profile); err != nil {
		return RunResult{}, err
	}

	return RunResult{
		Report:      report,
		ReportPath:  outputPath,
		Profile:     profile,
		ProfilePath: profilePath,
	}, nil
}

func ListProfiles() ([]string, error) {
	entries, err := os.ReadDir(profilesPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	type profileFile struct {
		name    string
		modTime time.Time
	}
	files := make([]profileFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.TrimSpace(entry.Name())
		if !strings.HasSuffix(strings.ToLower(name), ".json") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, profileFile{name: name, modTime: info.ModTime()})
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].modTime.After(files[j].modTime)
	})
	out := make([]string, 0, len(files))
	for _, file := range files {
		out = append(out, file.name)
	}
	return out, nil
}

func ListReports() ([]string, error) {
	root := calibrationRoot()
	if _, err := os.Stat(root); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	type reportFile struct {
		path    string
		modTime time.Time
	}

	seen := make(map[string]reportFile)
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info == nil {
			return nil
		}
		if info.IsDir() {
			name := strings.ToLower(strings.TrimSpace(info.Name()))
			switch name {
			case "profiles", "training", "siem":
				return filepath.SkipDir
			default:
				return nil
			}
		}
		name := strings.ToLower(strings.TrimSpace(info.Name()))
		if !strings.HasSuffix(name, ".json") {
			return nil
		}
		if name == "tuning.json" {
			return nil
		}
		if _, err := LoadReport(path); err != nil {
			return nil
		}
		normalized := filepath.Clean(path)
		if existing, ok := seen[normalized]; ok {
			if info.ModTime().After(existing.modTime) {
				seen[normalized] = reportFile{path: normalized, modTime: info.ModTime()}
			}
			return nil
		}
		seen[normalized] = reportFile{path: normalized, modTime: info.ModTime()}
		return nil
	})
	if err != nil {
		return nil, err
	}

	files := make([]reportFile, 0, len(seen))
	for _, item := range seen {
		files = append(files, item)
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].modTime.After(files[j].modTime)
	})

	out := make([]string, 0, len(files))
	for _, file := range files {
		out = append(out, file.path)
	}
	return out, nil
}

func LoadProfile(name string) (Profile, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Profile{}, fmt.Errorf("profile name is required")
	}
	if filepath.Base(name) != name {
		return Profile{}, fmt.Errorf("profile name must not include directories")
	}
	path := filepath.Join(profilesPath(), name)
	data, err := safeio.ReadFile(path)
	if err != nil {
		return Profile{}, err
	}
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return Profile{}, err
	}
	if strings.TrimSpace(p.Name) == "" {
		p.Name = name
	}
	return p, nil
}

func ApplyProfile(name string) (Profile, error) {
	profile, err := LoadProfile(name)
	if err != nil {
		return Profile{}, err
	}
	if err := profile.Settings.Apply(); err != nil {
		return Profile{}, err
	}
	cfg := ActiveConfig{
		Profile:   profile.Name,
		AppliedAt: time.Now().UTC(),
		Provider:  profile.Provider,
		Model:     profile.Model,
		Scope:     profile.Scope,
		Settings:  profile.Settings,
	}
	if err := writeJSONFile(activeConfigPath(), cfg); err != nil {
		return Profile{}, err
	}
	_ = MarkReportApplied(profile.SourceReport)
	return profile, nil
}

func LoadActiveConfig() (ActiveConfig, error) {
	path := activeConfigPath()
	data, err := safeio.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ActiveConfig{}, nil
		}
		return ActiveConfig{}, err
	}
	var cfg ActiveConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return ActiveConfig{}, err
	}
	return cfg, nil
}

func LoadAndApplyActiveProfile() (ActiveConfig, error) {
	cfg, err := LoadActiveConfig()
	if err != nil {
		return ActiveConfig{}, err
	}
	if strings.TrimSpace(cfg.Profile) == "" {
		return cfg, nil
	}
	if err := cfg.Settings.Apply(); err != nil {
		return ActiveConfig{}, err
	}
	return cfg, nil
}

func LoadReport(path string) (Report, error) {
	normalized := normalizeOutputPath(path)
	data, err := safeio.ReadFile(normalized)
	if err != nil {
		return Report{}, err
	}
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		return Report{}, err
	}
	if strings.TrimSpace(report.OutputPath) == "" {
		report.OutputPath = normalized
	}
	if strings.TrimSpace(report.SampleEvery) == "" {
		report.SampleEvery = DefaultSampleEvery().String()
	}
	if strings.TrimSpace(report.DatasetPath) == "" && strings.TrimSpace(report.OutputPath) != "" {
		report.DatasetPath = DatasetPathForReport(report.OutputPath)
	}
	if report.Confidence <= 0 {
		report.Confidence = deriveReportConfidence(report)
	}
	if strings.TrimSpace(report.RecommendationSource) == "" {
		report.RecommendationSource = "proxywatch-learning:" + normalizeProvider(report.Provider)
	}
	report.ReportLines = RenderReportLines(report)
	return report, nil
}

func activeConfigPath() string {
	return filepath.Join(calibrationRoot(), "tuning.json")
}

func profilesPath() string {
	return filepath.Join(calibrationRoot(), "profiles")
}

func calibrationRoot() string {
	return expandHomePath(defaultCalibrationDir)
}

func writeJSONFile(path string, value any) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("path is required")
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func normalizeOutputPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		path = defaultOutputPath
	}
	path = expandHomePath(path)
	if filepath.IsAbs(path) {
		path = filepath.Clean(path)
	} else {
		rel := sanitizeRelativeOutputPath(path, "latest.json")
		path = filepath.Join(calibrationRoot(), rel)
	}
	if !strings.HasSuffix(strings.ToLower(path), ".json") {
		path += ".json"
	}
	return path
}

func sanitizeRelativeOutputPath(path, fallback string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return fallback
	}
	path = filepath.Clean(path)
	if path == "." || path == "" {
		return fallback
	}
	for strings.HasPrefix(path, "."+string(filepath.Separator)) {
		path = strings.TrimPrefix(path, "."+string(filepath.Separator))
	}
	path = strings.TrimLeft(path, string(filepath.Separator))
	parentPrefix := ".." + string(filepath.Separator)
	for path == ".." || strings.HasPrefix(path, parentPrefix) {
		if path == ".." {
			return fallback
		}
		path = strings.TrimPrefix(path, parentPrefix)
	}
	if path == "" || path == "." {
		return fallback
	}
	return path
}

func analyzeSamples(samples []shared.Candidate) ([]shared.Candidate, map[string]int, map[string]int, []ProcessSummary) {
	latest := make(map[string]shared.Candidate)
	for _, sample := range samples {
		if sample.Proc == nil {
			continue
		}
		key := shared.CandidateKey(sample)
		existing, ok := latest[key]
		if !ok {
			latest[key] = sample
			continue
		}
		merged := existing
		if sample.ControlDurationSeconds > merged.ControlDurationSeconds {
			merged = sample
		}
		merged.ActiveProxying = merged.ActiveProxying || sample.ActiveProxying
		merged.StrongEvidence = merged.StrongEvidence || sample.StrongEvidence
		latest[key] = merged
	}

	unique := make([]shared.Candidate, 0, len(latest))
	for _, sample := range latest {
		unique = append(unique, sample)
	}
	sort.SliceStable(unique, func(i, j int) bool {
		return shared.CandidateLess(unique[i], unique[j])
	})

	roleCounts := map[string]int{
		"session":  0,
		"beacon":   0,
		"tunnel":   0,
		"outbound": 0,
		"listener": 0,
		"other":    0,
	}
	stateCounts := map[string]int{
		"watch":  0,
		"strong": 0,
		"active": 0,
	}

	top := make([]ProcessSummary, 0, minInt(6, len(unique)))
	for i, sample := range unique {
		family := shared.RoleFamily(sample.Role)
		roleCounts[family]++
		state := "watch"
		if sample.ActiveProxying {
			state = "active"
		} else if sample.StrongEvidence {
			state = "strong"
		}
		stateCounts[state]++

		if i >= cap(top) {
			continue
		}
		pid := 0
		name := "(unknown)"
		if sample.Proc != nil {
			pid = sample.Proc.Pid
			name = sample.Proc.Name
		}
		age := "0s"
		if sample.ControlDurationSeconds > 0 {
			age = (time.Duration(sample.ControlDurationSeconds) * time.Second).Round(time.Second).String()
		}
		top = append(top, ProcessSummary{
			Host:    shared.DisplayHost(sample.Host),
			PID:     pid,
			Process: name,
			Role:    family,
			Age:     age,
			State:   state,
		})
	}

	return unique, roleCounts, stateCounts, top
}

func applyContourHints(samples []shared.Candidate, hints []shared.ContourHint) ([]shared.Candidate, int) {
	if len(samples) == 0 || len(hints) == 0 {
		return samples, 0
	}
	hintsByKey := make(map[string][]shared.ContourHint, len(hints))
	hintsByHostPID := make(map[string][]shared.ContourHint, len(hints))
	for _, hint := range hints {
		if key := strings.TrimSpace(hint.CandidateKey); key != "" {
			hintsByKey[key] = append(hintsByKey[key], hint)
		}
		host := strings.TrimSpace(hint.Host)
		if host != "" && hint.PID > 0 {
			hostPID := strings.ToLower(host) + "|" + fmt.Sprintf("%d", hint.PID)
			hintsByHostPID[hostPID] = append(hintsByHostPID[hostPID], hint)
		}
	}
	if len(hintsByKey) == 0 && len(hintsByHostPID) == 0 {
		return samples, 0
	}

	out := make([]shared.Candidate, len(samples))
	applied := 0
	appliedSeen := make(map[string]struct{}, len(hints))
	for i := range samples {
		sample := samples[i]
		sampleKey := strings.TrimSpace(shared.CandidateKey(sample))
		merged := make([]shared.ContourHint, 0, 4)
		if sampleKey != "" {
			key := sampleKey
			merged = append(merged, hintsByKey[key]...)
		}
		if sample.Proc != nil {
			hostPID := strings.ToLower(shared.DisplayHost(sample.Host)) + "|" + fmt.Sprintf("%d", sample.Proc.Pid)
			if extra := hintsByHostPID[hostPID]; len(extra) > 0 {
				merged = append(merged, extra...)
			}
		}
		if len(merged) == 0 {
			out[i] = sample
			continue
		}

		for _, hint := range merged {
			if sig := strings.TrimSpace(hint.Signal); sig != "" {
				sample.Signals = appendUniqueString(sample.Signals, sig)
				applyKey := sampleKey + "|" + sig
				if _, ok := appliedSeen[applyKey]; !ok {
					appliedSeen[applyKey] = struct{}{}
					applied++
				}
			}
			reason := strings.TrimSpace(hint.Reason)
			if reason == "" && strings.TrimSpace(hint.Signal) != "" {
				reason = "Contour: " + strings.TrimSpace(hint.Signal)
			} else if reason != "" {
				reason = "Contour: " + reason
			}
			if reason != "" {
				sample.Reasons = appendUniqueString(sample.Reasons, reason)
			}
			switch shared.NormalizeContourSeverity(hint.Severity) {
			case "active":
				sample.ActiveProxying = true
				sample.StrongEvidence = true
			case "strong":
				sample.StrongEvidence = true
			}
		}
		out[i] = sample
	}
	return out, applied
}

func appendUniqueString(items []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return items
	}
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item), value) {
			return items
		}
	}
	return append(items, value)
}

func recommendTuning(current TuningSettings, roles, states map[string]int, total int, duration time.Duration, learning LearningContext) (TuningSettings, []string, string) {
	tuned := current
	recommendations := make([]string, 0, 4)

	if total == 0 {
		summary := fmt.Sprintf("No eligible samples were captured in %s.", duration.Round(time.Second))
		recommendations = append(recommendations, "Run calibration for at least 1m to collect enough behavior.")
		if learning.Runs > 0 {
			recommendations = append(recommendations, fmt.Sprintf("Historical baseline exists (%d runs, %d%% contamination estimate); retaining conservative defaults.", learning.Runs, learning.ContaminationPct))
		}
		return tuned, recommendations, summary
	}

	suspicious := roles["session"] + roles["beacon"] + roles["tunnel"]
	outbound := roles["outbound"]
	ratio := float64(suspicious) / float64(maxInt(total, 1))
	baselineSusp := learning.SuspiciousRatio

	if ratio < 0.20 && outbound >= suspicious {
		tuned.ReverseControlMinDuration = adjustDuration(tuned.ReverseControlMinDuration, 5*time.Second, 5*time.Second, 5*time.Minute)
		tuned.LongLivedOutboundMinAge = adjustDuration(tuned.LongLivedOutboundMinAge, 20*time.Second, 20*time.Second, 15*time.Minute)
		tuned.BeaconSleepThreshold = adjustDuration(tuned.BeaconSleepThreshold, 15*time.Second, 20*time.Second, 15*time.Minute)
		tuned.OutboundOnlyExternalCap = clampInt(tuned.OutboundOnlyExternalCap+10, 10, 500)
		tuned.ShapeDeltaThreshold = clampFloat(tuned.ShapeDeltaThreshold+0.02, 0.05, 1.5)
		tuned.BeaconJitterCoVMax = clampFloat(tuned.BeaconJitterCoVMax+0.10, 0.2, 5.0)
		recommendations = append(recommendations, "Environment appears outbound-heavy; raise outbound/control timing thresholds to reduce noisy promotion.")
	}

	if ratio > 0.45 || roles["tunnel"] >= 3 {
		tuned.ReverseControlMinDuration = adjustDuration(tuned.ReverseControlMinDuration, -3*time.Second, 5*time.Second, 5*time.Minute)
		tuned.LongLivedOutboundMinAge = adjustDuration(tuned.LongLivedOutboundMinAge, -15*time.Second, 20*time.Second, 15*time.Minute)
		tuned.BeaconSleepThreshold = adjustDuration(tuned.BeaconSleepThreshold, -10*time.Second, 20*time.Second, 15*time.Minute)
		tuned.BeaconMinIntervals = maxInt(1, tuned.BeaconMinIntervals-1)
		tuned.ShapeDeltaThreshold = clampFloat(tuned.ShapeDeltaThreshold-0.02, 0.05, 1.5)
		tuned.BeaconJitterCoVMax = clampFloat(tuned.BeaconJitterCoVMax-0.10, 0.2, 5.0)
		recommendations = append(recommendations, "Suspicious role density is high; tighten timing thresholds so control/tunnel traits are surfaced earlier.")
	}

	if learning.Runs >= 2 {
		switch {
		case ratio > baselineSusp+0.15:
			tuned.ReverseControlMinDuration = adjustDuration(tuned.ReverseControlMinDuration, -2*time.Second, 5*time.Second, 5*time.Minute)
			tuned.ShapeDeltaThreshold = clampFloat(tuned.ShapeDeltaThreshold-0.01, 0.05, 1.5)
			recommendations = append(recommendations, fmt.Sprintf("Current suspicious mix (%.0f%%) is above learned baseline (%.0f%%); slightly tightening control thresholds.", ratio*100, baselineSusp*100))
		case ratio+0.20 < baselineSusp && learning.ContaminationPct >= 35:
			recommendations = append(recommendations, fmt.Sprintf("Learned baseline indicates elevated contamination (%d%%); avoiding aggressive loosening despite low current suspicious mix.", learning.ContaminationPct))
		case ratio+0.15 < baselineSusp:
			tuned.ReverseControlMinDuration = adjustDuration(tuned.ReverseControlMinDuration, 2*time.Second, 5*time.Second, 5*time.Minute)
			tuned.OutboundOnlyExternalCap = clampInt(tuned.OutboundOnlyExternalCap+4, 10, 500)
			recommendations = append(recommendations, fmt.Sprintf("Current suspicious mix (%.0f%%) is below learned baseline (%.0f%%); slightly relaxing to reduce false positives.", ratio*100, baselineSusp*100))
		}
	}

	if states["active"] > 0 {
		recommendations = append(recommendations, "Active proxy behavior observed; keep reverse sticky score elevated to preserve operator visibility.")
		tuned.ReverseStickyScore = clampInt(tuned.ReverseStickyScore+5, 10, 250)
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Observed behavior was balanced; keep baseline tuning and monitor with periodic recalibration.")
	}

	summary := fmt.Sprintf(
		"Observed %d unique processes in %s (session=%d beacon=%d tunnel=%d outbound=%d).",
		total,
		duration.Round(time.Second),
		roles["session"],
		roles["beacon"],
		roles["tunnel"],
		roles["outbound"],
	)
	return tuned, recommendations, summary
}
