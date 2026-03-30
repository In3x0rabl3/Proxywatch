package calibration

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"proxywatch/internal/safeio"
	"proxywatch/internal/shared"
)

const defaultCalibrationSampleEvery = 15 * time.Second

type CalibrationMemory struct {
	ValidatedCalibrations int    `json:"validated_calibrations"`
	TrainingDataset       string `json:"training_dataset"`
}

type CalibrationValidation struct {
	SampleCount            int      `json:"sample_count"`
	PositiveSamples        int      `json:"positive_samples"`
	NegativeSamples        int      `json:"negative_samples"`
	BaselineScore          int      `json:"baseline_score"`
	TunedScore             int      `json:"tuned_score"`
	ScoreDelta             int      `json:"score_delta"`
	BaselinePrecisionPct   int      `json:"baseline_precision_pct"`
	TunedPrecisionPct      int      `json:"tuned_precision_pct"`
	BaselineRecallPct      int      `json:"baseline_recall_pct"`
	TunedRecallPct         int      `json:"tuned_recall_pct"`
	BaselineFalsePositives int      `json:"baseline_false_positives"`
	TunedFalsePositives    int      `json:"tuned_false_positives"`
	BaselineFalseNegatives int      `json:"baseline_false_negatives"`
	TunedFalseNegatives    int      `json:"tuned_false_negatives"`
	Improved               bool     `json:"improved"`
	ChangedProcesses       []string `json:"changed_processes,omitempty"`
	Notes                  []string `json:"notes,omitempty"`
}

type SimilarCalibration struct {
	Similarity     int       `json:"similarity"`
	Report         string    `json:"report"`
	Roles          string    `json:"roles"`
	Provider       string    `json:"provider"`
	Confidence     int       `json:"confidence"`
	Outcome        string    `json:"outcome"`
	Applied        bool      `json:"applied"`
	Summary        string    `json:"summary,omitempty"`
	GeneratedAt    time.Time `json:"generated_at,omitempty"`
	EnvFingerprint string    `json:"env_fingerprint,omitempty"`
}

type calibrationMemoryRecord struct {
	ReportPath     string         `json:"report_path"`
	GeneratedAt    time.Time      `json:"generated_at"`
	Provider       string         `json:"provider"`
	Model          string         `json:"model"`
	Scope          string         `json:"scope"`
	CandidateCount int            `json:"candidate_count"`
	RoleCounts     map[string]int `json:"role_counts"`
	StateCounts    map[string]int `json:"state_counts"`
	Confidence     int            `json:"confidence"`
	Applied        bool           `json:"applied"`
	Outcome        string         `json:"outcome"`
	OutcomeScore   int            `json:"outcome_score"`
	Summary        string         `json:"summary"`
	EnvFingerprint string         `json:"env_fingerprint,omitempty"`
}

type calibrationDatasetRow struct {
	Timestamp time.Time `json:"timestamp"`
	Host      string    `json:"host"`
	PID       int       `json:"pid"`
	Process   string    `json:"process"`
	Role      string    `json:"role"`
	State     string    `json:"state"`
	AgeSec    int       `json:"age_sec"`
	Inbound   int       `json:"inbound"`
	Outbound  int       `json:"outbound"`
	Reasons   []string  `json:"reasons,omitempty"`
	Signals   []string  `json:"signals,omitempty"`
}

func DefaultSampleEvery() time.Duration {
	return defaultCalibrationSampleEvery
}

func SuggestedSampleEvery(duration time.Duration) time.Duration {
	if duration <= 0 {
		return DefaultSampleEvery()
	}
	switch {
	case duration <= 15*time.Second:
		return 1 * time.Second
	case duration <= 45*time.Second:
		return 2 * time.Second
	case duration <= 2*time.Minute:
		return 5 * time.Second
	case duration <= 10*time.Minute:
		return 10 * time.Second
	default:
		return DefaultSampleEvery()
	}
}

func NewRunOutputPath() string {
	now := time.Now().UTC()
	dayDir := filepath.Join(calibrationRoot(), now.Format("20060102"))
	file := fmt.Sprintf(
		"proxywatch-calibration-%s-%06d.json",
		now.Format("20060102-150405"),
		now.UnixNano()%1_000_000,
	)
	return filepath.Join(dayDir, file)
}

func DatasetPathForReport(outputPath string) string {
	path := normalizeOutputPath(outputPath)
	base := strings.TrimSuffix(path, filepath.Ext(path))
	return base + ".dataset.jsonl"
}

func BuildReportArtifacts(report *Report, previous TuningSettings, samples []shared.Candidate, sampleEvery time.Duration) error {
	if report == nil {
		return fmt.Errorf("report is nil")
	}
	if sampleEvery <= 0 {
		sampleEvery = DefaultSampleEvery()
	}
	report.OutputPath = normalizeOutputPath(report.OutputPath)
	report.SampleEvery = sampleEvery.Round(time.Second).String()
	if strings.TrimSpace(report.RecommendationSource) == "" {
		report.RecommendationSource = "proxywatch-learning:" + normalizeProvider(report.Provider)
	}
	if report.Confidence <= 0 {
		report.Confidence = deriveReportConfidence(*report)
	}
	report.DatasetPath = DatasetPathForReport(report.OutputPath)
	if err := writeCalibrationDataset(report.DatasetPath, samples); err != nil {
		return err
	}

	report.RecommendedSettings = summarizeSettingDiff(previous, report.Settings)
	report.Validation = evaluateCalibrationValidation(previous, report.Settings, samples)
	if len(report.Risks) == 0 {
		report.Risks = defaultRiskNotes(*report)
	}
	if len(report.Reasoning) == 0 {
		report.Reasoning = defaultReasoningNotes(*report)
	}

	records, err := loadCalibrationMemory()
	if err != nil {
		return err
	}
	report.SimilarPast = buildSimilarPast(*report, records, 6)

	updated := upsertCalibrationRecord(records, calibrationMemoryRecord{
		ReportPath:     report.OutputPath,
		GeneratedAt:    report.GeneratedAt,
		Provider:       normalizeProvider(report.Provider),
		Model:          strings.TrimSpace(report.Model),
		Scope:          strings.TrimSpace(report.Scope),
		CandidateCount: report.CandidateCount,
		RoleCounts:     cloneIntMap(report.RoleCounts),
		StateCounts:    cloneIntMap(report.StateCounts),
		Confidence:     report.Confidence,
		Applied:        false,
		Outcome:        "n/a",
		OutcomeScore:   0,
		Summary:        strings.TrimSpace(report.Summary),
		EnvFingerprint: report.EnvFingerprint,
	})
	if err := saveCalibrationMemory(updated); err != nil {
		return err
	}

	report.Memory = CalibrationMemory{
		ValidatedCalibrations: len(updated),
		TrainingDataset:       calibrationTrainingDatasetPath(),
	}
	report.ReportLines = RenderReportLines(*report)
	return nil
}

func MarkReportApplied(reportPath string) error {
	if strings.TrimSpace(reportPath) == "" {
		return nil
	}
	path := normalizeOutputPath(reportPath)
	records, err := loadCalibrationMemory()
	if err != nil {
		return err
	}
	changed := false
	for i := range records {
		if normalizeOutputPath(records[i].ReportPath) != path {
			continue
		}
		if !records[i].Applied {
			records[i].Applied = true
			if strings.TrimSpace(records[i].Outcome) == "" || strings.EqualFold(strings.TrimSpace(records[i].Outcome), "n/a") {
				records[i].Outcome = "observed"
			}
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return saveCalibrationMemory(records)
}

func RenderReportLines(report Report) []string {
	lines := make([]string, 0, 60)
	summary := strings.TrimSpace(report.Summary)
	if summary == "" {
		summary = "No summary returned from calibration analysis."
	}

	// ── Summary ─────────────────────────────────────────────
	conf := clampInt(report.Confidence, 0, 100)
	confLevel := "low"
	if conf >= 70 {
		confLevel = "high"
	} else if conf >= 45 {
		confLevel = "moderate"
	}
	lines = append(lines, fmt.Sprintf("Confidence: %d (%s)", conf, confLevel))
	if e := strings.TrimSpace(report.AnalysisError); e != "" {
		lines = append(lines, "  [FAIL] "+e)
	}

	// ── Tuning + Validation ─────────────────────────────────
	lines = append(lines, "")
	lines = append(lines, "Tuning")
	if len(report.RecommendedSettings) == 0 {
		lines = append(lines, "  No changes recommended.")
	} else {
		for _, item := range report.RecommendedSettings {
			lines = append(lines, "  "+item)
		}
	}
	if report.Validation.SampleCount > 0 {
		v := report.Validation
		verdict := "unchanged"
		if v.ScoreDelta > 0 {
			verdict = "improved"
		} else if v.ScoreDelta < 0 {
			verdict = "regressed"
		}
		lines = append(lines, fmt.Sprintf("  Quality: %d -> %d (%+d, %s)  |  Precision: %d%% -> %d%%  |  Recall: %d%% -> %d%%",
			v.BaselineScore, v.TunedScore, v.ScoreDelta, verdict,
			v.BaselinePrecisionPct, v.TunedPrecisionPct, v.BaselineRecallPct, v.TunedRecallPct))
		fpD := v.TunedFalsePositives - v.BaselineFalsePositives
		fnD := v.TunedFalseNegatives - v.BaselineFalseNegatives
		lines = append(lines, fmt.Sprintf("  FP: %d -> %d (%+d)  |  FN: %d -> %d (%+d)  |  %d samples",
			v.BaselineFalsePositives, v.TunedFalsePositives, fpD,
			v.BaselineFalseNegatives, v.TunedFalseNegatives, fnD, v.SampleCount))
		if len(v.ChangedProcesses) > 0 {
			lines = append(lines, "  Changed: "+strings.Join(v.ChangedProcesses, ", "))
		}
	}

	// ── Recommendations + Risks ─────────────────────────────
	if len(report.Recommendations) > 0 || len(report.Risks) > 0 {
		lines = append(lines, "")
		lines = append(lines, "Recommendations")
		for _, rec := range report.Recommendations {
			lines = append(lines, wrapText("  - "+rec, 78, "    ")...)
		}
		for _, risk := range report.Risks {
			lines = append(lines, wrapText("  - [RISK] "+risk, 78, "    ")...)
		}
	}

	// ── Learning ────────────────────────────────────────────
	if report.LearningRuns > 0 || len(report.LearningTopNormal) > 0 {
		contamDesc := "clean"
		if report.LearningContamination >= 35 {
			contamDesc = "critical"
		} else if report.LearningContamination >= 20 {
			contamDesc = "elevated"
		} else if report.LearningContamination >= 5 {
			contamDesc = "low"
		}
		lines = append(lines, "")
		lines = append(lines, "Learning")
		lines = append(lines, fmt.Sprintf("  Runs: %d  |  Samples: %.0f  |  Contamination: %d%% (%s)",
			report.LearningRuns, report.LearningSamples, report.LearningContamination, contamDesc))
		if len(report.LearningTopNormal) > 0 {
			lines = append(lines, "  Baseline: "+compactReportList(report.LearningTopNormal, 5))
		}
		// Compare environment fingerprint with most recent similar past run.
		if report.EnvFingerprint != "" && len(report.SimilarPast) > 0 {
			envChanged := false
			for _, sim := range report.SimilarPast {
				if sim.EnvFingerprint != "" && sim.EnvFingerprint != report.EnvFingerprint {
					envChanged = true
					break
				}
			}
			if envChanged {
				lines = append(lines, "  Environment: changed since last calibration (new processes detected)")
			}
		}
		// Contamination recovery guidance: show likely contaminating processes.
		if report.LearningContamination >= 20 && len(report.TopProcesses) > 0 {
			suspRoles := map[string]bool{"session": true, "beacon": true, "tunnel": true, "smb-pipe": true}
			contam := make([]string, 0, 5)
			for _, p := range report.TopProcesses {
				if suspRoles[p.Role] {
					contam = append(contam, fmt.Sprintf("%s (%s)", p.Process, p.Role))
				}
				if len(contam) >= 5 {
					break
				}
			}
			if len(contam) > 0 {
				lines = append(lines, "  Contaminating: "+strings.Join(contam, ", "))
				lines = append(lines, "  Suggestion: whitelist these or recalibrate in a clean environment")
			}
		}
	}

	// ── Similar Past ────────────────────────────────────────
	if len(report.SimilarPast) > 0 {
		lines = append(lines, "")
		lines = append(lines, "History")
		maxSimilar := min(3, len(report.SimilarPast))
		for i := 0; i < maxSimilar; i++ {
			sim := report.SimilarPast[i]
			state := "not applied"
			if sim.Applied {
				state = "applied"
			}
			ts := ""
			if !sim.GeneratedAt.IsZero() {
				ts = sim.GeneratedAt.UTC().Format("2006-01-02 15:04")
			}
			lines = append(lines, fmt.Sprintf("  %d%% match  |  %s  |  confidence %d  |  %s", sim.Similarity, state, sim.Confidence, ts))
		}
	}

	// ── Reasoning (wrapped) ─────────────────────────────────
	if len(report.Reasoning) > 0 {
		lines = append(lines, "")
		lines = append(lines, "Reasoning")
		for _, reason := range report.Reasoning {
			wrapped := wrapText("  - "+reason, 78, "    ")
			lines = append(lines, wrapped...)
		}
	}

	return lines
}


func compactReportList(items []string, limit int) string {
	if limit <= 0 {
		limit = len(items)
	}
	out := make([]string, 0, limit)
	total := 0
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		total++
		if len(out) < limit {
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return "(none)"
	}
	joined := strings.Join(out, ", ")
	if total > len(out) {
		return fmt.Sprintf("%s (+%d more)", joined, total-len(out))
	}
	return joined
}

func wrapText(text string, maxWidth int, indent string) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}
	var lines []string
	line := words[0]
	for _, w := range words[1:] {
		if len(line)+1+len(w) > maxWidth {
			lines = append(lines, line)
			line = indent + w
		} else {
			line += " " + w
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

func deriveReportConfidence(report Report) int {
	score := 52
	if report.CandidateCount >= 3 {
		score += 6
	}
	if report.CandidateCount >= 8 {
		score += 6
	}
	if report.CandidateCount >= 15 {
		score += 6
	}
	susp := report.RoleCounts["session"] + report.RoleCounts["beacon"] + report.RoleCounts["tunnel"]
	score += minInt(14, susp*2)
	if report.StateCounts["strong"]+report.StateCounts["active"] > 0 {
		score += 6
	}
	if len(report.Recommendations) > 0 {
		score += 4
	}
	return clampInt(score, 35, 92)
}

func summarizeSettingDiff(before, after TuningSettings) []string {
	out := make([]string, 0, 8)
	addIntDiff := func(label string, a, b int) {
		if a != b {
			out = append(out, fmt.Sprintf("%s: %d -> %d", label, a, b))
		}
	}
	addFloatDiff := func(label string, a, b float64) {
		if math.Abs(a-b) > 0.0001 {
			out = append(out, fmt.Sprintf("%s: %.2f -> %.2f", label, a, b))
		}
	}
	addIntDiff("Reverse control base", before.ReverseControlBaseScore, after.ReverseControlBaseScore)
	addIntDiff("Outbound external cap", before.OutboundOnlyExternalCap, after.OutboundOnlyExternalCap)
	addIntDiff("Traffic verified penalty", before.TrafficVerifiedPenalty, after.TrafficVerifiedPenalty)
	addIntDiff("Verified external prefixes", before.VerifiedExternalPrefixes, after.VerifiedExternalPrefixes)
	addFloatDiff("Shape delta threshold", before.ShapeDeltaThreshold, after.ShapeDeltaThreshold)
	addFloatDiff("Beacon jitter CoV max", before.BeaconJitterCoVMax, after.BeaconJitterCoVMax)
	if len(out) > 8 {
		out = out[:8]
	}
	return out
}

func defaultRiskNotes(report Report) []string {
	risks := make([]string, 0, 3)
	if report.RoleCounts["listen"]+report.RoleCounts["outbound"] >= report.RoleCounts["session"]+report.RoleCounts["beacon"]+report.RoleCounts["tunnel"] {
		risks = append(risks, "Potential sensitivity to legitimate periodic health checks with stable timing; mitigated by conservative magnitude of changes.")
	}
	if len(report.RecommendedSettings) > 0 {
		risks = append(risks, "Small threshold shifts can increase benign alerts in developer-heavy traffic bursts.")
	}
	if len(risks) == 0 {
		risks = append(risks, "No major risk patterns were inferred from the current baseline.")
	}
	return risks
}

func defaultReasoningNotes(report Report) []string {
	out := make([]string, 0, 4)
	out = append(out, fmt.Sprintf("Baseline captured %d unique process candidates over %s.", report.CandidateCount, report.Duration))
	out = append(out, fmt.Sprintf("Role mix observed: session=%d, beacon=%d, tunnel=%d, listen=%d, outbound=%d.", report.RoleCounts["session"], report.RoleCounts["beacon"], report.RoleCounts["tunnel"], report.RoleCounts["listen"], report.RoleCounts["outbound"]))
	if len(report.RecommendedSettings) > 0 {
		out = append(out, "Recommended settings were constrained by guardrails to avoid overfitting.")
	} else {
		out = append(out, "No changes were recommended because current settings already fit observed traffic.")
	}
	return out
}

func buildSimilarPast(current Report, records []calibrationMemoryRecord, limit int) []SimilarCalibration {
	type scored struct {
		rec   calibrationMemoryRecord
		score int
	}
	scoredItems := make([]scored, 0, len(records))
	curPath := normalizeOutputPath(current.OutputPath)
	for _, rec := range records {
		recPath := normalizeOutputPath(rec.ReportPath)
		if recPath == curPath {
			continue
		}
		scoredItems = append(scoredItems, scored{
			rec:   rec,
			score: similarityScore(current, rec),
		})
	}
	sort.SliceStable(scoredItems, func(i, j int) bool {
		if scoredItems[i].score == scoredItems[j].score {
			return scoredItems[i].rec.GeneratedAt.After(scoredItems[j].rec.GeneratedAt)
		}
		return scoredItems[i].score > scoredItems[j].score
	})
	if limit > 0 && len(scoredItems) > limit {
		scoredItems = scoredItems[:limit]
	}
	out := make([]SimilarCalibration, 0, len(scoredItems))
	for _, item := range scoredItems {
		outcome := strings.TrimSpace(item.rec.Outcome)
		if outcome == "" {
			outcome = "n/a"
		}
		out = append(out, SimilarCalibration{
			Similarity:     clampInt(item.score, 0, 100),
			Report:         filepath.Base(item.rec.ReportPath),
			Roles:          nonEmpty(item.rec.Scope, "recommended"),
			Provider:       normalizeProvider(item.rec.Provider),
			Confidence:     clampInt(item.rec.Confidence, 0, 100),
			Outcome:        fmt.Sprintf("%s (%d)", outcome, item.rec.OutcomeScore),
			Applied:        item.rec.Applied,
			Summary:        strings.TrimSpace(item.rec.Summary),
			GeneratedAt:    item.rec.GeneratedAt,
			EnvFingerprint: item.rec.EnvFingerprint,
		})
	}
	return out
}

func similarityScore(current Report, rec calibrationMemoryRecord) int {
	score := 0
	if normalizeProvider(rec.Provider) == normalizeProvider(current.Provider) {
		score += 20
	}
	if strings.EqualFold(strings.TrimSpace(rec.Scope), strings.TrimSpace(current.Scope)) {
		score += 20
	}

	curTotal := maxInt(1, current.CandidateCount)
	recTotal := maxInt(1, rec.CandidateCount)
	ratio := float64(minInt(curTotal, recTotal)) / float64(maxInt(curTotal, recTotal))
	score += int(ratio * 15)

	families := []string{"session", "beacon", "tunnel", "listen", "outbound", "other"}
	var dist float64
	for _, fam := range families {
		a := float64(current.RoleCounts[fam]) / float64(curTotal)
		b := float64(rec.RoleCounts[fam]) / float64(recTotal)
		dist += math.Abs(a - b)
	}
	closeness := 1.0 - (dist / 2.0)
	if closeness < 0 {
		closeness = 0
	}
	score += int(closeness * 45)

	if rec.Applied {
		score += 3
	}
	return clampInt(score, 0, 100)
}

func writeCalibrationDataset(path string, samples []shared.Candidate) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	f, closeFile, err := safeio.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = closeFile() }()

	enc := json.NewEncoder(f)
	for _, sample := range samples {
		if sample.Proc == nil {
			continue
		}
		state := "watch"
		if sample.ActiveProxying {
			state = "active"
		} else if sample.StrongEvidence {
			state = "strong"
		}
		row := calibrationDatasetRow{
			Timestamp: time.Now().UTC(),
			Host:      shared.DisplayHost(sample.Host),
			PID:       sample.Proc.Pid,
			Process:   sample.Proc.Name,
			Role:      shared.RoleFamily(sample.Role),
			State:     state,
			AgeSec:    sample.ControlDurationSeconds,
			Inbound:   sample.InboundTotal,
			Outbound:  sample.OutTotal,
			Reasons:   limitStrings(sample.Reasons, 4),
			Signals:   limitStrings(sample.Signals, 6),
		}
		if err := enc.Encode(row); err != nil {
			return err
		}
	}
	return nil
}

func calibrationTrainingDatasetPath() string {
	return filepath.Join(calibrationRoot(), "training", "validated-calibrations.jsonl")
}

func loadCalibrationMemory() ([]calibrationMemoryRecord, error) {
	path := calibrationTrainingDatasetPath()
	f, closeFile, err := safeio.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = closeFile() }()

	records := make([]calibrationMemoryRecord, 0, 32)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec calibrationMemoryRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if strings.TrimSpace(rec.ReportPath) == "" {
			continue
		}
		records = append(records, rec)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func saveCalibrationMemory(records []calibrationMemoryRecord) error {
	path := calibrationTrainingDatasetPath()
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	f, closeFile, err := safeio.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = closeFile() }()

	sort.SliceStable(records, func(i, j int) bool {
		return records[i].GeneratedAt.Before(records[j].GeneratedAt)
	})
	enc := json.NewEncoder(f)
	for _, rec := range records {
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	return nil
}

func upsertCalibrationRecord(records []calibrationMemoryRecord, rec calibrationMemoryRecord) []calibrationMemoryRecord {
	path := normalizeOutputPath(rec.ReportPath)
	for i := range records {
		if normalizeOutputPath(records[i].ReportPath) != path {
			continue
		}
		records[i] = rec
		return records
	}
	return append(records, rec)
}

func cloneIntMap(src map[string]int) map[string]int {
	if len(src) == 0 {
		return map[string]int{}
	}
	out := make(map[string]int, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func nonEmpty(v, fallback string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return fallback
	}
	return v
}

type validationThresholds struct {
	reverseControlMin   time.Duration
	longLivedMinAge     time.Duration
	shortLivedMaxAge    time.Duration
	minInternalTargets  int
	outboundExternalCap int
	trafficPenalty      int
}

type validationCounts struct {
	tp int
	fp int
	tn int
	fn int
}

func evaluateCalibrationValidation(before, after TuningSettings, samples []shared.Candidate) CalibrationValidation {
	validation := CalibrationValidation{
		Notes: make([]string, 0, 4),
	}
	if len(samples) == 0 {
		validation.Notes = append(validation.Notes, "No samples were captured during calibration.")
		return validation
	}
	baseThresholds := buildValidationThresholds(before, before)
	tunedThresholds := buildValidationThresholds(after, before)
	baseCounts := validationCounts{}
	tunedCounts := validationCounts{}
	changedProcesses := make([]string, 0, 8)

	for _, sample := range samples {
		if sample.Proc == nil {
			continue
		}
		label := validationLabel(sample)
		if label {
			validation.PositiveSamples++
		} else {
			validation.NegativeSamples++
		}
		validation.SampleCount++

		basePred := validationPredict(sample, baseThresholds)
		tunedPred := validationPredict(sample, tunedThresholds)
		updateValidationCounts(&baseCounts, label, basePred)
		updateValidationCounts(&tunedCounts, label, tunedPred)

		// Track processes whose classification changed between baseline and tuned.
		if basePred != tunedPred {
			name := sample.Proc.Name
			baseState := validationChangeLabel(label, basePred)
			tunedState := validationChangeLabel(label, tunedPred)
			changedProcesses = append(changedProcesses, fmt.Sprintf("%s (%s->%s)", name, baseState, tunedState))
		}
	}
	if len(changedProcesses) > 5 {
		changedProcesses = changedProcesses[:5]
	}
	validation.ChangedProcesses = changedProcesses
	if validation.SampleCount == 0 {
		validation.Notes = append(validation.Notes, "Only empty process rows were captured.")
		return validation
	}
	basePrecision, baseRecall, baseSpecificity, baseF1 := validationMetrics(baseCounts)
	tunedPrecision, tunedRecall, tunedSpecificity, tunedF1 := validationMetrics(tunedCounts)
	validation.BaselineScore = validationQuality(baseF1, baseSpecificity)
	validation.TunedScore = validationQuality(tunedF1, tunedSpecificity)
	validation.ScoreDelta = validation.TunedScore - validation.BaselineScore
	validation.BaselinePrecisionPct = validationPercent(basePrecision)
	validation.TunedPrecisionPct = validationPercent(tunedPrecision)
	validation.BaselineRecallPct = validationPercent(baseRecall)
	validation.TunedRecallPct = validationPercent(tunedRecall)
	validation.BaselineFalsePositives = baseCounts.fp
	validation.TunedFalsePositives = tunedCounts.fp
	validation.BaselineFalseNegatives = baseCounts.fn
	validation.TunedFalseNegatives = tunedCounts.fn
	validation.Improved = validation.ScoreDelta > 0 || (validation.ScoreDelta == 0 && tunedCounts.fp < baseCounts.fp)

	if validation.PositiveSamples < 3 {
		validation.Notes = append(validation.Notes, "Few positive examples were observed; run a longer calibration for stronger evidence.")
	}
	if validation.NegativeSamples < 3 {
		validation.Notes = append(validation.Notes, "Few negative examples were observed; false-positive estimates may be unstable.")
	}
	validation.Notes = append(validation.Notes, "Validation uses captured high-confidence labels and compares baseline vs tuned settings on the same sample set.")
	return validation
}

func buildValidationThresholds(settings, fallback TuningSettings) validationThresholds {
	reverseMin, err := parseDurationOrDefault(settings.ReverseControlMinDuration, fallback.ReverseControlMinDuration)
	if err != nil {
		reverseMin = 5 * time.Second
	}
	longMin, err := parseDurationOrDefault(settings.LongLivedOutboundMinAge, fallback.LongLivedOutboundMinAge)
	if err != nil {
		longMin = 60 * time.Second
	}
	shortMax, err := parseDurationOrDefault(settings.ShortLivedOutboundMaxAge, fallback.ShortLivedOutboundMaxAge)
	if err != nil {
		shortMax = 10 * time.Second
	}
	if shortMax >= longMin {
		shortMaxSeconds := maxInt(5, int(longMin/time.Second/2))
		shortMax = time.Duration(shortMaxSeconds) * time.Second
	}
	return validationThresholds{
		reverseControlMin:   reverseMin,
		longLivedMinAge:     longMin,
		shortLivedMaxAge:    shortMax,
		minInternalTargets:  clampInt(defaultInt(settings.MinInternalTargetsForRev, fallback.MinInternalTargetsForRev), 1, 100),
		outboundExternalCap: clampInt(defaultInt(settings.OutboundOnlyExternalCap, fallback.OutboundOnlyExternalCap), 1, 500),
		trafficPenalty:      clampInt(defaultInt(settings.TrafficVerifiedPenalty, fallback.TrafficVerifiedPenalty), 1, 500),
	}
}

func validationLabel(sample shared.Candidate) bool {
	if sample.ActiveProxying || sample.StrongEvidence {
		return true
	}
	switch sample.Role {
	case "session", "beacon", "tunnel", "smb-pipe":
		return true
	default:
		return false
	}
}

func validationPredict(sample shared.Candidate, thresholds validationThresholds) bool {
	seenAge := time.Duration(maxInt(sample.SeenSeconds, 0)) * time.Second
	controlAge := time.Duration(maxInt(sample.ControlDurationSeconds, 0)) * time.Second
	score := 0.0

	if sample.ControlChannel != nil && controlAge >= thresholds.reverseControlMin {
		score += 2.2
	}
	if sample.OutInternal >= thresholds.minInternalTargets && sample.OutTotal > 0 {
		score += 1.1
	}
	if sample.OutLongLived > 0 && seenAge >= thresholds.longLivedMinAge {
		score += 0.9
	}
	if sample.OutShortLived > 0 && seenAge > 0 && seenAge <= thresholds.shortLivedMaxAge {
		score += 0.7
	}
	if sample.OutExternal > thresholds.outboundExternalCap {
		score += 0.6
	}
	if sample.InboundTotal > 0 && sample.OutTotal > 0 {
		score += 0.8
	}
	if sample.TrafficVerified && !sample.ActiveProxying {
		score -= 0.25 + (float64(thresholds.trafficPenalty) / 220.0)
	}
	if sample.OutTotal == 0 && sample.InboundTotal == 0 {
		score -= 0.4
	}
	return score >= 1.5
}

func updateValidationCounts(counts *validationCounts, label, pred bool) {
	switch {
	case label && pred:
		counts.tp++
	case !label && pred:
		counts.fp++
	case label && !pred:
		counts.fn++
	default:
		counts.tn++
	}
}

func validationMetrics(counts validationCounts) (precision, recall, specificity, f1 float64) {
	precision = ratioFloat(counts.tp, counts.tp+counts.fp)
	recall = ratioFloat(counts.tp, counts.tp+counts.fn)
	specificity = ratioFloat(counts.tn, counts.tn+counts.fp)
	if precision+recall > 0 {
		f1 = (2 * precision * recall) / (precision + recall)
	}
	return precision, recall, specificity, f1
}

func validationQuality(f1, specificity float64) int {
	return clampInt(int(math.Round((0.65*f1+0.35*specificity)*100.0)), 0, 100)
}

func validationPercent(v float64) int {
	return clampInt(int(math.Round(v*100.0)), 0, 100)
}

func validationChangeLabel(trueLabel, predicted bool) string {
	switch {
	case trueLabel && predicted:
		return "correct"
	case trueLabel && !predicted:
		return "missed"
	case !trueLabel && predicted:
		return "FP"
	default:
		return "correct"
	}
}

func ratioFloat(num, den int) float64 {
	if den <= 0 {
		return 0
	}
	return float64(num) / float64(den)
}
