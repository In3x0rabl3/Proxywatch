package siem

import (
	"bufio"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"proxywatch/internal/calibration"
	"proxywatch/internal/keystore"
	"proxywatch/internal/safeio"
)

const (
	defaultSIEMReportPath = "~/.proxywatch/siem/latest-report.md"
	defaultSIEMJSONPath   = "~/.proxywatch/siem/latest-detections.json"
	maxSIEMDatasetRows    = 800
)

type SIEMRunInput struct {
	SourceReport string
	Provider     string
	Model        string
	OutputReport string
	OutputJSON   string
	OnProgress   func(lines []string)
}

type SIEMRunResult struct {
	GeneratedAt    time.Time
	Mode           string
	Summary        string
	SourceReport   string
	SourceDataset  string
	ReportPath     string
	JSONPath       string
	ReportLines    []string
	DetectionCount int
}

type SIEMBundle struct {
	Schema          string          `json:"schema"`
	GeneratedAt     time.Time       `json:"generated_at"`
	Mode            string          `json:"mode"`
	Provider        string          `json:"provider"`
	Model           string          `json:"model"`
	Summary         string          `json:"summary"`
	Highlights      []string        `json:"highlights,omitempty"`
	Source          SIEMSourceMeta  `json:"source"`
	RoleCounts      map[string]int  `json:"role_counts"`
	StateCounts     map[string]int  `json:"state_counts"`
	Detections      []SIEMDetection `json:"detections"`
	Recommendations []string        `json:"recommendations,omitempty"`
	ReportLines     []string        `json:"-"`
}

type SIEMSourceMeta struct {
	CalibrationReport  string    `json:"calibration_report"`
	CalibrationDataset string    `json:"calibration_dataset"`
	Scope              string    `json:"scope"`
	Duration           string    `json:"duration"`
	CandidateCount     int       `json:"candidate_count"`
	GeneratedAt        time.Time `json:"generated_at"`
}

type SIEMDetection struct {
	ID                 string              `json:"id"`
	Title              string              `json:"title"`
	Role               string              `json:"role"`
	Severity           string              `json:"severity"`
	Description        string              `json:"description"`
	Processes          []string            `json:"processes,omitempty"`
	Signals            []string            `json:"signals,omitempty"`
	Reasons            []string            `json:"reasons,omitempty"`
	Techniques         []string            `json:"mitre_techniques,omitempty"`
	Tactics            []string            `json:"mitre_tactics,omitempty"`
	Queries            SIEMQueries         `json:"queries"`
	CalibrationContext *SIEMCalibrationCtx `json:"calibration_context,omitempty"`
}

// SIEMCalibrationCtx carries calibrated thresholds so downstream SIEM
// consumers can reference the tuned values in alert logic.
type SIEMCalibrationCtx struct {
	BeaconSleepThreshold string `json:"beacon_sleep_threshold,omitempty"`
	BeaconJitterCoVMax   string `json:"beacon_jitter_cov_max,omitempty"`
	ShapeDeltaThreshold  string `json:"shape_delta_threshold,omitempty"`
	ReverseStickyScore   int    `json:"reverse_sticky_score,omitempty"`
	Confidence           int    `json:"confidence_pct,omitempty"`
}

type SIEMQueries struct {
	Splunk   string         `json:"splunk"`
	KQL      string         `json:"kql"`
	Elastic  string         `json:"elastic_esql"`
	Sigma    map[string]any `json:"sigma_like"`
	YARA     string         `json:"yara,omitempty"`
	Suricata string         `json:"suricata,omitempty"`
}

type siemRoleStats struct {
	Count     int
	Processes map[string]int
	Signals   map[string]int
	Reasons   map[string]int
	States    map[string]int
}

type aiSIEMResult struct {
	Summary    string            `json:"summary"`
	Highlights []string          `json:"highlights"`
	Detections []aiSIEMDetection `json:"detections"`
}

type aiSIEMDetection struct {
	Title       string   `json:"title"`
	Role        string   `json:"role"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Processes   []string `json:"processes"`
	Signals     []string `json:"signals"`
	Reasons     []string `json:"reasons"`
}

type siemDatasetRow struct {
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

func DefaultSIEMReportPath() string {
	return defaultSIEMReportPath
}

func DefaultSIEMJSONPath() string {
	return defaultSIEMJSONPath
}

func ExecuteSIEM(input SIEMRunInput) (SIEMRunResult, error) {
	// Progress log — accumulated lines pushed to the UI during execution.
	progress := make([]string, 0, 32)
	emit := func(line string) {
		progress = append(progress, line)
		if input.OnProgress != nil {
			input.OnProgress(progress)
		}
	}

	stepPause := func() {
		time.Sleep(500 * time.Millisecond)
	}

	now := time.Now().UTC()
	emit("[*] Loading calibration profile...")
	stepPause()
	sourceReport := normalizeOutputPath(input.SourceReport)
	report, err := calibration.LoadReport(sourceReport)
	if err != nil {
		return SIEMRunResult{}, fmt.Errorf("load calibration report: %w", err)
	}
	emit(fmt.Sprintf("[+] Loaded: %d candidates, scope %s", report.CandidateCount, report.Scope))
	stepPause()
	datasetPath := normalizeSIEMDatasetPath(report.OutputPath, report.DatasetPath)
	emit("[*] Loading dataset (up to 800 rows)...")
	datasetRows, err := loadSIEMDatasetRows(datasetPath, maxSIEMDatasetRows)
	if err != nil {
		fallbackRows := buildSIEMRowsFromReport(report)
		if len(fallbackRows) == 0 {
			return SIEMRunResult{}, fmt.Errorf("load calibration dataset: %w", err)
		}
		datasetRows = fallbackRows
		datasetPath = "derived-from-report"
	}
	emit(fmt.Sprintf("[+] Dataset loaded: %d rows", len(datasetRows)))
	stepPause()

	provider := normalizeProvider(input.Provider)
	if provider == "" {
		provider = normalizeProvider(report.Provider)
	}
	if provider == "" {
		provider = normalizeProvider("openai")
	}
	model := strings.TrimSpace(input.Model)
	if model == "" {
		model = strings.TrimSpace(report.Model)
	}
	if model == "" {
		model = calibration.DefaultModel(provider)
	}

	reportPath := normalizeSIEMOutputPath(input.OutputReport, defaultSIEMReportPath, ".md")
	jsonPath := normalizeSIEMOutputPath(input.OutputJSON, defaultSIEMJSONPath, ".json")

	emit("[*] Building role statistics...")
	stepPause()
	roleStats := buildSIEMRoleStats(datasetRows)
	mode := "fallback"
	aiSummary := ""
	aiHighlights := []string{}
	aiDetections := []aiSIEMDetection{}
	aiErr := ""
	if ready, reason := calibration.ProviderReady(provider, calibration.DetectProviderAccess()); ready {
		emit(fmt.Sprintf("[*] Calling AI provider (%s / %s)...", provider, model))
		if parsed, err := generateSIEMWithAI(provider, model, report, roleStats, datasetRows); err == nil {
			mode = "ai"
			aiSummary = strings.TrimSpace(parsed.Summary)
			aiHighlights = sanitizeRecommendations(parsed.Highlights)
			aiDetections = parsed.Detections
		} else {
			aiErr = trimError(err.Error(), 240)
		}
	} else {
		emit("[*] Building fallback detections...")
		aiErr = reason
	}

	detections := buildSIEMDetections(report, roleStats, aiDetections)
	detections = deduplicateSIEMDetections(detections)
	emit(fmt.Sprintf("[+] Generated %d detections", len(detections)))
	stepPause()
	summary := aiSummary
	if summary == "" {
		summary = fallbackSIEMSummary(report, len(detections))
	}
	highlights := aiHighlights
	if len(highlights) == 0 {
		highlights = fallbackSIEMHighlights(report, roleStats)
	}
	recommendations := make([]string, 0, 4)
	if mode != "ai" && aiErr != "" {
		recommendations = append(recommendations, "AI unavailable for SIEM packaging: "+aiErr)
	}
	recommendations = append(recommendations, "Use generated queries as starting templates and align field names to your SIEM schema.")
	recommendations = append(recommendations, "Validate detections against known benign telemetry before production alerting.")

	bundle := SIEMBundle{
		Schema:      "proxywatch-siem-detections-v1",
		GeneratedAt: now,
		Mode:        mode,
		Provider:    provider,
		Model:       model,
		Summary:     summary,
		Highlights:  highlights,
		Source: SIEMSourceMeta{
			CalibrationReport:  report.OutputPath,
			CalibrationDataset: datasetPath,
			Scope:              report.Scope,
			Duration:           report.Duration,
			CandidateCount:     report.CandidateCount,
			GeneratedAt:        report.GeneratedAt,
		},
		RoleCounts:      cloneIntMap(report.RoleCounts),
		StateCounts:     cloneIntMap(report.StateCounts),
		Detections:      detections,
		Recommendations: sanitizeRecommendations(recommendations),
	}
	bundle.ReportLines = renderSIEMReportLines(bundle)

	emit("[*] Writing SIEM detections...")
	stepPause()
	if err := writeSIEMJSON(jsonPath, bundle); err != nil {
		return SIEMRunResult{}, err
	}
	if err := writeSIEMReport(reportPath, bundle); err != nil {
		return SIEMRunResult{}, err
	}
	emit(fmt.Sprintf("[+] Detections saved as %s", jsonPath))

	return SIEMRunResult{
		GeneratedAt:    now,
		Mode:           mode,
		Summary:        summary,
		SourceReport:   report.OutputPath,
		SourceDataset:  datasetPath,
		ReportPath:     reportPath,
		JSONPath:       jsonPath,
		ReportLines:    append([]string(nil), bundle.ReportLines...),
		DetectionCount: len(detections),
	}, nil
}

func deduplicateSIEMDetections(detections []SIEMDetection) []SIEMDetection {
	if len(detections) <= 1 {
		return detections
	}
	type dedupKey struct {
		role      string
		processes string
	}
	seen := make(map[dedupKey]int) // key -> index in result
	result := make([]SIEMDetection, 0, len(detections))

	sevRank := func(s string) int {
		switch strings.ToUpper(strings.TrimSpace(s)) {
		case "HIGH", "CRITICAL":
			return 3
		case "MEDIUM":
			return 2
		case "LOW":
			return 1
		default:
			return 0
		}
	}

	for _, det := range detections {
		procs := make([]string, len(det.Processes))
		copy(procs, det.Processes)
		sort.Strings(procs)
		key := dedupKey{role: det.Role, processes: strings.Join(procs, ",")}

		if idx, ok := seen[key]; ok {
			// Keep higher severity
			if sevRank(det.Severity) > sevRank(result[idx].Severity) {
				det.Description += " (merged from duplicate detection)"
				result[idx] = det
			} else {
				result[idx].Description += " (merged with duplicate)"
			}
		} else {
			seen[key] = len(result)
			result = append(result, det)
		}
	}
	return result
}

func loadSIEMDatasetRows(path string, maxRows int) ([]siemDatasetRow, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("dataset path is required")
	}
	f, closeFile, err := safeio.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = closeFile() }()

	rows := make([]siemDatasetRow, 0, 256)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var row siemDatasetRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		if strings.TrimSpace(row.Process) == "" {
			continue
		}
		rows = append(rows, row)
		if maxRows > 0 && len(rows) >= maxRows {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("dataset has no usable rows")
	}
	return rows, nil
}

func buildSIEMRoleStats(rows []siemDatasetRow) map[string]*siemRoleStats {
	stats := make(map[string]*siemRoleStats)
	for _, row := range rows {
		role := normalizeSIEMRole(row.Role)
		entry := stats[role]
		if entry == nil {
			entry = &siemRoleStats{
				Processes: make(map[string]int),
				Signals:   make(map[string]int),
				Reasons:   make(map[string]int),
				States:    make(map[string]int),
			}
			stats[role] = entry
		}
		entry.Count++
		name := strings.TrimSpace(strings.ToLower(row.Process))
		if name == "" {
			name = "(unknown)"
		}
		entry.Processes[name]++
		state := strings.TrimSpace(strings.ToLower(row.State))
		if state != "" {
			entry.States[state]++
		}
		for _, signal := range row.Signals {
			signal = strings.TrimSpace(signal)
			if signal == "" {
				continue
			}
			entry.Signals[signal]++
		}
		for _, reason := range row.Reasons {
			reason = strings.TrimSpace(reason)
			if reason == "" {
				continue
			}
			entry.Reasons[reason]++
		}
	}
	return stats
}

func fallbackSIEMSummary(report calibration.Report, detections int) string {
	return fmt.Sprintf(
		"Generated %d SIEM-ready detections from calibration report %s (scope=%s, candidates=%d).",
		detections,
		filepath.Base(report.OutputPath),
		nonEmpty(strings.TrimSpace(report.Scope), "recommended"),
		report.CandidateCount,
	)
}

func fallbackSIEMHighlights(report calibration.Report, roleStats map[string]*siemRoleStats) []string {
	out := []string{
		fmt.Sprintf("Calibration source role mix: session=%d, beacon=%d, pivot=%d, tunnel=%d, listen=%d, outbound=%d.", report.RoleCounts["control-session"], report.RoleCounts["control-beacon"], report.RoleCounts["control-pivot"], report.RoleCounts["control-tunnel"], report.RoleCounts["listen"], report.RoleCounts["outbound"]),
	}
	roles := orderedRoleFamiliesFromReport(report, roleStats)
	if len(roles) > 0 {
		out = append(out, "Detection coverage includes: "+strings.Join(roles, ", ")+".")
	}
	if len(report.Recommendations) > 0 {
		out = append(out, "Calibration guidance was used to tune SIEM detection specificity.")
	}
	return sanitizeRecommendations(out)
}

func orderedRoleFamiliesFromReport(report calibration.Report, roleStats map[string]*siemRoleStats) []string {
	preferred := []string{"control-session", "control-beacon", "control-pivot", "control-tunnel", "listener", "outbound", "other"}
	out := make([]string, 0, len(preferred))
	for _, role := range preferred {
		if report.RoleCounts[role] > 0 {
			out = append(out, role)
			continue
		}
		if st := roleStats[role]; st != nil && st.Count > 0 {
			out = append(out, role)
		}
	}
	return out
}

func sanitizeStringList(values []string, limit int) []string {
	if len(values) == 0 || limit <= 0 {
		return nil
	}
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, min(limit, len(values)))
	for _, value := range values {
		clean := strings.TrimSpace(value)
		if clean == "" {
			continue
		}
		key := strings.ToLower(clean)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, clean)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func topMapCounts(src map[string]int, limit int) []map[string]any {
	keys := topMapKeys(src, limit)
	out := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		out = append(out, map[string]any{"name": key, "count": src[key]})
	}
	return out
}

// severityIcon returns a Unicode icon for the given severity level.
func severityIcon(sev string) string {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL":
		return "\u25b2" // ▲
	case "HIGH":
		return "\u25cf" // ●
	case "MEDIUM":
		return "\u25c6" // ◆
	case "LOW":
		return "\u25cb" // ○
	default:
		return "\u25cb"
	}
}

// truncateQuery shortens a query string to maxLen characters, appending "..."
// if truncation is needed.
func truncateQuery(q string, maxLen int) string {
	q = strings.TrimSpace(q)
	if maxLen <= 0 || len(q) <= maxLen {
		return q
	}
	if maxLen <= 3 {
		return q[:maxLen]
	}
	return q[:maxLen-3] + "..."
}

// sigmaTitle extracts the title field from a sigma_like map, returning a
// fallback if not present.
func sigmaTitle(sigma map[string]any, fallback string) string {
	if sigma == nil {
		return ""
	}
	if t, ok := sigma["title"]; ok {
		if s, ok := t.(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return fallback
}

func renderSIEMReportLines(bundle SIEMBundle) []string {
	lines := make([]string, 0, 300)

	// ── Header block ──────────────────────────────────────
	lines = append(lines, "╔══════════════════════════════════════════════════════════════════════════════╗")
	lines = append(lines, "║                         SIEM DETECTION REPORT                              ║")
	lines = append(lines, fmt.Sprintf("║  %d detections  │  %d candidates  │  %s  │  %s / %s",
		len(bundle.Detections), bundle.Source.CandidateCount,
		bundle.Source.Duration, bundle.Provider, bundle.Model))
	lines = append(lines, "╚══════════════════════════════════════════════════════════════════════════════╝")

	// ── Summary ───────────────────────────────────────────
	if strings.TrimSpace(bundle.Summary) != "" {
		lines = append(lines, "")
		lines = append(lines, "  SUMMARY")
		lines = append(lines, "  ────────────────────────────────────────────────────────────────")
		for _, line := range wrapText(bundle.Summary, 72) {
			lines = append(lines, "  "+line)
		}
	}

	// ── Key Findings ──────────────────────────────────────
	if len(bundle.Highlights) > 0 {
		lines = append(lines, "")
		lines = append(lines, "  KEY FINDINGS")
		lines = append(lines, "  ────────────────────────────────────────────────────────────────")
		for _, h := range bundle.Highlights {
			lines = append(lines, "  • "+h)
		}
	}

	// ── Detection cards ───────────────────────────────────
	for i, det := range bundle.Detections {
		lines = append(lines, "")
		sevUpper := strings.ToUpper(strings.TrimSpace(det.Severity))
		icon := severityIcon(sevUpper)
		conf := siemDetectionConfidence(det.Severity, len(det.Signals))

		// Card header with severity bar
		lines = append(lines, "  ┌──────────────────────────────────────────────────────────────────────┐")
		lines = append(lines, fmt.Sprintf("  │  %s %s  %s", icon, sevUpper, det.Title))
		lines = append(lines, fmt.Sprintf("  │  Detection %d/%d  │  Confidence: %d%%  │  %d signals  │  %d queries",
			i+1, len(bundle.Detections), conf, len(det.Signals), siemQueryCount(det.Queries)))
		lines = append(lines, "  ├──────────────────────────────────────────────────────────────────────┤")

		// Metadata fields
		lines = append(lines, fmt.Sprintf("  │  Role:       %s", det.Role))
		lines = append(lines, fmt.Sprintf("  │  Severity:   %s", strings.ToLower(sevUpper)))
		if len(det.Processes) > 0 {
			lines = append(lines, fmt.Sprintf("  │  Processes:  %s", strings.Join(det.Processes, ", ")))
		}
		if len(det.Techniques) > 0 {
			lines = append(lines, fmt.Sprintf("  │  MITRE:      %s", strings.Join(det.Techniques, "  ")))
		}
		if len(det.Tactics) > 0 {
			lines = append(lines, fmt.Sprintf("  │  Tactics:    %s", strings.Join(det.Tactics, ", ")))
		}

		// Description
		if desc := strings.TrimSpace(det.Description); desc != "" {
			lines = append(lines, "  │")
			lines = append(lines, "  │  Description:")
			for _, dl := range wrapText(desc, 68) {
				lines = append(lines, "  │    "+dl)
			}
		}

		// Signals
		if len(det.Signals) > 0 {
			lines = append(lines, "  │")
			lines = append(lines, "  │  Signals:")
			for _, sig := range det.Signals {
				lines = append(lines, "  │    • "+sig)
			}
		}

		// Reasons
		if len(det.Reasons) > 0 {
			lines = append(lines, "  │")
			lines = append(lines, "  │  Analysis:")
			for _, r := range det.Reasons {
				lines = append(lines, "  │    ▸ "+r)
			}
		}

		// Queries
		type queryEntry struct {
			label, value string
			last         bool
		}
		qEntries := make([]queryEntry, 0, 6)
		if v := strings.TrimSpace(det.Queries.Splunk); v != "" {
			qEntries = append(qEntries, queryEntry{label: "Splunk", value: truncateQuery(v, 100)})
		}
		if v := strings.TrimSpace(det.Queries.KQL); v != "" {
			qEntries = append(qEntries, queryEntry{label: "KQL", value: truncateQuery(v, 100)})
		}
		if v := strings.TrimSpace(det.Queries.Elastic); v != "" {
			qEntries = append(qEntries, queryEntry{label: "ESQL", value: truncateQuery(v, 100)})
		}
		if v := strings.TrimSpace(det.Queries.Suricata); v != "" {
			qEntries = append(qEntries, queryEntry{label: "Suricata", value: truncateQuery(v, 100)})
		}
		if v := strings.TrimSpace(det.Queries.YARA); v != "" {
			qEntries = append(qEntries, queryEntry{label: "YARA", value: truncateQuery(v, 100)})
		}
		if st := sigmaTitle(det.Queries.Sigma, ""); st != "" {
			qEntries = append(qEntries, queryEntry{label: "Sigma", value: truncateQuery("title: "+st, 100)})
		}
		if len(qEntries) > 0 {
			qEntries[len(qEntries)-1].last = true
			lines = append(lines, "  │")
			lines = append(lines, "  │  Queries:")
			for _, qe := range qEntries {
				branch := "├─"
				if qe.last {
					branch = "└─"
				}
				lines = append(lines, fmt.Sprintf("  │    %s %s: %s", branch, qe.label, qe.value))
			}
		}

		lines = append(lines, "  └──────────────────────────────────────────────────────────────────────┘")
	}

	// ── Defender Notes ────────────────────────────────────
	if len(bundle.Recommendations) > 0 {
		lines = append(lines, "")
		lines = append(lines, "  DEFENDER NOTES")
		lines = append(lines, "  ────────────────────────────────────────────────────────────────")
		for i, note := range bundle.Recommendations {
			for j, wl := range wrapText(note, 70) {
				if j == 0 {
					lines = append(lines, fmt.Sprintf("  %d. %s", i+1, wl))
				} else {
					lines = append(lines, "     "+wl)
				}
			}
		}
	}

	lines = append(lines, "")
	return lines
}

// wrapText breaks text into lines of at most maxW characters at word boundaries.
func wrapText(text string, maxW int) []string {
	if maxW <= 0 {
		return []string{text}
	}
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}
	var lines []string
	cur := words[0]
	for _, w := range words[1:] {
		if len(cur)+1+len(w) > maxW {
			lines = append(lines, cur)
			cur = w
		} else {
			cur += " " + w
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// siemDetectionConfidence computes a 0-100 confidence percentage from severity
// and signal count.
func siemDetectionConfidence(sev string, signalCount int) int {
	base := 0
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL":
		base = 85
	case "HIGH":
		base = 70
	case "MEDIUM":
		base = 50
	case "LOW":
		base = 30
	default:
		base = 20
	}
	bonus := signalCount * 3
	if bonus > 15 {
		bonus = 15
	}
	total := base + bonus
	if total > 100 {
		total = 100
	}
	return total
}

// siemDetectionPriority assigns a 1-based priority rank to detections sorted
// by severity then process count descending.
func siemDetectionPriority(detections []SIEMDetection) []int {
	type ranked struct {
		idx      int
		sevRank  int
		procLen  int
		sigCount int
	}
	sevOrd := func(s string) int {
		switch strings.ToUpper(strings.TrimSpace(s)) {
		case "CRITICAL":
			return 4
		case "HIGH":
			return 3
		case "MEDIUM":
			return 2
		case "LOW":
			return 1
		default:
			return 0
		}
	}
	items := make([]ranked, len(detections))
	for i, d := range detections {
		items[i] = ranked{idx: i, sevRank: sevOrd(d.Severity), procLen: len(d.Processes), sigCount: len(d.Signals)}
	}
	sort.Slice(items, func(a, b int) bool {
		if items[a].sevRank != items[b].sevRank {
			return items[a].sevRank > items[b].sevRank
		}
		if items[a].procLen != items[b].procLen {
			return items[a].procLen > items[b].procLen
		}
		return items[a].sigCount > items[b].sigCount
	})
	priorities := make([]int, len(detections))
	for rank, item := range items {
		priorities[item.idx] = rank + 1
	}
	return priorities
}

// siemQueryCoverage returns a map of platform->bool indicating which SIEM
// platforms have queries for a detection.
func siemQueryCoverage(q SIEMQueries) map[string]bool {
	cov := make(map[string]bool, 6)
	cov["splunk"] = strings.TrimSpace(q.Splunk) != ""
	cov["kql"] = strings.TrimSpace(q.KQL) != ""
	cov["esql"] = strings.TrimSpace(q.Elastic) != ""
	cov["sigma"] = len(q.Sigma) > 0
	cov["yara"] = strings.TrimSpace(q.YARA) != ""
	cov["suricata"] = strings.TrimSpace(q.Suricata) != ""
	return cov
}

// siemQueryCount counts the number of non-empty query platforms for a detection.
func siemQueryCount(q SIEMQueries) int {
	count := 0
	for _, has := range siemQueryCoverage(q) {
		if has {
			count++
		}
	}
	return count
}

// siemJSONEnriched is a wrapper around SIEMBundle that adds per-detection
// enrichment fields for downstream consumers without modifying the core types.
type siemJSONEnriched struct {
	SIEMBundle
	GeneratedBy        string                     `json:"generated_by"`
	EnrichedDetections []siemJSONDetectionWrapper `json:"enriched_detections,omitempty"`
}

type siemJSONDetectionWrapper struct {
	SIEMDetection
	Confidence int             `json:"confidence"`
	Priority   int             `json:"priority"`
	QueryCount int             `json:"query_count"`
	Coverage   map[string]bool `json:"coverage"`
}

const proxyWatchVersion = "proxywatch"

func writeSIEMJSON(path string, bundle SIEMBundle) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("siem json path is required")
	}
	priorities := siemDetectionPriority(bundle.Detections)
	enriched := siemJSONEnriched{
		SIEMBundle:  bundle,
		GeneratedBy: proxyWatchVersion,
	}
	enriched.EnrichedDetections = make([]siemJSONDetectionWrapper, len(bundle.Detections))
	for i, det := range bundle.Detections {
		prio := 0
		if i < len(priorities) {
			prio = priorities[i]
		}
		enriched.EnrichedDetections[i] = siemJSONDetectionWrapper{
			SIEMDetection: det,
			Confidence:    siemDetectionConfidence(det.Severity, len(det.Signals)),
			Priority:      prio,
			QueryCount:    siemQueryCount(det.Queries),
			Coverage:      siemQueryCoverage(det.Queries),
		}
	}
	data, err := json.MarshalIndent(enriched, "", "  ")
	if err != nil {
		return err
	}
	vaultKey := vaultKeyFromPath(path)
	return keystore.VaultWrite(vaultKey, data, path)
}

func writeSIEMReport(path string, bundle SIEMBundle) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("siem report path is required")
	}
	text := strings.Join(bundle.ReportLines, "\n") + "\n"
	vaultKey := vaultKeyFromPath(path)
	return keystore.VaultWrite(vaultKey, []byte(text), path)
}

func vaultKeyFromPath(path string) string {
	path = strings.TrimSpace(path)
	if idx := strings.Index(path, ".proxywatch/"); idx >= 0 {
		return path[idx+len(".proxywatch/"):]
	}
	return filepath.Base(path)
}

func normalizeSIEMOutputPath(path, fallback, ext string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		path = fallback
	}
	path = safeio.ExpandHomePath(path)
	if filepath.IsAbs(path) {
		path = filepath.Clean(path)
	} else {
		rel := safeio.SanitizeRelativePath(path, filepath.Base(fallback))
		home := safeio.UserHomeDir()
		if home == "" {
			path = filepath.Join(".proxywatch", "siem", rel)
		} else {
			path = filepath.Join(home, ".proxywatch", "siem", rel)
		}
	}
	if ext != "" && !strings.HasSuffix(strings.ToLower(path), strings.ToLower(ext)) {
		path += ext
	}
	return path
}

func normalizeSIEMDatasetPath(reportPath, datasetPath string) string {
	reportPath = normalizeOutputPath(reportPath)
	datasetPath = strings.TrimSpace(datasetPath)
	if datasetPath == "" {
		return calibration.DatasetPathForReport(reportPath)
	}
	datasetPath = safeio.ExpandHomePath(datasetPath)
	if filepath.IsAbs(datasetPath) {
		return filepath.Clean(datasetPath)
	}
	rel := safeio.SanitizeRelativePath(datasetPath, filepath.Base(calibration.DatasetPathForReport(reportPath)))
	baseDir := filepath.Dir(reportPath)
	if baseDir == "" || baseDir == "." {
		baseDir = siemCalibrationRoot()
	}
	return filepath.Join(baseDir, rel)
}

func buildSIEMRowsFromReport(report calibration.Report) []siemDatasetRow {
	rows := make([]siemDatasetRow, 0, max(1, len(report.TopProcesses)))
	for _, proc := range report.TopProcesses {
		rows = append(rows, siemDatasetRow{
			Timestamp: report.GeneratedAt,
			Host:      strings.TrimSpace(proc.Host),
			PID:       proc.PID,
			Process:   strings.TrimSpace(proc.Process),
			Role:      normalizeSIEMRole(proc.Role),
			State:     strings.ToLower(strings.TrimSpace(proc.State)),
			AgeSec:    parseAgeToSeconds(proc.Age),
			Inbound:   0,
			Outbound:  0,
		})
	}
	if len(rows) > 0 {
		return rows
	}
	roles := []string{"control-session", "control-beacon", "control-pivot", "control-tunnel", "listener", "outbound", "other"}
	for _, role := range roles {
		count := report.RoleCounts[role]
		if count <= 0 {
			continue
		}
		rows = append(rows, siemDatasetRow{
			Timestamp: report.GeneratedAt,
			Host:      "unknown",
			PID:       0,
			Process:   role + "-activity",
			Role:      role,
			State:     "watch",
			AgeSec:    0,
			Inbound:   0,
			Outbound:  count,
		})
	}
	return rows
}

func parseAgeToSeconds(age string) int {
	age = strings.TrimSpace(age)
	if age == "" {
		return 0
	}
	if strings.HasSuffix(age, "s") || strings.HasSuffix(age, "m") || strings.HasSuffix(age, "h") {
		if d, err := time.ParseDuration(age); err == nil {
			return int(d.Seconds())
		}
	}
	return 0
}

func topMapKeys(freq map[string]int, limit int) []string {
	if len(freq) == 0 || limit <= 0 {
		return nil
	}
	type pair struct {
		key   string
		count int
	}
	pairs := make([]pair, 0, len(freq))
	for key, count := range freq {
		pairs = append(pairs, pair{key: key, count: count})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count == pairs[j].count {
			return pairs[i].key < pairs[j].key
		}
		return pairs[i].count > pairs[j].count
	})
	if len(pairs) > limit {
		pairs = pairs[:limit]
	}
	out := make([]string, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, p.key)
	}
	return out
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

func limitStrings(values []string, limit int) []string {
	if len(values) == 0 || limit <= 0 {
		return nil
	}
	out := make([]string, 0, min(limit, len(values)))
	for _, value := range values {
		clean := strings.TrimSpace(value)
		if clean == "" {
			continue
		}
		out = append(out, clean)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func sanitizeRecommendations(values []string) []string {
	out := make([]string, 0, min(6, len(values)))
	for _, value := range values {
		clean := strings.TrimSpace(value)
		if clean == "" {
			continue
		}
		out = append(out, clean)
		if len(out) >= 6 {
			break
		}
	}
	return out
}

func nonEmpty(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func trimError(msg string, maxLen int) string {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return "unknown error"
	}
	if maxLen <= 0 || len(msg) <= maxLen {
		return msg
	}
	if maxLen <= 3 {
		return msg[:maxLen]
	}
	return msg[:maxLen-3] + "..."
}

func normalizeProvider(provider string) string {
	p := strings.ToLower(strings.TrimSpace(provider))
	switch p {
	case "openai", "anthropic", "local":
		return p
	case "builtin":
		return "openai"
	case "a", "anthropic api":
		return "anthropic"
	case "openai api":
		return "openai"
	}
	switch strings.TrimSpace(provider) {
	case "OpenAI":
		return "openai"
	case "Anthropic":
		return "anthropic"
	case "Local":
		return "local"
	default:
		return "openai"
	}
}

func normalizeOutputPath(path string) string {
	return safeio.NormalizeJSONOutputPath(path, "~/.proxywatch/calibration/latest.json", siemCalibrationRoot())
}

func siemCalibrationRoot() string {
	home := safeio.UserHomeDir()
	if home == "" {
		return filepath.Join(".proxywatch", "calibration")
	}
	return filepath.Join(home, ".proxywatch", "calibration")
}
