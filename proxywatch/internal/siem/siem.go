package siem

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"proxywatch/internal/calibration"
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
	ReportLines     []string        `json:"report_lines,omitempty"`
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
	ID          string      `json:"id"`
	Title       string      `json:"title"`
	Role        string      `json:"role"`
	Severity    string      `json:"severity"`
	Description string      `json:"description"`
	Processes   []string    `json:"processes,omitempty"`
	Signals     []string    `json:"signals,omitempty"`
	Reasons     []string    `json:"reasons,omitempty"`
	Queries     SIEMQueries `json:"queries"`
}

type SIEMQueries struct {
	Splunk  string         `json:"splunk"`
	KQL     string         `json:"kql"`
	Elastic string         `json:"elastic_esql"`
	Sigma   map[string]any `json:"sigma_like"`
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
	now := time.Now().UTC()
	sourceReport := normalizeOutputPath(input.SourceReport)
	report, err := calibration.LoadReport(sourceReport)
	if err != nil {
		return SIEMRunResult{}, fmt.Errorf("load calibration report: %w", err)
	}
	datasetPath := normalizeSIEMDatasetPath(report.OutputPath, report.DatasetPath)
	datasetRows, err := loadSIEMDatasetRows(datasetPath, maxSIEMDatasetRows)
	if err != nil {
		fallbackRows := buildSIEMRowsFromReport(report)
		if len(fallbackRows) == 0 {
			return SIEMRunResult{}, fmt.Errorf("load calibration dataset: %w", err)
		}
		datasetRows = fallbackRows
		datasetPath = "derived-from-report"
	}

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

	roleStats := buildSIEMRoleStats(datasetRows)
	mode := "fallback"
	aiSummary := ""
	aiHighlights := []string{}
	aiDetections := []aiSIEMDetection{}
	aiErr := ""
	if ready, reason := calibration.ProviderReady(provider, calibration.DetectProviderAccess()); ready {
		if parsed, err := generateSIEMWithAI(provider, model, report, roleStats, datasetRows); err == nil {
			mode = "ai"
			aiSummary = strings.TrimSpace(parsed.Summary)
			aiHighlights = sanitizeRecommendations(parsed.Highlights)
			aiDetections = parsed.Detections
		} else {
			aiErr = trimError(err.Error(), 240)
		}
	} else {
		aiErr = reason
	}

	detections := buildSIEMDetections(report, roleStats, aiDetections)
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

	if err := writeSIEMJSON(jsonPath, bundle); err != nil {
		return SIEMRunResult{}, err
	}
	if err := writeSIEMReport(reportPath, bundle); err != nil {
		return SIEMRunResult{}, err
	}

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

func generateSIEMWithAI(provider, model string, report calibration.Report, roleStats map[string]*siemRoleStats, rows []siemDatasetRow) (aiSIEMResult, error) {
	roleView := make(map[string]map[string]any)
	for role, st := range roleStats {
		roleView[role] = map[string]any{
			"count":         st.Count,
			"top_processes": topMapCounts(st.Processes, 8),
			"top_signals":   topMapCounts(st.Signals, 8),
			"top_reasons":   topMapCounts(st.Reasons, 6),
			"states":        topMapCounts(st.States, 3),
		}
	}
	rowSamples := make([]map[string]any, 0, minInt(32, len(rows)))
	for i := 0; i < len(rows) && i < 32; i++ {
		row := rows[i]
		rowSamples = append(rowSamples, map[string]any{
			"host":     strings.TrimSpace(row.Host),
			"process":  strings.TrimSpace(row.Process),
			"role":     normalizeSIEMRole(row.Role),
			"state":    strings.TrimSpace(row.State),
			"age_sec":  row.AgeSec,
			"inbound":  row.Inbound,
			"outbound": row.Outbound,
			"signals":  limitStrings(row.Signals, 4),
			"reasons":  limitStrings(row.Reasons, 3),
		})
	}

	payload := map[string]any{
		"schema": "proxywatch-siem-v1",
		"calibration": map[string]any{
			"provider":        strings.TrimSpace(report.Provider),
			"model":           strings.TrimSpace(report.Model),
			"scope":           strings.TrimSpace(report.Scope),
			"duration":        strings.TrimSpace(report.Duration),
			"candidate_count": report.CandidateCount,
			"role_counts":     cloneIntMap(report.RoleCounts),
			"state_counts":    cloneIntMap(report.StateCounts),
			"summary":         strings.TrimSpace(report.Summary),
			"recommendations": limitStrings(report.Recommendations, 8),
		},
		"role_stats":   roleView,
		"row_examples": rowSamples,
	}
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return aiSIEMResult{}, err
	}

	system := strings.TrimSpace(`
You are generating SIEM detection content from Proxywatch calibration telemetry.
Return ONLY valid JSON with this exact shape:
{
  "summary": "short paragraph",
  "highlights": ["item 1", "item 2", "item 3"],
  "detections": [
    {
      "title": "detection title",
      "role": "session|beacon|tunnel|listener|outbound|other",
      "severity": "low|medium|high|critical",
      "description": "what to detect and why",
      "processes": ["proc1", "proc2"],
      "signals": ["signal1", "signal2"],
      "reasons": ["reason1", "reason2"]
    }
  ]
}
Rules:
- Keep detections aligned with observed roles and traffic behavior.
- Prefer precision and explainability over volume.
- Do not invent unsupported telemetry fields.
- No markdown.
`)
	user := "Proxywatch calibration telemetry JSON:\n" + string(rawPayload)
	response, err := calibration.RequestSIEMAI(context.Background(), provider, model, system, user)
	if err != nil {
		return aiSIEMResult{}, err
	}
	return parseAISIEMResult(response)
}

func parseAISIEMResult(raw string) (aiSIEMResult, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return aiSIEMResult{}, fmt.Errorf("empty response")
	}
	text = strings.TrimPrefix(text, "```json")
	text = strings.TrimPrefix(text, "```")
	text = strings.TrimSuffix(text, "```")
	text = strings.TrimSpace(text)

	var out aiSIEMResult
	if err := json.Unmarshal([]byte(text), &out); err == nil {
		return out, nil
	}
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start < 0 || end <= start {
		return aiSIEMResult{}, fmt.Errorf("response did not contain JSON object")
	}
	if err := json.Unmarshal([]byte(text[start:end+1]), &out); err != nil {
		return aiSIEMResult{}, err
	}
	return out, nil
}

func buildSIEMDetections(report calibration.Report, roleStats map[string]*siemRoleStats, aiDetections []aiSIEMDetection) []SIEMDetection {
	out := make([]SIEMDetection, 0, 12)
	if len(aiDetections) > 0 {
		for _, det := range aiDetections {
			role := normalizeSIEMRole(det.Role)
			st := roleStats[role]
			procNames := sanitizeAndFallbackList(det.Processes, st, "process")
			signals := sanitizeAndFallbackSignals(det.Signals, st)
			reasons := sanitizeAndFallbackReasons(det.Reasons, st)
			severity := normalizeSeverity(det.Severity, role)
			title := strings.TrimSpace(det.Title)
			if title == "" {
				title = defaultSIEMDetectionTitle(role)
			}
			desc := strings.TrimSpace(det.Description)
			if desc == "" {
				desc = fallbackSIEMDescription(role, st, procNames)
			}
			out = append(out, makeSIEMDetection(role, severity, title, desc, procNames, signals, reasons))
		}
	}

	if len(out) == 0 {
		roles := orderedRoleFamiliesFromReport(report, roleStats)
		for _, role := range roles {
			st := roleStats[role]
			procNames := topMapKeys(st.Processes, 5)
			signals := topMapKeys(st.Signals, 8)
			reasons := topMapKeys(st.Reasons, 5)
			out = append(out, makeSIEMDetection(
				role,
				normalizeSeverity("", role),
				defaultSIEMDetectionTitle(role),
				fallbackSIEMDescription(role, st, procNames),
				procNames,
				signals,
				reasons,
			))
		}
	}

	if len(out) == 0 {
		out = append(out, makeSIEMDetection(
			"other",
			"low",
			"Proxywatch behavioral outlier",
			"Alert on process network behavior that deviates from calibrated baseline.",
			nil,
			nil,
			nil,
		))
	}

	seen := make(map[string]bool, len(out))
	filtered := make([]SIEMDetection, 0, len(out))
	for _, det := range out {
		if seen[det.ID] {
			continue
		}
		seen[det.ID] = true
		filtered = append(filtered, det)
	}
	return filtered
}

func makeSIEMDetection(role, severity, title, description string, processes, signals, reasons []string) SIEMDetection {
	role = normalizeSIEMRole(role)
	if role == "" {
		role = "other"
	}
	processes = sanitizeStringList(processes, 6)
	signals = sanitizeStringList(signals, 10)
	reasons = sanitizeStringList(reasons, 8)
	id := strings.ToLower(strings.ReplaceAll(role+"-"+title, " ", "-"))
	id = sanitizeDetectionID(id)
	det := SIEMDetection{
		ID:          id,
		Title:       strings.TrimSpace(title),
		Role:        role,
		Severity:    normalizeSeverity(severity, role),
		Description: strings.TrimSpace(description),
		Processes:   processes,
		Signals:     signals,
		Reasons:     reasons,
	}
	det.Queries = SIEMQueries{
		Splunk:  buildSIEMSplunkQuery(det),
		KQL:     buildSIEMKQLQuery(det),
		Elastic: buildSIEMElasticQuery(det),
		Sigma:   buildSIEMSigma(det),
	}
	return det
}

func sanitizeDetectionID(id string) string {
	id = strings.TrimSpace(strings.ToLower(id))
	if id == "" {
		return "proxywatch-detection"
	}
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "proxywatch-detection"
	}
	return out
}

func normalizeSIEMRole(role string) string {
	s := strings.ToLower(strings.TrimSpace(role))
	switch s {
	case "session", "susp-session", "reverse-control":
		return "session"
	case "beacon", "susp-beacon":
		return "beacon"
	case "tunnel", "tun", "susp-tun", "reverse-transport", "reverse-proxy", "reverse-tunnel", "smb-pipe":
		return "tunnel"
	case "listener", "proxy-listener", "listener-with-clients", "listener-with-outbound", "listener-only":
		return "listener"
	case "outbound", "outbound-only":
		return "outbound"
	default:
		return "other"
	}
}

func normalizeSeverity(raw, role string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch s {
	case "low", "medium", "high", "critical":
		return s
	}
	switch normalizeSIEMRole(role) {
	case "session", "beacon", "tunnel":
		return "high"
	case "listener":
		return "medium"
	case "outbound":
		return "low"
	default:
		return "low"
	}
}

func defaultSIEMDetectionTitle(role string) string {
	switch normalizeSIEMRole(role) {
	case "session":
		return "Persistent control-session behavior"
	case "beacon":
		return "Beacon-like callback pattern"
	case "tunnel":
		return "Tunnel or pivot traffic pattern"
	case "listener":
		return "Unexpected listener exposure"
	case "outbound":
		return "Anomalous outbound pattern"
	default:
		return "Behavioral outlier"
	}
}

func fallbackSIEMDescription(role string, st *siemRoleStats, processes []string) string {
	count := 0
	if st != nil {
		count = st.Count
	}
	procText := ""
	if len(processes) > 0 {
		procText = " Top processes: " + strings.Join(processes, ", ") + "."
	}
	switch normalizeSIEMRole(role) {
	case "session":
		return fmt.Sprintf("Detected %d calibration samples with stable control-session characteristics.%s", count, procText)
	case "beacon":
		return fmt.Sprintf("Detected %d calibration samples with recurring beacon-like timing.%s", count, procText)
	case "tunnel":
		return fmt.Sprintf("Detected %d calibration samples consistent with tunnel/pivot traffic.%s", count, procText)
	case "listener":
		return fmt.Sprintf("Detected %d calibration samples with listener behavior.%s", count, procText)
	case "outbound":
		return fmt.Sprintf("Detected %d calibration samples with sustained outbound traffic.%s", count, procText)
	default:
		return fmt.Sprintf("Detected %d calibration samples with behavior deviations.%s", count, procText)
	}
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
		fmt.Sprintf("Calibration source role mix: session=%d beacon=%d tunnel=%d listener=%d outbound=%d.", report.RoleCounts["session"], report.RoleCounts["beacon"], report.RoleCounts["tunnel"], report.RoleCounts["listener"], report.RoleCounts["outbound"]),
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
	preferred := []string{"session", "beacon", "tunnel", "listener", "outbound", "other"}
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
	out := make([]string, 0, minInt(limit, len(values)))
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

func sanitizeAndFallbackList(values []string, st *siemRoleStats, kind string) []string {
	clean := sanitizeStringList(values, 6)
	if len(clean) > 0 {
		return clean
	}
	if st == nil {
		return nil
	}
	switch kind {
	case "process":
		return topMapKeys(st.Processes, 6)
	default:
		return nil
	}
}

func sanitizeAndFallbackSignals(values []string, st *siemRoleStats) []string {
	clean := sanitizeStringList(values, 10)
	if len(clean) > 0 {
		return clean
	}
	if st == nil {
		return nil
	}
	return topMapKeys(st.Signals, 10)
}

func sanitizeAndFallbackReasons(values []string, st *siemRoleStats) []string {
	clean := sanitizeStringList(values, 8)
	if len(clean) > 0 {
		return clean
	}
	if st == nil {
		return nil
	}
	return topMapKeys(st.Reasons, 8)
}

func buildSIEMSplunkQuery(det SIEMDetection) string {
	parts := []string{`index=<endpoint_index>`, `sourcetype=<endpoint_network_or_edr>`}
	clauses := make([]string, 0, 3)
	clauses = append(clauses, `proxywatch_role="`+escapeSIEMQuery(det.Role)+`"`)
	if len(det.Processes) > 0 {
		procVals := make([]string, 0, len(det.Processes))
		for _, p := range det.Processes {
			procVals = append(procVals, `"`+escapeSIEMQuery(p)+`"`)
		}
		clauses = append(clauses, "process_name IN ("+strings.Join(procVals, ",")+")")
	}
	if len(det.Signals) > 0 {
		sigVals := make([]string, 0, len(det.Signals))
		for _, s := range det.Signals {
			sigVals = append(sigVals, `"`+escapeSIEMQuery(s)+`"`)
		}
		clauses = append(clauses, "signal IN ("+strings.Join(sigVals, ",")+")")
	}
	parts = append(parts, "("+strings.Join(clauses, " OR ")+")")
	parts = append(parts, `| stats count min(_time) as first_seen max(_time) as last_seen by host process_name dest_ip dest_port signal`)
	return strings.Join(parts, " ")
}

func buildSIEMKQLQuery(det SIEMDetection) string {
	lines := []string{
		"DeviceNetworkEvents",
		`| where tostring(AdditionalFields.ProxywatchRole) =~ "` + escapeSIEMQuery(det.Role) + `"`,
	}
	if len(det.Processes) > 0 {
		vals := make([]string, 0, len(det.Processes))
		for _, p := range det.Processes {
			vals = append(vals, `"`+escapeSIEMQuery(p)+`"`)
		}
		lines = append(lines, "| where InitiatingProcessFileName in~ ("+strings.Join(vals, ", ")+")")
	}
	if len(det.Signals) > 0 {
		vals := make([]string, 0, len(det.Signals))
		for _, s := range det.Signals {
			vals = append(vals, `"`+escapeSIEMQuery(s)+`"`)
		}
		lines = append(lines, "| where tostring(AdditionalFields.ProxywatchSignal) in~ ("+strings.Join(vals, ", ")+")")
	}
	lines = append(lines, "| summarize hits=count(), first_seen=min(Timestamp), last_seen=max(Timestamp) by DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort")
	return strings.Join(lines, "\n")
}

func buildSIEMElasticQuery(det SIEMDetection) string {
	lines := []string{"from logs-endpoint.events.network*"}
	lines = append(lines, `| where proxywatch.role == "`+escapeSIEMQuery(det.Role)+`"`)
	if len(det.Processes) > 0 {
		vals := make([]string, 0, len(det.Processes))
		for _, p := range det.Processes {
			vals = append(vals, `"`+escapeSIEMQuery(p)+`"`)
		}
		lines = append(lines, "| where process.name in ("+strings.Join(vals, ", ")+")")
	}
	if len(det.Signals) > 0 {
		vals := make([]string, 0, len(det.Signals))
		for _, s := range det.Signals {
			vals = append(vals, `"`+escapeSIEMQuery(s)+`"`)
		}
		lines = append(lines, "| where proxywatch.signal in ("+strings.Join(vals, ", ")+")")
	}
	lines = append(lines, "| stats hits = count(*) by host.name, process.name, destination.ip, destination.port")
	return strings.Join(lines, "\n")
}

func buildSIEMSigma(det SIEMDetection) map[string]any {
	selection := map[string]any{
		"ProxywatchRole": det.Role,
	}
	if len(det.Processes) > 0 {
		selection["ProcessName|contains"] = det.Processes
	}
	if len(det.Signals) > 0 {
		selection["ProxywatchSignal|contains"] = det.Signals
	}
	return map[string]any{
		"title":       det.Title,
		"id":          det.ID,
		"status":      "experimental",
		"description": det.Description,
		"logsource": map[string]any{
			"category": "network_connection",
			"product":  "windows",
		},
		"detection": map[string]any{
			"selection": selection,
			"condition": "selection",
		},
		"level": det.Severity,
	}
}

func escapeSIEMQuery(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	v = strings.ReplaceAll(v, "\\", "\\\\")
	v = strings.ReplaceAll(v, `"`, `\\"`)
	return v
}

func topMapCounts(src map[string]int, limit int) []map[string]any {
	keys := topMapKeys(src, limit)
	out := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		out = append(out, map[string]any{"name": key, "count": src[key]})
	}
	return out
}

func renderSIEMReportLines(bundle SIEMBundle) []string {
	lines := make([]string, 0, 200)
	lines = append(lines, "# Proxywatch SIEM Detection Report")
	lines = append(lines, "")
	lines = append(lines, "Generated: "+bundle.GeneratedAt.Format(time.RFC3339))
	lines = append(lines, "Mode: "+bundle.Mode)
	lines = append(lines, "Provider/Model: "+bundle.Provider+" / "+bundle.Model)
	lines = append(lines, "Source calibration report: "+bundle.Source.CalibrationReport)
	lines = append(lines, "Source calibration dataset: "+bundle.Source.CalibrationDataset)
	lines = append(lines, fmt.Sprintf("Scope: %s | Duration: %s | Candidates: %d", nonEmpty(bundle.Source.Scope, "recommended"), bundle.Source.Duration, bundle.Source.CandidateCount))
	lines = append(lines, "")
	lines = append(lines, "## Summary")
	lines = append(lines, bundle.Summary)
	lines = append(lines, "")
	if len(bundle.Highlights) > 0 {
		lines = append(lines, "## Highlights")
		for _, h := range bundle.Highlights {
			lines = append(lines, "- "+h)
		}
		lines = append(lines, "")
	}
	lines = append(lines, "## Detection Coverage")
	roles := []string{"session", "beacon", "tunnel", "listener", "outbound", "other"}
	for _, role := range roles {
		count := bundle.RoleCounts[role]
		if count > 0 {
			lines = append(lines, fmt.Sprintf("- %s: %d", role, count))
		}
	}
	lines = append(lines, "")
	lines = append(lines, "## Detections")
	for i, det := range bundle.Detections {
		lines = append(lines, fmt.Sprintf("### %d. %s [%s]", i+1, det.Title, strings.ToUpper(det.Severity)))
		lines = append(lines, "Role: "+det.Role)
		lines = append(lines, "Description: "+det.Description)
		if len(det.Processes) > 0 {
			lines = append(lines, "Processes: "+strings.Join(det.Processes, ", "))
		}
		if len(det.Signals) > 0 {
			lines = append(lines, "Signals: "+strings.Join(det.Signals, ", "))
		}
		if len(det.Reasons) > 0 {
			lines = append(lines, "Reasons: "+strings.Join(det.Reasons, " | "))
		}
		lines = append(lines, "Splunk query:")
		lines = append(lines, "```")
		lines = append(lines, det.Queries.Splunk)
		lines = append(lines, "```")
		lines = append(lines, "KQL query:")
		lines = append(lines, "```")
		lines = append(lines, det.Queries.KQL)
		lines = append(lines, "```")
		lines = append(lines, "Elastic ESQL query:")
		lines = append(lines, "```")
		lines = append(lines, det.Queries.Elastic)
		lines = append(lines, "```")
		lines = append(lines, "")
	}
	if len(bundle.Recommendations) > 0 {
		lines = append(lines, "## Defender Notes")
		for _, note := range bundle.Recommendations {
			lines = append(lines, "- "+note)
		}
	}
	return lines
}

func writeSIEMJSON(path string, bundle SIEMBundle) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("siem json path is required")
	}
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
	enc.SetIndent("", "  ")
	return enc.Encode(bundle)
}

func writeSIEMReport(path string, bundle SIEMBundle) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("siem report path is required")
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	text := strings.Join(bundle.ReportLines, "\n") + "\n"
	f, closeFile, err := safeio.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = closeFile() }()
	_, err = f.WriteString(text)
	return err
}

func normalizeSIEMOutputPath(path, fallback, ext string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		path = fallback
	}
	path = expandHomePath(path)
	if filepath.IsAbs(path) {
		path = filepath.Clean(path)
	} else {
		rel := sanitizeRelativeOutputPath(path, filepath.Base(fallback))
		home := userHomeDir()
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
	datasetPath = expandHomePath(datasetPath)
	if filepath.IsAbs(datasetPath) {
		return filepath.Clean(datasetPath)
	}
	rel := sanitizeRelativeOutputPath(datasetPath, filepath.Base(calibration.DatasetPathForReport(reportPath)))
	baseDir := filepath.Dir(reportPath)
	if baseDir == "" || baseDir == "." {
		baseDir = siemCalibrationRoot()
	}
	return filepath.Join(baseDir, rel)
}

func buildSIEMRowsFromReport(report calibration.Report) []siemDatasetRow {
	rows := make([]siemDatasetRow, 0, maxInt(1, len(report.TopProcesses)))
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
	roles := []string{"session", "beacon", "tunnel", "listener", "outbound", "other"}
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
	out := make([]string, 0, minInt(limit, len(values)))
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
	out := make([]string, 0, minInt(6, len(values)))
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
	path = strings.TrimSpace(path)
	if path == "" {
		path = "~/.proxywatch/calibration/latest.json"
	}
	path = expandHomePath(path)
	if filepath.IsAbs(path) {
		path = filepath.Clean(path)
	} else {
		path = filepath.Join(siemCalibrationRoot(), sanitizeRelativeOutputPath(path, "latest.json"))
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

func expandHomePath(path string) string {
	if path == "" || path[0] != '~' {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return path
	}
	if path == "~" {
		return home
	}
	if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, "~\\") {
		return filepath.Join(home, path[2:])
	}
	return path
}

func siemCalibrationRoot() string {
	home := userHomeDir()
	if home == "" {
		return filepath.Join(".proxywatch", "calibration")
	}
	return filepath.Join(home, ".proxywatch", "calibration")
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func userHomeDir() string {
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		return strings.TrimSpace(home)
	}
	for _, key := range []string{"HOME", "USERPROFILE"} {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	drive := strings.TrimSpace(os.Getenv("HOMEDRIVE"))
	path := strings.TrimSpace(os.Getenv("HOMEPATH"))
	if drive != "" && path != "" {
		return drive + path
	}
	return ""
}
