package siem

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"proxywatch/internal/calibration"
)

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
	rowSamples := make([]map[string]any, 0, min(32, len(rows)))
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
