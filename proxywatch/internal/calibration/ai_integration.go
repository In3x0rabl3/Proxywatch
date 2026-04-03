package calibration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"proxywatch/internal/keystore"
	"proxywatch/internal/shared"
)

func calibrateWithAI(
	ctx context.Context,
	provider, model, scope string,
	duration time.Duration,
	current TuningSettings,
	samples []shared.Candidate,
	roleCounts map[string]int,
	stateCounts map[string]int,
	topProcesses []ProcessSummary,
	learning learningContext,
) (aiCalibrationResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(samples) == 0 {
		// Keep a stable output when no telemetry was available.
		tuned, recs, summary := recommendTuning(current, roleCounts, stateCounts, 0, duration, learning)
		return aiCalibrationResult{
			Summary:         summary,
			Recommendations: recs,
			Risks:           []string{"No telemetry sample set was available; recommendations are conservative defaults."},
			Reasoning:       []string{"Calibration fallback mode was used because no candidate samples were collected."},
			Settings:        tuned,
		}, nil
	}

	processNameCounts, remotePortCounts, roleExamples := extractFeatureViews(samples)
	promptBytes, promptMeta := buildCalibrationPromptPayload(
		scope,
		duration,
		current,
		samples,
		roleCounts,
		stateCounts,
		topProcesses,
		processNameCounts,
		remotePortCounts,
		roleExamples,
		learning,
		false,
	)

	system := strings.TrimSpace(`
You are the intelligence and decision engine for Proxywatch, an advanced security telemetry analysis system.
Your role is to calibrate detection thresholds AND continuously improve how detections are formed and how decisions are made under uncertainty.

You receive normalized telemetry: process context, network metadata, behavior patterns, timing data, signal lists, and environmental observations.

Your mission has two goals:
1. Calibrate detection settings for this specific environment
2. Propose new detection intelligence — signals, correlations, and reasoning improvements

Threat areas: C2 sessions, beaconing, malicious tunnels, SOCKS/covert proxying, TCP pivots, SMB/named pipe pivots, lateral movement, stealthy exfiltration, protocol abuse, OPSEC-aware malware, adversaries blending into normal activity.

Think like a detection engineer, threat hunter, malware analyst, and adversary operator simultaneously.
Focus on behavior, sequence, relationships, timing, and context — not IOCs.
Assume attackers adapt quickly and the environment contains noise and false positives.

Return ONLY JSON with this exact shape:
{
  "summary": "paragraph analyzing this environment's threat posture",
  "recommendations": ["actionable recommendation 1", "..."],
  "risks": ["risk this environment faces 1", "..."],
  "reasoning": ["why these settings were chosen 1", "..."],
  "settings": {
    "reverse_control_min_duration": "duration",
    "long_lived_outbound_min_age": "duration",
    "short_lived_outbound_max_age": "duration",
    "beacon_sleep_threshold": "duration",
    "active_window": "duration",
    "suspicion_window": "duration",
    "beacon_min_intervals": number,
    "reverse_sticky_score": number,
    "forward_sticky_score": number,
    "reverse_control_base_score": number,
    "min_internal_targets_for_rev": number,
    "min_internal_ports_for_rev": number,
    "outbound_only_external_cap": number,
    "traffic_verified_penalty": number,
    "verified_external_min_prefixes": number,
    "shape_delta_threshold": number,
    "beacon_jitter_cov_max": number
  },
  "new_signals": [
    {"name": "signal-name", "description": "what to detect and why", "weight": "low|medium|high"}
  ],
  "correlations": [
    {"name": "recipe-name", "signals": ["signal-a", "signal-b"], "meaning": "what this combination proves", "severity": "watch|strong|active"}
  ],
  "learning_guidance": ["what the model should learn from this telemetry"],
  "fast_heuristics": ["quick decision rules for real-time scoring"],
  "counter_evasion": ["how attackers may adapt and how to counter"],
  "innovation_ideas": ["novel detection concepts beyond static rules"],
  "confidence_logic": ["how to score weak evidence, when to hold vs decide"],
  "feedback_gaps": ["what additional telemetry would improve future decisions"]
}
Rules:
- Settings must be realistic and conservative for THIS environment's telemetry.
- Durations are valid Go durations like "10s", "2m", "5m".
- Numeric integer values must be positive integers.
- shape_delta_threshold and beacon_jitter_cov_max are floats.
- Minimize false positives while preserving session/tunnel/beacon detection.
- New signals should be behavioral, not IOC-based. Prefer signals that survive attacker modification.
- Correlations should combine weak signals into strong judgments.
- Be creative and specific to what you observe in the telemetry data.
- Do not include markdown or extra fields.
`)
	user := "Calibration telemetry JSON:\n" + string(promptBytes)

	raw, err := requestCalibrationAI(ctx, provider, model, system, user)
	if err != nil && (isContextTooLargeError(err) || isRetryableRequestError(err) || promptMeta["prompt_mode"] == "compact") {
		compactBytes, _ := buildCalibrationPromptPayload(
			scope,
			duration,
			current,
			samples,
			roleCounts,
			stateCounts,
			topProcesses,
			processNameCounts,
			remotePortCounts,
			roleExamples,
			learning,
			true,
		)
		raw, err = requestCalibrationAI(ctx, provider, model, system, "Calibration telemetry JSON:\n"+string(compactBytes))
	}
	if err != nil {
		return aiCalibrationResult{}, err
	}

	parsed, err := parseAIResult(raw)
	if err != nil {
		return aiCalibrationResult{}, fmt.Errorf("invalid AI calibration response: %w", err)
	}

	normalized, guardrailNotes := mergeAndNormalizeSettings(current, parsed.Settings)
	final := aiCalibrationResult{
		Summary:         strings.TrimSpace(parsed.Summary),
		Recommendations: sanitizeRecommendations(parsed.Recommendations),
		Risks:           sanitizeRecommendations(parsed.Risks),
		Reasoning:       sanitizeRecommendations(parsed.Reasoning),
		Settings:        normalized,
	}
	if len(guardrailNotes) > 0 {
		summary := fmt.Sprintf("Applied %d safety guardrails to AI-proposed settings.", len(guardrailNotes))
		if len(guardrailNotes) > 0 {
			summary += " " + strings.Join(guardrailNotes[:minInt(2, len(guardrailNotes))], "; ")
		}
		final.Recommendations = append(final.Recommendations, summary)
		final.Recommendations = sanitizeRecommendations(final.Recommendations)
	}
	if len(final.Recommendations) == 0 {
		final.Recommendations = []string{"Model response contained no recommendations; baseline settings retained."}
	}
	if len(final.Risks) == 0 {
		final.Risks = []string{"Small threshold changes can alter alert volume; changes were guardrail-limited to reduce risk."}
	}
	if len(final.Reasoning) == 0 {
		final.Reasoning = []string{"Telemetry role/state distribution was used with conservative guardrails to avoid overfitting."}
	}
	if final.Summary == "" {
		final.Summary = "AI calibration completed. Recommended thresholds were generated from observed process behavior."
	}
	return final, nil
}

func buildCalibrationPromptPayload(
	scope string,
	duration time.Duration,
	current TuningSettings,
	samples []shared.Candidate,
	roleCounts map[string]int,
	stateCounts map[string]int,
	topProcesses []ProcessSummary,
	processNameCounts map[string]int,
	remotePortCounts map[string]int,
	roleExamples []processFeature,
	learning learningContext,
	forceCompact bool,
) ([]byte, map[string]string) {
	mode := "normal"
	targetBytes := maxPromptTargetBytes
	if forceCompact {
		mode = "compact"
		targetBytes = 9000
	}

	sampleLimit := 18
	roleExampleLimit := 10
	topProcessLimit := 6
	nameLimit := 12
	portLimit := 12
	learningTopLimit := 6
	learningNotesLimit := 4
	reasonLimit := 2
	signalLimit := 2
	includeSnapshot := true
	includeRoleExamples := true
	includeTopProcesses := true
	includeLearningNotes := true

	if forceCompact {
		sampleLimit = 8
		roleExampleLimit = 5
		topProcessLimit = 4
		nameLimit = 8
		portLimit = 8
		learningTopLimit = 4
		learningNotesLimit = 2
		reasonLimit = 1
		signalLimit = 1
	}

	var raw []byte
	for step := 0; step < 7; step++ {
		payload := map[string]any{
			"schema":          "proxywatch-calibration-v2",
			"scope":           trimPromptText(scope, 24),
			"duration":        duration.Round(time.Second).String(),
			"candidate_count": len(samples),
			"role_counts":     cloneIntMap(roleCounts),
			"state_counts":    cloneIntMap(stateCounts),
			"current_settings": map[string]any{
				"reverse_control_min_duration":   current.ReverseControlMinDuration,
				"long_lived_outbound_min_age":    current.LongLivedOutboundMinAge,
				"short_lived_outbound_max_age":   current.ShortLivedOutboundMaxAge,
				"beacon_sleep_threshold":         current.BeaconSleepThreshold,
				"active_window":                  current.ActiveWindow,
				"suspicion_window":               current.SuspicionWindow,
				"beacon_min_intervals":           current.BeaconMinIntervals,
				"reverse_sticky_score":           current.ReverseStickyScore,
				"forward_sticky_score":           current.ForwardStickyScore,
				"reverse_control_base_score":     current.ReverseControlBaseScore,
				"min_internal_targets_for_rev":   current.MinInternalTargetsForRev,
				"min_internal_ports_for_rev":     current.MinInternalPortsForRev,
				"outbound_only_external_cap":     current.OutboundOnlyExternalCap,
				"traffic_verified_penalty":       current.TrafficVerifiedPenalty,
				"verified_external_min_prefixes": current.VerifiedExternalPrefixes,
				"shape_delta_threshold":          current.ShapeDeltaThreshold,
				"beacon_jitter_cov_max":          current.BeaconJitterCoVMax,
			},
			"top_process_names": mapTopCounts(processNameCounts, nameLimit),
			"top_remote_ports":  mapTopCounts(remotePortCounts, portLimit),
			"learning": buildPromptLearningView(
				learning,
				learningTopLimit,
				learningNotesLimit,
				includeLearningNotes,
			),
			"context_notes": []string{
				"telemetry is summarized from environment collection and compacted for model context limits",
				"session/beacon/tunnel activity can be present during calibration; avoid blindly learning those traits as benign",
			},
		}

		if includeTopProcesses && topProcessLimit > 0 {
			payload["top_processes"] = compactProcessSummaries(topProcesses, topProcessLimit)
		}
		if includeRoleExamples && roleExampleLimit > 0 {
			payload["role_examples"] = compactProcessFeatures(roleExamples, roleExampleLimit, reasonLimit, signalLimit)
		}
		if includeSnapshot && sampleLimit > 0 {
			payload["sample_snapshot"] = buildPromptSampleSnapshot(samples, sampleLimit, reasonLimit, signalLimit)
		}

		encoded, err := json.Marshal(payload)
		if err != nil {
			break
		}
		raw = encoded
		if len(raw) <= targetBytes {
			break
		}

		mode = "compact"
		switch step {
		case 0:
			sampleLimit = maxInt(8, sampleLimit/2)
			roleExampleLimit = maxInt(5, roleExampleLimit/2)
			nameLimit = maxInt(8, nameLimit/2)
			portLimit = maxInt(8, portLimit/2)
		case 1:
			reasonLimit = 1
			signalLimit = 1
			topProcessLimit = maxInt(4, topProcessLimit/2)
			learningNotesLimit = minInt(2, learningNotesLimit)
		case 2:
			includeSnapshot = false
			roleExampleLimit = maxInt(4, roleExampleLimit/2)
			learningTopLimit = maxInt(4, learningTopLimit/2)
		case 3:
			includeRoleExamples = false
			includeLearningNotes = false
			nameLimit = maxInt(6, nameLimit/2)
			portLimit = maxInt(6, portLimit/2)
		case 4:
			includeTopProcesses = false
			learningTopLimit = maxInt(3, learningTopLimit/2)
		default:
		}
	}

	if len(raw) > maxPromptHardBytes || len(raw) == 0 {
		mode = "compact"
		minimal := map[string]any{
			"schema":               "proxywatch-calibration-v2-min",
			"scope":                trimPromptText(scope, 24),
			"duration":             duration.Round(time.Second).String(),
			"candidate_count":      len(samples),
			"role_counts":          cloneIntMap(roleCounts),
			"state_counts":         cloneIntMap(stateCounts),
			"learning_runs":        learning.Runs,
			"contamination_pct":    learning.ContaminationPct,
			"top_process_names":    mapTopCounts(processNameCounts, 4),
			"top_remote_ports":     mapTopCounts(remotePortCounts, 4),
			"context_compact_note": "payload reduced to aggregate-only mode to fit context limits",
		}
		raw, _ = json.Marshal(minimal)
	}

	meta := map[string]string{
		"prompt_mode":    mode,
		"prompt_bytes":   strconv.Itoa(len(raw)),
		"sample_count":   strconv.Itoa(len(samples)),
		"top_proc_count": strconv.Itoa(minInt(topProcessLimit, len(topProcesses))),
	}
	return raw, meta
}

func buildPromptLearningView(learning learningContext, topLimit, noteLimit int, includeNotes bool) map[string]any {
	view := map[string]any{
		"runs":                 learning.Runs,
		"weighted_samples":     fmt.Sprintf("%.1f", learning.WeightedSamples),
		"suspicious_ratio_pct": int(learning.SuspiciousRatio*100 + 0.5),
		"contamination_pct":    learning.ContaminationPct,
		"role_ratio_pct":       ratioMapToPercent(learning.RoleRatios),
		"state_ratio_pct":      ratioMapToPercent(learning.StateRatios),
	}
	if top := trimPromptList(learning.TopNormalProcesses, topLimit, 78); len(top) > 0 {
		view["top_normal_processes"] = top
	}
	if includeNotes {
		if notes := trimPromptList(learning.Notes, noteLimit, 120); len(notes) > 0 {
			view["notes"] = notes
		}
	}
	return view
}

func buildPromptSampleSnapshot(samples []shared.Candidate, limit, reasonLimit, signalLimit int) []map[string]any {
	if limit <= 0 || len(samples) == 0 {
		return nil
	}
	ordered := make([]shared.Candidate, len(samples))
	copy(ordered, samples)
	sort.SliceStable(ordered, func(i, j int) bool {
		pi := samplePromptPriority(ordered[i])
		pj := samplePromptPriority(ordered[j])
		if pi == pj {
			return strings.ToLower(promptProcessName(ordered[i])) < strings.ToLower(promptProcessName(ordered[j]))
		}
		return pi > pj
	})

	out := make([]map[string]any, 0, minInt(limit, len(ordered)))
	seen := make(map[string]bool, len(ordered))
	for _, sample := range ordered {
		if sample.Proc == nil {
			continue
		}
		key := shared.CandidateKey(sample)
		if seen[key] {
			continue
		}
		seen[key] = true

		item := map[string]any{
			"host":     trimPromptText(shared.DisplayHost(sample.Host), 20),
			"pid":      sample.Proc.Pid,
			"process":  trimPromptText(sample.Proc.Name, 34),
			"role":     shared.RoleFamily(sample.Role),
			"state":    sampleState(sample),
			"age_sec":  maxInt(sample.ControlDurationSeconds, 0),
			"inbound":  sample.InboundTotal,
			"outbound": sample.OutTotal,
			"external": sample.OutExternal,
			"internal": sample.OutInternal,
			"loopback": sample.OutLoopback,
		}
		if reasons := trimPromptList(sample.Reasons, reasonLimit, 96); len(reasons) > 0 {
			item["reasons"] = reasons
		}
		if signals := trimPromptList(sample.Signals, signalLimit, 72); len(signals) > 0 {
			item["signals"] = signals
		}
		out = append(out, item)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func compactProcessSummaries(rows []ProcessSummary, limit int) []map[string]any {
	if limit <= 0 || len(rows) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, minInt(limit, len(rows)))
	for i := 0; i < len(rows) && len(out) < limit; i++ {
		row := rows[i]
		out = append(out, map[string]any{
			"host":    trimPromptText(row.Host, 20),
			"pid":     row.PID,
			"process": trimPromptText(row.Process, 34),
			"role":    trimPromptText(row.Role, 16),
			"age":     trimPromptText(row.Age, 16),
			"state":   trimPromptText(row.State, 16),
		})
	}
	return out
}

func compactProcessFeatures(rows []processFeature, limit, reasonLimit, signalLimit int) []map[string]any {
	if limit <= 0 || len(rows) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, minInt(limit, len(rows)))
	for i := 0; i < len(rows) && len(out) < limit; i++ {
		row := rows[i]
		item := map[string]any{
			"host":     trimPromptText(row.Host, 20),
			"process":  trimPromptText(row.Process, 34),
			"pid":      row.PID,
			"role":     trimPromptText(row.RoleFamily, 16),
			"state":    trimPromptText(row.State, 16),
			"age_sec":  maxInt(row.AgeSeconds, 0),
			"inbound":  row.Inbound,
			"outbound": row.Outbound,
		}
		if reasons := trimPromptList(row.Reasons, reasonLimit, 96); len(reasons) > 0 {
			item["reasons"] = reasons
		}
		if signals := trimPromptList(row.Signals, signalLimit, 72); len(signals) > 0 {
			item["signals"] = signals
		}
		out = append(out, item)
	}
	return out
}

func ratioMapToPercent(src map[string]float64) map[string]int {
	if len(src) == 0 {
		return map[string]int{}
	}
	out := make(map[string]int, len(src))
	for key, value := range src {
		if value <= 0 {
			continue
		}
		out[key] = int(value*100 + 0.5)
	}
	return out
}

func trimPromptList(values []string, limit, maxLen int) []string {
	if limit <= 0 || len(values) == 0 {
		return nil
	}
	out := make([]string, 0, minInt(limit, len(values)))
	for _, value := range values {
		clean := trimPromptText(value, maxLen)
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

func trimPromptText(value string, maxLen int) string {
	value = strings.TrimSpace(value)
	if maxLen <= 0 || len(value) <= maxLen {
		return value
	}
	if maxLen <= 3 {
		return value[:maxLen]
	}
	return value[:maxLen-3] + "..."
}

func samplePromptPriority(sample shared.Candidate) int {
	priority := 0
	if sample.ActiveProxying {
		priority += 1000
	}
	if sample.StrongEvidence {
		priority += 450
	}
	switch sample.Role {
	case "control-session", "control-beacon":
		priority += 320
	case "control-tunnel", "control-pivot":
		priority += 280
	case "outbound":
		priority += 140
	case "listen":
		priority += 100
	default:
		priority += 50
	}
	priority += minInt(sample.OutTotal, 120)
	priority += minInt(sample.ControlDurationSeconds/5, 120)
	return priority
}

func promptProcessName(sample shared.Candidate) string {
	if sample.Proc == nil {
		return ""
	}
	return strings.TrimSpace(sample.Proc.Name)
}

func requestCalibrationAI(ctx context.Context, provider, model, system, user string) (string, error) {
	switch normalizeProvider(provider) {
	case "openai":
		return callOpenAI(ctx, model, system, user)
	case "anthropic":
		return callAnthropic(ctx, model, system, user)
	case "local":
		return callLocalLLM(ctx, model, system, user)
	default:
		return callOpenAI(ctx, model, system, user)
	}
}

func isContextTooLargeError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	indicators := []string{
		"maximum context length",
		"context length",
		"context window",
		"context_length_exceeded",
		"prompt is too long",
		"prompt too long",
		"too many tokens",
		"token limit",
		"max tokens",
		"input is too long",
		"request too large",
		"payload too large",
		"413",
	}
	for _, token := range indicators {
		if strings.Contains(msg, token) {
			return true
		}
	}
	return false
}

func callOpenAI(ctx context.Context, model, system, user string) (string, error) {
	apiKey := strings.TrimSpace(keystore.RuntimeValue("OPENAI_API_KEY"))
	if apiKey == "" {
		return "", fmt.Errorf("missing OPENAI_API_KEY")
	}
	baseURL := strings.TrimSpace(keystore.RuntimeValue("OPENAI_BASE_URL"))
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	baseURL, err := validateProviderBaseURL(baseURL, false)
	if err != nil {
		return "", err
	}
	// Try chat-completions first for compatibility with existing behavior.
	content, err := callOpenAIChatCompletions(ctx, baseURL, apiKey, model, system, user)
	if err == nil {
		return content, nil
	}
	// Fallback to Responses API when chat-completions is unsupported or strict.
	contentFallback, fallbackErr := callOpenAIResponses(ctx, baseURL, apiKey, model, system, user)
	if fallbackErr == nil {
		return contentFallback, nil
	}
	return "", fmt.Errorf("openai chat/completions failed: %v; responses fallback failed: %v", err, fallbackErr)
}

func callOpenAIChatCompletions(ctx context.Context, baseURL, apiKey, model, system, user string) (string, error) {
	url := strings.TrimRight(baseURL, "/") + "/chat/completions"
	reqBody := map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
		"response_format": map[string]string{
			"type": "json_object",
		},
	}
	raw, err := doJSONRequest(ctx, url, map[string]string{
		"Authorization": "Bearer " + apiKey,
	}, reqBody)
	if err != nil {
		return "", err
	}
	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", err
	}
	if len(parsed.Choices) == 0 {
		return "", fmt.Errorf("empty choices")
	}
	content := strings.TrimSpace(parsed.Choices[0].Message.Content)
	if content == "" {
		return "", fmt.Errorf("empty model content")
	}
	return content, nil
}

func callOpenAIResponses(ctx context.Context, baseURL, apiKey, model, system, user string) (string, error) {
	url := strings.TrimRight(baseURL, "/") + "/responses"
	reqBody := map[string]any{
		"model": model,
		"input": []map[string]any{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
	}
	raw, err := doJSONRequest(ctx, url, map[string]string{
		"Authorization": "Bearer " + apiKey,
	}, reqBody)
	if err != nil {
		return "", err
	}

	var parsed struct {
		OutputText string `json:"output_text"`
		Output     []struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", err
	}
	if strings.TrimSpace(parsed.OutputText) != "" {
		return strings.TrimSpace(parsed.OutputText), nil
	}
	for _, item := range parsed.Output {
		for _, content := range item.Content {
			if strings.TrimSpace(content.Text) != "" {
				return strings.TrimSpace(content.Text), nil
			}
		}
	}
	return "", fmt.Errorf("no text content returned")
}

func callAnthropic(ctx context.Context, model, system, user string) (string, error) {
	apiKey := strings.TrimSpace(keystore.RuntimeValue("ANTHROPIC_API_KEY"))
	if apiKey == "" {
		return "", fmt.Errorf("missing ANTHROPIC_API_KEY")
	}
	baseURL := strings.TrimSpace(keystore.RuntimeValue("ANTHROPIC_BASE_URL"))
	if baseURL == "" {
		baseURL = "https://api.anthropic.com/v1"
	}
	baseURL, err := validateProviderBaseURL(baseURL, false)
	if err != nil {
		return "", err
	}
	url := strings.TrimRight(baseURL, "/") + "/messages"

	reqBody := map[string]any{
		"model":       model,
		"max_tokens":  1800,
		"temperature": 0.1,
		"system":      system,
		"messages": []map[string]any{
			{
				"role": "user",
				"content": []map[string]string{
					{"type": "text", "text": user},
				},
			},
		},
	}
	raw, err := doJSONRequest(ctx, url, map[string]string{
		"x-api-key":         apiKey,
		"anthropic-version": "2023-06-01",
	}, reqBody)
	if err != nil {
		return "", err
	}

	var parsed struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", err
	}
	for _, part := range parsed.Content {
		if part.Type == "text" && strings.TrimSpace(part.Text) != "" {
			return part.Text, nil
		}
	}
	return "", fmt.Errorf("no text content returned")
}

func callLocalLLM(ctx context.Context, model, system, user string) (string, error) {
	baseURL := strings.TrimSpace(keystore.RuntimeValue("LOCAL_LLM_URL"))
	if baseURL == "" {
		return "", fmt.Errorf("missing LOCAL_LLM_URL")
	}
	baseURL, err := validateProviderBaseURL(baseURL, true)
	if err != nil {
		return "", err
	}
	apiKey := strings.TrimSpace(keystore.RuntimeValue("LOCAL_LLM_API_KEY"))
	if apiKey == "" {
		return "", fmt.Errorf("missing LOCAL_LLM_API_KEY")
	}
	url := baseURL
	if !strings.Contains(strings.ToLower(url), "/chat/completions") {
		url = strings.TrimRight(url, "/") + "/v1/chat/completions"
	}

	reqBody := map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
		"temperature": 0.1,
	}
	raw, err := doJSONRequest(ctx, url, map[string]string{
		"Authorization": "Bearer " + apiKey,
	}, reqBody)
	if err != nil {
		return "", err
	}

	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", err
	}
	if len(parsed.Choices) == 0 {
		return "", fmt.Errorf("empty choices")
	}
	content := strings.TrimSpace(parsed.Choices[0].Message.Content)
	if content == "" {
		return "", fmt.Errorf("empty model content")
	}
	return content, nil
}

func doJSONRequest(ctx context.Context, url string, headers map[string]string, body any) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	const maxAttempts = 2
	timeout := calibrationHTTPTimeout()
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		for k, v := range headers {
			if strings.TrimSpace(v) != "" {
				req.Header.Set(k, v)
			}
		}

		client := &http.Client{Timeout: timeout}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			if attempt < maxAttempts && isRetryableRequestError(err) {
				if !sleepWithContext(ctx, time.Duration(attempt*2)*time.Second) {
					return nil, ctx.Err()
				}
				continue
			}
			return nil, err
		}

		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
		if err := resp.Body.Close(); err != nil {
			return nil, err
		}
		if resp.StatusCode/100 == 2 {
			return raw, nil
		}

		body := strings.TrimSpace(string(raw))
		if len(body) > 500 {
			body = body[:500] + "..."
		}
		msg := fmt.Errorf("api %s returned status %d: %s", url, resp.StatusCode, body)
		lastErr = msg
		if attempt < maxAttempts && isRetryableStatus(resp.StatusCode) {
			if !sleepWithContext(ctx, time.Duration(attempt*2)*time.Second) {
				return nil, ctx.Err()
			}
			continue
		}
		return nil, msg
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("api request failed without response")
}

func calibrationHTTPTimeout() time.Duration {
	raw := strings.TrimSpace(keystore.RuntimeValue("CALIBRATION_HTTP_TIMEOUT"))
	if raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			if parsed > 5*time.Minute {
				parsed = 5 * time.Minute
			}
			return parsed
		}
	}
	return 2 * time.Minute
}

func sleepWithContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func isRetryableStatus(status int) bool {
	switch status {
	case http.StatusRequestTimeout,
		http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return status >= 500
	}
}

func isRetryableRequestError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "context deadline exceeded") ||
		strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "tls handshake timeout") ||
		strings.Contains(msg, "temporary") {
		return true
	}
	return false
}

func validateProviderBaseURL(raw string, allowLoopbackHTTP bool) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("missing provider base URL")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid provider URL: %w", err)
	}
	if strings.TrimSpace(parsed.Host) == "" || strings.TrimSpace(parsed.Scheme) == "" {
		return "", fmt.Errorf("invalid provider URL: missing scheme or host")
	}
	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "https":
		return strings.TrimRight(parsed.String(), "/"), nil
	case "http":
		if allowLoopbackHTTP && isLoopbackHost(parsed.Hostname()) {
			return strings.TrimRight(parsed.String(), "/"), nil
		}
		return "", fmt.Errorf("insecure provider URL %q: use https (http allowed only for localhost)", trimmed)
	default:
		return "", fmt.Errorf("unsupported provider URL scheme %q", parsed.Scheme)
	}
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// RequestSIEMAI exposes the shared calibration AI request pipeline for the
// SIEM package, so SIEM generation can remain outside the calibration package
// while reusing provider/runtime auth and retry behavior.
func RequestSIEMAI(ctx context.Context, provider, model, system, user string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	return requestCalibrationAI(ctx, provider, model, system, user)
}
