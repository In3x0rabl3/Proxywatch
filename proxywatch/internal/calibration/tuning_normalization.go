package calibration

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"proxywatch/internal/shared"
)

func parseAIResult(raw string) (aiCalibrationResult, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return aiCalibrationResult{}, fmt.Errorf("empty response")
	}
	// Remove fenced code blocks if model still wrapped JSON.
	text = strings.TrimPrefix(text, "```json")
	text = strings.TrimPrefix(text, "```")
	text = strings.TrimSuffix(text, "```")
	text = strings.TrimSpace(text)

	var out aiCalibrationResult
	if err := json.Unmarshal([]byte(text), &out); err == nil {
		return out, nil
	}

	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start < 0 || end <= start {
		return aiCalibrationResult{}, fmt.Errorf("response did not contain JSON object")
	}
	if err := json.Unmarshal([]byte(text[start:end+1]), &out); err != nil {
		return aiCalibrationResult{}, err
	}
	return out, nil
}

func extractFeatureViews(samples []shared.Candidate) (map[string]int, map[string]int, []processFeature) {
	nameCounts := make(map[string]int)
	portCounts := make(map[string]int)
	features := make([]processFeature, 0, minInt(12, len(samples)))

	seen := make(map[string]bool)
	for _, sample := range samples {
		if sample.Proc == nil {
			continue
		}

		name := strings.ToLower(strings.TrimSpace(sample.Proc.Name))
		if name == "" {
			name = "(unknown)"
		}
		nameCounts[name]++

		for _, cn := range sample.Conns {
			if cn.RemotePort <= 0 {
				continue
			}
			portCounts[strconv.Itoa(cn.RemotePort)]++
		}

		key := shared.CandidateKey(sample)
		if seen[key] || len(features) >= 12 {
			continue
		}
		seen[key] = true

		state := "watch"
		if sample.ActiveProxying {
			state = "active"
		} else if sample.StrongEvidence {
			state = "strong"
		}
		features = append(features, processFeature{
			Host:       shared.DisplayHost(sample.Host),
			Process:    sample.Proc.Name,
			PID:        sample.Proc.Pid,
			RoleFamily: shared.RoleFamily(sample.Role),
			State:      state,
			AgeSeconds: sample.ControlDurationSeconds,
			Inbound:    sample.InboundTotal,
			Outbound:   sample.OutTotal,
			Reasons:    limitStrings(sample.Reasons, 3),
			Signals:    limitStrings(sample.Signals, 3),
		})
	}

	return mapTopCounts(nameCounts, 20), mapTopCounts(portCounts, 20), features
}

func mapTopCounts(src map[string]int, limit int) map[string]int {
	type kv struct {
		k string
		v int
	}
	items := make([]kv, 0, len(src))
	for k, v := range src {
		items = append(items, kv{k: k, v: v})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].v == items[j].v {
			return items[i].k < items[j].k
		}
		return items[i].v > items[j].v
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	out := make(map[string]int, len(items))
	for _, item := range items {
		out[item.k] = item.v
	}
	return out
}

func limitStrings(values []string, limit int) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, minInt(limit, len(values)))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		out = append(out, v)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func mergeAndNormalizeSettings(base, proposed TuningSettings) (TuningSettings, []string) {
	out := base
	notes := make([]string, 0, 8)

	out.ReverseControlMinDuration = normalizeDurationSetting(
		"reverse_control_min_duration",
		base.ReverseControlMinDuration,
		proposed.ReverseControlMinDuration,
		5*time.Second,
		10*time.Minute,
		0.4,
		2.5,
		&notes,
	)
	out.LongLivedOutboundMinAge = normalizeDurationSetting(
		"long_lived_outbound_min_age",
		base.LongLivedOutboundMinAge,
		proposed.LongLivedOutboundMinAge,
		20*time.Second,
		20*time.Minute,
		0.5,
		2.5,
		&notes,
	)
	out.ShortLivedOutboundMaxAge = normalizeDurationSetting(
		"short_lived_outbound_max_age",
		base.ShortLivedOutboundMaxAge,
		proposed.ShortLivedOutboundMaxAge,
		3*time.Second,
		5*time.Minute,
		0.5,
		2.0,
		&notes,
	)
	out.BeaconSleepThreshold = normalizeDurationSetting(
		"beacon_sleep_threshold",
		base.BeaconSleepThreshold,
		proposed.BeaconSleepThreshold,
		10*time.Second,
		30*time.Minute,
		0.5,
		3.0,
		&notes,
	)
	out.ActiveWindow = normalizeDurationSetting(
		"active_window",
		base.ActiveWindow,
		proposed.ActiveWindow,
		2*time.Second,
		2*time.Minute,
		0.5,
		2.0,
		&notes,
	)
	out.SuspicionWindow = normalizeDurationSetting(
		"suspicion_window",
		base.SuspicionWindow,
		proposed.SuspicionWindow,
		30*time.Second,
		30*time.Minute,
		0.5,
		2.0,
		&notes,
	)

	out.BeaconMinIntervals = normalizeIntSetting("beacon_min_intervals", base.BeaconMinIntervals, proposed.BeaconMinIntervals, 1, 10, 4, &notes)
	out.ReverseStickyScore = normalizeIntSetting("reverse_sticky_score", base.ReverseStickyScore, proposed.ReverseStickyScore, 10, 250, 80, &notes)
	out.ForwardStickyScore = normalizeIntSetting("forward_sticky_score", base.ForwardStickyScore, proposed.ForwardStickyScore, 10, 250, 80, &notes)
	out.ReverseControlBaseScore = normalizeIntSetting("reverse_control_base_score", base.ReverseControlBaseScore, proposed.ReverseControlBaseScore, 1, 200, 60, &notes)
	out.MinInternalTargetsForRev = normalizeIntSetting("min_internal_targets_for_rev", base.MinInternalTargetsForRev, proposed.MinInternalTargetsForRev, 1, 100, 20, &notes)
	out.MinInternalPortsForRev = normalizeIntSetting("min_internal_ports_for_rev", base.MinInternalPortsForRev, proposed.MinInternalPortsForRev, 1, 100, 20, &notes)
	out.OutboundOnlyExternalCap = normalizeIntSetting("outbound_only_external_cap", base.OutboundOnlyExternalCap, proposed.OutboundOnlyExternalCap, 1, 500, 80, &notes)
	out.TrafficVerifiedPenalty = normalizeIntSetting("traffic_verified_penalty", base.TrafficVerifiedPenalty, proposed.TrafficVerifiedPenalty, 1, 500, 100, &notes)
	out.VerifiedExternalPrefixes = normalizeIntSetting("verified_external_min_prefixes", base.VerifiedExternalPrefixes, proposed.VerifiedExternalPrefixes, 1, 200, 40, &notes)
	out.ShapeDeltaThreshold = normalizeFloatSetting("shape_delta_threshold", base.ShapeDeltaThreshold, proposed.ShapeDeltaThreshold, 0.05, 1.5, 0.35, &notes)
	out.BeaconJitterCoVMax = normalizeFloatSetting("beacon_jitter_cov_max", base.BeaconJitterCoVMax, proposed.BeaconJitterCoVMax, 0.2, 5.0, 0.5, &notes)

	return out, notes
}

func normalizeDurationSetting(
	name, baseRaw, proposedRaw string,
	hardMin, hardMax time.Duration,
	softLowerFactor, softUpperFactor float64,
	notes *[]string,
) string {
	base, err := time.ParseDuration(strings.TrimSpace(baseRaw))
	if err != nil || base <= 0 {
		base = hardMin
	}
	raw := strings.TrimSpace(proposedRaw)
	if raw == "" {
		return base.String()
	}
	v, err := time.ParseDuration(raw)
	if err != nil || v <= 0 {
		*notes = append(*notes, name+" invalid, kept baseline")
		return base.String()
	}

	if v < hardMin {
		v = hardMin
		*notes = append(*notes, name+" clamped to minimum")
	}
	if hardMax > 0 && v > hardMax {
		v = hardMax
		*notes = append(*notes, name+" clamped to maximum")
	}

	softMin := time.Duration(float64(base) * softLowerFactor)
	softMax := time.Duration(float64(base) * softUpperFactor)
	if softMin < hardMin {
		softMin = hardMin
	}
	if hardMax > 0 && softMax > hardMax {
		softMax = hardMax
	}
	if softMax > 0 && v > softMax {
		v = softMax
		*notes = append(*notes, name+" limited to safe growth")
	}
	if v < softMin {
		v = softMin
		*notes = append(*notes, name+" limited to safe reduction")
	}
	if v <= 0 {
		v = hardMin
	}
	return v.Round(time.Second).String()
}

func normalizeIntSetting(name string, base, proposed, hardMin, hardMax, maxDelta int, notes *[]string) int {
	if base <= 0 {
		base = hardMin
	}
	if proposed <= 0 {
		return base
	}
	v := proposed
	if v < hardMin {
		v = hardMin
		*notes = append(*notes, name+" clamped to minimum")
	}
	if v > hardMax {
		v = hardMax
		*notes = append(*notes, name+" clamped to maximum")
	}

	softMin := base - maxDelta
	softMax := base + maxDelta
	if softMin < hardMin {
		softMin = hardMin
	}
	if softMax > hardMax {
		softMax = hardMax
	}
	if v < softMin {
		v = softMin
		*notes = append(*notes, name+" limited to safe reduction")
	}
	if v > softMax {
		v = softMax
		*notes = append(*notes, name+" limited to safe growth")
	}
	return v
}

func normalizeFloatSetting(name string, base, proposed, hardMin, hardMax, maxDelta float64, notes *[]string) float64 {
	if base <= 0 {
		base = hardMin
	}
	if proposed <= 0 {
		return base
	}
	v := proposed
	if v < hardMin {
		v = hardMin
		*notes = append(*notes, name+" clamped to minimum")
	}
	if v > hardMax {
		v = hardMax
		*notes = append(*notes, name+" clamped to maximum")
	}
	softMin := base - maxDelta
	softMax := base + maxDelta
	if softMin < hardMin {
		softMin = hardMin
	}
	if softMax > hardMax {
		softMax = hardMax
	}
	if v < softMin {
		v = softMin
		*notes = append(*notes, name+" limited to safe reduction")
	}
	if v > softMax {
		v = softMax
		*notes = append(*notes, name+" limited to safe growth")
	}
	return v
}

func sanitizeRecommendations(recs []string) []string {
	out := make([]string, 0, len(recs))
	for _, rec := range recs {
		rec = strings.TrimSpace(rec)
		if rec == "" {
			continue
		}
		out = append(out, rec)
		if len(out) >= 6 {
			break
		}
	}
	return out
}

func trimCalibrationError(msg string, maxLen int) string {
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

func parseDurationOrDefault(raw string, fallback string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, fmt.Errorf("must be > 0")
	}
	return d, nil
}

func adjustDuration(raw string, delta, min, max time.Duration) string {
	base, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil || base <= 0 {
		base = min
	}
	base += delta
	if base < min {
		base = min
	}
	if max > 0 && base > max {
		base = max
	}
	return base.String()
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

func normalizeProvider(provider string) string {
	p := strings.ToLower(strings.TrimSpace(provider))
	switch p {
	case "openai":
		return p
	case "anthropic":
		return p
	case "local":
		return p
	case "builtin":
		// Backward compatibility for old profile/report data.
		return "openai"
	case "a", "anthropic api":
		return "anthropic"
	case "openai api":
		return "openai"
	default:
		// Accept title-cased labels from menu selection paths.
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
}

func sanitizeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "openai"
	}
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			out = append(out, r)
		} else {
			out = append(out, '-')
		}
	}
	return strings.Trim(string(out), "-")
}

func defaultInt(v, fallback int) int {
	if v <= 0 {
		return fallback
	}
	return v
}

func defaultFloat(v, fallback float64) float64 {
	if v <= 0 {
		return fallback
	}
	return v
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func clampFloat(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
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
