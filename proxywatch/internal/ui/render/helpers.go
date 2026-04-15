package render

import (
	"strings"

	"proxywatch/internal/shared"
)

// Helper functions duplicated from internal/ui to avoid circular imports.
// These are private to the render package.

func refreshCollectSources(app *shared.AppState) {
	if app == nil {
		return
	}
	opts := collectSourceOptions(app)
	app.CollectSourceOpts = opts
	if len(opts) == 0 {
		app.CollectSource = "all"
		app.CollectSourceIndex = 0
		return
	}
	current := strings.TrimSpace(app.CollectSource)
	if current == "" {
		current = "all"
	}
	idx := -1
	for i, opt := range opts {
		if opt == current {
			idx = i
			break
		}
	}
	if idx < 0 {
		for i, opt := range opts {
			if strings.EqualFold(opt, current) {
				idx = i
				break
			}
		}
	}
	if idx < 0 {
		idx = 0
	}
	app.CollectSourceIndex = idx
	app.CollectSource = opts[idx]
}

func collectSourceOptions(app *shared.AppState) []string {
	opts := []string{"all"}
	if app == nil {
		return opts
	}
	hosts := make([]string, 0, 16)
	seen := make(map[string]bool)
	addHost := func(host string) {
		host = strings.TrimSpace(host)
		if host == "" {
			return
		}
		key := strings.ToLower(host)
		if seen[key] {
			return
		}
		seen[key] = true
		hosts = append(hosts, host)
	}
	for _, hs := range app.HostSummaries {
		addHost(hs.Host)
	}
	for _, c := range app.Candidates {
		addHost(c.Host)
	}
	opts = append(opts, hosts...)
	return opts
}

func dashboardHostListMode(app *shared.AppState) bool {
	if app == nil {
		return false
	}
	return strings.TrimSpace(app.LocalHost) == "" && !app.DashboardHostProcessView
}

func dashboardProcessCandidates(app *shared.AppState) []shared.Candidate {
	if app == nil {
		return nil
	}
	base := app.Candidates
	if strings.TrimSpace(app.LocalHost) == "" && app.DashboardHostProcessView {
		target := strings.TrimSpace(app.DashboardHostKey)
		if target == "" {
			return nil
		}
		filtered := make([]shared.Candidate, 0, len(app.Candidates))
		for _, cand := range app.Candidates {
			if strings.EqualFold(shared.DisplayHost(cand.Host), target) {
				filtered = append(filtered, cand)
			}
		}
		base = filtered
	}

	if len(base) == 0 {
		return nil
	}

	byKey := make(map[string]shared.Candidate, len(base))
	for _, cand := range base {
		key := shared.CandidateKey(cand)
		if existing, ok := byKey[key]; !ok || shared.CandidateLess(cand, existing) {
			byKey[key] = cand
		}
	}
	out := make([]shared.Candidate, 0, len(byKey))
	for _, cand := range byKey {
		out = append(out, cand)
	}
	out = sortedCandidates(out, app.SortPreset)
	return out
}

func sortedCandidates(cands []shared.Candidate, preset string) []shared.Candidate {
	// Delegate to common.SortedCandidates.
	return commonSortedCandidates(cands, preset)
}

func selectedDashboardProcessIndex(app *shared.AppState, view []shared.Candidate) int {
	if len(view) == 0 {
		return -1
	}
	if key := strings.TrimSpace(app.SelectedKey); key != "" {
		for i := range view {
			if shared.CandidateKey(view[i]) == key {
				return i
			}
		}
	}
	if app.SelectedIdx >= 0 && app.SelectedIdx < len(app.Candidates) {
		key := shared.CandidateKey(app.Candidates[app.SelectedIdx])
		for i := range view {
			if shared.CandidateKey(view[i]) == key {
				return i
			}
		}
	}
	return 0
}

func whitelistProcessCandidates(app *shared.AppState) []shared.Candidate {
	if app == nil {
		return nil
	}
	if len(app.SnapshotCandidates) > 0 {
		return app.SnapshotCandidates
	}
	return app.Candidates
}

func selectedWhitelistProcessCandidate(app *shared.AppState) (shared.Candidate, bool) {
	if app == nil {
		return shared.Candidate{}, false
	}
	procs := whitelistProcessCandidates(app)
	if len(procs) == 0 {
		return shared.Candidate{}, false
	}
	if app.WhitelistProcessSelected < 0 {
		app.WhitelistProcessSelected = 0
	}
	if app.WhitelistProcessSelected >= len(procs) {
		app.WhitelistProcessSelected = len(procs) - 1
	}
	if app.WhitelistProcessSelected >= 0 && app.WhitelistProcessSelected < len(procs) {
		return procs[app.WhitelistProcessSelected], true
	}
	return shared.Candidate{}, false
}

func keystoreFieldVisible(field int) bool {
	switch field {
	case keystoreFieldOpenAIBaseURL, keystoreFieldAnthropicBaseURL,
		keystoreFieldCalibrationTimeout,
		keystoreFieldDisableClientCert, keystoreFieldTrustOnFirstUse,
		keystoreFieldMethod, keystoreFieldNew,
		keystoreFieldBuildkiteToken, keystoreFieldAWSAccessKey, keystoreFieldAWSSecretKey,
		keystoreFieldAzureClientID, keystoreFieldAzureClientSecret, keystoreFieldGCPServiceKey,
		keystoreFieldSlackBotToken, keystoreFieldDiscordBotToken, keystoreFieldTelegramBotKey,
		keystoreFieldFirebaseKey, keystoreFieldTeamsAuth, keystoreFieldGitLabToken:
		return false
	}
	return field >= keystoreFieldOpenAIKey && field <= keystoreFieldMax
}

func keystoreFieldEnvKey(field int) (string, bool) {
	switch field {
	case keystoreFieldOpenAIKey:
		return "OPENAI_API_KEY", true
	case keystoreFieldOpenAIBaseURL:
		return "OPENAI_BASE_URL", true
	case keystoreFieldAnthropicKey:
		return "ANTHROPIC_API_KEY", true
	case keystoreFieldAnthropicBaseURL:
		return "ANTHROPIC_BASE_URL", true
	case keystoreFieldLocalLLMURL:
		return "LOCAL_LLM_URL", true
	case keystoreFieldLocalLLMAPIKey:
		return "LOCAL_LLM_API_KEY", true
	case keystoreFieldCalibrationTimeout:
		return "CALIBRATION_HTTP_TIMEOUT", true
	case keystoreFieldProxyhoundURL:
		return "BLOODHOUND_API_URL", true
	case keystoreFieldProxyhoundToken:
		return "BLOODHOUND_API_TOKEN", true
	case keystoreFieldProxyhoundTokenID:
		return "BLOODHOUND_API_TOKEN_ID", true
	case keystoreFieldTLSDir:
		return "PROXYWATCH_TLS_DIR", true
	case keystoreFieldAgentToken:
		return "PROXYWATCH_AGENT_TOKEN", true
	case keystoreFieldDisableClientCert:
		return "PROXYWATCH_DISABLE_CLIENT_CERT", true
	case keystoreFieldTrustOnFirstUse:
		return "PROXYWATCH_TRUST_ON_FIRST_USE", true
	case keystoreFieldGitHubToken:
		return "GITHUB_TOKEN", true
	case keystoreFieldBuildkiteToken:
		return "BUILDKITE_TOKEN", true
	case keystoreFieldAWSAccessKey:
		return "AWS_ACCESS_KEY_ID", true
	case keystoreFieldAWSSecretKey:
		return "AWS_SECRET_ACCESS_KEY", true
	case keystoreFieldAzureClientID:
		return "AZURE_CLIENT_ID", true
	case keystoreFieldAzureClientSecret:
		return "AZURE_CLIENT_SECRET", true
	case keystoreFieldGCPServiceKey:
		return "GCP_SERVICE_KEY", true
	case keystoreFieldSlackBotToken:
		return "SLACK_BOT_TOKEN", true
	case keystoreFieldDiscordBotToken:
		return "DISCORD_BOT_TOKEN", true
	case keystoreFieldTelegramBotKey:
		return "TELEGRAM_BOT_KEY", true
	case keystoreFieldFirebaseKey:
		return "FIREBASE_KEY", true
	case keystoreFieldTeamsAuth:
		return "TEAMS_DEADDROP_AUTH", true
	case keystoreFieldGitLabToken:
		return "GITLAB_TOKEN", true
	default:
		return "", false
	}
}

func nonEmptyValue(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value != "" {
		return value
	}
	return fallback
}

func roleSortMenuLabels() []string {
	choices := roleSortMenuChoices()
	labels := make([]string, 0, len(choices))
	for _, choice := range choices {
		if choice.kind == "sort" {
			labels = append(labels, "sort: "+choice.value)
			continue
		}
		labels = append(labels, "role: "+choice.value)
	}
	return labels
}

type roleSortMenuChoice struct {
	kind  string
	value string
}

func roleSortMenuChoices() []roleSortMenuChoice {
	var choices []roleSortMenuChoice
	for _, r := range []string{"recommended", "all", "control-channel", "control-pivot", "listener", "outbound"} {
		choices = append(choices, roleSortMenuChoice{kind: "role", value: r})
	}
	for _, s := range []string{"default", "host", "role", "age", "state", "pid", "process"} {
		choices = append(choices, roleSortMenuChoice{kind: "sort", value: s})
	}
	return choices
}

// commonSortedCandidates is a thin wrapper that delegates to common.SortedCandidates.
// Imported via the common_bridge.go file.
