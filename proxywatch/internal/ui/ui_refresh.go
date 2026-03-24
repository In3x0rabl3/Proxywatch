package ui

import (
	"path/filepath"
	"sort"
	"strings"
	"time"

	"proxywatch/internal/bloodhound"
	"proxywatch/internal/shared"
)

func beginRefresh(app *shared.AppState, scanner shared.Scanner, refreshCh chan<- refreshResult, inFlight *bool) {
	if *inFlight {
		return
	}
	*inFlight = true

	selectionKeyAtStart := app.SelectedKey
	go func() {
		tmp := *app
		tmp.Screen = nil
		scanner.Refresh(&tmp)
		refreshCh <- refreshResult{
			candidates:          tmp.Candidates,
			snapshotCandidates:  tmp.SnapshotCandidates,
			hostSummaries:       tmp.HostSummaries,
			lastError:           tmp.LastError,
			lastUpdate:          tmp.LastUpdate,
			selectedKey:         tmp.SelectedKey,
			selectedIdx:         tmp.SelectedIdx,
			selectionKeyAtStart: selectionKeyAtStart,
		}
	}()
}

func applyRefreshResult(app *shared.AppState, res refreshResult) {
	app.Candidates = res.candidates
	app.SnapshotCandidates = res.snapshotCandidates
	app.HostSummaries = res.hostSummaries
	app.LastError = res.lastError
	app.LastUpdate = res.lastUpdate

	if len(app.Candidates) == 0 {
		app.SelectedIdx = -1
		app.SelectedKey = ""
		resortCandidates(app)
		return
	}

	desiredKey := res.selectedKey
	if app.SelectedKey != res.selectionKeyAtStart {
		desiredKey = app.SelectedKey
	} else if res.selectedIdx >= 0 && res.selectedIdx < len(app.Candidates) {
		desiredKey = shared.CandidateKey(app.Candidates[res.selectedIdx])
	}
	app.SelectedKey = desiredKey
	resortCandidates(app)
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

func findCandidateIndexByKey(cands []shared.Candidate, key string) int {
	key = strings.TrimSpace(key)
	if key == "" {
		return -1
	}
	for i := range cands {
		if shared.CandidateKey(cands[i]) == key {
			return i
		}
	}
	return -1
}

func resortCandidates(app *shared.AppState) {
	if app == nil {
		return
	}
	defer refreshCollectSources(app)
	selectedHostKey := strings.TrimSpace(app.DashboardHostKey)
	selectedProcessKey := ""
	if proc, ok := selectedWhitelistProcessCandidate(app); ok {
		selectedProcessKey = shared.CandidateKey(proc)
	}
	app.HostSummaries = sortHostSummaries(app.HostSummaries)
	if strings.TrimSpace(app.LocalHost) == "" {
		if selectedHostKey != "" {
			for i := range app.HostSummaries {
				if strings.EqualFold(app.HostSummaries[i].Host, selectedHostKey) {
					app.DashboardHostSelected = i
					app.DashboardHostKey = app.HostSummaries[i].Host
					break
				}
			}
		}
		if len(app.HostSummaries) == 0 {
			app.DashboardHostSelected = -1
			app.DashboardHostKey = ""
			app.DashboardHostProcessView = false
		} else {
			if app.DashboardHostSelected < 0 || app.DashboardHostSelected >= len(app.HostSummaries) {
				app.DashboardHostSelected = 0
			}
			app.DashboardHostKey = app.HostSummaries[app.DashboardHostSelected].Host
			if app.DashboardHostProcessView {
				found := false
				for _, summary := range app.HostSummaries {
					if strings.EqualFold(summary.Host, app.DashboardHostKey) {
						found = true
						break
					}
				}
				if !found {
					app.DashboardHostProcessView = false
				}
			}
		}
	}
	app.SnapshotCandidates = sortedCandidates(app.SnapshotCandidates, app.SortPreset)
	if selectedProcessKey != "" {
		if idx := findCandidateIndexByKey(app.SnapshotCandidates, selectedProcessKey); idx >= 0 {
			app.WhitelistProcessSelected = idx
		}
	}
	app.Candidates = sortedCandidates(app.Candidates, app.SortPreset)
	if len(app.Candidates) == 0 {
		app.SelectedIdx = -1
		app.SelectedKey = ""
		return
	}
	if strings.TrimSpace(app.LocalHost) == "" && app.DashboardHostProcessView {
		view := dashboardProcessCandidates(app)
		if len(view) == 0 {
			app.SelectedIdx = -1
			app.SelectedKey = ""
			return
		}
		syncDashboardProcessSelection(app, view, selectedDashboardProcessIndex(app, view))
		return
	}
	if strings.TrimSpace(app.SelectedKey) != "" {
		if idx := FindIndexByKey(app.Candidates, app.SelectedKey); idx >= 0 {
			app.SelectedIdx = idx
			return
		}
	}
	if app.SelectedIdx < 0 || app.SelectedIdx >= len(app.Candidates) {
		app.SelectedIdx = 0
	}
	app.SelectedKey = shared.CandidateKey(app.Candidates[app.SelectedIdx])
}

func sortHostSummaries(summaries []shared.HostSummary) []shared.HostSummary {
	out := make([]shared.HostSummary, len(summaries))
	copy(out, summaries)
	sort.SliceStable(out, func(i, j int) bool {
		iConnected := strings.EqualFold(strings.TrimSpace(out[i].Status), "connected")
		jConnected := strings.EqualFold(strings.TrimSpace(out[j].Status), "connected")
		if iConnected != jConnected {
			return iConnected
		}
		hostI := strings.ToLower(strings.TrimSpace(out[i].Host))
		hostJ := strings.ToLower(strings.TrimSpace(out[j].Host))
		if hostI != hostJ {
			return hostI < hostJ
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out
}

func updateCollectionState(app *shared.AppState) {
	if !app.CollectActive {
		return
	}
	app.CollectData = append(app.CollectData, collectCandidatesForSource(app)...)

	if time.Now().After(app.CollectUntil) {
		finalizeCollection(app)
	}
}

func finalizeCollection(app *shared.AppState) {
	payload := bloodhound.BuildGraph(app.CollectData)
	if err := bloodhound.WriteJSON(app.CollectOutput, payload); err != nil {
		setCollectStatus(app, "collection failed: "+err.Error(), true)
	} else if configured, reason := bloodhound.UploadConfigStatus(); !configured {
		setCollectStatus(app, "collection written: "+app.CollectOutput+" (upload skipped: "+reason+")", false)
	} else if err := bloodhound.UploadIfConfigured(filepath.Base(app.CollectOutput), payload); err != nil {
		setCollectStatus(app, "collection written, upload failed: "+err.Error(), true)
	} else {
		setCollectStatus(app, "collection written: "+app.CollectOutput, false)
	}
	app.CollectActive = false
	app.CollectStartedAt = time.Time{}
	app.CollectData = nil
	app.CollectEditing = false
}

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
	idx := findIndex(opts, current)
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
		if host == "" || strings.EqualFold(host, "all") {
			return
		}
		key := strings.ToLower(host)
		if seen[key] {
			return
		}
		seen[key] = true
		hosts = append(hosts, host)
	}
	addHost(shared.DefaultHostID(strings.TrimSpace(app.LocalHost)))
	for _, hs := range app.HostSummaries {
		addHost(shared.DisplayHost(hs.Host))
	}
	for _, c := range app.Candidates {
		addHost(shared.DisplayHost(c.Host))
	}
	for _, c := range app.SnapshotCandidates {
		addHost(shared.DisplayHost(c.Host))
	}
	sort.SliceStable(hosts, func(i, j int) bool {
		return strings.ToLower(hosts[i]) < strings.ToLower(hosts[j])
	})
	opts = append(opts, hosts...)
	return opts
}

func collectCandidatesForSource(app *shared.AppState) []shared.Candidate {
	if app == nil {
		return nil
	}
	source := strings.TrimSpace(app.CollectSource)
	if source == "" || strings.EqualFold(source, "all") {
		return app.Candidates
	}
	filtered := make([]shared.Candidate, 0, len(app.Candidates))
	for _, cand := range app.Candidates {
		if strings.EqualFold(shared.DisplayHost(cand.Host), source) {
			filtered = append(filtered, cand)
		}
	}
	return filtered
}

func trimLastRune(s string) string {
	if s == "" {
		return s
	}
	runes := []rune(s)
	return string(runes[:len(runes)-1])
}

func clampChoice(i, size int) int {
	if size <= 0 {
		return 0
	}
	if i < 0 {
		return 0
	}
	if i >= size {
		return size - 1
	}
	return i
}

func indexOf(items []string, value string) int {
	for i := range items {
		if items[i] == value {
			return i
		}
	}
	return 0
}

func indexOfDuration(items []string, value time.Duration) int {
	for i := range items {
		d, err := time.ParseDuration(items[i])
		if err != nil {
			continue
		}
		if d == value {
			return i
		}
	}
	return 0
}

func findIndex(items []string, value string) int {
	for i := range items {
		if items[i] == value {
			return i
		}
	}
	return -1
}

func stepOption(options []string, current string, dir int) string {
	if len(options) == 0 {
		return current
	}
	idx := findIndex(options, current)
	if idx < 0 {
		idx = 0
	}
	if dir > 0 {
		idx = (idx + 1) % len(options)
	} else if dir < 0 {
		idx = (idx - 1 + len(options)) % len(options)
	}
	return options[idx]
}

func containsString(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func safePreset(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func setCollectStatus(app *shared.AppState, msg string, isError bool) {
	app.LastError = msg
	app.CollectStatusText = msg
	app.CollectStatusError = isError
	now := time.Now()
	if isError {
		app.CollectStatusUntil = now.Add(10 * time.Second)
		return
	}
	app.CollectStatusUntil = now.Add(5 * time.Second)
}

func setCalibrationStatus(app *shared.AppState, msg string, isError bool) {
	app.LastError = msg
	app.CalibrateStatusText = msg
	app.CalibrateStatusError = isError
	now := time.Now()
	if isError {
		app.CalibrateStatusUntil = now.Add(10 * time.Second)
		return
	}
	app.CalibrateStatusUntil = now.Add(5 * time.Second)
}

func applyRolePreset(app *shared.AppState, preset string) {
	app.RolePreset = preset
	switch preset {
	case "recommended":
		app.RoleFilterOverride = shared.ParseRoleFilter("session,beacon,tunnel")
	case "all":
		app.RoleFilterOverride = shared.ParseRoleFilter("all")
	case "control":
		app.RoleFilterOverride = shared.ParseRoleFilter("control")
	case "reverse":
		app.RoleFilterOverride = shared.ParseRoleFilter("reverse")
	case "listener":
		app.RoleFilterOverride = shared.ParseRoleFilter("listener")
	case "outbound":
		app.RoleFilterOverride = shared.ParseRoleFilter("outbound")
	default:
		app.RoleFilterOverride = shared.ParseRoleFilter(preset)
	}
}
