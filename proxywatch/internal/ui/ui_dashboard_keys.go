package ui

import (
	"sort"
	"strings"
	"time"

	"proxywatch/internal/calibration"
	"proxywatch/internal/contour"
	"proxywatch/internal/keystore"
	"proxywatch/internal/shared"
	"proxywatch/internal/siem"

	"github.com/gdamore/tcell/v2"
)

func handleDashboardKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if app.ShowHelp || app.ShowRoleMenu || app.ShowSortMenu || app.ShowRefreshMenu {
		return handleDashboardOverlayKey(app, tev)
	}

	switch tev.Key() {
	case tcell.KeyUp:
		moveDashboardSelectionUp(app)
	case tcell.KeyDown:
		moveDashboardSelectionDown(app)
	case tcell.KeyPgUp:
		moveDashboardSelectionByPage(app, -1)
	case tcell.KeyPgDn:
		moveDashboardSelectionByPage(app, 1)
	case tcell.KeyHome:
		moveDashboardSelectionHome(app)
	case tcell.KeyEnd:
		moveDashboardSelectionEnd(app)
	case tcell.KeyLeft:
		stepDashboardWorkflow(app, -1)
	case tcell.KeyRight:
		stepDashboardWorkflow(app, 1)
	case tcell.KeyEscape:
		leaveDashboardHostProcessView(app)
	case tcell.KeyEnter:
		if dashboardHostListMode(app) {
			enterDashboardHostProcessView(app)
		} else {
			enterInspector(app)
		}
	}

	switch tev.Rune() {
	case '?':
		app.ShowHelp = true
		app.HelpMenuIndex = 0
	case 'r':
		if tryRemoveSelectedDisconnectedHost(app) {
			return false
		}
		openDashboardRefreshMenu(app)
	case 'R':
		openDashboardRefreshMenu(app)
	case 'c', 'C':
		openRoleSortMenu(app)
	case '1':
		enterCalibrationMode(app)
	case '2':
		enterSIEMMode(app)
	case '3':
		enterContourMode(app)
	case '4':
		enterCollectMode(app)
	case '5':
		enterWhitelistManager(app)
	case '<':
		stepDashboardWorkflow(app, -1)
	case '>':
		stepDashboardWorkflow(app, 1)
	case 'k', 'K':
		enterKeystoreMode(app)
	case 'W':
		whitelistSelectedCandidate(app)
	case 'x', 'X':
		removeSelectedDisconnectedHost(app)
	case 'f', 'F':
		openRoleSortMenu(app)
	case 'b', 'B':
		enterCollectMode(app)
	case 'o', 'O':
		enterContourMode(app)
	case 'm', 'M':
		enterSIEMMode(app)
	case 'w':
		enterWhitelistManager(app)
	case 'q':
		return requestQuit(app)
	}

	return false
}

func handleDashboardOverlayKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if tev.Rune() == 'q' {
		return requestQuit(app)
	}
	switch tev.Key() {
	case tcell.KeyLeft:
		closeDashboardOverlays(app)
		stepDashboardWorkflow(app, -1)
		return false
	case tcell.KeyRight:
		closeDashboardOverlays(app)
		stepDashboardWorkflow(app, 1)
		return false
	}
	if tev.Key() == tcell.KeyEscape {
		closeDashboardOverlays(app)
		return false
	}

	// Allow direct menu switching while any overlay is open.
	switch tev.Rune() {
	case '?':
		app.ShowHelp = !app.ShowHelp
		if app.ShowHelp {
			app.ShowRoleMenu = false
			app.ShowSortMenu = false
			app.ShowRefreshMenu = false
			app.HelpMenuIndex = 0
		}
		return false
	case 'r':
		if tryRemoveSelectedDisconnectedHost(app) {
			closeDashboardOverlays(app)
			return false
		}
		openDashboardRefreshMenu(app)
		return false
	case 'R':
		openDashboardRefreshMenu(app)
		return false
	case 'c', 'C', 'f', 'F':
		openRoleSortMenu(app)
		return false
	case '1':
		closeDashboardOverlays(app)
		enterCalibrationMode(app)
		return false
	case '2':
		closeDashboardOverlays(app)
		enterSIEMMode(app)
		return false
	case '3':
		closeDashboardOverlays(app)
		enterContourMode(app)
		return false
	case '4':
		closeDashboardOverlays(app)
		enterCollectMode(app)
		return false
	case '5':
		closeDashboardOverlays(app)
		enterWhitelistManager(app)
		return false
	case '<':
		closeDashboardOverlays(app)
		stepDashboardWorkflow(app, -1)
		return false
	case '>':
		closeDashboardOverlays(app)
		stepDashboardWorkflow(app, 1)
		return false
	case 'm', 'M':
		closeDashboardOverlays(app)
		enterSIEMMode(app)
		return false
	case 'o', 'O':
		closeDashboardOverlays(app)
		enterContourMode(app)
		return false
	case 'b', 'B':
		closeDashboardOverlays(app)
		enterCollectMode(app)
		return false
	case 'w':
		closeDashboardOverlays(app)
		enterWhitelistManager(app)
		return false
	case 'k', 'K':
		closeDashboardOverlays(app)
		enterKeystoreMode(app)
		return false
	case 'W':
		whitelistSelectedCandidate(app)
		return false
	case 'x', 'X':
		removeSelectedDisconnectedHost(app)
		return false
	case 'q':
		return requestQuit(app)
	}

	if app.ShowHelp {
		maxIdx := len(dashboardMenuHelpOptions()) - 1
		switch tev.Key() {
		case tcell.KeyUp:
			if app.HelpMenuIndex > 0 {
				app.HelpMenuIndex--
			}
		case tcell.KeyDown:
			if app.HelpMenuIndex < max(0, maxIdx) {
				app.HelpMenuIndex++
			}
		}
		return false
	}

	if app.ShowRoleMenu {
		choices := roleSortMenuChoices()
		if len(choices) == 0 {
			app.ShowRoleMenu = false
			return false
		}
		switch tev.Key() {
		case tcell.KeyUp:
			if app.RoleMenuIndex > 0 {
				app.RoleMenuIndex--
			}
		case tcell.KeyDown:
			if app.RoleMenuIndex < len(choices)-1 {
				app.RoleMenuIndex++
			}
		case tcell.KeyEnter:
			applyRoleSortMenuChoice(app, choices[clampChoice(app.RoleMenuIndex, len(choices))])
			app.ShowRoleMenu = false
		}
		return false
	}

	if app.ShowSortMenu {
		switch tev.Key() {
		case tcell.KeyUp:
			if app.SortMenuIndex > 0 {
				app.SortMenuIndex--
			}
		case tcell.KeyDown:
			if app.SortMenuIndex < len(sortMenuChoices)-1 {
				app.SortMenuIndex++
			}
		case tcell.KeyEnter:
			app.SortPreset = sortMenuChoices[clampChoice(app.SortMenuIndex, len(sortMenuChoices))]
			resortCandidates(app)
			app.ShowSortMenu = false
		}
		return false
	}

	if app.ShowRefreshMenu {
		switch tev.Key() {
		case tcell.KeyUp:
			if app.RefreshMenuIndex > 0 {
				app.RefreshMenuIndex--
			}
		case tcell.KeyDown:
			if app.RefreshMenuIndex < len(refreshMenuChoices)-1 {
				app.RefreshMenuIndex++
			}
		case tcell.KeyEnter:
			preset := refreshMenuChoices[clampChoice(app.RefreshMenuIndex, len(refreshMenuChoices))]
			if dur, err := time.ParseDuration(preset); err == nil && dur > 0 {
				app.RefreshInt = dur
				app.LastError = "Refresh set to " + dur.String()
				app.RefreshRequested = true
			}
			app.ShowRefreshMenu = false
		}
		return false
	}
	return false
}

func openDashboardRefreshMenu(app *shared.AppState) {
	app.ShowHelp = false
	app.ShowRoleMenu = false
	app.ShowSortMenu = false
	app.ShowRefreshMenu = true
	app.RefreshMenuIndex = indexOfDuration(refreshMenuChoices, app.RefreshInt)
}

func tryRemoveSelectedDisconnectedHost(app *shared.AppState) bool {
	if app == nil || !dashboardHostListMode(app) {
		return false
	}
	summary, ok := selectedDashboardHostSummary(app)
	if !ok {
		return false
	}
	if strings.EqualFold(summary.Status, "connected") {
		return false
	}
	removeSelectedDisconnectedHost(app)
	return true
}

func stepDashboardWorkflow(app *shared.AppState, dir int) {
	_ = stepWorkflowMenu(app, dir)
}

func dashboardOverlayOpen(app *shared.AppState) bool {
	return app.ShowHelp || app.ShowRoleMenu || app.ShowSortMenu || app.ShowRefreshMenu
}

func shouldPausePeriodicRefresh(app *shared.AppState) bool {
	switch app.Mode {
	case shared.ModeDashboard:
		return dashboardOverlayOpen(app)
	case shared.ModeInspect:
		return app.ShowInspectMenu
	case shared.ModeWhitelist, shared.ModeKeystore, shared.ModeSIEM:
		return true
	case shared.ModeCollect:
		if app.CollectActive {
			return false
		}
		return app.CollectEditing || app.CollectShowMenu
	case shared.ModeContour:
		if app.ContourActive || app.ContourAnalyzing {
			return false
		}
		return app.ContourEditing || app.ContourShowMenu
	case shared.ModeCalibration:
		if app.CalibrateActive || app.CalibrateAnalyzing {
			return false
		}
		return app.ShowCalibrateMenu || app.ShowCalibrateHelp || app.CalibrateEditing
	default:
		return false
	}
}

func closeDashboardOverlays(app *shared.AppState) {
	app.ShowHelp = false
	app.ShowRoleMenu = false
	app.ShowSortMenu = false
	app.ShowRefreshMenu = false
}

type roleSortMenuChoice struct {
	Kind  string
	Value string
}

func roleSortMenuChoices() []roleSortMenuChoice {
	roles := rolePresetOptions()
	sorts := sortPresetOptions()
	choices := make([]roleSortMenuChoice, 0, len(roles)+len(sorts))
	for _, role := range roles {
		choices = append(choices, roleSortMenuChoice{Kind: "role", Value: role})
	}
	for _, sort := range sorts {
		choices = append(choices, roleSortMenuChoice{Kind: "sort", Value: sort})
	}
	return choices
}

func roleSortMenuLabels() []string {
	choices := roleSortMenuChoices()
	labels := make([]string, 0, len(choices))
	for _, choice := range choices {
		if choice.Kind == "sort" {
			labels = append(labels, "sort: "+choice.Value)
			continue
		}
		labels = append(labels, "role: "+choice.Value)
	}
	return labels
}

func openRoleSortMenu(app *shared.AppState) {
	app.ShowHelp = false
	app.ShowRefreshMenu = false
	app.ShowSortMenu = false
	app.ShowRoleMenu = true
	choices := roleSortMenuChoices()
	if len(choices) == 0 {
		app.RoleMenuIndex = 0
		return
	}
	app.RoleMenuIndex = roleSortMenuIndex(choices, "role", safePreset(app.RolePreset, "recommended"))
}

func roleSortMenuIndex(choices []roleSortMenuChoice, kind, value string) int {
	for i, choice := range choices {
		if choice.Kind == kind && choice.Value == value {
			return i
		}
	}
	return 0
}

func applyRoleSortMenuChoice(app *shared.AppState, choice roleSortMenuChoice) {
	switch choice.Kind {
	case "sort":
		app.SortPreset = choice.Value
		resortCandidates(app)
	default:
		applyRolePreset(app, choice.Value)
		app.RefreshRequested = true
	}
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

	// Process view should be one row per host+pid. Keep the highest-priority
	// row when duplicate classifier entries exist for the same process.
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
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]

		stateRank := func(c shared.Candidate) int {
			switch shared.CandidateState(c) {
			case "active":
				return 3
			case "strong":
				return 2
			default:
				return 1
			}
		}
		if stateRank(a) != stateRank(b) {
			return stateRank(a) > stateRank(b)
		}
		priorityA := shared.RolePriority(a.Role)
		priorityB := shared.RolePriority(b.Role)
		if priorityA != priorityB {
			return priorityA > priorityB
		}
		hostA := strings.ToLower(shared.DisplayHost(a.Host))
		hostB := strings.ToLower(shared.DisplayHost(b.Host))
		if hostA != hostB {
			return hostA < hostB
		}
		nameA := strings.ToLower(shared.DisplayProcessName(a.Proc))
		nameB := strings.ToLower(shared.DisplayProcessName(b.Proc))
		if nameA != nameB {
			return nameA < nameB
		}
		pidA, pidB := 0, 0
		if a.Proc != nil {
			pidA = a.Proc.Pid
		}
		if b.Proc != nil {
			pidB = b.Proc.Pid
		}
		if pidA != pidB {
			return pidA < pidB
		}
		return strings.ToLower(shared.CandidateKey(a)) < strings.ToLower(shared.CandidateKey(b))
	})
	return out
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

func syncDashboardProcessSelection(app *shared.AppState, view []shared.Candidate, idx int) {
	if len(view) == 0 {
		app.SelectedIdx = -1
		app.SelectedKey = ""
		return
	}
	if idx < 0 {
		idx = 0
	}
	if idx >= len(view) {
		idx = len(view) - 1
	}
	key := shared.CandidateKey(view[idx])
	app.SelectedKey = key
	app.SelectedIdx = FindIndexByKey(app.Candidates, key)
}

func selectedDashboardHostSummary(app *shared.AppState) (shared.HostSummary, bool) {
	if app == nil || len(app.HostSummaries) == 0 {
		return shared.HostSummary{}, false
	}
	idx := app.DashboardHostSelected
	if idx < 0 {
		idx = 0
	}
	if idx >= len(app.HostSummaries) {
		idx = len(app.HostSummaries) - 1
	}
	app.DashboardHostSelected = idx
	app.DashboardHostKey = app.HostSummaries[idx].Host
	return app.HostSummaries[idx], true
}

func removeSelectedDisconnectedHost(app *shared.AppState) {
	if app == nil || !dashboardHostListMode(app) {
		return
	}
	summary, ok := selectedDashboardHostSummary(app)
	if !ok {
		return
	}
	if strings.EqualFold(summary.Status, "connected") {
		app.LastError = "selected host is still connected"
		return
	}
	if app.RemoveRemoteHost == nil {
		app.LastError = "host removal not configured"
		return
	}
	if err := app.RemoveRemoteHost(summary.Host); err != nil {
		app.LastError = "remove host failed: " + err.Error()
		return
	}

	removedHost := strings.TrimSpace(summary.Host)
	filterByHost := func(cands []shared.Candidate) []shared.Candidate {
		if len(cands) == 0 {
			return cands
		}
		out := make([]shared.Candidate, 0, len(cands))
		for _, cand := range cands {
			if strings.EqualFold(shared.DisplayHost(cand.Host), removedHost) {
				continue
			}
			out = append(out, cand)
		}
		return out
	}
	app.Candidates = filterByHost(app.Candidates)
	app.SnapshotCandidates = filterByHost(app.SnapshotCandidates)

	next := make([]shared.HostSummary, 0, len(app.HostSummaries)-1)
	for _, host := range app.HostSummaries {
		if strings.EqualFold(strings.TrimSpace(host.Host), removedHost) {
			continue
		}
		next = append(next, host)
	}
	app.HostSummaries = next
	if len(app.HostSummaries) == 0 {
		app.DashboardHostSelected = -1
		app.DashboardHostKey = ""
		app.DashboardHostProcessView = false
		app.LastError = "removed host " + removedHost
		app.SelectedIdx = -1
		app.SelectedKey = ""
		app.RefreshRequested = true
		return
	}
	if app.DashboardHostSelected >= len(app.HostSummaries) {
		app.DashboardHostSelected = len(app.HostSummaries) - 1
	}
	if app.DashboardHostSelected < 0 {
		app.DashboardHostSelected = 0
	}
	app.DashboardHostKey = app.HostSummaries[app.DashboardHostSelected].Host
	resortCandidates(app)
	app.LastError = "removed host " + removedHost
	app.RefreshRequested = true
}

func enterDashboardHostProcessView(app *shared.AppState) {
	summary, ok := selectedDashboardHostSummary(app)
	if !ok {
		return
	}
	app.DashboardHostProcessView = true
	app.DashboardHostKey = summary.Host
	view := dashboardProcessCandidates(app)
	if len(view) == 0 {
		app.SelectedIdx = -1
		app.SelectedKey = ""
		return
	}
	syncDashboardProcessSelection(app, view, 0)
}

func leaveDashboardHostProcessView(app *shared.AppState) {
	if app == nil || strings.TrimSpace(app.LocalHost) != "" || !app.DashboardHostProcessView {
		return
	}
	app.DashboardHostProcessView = false
	if strings.TrimSpace(app.DashboardHostKey) == "" && len(app.HostSummaries) > 0 {
		app.DashboardHostSelected = clampIndex(app.DashboardHostSelected, len(app.HostSummaries))
		if app.DashboardHostSelected < 0 {
			app.DashboardHostSelected = 0
		}
		app.DashboardHostKey = app.HostSummaries[app.DashboardHostSelected].Host
	}
}

func moveDashboardSelectionUp(app *shared.AppState) {
	if dashboardHostListMode(app) {
		if app.DashboardHostSelected > 0 {
			app.DashboardHostSelected--
		}
		if app.DashboardHostSelected >= 0 && app.DashboardHostSelected < len(app.HostSummaries) {
			app.DashboardHostKey = app.HostSummaries[app.DashboardHostSelected].Host
		}
		return
	}
	view := dashboardProcessCandidates(app)
	if len(view) == 0 {
		return
	}
	idx := selectedDashboardProcessIndex(app, view)
	if idx > 0 {
		idx--
	}
	syncDashboardProcessSelection(app, view, idx)
}

func moveDashboardSelectionDown(app *shared.AppState) {
	if dashboardHostListMode(app) {
		if app.DashboardHostSelected < len(app.HostSummaries)-1 {
			app.DashboardHostSelected++
		}
		if app.DashboardHostSelected >= 0 && app.DashboardHostSelected < len(app.HostSummaries) {
			app.DashboardHostKey = app.HostSummaries[app.DashboardHostSelected].Host
		}
		return
	}
	view := dashboardProcessCandidates(app)
	if len(view) == 0 {
		return
	}
	idx := selectedDashboardProcessIndex(app, view)
	if idx < len(view)-1 {
		idx++
	}
	syncDashboardProcessSelection(app, view, idx)
}

func moveDashboardSelectionByPage(app *shared.AppState, dir int) {
	step := 10
	if dashboardHostListMode(app) {
		if len(app.HostSummaries) == 0 {
			return
		}
		app.DashboardHostSelected += dir * step
		if app.DashboardHostSelected < 0 {
			app.DashboardHostSelected = 0
		}
		if app.DashboardHostSelected >= len(app.HostSummaries) {
			app.DashboardHostSelected = len(app.HostSummaries) - 1
		}
		app.DashboardHostKey = app.HostSummaries[app.DashboardHostSelected].Host
		return
	}
	view := dashboardProcessCandidates(app)
	if len(view) == 0 {
		return
	}
	idx := selectedDashboardProcessIndex(app, view)
	if idx < 0 {
		idx = 0
	}
	idx += dir * step
	if idx < 0 {
		idx = 0
	}
	if idx >= len(view) {
		idx = len(view) - 1
	}
	syncDashboardProcessSelection(app, view, idx)
}

func moveDashboardSelectionHome(app *shared.AppState) {
	if dashboardHostListMode(app) {
		if len(app.HostSummaries) == 0 {
			return
		}
		app.DashboardHostSelected = 0
		app.DashboardHostKey = app.HostSummaries[0].Host
		return
	}
	view := dashboardProcessCandidates(app)
	if len(view) == 0 {
		return
	}
	syncDashboardProcessSelection(app, view, 0)
}

func moveDashboardSelectionEnd(app *shared.AppState) {
	if dashboardHostListMode(app) {
		if len(app.HostSummaries) == 0 {
			return
		}
		app.DashboardHostSelected = len(app.HostSummaries) - 1
		app.DashboardHostKey = app.HostSummaries[app.DashboardHostSelected].Host
		return
	}
	view := dashboardProcessCandidates(app)
	if len(view) == 0 {
		return
	}
	syncDashboardProcessSelection(app, view, len(view)-1)
}

func enterInspector(app *shared.AppState) {
	if dashboardHostListMode(app) {
		return
	}
	view := dashboardProcessCandidates(app)
	idx := selectedDashboardProcessIndex(app, view)
	if idx < 0 || idx >= len(view) {
		return
	}
	app.InspectKey = shared.CandidateKey(view[idx])
	app.InspectScroll = 0
	app.InspectMaxScroll = 0
	app.ShowInspectMenu = false
	app.Mode = shared.ModeInspect
}

func enterCollectMode(app *shared.AppState) {
	if app.CollectOutput == "" {
		app.CollectOutput = "~/.proxywatch/collections/proxywatch-collection.json"
	}
	if app.CollectDurationStr == "" {
		app.CollectDurationStr = "5m"
	}
	refreshCollectSources(app)
	if strings.TrimSpace(app.CollectSource) == "" {
		app.CollectSource = "all"
	}
	app.CollectEditing = false
	app.CollectShowMenu = false
	app.CollectShowHelp = false
	if app.CollectField < 0 || app.CollectField > collectFieldMax {
		app.CollectField = collectFieldSource
	}
	app.Mode = shared.ModeCollect
}

func enterContourMode(app *shared.AppState) {
	if strings.TrimSpace(app.ContourOutput) == "" {
		app.ContourOutput = contour.DefaultOutputPath()
	}
	if strings.TrimSpace(app.ContourDuration) == "" {
		app.ContourDuration = "5m"
	}
	if strings.TrimSpace(app.ContourSource) == "" {
		app.ContourSource = "all"
	}
	if strings.TrimSpace(app.ContourProbeEndpoint) == "" {
		app.ContourProbeEndpoint = "127.0.0.1"
	}
	if strings.TrimSpace(app.ContourProbeMode) == "" {
		app.ContourProbeMode = contour.DefaultProbeMode()
	}
	if strings.TrimSpace(app.ContourProbeRole) == "" {
		app.ContourProbeRole = contour.DefaultProbeRole()
	}
	app.ContourProbeMode = contour.NormalizeProbeMode(app.ContourProbeMode)
	app.ContourProbeRole = contour.NormalizeProbeRole(app.ContourProbeRole)
	refreshContourState(app)
	app.ContourEditing = false
	app.ContourShowMenu = false
	app.ContourShowHelp = false
	if app.ContourField < 0 || app.ContourField > contourFieldMax {
		app.ContourField = contourFieldEndpoint
	}
	normalizeContourFieldSelection(app)
	app.Mode = shared.ModeContour
}

func enterCalibrationMode(app *shared.AppState) {
	app.CalibrateProvider = calibration.ProviderKey(app.CalibrateProvider)
	if app.CalibrateDuration == "" {
		app.CalibrateDuration = "1h"
	}
	if app.CalibrateProvider == "" {
		app.CalibrateProvider = calibration.ProviderKey("OpenAI")
	}
	if app.CalibrateModel == "" || !containsString(calibration.ModelOptions(app.CalibrateProvider), app.CalibrateModel) {
		app.CalibrateModel = calibration.DefaultModel(app.CalibrateProvider)
	}
	if app.CalibrateProfile == "" {
		app.CalibrateProfile = "tuning.json"
	}
	if app.CalibrateOutput == "" {
		app.CalibrateOutput = calibration.DefaultOutputPath()
	}
	app.CalibrateEditing = false
	app.ShowCalibrateMenu = false
	app.ShowCalibrateHelp = false
	app.CalibrateReportScroll = 0
	if app.CalibrateField < 0 || app.CalibrateField > calibrateFieldMax {
		app.CalibrateField = calibrateFieldOutput
	}
	refreshCalibrationState(app)
	app.Mode = shared.ModeCalibration
}

func enterKeystoreMode(app *shared.AppState) {
	if strings.TrimSpace(app.KeystorePath) == "" {
		app.KeystorePath = keystore.DefaultPath()
	}
	ensureKeystoreValues(app)
	for _, key := range keystore.ManagedKeys {
		if _, ok := app.KeystoreValues[key]; !ok {
			app.KeystoreValues[key] = keystore.RuntimeValue(key)
		}
	}
	app.KeystoreEditing = false
	app.KeystoreShowHelp = false
	if !app.KeystoreUnlocked || app.KeystoreActiveEntry == "" {
		app.KeystoreField = keystoreFieldLoad
		app.KeystorePanel = 0
	} else if app.KeystoreField < 0 || app.KeystoreField > keystoreFieldMax {
		app.KeystoreField = keystoreFieldOpenAIKey
	}
	app.Mode = shared.ModeKeystore
}

func enterSIEMMode(app *shared.AppState) {
	app.SIEMDebugLogPath = strings.TrimSpace(app.KeystoreValues["PROXYWATCH_DETECT_DEBUG_LOG"])
	app.SIEMRulesJSONPath = strings.TrimSpace(app.KeystoreValues["PROXYWATCH_DETECT_RULES_JSON"])
	app.SIEMSourceReport = strings.TrimSpace(app.KeystoreValues["PROXYWATCH_SIEM_SOURCE_REPORT"])
	app.SIEMProvider = calibration.ProviderKey(app.KeystoreValues["PROXYWATCH_SIEM_PROVIDER"])
	app.SIEMModel = strings.TrimSpace(app.KeystoreValues["PROXYWATCH_SIEM_MODEL"])
	app.SIEMReportPath = strings.TrimSpace(app.KeystoreValues["PROXYWATCH_SIEM_REPORT_OUTPUT"])
	app.SIEMExportPath = strings.TrimSpace(app.KeystoreValues["PROXYWATCH_SIEM_JSON_OUTPUT"])
	if app.SIEMSourceReport == "" {
		app.SIEMSourceReport = app.CalibrateOutput
	}
	if app.SIEMProvider == "" {
		app.SIEMProvider = calibration.ProviderKey("OpenAI")
	}
	if app.SIEMModel == "" || !containsString(calibration.ModelOptions(app.SIEMProvider), app.SIEMModel) {
		app.SIEMModel = calibration.DefaultModel(app.SIEMProvider)
	}
	if app.SIEMReportPath == "" {
		app.SIEMReportPath = siem.DefaultSIEMReportPath()
	}
	if app.SIEMExportPath == "" {
		app.SIEMExportPath = siem.DefaultSIEMJSONPath()
	}
	app.SIEMEditing = false
	app.SIEMShowMenu = false
	app.SIEMShowHelp = false
	if app.SIEMField < 0 || app.SIEMField > siemFieldMax {
		app.SIEMField = siemFieldProvider
	}
	refreshSIEMSourceReports(app)
	// Only reload from disk if no report lines are already in memory.
	// The in-memory lines have clean formatting; reloading from the
	// markdown file would scramble them.
	if len(app.SIEMReportLines) == 0 {
		refreshSIEMReportPreview(app)
	}
	app.Mode = shared.ModeSIEM
}

func enterWhitelistManager(app *shared.AppState) {
	if app.Whitelist == nil {
		app.LastError = "whitelist not configured"
		return
	}
	app.WhitelistItems = app.Whitelist.List()
	if len(app.WhitelistItems) == 0 {
		app.WhitelistSelected = -1
		app.WhitelistListOffset = 0
	} else if app.WhitelistSelected < 0 || app.WhitelistSelected >= len(app.WhitelistItems) {
		app.WhitelistSelected = 0
	}
	if app.WhitelistField < whitelistFieldProcess || app.WhitelistField > whitelistFieldMax {
		app.WhitelistField = whitelistFieldProcess
	}
	app.WhitelistShowHelp = false
	procList := whitelistProcessCandidates(app)
	if len(procList) == 0 {
		app.WhitelistProcessSelected = -1
		app.WhitelistProcessOffset = 0
	} else {
		idx := findCandidateIndexByKey(procList, app.SelectedKey)
		if idx < 0 {
			idx = 0
		}
		app.WhitelistProcessSelected = idx
	}
	app.Mode = shared.ModeWhitelist
}

func whitelistSelectedCandidate(app *shared.AppState) {
	if app.Whitelist == nil {
		app.LastError = "whitelist not configured"
		return
	}
	cand, ok := selectedWhitelistProcessCandidate(app)
	if !ok {
		app.LastError = "No process selected to whitelist"
		return
	}
	if cand.Proc == nil {
		app.LastError = "No process selected to whitelist"
		return
	}

	if _, err := app.Whitelist.AddCandidate(cand); err != nil {
		app.LastError = "whitelist failed: " + err.Error()
		return
	}

	app.LastError = "Whitelisted " + cand.Proc.Name
	app.WhitelistItems = app.Whitelist.List()
	if len(app.WhitelistItems) > 0 && app.WhitelistSelected < 0 {
		app.WhitelistSelected = 0
	}
	app.Candidates = app.Whitelist.Filter(app.Candidates)
	if len(app.Candidates) == 0 {
		app.SelectedIdx = -1
		app.SelectedKey = ""
		app.RefreshRequested = true
		return
	}
	if app.SelectedIdx >= len(app.Candidates) {
		app.SelectedIdx = len(app.Candidates) - 1
	}
	app.SelectedKey = shared.CandidateKey(app.Candidates[app.SelectedIdx])
	app.RefreshRequested = true
}
