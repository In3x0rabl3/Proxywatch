package keys

import (
	"strings"
	"time"

	"proxywatch/internal/contour"
	"proxywatch/internal/detection"
	"proxywatch/internal/keystore"
	"proxywatch/internal/detection/model"
	"proxywatch/internal/shared"

	"github.com/gdamore/tcell/v2"
)

func HandleDashboardKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if app.ShowHelp || app.ShowRoleMenu || app.ShowSortMenu || app.ShowRefreshMenu {
		return HandleDashboardOverlayKey(app, tev)
	}

	switch tev.Key() {
	case tcell.KeyUp:
		MoveDashboardSelectionUp(app)
	case tcell.KeyDown:
		MoveDashboardSelectionDown(app)
	case tcell.KeyPgUp:
		MoveDashboardSelectionByPage(app, -1)
	case tcell.KeyPgDn:
		MoveDashboardSelectionByPage(app, 1)
	case tcell.KeyHome:
		MoveDashboardSelectionHome(app)
	case tcell.KeyEnd:
		MoveDashboardSelectionEnd(app)
	case tcell.KeyLeft:
		StepDashboardWorkflow(app, -1)
	case tcell.KeyRight:
		StepDashboardWorkflow(app, 1)
	case tcell.KeyEscape:
		LeaveDashboardHostProcessView(app)
	case tcell.KeyEnter:
		if DashboardHostListMode(app) {
			EnterDashboardHostProcessView(app)
		} else {
			EnterInspector(app)
		}
	}

	switch tev.Rune() {
	case '?':
		app.ShowHelp = true
		app.HelpMenuIndex = 0
	case 'r':
		if TryRemoveSelectedDisconnectedHost(app) {
			return false
		}
		OpenDashboardRefreshMenu(app)
	case 'R':
		OpenDashboardRefreshMenu(app)
	case 'c', 'C':
		OpenRoleSortMenu(app)
	case '1':
		EnterTrainingMode(app)
	case '2':
		EnterContourMode(app)
	case '3':
		EnterCollectMode(app)
	case '4':
		EnterSIEMMode(app)
	case '5':
		EnterWhitelistManager(app)
	case '6':
		EnterKeystoreMode(app)
	case '<':
		StepDashboardWorkflow(app, -1)
	case '>':
		StepDashboardWorkflow(app, 1)
	case 'k', 'K':
		EnterKeystoreMode(app)
	case 'W':
		WhitelistSelectedCandidate(app)
	case 'x', 'X':
		RemoveSelectedDisconnectedHost(app)
	case 'f', 'F':
		OpenRoleSortMenu(app)
	case 'b', 'B':
		EnterCollectMode(app)
	case 'o', 'O':
		EnterContourMode(app)
	case 'w':
		EnterWhitelistManager(app)
	case 'q':
		return requestQuit(app)
	}

	return false
}

func HandleDashboardOverlayKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if tev.Rune() == 'q' {
		return requestQuit(app)
	}
	switch tev.Key() {
	case tcell.KeyLeft:
		CloseDashboardOverlays(app)
		StepDashboardWorkflow(app, -1)
		return false
	case tcell.KeyRight:
		CloseDashboardOverlays(app)
		StepDashboardWorkflow(app, 1)
		return false
	}
	if tev.Key() == tcell.KeyEscape {
		CloseDashboardOverlays(app)
		return false
	}

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
		if TryRemoveSelectedDisconnectedHost(app) {
			CloseDashboardOverlays(app)
			return false
		}
		OpenDashboardRefreshMenu(app)
		return false
	case 'R':
		OpenDashboardRefreshMenu(app)
		return false
	case 'c', 'C', 'f', 'F':
		OpenRoleSortMenu(app)
		return false
	case '1':
		CloseDashboardOverlays(app)
		EnterTrainingMode(app)
		return false
	case '2':
		CloseDashboardOverlays(app)
		EnterContourMode(app)
		return false
	case '3':
		CloseDashboardOverlays(app)
		EnterCollectMode(app)
		return false
	case '4':
		CloseDashboardOverlays(app)
		EnterSIEMMode(app)
		return false
	case '5':
		CloseDashboardOverlays(app)
		EnterWhitelistManager(app)
		return false
	case '6':
		CloseDashboardOverlays(app)
		EnterKeystoreMode(app)
		return false
	case '<':
		CloseDashboardOverlays(app)
		StepDashboardWorkflow(app, -1)
		return false
	case '>':
		CloseDashboardOverlays(app)
		StepDashboardWorkflow(app, 1)
		return false
	case 'o', 'O':
		CloseDashboardOverlays(app)
		EnterContourMode(app)
		return false
	case 'b', 'B':
		CloseDashboardOverlays(app)
		EnterCollectMode(app)
		return false
	case 'w':
		CloseDashboardOverlays(app)
		EnterWhitelistManager(app)
		return false
	case 'k', 'K':
		CloseDashboardOverlays(app)
		EnterKeystoreMode(app)
		return false
	case 'W':
		WhitelistSelectedCandidate(app)
		return false
	case 'x', 'X':
		RemoveSelectedDisconnectedHost(app)
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
		choices := RoleSortMenuChoices()
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
			ApplyRoleSortMenuChoice(app, choices[clampChoice(app.RoleMenuIndex, len(choices))])
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
			if app.SortMenuIndex < len(SortMenuChoices)-1 {
				app.SortMenuIndex++
			}
		case tcell.KeyEnter:
			app.SortPreset = SortMenuChoices[clampChoice(app.SortMenuIndex, len(SortMenuChoices))]
			ResortCandidates(app)
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
			if app.RefreshMenuIndex < len(RefreshMenuChoices)-1 {
				app.RefreshMenuIndex++
			}
		case tcell.KeyEnter:
			preset := RefreshMenuChoices[clampChoice(app.RefreshMenuIndex, len(RefreshMenuChoices))]
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

func dashboardMenuHelpOptions() []string {
	return []string{
		"[Navigation]",
		"UP/DOWN      Move selection",
		"PGUP/PGDN    Move by page",
		"ENTER        Open selected row",
		"ESC          Exit host process view",
		"",
		"[Workflows]",
		"1            Model",
		"2            Contour",
		"3            ProxyHound",
		"4            SIEM",
		"5            Whitelist",
		"6            Keystore",
		"LEFT/RIGHT   Cycle workflows",
		"",
		"[Actions]",
		"r            Refresh / remove host",
		"c            Role + sort menu",
		"x            Remove disconnected host",
		"?            Close this menu",
		"q            Quit",
	}
}

func OpenDashboardRefreshMenu(app *shared.AppState) {
	app.ShowHelp = false
	app.ShowRoleMenu = false
	app.ShowSortMenu = false
	app.ShowRefreshMenu = true
	app.RefreshMenuIndex = indexOfDuration(RefreshMenuChoices, app.RefreshInt)
}

func TryRemoveSelectedDisconnectedHost(app *shared.AppState) bool {
	if app == nil || !DashboardHostListMode(app) {
		return false
	}
	summary, ok := SelectedDashboardHostSummary(app)
	if !ok {
		return false
	}
	if strings.EqualFold(summary.Status, "connected") {
		return false
	}
	RemoveSelectedDisconnectedHost(app)
	return true
}

func StepDashboardWorkflow(app *shared.AppState, dir int) {
	_ = StepWorkflowMenu(app, dir)
}

func DashboardOverlayOpen(app *shared.AppState) bool {
	return app.ShowHelp || app.ShowRoleMenu || app.ShowSortMenu || app.ShowRefreshMenu
}

func ShouldPausePeriodicRefresh(app *shared.AppState) bool {
	switch app.Mode {
	case shared.ModeDashboard:
		return DashboardOverlayOpen(app)
	case shared.ModeInspect:
		return app.ShowInspectMenu
	case shared.ModeWhitelist, shared.ModeKeystore:
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
	default:
		return false
	}
}

type RoleSortMenuChoice struct {
	Kind  string
	Value string
}

func RoleSortMenuChoices() []RoleSortMenuChoice {
	roles := rolePresetOptions()
	sorts := sortPresetOptions()
	choices := make([]RoleSortMenuChoice, 0, len(roles)+len(sorts))
	for _, role := range roles {
		choices = append(choices, RoleSortMenuChoice{Kind: "role", Value: role})
	}
	for _, sort := range sorts {
		choices = append(choices, RoleSortMenuChoice{Kind: "sort", Value: sort})
	}
	return choices
}

func rolePresetOptions() []string {
	return []string{"recommended", "all", "control-channel", "control-pivot", "listener", "outbound"}
}

func sortPresetOptions() []string {
	return []string{"default", "host", "role", "age", "state", "pid", "process"}
}

func RoleSortMenuLabels() []string {
	choices := RoleSortMenuChoices()
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

func OpenRoleSortMenu(app *shared.AppState) {
	app.ShowHelp = false
	app.ShowRefreshMenu = false
	app.ShowSortMenu = false
	app.ShowRoleMenu = true
	choices := RoleSortMenuChoices()
	if len(choices) == 0 {
		app.RoleMenuIndex = 0
		return
	}
	app.RoleMenuIndex = roleSortMenuIndex(choices, "role", safePreset(app.RolePreset, "recommended"))
}

func roleSortMenuIndex(choices []RoleSortMenuChoice, kind, value string) int {
	for i, choice := range choices {
		if choice.Kind == kind && choice.Value == value {
			return i
		}
	}
	return 0
}

func ApplyRoleSortMenuChoice(app *shared.AppState, choice RoleSortMenuChoice) {
	switch choice.Kind {
	case "sort":
		app.SortPreset = choice.Value
		ResortCandidates(app)
	default:
		applyRolePreset(app, choice.Value)
		app.RefreshRequested = true
	}
}

func RemoveSelectedDisconnectedHost(app *shared.AppState) {
	if app == nil || !DashboardHostListMode(app) {
		return
	}
	summary, ok := SelectedDashboardHostSummary(app)
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
	ResortCandidates(app)
	app.LastError = "removed host " + removedHost
	app.RefreshRequested = true
}

func EnterDashboardHostProcessView(app *shared.AppState) {
	summary, ok := SelectedDashboardHostSummary(app)
	if !ok {
		return
	}
	app.DashboardHostProcessView = true
	app.DashboardHostKey = summary.Host
	view := DashboardProcessCandidates(app)
	if len(view) == 0 {
		app.SelectedIdx = -1
		app.SelectedKey = ""
		return
	}
	SyncDashboardProcessSelection(app, view, 0)
}

func LeaveDashboardHostProcessView(app *shared.AppState) {
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

func MoveDashboardSelectionUp(app *shared.AppState) {
	if DashboardHostListMode(app) {
		if app.DashboardHostSelected > 0 {
			app.DashboardHostSelected--
		}
		if app.DashboardHostSelected >= 0 && app.DashboardHostSelected < len(app.HostSummaries) {
			app.DashboardHostKey = app.HostSummaries[app.DashboardHostSelected].Host
		}
		return
	}
	view := DashboardProcessCandidates(app)
	if len(view) == 0 {
		return
	}
	idx := SelectedDashboardProcessIndex(app, view)
	if idx > 0 {
		idx--
	}
	SyncDashboardProcessSelection(app, view, idx)
}

func MoveDashboardSelectionDown(app *shared.AppState) {
	if DashboardHostListMode(app) {
		if app.DashboardHostSelected < len(app.HostSummaries)-1 {
			app.DashboardHostSelected++
		}
		if app.DashboardHostSelected >= 0 && app.DashboardHostSelected < len(app.HostSummaries) {
			app.DashboardHostKey = app.HostSummaries[app.DashboardHostSelected].Host
		}
		return
	}
	view := DashboardProcessCandidates(app)
	if len(view) == 0 {
		return
	}
	idx := SelectedDashboardProcessIndex(app, view)
	if idx < len(view)-1 {
		idx++
	}
	SyncDashboardProcessSelection(app, view, idx)
}

func MoveDashboardSelectionByPage(app *shared.AppState, dir int) {
	step := 10
	if DashboardHostListMode(app) {
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
	view := DashboardProcessCandidates(app)
	if len(view) == 0 {
		return
	}
	idx := SelectedDashboardProcessIndex(app, view)
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
	SyncDashboardProcessSelection(app, view, idx)
}

func MoveDashboardSelectionHome(app *shared.AppState) {
	if DashboardHostListMode(app) {
		if len(app.HostSummaries) == 0 {
			return
		}
		app.DashboardHostSelected = 0
		app.DashboardHostKey = app.HostSummaries[0].Host
		return
	}
	view := DashboardProcessCandidates(app)
	if len(view) == 0 {
		return
	}
	SyncDashboardProcessSelection(app, view, 0)
}

func MoveDashboardSelectionEnd(app *shared.AppState) {
	if DashboardHostListMode(app) {
		if len(app.HostSummaries) == 0 {
			return
		}
		app.DashboardHostSelected = len(app.HostSummaries) - 1
		app.DashboardHostKey = app.HostSummaries[app.DashboardHostSelected].Host
		return
	}
	view := DashboardProcessCandidates(app)
	if len(view) == 0 {
		return
	}
	SyncDashboardProcessSelection(app, view, len(view)-1)
}

func EnterInspector(app *shared.AppState) {
	if DashboardHostListMode(app) {
		return
	}
	view := DashboardProcessCandidates(app)
	idx := SelectedDashboardProcessIndex(app, view)
	if idx < 0 || idx >= len(view) {
		return
	}
	app.InspectKey = shared.CandidateKey(view[idx])
	app.InspectScroll = 0
	app.InspectMaxScroll = 0
	app.ShowInspectMenu = false
	app.Mode = shared.ModeInspect
}

func EnterCollectMode(app *shared.AppState) {
	if app.CollectOutput == "" {
		app.CollectOutput = "~/.proxywatch/collections/proxywatch-collection.json"
	}
	if app.CollectDurationStr == "" {
		app.CollectDurationStr = "5m"
	}
	RefreshCollectSources(app)
	if strings.TrimSpace(app.CollectSource) == "" {
		app.CollectSource = "all"
	}
	app.CollectEditing = false
	app.CollectShowMenu = false
	app.CollectShowHelp = false
	minField := CollectFieldSource
	if strings.TrimSpace(app.LocalHost) != "" {
		minField = CollectFieldOutput
	}
	if app.CollectField < minField || app.CollectField > CollectFieldMax {
		app.CollectField = minField
	}
	app.Mode = shared.ModeCollect
}

func EnterContourMode(app *shared.AppState) {
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
	RefreshContourState(app)
	app.ContourEditing = false
	app.ContourShowMenu = false
	app.ContourShowHelp = false
	if app.ContourField < 0 || app.ContourField > ContourFieldMax {
		app.ContourField = ContourFieldEndpoint
	}
	NormalizeContourFieldSelection(app)
	app.Mode = shared.ModeContour
}

func EnterSIEMMode(app *shared.AppState) {
	if app == nil {
		return
	}
	app.SiemShowHelp = false
	app.SiemField = 0
	// Deliberately retain SiemGeneratedSet / SiemGenerated across mode
	// transitions so an operator can jump to another workflow and back
	// without losing their snapshot. A fresh [g] regenerates.
	app.Mode = shared.ModeSIEM
}

func EnterTrainingMode(app *shared.AppState) {
	app.TrainingDashboardActive = true
	app.Mode = shared.ModeTraining
}

func EnterKeystoreMode(app *shared.AppState) {
	if strings.TrimSpace(app.KeystorePath) == "" {
		app.KeystorePath = keystore.DefaultPath()
	}
	EnsureKeystoreValues(app)
	for _, key := range keystore.ManagedKeys {
		if _, ok := app.KeystoreValues[key]; !ok {
			app.KeystoreValues[key] = keystore.RuntimeValue(key)
		}
	}
	app.KeystoreEditing = false
	app.KeystoreShowHelp = false
	if !app.KeystoreUnlocked || app.KeystoreActiveEntry == "" {
		app.KeystoreField = KeystoreFieldLoad
		app.KeystorePanel = 0
	} else if app.KeystoreField < 0 || app.KeystoreField > KeystoreFieldMax {
		app.KeystoreField = KeystoreFieldOpenAIKey
	}
	app.Mode = shared.ModeKeystore
}

func EnterWhitelistManager(app *shared.AppState) {
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
	if app.WhitelistField < WhitelistFieldProcess || app.WhitelistField > WhitelistFieldMax {
		app.WhitelistField = WhitelistFieldProcess
	}
	app.WhitelistShowHelp = false
	procList := WhitelistProcessCandidates(app)
	if len(procList) == 0 {
		app.WhitelistProcessSelected = -1
		app.WhitelistProcessOffset = 0
	} else {
		idx := FindCandidateIndexByKey(procList, app.SelectedKey)
		if idx < 0 {
			idx = 0
		}
		app.WhitelistProcessSelected = idx
	}
	app.Mode = shared.ModeWhitelist
}

func WhitelistSelectedCandidate(app *shared.AppState) {
	if app.Whitelist == nil {
		app.LastError = "whitelist not configured"
		return
	}
	cand, ok := SelectedWhitelistProcessCandidate(app)
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

	model.RecordFeedback(model.FeedbackEntry{
		Timestamp:   time.Now().UTC(),
		Action:      "whitelist",
		ProcessKey:  detection.ProcessBehaviorKey(&cand),
		ProcessName: cand.Proc.Name,
		Role:        cand.Role,
		Score:       cand.Score,
		Signals:     cand.Signals,
	})

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
