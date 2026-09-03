package ui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/gdamore/tcell/v2"

	"proxywatch/internal/keystore"
	"proxywatch/internal/shared"
	uicommon "proxywatch/internal/ui/common"
	"proxywatch/internal/ui/keys"
	"proxywatch/internal/ui/platform"
	"proxywatch/internal/ui/render"
	"proxywatch/internal/ui/views"
)

// ── Private result types ────────────────────────────────────────────────────

type refreshResult struct {
	candidates          []shared.Candidate
	snapshotCandidates  []shared.Candidate
	hostSummaries       []shared.HostSummary
	lastError           string
	lastUpdate          time.Time
	selectedKey         string
	selectedIdx         int
	selectionKeyAtStart string
}

// ── Run ─────────────────────────────────────────────────────────────────────

func Run(app *shared.AppState, scanner shared.Scanner) error {
	initAppDefaults(app)

	scanner.Refresh(app)
	keys.ResortCandidates(app)
	normalizeInitialWhitelistSelection(app)

	// Auto-load keystore on startup. Prefer the last active keystore
	// (remembered across restarts), fall back to first unencrypted one.
	if entries := keystore.ListKeystores(); len(entries) > 0 {
		lastActive := keystore.LoadLastActiveKeystore()
		loaded := false
		if lastActive != "" {
			for _, entry := range entries {
				if entry.Name == lastActive && !entry.Secure {
					if values, err := keystore.LoadNonSecure(entry.Path); err == nil {
						app.KeystoreActiveEntry = entry.Name
						app.KeystorePath = entry.Path
						app.KeystoreSecure = false
						app.KeystoreValues = values
						keystore.ApplyToRuntime(values)
						keystore.SetActiveKeystore(&app.KeystoreValues)
						loaded = true
						break
					}
				}
			}
		}
		if !loaded {
			for _, entry := range entries {
				if !entry.Secure {
					if values, err := keystore.LoadNonSecure(entry.Path); err == nil {
						app.KeystoreActiveEntry = entry.Name
						app.KeystorePath = entry.Path
						app.KeystoreSecure = false
						app.KeystoreValues = values
						keystore.ApplyToRuntime(values)
						keystore.SetActiveKeystore(&app.KeystoreValues)
						keystore.SaveLastActiveKeystore(entry.Name)
						break
					}
				}
			}
		}
	}

	// Wire up the function variables in the views package so view models
	// can call back into key handlers and render helpers.
	wireBridge()

	root := NewRootModel(app, scanner)
	wireTrainingCallback(app, root.trainingCh, &root.trainingInFlight)

	// Wire YubiKey touch callback to update UI state.
	keystore.TouchCallback = func(active bool) {
		app.YubiKeyTouchRequired = active
	}

	return platform.RunTeaProgram(root)
}

// ── Bridge wiring ───────────────────────────────────────────────────────────
// Assign function variables in the views package so they can call back into
// key handlers and render/common helpers without importing the parent ui pkg.

func wireBridge() {
	views.ConvertKeyMsg = legacyConvertKeyMsg
	views.HandleQuitConfirmKey = handleQuitConfirmKey
	views.StepWorkflowMenu = keys.StepWorkflowMenu
	views.JumpToWorkflow = keys.JumpToWorkflow
	views.RequestQuit = requestQuit
	views.HandleContourKey = keys.HandleContourKey
	views.HandleContourModeKey = keys.HandleContourModeKey
	views.HandleDashboardKey = keys.HandleDashboardKey
	views.HandleKeystoreKey = keys.HandleKeystoreKey
	views.HandleWhitelistKey = keys.HandleWhitelistKey
	views.HandleInspectKey = keys.HandleInspectKey
	views.HandleCollectKey = keys.HandleCollectKey
	views.HandleKeyEvent = handleKeyEvent
	views.DrawCurrentMode = drawCurrentMode
	views.DrawQuitConfirmOverlay = uicommon.DrawQuitConfirmOverlay
	views.DashboardHostListMode = keys.DashboardHostListMode
	views.DashboardProcessCandidates = keys.DashboardProcessCandidates
	views.SelectedDashboardProcessIndex = keys.SelectedDashboardProcessIndex
	views.SafeRolePreset = uicommon.SafeRolePreset
	views.FormatDashboardAge = uicommon.FormatDashboardAge
	views.NormalizeDashboardRole = uicommon.NormalizeDashboardRole
	views.DashboardCandidateAgeSeconds = uicommon.DashboardCandidateAgeSeconds
	views.CycleInspectProcess = keys.CycleInspectProcess
	views.InspectorExternalOrgs = render.InspectorExternalOrgs
	views.EnsureKeystoreValues = keys.EnsureKeystoreValues
	views.KeystoreFieldEnvKey = keys.KeystoreFieldEnvKey
	views.KeystoreFieldVisible = keys.KeystoreFieldVisible
	views.RefreshCollectSources = keys.RefreshCollectSources
	views.CollectActionLabel = uicommon.CollectActionLabel
	views.CollectLiveLines = render.CollectLiveLines
	views.WhitelistProcessCandidates = keys.WhitelistProcessCandidates
	views.FormatWhitelistEntry = render.FormatWhitelistEntry
	views.RoleSortMenuLabels = keys.RoleSortMenuLabels
	views.ClampIndex = uicommon.ClampIndex
	views.HandleTrainingKey = keys.HandleTrainingKey
	views.HandlePcapAnalyzerKey = keys.HandlePcapAnalyzerKey
	views.EnterPcapAnalyzerMode = keys.EnterPcapAnalyzerMode
}

// ── Init / defaults ─────────────────────────────────────────────────────────

func initAppDefaults(app *shared.AppState) {
	if app.RefreshInt <= 0 {
		app.RefreshInt = 1 * time.Second
	}
	if app.ConfirmKillTimeout <= 0 {
		app.ConfirmKillTimeout = 3 * time.Second
	}
	app.SelectedIdx = -1
	app.Mode = shared.ModeDashboard
	if app.SortPreset == "" {
		app.SortPreset = "role"
	}
	if app.RolePreset == "" {
		app.RolePreset = "all"
	}

	// Training control plane defaults.
	app.TrainingAutoRetrain = true
	app.TrainingField = 0
	shared.AutoRetrainEnabled.Store(true)

	// Clear stale report data from previous runs.
	app.ContourReportLines = nil
	app.ContourProgressLines = nil
	app.CollectResultHasData = false
}

func normalizeInitialWhitelistSelection(app *shared.AppState) {
	if app.WhitelistSelected == 0 && len(app.WhitelistItems) == 0 {
		app.WhitelistSelected = -1
	}
}

func clearExpiredKillConfirmation(app *shared.AppState) {
	if app.ConfirmKillKey != "" && time.Now().After(app.ConfirmKillDeadline) {
		app.ConfirmKillKey = ""
	}
}

func clearExpiredQuitConfirmation(app *shared.AppState) {
	if app.ShowQuitConfirm && time.Now().After(app.QuitConfirmDeadline) {
		app.ShowQuitConfirm = false
	}
}

// ── Legacy key mapping ──────────────────────────────────────────────────────
// legacyConvertKeyMsg translates a bubbletea KeyMsg into a tcell EventKey.

func legacyConvertKeyMsg(msg tea.KeyMsg) *tcell.EventKey {
	switch msg.Type {
	case tea.KeyUp:
		return tcell.NewEventKey(tcell.KeyUp, 0, tcell.ModNone)
	case tea.KeyDown:
		return tcell.NewEventKey(tcell.KeyDown, 0, tcell.ModNone)
	case tea.KeyLeft:
		return tcell.NewEventKey(tcell.KeyLeft, 0, tcell.ModNone)
	case tea.KeyRight:
		return tcell.NewEventKey(tcell.KeyRight, 0, tcell.ModNone)
	case tea.KeyPgUp:
		return tcell.NewEventKey(tcell.KeyPgUp, 0, tcell.ModNone)
	case tea.KeyPgDown:
		return tcell.NewEventKey(tcell.KeyPgDn, 0, tcell.ModNone)
	case tea.KeyHome:
		return tcell.NewEventKey(tcell.KeyHome, 0, tcell.ModNone)
	case tea.KeyEnd:
		return tcell.NewEventKey(tcell.KeyEnd, 0, tcell.ModNone)
	case tea.KeyEnter:
		return tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone)
	case tea.KeyEscape:
		return tcell.NewEventKey(tcell.KeyEscape, 0, tcell.ModNone)
	case tea.KeyTab:
		return tcell.NewEventKey(tcell.KeyTab, 0, tcell.ModNone)
	case tea.KeyShiftTab:
		return tcell.NewEventKey(tcell.KeyBacktab, 0, tcell.ModNone)
	case tea.KeyBackspace:
		return tcell.NewEventKey(tcell.KeyBackspace2, 0, tcell.ModNone)
	case tea.KeyDelete:
		return tcell.NewEventKey(tcell.KeyDelete, 0, tcell.ModNone)
	case tea.KeySpace:
		return tcell.NewEventKey(tcell.KeyRune, ' ', tcell.ModNone)
	case tea.KeyF1:
		return tcell.NewEventKey(tcell.KeyF1, 0, tcell.ModNone)
	case tea.KeyF2:
		return tcell.NewEventKey(tcell.KeyF2, 0, tcell.ModNone)
	case tea.KeyF3:
		return tcell.NewEventKey(tcell.KeyF3, 0, tcell.ModNone)
	case tea.KeyF4:
		return tcell.NewEventKey(tcell.KeyF4, 0, tcell.ModNone)
	case tea.KeyF5:
		return tcell.NewEventKey(tcell.KeyF5, 0, tcell.ModNone)
	case tea.KeyCtrlC:
		return tcell.NewEventKey(tcell.KeyCtrlC, 0, tcell.ModCtrl)
	case tea.KeyRunes:
		if len(msg.Runes) > 0 {
			return tcell.NewEventKey(tcell.KeyRune, msg.Runes[0], tcell.ModNone)
		}
		return tcell.NewEventKey(tcell.KeyRune, 0, tcell.ModNone)
	}
	if len(msg.Runes) > 0 {
		return tcell.NewEventKey(tcell.KeyRune, msg.Runes[0], tcell.ModNone)
	}
	return tcell.NewEventKey(tcell.KeyRune, 0, tcell.ModNone)
}

// ── Legacy draw/key dispatch ────────────────────────────────────────────────

func drawCurrentMode(app *shared.AppState) {
	switch app.Mode {
	case shared.ModeDashboard:
		render.DrawDashboard(app)
	case shared.ModeInspect:
		render.DrawInspector(app)
	case shared.ModeWhitelist:
		render.DrawWhitelist(app)
	case shared.ModeCollect:
		render.DrawCollect(app)
	case shared.ModeContour:
		render.DrawContour(app)
	case shared.ModeKeystore:
		render.DrawKeystore(app)
	}
	uicommon.DrawQuitConfirmOverlay(app)
}

func handleKeyEvent(app *shared.AppState, tev *tcell.EventKey) bool {
	// Left/Right workflow cycling is handled by each bubbletea view directly.
	// The legacy path here only handles Escape and mode-specific keys.

	if tev.Key() == tcell.KeyEscape && app.Mode != shared.ModeDashboard && !uicommon.AnyOverlayOpen(app) {
		escapeToDashboard(app)
		return false
	}

	switch app.Mode {
	case shared.ModeDashboard:
		return keys.HandleDashboardKey(app, tev)
	case shared.ModeInspect:
		return keys.HandleInspectKey(app, tev)
	case shared.ModeWhitelist:
		return keys.HandleWhitelistKey(app, tev)
	case shared.ModeCollect:
		return keys.HandleCollectKey(app, tev)
	case shared.ModeContour:
		return keys.HandleContourKey(app, tev)
	case shared.ModeKeystore:
		return keys.HandleKeystoreKey(app, tev)
	default:
		return false
	}
}

func escapeToDashboard(app *shared.AppState) bool {
	switch app.Mode {
	case shared.ModeInspect:
		app.ShowInspectMenu = false
		app.ConfirmKillKey = ""
	case shared.ModeWhitelist:
		app.WhitelistShowHelp = false
	case shared.ModeCollect:
		app.CollectEditing = false
		app.CollectShowHelp = false
		app.CollectShowMenu = false
	case shared.ModeContour:
		app.ContourEditing = false
		app.ContourShowHelp = false
		app.ContourShowMenu = false
	case shared.ModeKeystore:
		app.KeystoreEditing = false
		app.KeystoreShowHelp = false
	}
	app.Mode = shared.ModeDashboard
	return false
}

func requestQuit(app *shared.AppState) bool {
	now := time.Now()
	if app.ShowQuitConfirm && now.Before(app.QuitConfirmDeadline) {
		app.ShowQuitConfirm = false
		return true
	}
	app.ShowQuitConfirm = true
	app.QuitConfirmDeadline = now.Add(keys.QuitConfirmTimeout)
	return false
}

func handleQuitConfirmKey(app *shared.AppState, tev *tcell.EventKey) (handled bool, shouldQuit bool) {
	if !app.ShowQuitConfirm {
		return false, false
	}
	switch tev.Key() {
	case tcell.KeyEscape:
		app.ShowQuitConfirm = false
		return true, false
	case tcell.KeyEnter:
		app.ShowQuitConfirm = false
		return true, true
	}
	switch tev.Rune() {
	case 'y', 'Y', 'q', 'Q':
		app.ShowQuitConfirm = false
		return true, true
	case 'n', 'N':
		app.ShowQuitConfirm = false
		return true, false
	default:
		return true, false
	}
}

// ── Refresh logic ───────────────────────────────────────────────────────────

func beginRefresh(app *shared.AppState, scanner shared.Scanner, refreshCh chan<- refreshResult, inFlight *bool) {
	if *inFlight {
		return
	}
	*inFlight = true

	selectionKeyAtStart := app.SelectedKey
	roleFilter := app.RoleFilterOverride
	go func() {
		defer func() {
			if r := recover(); r != nil {
				refreshCh <- refreshResult{
					lastError: fmt.Sprintf("refresh panic: %v", r),
				}
			}
		}()
		refreshApp := &shared.AppState{
			RoleFilterOverride: roleFilter,
		}
		scanner.Refresh(refreshApp)
		refreshCh <- refreshResult{
			candidates:          refreshApp.Candidates,
			snapshotCandidates:  refreshApp.SnapshotCandidates,
			hostSummaries:       refreshApp.HostSummaries,
			lastError:           refreshApp.LastError,
			lastUpdate:          refreshApp.LastUpdate,
			selectedKey:         refreshApp.SelectedKey,
			selectedIdx:         refreshApp.SelectedIdx,
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

	// Terminal bell + session logging for new suspicious candidates.
	newKeys := make(map[string]string, len(app.Candidates))
	bellRung := false
	for _, c := range app.Candidates {
		key := shared.CandidateKey(c)
		role := c.Role
		newKeys[key] = role
		if app.PrevCandidateKeys != nil {
			if _, existed := app.PrevCandidateKeys[key]; !existed {
				if role == "beacon" || role == "pivot" {
					if !bellRung && c.StrongEvidence {
						// Bell disabled — writing to stderr corrupts TUI.
						// TODO: use bubbletea program.Send() for bell.
						bellRung = true
					}
					state := shared.CandidateState(c)
					shared.LogSessionEvent(app, shared.SessionEvent{
						Timestamp: time.Now().UTC(),
						Host:      shared.DisplayHost(c.Host),
						PID:       candidatePID(c),
						Process:   candidateProcessName(c),
						Role:      c.Role,
						State:     state,
						Score:     c.Score,
						Event:     "new",
					})
				}
			}
		}
	}
	app.PrevCandidateKeys = newKeys

	if len(app.Candidates) == 0 {
		app.SelectedIdx = -1
		app.SelectedKey = ""
		keys.ResortCandidates(app)
		return
	}

	desiredKey := app.SelectedKey
	if desiredKey == "" {
		desiredKey = res.selectedKey
	}
	found := false
	for _, c := range app.Candidates {
		if shared.CandidateKey(c) == desiredKey {
			found = true
			break
		}
	}
	if !found && len(app.Candidates) > 0 {
		desiredKey = shared.CandidateKey(app.Candidates[0])
	}
	app.SelectedKey = desiredKey
	keys.ResortCandidates(app)
}

func candidatePID(c shared.Candidate) int {
	if c.Proc != nil {
		return c.Proc.Pid
	}
	return 0
}

func candidateProcessName(c shared.Candidate) string {
	if c.Proc != nil {
		return c.Proc.Name
	}
	return ""
}

func updateCollectionState(app *shared.AppState) {
	if !app.CollectActive {
		return
	}
	app.CollectData = append(app.CollectData, collectCandidatesForSource(app)...)

	// Only auto-stop if a duration was set (non-zero CollectUntil)
	if !app.CollectUntil.IsZero() && time.Now().After(app.CollectUntil) {
		keys.FinalizeCollection(app)
	}
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

// wireTrainingCallback sets up app.StartTrainingRetrain to poll the
// orchestrator for completion and deliver the result via the channel.
// The caller (keys/training.go) triggers the orchestrator directly before
// calling this callback.
func wireTrainingCallback(app *shared.AppState, ch chan TrainingExecResultMsg, inFlight *bool) {
	app.StartTrainingRetrain = func() {
		if *inFlight {
			return
		}
		*inFlight = true
		go func() {
			// The orchestrator runs asynchronously. Poll until done.
			if tOrch, ok := app.TrainingOrchestrator.(interface{ IsActive() bool }); ok {
				time.Sleep(200 * time.Millisecond)
				for tOrch.IsActive() {
					time.Sleep(500 * time.Millisecond)
				}
			}
			ch <- TrainingExecResultMsg{}
		}()
	}
}
