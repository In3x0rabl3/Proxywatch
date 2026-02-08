package ui

import (
	"path/filepath"
	"strconv"
	"time"

	"proxywatch/internal/bloodhound"
	"proxywatch/internal/shared"
	"proxywatch/internal/telemetry"

	"github.com/gdamore/tcell/v2"
)

const (
	collectFieldOutput = iota
	collectFieldDuration
	collectFieldRoles
	collectFieldAction
)

const collectFieldMax = collectFieldAction

type refreshResult struct {
	candidates          []shared.Candidate
	lastError           string
	lastUpdate          time.Time
	selectedKey         string
	selectedIdx         int
	selectionKeyAtStart string
}

func Run(app *shared.AppState, scanner shared.Scanner) error {
	s, err := tcell.NewScreen()
	if err != nil {
		return err
	}
	if err := s.Init(); err != nil {
		return err
	}
	defer s.Fini()

	app.Screen = s
	initAppDefaults(app)

	scanner.Refresh(app)
	normalizeInitialWhitelistSelection(app)

	events := startEventPump(s)
	refreshCh := make(chan refreshResult, 1)
	refreshInFlight := false

	tick := time.NewTicker(app.RefreshInt)
	defer tick.Stop()

	for {
		clearExpiredKillConfirmation(app)
		drawCurrentMode(app)
		s.Show()

		select {
		case ev := <-events:
			if handleUIEvent(app, s, ev) {
				return nil
			}

		case <-tick.C:
			beginRefresh(app, scanner, refreshCh, &refreshInFlight)

		case res := <-refreshCh:
			refreshInFlight = false
			applyRefreshResult(app, res)
			updateCollectionState(app)
		}
	}
}

func initAppDefaults(app *shared.AppState) {
	if app.RefreshInt <= 0 {
		app.RefreshInt = 1 * time.Second
	}
	if app.ConfirmKillTimeout <= 0 {
		app.ConfirmKillTimeout = 3 * time.Second
	}
	app.SelectedIdx = -1
	app.Mode = shared.ModeDashboard
}

func normalizeInitialWhitelistSelection(app *shared.AppState) {
	if app.WhitelistSelected == 0 && len(app.WhitelistItems) == 0 {
		app.WhitelistSelected = -1
	}
}

func startEventPump(s tcell.Screen) chan tcell.Event {
	events := make(chan tcell.Event, 16)
	go func() {
		for {
			events <- s.PollEvent()
		}
	}()
	return events
}

func clearExpiredKillConfirmation(app *shared.AppState) {
	if app.ConfirmKillKey != "" && time.Now().After(app.ConfirmKillDeadline) {
		app.ConfirmKillKey = ""
	}
}

func drawCurrentMode(app *shared.AppState) {
	switch app.Mode {
	case shared.ModeDashboard:
		DrawDashboard(app)
	case shared.ModeInspect:
		DrawInspector(app)
	case shared.ModeWhitelist:
		DrawWhitelist(app)
	case shared.ModeCollect:
		DrawCollect(app)
	}
}

func handleUIEvent(app *shared.AppState, s tcell.Screen, ev tcell.Event) bool {
	switch tev := ev.(type) {
	case *tcell.EventResize:
		s.Sync()
	case *tcell.EventKey:
		return handleKeyEvent(app, tev)
	}
	return false
}

func handleKeyEvent(app *shared.AppState, tev *tcell.EventKey) bool {
	switch app.Mode {
	case shared.ModeDashboard:
		return handleDashboardKey(app, tev)
	case shared.ModeInspect:
		return handleInspectKey(app, tev)
	case shared.ModeWhitelist:
		return handleWhitelistKey(app, tev)
	case shared.ModeCollect:
		return handleCollectKey(app, tev)
	default:
		return false
	}
}

func handleDashboardKey(app *shared.AppState, tev *tcell.EventKey) bool {
	switch tev.Key() {
	case tcell.KeyUp:
		moveDashboardSelectionUp(app)
	case tcell.KeyDown:
		moveDashboardSelectionDown(app)
	case tcell.KeyEnter:
		enterInspector(app)
	}

	switch tev.Rune() {
	case 'c', 'C':
		enterCollectMode(app)
	case 'W':
		enterWhitelistManager(app)
	case 'w':
		whitelistSelectedCandidate(app)
	case 'q':
		return true
	}

	return false
}

func moveDashboardSelectionUp(app *shared.AppState) {
	if len(app.Candidates) > 0 && app.SelectedIdx > 0 && app.SelectedIdx < len(app.Candidates) {
		app.SelectedIdx--
		app.SelectedKey = shared.CandidateKey(app.Candidates[app.SelectedIdx])
	}
}

func moveDashboardSelectionDown(app *shared.AppState) {
	if app.SelectedIdx >= 0 && app.SelectedIdx < len(app.Candidates)-1 {
		app.SelectedIdx++
		app.SelectedKey = shared.CandidateKey(app.Candidates[app.SelectedIdx])
	}
}

func enterInspector(app *shared.AppState) {
	if app.SelectedIdx < 0 || app.SelectedIdx >= len(app.Candidates) {
		return
	}
	app.InspectKey = shared.CandidateKey(app.Candidates[app.SelectedIdx])
	app.InspectExplain = false
	app.Mode = shared.ModeInspect
}

func enterCollectMode(app *shared.AppState) {
	if app.CollectOutput == "" {
		app.CollectOutput = "proxywatch-collection.json"
	}
	if app.CollectDurationStr == "" {
		app.CollectDurationStr = "5m"
	}
	if app.CollectRoles == "" {
		app.CollectRoles = "tunnel,session,beacon"
	}
	app.CollectEditing = false
	if app.CollectField < 0 || app.CollectField > collectFieldMax {
		app.CollectField = collectFieldOutput
	}
	app.Mode = shared.ModeCollect
}

func enterWhitelistManager(app *shared.AppState) {
	if app.Whitelist == nil {
		app.LastError = "whitelist not configured"
		return
	}
	app.WhitelistItems = app.Whitelist.List()
	if len(app.WhitelistItems) == 0 {
		app.WhitelistSelected = -1
	} else if app.WhitelistSelected < 0 || app.WhitelistSelected >= len(app.WhitelistItems) {
		app.WhitelistSelected = 0
	}
	app.Mode = shared.ModeWhitelist
}

func whitelistSelectedCandidate(app *shared.AppState) {
	if app.SelectedIdx < 0 || app.SelectedIdx >= len(app.Candidates) {
		return
	}
	if app.Whitelist == nil {
		app.LastError = "whitelist not configured"
		return
	}

	cand := app.Candidates[app.SelectedIdx]
	if _, err := app.Whitelist.AddCandidate(cand); err != nil {
		app.LastError = "whitelist failed: " + err.Error()
		return
	}

	app.LastError = "Whitelisted " + cand.Proc.Name
	app.Candidates = app.Whitelist.Filter(app.Candidates)
	if len(app.Candidates) == 0 {
		app.SelectedIdx = -1
		app.SelectedKey = ""
		return
	}
	if app.SelectedIdx >= len(app.Candidates) {
		app.SelectedIdx = len(app.Candidates) - 1
	}
	app.SelectedKey = shared.CandidateKey(app.Candidates[app.SelectedIdx])
}

func handleInspectKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if app.ConfirmKillKey != "" {
		if r := tev.Rune(); r != 'k' && r != 'K' && r != 'y' && r != 'Y' {
			app.ConfirmKillKey = ""
		}
	}

	if tev.Key() == tcell.KeyEscape {
		app.ConfirmKillKey = ""
		app.Mode = shared.ModeDashboard
	}

	if tev.Rune() == 'q' {
		app.ConfirmKillKey = ""
		return true
	}

	if tev.Rune() == 'x' || tev.Rune() == 'X' {
		app.InspectExplain = !app.InspectExplain
	}

	if tev.Rune() == 'k' || tev.Rune() == 'K' || tev.Rune() == 'y' || tev.Rune() == 'Y' {
		handleKillRequest(app, tev.Rune())
	}

	return false
}

func handleKillRequest(app *shared.AppState, keyRune rune) {
	key := app.InspectKey
	if app.ConfirmKill {
		if app.ConfirmKillKey != key || time.Now().After(app.ConfirmKillDeadline) {
			if keyRune == 'y' || keyRune == 'Y' {
				return
			}
			app.ConfirmKillKey = key
			app.ConfirmKillDeadline = time.Now().Add(app.ConfirmKillTimeout)
			return
		}
	}

	idx := FindIndexByKey(app.Candidates, key)
	if idx == -1 {
		app.LastError = "Process no longer present"
		app.ConfirmKillKey = ""
		return
	}

	pid := app.Candidates[idx].Proc.Pid
	host := shared.DisplayHost(app.Candidates[idx].Host)

	if app.LocalHost != "" && host == app.LocalHost {
		if err := telemetry.KillProcess(pid); err != nil {
			app.LastError = "Kill failed: " + err.Error()
		} else {
			app.LastError = "Killed PID " + strconv.Itoa(pid) + " (" + app.Candidates[idx].Proc.Name + ")"
		}
		app.ConfirmKillKey = ""
		return
	}

	if app.RemoteKill == nil {
		app.LastError = "Kill disabled for remote host"
		app.ConfirmKillKey = ""
		return
	}

	if err := app.RemoteKill(host, pid); err != nil {
		app.LastError = "Remote kill failed: " + err.Error()
	} else {
		app.LastError = "Remote kill sent for PID " + strconv.Itoa(pid) + " (" + app.Candidates[idx].Proc.Name + ")"
	}
	app.ConfirmKillKey = ""
}

func handleWhitelistKey(app *shared.AppState, tev *tcell.EventKey) bool {
	switch tev.Key() {
	case tcell.KeyUp:
		if app.WhitelistSelected > 0 && app.WhitelistSelected < len(app.WhitelistItems) {
			app.WhitelistSelected--
		}
	case tcell.KeyDown:
		if app.WhitelistSelected >= 0 && app.WhitelistSelected < len(app.WhitelistItems)-1 {
			app.WhitelistSelected++
		}
	case tcell.KeyEscape:
		app.Mode = shared.ModeDashboard
	}

	if tev.Rune() == 'q' {
		return true
	}

	if tev.Rune() == 'd' || tev.Rune() == 'D' || tev.Rune() == 'u' || tev.Rune() == 'U' {
		removeSelectedWhitelistEntry(app)
	}

	return false
}

func removeSelectedWhitelistEntry(app *shared.AppState) {
	if app.Whitelist == nil {
		app.LastError = "whitelist not configured"
		return
	}
	if app.WhitelistSelected < 0 || app.WhitelistSelected >= len(app.WhitelistItems) {
		return
	}

	key := app.WhitelistItems[app.WhitelistSelected]
	if err := app.Whitelist.Remove(key); err != nil {
		app.LastError = "unwhitelist failed: " + err.Error()
		return
	}

	app.LastError = "Removed whitelist entry"
	app.WhitelistItems = app.Whitelist.List()
	if len(app.WhitelistItems) == 0 {
		app.WhitelistSelected = -1
	} else if app.WhitelistSelected >= len(app.WhitelistItems) {
		app.WhitelistSelected = len(app.WhitelistItems) - 1
	}
}

func handleCollectKey(app *shared.AppState, tev *tcell.EventKey) bool {
	switch tev.Key() {
	case tcell.KeyUp:
		if app.CollectField > collectFieldOutput {
			app.CollectField--
		} else {
			app.CollectField = collectFieldMax
		}
	case tcell.KeyDown:
		if app.CollectField < collectFieldMax {
			app.CollectField++
		} else {
			app.CollectField = collectFieldOutput
		}
	case tcell.KeyLeft:
		if app.CollectField == collectFieldDuration && !app.CollectActive {
			app.CollectDurationStr = stepDuration(app.CollectDurationStr, -1)
		}
	case tcell.KeyRight:
		if app.CollectField == collectFieldDuration && !app.CollectActive {
			app.CollectDurationStr = stepDuration(app.CollectDurationStr, 1)
		}
	case tcell.KeyBackspace, tcell.KeyBackspace2:
		handleCollectBackspace(app)
	case tcell.KeyEnter:
		handleCollectEnter(app)
	case tcell.KeyEscape:
		if app.CollectEditing {
			app.CollectEditing = false
		} else {
			app.Mode = shared.ModeDashboard
		}
	}

	if tev.Rune() == 'q' {
		return true
	}

	if tev.Key() == tcell.KeyRune && tev.Rune() != 0 {
		handleCollectRuneInput(app, tev.Rune())
	}

	return false
}

func handleCollectBackspace(app *shared.AppState) {
	if !app.CollectEditing {
		return
	}
	switch app.CollectField {
	case collectFieldOutput:
		app.CollectOutput = trimLastRune(app.CollectOutput)
	case collectFieldRoles:
		app.CollectRoles = trimLastRune(app.CollectRoles)
	}
}

func handleCollectEnter(app *shared.AppState) {
	switch app.CollectField {
	case collectFieldOutput, collectFieldRoles:
		if app.CollectActive {
			return
		}
		app.CollectEditing = !app.CollectEditing

	case collectFieldAction:
		if app.CollectActive {
			finalizeCollection(app)
			return
		}

		dur, err := time.ParseDuration(app.CollectDurationStr)
		if err != nil || dur <= 0 {
			app.LastError = "invalid duration"
			return
		}

		app.CollectRoleFilter = shared.ParseRoleFilter(app.CollectRoles)
		if len(app.CollectRoleFilter) == 0 {
			app.CollectRoleFilter = shared.ParseRoleFilter("tunnel,session,beacon")
		}
		app.RoleFilterOverride = app.CollectRoleFilter
		app.CollectData = nil
		app.CollectActive = true
		app.CollectUntil = time.Now().Add(dur)
		app.CollectEditing = false
		app.Mode = shared.ModeDashboard
	}
}

func handleCollectRuneInput(app *shared.AppState, r rune) {
	if !app.CollectEditing || r < 32 || r > 126 {
		return
	}
	switch app.CollectField {
	case collectFieldOutput:
		app.CollectOutput += string(r)
	case collectFieldRoles:
		app.CollectRoles += string(r)
	}
}

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
	app.LastError = res.lastError
	app.LastUpdate = res.lastUpdate

	if len(app.Candidates) == 0 {
		app.SelectedIdx = -1
		app.SelectedKey = ""
		return
	}

	if app.SelectedKey != res.selectionKeyAtStart {
		idx := FindIndexByKey(app.Candidates, app.SelectedKey)
		if idx >= 0 {
			app.SelectedIdx = idx
		} else {
			app.SelectedIdx = 0
			app.SelectedKey = shared.CandidateKey(app.Candidates[0])
		}
		return
	}

	app.SelectedKey = res.selectedKey
	app.SelectedIdx = res.selectedIdx
}

func updateCollectionState(app *shared.AppState) {
	if !app.CollectActive {
		return
	}

	if len(app.CollectRoleFilter) == 0 {
		app.CollectRoleFilter = shared.ParseRoleFilter(app.CollectRoles)
	}
	for _, c := range app.Candidates {
		if !shared.RoleMatchesFilter(c.Role, app.CollectRoleFilter) {
			continue
		}
		app.CollectData = append(app.CollectData, c)
	}

	if time.Now().After(app.CollectUntil) {
		finalizeCollection(app)
	}
}

func finalizeCollection(app *shared.AppState) {
	payload := bloodhound.BuildGraph(app.CollectData, app.CollectRoleFilter)
	if err := bloodhound.WriteJSON(app.CollectOutput, payload); err != nil {
		app.LastError = "collection failed: " + err.Error()
	} else if configured, reason := bloodhound.UploadConfigStatus(); !configured {
		app.LastError = "collection written: " + app.CollectOutput + " (upload skipped: " + reason + ")"
	} else if err := bloodhound.UploadIfConfigured(filepath.Base(app.CollectOutput), payload); err != nil {
		app.LastError = "collection written, upload failed: " + err.Error()
	} else {
		app.LastError = "collection written: " + app.CollectOutput
	}
	app.CollectActive = false
	app.CollectData = nil
	app.CollectRoleFilter = nil
	app.RoleFilterOverride = nil
	app.CollectEditing = false
}

func trimLastRune(s string) string {
	if s == "" {
		return s
	}
	runes := []rune(s)
	return string(runes[:len(runes)-1])
}
