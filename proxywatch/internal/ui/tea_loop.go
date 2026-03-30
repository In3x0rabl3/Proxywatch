package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"proxywatch/internal/bloodhound"
	"proxywatch/internal/calibration"
	"proxywatch/internal/contour"
	"proxywatch/internal/keystore"
	"proxywatch/internal/shared"
	"proxywatch/internal/siem"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/gdamore/tcell/v2"
)

const quitConfirmTimeout = 5 * time.Second

const (
	collectFieldSource = iota
	collectFieldOutput
	collectFieldDuration
	collectFieldAction
)

const collectFieldMax = collectFieldAction

const (
	whitelistFieldProcess = iota
	whitelistFieldEntry
	whitelistFieldAdd
	whitelistFieldRemove
)

const whitelistFieldMax = whitelistFieldRemove

const (
	calibrateFieldProvider = iota
	calibrateFieldModel
	calibrateFieldProfile
	calibrateFieldOutput
	calibrateFieldDuration
	calibrateFieldAction
	calibrateFieldApply
)

const calibrateFieldMax = calibrateFieldApply

const (
	contourFieldEndpoint = iota
	contourFieldOutput
	contourFieldDuration
	contourFieldProbeMode
	contourFieldProbeRole
	contourFieldAction
)

const contourFieldMax = contourFieldAction

const (
	siemFieldProvider = iota
	siemFieldModel
	siemFieldSourceReport
	siemFieldJSONOutput
	siemFieldGenerate
	siemFieldCalibrate
	siemFieldReportOutput  // unused but kept for compatibility
	siemFieldSaveGeneration
	siemFieldDebugLog
	siemFieldRulesJSON
	siemFieldApply
	siemFieldSave
	siemFieldDisable
)

const siemFieldMax = siemFieldCalibrate

func siemFieldMaxFor(app *shared.AppState) int {
	if len(app.SIEMSourceReports) == 0 {
		return siemFieldCalibrate
	}
	return siemFieldGenerate
}

const (
	keystoreFieldOpenAIKey = iota
	keystoreFieldOpenAIBaseURL
	keystoreFieldAnthropicKey
	keystoreFieldAnthropicBaseURL
	keystoreFieldLocalLLMURL
	keystoreFieldLocalLLMAPIKey
	keystoreFieldCalibrationTimeout
	keystoreFieldBloodhoundURL
	keystoreFieldBloodhoundToken
	keystoreFieldBloodhoundTokenID
	keystoreFieldTLSDir
	keystoreFieldAgentToken
	keystoreFieldDisableClientCert
	keystoreFieldTrustOnFirstUse
	keystoreFieldMethod
	keystoreFieldSave
	keystoreFieldApply
	keystoreFieldLock
	keystoreFieldLoad // create new keystore (rendered in setup panel)
	keystoreFieldNew  // unused placeholder
)

const keystoreFieldMax = keystoreFieldNew

var (
	roleMenuChoices    = []string{"recommended", "all", "session", "beacon", "tunnel", "listen", "outbound"}
	sortMenuChoices    = []string{"default", "host", "role", "age", "state", "pid", "process"}
	refreshMenuChoices = []string{"100ms", "250ms", "500ms", "1s", "2s", "5s"}
)

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

type calibrationExecResult struct {
	result calibration.RunResult
	err    error
}

type contourExecResult struct {
	result contour.RunResult
	err    error
}

type siemExecResult struct {
	result siem.SIEMRunResult
	err    error
}

func Run(app *shared.AppState, scanner shared.Scanner) error {
	initAppDefaults(app)

	scanner.Refresh(app)
	resortCandidates(app)
	normalizeInitialWhitelistSelection(app)

	// Auto-load the first unencrypted keystore on startup.
	// Values are applied to runtime so dashboards can use them, but the
	// keystore stays locked (fields not visible) until explicitly opened.
	// Encrypted keystores are skipped entirely — user must activate via
	// Keystore view.
	if entries := keystore.ListKeystores(); len(entries) > 0 {
		for _, entry := range entries {
			if !entry.Secure {
				if values, err := keystore.LoadNonSecure(entry.Path); err == nil {
					app.KeystoreActiveEntry = entry.Name
					app.KeystorePath = entry.Path
					app.KeystoreSecure = false
					keystore.ApplyToRuntime(values)
					break
				}
			}
		}
	}

	root := NewRootModel(app, scanner)
	wireSIEMCallback(app, root.siemCh, &root.siemInFlight)

	// Wire YubiKey touch callback to update UI state.
	keystore.TouchCallback = func(active bool) {
		app.YubiKeyTouchRequired = active
	}

	// Set terminal default background to match the app theme.
	// This ensures ANSI reset codes ([0m) fall back to dark grey, not black.
	fmt.Fprint(os.Stdout, "\033]11;rgb:1e/1e/1e\007")

	p := tea.NewProgram(root, tea.WithAltScreen(), tea.WithInputTTY(), tea.WithMouseCellMotion())
	_, err := p.Run()

	// Restore terminal default background.
	fmt.Fprint(os.Stdout, "\033]111\007")
	return err
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
	case shared.ModeCalibration:
		DrawCalibration(app)
	case shared.ModeContour:
		DrawContour(app)
	case shared.ModeKeystore:
		DrawKeystore(app)
	case shared.ModeSIEM:
		DrawSIEM(app)
	}
	drawQuitConfirmOverlay(app)
}

func handleKeyEvent(app *shared.AppState, tev *tcell.EventKey) bool {
	switch tev.Key() {
	case tcell.KeyLeft:
		if stepWorkflowMenu(app, -1) {
			return false
		}
	case tcell.KeyRight:
		if stepWorkflowMenu(app, 1) {
			return false
		}
	}

	if tev.Key() == tcell.KeyEscape && app.Mode != shared.ModeDashboard && !anyOverlayOpen(app) {
		return escapeToDashboard(app)
	}

	switch app.Mode {
	case shared.ModeDashboard:
		return handleDashboardKey(app, tev)
	case shared.ModeInspect:
		return handleInspectKey(app, tev)
	case shared.ModeWhitelist:
		return handleWhitelistKey(app, tev)
	case shared.ModeCollect:
		return handleCollectKey(app, tev)
	case shared.ModeCalibration:
		return handleCalibrationKey(app, tev)
	case shared.ModeContour:
		return handleContourKey(app, tev)
	case shared.ModeKeystore:
		return handleKeystoreKey(app, tev)
	case shared.ModeSIEM:
		return handleSIEMKey(app, tev)
	default:
		return false
	}
}

func stepWorkflowMenu(app *shared.AppState, dir int) bool {
	if app == nil || dir == 0 {
		return false
	}
	order := []shared.AppMode{
		shared.ModeWhitelist,
		shared.ModeDashboard,
		shared.ModeCalibration,
		shared.ModeSIEM,
		shared.ModeCollect,
		shared.ModeContour,
		shared.ModeKeystore,
	}
	idx := -1
	for i, mode := range order {
		if mode == app.Mode {
			idx = i
			break
		}
	}
	if idx < 0 {
		return false
	}
	next := idx + dir
	if next < 0 {
		next = len(order) - 1
	}
	if next >= len(order) {
		next = 0
	}
	target := order[next]

	// When leaving a dashboard that uses a secure keystore, clear
	// sensitive runtime values so the next dashboard requires a fresh
	// YubiKey touch.
	if isActiveKeystoreSecure(app) {
		keystore.ClearSensitiveRuntime()
	}

	// Auto-lock the keystore when leaving the Keystore view.
	if app.Mode == shared.ModeKeystore && app.KeystoreUnlocked {
		app.KeystoreValues = make(map[string]string)
		app.KeystoreUnlocked = false
		keystore.SetActiveKeystore(nil)
		app.KeystoreEditing = false
		app.KeystorePanel = 0
		app.KeystoreField = keystoreFieldLoad
	}

	// For unlocked plain keystores, keep runtime in sync.
	if app.KeystoreUnlocked && app.KeystoreValues != nil && !isActiveKeystoreSecure(app) {
		keystore.ApplyToRuntime(app.KeystoreValues)
		keystore.SetActiveKeystore(&app.KeystoreValues)
	}
	if app.Mode == shared.ModeDashboard {
		closeDashboardOverlays(app)
	}
	switch target {
	case shared.ModeDashboard:
		escapeToDashboard(app)
	case shared.ModeWhitelist:
		enterWhitelistManager(app)
	case shared.ModeCalibration:
		enterCalibrationMode(app)
	case shared.ModeContour:
		enterContourMode(app)
	case shared.ModeSIEM:
		enterSIEMMode(app)
	case shared.ModeCollect:
		enterCollectMode(app)
	case shared.ModeKeystore:
		enterKeystoreMode(app)
	}
	return true
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
	case shared.ModeCalibration:
		app.CalibrateEditing = false
		app.ShowCalibrateHelp = false
		app.ShowCalibrateMenu = false
	case shared.ModeContour:
		app.ContourEditing = false
		app.ContourShowHelp = false
		app.ContourShowMenu = false
	case shared.ModeKeystore:
		app.KeystoreEditing = false
		app.KeystoreShowHelp = false
	case shared.ModeSIEM:
		app.SIEMEditing = false
		app.SIEMShowHelp = false
		app.SIEMShowMenu = false
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
	app.QuitConfirmDeadline = now.Add(quitConfirmTimeout)
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

// --- refresh logic (merged from ui_refresh.go) ---

func beginRefresh(app *shared.AppState, scanner shared.Scanner, refreshCh chan<- refreshResult, inFlight *bool) {
	if *inFlight {
		return
	}
	*inFlight = true

	selectionKeyAtStart := app.SelectedKey
	// Capture only the fields the scanner needs — copying the full AppState
	// would copy ProgressMu (sync.Mutex) which is undefined behavior.
	roleFilter := app.RoleFilterOverride
	go func() {
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
				if role == "session" || role == "beacon" || role == "tunnel" {
					if !bellRung {
						fmt.Fprint(os.Stderr, "\a") // terminal bell
						bellRung = true
					}
					state := "watch"
					if c.ActiveProxying {
						state = "active"
					} else if c.StrongEvidence {
						state = "strong"
					}
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
	collectEmit := func(line string) {
		app.CollectProgressLines = append(app.CollectProgressLines, line)
	}
	candidateCount := len(app.CollectData)
	collectEmit(fmt.Sprintf("[*] Building graph from %d candidates...", candidateCount))
	payload := bloodhound.BuildGraph(app.CollectData)
	collectEmit(fmt.Sprintf("[+] Graph: %d nodes, %d edges", len(payload.Graph.Nodes), len(payload.Graph.Edges)))
	collectEmit(fmt.Sprintf("[*] Writing JSON to %s...", app.CollectOutput))

	// Save results for display.
	app.CollectResultNodes = len(payload.Graph.Nodes)
	app.CollectResultEdges = len(payload.Graph.Edges)
	app.CollectResultOutput = app.CollectOutput
	app.CollectResultCandidates = candidateCount
	app.CollectResultDuration = time.Since(app.CollectStartedAt).Round(time.Second).String()
	// Count hosts, external/internal connections, listeners.
	hosts := make(map[string]bool)
	extCount, intCount, listenCount := 0, 0, 0
	for _, c := range app.CollectData {
		hosts[shared.DisplayHost(c.Host)] = true
		listenCount += len(c.Listeners)
		for _, cn := range c.Conns {
			if shared.IsInternalIP(cn.RemoteAddress) {
				intCount++
			} else if cn.RemoteAddress != "" && !shared.IsLoopbackIP(cn.RemoteAddress) {
				extCount++
			}
		}
	}
	app.CollectResultHosts = len(hosts)
	app.CollectResultExternal = extCount
	app.CollectResultInternal = intCount
	app.CollectResultListeners = listenCount
	app.CollectResultUploaded = false
	app.CollectResultHasData = true

	if err := bloodhound.WriteJSON(app.CollectOutput, payload); err != nil {
		collectEmit("[-] Write failed: " + err.Error())
		setWorkflowStatus(app, &app.CollectStatusText, &app.CollectStatusError, &app.CollectStatusUntil,"collection failed: "+err.Error(), true)
	} else {
		collectEmit("[+] JSON written")
		if configured, reason := bloodhound.UploadConfigStatus(); !configured {
			setWorkflowStatus(app, &app.CollectStatusText, &app.CollectStatusError, &app.CollectStatusUntil,"collection written: "+app.CollectOutput+" (upload skipped: "+reason+")", false)
		} else {
			collectEmit("[*] Uploading to BloodHound...")
			if err := bloodhound.UploadIfConfigured(filepath.Base(app.CollectOutput), payload); err != nil {
				collectEmit("[-] Upload failed: " + err.Error())
				setWorkflowStatus(app, &app.CollectStatusText, &app.CollectStatusError, &app.CollectStatusUntil,"collection written, upload failed: "+err.Error(), true)
			} else {
				collectEmit("[+] Upload complete")
				app.CollectResultUploaded = true
				setWorkflowStatus(app, &app.CollectStatusText, &app.CollectStatusError, &app.CollectStatusUntil,"collection written: "+app.CollectOutput, false)
			}
		}
	}
	app.CollectActive = false
	app.CollectStartedAt = time.Time{}
	app.CollectData = nil
	app.CollectEditing = false
	app.CollectProgressLines = nil
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

func applyRolePreset(app *shared.AppState, preset string) {
	app.RolePreset = preset
	switch preset {
	case "recommended":
		app.RoleFilterOverride = shared.ParseRoleFilter("session,beacon,tunnel")
	case "all":
		app.RoleFilterOverride = shared.ParseRoleFilter("all")
	default:
		app.RoleFilterOverride = shared.ParseRoleFilter(preset)
	}
}
