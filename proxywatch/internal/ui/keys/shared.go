package keys

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"proxywatch/internal/keystore"
	"proxywatch/internal/proxyhound"
	"proxywatch/internal/shared"
	"proxywatch/internal/ui/common"

	"github.com/gdamore/tcell/v2"
)

// ── Field constants (mirrors of ui package private constants) ───────────────

const (
	CollectFieldSource = iota
	CollectFieldOutput
	CollectFieldDuration
	CollectFieldAction
)

const CollectFieldMax = CollectFieldAction

const (
	WhitelistFieldProcess = iota
	WhitelistFieldEntry
	WhitelistFieldAdd
	WhitelistFieldRemove
)

const WhitelistFieldMax = WhitelistFieldRemove

const (
	ContourFieldSource = iota
	ContourFieldEndpoint
	ContourFieldOutput
	ContourFieldDuration
	ContourFieldProbeMode
	ContourFieldProbeRole
	ContourFieldAction
)

const ContourFieldMax = ContourFieldAction

const (
	ContourNewFieldRole = iota
	ContourNewFieldMethod
	ContourNewFieldPort
	ContourNewFieldMode
)

const (
	ContourDashScan     = 0
	ContourDashContour  = 1
	ContourDashServices = 2
)

const (
	KeystoreFieldOpenAIKey = iota
	KeystoreFieldOpenAIBaseURL
	KeystoreFieldAnthropicKey
	KeystoreFieldAnthropicBaseURL
	KeystoreFieldLocalLLMURL
	KeystoreFieldLocalLLMAPIKey
	KeystoreFieldCalibrationTimeout
	KeystoreFieldProxyhoundURL
	KeystoreFieldProxyhoundToken
	KeystoreFieldProxyhoundTokenID
	KeystoreFieldTLSDir
	KeystoreFieldAgentToken
	KeystoreFieldDisableClientCert
	KeystoreFieldTrustOnFirstUse
	KeystoreFieldSentinelAuth
	KeystoreFieldSentinelEndpoint
	KeystoreFieldSentinelDCRID
	KeystoreFieldSentinelStream
	KeystoreFieldMethod
	KeystoreFieldGitHubToken
	KeystoreFieldBuildkiteToken
	KeystoreFieldAWSAccessKey
	KeystoreFieldAWSSecretKey
	KeystoreFieldAzureTenantID
	KeystoreFieldAzureClientID
	KeystoreFieldAzureClientSecret
	KeystoreFieldGCPServiceKey
	KeystoreFieldSlackBotToken
	KeystoreFieldDiscordBotToken
	KeystoreFieldTelegramBotKey
	KeystoreFieldFirebaseKey
	KeystoreFieldTeamsAuth
	KeystoreFieldGitLabToken
	KeystoreFieldSave
	KeystoreFieldApply
	KeystoreFieldLock
	KeystoreFieldLoad
	KeystoreFieldNew
)

const KeystoreFieldMax = KeystoreFieldNew

var (
	RoleMenuChoices    = []string{"recommended", "all", "control-channel", "control-pivot", "listener", "outbound"}
	SortMenuChoices    = []string{"default", "host", "role", "age", "state", "pid", "process"}
	RefreshMenuChoices = []string{"100ms", "250ms", "500ms", "1s", "2s", "5s"}
)

const QuitConfirmTimeout = 5 * time.Second

// ── Result types ────────────────────────────────────────────────────────────

// ── Private helper functions (mirrors of ui package private funcs) ──────────

func requestQuit(app *shared.AppState) bool {
	now := time.Now()
	if app.ShowQuitConfirm && now.Before(app.QuitConfirmDeadline) {
		app.ShowQuitConfirm = false
		return true
	}
	app.ShowQuitConfirm = true
	app.QuitConfirmDeadline = now.Add(QuitConfirmTimeout)
	return false
}

func handleOverlayKey(app *shared.AppState, tev *tcell.EventKey, ov overlayState) bool {
	if tev.Rune() == 'q' {
		return requestQuit(app)
	}
	if tev.Rune() == '?' {
		if *ov.showHelp {
			*ov.showHelp = false
		} else {
			*ov.showMenu = false
			*ov.showHelp = true
			*ov.helpIndex = 0
		}
		return false
	}
	if tev.Key() == tcell.KeyEscape {
		if *ov.showHelp {
			*ov.showHelp = false
		} else {
			*ov.showMenu = false
		}
		return false
	}
	if *ov.showHelp {
		maxIdx := len(ov.helpOptions()) - 1
		switch tev.Key() {
		case tcell.KeyUp:
			if *ov.helpIndex > 0 {
				*ov.helpIndex--
			}
		case tcell.KeyDown:
			if *ov.helpIndex < max(0, maxIdx) {
				*ov.helpIndex++
			}
		}
		return false
	}
	if !*ov.showMenu || len(*ov.menuOptions) == 0 {
		return false
	}
	switch tev.Key() {
	case tcell.KeyUp:
		if *ov.menuIndex > 0 {
			*ov.menuIndex--
		}
	case tcell.KeyDown:
		if *ov.menuIndex < len(*ov.menuOptions)-1 {
			*ov.menuIndex++
		}
	case tcell.KeyEnter:
		ov.applyMenu(app)
		*ov.showMenu = false
	}
	return false
}

type overlayState struct {
	showHelp    *bool
	showMenu    *bool
	helpIndex   *int
	menuIndex   *int
	menuOptions *[]string
	menuKind    *string
	menuTitle   *string
	helpOptions func() []string
	applyMenu   func(*shared.AppState)
}

func openWorkflowMenu(kind, title string, options []string, selected int, showHelp, showMenu *bool, menuKind, menuTitle *string, menuOptions *[]string, menuIndex *int) {
	if len(options) == 0 {
		return
	}
	if showHelp != nil {
		*showHelp = false
	}
	*showMenu = true
	*menuKind = kind
	*menuTitle = title
	*menuOptions = options
	if selected < 0 {
		selected = 0
	}
	if selected >= len(options) {
		selected = len(options) - 1
	}
	*menuIndex = selected
}

func cycleField(field *int, minField, maxField int, up bool) {
	if up {
		if *field > minField {
			*field--
		} else {
			*field = maxField
		}
	} else {
		if *field < maxField {
			*field++
		} else {
			*field = minField
		}
	}
}

func setWorkflowStatus(app *shared.AppState, text *string, isErr *bool, until *time.Time, msg string, isError bool) {
	common.SetWorkflowStatus(app, text, isErr, until, msg, isError)
}

func findIndex(items []string, value string) int {
	for i := range items {
		if items[i] == value {
			return i
		}
	}
	return -1
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

func trimLastRune(s string) string {
	if s == "" {
		return s
	}
	runes := []rune(s)
	return string(runes[:len(runes)-1])
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

func safePreset(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func clampIndex(idx, n int) int {
	return common.ClampIndex(idx, n)
}

func sortedCandidates(cands []shared.Candidate, preset string) []shared.Candidate {
	return common.SortedCandidates(cands, preset)
}

// FindIndexByKey is exported so the ui package can call it if needed.
func FindIndexByKey(cands []shared.Candidate, key string) int {
	return common.FindIndexByKey(cands, key)
}

func applyRolePreset(app *shared.AppState, preset string) {
	app.RolePreset = preset
	switch preset {
	case "recommended":
		app.RoleFilterOverride = shared.ParseRoleFilter("control-session,control-beacon,control-pivot")
	case "all":
		app.RoleFilterOverride = nil
	default:
		app.RoleFilterOverride = shared.ParseRoleFilter(preset)
	}
}

// ── Workflow step function ──────────────────────────────────────────────────

func StepWorkflowMenu(app *shared.AppState, dir int) bool {
	if app == nil || dir == 0 {
		return false
	}
	order := []shared.AppMode{
		shared.ModeDashboard,
		shared.ModeTraining,
		shared.ModeContour,
		shared.ModeCollect,
		shared.ModeSIEM,
		shared.ModeWhitelist,
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
	app.LastError = ""
	if app.Mode == shared.ModeKeystore && app.KeystoreUnlocked {
		if app.KeystoreSecure {
			app.KeystoreValues = make(map[string]string)
			keystore.SetActiveKeystore(nil)
		}
		app.KeystoreUnlocked = false
		app.KeystoreEditing = false
		app.KeystoreWizardOpen = false
		app.KeystorePanel = 0
		app.KeystoreField = KeystoreFieldLoad
	}
	if len(app.KeystoreValues) > 0 && !isActiveKeystoreSecure(app) {
		keystore.ApplyToRuntime(app.KeystoreValues)
		keystore.SetActiveKeystore(&app.KeystoreValues)
	}
	if app.Mode == shared.ModeDashboard {
		CloseDashboardOverlays(app)
	}
	switch target {
	case shared.ModeDashboard:
		escapeToDashboard(app)
	case shared.ModeWhitelist:
		EnterWhitelistManager(app)
	case shared.ModeTraining:
		EnterTrainingMode(app)
	case shared.ModeContour:
		EnterContourMode(app)
	case shared.ModeCollect:
		EnterCollectMode(app)
	case shared.ModeSIEM:
		EnterSIEMMode(app)
	case shared.ModeKeystore:
		EnterKeystoreMode(app)
	}
	return true
}

// JumpToWorkflow switches to a workflow by number key (1-6) or 0 for dashboard.
// Returns true if the key was handled.
func JumpToWorkflow(app *shared.AppState, r rune) bool {
	if app == nil {
		return false
	}
	// Allow jumping even without a host since the user is explicitly requesting it.
	var target shared.AppMode
	switch r {
	case '0':
		target = shared.ModeDashboard
	case '1':
		target = shared.ModeTraining
	case '2':
		target = shared.ModeContour
	case '3':
		target = shared.ModeCollect
	case '4':
		target = shared.ModeSIEM
	case '5':
		target = shared.ModeWhitelist
	case '6':
		target = shared.ModeKeystore
	default:
		return false
	}
	if target == app.Mode {
		return true // already there
	}
	// Clean up keystore state when leaving.
	if app.Mode == shared.ModeKeystore && app.KeystoreUnlocked {
		if app.KeystoreSecure {
			app.KeystoreValues = make(map[string]string)
			keystore.SetActiveKeystore(nil)
		}
		app.KeystoreUnlocked = false
		app.KeystoreEditing = false
		app.KeystoreWizardOpen = false
		app.KeystorePanel = 0
		app.KeystoreField = KeystoreFieldLoad
	}
	if len(app.KeystoreValues) > 0 && !isActiveKeystoreSecure(app) {
		keystore.ApplyToRuntime(app.KeystoreValues)
		keystore.SetActiveKeystore(&app.KeystoreValues)
	}
	if app.Mode == shared.ModeDashboard {
		CloseDashboardOverlays(app)
	}
	app.LastError = ""
	switch target {
	case shared.ModeDashboard:
		escapeToDashboard(app)
	case shared.ModeTraining:
		EnterTrainingMode(app)
	case shared.ModeContour:
		EnterContourMode(app)
	case shared.ModeCollect:
		EnterCollectMode(app)
	case shared.ModeSIEM:
		EnterSIEMMode(app)
	case shared.ModeWhitelist:
		EnterWhitelistManager(app)
	case shared.ModeKeystore:
		EnterKeystoreMode(app)
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

func CloseDashboardOverlays(app *shared.AppState) {
	app.ShowHelp = false
	app.ShowRoleMenu = false
	app.ShowSortMenu = false
	app.ShowRefreshMenu = false
}

func isActiveKeystoreSecure(app *shared.AppState) bool {
	if app.KeystoreActiveEntry == "" {
		return false
	}
	for _, e := range keystore.ListKeystores() {
		if e.Name == app.KeystoreActiveEntry {
			return e.Secure
		}
	}
	return false
}

// ── Collect helpers ─────────────────────────────────────────────────────────

var CollectDurations = common.CollectDurations

func RefreshCollectSources(app *shared.AppState) {
	if app == nil {
		return
	}
	opts := CollectSourceOptions(app)
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

func CollectSourceOptions(app *shared.AppState) []string {
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

func FinalizeCollection(app *shared.AppState) {
	collectEmit := func(line string) {
		app.CollectProgressLines = append(app.CollectProgressLines, line)
	}
	candidateCount := len(app.CollectData)
	collectEmit(fmt.Sprintf("[*] Building graph from %d candidates...", candidateCount))
	payload := proxyhound.BuildGraph(app.CollectData)
	collectEmit(fmt.Sprintf("[+] Graph: %d nodes, %d edges", len(payload.Graph.Nodes), len(payload.Graph.Edges)))
	collectEmit(fmt.Sprintf("[*] Writing JSON to %s...", app.CollectOutput))

	app.CollectResultNodes = len(payload.Graph.Nodes)
	app.CollectResultEdges = len(payload.Graph.Edges)
	app.CollectResultOutput = app.CollectOutput
	app.CollectResultCandidates = candidateCount
	app.CollectResultDuration = time.Since(app.CollectStartedAt).Round(time.Second).String()
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

	if err := proxyhound.WriteJSON(app.CollectOutput, payload); err != nil {
		collectEmit("[-] Write failed: " + err.Error())
		setWorkflowStatus(app, &app.CollectStatusText, &app.CollectStatusError, &app.CollectStatusUntil, "collection failed: "+err.Error(), true)
	} else {
		collectEmit("[+] JSON written")
		if configured, reason := proxyhound.UploadConfigStatus(); !configured {
			setWorkflowStatus(app, &app.CollectStatusText, &app.CollectStatusError, &app.CollectStatusUntil, "collection written: "+app.CollectOutput+" (upload skipped: "+reason+")", false)
		} else {
			collectEmit("[*] Uploading to ProxyHound...")
			if err := proxyhound.UploadIfConfigured(filepath.Base(app.CollectOutput), payload); err != nil {
				collectEmit("[-] Upload failed: " + err.Error())
				setWorkflowStatus(app, &app.CollectStatusText, &app.CollectStatusError, &app.CollectStatusUntil, "collection written, upload failed: "+err.Error(), true)
			} else {
				collectEmit("[+] Upload complete")
				app.CollectResultUploaded = true
				setWorkflowStatus(app, &app.CollectStatusText, &app.CollectStatusError, &app.CollectStatusUntil, "collection written: "+app.CollectOutput, false)
			}
		}
	}
	app.CollectActive = false
	app.CollectStartedAt = time.Time{}
	app.CollectData = nil
	app.CollectEditing = false
	app.CollectProgressLines = nil
}

// ── Whitelist helpers ───────────────────────────────────────────────────────

func WhitelistProcessCandidates(app *shared.AppState) []shared.Candidate {
	if app == nil {
		return nil
	}
	if len(app.SnapshotCandidates) > 0 {
		return app.SnapshotCandidates
	}
	return app.Candidates
}

func FindCandidateIndexByKey(cands []shared.Candidate, key string) int {
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

func ResortCandidates(app *shared.AppState) {
	if app == nil {
		return
	}
	defer RefreshCollectSources(app)
	selectedHostKey := strings.TrimSpace(app.DashboardHostKey)
	selectedProcessKey := ""
	if proc, ok := SelectedWhitelistProcessCandidate(app); ok {
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
		if idx := FindCandidateIndexByKey(app.SnapshotCandidates, selectedProcessKey); idx >= 0 {
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
		view := DashboardProcessCandidates(app)
		if len(view) == 0 {
			app.SelectedIdx = -1
			app.SelectedKey = ""
			return
		}
		SyncDashboardProcessSelection(app, view, SelectedDashboardProcessIndex(app, view))
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

// ── Clone helpers ───────────────────────────────────────────────────────────

func CloneCandidate(c shared.Candidate) shared.Candidate {
	cloned := c
	if c.Proc != nil {
		proc := *c.Proc
		cloned.Proc = &proc
	}
	if len(c.Listeners) > 0 {
		cloned.Listeners = append([]shared.ListenerInfo(nil), c.Listeners...)
	}
	if len(c.Conns) > 0 {
		cloned.Conns = append([]shared.ConnectionInfo(nil), c.Conns...)
	}
	if len(c.UDPListeners) > 0 {
		cloned.UDPListeners = append([]shared.UDPListenerInfo(nil), c.UDPListeners...)
	}
	if len(c.Reasons) > 0 {
		cloned.Reasons = append([]string(nil), c.Reasons...)
	}
	if len(c.Signals) > 0 {
		cloned.Signals = append([]string(nil), c.Signals...)
	}
	return cloned
}

func CloneCalibrationSamples(samples []shared.Candidate) []shared.Candidate {
	if len(samples) == 0 {
		return nil
	}
	out := make([]shared.Candidate, 0, len(samples))
	for _, sample := range samples {
		out = append(out, CloneCandidate(sample))
	}
	return out
}

func CloneContourHints(hints []shared.ContourHint) []shared.ContourHint {
	if len(hints) == 0 {
		return nil
	}
	out := make([]shared.ContourHint, len(hints))
	copy(out, hints)
	return out
}

// ── Dashboard helpers (needed by dashboard.go) ──────────────────────────────

func DashboardHostListMode(app *shared.AppState) bool {
	if app == nil {
		return false
	}
	return strings.TrimSpace(app.LocalHost) == "" && !app.DashboardHostProcessView
}

func DashboardProcessCandidates(app *shared.AppState) []shared.Candidate {
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

func SelectedDashboardProcessIndex(app *shared.AppState, view []shared.Candidate) int {
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

func SyncDashboardProcessSelection(app *shared.AppState, view []shared.Candidate, idx int) {
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

func SelectedDashboardHostSummary(app *shared.AppState) (shared.HostSummary, bool) {
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

// ── Keystore field helpers ──────────────────────────────────────────────────

func KeystoreFieldVisible(field int) bool {
	switch field {
	case KeystoreFieldOpenAIBaseURL, KeystoreFieldAnthropicBaseURL,
		KeystoreFieldCalibrationTimeout,
		KeystoreFieldDisableClientCert, KeystoreFieldTrustOnFirstUse,
		KeystoreFieldMethod, KeystoreFieldNew,
		KeystoreFieldBuildkiteToken, KeystoreFieldAWSAccessKey, KeystoreFieldAWSSecretKey,
		KeystoreFieldGCPServiceKey,
		KeystoreFieldSlackBotToken, KeystoreFieldDiscordBotToken, KeystoreFieldTelegramBotKey,
		KeystoreFieldFirebaseKey, KeystoreFieldTeamsAuth, KeystoreFieldGitLabToken:
		return false
	}
	return field >= KeystoreFieldOpenAIKey && field <= KeystoreFieldMax
}

func CycleKeystoreField(field *int, up bool) {
	start := *field
	for {
		if up {
			*field--
			if *field < KeystoreFieldOpenAIKey {
				*field = KeystoreFieldMax
			}
		} else {
			*field++
			if *field > KeystoreFieldMax {
				*field = KeystoreFieldOpenAIKey
			}
		}
		if KeystoreFieldVisible(*field) {
			return
		}
		if *field == start {
			return
		}
	}
}

func KeystoreFieldEnvKey(field int) (string, bool) {
	switch field {
	case KeystoreFieldOpenAIKey:
		return "OPENAI_API_KEY", true
	case KeystoreFieldOpenAIBaseURL:
		return "OPENAI_BASE_URL", true
	case KeystoreFieldAnthropicKey:
		return "ANTHROPIC_API_KEY", true
	case KeystoreFieldAnthropicBaseURL:
		return "ANTHROPIC_BASE_URL", true
	case KeystoreFieldLocalLLMURL:
		return "LOCAL_LLM_URL", true
	case KeystoreFieldLocalLLMAPIKey:
		return "LOCAL_LLM_API_KEY", true
	case KeystoreFieldCalibrationTimeout:
		return "CALIBRATION_HTTP_TIMEOUT", true
	case KeystoreFieldProxyhoundURL:
		return "BLOODHOUND_API_URL", true
	case KeystoreFieldProxyhoundToken:
		return "BLOODHOUND_API_TOKEN", true
	case KeystoreFieldProxyhoundTokenID:
		return "BLOODHOUND_API_TOKEN_ID", true
	case KeystoreFieldTLSDir:
		return "PROXYWATCH_TLS_DIR", true
	case KeystoreFieldAgentToken:
		return "PROXYWATCH_AGENT_TOKEN", true
	case KeystoreFieldDisableClientCert:
		return "PROXYWATCH_DISABLE_CLIENT_CERT", true
	case KeystoreFieldTrustOnFirstUse:
		return "PROXYWATCH_TRUST_ON_FIRST_USE", true
	case KeystoreFieldSentinelAuth:
		return "PROXYWATCH_SENTINEL_AUTH", true
	case KeystoreFieldSentinelEndpoint:
		return "PROXYWATCH_SENTINEL_DCE_ENDPOINT", true
	case KeystoreFieldSentinelDCRID:
		return "PROXYWATCH_SENTINEL_DCR_ID", true
	case KeystoreFieldSentinelStream:
		return "PROXYWATCH_SENTINEL_STREAM_NAME", true
	case KeystoreFieldGitHubToken:
		return "GITHUB_TOKEN", true
	case KeystoreFieldBuildkiteToken:
		return "BUILDKITE_TOKEN", true
	case KeystoreFieldAWSAccessKey:
		return "AWS_ACCESS_KEY_ID", true
	case KeystoreFieldAWSSecretKey:
		return "AWS_SECRET_ACCESS_KEY", true
	case KeystoreFieldAzureTenantID:
		return "AZURE_TENANT_ID", true
	case KeystoreFieldAzureClientID:
		return "AZURE_CLIENT_ID", true
	case KeystoreFieldAzureClientSecret:
		return "AZURE_CLIENT_SECRET", true
	case KeystoreFieldGCPServiceKey:
		return "GCP_SERVICE_KEY", true
	case KeystoreFieldSlackBotToken:
		return "SLACK_BOT_TOKEN", true
	case KeystoreFieldDiscordBotToken:
		return "DISCORD_BOT_TOKEN", true
	case KeystoreFieldTelegramBotKey:
		return "TELEGRAM_BOT_KEY", true
	case KeystoreFieldFirebaseKey:
		return "FIREBASE_KEY", true
	case KeystoreFieldTeamsAuth:
		return "TEAMS_DEADDROP_AUTH", true
	case KeystoreFieldGitLabToken:
		return "GITLAB_TOKEN", true
	default:
		return "", false
	}
}

func EnsureKeystoreValues(app *shared.AppState) {
	if app.KeystoreValues == nil {
		app.KeystoreValues = keystore.ValuesFromRuntime()
	}
	if app.KeystoreUnlocked && len(app.KeystoreValues) > 0 {
		keystore.ApplyToRuntime(app.KeystoreValues)
		keystore.SetActiveKeystore(&app.KeystoreValues)
	}
}

func InitMissingKeystoreKeys(app *shared.AppState) {
	if app.KeystoreValues == nil {
		return
	}
	for f := KeystoreFieldOpenAIKey; f <= KeystoreFieldGitLabToken; f++ {
		key, ok := KeystoreFieldEnvKey(f)
		if !ok || key == "" {
			continue
		}
		if _, exists := app.KeystoreValues[key]; !exists {
			app.KeystoreValues[key] = ""
		}
	}
}

// SelectedWhitelistProcessCandidate returns the currently selected process candidate
// in the whitelist panel.
func SelectedWhitelistProcessCandidate(app *shared.AppState) (shared.Candidate, bool) {
	if app == nil {
		return shared.Candidate{}, false
	}
	procs := WhitelistProcessCandidates(app)
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
