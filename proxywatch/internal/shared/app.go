package shared

import (
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
)

type AppMode int

const (
	ModeDashboard AppMode = iota
	ModeInspect
	ModeWhitelist
	ModeCollect
	ModeCalibration
	ModeContour
	ModeKeystore
	ModeSIEM
)

type HostSummary struct {
	Host      string
	Status    string
	FirstSeen time.Time
	LastSeen  time.Time
	Processes int
	Watch     int
	Strong    int
	Roles     int
	Active    int
}

type AppState struct {
	Screen tcell.Screen

	// ScreenWidth and ScreenHeight are set by the bubbletea WindowSizeMsg
	// and used by rendering code that needs dimensions without a tcell.Screen.
	ScreenWidth  int
	ScreenHeight int

	// ProgressMu protects progress line slices that are written by
	// background goroutines and read by the UI goroutine.
	ProgressMu sync.Mutex

	// YubiKeyTouchRequired is set true when a YubiKey touch is needed.
	// The UI shows a prominent prompt when this is true.
	YubiKeyTouchRequired bool

	LastError           string
	LastUpdate          time.Time
	RefreshInt          time.Duration
	ConfirmKill         bool
	ConfirmKillTimeout  time.Duration
	ConfirmKillKey      string
	ConfirmKillDeadline time.Time
	LocalHost           string
	Whitelist           *Whitelist
	WhitelistItems      []string
	WhitelistSelected   int
	WhitelistField      int
	WhitelistListOffset int
	RemoteKill          func(host string, pid int) error
	RemoveRemoteHost    func(host string) error
	RoleFilterOverride  map[string]bool
	RolePreset          string
	AgentToken          string
	SortPreset          string
	ShowHelp            bool
	ShowRoleMenu        bool
	ShowSortMenu        bool
	ShowRefreshMenu     bool
	ShowInspectMenu     bool
	HelpMenuIndex       int
	InspectMenuIndex    int
	RoleMenuIndex       int
	SortMenuIndex       int
	RefreshMenuIndex    int
	RefreshRequested    bool
	ShowQuitConfirm     bool
	QuitConfirmDeadline time.Time

	CollectActive      bool
	CollectStartedAt   time.Time
	CollectUntil       time.Time
	CollectDurationStr string
	CollectOutput      string
	CollectData        []Candidate
	CollectField       int
	CollectEditing     bool
	CollectSource      string
	CollectSourceIndex int
	CollectSourceOpts  []string
	CollectShowMenu    bool
	CollectMenuKind    string
	CollectMenuTitle   string
	CollectMenuOptions []string
	CollectMenuIndex   int
	CollectStatusText  string
	CollectStatusUntil time.Time
	CollectStatusError bool

	// Collection results for display.
	CollectResultNodes      int
	CollectResultEdges      int
	CollectResultOutput     string
	CollectResultUploaded   bool
	CollectResultHasData    bool
	CollectResultCandidates int
	CollectResultHosts      int
	CollectResultExternal   int
	CollectResultInternal   int
	CollectResultListeners  int
	CollectResultDuration   string
	CollectShowHelp         bool
	CollectHelpIndex        int
	CollectProgressLines    []string

	CalibrateDuration      string
	CalibrateProvider      string
	CalibrateModel         string
	CalibrateProfile       string
	CalibrateOutput        string
	CalibrateField         int
	CalibrateEditing       bool
	CalibrateEditCursor    int
	CalibrateActive        bool
	CalibrateAnalyzing     bool
	CalibrateCancel        func()
	CalibrateStartedAt     time.Time
	CalibrateUntil         time.Time
	CalibrateSamples       []Candidate
	CalibrateProgressLines []string

	CalibrateStatusText       string
	CalibrateStatusUntil      time.Time
	CalibrateStatusError      bool
	CalibrateDecryptAttempted bool

	CalibrateHostScope      string
	CalibrateHostScopeOpts  []string
	CalibrateHostScopeIndex int
	CalibrateResetConfirm   bool
	CalibrateResetDeadline  time.Time

	CalibrateProfiles        []string
	CalibrateProfileIndex    int
	CalibrateAppliedProfile  string
	CalibrateReportSummary   string
	CalibrateReportPath      string
	CalibrateReportTime      time.Time
	CalibrateRecommendations []string
	CalibrateReportLines     []string
	CalibrateProfilePreview  []string // temporary preview when selecting a profile
	CalibrateReportScroll    int
	CalibrateReportMaxScroll int
	CalibrateSampleEvery     time.Duration
	CalibrateLastSample      time.Time

	ShowCalibrateHelp    bool
	CalibrateHelpIndex   int
	ShowCalibrateMenu    bool
	CalibrateMenuKind    string
	CalibrateMenuTitle   string
	CalibrateMenuOptions []string
	CalibrateMenuIndex   int

	ContourDashMode         int              // 0 = Scan, 1 = Contour
	ContourNewRole          string           // Contour mode: "Server" or "Client"
	ContourNewMethod        string           // Contour mode: selected protocol method
	ContourNewMode          string           // Contour mode: "Tunnel" or "Listen"
	ContourNewField         int              // Contour mode: selected field index
	ContourNewPort          int              // Selected port (0 = auto)
	ContourNewDirection     string           // Tunnel mode: "Forward" or "Reverse"
	ContourNewListenPort    int              // Tunnel mode: local SOCKS listen port (0 = random)
	ContourNewEditing       bool             // Contour mode: editing text field
	ContourNewMethods       []string         // Available methods from scan results
	ContourNewMethodPorts   map[string][]int // Protocol → available ports
	ContourNewActive        bool             // Contour mode: operation running
	ContourNewCancel        func()           // Cancel running operation
	ContourNewDone          chan struct{}    // Closed when the goroutine exits
	ContourNewService       string           // Selected service name (e.g., "Slack", "Discord")
	ContourNewServiceMethod string           // "Route Through" or "Domain Front"
	ContourNewServices      []string         // Available services from scan (reachable only)
	ContourNewShowMenu      bool
	ContourNewMenuTitle     string
	ContourNewMenuOptions   []string
	ContourNewMenuIndex     int
	ContourNewMenuKind      string

	ContourDuration           string
	ContourOutput             string
	ContourProbeEndpoint      string
	ContourProbeMode          string
	ContourProbeRole          string
	ContourField              int
	ContourEditing            bool
	ContourActive             bool
	ContourAnalyzing          bool
	ContourCancel             func()
	ContourStartedAt          time.Time
	ContourUntil              time.Time
	ContourSource             string
	ContourSourceIndex        int
	ContourSourceOpts         []string
	ContourSampleEvery        time.Duration
	ContourLastSample         time.Time
	ContourSamples            []Candidate
	ContourShowMenu           bool
	ContourShowHelp           bool
	ContourHelpIndex          int
	ContourMenuKind           string
	ContourMenuTitle          string
	ContourMenuOptions        []string
	ContourMenuIndex          int
	ContourStatusText         string
	ContourStatusUntil        time.Time
	ContourStatusError        bool
	ContourProgressLines      []string
	ContourPartialReportLines []string
	ContourPartialProbe       any // *contour.ProbeSummary during scan, nil otherwise
	ContourReport             any // *contour.Report after scan completes, nil otherwise
	ContourReportLines        []string
	ContourReportPath         string
	ContourReportTime         time.Time
	ContourReportScroll       int
	ContourReportMaxScroll    int
	ContourHints              []ContourHint

	KeystorePath           string
	KeystoreValues         map[string]string
	KeystoreField          int
	KeystoreEditing        bool
	KeystoreUnlocked       bool
	KeystoreMethod         string   // "local", "gpg", "yubikey"
	KeystoreEntries        []string // list of keystore names
	KeystoreSelected       int      // selected keystore index
	KeystoreActiveEntry    string   // currently active keystore name
	KeystoreSecure         bool     // whether active keystore is hardware-key secured
	KeystorePanel          int      // 0=setup, 1=keystores, 2=fields
	KeystoreStatusText     string
	KeystoreStatusUntil    time.Time
	KeystoreStatusError    bool
	KeystoreShowHelp       bool
	KeystoreHelpIndex      int
	KeystoreCreateMenuOpen bool
	KeystoreCreateMenuOpts []string
	KeystoreCreateMenuIdx  int
	KeystoreDeleteConfirm  bool   // true = waiting for second 'd' press
	KeystoreDeleteTarget   string // name of keystore pending delete
	KeystoreWizardOpen     bool
	KeystoreWizardField    int // 0=name, 1=encryption, 2=slot/password, 3=confirm/create
	KeystoreWizardName     string
	KeystoreWizardSecure   bool
	KeystoreWizardMethod   string // "local", "password", "yubikey"
	KeystoreWizardSlot     string
	KeystoreWizardPassword string // password for password-protected keystore
	KeystoreWizardConfirm  string // password confirmation
	KeystoreWizardEditing  bool

	// Password prompt for unlocking/saving password-protected keystores.
	KeystorePasswordPrompt bool   // show password prompt overlay
	KeystorePasswordInput  string // password being typed
	KeystorePasswordSave   bool   // true=saving, false=unlocking

	SIEMDebugLogPath     string
	SIEMRulesJSONPath    string
	SIEMSourceReport     string
	SIEMSourceReports    []string
	SIEMSourceIndex      int
	SIEMProvider         string
	SIEMModel            string
	SIEMReportPath       string
	SIEMExportPath       string
	SIEMReportLines      []string
	SIEMReportScroll     int
	SIEMReportMaxScroll  int
	SIEMField            int
	SIEMEditing          bool
	SIEMShowMenu         bool
	SIEMShowHelp         bool
	SIEMHelpIndex        int
	SIEMMenuKind         string
	SIEMMenuTitle        string
	SIEMMenuOptions      []string
	SIEMMenuIndex        int
	SIEMProgressLines    []string
	SIEMGenerating       bool
	SIEMStartedAt        time.Time
	SIEMStatusText       string
	SIEMStatusUntil      time.Time
	SIEMStatusError      bool
	SIEMDecryptAttempted bool
	StartSIEMGeneration  func(sourceReport, provider, model, outputReport, outputJSON string)

	AutoCalibrateInterval time.Duration
	AutoCalibrateLastRun  time.Time
	AutoCalibrateEnabled  bool

	CalibrationCollect func() (*Snapshot, error)

	PrevCandidateKeys map[string]string // key -> role from last refresh

	SessionLogPath string
	SessionLogFile *os.File

	Candidates               []Candidate
	SnapshotCandidates       []Candidate
	HostSummaries            []HostSummary
	Mode                     AppMode
	SelectedKey              string
	SelectedIdx              int
	DashboardHostSelected    int
	DashboardHostKey         string
	DashboardHostProcessView bool
	WhitelistProcessSelected int
	WhitelistProcessOffset   int
	WhitelistShowHelp        bool
	WhitelistHelpIndex       int
	InspectKey               string
	InspectScroll            int
	InspectMaxScroll         int
	InspectSectionStarts     []int
}

type Scanner interface {
	Refresh(app *AppState)
}

type IOSample struct {
	Read      uint64
	Write     uint64
	Other     uint64
	Timestamp time.Time
}

type ScannerAdapter struct {
	Options     ClassifyOptions
	Cache       ClassifierCache
	LastIO      map[int]IOSample
	HostID      string
	Whitelist   *Whitelist
	LingerFor   time.Duration
	LingerCache map[string]LingerEntry
	Collect     func() (*Snapshot, error)
	Classify    ClassifyFunc
}

func (s *ScannerAdapter) Refresh(app *AppState) {
	if s.Collect == nil || s.Classify == nil {
		ResetAppState(app, "scanner not configured")
		return
	}

	snap, err := s.Collect()
	if err != nil {
		ResetAppState(app, err.Error())
		return
	}

	opts := s.Options
	if app != nil && len(app.RoleFilterOverride) > 0 {
		opts.RoleFilter = app.RoleFilterOverride
	}
	if strings.TrimSpace(opts.HostScope) == "" {
		opts.HostScope = s.HostID
	}
	cands := s.Classify(snap, opts, &s.Cache)
	now := time.Now().UTC()
	if s.HostID == "" {
		s.HostID = "local"
	}
	for i := range cands {
		cands[i].Host = s.HostID
	}
	cands = FilterProxywatchCandidates(cands)
	ApplyIORates(cands, now, &s.LastIO)
	cands = ApplyCandidateLinger(cands, now, s.LingerFor, &s.LingerCache)
	// Keep role/score filtering authoritative after linger rehydrates stale rows.
	cands = ApplyScoreAndRoleFilters(cands, opts.MinScore, opts.RoleFilter)
	if app != nil {
		app.SnapshotCandidates = cands
		app.HostSummaries = nil
	}
	filtered := ApplyWhitelist(cands, s.Whitelist)
	ApplySelection(app, filtered, now)
}

func ApplyIORates(cands []Candidate, now time.Time, prev *map[int]IOSample) {
	if *prev == nil {
		*prev = make(map[int]IOSample, len(cands))
	}

	next := make(map[int]IOSample, len(cands))
	for i := range cands {
		pi := cands[i].Proc
		if pi == nil {
			continue
		}

		sample := IOSample{
			Read:      pi.IOReadBytes,
			Write:     pi.IOWriteBytes,
			Other:     pi.IOOtherBytes,
			Timestamp: now,
		}

		if p, ok := (*prev)[pi.Pid]; ok && now.After(p.Timestamp) {
			dt := now.Sub(p.Timestamp).Seconds()
			if dt > 0 {
				if pi.IOReadBytes >= p.Read {
					pi.IOReadBps = uint64(float64(pi.IOReadBytes-p.Read) / dt)
				}
				if pi.IOWriteBytes >= p.Write {
					pi.IOWriteBps = uint64(float64(pi.IOWriteBytes-p.Write) / dt)
				}
				if pi.IOOtherBytes >= p.Other {
					pi.IOOtherBps = uint64(float64(pi.IOOtherBytes-p.Other) / dt)
				}
			}
		}

		next[pi.Pid] = sample
	}

	*prev = next
}

// ResetAppState clears current candidates and sets an error message.
func ResetAppState(app *AppState, msg string) {
	if app == nil {
		return
	}
	app.LastError = msg
	app.Candidates = nil
	app.SnapshotCandidates = nil
	app.HostSummaries = nil
	app.SelectedIdx = -1
	app.SelectedKey = ""
	app.LastUpdate = time.Now().UTC()
}

// ApplySelection updates app selection and timestamps after a refresh.
func ApplySelection(app *AppState, cands []Candidate, now time.Time) {
	if app == nil {
		return
	}
	app.LastError = ""
	app.Candidates = cands
	app.LastUpdate = now

	if len(app.Candidates) == 0 {
		app.SelectedIdx = -1
		app.SelectedKey = ""
		return
	}

	if app.SelectedKey != "" {
		for i, c := range app.Candidates {
			if CandidateKey(c) == app.SelectedKey {
				app.SelectedIdx = i
				return
			}
		}
	}

	app.SelectedIdx = 0
	app.SelectedKey = CandidateKey(app.Candidates[0])
}

// ApplyWhitelist returns the filtered list if a whitelist is present.
func ApplyWhitelist(cands []Candidate, w *Whitelist) []Candidate {
	if w == nil {
		return cands
	}
	return w.Filter(cands)
}

// ApplyScoreAndRoleFilters filters candidates by minimum score and role filter.
func ApplyScoreAndRoleFilters(cands []Candidate, minScore int, roleFilter map[string]bool) []Candidate {
	if minScore <= 0 && len(roleFilter) == 0 {
		return cands
	}
	filtered := make([]Candidate, 0, len(cands))
	for _, c := range cands {
		if minScore > 0 && c.Score < minScore {
			continue
		}
		if !RoleMatchesFilter(c.Role, roleFilter) {
			continue
		}
		filtered = append(filtered, c)
	}
	return filtered
}

func DefaultHostID(fallback string) string {
	name, err := os.Hostname()
	if err == nil {
		name = strings.TrimSpace(name)
	}
	if name == "" {
		return fallback
	}
	return name
}

func DisplayHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return "local"
	}
	return host
}
