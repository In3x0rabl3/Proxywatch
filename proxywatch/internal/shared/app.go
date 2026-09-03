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
	ModeContour
	ModeKeystore
	ModeTraining
	ModePcapAnalyzer
)

type HostSummary struct {
	Host      string
	Status    string
	FirstSeen time.Time
	LastSeen  time.Time
	Processes int
	Watch     int
	Tunneling int
	Roles     int
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
	ShowWhitelistPanel       bool // overlay panel on dashboard
	InspectKey               string
	InspectScroll            int
	InspectMaxScroll         int
	InspectSectionStarts     []int
	InspectEvidenceCache     []string // cached evidence lines
	InspectEvidenceCacheKey  string   // candidate key for cache validity
	InspectEvidenceCacheTime int64    // unix timestamp of cache
	InspectShowAllSignals    bool     // 'x' toggle: show all signals in evidence

	// Training dashboard state.
	TrainingDashboardActive bool
	TrainingBufferSize      int
	TrainingModelVersion    string
	TrainingLastError       string

	// PCAP analyzer state.
	// PcapStage values: "picking" (text-input file picker visible),
	// "analyzing" (replay running), "results" (3-bucket list shown),
	// "detail" (single candidate drill-down). The result + progress
	// payloads themselves live on the view model, not here.
	PcapStage      string
	PcapPath       string
	PcapPathCursor int
	PcapField      int  // SETUP form: 0=file, 1=action
	PcapEditing    bool // SETUP form: file field in edit mode
	PcapError      string

	// PCAP file-picker overlay. Triggered by `Tab` (or `b`) on the File
	// field — gives the operator a terminal-native directory browser
	// instead of typing the full path. Up/Down move cursor, Enter on a
	// directory cd's into it, Enter on a .pcap/.pcapng file selects and
	// closes. Esc cancels and restores the prior PcapPath.
	PcapBrowsing         bool
	PcapBrowseDir        string   // current directory being browsed
	PcapBrowseEntries    []string // names ("../" first, then dirs with trailing "/", then files)
	PcapBrowseCursor     int
	PcapBrowsePathBefore string // PcapPath at the moment the browser opened (restored on Esc)
	PcapBucketIdx        int    // legacy — retained for back-compat with older sessions; unused by current view
	PcapRowCursor        int
	PcapDetailKey        string // CandidateKey of the selected drill-down row
	PcapShowSignals      bool   // operator toggled 'x' in detail to show full signal list
	PcapShowHelp         bool   // operator toggled '?' to show the pcap analyzer help overlay
	// PcapLabelRequest signals the PCAP TUI to apply an operator
	// label to the currently-selected finding on the next render.
	// Values: "" (no request), "malicious", "benign", "clear". The
	// view consumes the request, calls SetPcapOperatorLabel /
	// ClearPcapOperatorLabel, then resets back to "".
	PcapLabelRequest string
	PcapAnalysisRun  bool   // true while analysis is in flight
	PcapCancelFunc   func() // populated for the duration of analysis; cleared on done/cancel
	// PcapMode selects how the analyzer reads the file:
	//   "oneshot" — walk to EOF, classify, done (default)
	//   "tail"    — follow growth, classify per second, push incremental
	//                results until Esc.
	PcapMode string
	// PcapShowAllFindings toggles the results-stage filter:
	//   false (default) → show beacon-* / smb-pipe / tunnel + tunneling
	//                     state findings, plus their parent listeners.
	//   true            → show every candidate the analyzer produced.
	// Operator binds 'a' to flip this in the pcap results view.
	PcapShowAllFindings bool
	// PcapResultsTab selects which sub-view of the results stage is
	// rendered. Tab cycles through:
	//   ""           → findings (default per-host/per-flow table)
	//   "destinations" → contour-style C2 / external destinations panel
	// Other tab values reserved for future sub-views.
	PcapResultsTab string

	// PcapGroupBy controls the row-identity in the FINDINGS panel.
	// Different lenses on the same underlying flows:
	//   "" / "cluster"   → /16 cluster (default; pcap:<host> → <prefix>/16:<port>)
	//   "flow"           → per-flow 5-tuple (one row per ESTABLISHED conn)
	//   "ja3"            → per-(host, JA3 hash) — TLS fingerprint as identity
	//   "asn"            → per-(host, ASN org) — Cloudflare = one row
	//   "session"        → per-(host, time-window session) — captures
	//                      C2-with-active-pivot as one row
	//   "behavior"       → per-(host, behavioral fingerprint) — same
	//                      traffic shape clusters together
	// Operator cycles via the `g` hotkey in pcap analyzer view.
	PcapGroupBy string

	// PcapSortMode controls the FINDINGS panel sort order.
	//   "" / "time"      → first-packet ascending (default)
	//   "bytes"          → cumulative bytes descending
	//   "packets"        → packet count descending
	// Operator cycles via the `S` hotkey.
	PcapSortMode string

	// Training control plane state.
	TrainingField         int
	TrainingShowHelp      bool
	TrainingAutoRetrain   bool // mirrors shared.AutoRetrainEnabled
	TrainingRetraining    bool // retrain in progress
	TrainingRetrainStart  time.Time
	TrainingMetricsCache  interface{} // *inference.ModelMetrics (avoid import cycle)
	TrainingOrchestrator  interface{} // *training.Orchestrator
	TrainingLearner       interface{} // *inference.ContinuousLearner
	TrainingSampleMode    bool
	TrainingSampleIndex   int
	TrainingSampleCount   int       // count of low-confidence samples
	StartTrainingRetrain  func()    // wired callback for async retrain
	TrainingResetConfirm  bool      // double-confirm for baseline reset
	TrainingResetDeadline time.Time // confirmation window
	MLClassifierPrimary   bool      // true if ML drives role assignment, false if shadow
	MLPrimarySource       *bool     // live pointer to detection.MLPrimary for tick sync
	TrainingBaselineIndex int       // selected index in baseline list
	TrainingBaselineList  []string  // cached baseline display names
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
	// Post-linger: correlate exited children with live parents.
	// Lingered children now retain connection data, so we can detect
	// tunnel relay patterns even after the child exits.
	AggregateLingerChildEvidence(cands, now)
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
	// Record every candidate's current connections into the per-PID
	// sticky cache so closed connections remain visible in the
	// Inspector's CONNECTIONS panel for InspectorConnStickyWindow
	// (10 min). Without this hook the cache only fills while the
	// user is actively viewing a candidate and slow beaconers
	// (callbacks at 7m / 17m intervals) show empty connection lists.
	RecordCandidateConnsForInspector(cands)

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
//
// Reads TunnelingSeen for the score-exemption gate; takes ClassifyMu.RLock
// for the duration so the read never races against a concurrent
// detection.Classify write (live scanner running while pcap analyzer
// is also ingesting, both call Classify which writes TunnelingSeen).
func ApplyScoreAndRoleFilters(cands []Candidate, minScore int, roleFilter map[string]bool) []Candidate {
	if minScore <= 0 && len(roleFilter) == 0 {
		return cands
	}
	ClassifyMu.RLock()
	defer ClassifyMu.RUnlock()
	filtered := make([]Candidate, 0, len(cands))
	for _, c := range cands {
		// Control roles, exited processes, and processes still in the
		// analyzing phase bypass the MinScore filter. During the first
		// 30 seconds we don't yet know if a process is suspicious —
		// filtering by score is premature.
		wasTunneling := false
		if c.Proc != nil {
			if _, ok := TunnelingSeen[c.Proc.Pid]; ok {
				wasTunneling = true
			}
			// Also check parent — child tunnel handlers inherit parent's status
			if !wasTunneling && c.Proc.ParentPid > 0 {
				if _, ok := TunnelingSeen[c.Proc.ParentPid]; ok {
					wasTunneling = true
				}
			}
		}
		scoreExempt := IsControlRole(c.Role) || c.Exited ||
			c.SeenSeconds < AnalyzingMinSeconds || wasTunneling
		if minScore > 0 && c.Score < minScore && !scoreExempt {
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
