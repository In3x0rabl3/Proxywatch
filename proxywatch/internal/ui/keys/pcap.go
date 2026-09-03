package keys

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"proxywatch/internal/pcap"
	"proxywatch/internal/shared"
	"proxywatch/internal/ui/platform"

	"github.com/gdamore/tcell/v2"
)

// PCAP analyzer view stages.
const (
	PcapStagePicking   = "picking"
	PcapStageAnalyzing = "analyzing"
	PcapStageResults   = "results"
)

// PCAP analyzer SETUP form field indices.
const (
	PcapFieldFile   = 0
	PcapFieldAction = 1
	PcapFieldMax    = PcapFieldAction
)

// PCAP analyzer reading modes.
const (
	PcapModeOneshot = "oneshot"
	PcapModeTail    = "tail"
)

// EnterPcapAnalyzerMode initializes app state for the PCAP analyzer view
// and switches to it. Seeds the file picker with CWD if no path is set.
func EnterPcapAnalyzerMode(app *shared.AppState) {
	if app == nil {
		return
	}
	if strings.TrimSpace(app.PcapStage) == "" {
		app.PcapStage = PcapStagePicking
	}
	if strings.TrimSpace(app.PcapPath) == "" {
		if cwd, err := os.Getwd(); err == nil {
			app.PcapPath = cwd + string(os.PathSeparator)
		}
		app.PcapPathCursor = len(app.PcapPath)
	}
	if strings.TrimSpace(app.PcapMode) == "" {
		app.PcapMode = PcapModeOneshot
	}
	// Default to "show all findings" so outbound + listener
	// candidates surface alongside the beacon-* / tunneling
	// findings. Operator can press 'a' to toggle back to the
	// suspicious-only filter when the table gets noisy.
	app.PcapShowAllFindings = true
	app.PcapError = ""
	app.Mode = shared.ModePcapAnalyzer
}

// HandlePcapAnalyzerKey dispatches keys for the PCAP analyzer view based
// on its current stage. Returns true only on quit-confirm; navigation
// events return false so the caller does not exit the program.
func HandlePcapAnalyzerKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if app == nil || tev == nil {
		return false
	}

	// Help overlay handling — same pattern as the other dashboards.
	// Open on '?' from any stage; while open, '?' / ESC close it and
	// 'q' triggers quit-confirm.
	if app.PcapShowHelp {
		switch tev.Key() {
		case tcell.KeyEscape:
			app.PcapShowHelp = false
			return false
		}
		switch tev.Rune() {
		case '?':
			app.PcapShowHelp = false
			return false
		case 'q':
			app.PcapShowHelp = false
			return requestQuit(app)
		}
		return false
	}
	if tev.Rune() == '?' {
		app.PcapShowHelp = true
		return false
	}

	// File-browser overlay takes precedence over stage dispatch — its
	// own Esc / Enter keys must not fall through to picking-stage edit
	// handling.
	if app.PcapBrowsing {
		return handlePcapBrowseKey(app, tev)
	}

	switch app.PcapStage {
	case PcapStageAnalyzing:
		return handlePcapAnalyzingKey(app, tev)
	case PcapStageResults:
		return handlePcapResultsKey(app, tev)
	default:
		return handlePcapPickingKey(app, tev)
	}
}

func handlePcapPickingKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if app.PcapEditing {
		return handlePcapPickingEditKey(app, tev)
	}
	return handlePcapPickingNavKey(app, tev)
}

// handlePcapPickingNavKey handles keys when the SETUP form has focus but
// the file field is not in edit mode. Up/Down moves between File and
// Action; Enter on File enters edit; Enter on Action runs analysis.
func handlePcapPickingNavKey(app *shared.AppState, tev *tcell.EventKey) bool {
	switch tev.Key() {
	case tcell.KeyEscape:
		app.Mode = shared.ModeDashboard
		return false
	case tcell.KeyLeft:
		StepWorkflowMenu(app, -1)
		return false
	case tcell.KeyRight:
		StepWorkflowMenu(app, 1)
		return false
	case tcell.KeyUp:
		if app.PcapField > PcapFieldFile {
			app.PcapField--
		}
		return false
	case tcell.KeyDown:
		if app.PcapField < PcapFieldMax {
			app.PcapField++
		}
		return false
	case tcell.KeyEnter:
		switch app.PcapField {
		case PcapFieldFile:
			app.PcapEditing = true
			app.PcapPathCursor = len(app.PcapPath)
		case PcapFieldAction:
			validatePcapPath(app)
		}
		return false
	case tcell.KeyTab:
		if app.PcapField == PcapFieldFile {
			openPcapBrowser(app)
		}
		return false
	}
	switch tev.Rune() {
	case 'b', 'B':
		if app.PcapField == PcapFieldFile {
			openPcapBrowser(app)
			return false
		}
	case 'g', 'G':
		if app.PcapField == PcapFieldFile {
			openNativeFileDialog(app)
			return false
		}
	case 'q':
		return requestQuit(app)
	}
	if JumpToWorkflow(app, tev.Rune()) {
		return false
	}
	return false
}

// handlePcapPickingEditKey handles keys when the file path field is in
// edit mode. Esc / Enter exits edit; the rest is plain text input.
func handlePcapPickingEditKey(app *shared.AppState, tev *tcell.EventKey) bool {
	switch tev.Key() {
	case tcell.KeyEscape, tcell.KeyEnter:
		app.PcapEditing = false
		return false
	case tcell.KeyTab:
		// Tab in edit mode opens the directory browser starting at
		// whatever path the operator has typed so far. Lets them
		// switch from typing to point-and-click without leaving the
		// File field.
		openPcapBrowser(app)
		return false
	case tcell.KeyBackspace, tcell.KeyBackspace2:
		if app.PcapPathCursor > 0 {
			app.PcapPath = app.PcapPath[:app.PcapPathCursor-1] + app.PcapPath[app.PcapPathCursor:]
			app.PcapPathCursor--
			app.PcapError = ""
		}
		return false
	case tcell.KeyDelete:
		if app.PcapPathCursor < len(app.PcapPath) {
			app.PcapPath = app.PcapPath[:app.PcapPathCursor] + app.PcapPath[app.PcapPathCursor+1:]
			app.PcapError = ""
		}
		return false
	case tcell.KeyHome:
		app.PcapPathCursor = 0
		return false
	case tcell.KeyEnd:
		app.PcapPathCursor = len(app.PcapPath)
		return false
	case tcell.KeyLeft:
		if app.PcapPathCursor > 0 {
			app.PcapPathCursor--
		}
		return false
	case tcell.KeyRight:
		if app.PcapPathCursor < len(app.PcapPath) {
			app.PcapPathCursor++
		}
		return false
	case tcell.KeyCtrlU:
		app.PcapPath = ""
		app.PcapPathCursor = 0
		app.PcapError = ""
		return false
	case tcell.KeyRune:
		r := tev.Rune()
		if r == 0 {
			return false
		}
		insert := string(r)
		app.PcapPath = app.PcapPath[:app.PcapPathCursor] + insert + app.PcapPath[app.PcapPathCursor:]
		app.PcapPathCursor += len(insert)
		app.PcapError = ""
		return false
	}
	return false
}

func handlePcapAnalyzingKey(app *shared.AppState, tev *tcell.EventKey) bool {
	switch tev.Key() {
	case tcell.KeyEscape:
		if app.PcapCancelFunc != nil {
			app.PcapCancelFunc()
		}
		return false
	case tcell.KeyLeft:
		// Workflow nav stays live during analysis — the goroutine
		// keeps running in the background while the operator can
		// pop over to another dashboard. Coming back to the pcap
		// view shows the latest analyzed state.
		StepWorkflowMenu(app, -1)
		return false
	case tcell.KeyRight:
		StepWorkflowMenu(app, 1)
		return false
	}
	switch tev.Rune() {
	case 'q':
		// Cancel + quit-confirm; cancel runs first so the goroutine exits cleanly.
		if app.PcapCancelFunc != nil {
			app.PcapCancelFunc()
		}
		return requestQuit(app)
	}
	if JumpToWorkflow(app, tev.Rune()) {
		return false
	}
	return false
}

func handlePcapResultsKey(app *shared.AppState, tev *tcell.EventKey) bool {
	switch tev.Key() {
	case tcell.KeyEscape:
		// Esc breadcrumb: results → SETUP picker → main dashboard.
		// (1) Watch session still active → cancel it first; stay on
		//     the results view so the operator sees the final state.
		// (2) Otherwise step back to the SETUP picker so the
		//     operator can pick a different file or re-run. The
		//     cached findings stay on app state, so a subsequent Esc
		//     from picker → dashboard preserves the data, and the
		//     operator can return to results by re-running analysis
		//     on the same path.
		if app.PcapAnalysisRun && app.PcapCancelFunc != nil {
			app.PcapCancelFunc()
			return false
		}
		app.PcapStage = PcapStagePicking
		app.PcapField = PcapFieldFile
		app.PcapEditing = false
		return false
	case tcell.KeyEnter:
		// Enter while a watch is in progress stops it — same
		// affordance as pressing Esc, since the SETUP "Stop Watch"
		// button is what the operator is visually pointed at.
		if app.PcapAnalysisRun && app.PcapCancelFunc != nil {
			app.PcapCancelFunc()
			return false
		}
		// Otherwise no-op: with the split-panel layout the Details
		// panel is always visible for the selected row, so there's
		// no full-screen detail to drill into.
		return false
	case tcell.KeyUp:
		if app.PcapRowCursor > 0 {
			app.PcapRowCursor--
		}
		return false
	case tcell.KeyDown:
		app.PcapRowCursor++
		return false
	case tcell.KeyHome:
		app.PcapRowCursor = 0
		return false
	case tcell.KeyEnd:
		// Sentinel: clamped to the last finding by the renderer.
		app.PcapRowCursor = 1<<31 - 1
		return false
	case tcell.KeyLeft:
		StepWorkflowMenu(app, -1)
		return false
	case tcell.KeyRight:
		StepWorkflowMenu(app, 1)
		return false
	case tcell.KeyTab:
		// Cycle results sub-view: findings ↔ destinations.
		// Future tabs (e.g. timeline-only, host-summary) get appended
		// to the rotation here without touching the renderer.
		switch app.PcapResultsTab {
		case "destinations":
			app.PcapResultsTab = ""
		default:
			app.PcapResultsTab = "destinations"
		}
		app.PcapRowCursor = 0
		return false
	}

	switch tev.Rune() {
	case 'q':
		return requestQuit(app)
	case 'a':
		// Toggle "show all" — default view filters to beacon-* /
		// tunneling findings + their parent listeners; pressing 'a'
		// reveals every candidate (background traffic context).
		app.PcapShowAllFindings = !app.PcapShowAllFindings
		app.PcapRowCursor = 0
		return false
	case 'x':
		// Toggle full-signals view in the Details panel — same
		// affordance the inspector view uses. Folded in from the
		// removed full-screen detail stage so operators retain the
		// expanded-signal toggle without leaving the split layout.
		app.PcapShowSignals = !app.PcapShowSignals
		return false
	case 'm':
		// Mark currently-selected finding as MALICIOUS. The label
		// force-promotes the cluster to beacon (or
		// pivot for internal/listener clusters) on every
		// future cycle and re-analysis, persisted to disk in
		// ~/.proxywatch/pcap_operator_labels/.
		app.PcapLabelRequest = "malicious"
		return false
	case 'b':
		// Mark selected finding as BENIGN. The label force-demotes
		// the cluster to outbound and suppresses re-promotion. Use
		// for confirmed FPs (Chrome browsing, vendor telemetry,
		// admin SSH, etc.).
		app.PcapLabelRequest = "benign"
		return false
	case 'c':
		// Clear any operator label on the selected finding.
		app.PcapLabelRequest = "clear"
		return false
	case 't':
		// Mark the TLS attributes (JA3 hash + SNI hostname) of the
		// selected finding as MALICIOUS. Unlike `m` (cluster label,
		// network-bound), TLS labels propagate across captures: any
		// future cluster with the same JA3 hash or SNI hostname will
		// auto-promote to beacon. Persisted to disk in
		// ~/.proxywatch/pcap_tls_labels/.
		app.PcapLabelRequest = "tls-malicious"
		return false
	case 'T':
		// Mark TLS attributes as BENIGN — propagates across captures
		// to suppress re-promotion of this JA3/SNI on any future
		// cluster. Use for confirmed-vendor TLS fingerprints
		// (Chrome JA3 + googleapis SNI, Office365 SNI, etc.).
		app.PcapLabelRequest = "tls-benign"
		return false
	case 'C':
		// Clear any TLS label on the selected finding's JA3 / SNI.
		app.PcapLabelRequest = "tls-clear"
		return false
	case 'g':
		// Cycle the FINDINGS row-identity grouping mode. Same flows,
		// different lens. Default is /16 cluster; cycle through
		// flow → ja3 → asn → session → behavior → cluster.
		app.PcapGroupBy = nextPcapGroupBy(app.PcapGroupBy)
		app.PcapRowCursor = 0
		return false
	case 'S':
		// Cycle FINDINGS sort order. time → bytes → packets → time.
		app.PcapSortMode = nextPcapSortMode(app.PcapSortMode)
		app.PcapRowCursor = 0
		return false
	}
	if JumpToWorkflow(app, tev.Rune()) {
		return false
	}
	return false
}

// validatePcapPath checks the path entered in the picker and, if valid,
// flips PcapStage to "analyzing". The view's Update loop watches for
// this transition and kicks off the ingest goroutine — the keys package
// stays free of goroutine ownership.
func validatePcapPath(app *shared.AppState) {
	path := strings.TrimSpace(app.PcapPath)
	if path == "" {
		app.PcapError = "enter a path to a .pcap, .pcapng, or .log file (or Zeek directory)"
		return
	}

	info, err := os.Stat(path)
	if err != nil {
		app.PcapError = "cannot open: " + err.Error()
		return
	}

	// Check if it's a Zeek log directory (contains conn.log)
	if info.IsDir() {
		if pcap.IsZeekLog(path) {
			app.PcapError = ""
			app.PcapEditing = false
			app.PcapStage = PcapStageAnalyzing
			return
		}
		app.PcapError = "directory must contain Zeek logs (conn.log)"
		return
	}

	// Check file extension
	if !pcap.IsValidExtension(path) {
		app.PcapError = "file must end in .pcap, .pcapng, or .log"
		return
	}

	// For .log files, verify conn.log exists (required for Zeek analysis)
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".log") && !pcap.IsZeekLog(path) {
		dir := filepath.Dir(path)
		app.PcapError = fmt.Sprintf("Zeek analysis requires conn.log in %s", dir)
		return
	}

	app.PcapError = ""
	app.PcapEditing = false
	app.PcapStage = PcapStageAnalyzing
}

// nextPcapGroupBy advances the PcapGroupBy mode through the cycle.
// Empty string and "cluster" both map to the default /16 cluster mode.
func nextPcapGroupBy(current string) string {
	switch current {
	case "", "cluster":
		return "flow"
	case "flow":
		return "ja3"
	case "ja3":
		return "asn"
	case "asn":
		return "beacon"
	case "beacon":
		return "behavior"
	case "behavior":
		return "cluster"
	default:
		return "cluster"
	}
}

// nextPcapSortMode advances the PcapSortMode through the cycle.
func nextPcapSortMode(current string) string {
	switch current {
	case "", "time":
		return "bytes"
	case "bytes":
		return "packets"
	case "packets":
		return "time"
	default:
		return "time"
	}
}

// ── PCAP file browser overlay ──────────────────────────────────────────
// Triggered by Tab (or `b`) on the File field; gives the operator a
// terminal-native directory browser instead of typing the full path.
// Up/Down move cursor, Enter on a directory cd's into it, Enter on a
// .pcap/.pcapng file selects and closes. Esc cancels and restores the
// path the operator had before opening the browser.

const pcapBrowseParent = "../"

// openPcapBrowser snapshots the current PcapPath, picks a starting
// directory (the dirname of PcapPath if it points at a file, else the
// path itself if it's a directory, else the user's home), and loads
// the first page of entries.
func openPcapBrowser(app *shared.AppState) {
	if app == nil {
		return
	}
	app.PcapBrowsePathBefore = app.PcapPath
	dir := pcapInitialBrowseDir(app.PcapPath)
	app.PcapBrowseDir = dir
	app.PcapBrowseEntries = listPcapBrowseEntries(dir)
	app.PcapBrowseCursor = 0
	app.PcapBrowsing = true
	app.PcapEditing = false
	app.PcapError = ""
}

// openNativeFileDialog opens the system's native file picker dialog (zenity/kdialog
// on Linux, PowerShell dialog on Windows). If a file is selected, it updates PcapPath.
// Falls back to the terminal browser if no native dialog is available.
func openNativeFileDialog(app *shared.AppState) {
	if app == nil {
		return
	}
	if !platform.HasNativeDialog() {
		openPcapBrowser(app)
		return
	}

	startDir := pcapInitialBrowseDir(app.PcapPath)
	selected := platform.OpenFileDialog(
		"Select PCAP File",
		startDir,
		"*.pcap *.pcapng",
	)
	if selected != "" {
		app.PcapPath = selected
		app.PcapPathCursor = len(selected)
		app.PcapError = ""
		app.PcapEditing = false
	}
}

// pcapInitialBrowseDir resolves the directory to start the browser in
// based on the path the operator has typed (or empty).
func pcapInitialBrowseDir(path string) string {
	path = strings.TrimSpace(path)
	if path != "" {
		if info, err := os.Stat(path); err == nil {
			if info.IsDir() {
				return path
			}
			if d := filepath.Dir(path); d != "" && d != "." {
				return d
			}
		}
		if d := filepath.Dir(path); d != "" && d != "." {
			if info, err := os.Stat(d); err == nil && info.IsDir() {
				return d
			}
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		return home
	}
	if cwd, err := os.Getwd(); err == nil {
		return cwd
	}
	return string(os.PathSeparator)
}

// listPcapBrowseEntries returns directory contents formatted for the
// browser: "../" first (unless at filesystem root), then directories
// (alphabetical) suffixed with "/", then .pcap/.pcapng files. Hidden
// dotfiles excluded — they're rare for capture files and clutter the
// list. Other extensions are skipped because the validator only
// accepts .pcap/.pcapng anyway.
func listPcapBrowseEntries(dir string) []string {
	out := []string{}
	if !atFilesystemRoot(dir) {
		out = append(out, pcapBrowseParent)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	var dirs, files []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		if e.IsDir() {
			dirs = append(dirs, name+"/")
			continue
		}
		lower := strings.ToLower(name)
		if strings.HasSuffix(lower, ".pcap") || strings.HasSuffix(lower, ".pcapng") {
			files = append(files, name)
		}
	}
	sort.Strings(dirs)
	sort.Strings(files)
	out = append(out, dirs...)
	out = append(out, files...)
	return out
}

// atFilesystemRoot reports whether dir has no parent left (so we
// don't render a useless "../" entry that would just stay on the
// same directory).
func atFilesystemRoot(dir string) bool {
	clean := filepath.Clean(dir)
	parent := filepath.Dir(clean)
	return parent == clean
}

// handlePcapBrowseKey routes keys while the browser overlay is up.
func handlePcapBrowseKey(app *shared.AppState, tev *tcell.EventKey) bool {
	switch tev.Key() {
	case tcell.KeyEscape:
		// Cancel: restore the path the operator had before opening.
		app.PcapPath = app.PcapBrowsePathBefore
		app.PcapPathCursor = len(app.PcapPath)
		closePcapBrowser(app)
		return false
	case tcell.KeyUp:
		if app.PcapBrowseCursor > 0 {
			app.PcapBrowseCursor--
		}
		return false
	case tcell.KeyDown:
		if app.PcapBrowseCursor < len(app.PcapBrowseEntries)-1 {
			app.PcapBrowseCursor++
		}
		return false
	case tcell.KeyPgUp, tcell.KeyHome:
		app.PcapBrowseCursor = 0
		return false
	case tcell.KeyPgDn, tcell.KeyEnd:
		if n := len(app.PcapBrowseEntries); n > 0 {
			app.PcapBrowseCursor = n - 1
		}
		return false
	case tcell.KeyEnter:
		pcapBrowserActivate(app)
		return false
	case tcell.KeyBackspace, tcell.KeyBackspace2:
		// Backspace = go up one directory (matches `cd ..`).
		pcapBrowseInto(app, pcapBrowseParent)
		return false
	case tcell.KeyTab:
		// Tab while browsing closes the browser and returns to text
		// edit mode at the current directory — symmetric with the
		// open trigger.
		app.PcapPath = ensureTrailingSeparator(app.PcapBrowseDir)
		app.PcapPathCursor = len(app.PcapPath)
		closePcapBrowser(app)
		app.PcapEditing = true
		return false
	}
	switch tev.Rune() {
	case 'q':
		return requestQuit(app)
	}
	return false
}

// pcapBrowserActivate handles Enter on the cursor entry: a directory
// becomes the new browse dir; a .pcap/.pcapng file is selected and
// closes the browser.
func pcapBrowserActivate(app *shared.AppState) {
	if app.PcapBrowseCursor < 0 || app.PcapBrowseCursor >= len(app.PcapBrowseEntries) {
		return
	}
	entry := app.PcapBrowseEntries[app.PcapBrowseCursor]
	pcapBrowseInto(app, entry)
}

// pcapBrowseInto handles either kind of activation. "../" goes up a
// level; trailing-"/" entries cd in; everything else is a file
// selection.
func pcapBrowseInto(app *shared.AppState, entry string) {
	if entry == pcapBrowseParent {
		parent := filepath.Dir(filepath.Clean(app.PcapBrowseDir))
		if parent == app.PcapBrowseDir {
			return
		}
		app.PcapBrowseDir = parent
		app.PcapBrowseEntries = listPcapBrowseEntries(parent)
		app.PcapBrowseCursor = 0
		return
	}
	if strings.HasSuffix(entry, "/") {
		next := filepath.Join(app.PcapBrowseDir, strings.TrimSuffix(entry, "/"))
		if info, err := os.Stat(next); err == nil && info.IsDir() {
			app.PcapBrowseDir = next
			app.PcapBrowseEntries = listPcapBrowseEntries(next)
			app.PcapBrowseCursor = 0
		}
		return
	}
	// File: select and close.
	full := filepath.Join(app.PcapBrowseDir, entry)
	app.PcapPath = full
	app.PcapPathCursor = len(full)
	app.PcapError = ""
	closePcapBrowser(app)
}

// closePcapBrowser tears down the overlay state.
func closePcapBrowser(app *shared.AppState) {
	app.PcapBrowsing = false
	app.PcapBrowseEntries = nil
	app.PcapBrowseCursor = 0
}

// ensureTrailingSeparator appends the OS path separator to dir if
// not already present, so the operator can keep typing a filename.
func ensureTrailingSeparator(dir string) string {
	if dir == "" {
		return dir
	}
	if strings.HasSuffix(dir, string(os.PathSeparator)) {
		return dir
	}
	return dir + string(os.PathSeparator)
}
