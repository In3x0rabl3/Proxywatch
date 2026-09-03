package common

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	"proxywatch/internal/shared"

	"github.com/gdamore/tcell/v2"
)

func PutStringStyle(s tcell.Screen, x, y int, text string, st tcell.Style) {
	sw, sh := s.Size()
	if y < 0 || y >= sh || sw <= 0 {
		return
	}
	for i, r := range text {
		cx := x + i
		if cx < 0 || cx >= sw {
			continue
		}
		s.SetContent(cx, y, r, nil, st)
	}
}

// AnyOverlayOpen returns true when any workflow has a help or menu overlay visible.
func AnyOverlayOpen(app *shared.AppState) bool {
	return app.ContourShowHelp || app.ContourShowMenu ||
		app.KeystoreShowHelp ||
		app.WhitelistShowHelp ||
		app.ShowInspectMenu
}

// RoleStyle returns the display style for a candidate role.
func RoleStyle(role string) tcell.Style {
	switch shared.RoleFamily(role) {
	case "beacon":
		return StyleSession
	case "pivot":
		return StylePivot
	default:
		return StyleTextB
	}
}

// StateStyle returns the display style for a candidate state.
func StateStyle(state string) tcell.Style {
	switch {
	case state == "tunneling":
		return StyleAlertB
	case state == "analyzing" || strings.Contains(state, "Analyzing"):
		return StyleDim
	case state == "exited":
		return StyleDim
	default: // "watch"
		return StyleWatch
	}
}

func SetWorkflowStatus(app *shared.AppState, text *string, isErr *bool, until *time.Time, msg string, isError bool) {
	*text = msg
	*isErr = isError
	now := time.Now()
	if isError {
		*until = now.Add(30 * time.Second)
		return
	}
	*until = now.Add(5 * time.Second)
}

var (
	UIWindows = runtime.GOOS == "windows"

	// Palette tuned to match the reference screenshots.
	ColBg      = tcell.NewRGBColor(30, 30, 30)
	ColText    = tcell.NewRGBColor(226, 234, 242)
	ColTextHi  = tcell.NewRGBColor(245, 250, 255)
	ColFrame   = tcell.NewRGBColor(132, 92, 182)
	ColAccent  = tcell.NewRGBColor(165, 125, 82)
	ColSession = tcell.NewRGBColor(198, 118, 130)
	ColWatch   = tcell.NewRGBColor(94, 188, 142)
	ColWatchHi = tcell.NewRGBColor(120, 210, 160)
	ColCyan    = ColWatch
	ColDim     = tcell.NewRGBColor(126, 142, 168)
	ColDimHi   = tcell.NewRGBColor(156, 172, 196)
	ColMuted   = tcell.NewRGBColor(112, 130, 160)
	ColAlert   = tcell.NewRGBColor(198, 118, 130)
	ColWarn    = tcell.NewRGBColor(201, 173, 94)
	ColOrange  = tcell.NewRGBColor(220, 155, 75)
	// Use a neutral slate selection background across all platforms.
	ColSelect = tcell.NewRGBColor(42, 52, 68)

	StyleText    = tcell.StyleDefault.Foreground(ColText).Background(ColBg)
	StyleTextB   = tcell.StyleDefault.Foreground(ColText).Background(ColBg).Bold(true)
	StyleFrame   = tcell.StyleDefault.Foreground(ColFrame).Background(ColBg)
	StyleAccent  = tcell.StyleDefault.Foreground(ColAccent).Background(ColBg).Bold(true)
	StyleSession = tcell.StyleDefault.Foreground(ColSession).Background(ColBg).Bold(true)
	StylePivot   = tcell.StyleDefault.Foreground(ColWarn).Background(ColBg).Bold(true)
	StyleTunnel  = tcell.StyleDefault.Foreground(ColOrange).Background(ColBg).Bold(true)
	StyleCyan    = tcell.StyleDefault.Foreground(ColCyan).Background(ColBg)
	StyleCyanB   = tcell.StyleDefault.Foreground(ColCyan).Background(ColBg).Bold(true)
	StyleWatch   = tcell.StyleDefault.Foreground(ColWatch).Background(ColBg).Bold(true)
	StyleDimB    = tcell.StyleDefault.Foreground(ColDim).Background(ColBg).Bold(true)
	StyleDim     = tcell.StyleDefault.Foreground(ColDim).Background(ColBg)
	StyleMuted   = tcell.StyleDefault.Foreground(ColMuted).Background(ColBg)
	StyleAlert   = tcell.StyleDefault.Foreground(ColAlert).Background(ColBg)
	StyleAlertB  = tcell.StyleDefault.Foreground(ColAlert).Background(ColBg).Bold(true)
	StyleWarn    = tcell.StyleDefault.Foreground(ColWarn).Background(ColBg).Bold(true)
)

func init() {
	if !UIWindows {
		return
	}

	// Windows terminals frequently ignore bold attributes; use explicit brighter
	// foreground colors and row background highlighting to preserve emphasis.
	StyleTextB = tcell.StyleDefault.Foreground(ColTextHi).Background(ColBg).Bold(true)
	StyleAccent = tcell.StyleDefault.Foreground(ColAccent).Background(ColBg).Bold(true)
	StyleSession = tcell.StyleDefault.Foreground(ColSession).Background(ColBg).Bold(true)
	StylePivot = tcell.StyleDefault.Foreground(ColWarn).Background(ColBg).Bold(true)
	StyleTunnel = tcell.StyleDefault.Foreground(ColOrange).Background(ColBg).Bold(true)
	StyleCyanB = tcell.StyleDefault.Foreground(ColWatchHi).Background(ColBg).Bold(true)
	StyleWatch = tcell.StyleDefault.Foreground(ColWatchHi).Background(ColBg).Bold(true)
	StyleDimB = tcell.StyleDefault.Foreground(ColDimHi).Background(ColBg).Bold(true)
	StyleAlertB = tcell.StyleDefault.Foreground(ColAlert).Background(ColBg).Bold(true)
	StyleWarn = tcell.StyleDefault.Foreground(ColWarn).Background(ColBg).Bold(true)
}

func ApplySelectedRowStyle(st tcell.Style, selected bool) tcell.Style {
	if !selected {
		return st
	}
	return st.Background(ColSelect)
}

func FillSelectedRowBar(s tcell.Screen, y, x, w int, selected bool) {
	if !selected || w <= 0 {
		return
	}
	FillLine(s, x, y, w, ' ', StyleText.Background(ColSelect))
}

func ClearScreen(s tcell.Screen) {
	s.SetStyle(StyleText)
	s.HideCursor()
	s.Clear()
}

func TextCursorX(startX int, value string, maxWidth int) int {
	if maxWidth <= 0 {
		return startX
	}
	width := len([]rune(value))
	if width > maxWidth {
		width = maxWidth
	}
	if width < 0 {
		width = 0
	}
	return startX + width
}

func ShowInputCursor(s tcell.Screen, x, y int) {
	if s == nil {
		return
	}
	w, h := s.Size()
	if w <= 0 || h <= 0 {
		return
	}
	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}
	if x >= w {
		x = w - 1
	}
	if y >= h {
		y = h - 1
	}
	s.ShowCursor(x, y)
}

func DrawEditingTag(s tcell.Screen, y, w int, active bool) {
	if !active || s == nil || w <= 0 {
		return
	}
	tag := "[editing]"
	x := max(2, w-2-len(tag))
	PutStringStyle(s, x, y, tag, StyleWarn)
}

func FillLine(s tcell.Screen, x, y, w int, ch rune, st tcell.Style) {
	if w <= 0 {
		return
	}
	sw, sh := s.Size()
	if y < 0 || y >= sh || sw <= 0 {
		return
	}
	for i := 0; i < w; i++ {
		cx := x + i
		if cx < 0 || cx >= sw {
			continue
		}
		s.SetContent(cx, y, ch, nil, st)
	}
}

func DrawPanel(s tcell.Screen, x, y, w, h int, title, right string) {
	sw, sh := s.Size()
	if x < 0 || y < 0 || x >= sw || y >= sh {
		return
	}
	if x+w > sw {
		w = sw - x
	}
	if y+h > sh {
		h = sh - y
	}
	if w < 2 || h < 2 {
		return
	}
	FillLine(s, x+1, y, w-2, '─', StyleFrame)
	FillLine(s, x+1, y+h-1, w-2, '─', StyleFrame)
	s.SetContent(x, y, '┌', nil, StyleFrame)
	s.SetContent(x+w-1, y, '┐', nil, StyleFrame)
	s.SetContent(x, y+h-1, '└', nil, StyleFrame)
	s.SetContent(x+w-1, y+h-1, '┘', nil, StyleFrame)
	for yy := y + 1; yy < y+h-1; yy++ {
		s.SetContent(x, yy, '│', nil, StyleFrame)
		s.SetContent(x+w-1, yy, '│', nil, StyleFrame)
	}

	if title != "" && w > 6 {
		label := " " + title + " "
		PutStringStyle(s, x+2, y, TruncateToWidth(label, w-4), StyleAccent)
	}
	if right != "" && w > 6 {
		label := " " + right + " "
		start := x + w - 2 - len(label)
		if start > x+2 {
			PutStringStyle(s, start, y, label, StyleCyanB)
		}
	}
}

func DrawMenuPanel(s tcell.Screen, w, h int, title string, options []string, selected int, footer string) {
	maxLen := 0
	if title != "" {
		if n := len(title) + 8; n > maxLen {
			maxLen = n
		}
	}
	for _, opt := range options {
		if n := len(opt) + 4; n > maxLen {
			maxLen = n
		}
	}
	if footer != "" {
		if n := len(footer) + 4; n > maxLen {
			maxLen = n
		}
	}
	menuW := max(28, maxLen)
	if w < menuW+2 {
		menuW = w - 2
	}
	if menuW < 20 {
		return
	}
	menuH := len(options) + 3
	if footer != "" {
		menuH++
	}
	if menuH >= h {
		menuH = h - 2
	}
	x := (w - menuW) / 2
	y := (h - menuH) / 2
	DrawPanel(s, x, y, menuW, menuH, title, "menu")
	// Opaque menu body so underlying dashboard rows do not bleed through.
	for yy := y + 1; yy < y+menuH-1; yy++ {
		FillLine(s, x+1, yy, menuW-2, ' ', StyleText)
	}

	if len(options) == 0 {
		return
	}

	innerRows := menuH - 2
	if innerRows <= 0 {
		return
	}
	if footer != "" {
		innerRows--
	}
	if innerRows <= 0 {
		return
	}

	start := 0
	if selected >= 0 {
		if selected >= len(options) {
			selected = len(options) - 1
		}
		if selected < 0 {
			selected = 0
		}
		if len(options) > innerRows {
			start = selected - innerRows + 1
			if start < 0 {
				start = 0
			}
			maxStart := len(options) - innerRows
			if start > maxStart {
				start = maxStart
			}
		}
	}

	for rowOff := 0; rowOff < innerRows; rowOff++ {
		optIdx := start + rowOff
		if optIdx >= len(options) {
			break
		}
		row := y + 1 + rowOff
		opt := options[optIdx]
		rowSelected := selected >= 0 && optIdx == selected

		// Section header lines (start with "[")
		if strings.HasPrefix(opt, "[") {
			PutStringStyle(s, x+2, row, TruncateToWidth("  "+opt, menuW-4), ApplySelectedRowStyle(StyleMuted, rowSelected))
			continue
		}

		// Separator lines
		if opt == "" {
			continue
		}

		prefix := "  "
		if rowSelected {
			prefix = "> "
			FillSelectedRowBar(s, row, x+1, menuW-2, true)
		}

		// Split "KEY  Description" into key and desc parts for distinct styling.
		keyPart, descPart := opt, ""
		if idx := strings.Index(opt, "  "); idx > 0 {
			keyPart = opt[:idx]
			descPart = strings.TrimLeft(opt[idx:], " ")
		}
		keyStyle := ApplySelectedRowStyle(StyleCyanB, rowSelected)
		descStyle := ApplySelectedRowStyle(StyleText, rowSelected)
		prefixStyle := ApplySelectedRowStyle(StyleDim, rowSelected)
		if rowSelected {
			descStyle = ApplySelectedRowStyle(StyleTextB, rowSelected)
		}

		PutStringStyle(s, x+2, row, prefix, prefixStyle)
		keyX := x + 2 + len(prefix)
		PutStringStyle(s, keyX, row, TruncateToWidth(keyPart, menuW-4-len(prefix)), keyStyle)
		if descPart != "" {
			descX := keyX + 13
			if descX < x+menuW-2 {
				PutStringStyle(s, descX, row, TruncateToWidth(descPart, x+menuW-2-descX), descStyle)
			}
		}
	}

	if footer != "" && y+menuH-2 >= y+1 {
		PutStringStyle(s, x+2, y+menuH-2, TruncateToWidth(footer, menuW-4), StyleMuted)
	}
}

func DrawQuitConfirmOverlay(app *shared.AppState) {
	if app == nil || !app.ShowQuitConfirm || app.Screen == nil {
		return
	}
	s := app.Screen
	w, h := s.Size()
	remaining := int(time.Until(app.QuitConfirmDeadline).Round(time.Second).Seconds())
	if remaining < 0 {
		remaining = 0
	}
	opts := []string{
		"Press 'y' or ENTER to quit",
		"Press 'n' or ESC to stay",
	}
	footer := fmt.Sprintf("Timeout: %ds", remaining)
	DrawMenuPanel(s, w, h, "Confirm Exit", opts, -1, footer)
}

const UTCTimeFormat = "2006-01-02 15:04:05"

func FindIndexByKey(cands []shared.Candidate, key string) int {
	for i, c := range cands {
		if shared.CandidateKey(c) == key {
			return i
		}
	}
	return -1
}

func TruncateToWidth(s string, w int) string {
	if w <= 0 || len(s) <= w {
		return s
	}
	if w <= 3 {
		return s[:w]
	}
	return s[:w-3] + "..."
}

// ClipToWidth hard-clips without appending ellipsis.
func ClipToWidth(s string, w int) string {
	if w <= 0 || len(s) <= w {
		return s
	}
	return s[:w]
}

func FormatBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}

	div := uint64(unit)
	exp := 0
	for n >= div*unit && exp < 4 {
		div *= unit
		exp++
	}

	value := float64(n) / float64(div)
	suffixes := []string{"KB", "MB", "GB", "TB", "PB"}
	return fmt.Sprintf("%.1f %s", value, suffixes[exp])
}

func FormatBytesPerSec(n uint64) string {
	return FormatBytes(n) + "/s"
}

var CollectDurations = []string{"30s", "1m", "5m"}

func SafeRolePreset(app *shared.AppState) string {
	p := strings.TrimSpace(app.RolePreset)
	if p == "" {
		return "all"
	}
	return p
}

func CollectActionLabel(app *shared.AppState) string {
	if app.CollectActive {
		remaining := time.Until(app.CollectUntil).Round(time.Second)
		if remaining < 0 {
			remaining = 0
		}
		return "Stop collection (" + remaining.String() + " left)"
	}
	return "Start collection"
}

func FormatDashboardAge(seconds int) string {
	if seconds <= 0 {
		return "+000s"
	}
	d := time.Duration(seconds) * time.Second
	if d < time.Minute {
		return fmt.Sprintf("+%03ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("+%03dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("+%03dh", int(d.Hours()))
	}
	return fmt.Sprintf("+%03dd", int(d.Hours()/24))
}

func DashboardCandidateAgeSeconds(c shared.Candidate) int {
	if c.SeenSeconds > 0 {
		return c.SeenSeconds
	}
	if c.ControlDurationSeconds > 0 {
		return c.ControlDurationSeconds
	}
	return 0
}

func RefreshPresetOptions() []string {
	return []string{"100ms", "250ms", "500ms", "1s", "2s", "5s"}
}

// All help menus follow the same template so operators get a uniform
// reading order across views:
//
//	[Navigation]   movement keys (Up/Down/PgUp/PgDn/Home/End/Tab)
//	[Workflows]    workflow switching (LEFT/RIGHT, 0-6 jump)
//	[Editing]      form editing (when applicable)
//	[Actions]      view-specific shortcuts
//	[General]      ?, ESC, q — same wording on every menu
//
// Workflow numbering — '0'=Dashboard, '1'=Model, '2'=Contour,
// '3'=ProxyHound, '4'=Whitelist, '5'=Keystore, '6'=PCAP Analyzer.
// See keys/shared.go JumpToWorkflow for the authoritative mapping.
// Dashboard's menu lists each one explicitly since it's the home
// screen; sub-views condense to "0-6".

func DashboardMenuHelpOptions() []string {
	return []string{
		"[Navigation]",
		"UP/DOWN      Move selection",
		"PGUP/PGDN    Move by page",
		"ENTER        Open selected row",
		"",
		"[Workflows]",
		"LEFT/RIGHT   Cycle workflows",
		"1            Model",
		"2            Contour",
		"3            ProxyHound",
		"4            Whitelist",
		"5            Keystore",
		"6            PCAP Analyzer",
		"",
		"[Actions]",
		"w            Open whitelist panel",
		"W            Whitelist selected process",
		"r            Refresh / remove host",
		"c            Role + sort menu",
		"x            Remove disconnected host",
		"",
		"[General]",
		"?            Close this menu",
		"ESC          Exit host process view",
		"q            Quit",
	}
}

func CollectMenuHelpOptions() []string {
	return []string{
		"[Navigation]",
		"UP/DOWN      Move field",
		"",
		"[Workflows]",
		"LEFT/RIGHT   Cycle workflows",
		"0-6          Jump to workflow",
		"",
		"[Editing]",
		"ENTER        Edit / open / start",
		"BACKSPACE    Delete while editing",
		"",
		"[General]",
		"?            Close this menu",
		"ESC          Back to dashboard",
		"q            Quit",
	}
}

func ContourMenuHelpOptions() []string {
	return []string{
		"[Navigation]",
		"UP/DOWN      Move field",
		"TAB/BTAB     Next / prev field",
		"PGUP/PGDN    Scroll report page",
		"[ / ]        Scroll report line",
		"",
		"[Workflows]",
		"LEFT/RIGHT   Cycle workflows",
		"0-6          Jump to workflow",
		"",
		"[Editing]",
		"ENTER        Edit / open / start",
		"BACKSPACE    Delete while editing",
		"",
		"[General]",
		"?            Close this menu",
		"ESC          Back to dashboard",
		"q            Quit",
	}
}

func KeystoreMenuHelpOptions() []string {
	return []string{
		"[Navigation]",
		"UP/DOWN      Move field / select keystore",
		"PGUP         Jump to Setup",
		"PGDN         Jump to Keystores list",
		"TAB          Toggle fields / keystores list",
		"",
		"[Workflows]",
		"LEFT/RIGHT   Cycle workflows",
		"0-6          Jump to workflow",
		"",
		"[Editing]",
		"ENTER        Edit / open / switch keystore",
		"BACKSPACE    Delete while editing",
		"",
		"[Actions]",
		"a            Activate selected keystore",
		"n            Create new keystore",
		"d            Delete selected keystore",
		"",
		"[General]",
		"?            Close this menu",
		"ESC          Back / lock keystore",
		"q            Quit",
	}
}

func WhitelistMenuHelpOptions() []string {
	return []string{
		"[Navigation]",
		"UP/DOWN      Navigate within panel",
		"PGUP         Switch to Processes",
		"PGDN         Switch to Whitelisted",
		"TAB          Toggle panels",
		"",
		"[Workflows]",
		"LEFT/RIGHT   Cycle workflows",
		"0-6          Jump to workflow",
		"",
		"[Actions]",
		"ENTER        Add (processes) / Remove (whitelisted)",
		"",
		"[General]",
		"?            Close this menu",
		"ESC          Back to dashboard",
		"q            Quit",
	}
}

func InspectorMenuOptions() []string {
	return []string{
		"[Navigation]",
		"UP/DOWN      Scroll details",
		"TAB/BTAB     Jump sections",
		"",
		"[Workflows]",
		"LEFT/RIGHT   Cycle workflows",
		"0-6          Jump to workflow",
		"",
		"[Actions]",
		"x            Toggle explain view",
		"k            Kill process (k then y)",
		"t            Cycle training label",
		"",
		"[General]",
		"?            Close this menu",
		"ESC          Back to dashboard",
		"q            Quit",
	}
}

func PcapAnalyzerMenuHelpOptions() []string {
	return []string{
		"[Navigation]",
		"UP/DOWN      Move cursor / select field",
		"TAB          Cycle findings ↔ destinations",
		"PGUP/PGDN    Page through findings list",
		"[ / ]        Scroll CONNECTIONS / SIGNALS panel",
		"{ / }        Page CONNECTIONS / SIGNALS panel",
		"HOME/END     Jump to first / last finding",
		"",
		"[Workflows]",
		"LEFT/RIGHT   Cycle workflows",
		"0-6          Jump to workflow",
		"",
		"[Editing]",
		"ENTER        Edit field / start analysis / re-analyze",
		"BACKSPACE    Delete while editing path",
		"TAB / b      Open directory browser on File field",
		"",
		"[Actions]",
		"a            Toggle show all findings",
		"x            Toggle full signals view",
		"g            Cycle row grouping (cluster/16 → flow → ja3 → asn → session → behavior)",
		"S            Cycle sort order (time → bytes → packets)",
		"",
		"[Operator labels — applies to selected finding]",
		"m            Mark cluster MALICIOUS (force beacon-* this network)",
		"b            Mark cluster BENIGN (force outbound this network)",
		"c            Clear cluster label",
		"t            Mark TLS (JA3 + SNI) MALICIOUS (propagates across captures)",
		"T            Mark TLS (JA3 + SNI) BENIGN (propagates across captures)",
		"C            Clear TLS label",
		"             Labels persist to disk across restarts /",
		"             re-analyses, keyed on cluster name.",
		"",
		"[Playback — streaming mode]",
		"SPACE        Pause / resume playback",
		", / .        Seek backward / forward",
		"< / >        Seek backward / forward (alternate)",
		"HOME/END     Jump to start / end of capture",
		"+/-          Increase / decrease playback speed",
		"",
		"[General]",
		"?            Close this menu",
		"ESC          Stop watch / back to picker",
		"q            Quit",
	}
}

func NormalizeDashboardRole(role string) string {
	f := shared.RoleFamily(role)
	if f == "other" {
		return "outbound"
	}
	return f
}

func ClampIndex(idx, n int) int {
	if n <= 0 {
		return -1
	}
	if idx < 0 {
		return 0
	}
	if idx >= n {
		return n - 1
	}
	return idx
}

func SortedCandidates(cands []shared.Candidate, preset string) []shared.Candidate {
	view := make([]shared.Candidate, len(cands))
	copy(view, cands)

	lessByDefault := func(a, b shared.Candidate) bool { return shared.CandidateLess(a, b) }
	hostOf := func(c shared.Candidate) string { return strings.ToLower(shared.DisplayHost(c.Host)) }
	nameOf := func(c shared.Candidate) string {
		if c.Proc == nil {
			return ""
		}
		return strings.ToLower(c.Proc.Name)
	}
	pidOf := func(c shared.Candidate) int {
		if c.Proc == nil {
			return 0
		}
		return c.Proc.Pid
	}
	stateOf := func(c shared.Candidate) string {
		return shared.CandidateState(c)
	}
	ageOf := func(c shared.Candidate) int {
		return DashboardCandidateAgeSeconds(c)
	}
	// rolePriority returns a sort rank: lower = higher threat = sorted first.
	// pivot(0) > beacon(1) >
	// listener(4) > outbound(5) > unknown(6)
	rolePriority := func(c shared.Candidate) int {
		r := NormalizeDashboardRole(c.Role)
		switch r {
		case "pivot":
			return 0
		case "beacon":
			return 1
		case "listener":
			return 4
		case "outbound":
			return 5
		default:
			return 6
		}
	}

	presetLower := strings.ToLower(strings.TrimSpace(preset))
	sort.SliceStable(view, func(i, j int) bool {
		a, b := view[i], view[j]
		switch presetLower {
		case "role":
			// Sort by role priority — group all beacons together, all sessions
			// together, etc. Exited processes stay with their role group.
			pa, pb := rolePriority(a), rolePriority(b)
			if pa != pb {
				return pa < pb
			}
			// Within same role, live above exited.
			if a.Exited != b.Exited {
				return !a.Exited && b.Exited
			}
		case "host":
			if hostOf(a) != hostOf(b) {
				return hostOf(a) < hostOf(b)
			}
			if a.Exited != b.Exited {
				return !a.Exited && b.Exited
			}
		case "age":
			if ageOf(a) != ageOf(b) {
				return ageOf(a) > ageOf(b)
			}
		case "state":
			if stateOf(a) != stateOf(b) {
				return stateOf(a) < stateOf(b)
			}
		case "pid":
			if pidOf(a) != pidOf(b) {
				return pidOf(a) < pidOf(b)
			}
		case "process":
			if nameOf(a) != nameOf(b) {
				return nameOf(a) < nameOf(b)
			}
		default:
			// Default sort: live above exited, then by threat priority.
			if a.Exited != b.Exited {
				return !a.Exited && b.Exited
			}
			return lessByDefault(a, b)
		}
		// When the primary sort key is equal, use secondary sort
		// (process name then PID).
		if nameOf(a) != nameOf(b) {
			return nameOf(a) < nameOf(b)
		}
		return pidOf(a) < pidOf(b)
	})
	return view
}
