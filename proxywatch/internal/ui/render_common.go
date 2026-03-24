package ui

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

// PutOverlayStringStyle draws only non-space glyphs so existing background
// content remains visible under overlay text.
func PutOverlayStringStyle(s tcell.Screen, x, y int, text string, st tcell.Style) {
	sw, sh := s.Size()
	if y < 0 || y >= sh || sw <= 0 {
		return
	}
	for i, r := range text {
		if r == ' ' {
			continue
		}
		cx := x + i
		if cx < 0 || cx >= sw {
			continue
		}
		s.SetContent(cx, y, r, nil, st)
	}
}

var (
	uiWindows = runtime.GOOS == "windows"

	// Palette tuned to match the reference screenshots.
	colBg      = tcell.NewRGBColor(0, 0, 0)
	colText    = tcell.NewRGBColor(226, 234, 242)
	colTextHi  = tcell.NewRGBColor(245, 250, 255)
	colFrame   = tcell.NewRGBColor(132, 92, 182)
	colAccent  = tcell.NewRGBColor(165, 125, 82)
	colSession = tcell.NewRGBColor(198, 118, 130)
	colWatch   = tcell.NewRGBColor(94, 188, 142)
	colWatchHi = tcell.NewRGBColor(120, 210, 160)
	colCyan    = colWatch
	colDim     = tcell.NewRGBColor(126, 142, 168)
	colDimHi   = tcell.NewRGBColor(156, 172, 196)
	colMuted   = tcell.NewRGBColor(112, 130, 160)
	colAlert   = tcell.NewRGBColor(198, 118, 130)
	colWarn    = tcell.NewRGBColor(201, 173, 94)
	// Use a neutral slate selection background across all platforms.
	colSelect = tcell.NewRGBColor(28, 34, 42)

	styleText    = tcell.StyleDefault.Foreground(colText).Background(colBg)
	styleTextB   = tcell.StyleDefault.Foreground(colText).Background(colBg).Bold(true)
	styleFrame   = tcell.StyleDefault.Foreground(colFrame).Background(colBg)
	styleAccent  = tcell.StyleDefault.Foreground(colAccent).Background(colBg).Bold(true)
	styleSession = tcell.StyleDefault.Foreground(colSession).Background(colBg).Bold(true)
	styleCyan    = tcell.StyleDefault.Foreground(colCyan).Background(colBg)
	styleCyanB   = tcell.StyleDefault.Foreground(colCyan).Background(colBg).Bold(true)
	styleWatch   = tcell.StyleDefault.Foreground(colWatch).Background(colBg).Bold(true)
	styleDimB    = tcell.StyleDefault.Foreground(colDim).Background(colBg).Bold(true)
	styleDim     = tcell.StyleDefault.Foreground(colDim).Background(colBg)
	styleMuted   = tcell.StyleDefault.Foreground(colMuted).Background(colBg)
	styleAlert   = tcell.StyleDefault.Foreground(colAlert).Background(colBg)
	styleAlertB  = tcell.StyleDefault.Foreground(colAlert).Background(colBg).Bold(true)
	styleWarn    = tcell.StyleDefault.Foreground(colWarn).Background(colBg).Bold(true)
)

func init() {
	if !uiWindows {
		return
	}

	// Windows terminals frequently ignore bold attributes; use explicit brighter
	// foreground colors and row background highlighting to preserve emphasis.
	styleTextB = tcell.StyleDefault.Foreground(colTextHi).Background(colBg).Bold(true)
	styleAccent = tcell.StyleDefault.Foreground(colAccent).Background(colBg).Bold(true)
	styleSession = tcell.StyleDefault.Foreground(colSession).Background(colBg).Bold(true)
	styleCyanB = tcell.StyleDefault.Foreground(colWatchHi).Background(colBg).Bold(true)
	styleWatch = tcell.StyleDefault.Foreground(colWatchHi).Background(colBg).Bold(true)
	styleDimB = tcell.StyleDefault.Foreground(colDimHi).Background(colBg).Bold(true)
	styleAlertB = tcell.StyleDefault.Foreground(colAlert).Background(colBg).Bold(true)
	styleWarn = tcell.StyleDefault.Foreground(colWarn).Background(colBg).Bold(true)
}

func applySelectedRowStyle(st tcell.Style, selected bool) tcell.Style {
	if !selected {
		return st
	}
	return st.Background(colSelect)
}

func fillSelectedRowBar(s tcell.Screen, y, x, w int, selected bool) {
	if !selected || w <= 0 {
		return
	}
	fillLine(s, x, y, w, ' ', styleText.Background(colSelect))
}

func clearScreen(s tcell.Screen) {
	s.SetStyle(styleText)
	s.Clear()
}

func fillLine(s tcell.Screen, x, y, w int, ch rune, st tcell.Style) {
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

func drawPanel(s tcell.Screen, x, y, w, h int, title, right string) {
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
	fillLine(s, x, y, w, '-', styleFrame)
	fillLine(s, x, y+h-1, w, '-', styleFrame)
	s.SetContent(x, y, '+', nil, styleFrame)
	s.SetContent(x+w-1, y, '+', nil, styleFrame)
	s.SetContent(x, y+h-1, '+', nil, styleFrame)
	s.SetContent(x+w-1, y+h-1, '+', nil, styleFrame)
	for yy := y + 1; yy < y+h-1; yy++ {
		s.SetContent(x, yy, '|', nil, styleFrame)
		s.SetContent(x+w-1, yy, '|', nil, styleFrame)
	}

	if title != "" && w > 6 {
		label := " " + title + " "
		PutStringStyle(s, x+2, y, TruncateToWidth(label, w-4), styleAccent)
	}
	if right != "" && w > 6 {
		label := " " + right + " "
		start := x + w - 2 - len(label)
		if start > x+2 {
			PutStringStyle(s, start, y, label, styleCyanB)
		}
	}
}

func drawMenuPanel(s tcell.Screen, w, h int, title string, options []string, selected int, footer string) {
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
	menuW := max(44, maxLen)
	if w < menuW+2 {
		menuW = w - 2
	}
	if menuW < 20 {
		return
	}
	menuH := len(options) + 4
	if footer != "" {
		menuH++
	}
	if menuH >= h {
		menuH = h - 2
	}
	x := (w - menuW) / 2
	y := (h - menuH) / 2
	drawPanel(s, x, y, menuW, menuH, title, "menu")
	// Opaque menu body so underlying dashboard rows do not bleed through.
	for yy := y + 1; yy < y+menuH-1; yy++ {
		fillLine(s, x+1, yy, menuW-2, ' ', styleText)
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
		rowSelected := selected >= 0 && optIdx == selected
		prefix := "  "
		st := styleText
		if rowSelected {
			prefix = "> "
			st = styleTextB
		}
		fillSelectedRowBar(s, row, x+1, menuW-2, rowSelected)
		PutStringStyle(s, x+2, row, TruncateToWidth(prefix+options[optIdx], menuW-4), applySelectedRowStyle(st, rowSelected))
	}

	if footer != "" && y+menuH-2 >= y+1 {
		PutStringStyle(s, x+2, y+menuH-2, TruncateToWidth(footer, menuW-4), styleMuted)
	}
}

func drawQuitConfirmOverlay(app *shared.AppState) {
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
	drawMenuPanel(s, w, h, "Confirm Exit", opts, -1, footer)
}

const utcTimeFormat = "2006-01-02 15:04:05"

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

func FormatIOBytes(read, write, other uint64) string {
	return formatIOMetric(read, write, other, FormatBytes)
}

func FormatIORate(read, write, other uint64) string {
	return formatIOMetric(read, write, other, FormatBytesPerSec)
}

func formatIOMetric(read, write, other uint64, format func(uint64) string) string {
	total := read + write + other
	if total == 0 {
		return format(0)
	}

	parts := make([]string, 0, 3)
	if read > 0 {
		parts = append(parts, "R "+format(read))
	}
	if write > 0 {
		parts = append(parts, "W "+format(write))
	}
	if other > 0 {
		parts = append(parts, "O "+format(other))
	}

	totalStr := format(total)
	if len(parts) == 0 {
		return totalStr
	}
	if len(parts) == 1 {
		return fmt.Sprintf("%s (%s)", totalStr, parts[0])
	}
	return fmt.Sprintf("%s (%s)", totalStr, strings.Join(parts, " "))
}

var collectDurations = []string{"30s", "1m", "2m", "5m", "10m", "15m"}

func safeRolePreset(app *shared.AppState) string {
	p := strings.TrimSpace(app.RolePreset)
	if p == "" {
		return "recommended"
	}
	return p
}

func collectActionLabel(app *shared.AppState) string {
	if app.CollectActive {
		remaining := time.Until(app.CollectUntil).Round(time.Second)
		if remaining < 0 {
			remaining = 0
		}
		return "Stop collection (" + remaining.String() + " left)"
	}
	return "Start collection"
}

func formatDashboardAge(seconds int) string {
	if seconds <= 0 {
		return "0s"
	}
	d := time.Duration(seconds) * time.Second
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

func dashboardCandidateAgeSeconds(c shared.Candidate) int {
	if c.SeenSeconds > 0 {
		return c.SeenSeconds
	}
	if c.ControlDurationSeconds > 0 {
		return c.ControlDurationSeconds
	}
	return 0
}

func rolePresetOptions() []string {
	return []string{"recommended", "all", "control", "reverse", "listener", "outbound"}
}

func sortPresetOptions() []string {
	return []string{"default", "host", "role", "age", "state", "pid", "process"}
}

func refreshPresetOptions() []string {
	return []string{"100ms", "250ms", "500ms", "1s", "2s", "5s"}
}

func dashboardMenuHelpOptions() []string {
	return []string{
		"'UP/DOWN': move selection",
		"'PGUP/PGDN': move by page",
		"'HOME/END': jump to start or end",
		"'ENTER': open the selected host or inspect the selected process",
		"'ESC': leave a host process view and return to the host list",
		"'x': remove the selected disconnected host",
		"'r': open refresh options",
		"'f': open role/sort menu",
		"'b': open BloodHound collection workflow",
		"'o': open contour workflow",
		"'c': open calibration workflow",
		"'k': open keystore workflow",
		"'m': open SIEM workflow",
		"'w': open whitelist workflow",
		"'?' or 'ESC': close this menu",
		"'q': quit",
	}
}

func calibrationMenuHelpOptions() []string {
	return []string{
		"'UP/DOWN': move selection",
		"'TAB/SHIFT+TAB': move selection",
		"'PGUP/PGDN': scroll report by page",
		"'j'/'k': scroll report by line",
		"'LEFT/RIGHT': quick-change selected value",
		"'ENTER': edit field, open picker, or run action",
		"'?': open or close this menu",
		"'ESC': close menu or return to dashboard",
		"'q': quit",
	}
}

func collectMenuHelpOptions() []string {
	return []string{
		"'UP/DOWN': move selection",
		"'LEFT/RIGHT': quick-change source or duration",
		"'ENTER': edit field, open picker, or run action",
		"'?': open or close this menu",
		"'ESC': close menu or return to dashboard",
		"'q': quit",
	}
}

func contourMenuHelpOptions() []string {
	return []string{
		"'UP/DOWN': move selection",
		"'LEFT/RIGHT': quick-change role or probe mode",
		"'PGUP/PGDN': scroll report by page",
		"'j'/'k': scroll report by line",
		"'ENTER': edit field, open picker, or run action",
		"'?': open or close this menu",
		"'ESC': close menu or return to dashboard",
		"'q': quit",
	}
}

func keystoreMenuHelpOptions() []string {
	return []string{
		"'UP/DOWN': move selection",
		"'ENTER': edit field or run Load/Save/Apply",
		"'BACKSPACE': remove last character while editing",
		"'?': open or close this menu",
		"'ESC': stop editing, then return to dashboard",
		"'q': quit",
	}
}

func siemMenuHelpOptions() []string {
	return []string{
		"'UP/DOWN': move selection",
		"'LEFT/RIGHT': quick-change provider/model/source",
		"'PGUP/PGDN': scroll report by page",
		"'j'/'k': scroll report by line",
		"'ENTER': edit field, open picker, or run action",
		"'?': open or close this menu",
		"'ESC': close menu or return to dashboard",
		"'q': quit",
	}
}

func whitelistMenuHelpOptions() []string {
	return []string{
		"'UP/DOWN' or 'TAB/SHIFT+TAB': move setup selection",
		"'LEFT/RIGHT' or 'j'/'k': browse focused list",
		"'ENTER' or 'a': add selected process to whitelist",
		"'d'/'u'/'x': remove selected whitelist entry",
		"'?': open or close this menu",
		"'ESC': return to dashboard",
		"'q': quit",
	}
}

func inspectorMenuOptions() []string {
	return []string{
		"'UP/DOWN': scroll details",
		"'TAB/SHIFT+TAB': jump between sections",
		"'x': toggle explain section",
		"'k': request kill (k/y to confirm)",
		"'ESC': close menu",
		"'ESC' again: return to dashboard",
		"'?': close this menu",
		"'q': quit",
	}
}

func normalizeDashboardRole(role string) string {
	role = strings.ToLower(strings.TrimSpace(role))
	switch role {
	case "smb-pipe":
		return "smb-pipe"
	case "susp-session", "reverse-control", "session":
		return "session"
	case "susp-beacon", "beacon":
		return "beacon"
	case "susp-tun", "reverse-proxy", "reverse-transport", "reverse-tunnel", "tunnel":
		return "tunnel"
	case "proxy-listener", "listener-with-clients", "listener-with-outbound", "listener-only", "listener":
		return "listener"
	case "outbound-only", "outbound":
		return "outbound"
	default:
		return "outbound"
	}
}

func clampIndex(idx, n int) int {
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

func sortedCandidates(cands []shared.Candidate, preset string) []shared.Candidate {
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
		if c.Proc == nil {
			return ""
		}
		return strings.ToLower(c.Proc.Status)
	}
	ageOf := func(c shared.Candidate) int {
		return dashboardCandidateAgeSeconds(c)
	}
	roleOf := func(c shared.Candidate) string { return strings.ToLower(shared.RoleFamily(c.Role)) }

	sort.SliceStable(view, func(i, j int) bool {
		a, b := view[i], view[j]
		switch strings.ToLower(strings.TrimSpace(preset)) {
		case "host":
			if hostOf(a) != hostOf(b) {
				return hostOf(a) < hostOf(b)
			}
		case "role":
			if roleOf(a) != roleOf(b) {
				return roleOf(a) < roleOf(b)
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
			return lessByDefault(a, b)
		}
		return lessByDefault(a, b)
	})
	return view
}
