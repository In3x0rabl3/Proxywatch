package views

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"proxywatch/internal/shared"
	"proxywatch/internal/ui/common"
)

// DashboardModel is the native bubbletea model for the Dashboard view.
type DashboardModel struct {
	app    *shared.AppState
	width  int
	height int
}

func NewDashboardModel(app *shared.AppState) DashboardModel {
	return DashboardModel{app: app}
}

func (m DashboardModel) Init() tea.Cmd { return nil }

func (m DashboardModel) Update(msg tea.Msg) (DashboardModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		tev := convertKeyMsg(msg)

		handled, shouldQuit := handleQuitConfirmKey(m.app, tev)
		if handled {
			if shouldQuit {
				return m, tea.Quit
			}
			return m, nil
		}

		// Number key workflow jumping.
		if jumpToWorkflow(m.app, tev.Rune()) {
			return m, nil
		}

		if handleDashboardKey(m.app, tev) {
			return m, tea.Quit
		}
	}

	return m, nil
}

func (m DashboardModel) View() string {
	w := m.width
	h := m.height
	if w <= 0 {
		w = 80
	}
	if h <= 0 {
		h = 24
	}

	top := shellBanner(w)
	bottom := m.renderBottomBar(w)

	var sections []string
	sections = append(sections, top)
	if progress := m.renderCollectProgress(w); progress != "" {
		sections = append(sections, progress)
	}

	used := lipgloss.Height(bottom)
	for _, s := range sections {
		used += lipgloss.Height(s)
	}
	bodyH := h - used
	if m.app.ShowQuitConfirm || m.app.LastError != "" {
		bodyH--
	}
	if bodyH < 6 {
		bodyH = 6
	}
	sections = append(sections, m.renderBody(w, bodyH))
	sections = append(sections, bottom)

	view := lipgloss.JoinVertical(lipgloss.Left, sections...)

	if m.app.ShowHelp {
		help := dashboardMenuHelpOptions()
		view = overlayCenter(view, renderHelpPanel("Dashboard Menu", help, w), w, h)
	} else if m.app.ShowRoleMenu {
		opts := roleSortMenuLabels()
		view = overlayCenter(view, renderMenuPanel("Roles + Sort", opts, clampIndex(m.app.RoleMenuIndex, len(opts)),
			"Enter apply   f role/sort menu   Esc close", w), w, h)
	} else if m.app.ShowRefreshMenu {
		opts := refreshPresetOptions()
		view = overlayCenter(view, renderMenuPanel("Refresh Rate", opts, clampIndex(m.app.RefreshMenuIndex, len(opts)),
			"Enter apply   Esc close", w), w, h)
	} else if m.app.ShowWhitelistPanel {
		view = overlayCenter(view, m.renderWhitelistPanel(w), w, h)
	}

	if m.app.LastError != "" {
		view += "\n" + statusFail.Render("  "+m.app.LastError)
	}
	if m.app.ShowQuitConfirm && time.Now().Before(m.app.QuitConfirmDeadline) {
		quitPanel := renderQuitConfirm(m.app.QuitConfirmDeadline, w)
		view = overlayCenter(view, quitPanel, w, m.height)
	}

	return view
}

// ── Framing: top section, bottom bar, collect progress ───────────────────────

// proxywatchBannerContent is the PROXYWATCH logo content (no border).
var proxywatchBannerContent = []string{
	" ██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗",
	" ██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║",
	" ██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝ ██║ █╗ ██║███████║   ██║   ██║     ███████║",
	" ██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝  ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║",
	" ██║     ██║  ██║╚██████╔╝██╔╝ ██╗   ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║",
	" ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝",
}

const proxywatchBannerW = 88

// proxywatchEyeW is the width of the rendered tower emblem.
const proxywatchEyeW = 11

// renderEyeOfSauron returns 5 styled lines for the Tower of Barad-dûr with
// the Eye of Sauron at the top, looking around randomly.
func renderEyeOfSauron() []string {
	// Animation: pupil looks around in a random-seeming pattern
	lookPattern := []int{1, 3, 0, 2, 4, 1, 3, 2, 0, 4, 2, 1, 3, 0, 2, 4}
	ms := time.Now().UnixMilli()
	idx := (ms / 500) % int64(len(lookPattern))
	phase := lookPattern[idx] // 0-4: left to right positions

	// Purple palette
	dark := lipgloss.NewStyle().Foreground(lipgloss.Color("#3A2A5E")).Background(common.ColorBg)
	stone := lipgloss.NewStyle().Foreground(common.ColorLogoDim).Background(common.ColorBg)
	bright := lipgloss.NewStyle().Foreground(common.ColorLogo).Background(common.ColorBg)
	glow := lipgloss.NewStyle().Foreground(lipgloss.Color("#C9A0FF")).Background(common.ColorBg)
	hot := lipgloss.NewStyle().Foreground(lipgloss.Color("#E8D0FF")).Background(common.ColorBg)
	pupil := lipgloss.NewStyle().Foreground(lipgloss.Color("#000000")).Background(common.ColorBg)
	bg := common.Bg()

	// Build the eye row with moving pupil (5 positions)
	eyeChars := []string{"▒", "▒", "▓", "▒", "▒"}
	for i := range eyeChars {
		if i == phase {
			eyeChars[i] = pupil.Render("●")
		} else if i == phase-1 || i == phase+1 {
			eyeChars[i] = hot.Render("░")
		} else {
			eyeChars[i] = glow.Render("▒")
		}
	}
	eyeRow := stone.Render("╱") + bright.Render("(") + eyeChars[0] + eyeChars[1] + eyeChars[2] + eyeChars[3] + eyeChars[4] + bright.Render(")") + stone.Render("╲")

	return []string{
		bg.Render(" ") + dark.Render("╱") + stone.Render("▔") + bright.Render("▔▔▔▔▔") + stone.Render("▔") + dark.Render("╲") + bg.Render(" "),
		bg.Render("") + eyeRow + bg.Render(" "),
		bg.Render(" ") + dark.Render("╲") + stone.Render("▁") + bright.Render("▁▁▁▁▁") + stone.Render("▁") + dark.Render("╱") + bg.Render(" "),
		bg.Render("  ") + dark.Render("║") + stone.Render("▓") + bright.Render("███") + stone.Render("▓") + dark.Render("║") + bg.Render("  "),
		bg.Render(" ") + dark.Render("╱") + stone.Render("▀") + bright.Render("▀▀▀▀▀") + stone.Render("▀") + dark.Render("╲") + bg.Render(" "),
	}
}

// shellBannerHeight reports how many rows shellBanner occupies at width w:
// the full banner when wide, or a single compact line when narrow.
func shellBannerHeight(w int) int {
	if w < proxywatchBannerW+2 {
		return 1
	}
	return len(proxywatchBannerContent) + 1 // content + top spacing
}

// shellBanner draws the tactical PROXYWATCH banner with border
// on the left and date/time box in the top-right corner.
func shellBanner(w int) string {
	logoStyle := lipgloss.NewStyle().Foreground(common.ColorLogo).Background(common.ColorBg)

	pad := func(line string) string {
		if p := w - lipgloss.Width(line); p > 0 {
			return line + bgSp(p)
		}
		return line
	}

	if w < proxywatchBannerW+2 {
		line := bgSp(1) + logoStyle.Render("██ PROXYWATCH")
		return pad(line)
	}

	now := time.Now().UTC()
	dayOfYear := now.YearDay()

	// Military/tactical style: DDMMMYY, Julian day, Zulu time
	dateFmt := strings.ToUpper(now.Format("02JAN06"))
	timeFmt := now.Format("15:04:05")

	labelStyle := lipgloss.NewStyle().Foreground(common.ColorDim).Background(common.ColorBg)
	valueStyle := lipgloss.NewStyle().Foreground(common.ColorAccent).Bold(true).Background(common.ColorBg)
	zuluStyle := lipgloss.NewStyle().Foreground(common.ColorCyan).Bold(true).Background(common.ColorBg)

	line1 := labelStyle.Render("DATE ") + valueStyle.Render(dateFmt) + labelStyle.Render(fmt.Sprintf(" J%03d", dayOfYear))
	line2 := labelStyle.Render("ZULU ") + zuluStyle.Render(timeFmt) + labelStyle.Render("Z")

	dateTimeBox := line1 + "\n" + line2
	boxWidth := lipgloss.Width(line1)

	// Build banner - logo content only with space above
	var leftLines []string

	// Empty line for spacing above
	leftLines = append(leftLines, "")

	// Logo content rows
	for _, line := range proxywatchBannerContent {
		leftLines = append(leftLines, logoStyle.Render(line))
	}

	leftBlock := strings.Join(leftLines, "\n")

	gap := w - proxywatchBannerW - boxWidth
	if gap < 2 {
		gap = 2
	}

	// Align date/time to top-right (no vertical padding)
	combined := lipgloss.JoinHorizontal(lipgloss.Top, leftBlock, bgSp(gap), dateTimeBox)

	var result []string
	for _, line := range strings.Split(combined, "\n") {
		if extra := w - lipgloss.Width(line); extra > 0 {
			line += bgSp(extra)
		}
		result = append(result, line)
	}
	return strings.Join(result, "\n")
}

// renderBottomBar draws the bottom bar: status context on the left, help hints
// on the right.
func (m DashboardModel) renderBottomBar(w int) string {
	line := bgSp(1) + dimText.Render("? help   q quit")
	if pad := w - lipgloss.Width(line); pad > 0 {
		line += bgSp(pad)
	}
	return line
}

// renderCollectProgress draws the thin ProxyHound collection progress line
// while a collection is active, else "".
func (m DashboardModel) renderCollectProgress(w int) string {
	if !m.app.CollectActive {
		return ""
	}
	total := m.app.CollectUntil.Sub(m.app.CollectStartedAt)
	elapsed := time.Since(m.app.CollectStartedAt)
	remaining := time.Until(m.app.CollectUntil).Round(time.Second)
	if remaining < 0 {
		remaining = 0
	}
	pct := 0.0
	if total > 0 {
		pct = float64(elapsed) / float64(total)
		if pct > 1 {
			pct = 1
		}
	}
	barW := w - 30
	if barW < 10 {
		barW = 10
	}
	filled := int(float64(barW) * pct)
	return sectionLabel.Render(" ProxyHound ") +
		statusPass.Render(strings.Repeat("━", filled)) +
		dimText.Render(strings.Repeat("─", barW-filled)) +
		dimText.Render(fmt.Sprintf(" %s remaining", remaining))
}

func (m DashboardModel) renderStatusBanners(w int) string {
	return ""
}

func (m DashboardModel) renderMultiHostSummary(w int) string {
	summaryLine := buildMultiHostSummary(m.app)
	titleLine := rightLabelStyle.Render(fmt.Sprintf("  HOST SUMMARY (%d hosts)", len(m.app.HostSummaries)))
	detail := mutedText.Render("    " + TruncateToWidth(summaryLine, max(10, w-8)))
	return titleLine + "\n" + detail
}

// ── Body ────────────────────────────────────────────────────────────────────

func (m DashboardModel) renderBody(w, bodyH int) string {
	// Both views are full-width tables with no surrounding box.
	if dashboardHostListMode(m.app) {
		return m.renderHostList(w, bodyH)
	}
	return m.renderProcessList(w, bodyH)
}

// ── Host list view ──────────────────────────────────────────────────────────

func (m DashboardModel) renderHostList(w, bodyH int) string {
	if len(m.app.HostSummaries) == 0 {
		return lgText.Render("No connected hosts yet.") + "\n" +
			lgMuted.Render("Start agents and wait for telemetry updates.")
	}

	if m.app.DashboardHostSelected < 0 || m.app.DashboardHostSelected >= len(m.app.HostSummaries) {
		m.app.DashboardHostSelected = 0
	}
	if strings.TrimSpace(m.app.DashboardHostKey) == "" {
		m.app.DashboardHostKey = m.app.HostSummaries[m.app.DashboardHostSelected].Host
	}
	for i := range m.app.HostSummaries {
		if strings.EqualFold(m.app.HostSummaries[i].Host, m.app.DashboardHostKey) {
			m.app.DashboardHostSelected = i
			break
		}
	}

	cols := hostColumns(w)
	maxRows := bodyH - 4 // top + header + rule + bottom border lines
	if maxRows < 1 {
		maxRows = 1
	}
	start := scrollStart(m.app.DashboardHostSelected, len(m.app.HostSummaries), maxRows)

	var rows [][]common.BorderedCell
	selInWindow := -1
	for row, i := 0, start; i < len(m.app.HostSummaries) && row < maxRows; i, row = i+1, row+1 {
		item := m.app.HostSummaries[i]
		if i == m.app.DashboardHostSelected {
			selInWindow = row
		}
		connected := strings.EqualFold(strings.TrimSpace(item.Status), "connected")

		seen := "now"
		if !connected && !item.LastSeen.IsZero() {
			seen = formatDashboardAge(max(0, int(time.Since(item.LastSeen).Seconds())))
		} else if !connected {
			seen = "-"
		}

		// Severity from the worst on-host threat: tunneling → Critical,
		// watchlist → High, otherwise Low. Disconnected hosts read "offline".
		sevKind, sevLabel := "low", "Low"
		switch {
		case !connected:
			sevKind, sevLabel = "off", "offline"
		case item.Tunneling > 0:
			sevKind, sevLabel = "critical", "Critical"
		case item.Watch > 0:
			sevKind, sevLabel = "high", "High"
		}

		var dim *lipgloss.Style
		sevStyle := severityCellStyle(sevKind)
		if sevKind == "off" {
			d := lgDim
			dim, sevStyle = &d, d
		}
		cell := func(t string) common.BorderedCell {
			return common.BorderedCell{Text: t, Style: dim}
		}
		rows = append(rows, []common.BorderedCell{
			{Text: sevLabel, Style: &sevStyle, KeepBg: sevKind == "critical"},
			cell(shared.DisplayHost(item.Host)),
			cell(item.Status),
			cell(seen),
			cell(fmt.Sprintf("%d", item.Processes)),
			cell(fmt.Sprintf("%d", item.Watch)),
			cell(fmt.Sprintf("%d", item.Tunneling)),
			cell(fmt.Sprintf("%d", item.Roles)),
		})
	}
	return common.RenderBorderedTable(w, cols, rows, selInWindow)
}

// hostColumns is the column layout for the multi-host HOST VIEW, with
// HOST expanded to consume the width left by the bordered-table chrome.
func hostColumns(w int) []common.Col {
	cols := []common.Col{
		{Title: "SEVERITY", Width: 8},
		{Title: "HOST", Width: 12}, // flex — index 1
		{Title: "STATUS", Width: 12},
		{Title: "SEEN", Width: 6, Right: true},
		{Title: "PROCESSES", Width: 9, Right: true},
		{Title: "WATCH", Width: 6, Right: true},
		{Title: "TUNNELING", Width: 9, Right: true},
		{Title: "ROLES", Width: 6, Right: true},
	}
	const hostIdx = 1
	const minHost = 8
	nonflex := 0
	for i, c := range cols {
		if i != hostIdx {
			nonflex += c.Width
		}
	}
	// Give HOST whatever the fixed columns leave, so the table always fits.
	cols[hostIdx].Width = max(minHost, w-common.BorderedChrome(len(cols))-nonflex)
	if cols[hostIdx].Width < 4 {
		cols[hostIdx].Width = 4
	}
	return cols
}

// ── Process list view ───────────────────────────────────────────────────────

func (m DashboardModel) renderProcessList(w, bodyH int) string {
	view := dashboardProcessCandidates(m.app)
	if len(view) == 0 {
		return lgText.Render("Nothing in the current view matches the active filter yet.") + "\n" +
			lgMuted.Render("Roles: "+safeRolePreset(m.app)) + "\n" +
			lgMuted.Render("Try waiting for the next refresh or widening the view with the role/sort menu (c).")
	}

	// Render in the exact order navigation uses (dashboardProcessCandidates
	// already applies the active sort preset). Re-sorting here would desync
	// the selection from the arrow-key navigation and make the cursor jump.
	selectedViewIdx := selectedDashboardProcessIndex(m.app, view)

	cols := dashboardColumns(w)
	maxRows := bodyH - 4 // top + header + rule + bottom border lines
	if maxRows < 1 {
		maxRows = 1
	}
	start := scrollStart(selectedViewIdx, len(view), maxRows)

	var rows [][]common.BorderedCell
	selInWindow := -1
	for row, i := 0, start; i < len(view) && row < maxRows; i, row = i+1, row+1 {
		if i == selectedViewIdx {
			selInWindow = row
		}
		rows = append(rows, dashboardRowCells(view[i]))
	}
	return common.RenderBorderedTable(w, cols, rows, selInWindow)
}

// scrollStart returns the first visible index for a windowed list so the
// selected item stays on-screen.
func scrollStart(selected, total, maxRows int) int {
	start := 0
	if selected >= maxRows {
		start = selected - maxRows + 1
	}
	if maxStart := max(0, total-maxRows); start > maxStart {
		start = maxStart
	}
	if start < 0 {
		start = 0
	}
	return start
}

// dashboardColumns returns the column layout, expanding PROCESS and
// DESTINATION to consume the width left over by the bordered-table chrome.
func dashboardColumns(w int) []common.Col {
	cols := []common.Col{
		{Title: "HOST", Width: 7},
		{Title: "PROCESS", Width: 12},     // flex — index 1
		{Title: "DESTINATION", Width: 20}, // flex — index 2
		{Title: "PID", Width: 6, Right: true},
		{Title: "USER", Width: 12},
		{Title: "AGE", Width: 6, Right: true},
		{Title: "PROTO", Width: 9},
		{Title: "ROLE", Width: 8},
		{Title: "STATUS", Width: 11},
	}
	const procIdx, destIdx = 1, 2
	const minProc, minDest = 12, 16
	nonflex := 0
	for i, c := range cols {
		if i != procIdx && i != destIdx {
			nonflex += c.Width
		}
	}
	// avail is the exact width the two flex columns may occupy so the whole
	// table fits the box; always split avail rather than hardcoding, or the
	// table overflows the terminal on narrow widths.
	avail := w - common.BorderedChrome(len(cols)) - nonflex
	if avail < 2 {
		avail = 2 // 1 cell each; only hit on unrealistically narrow terminals
	}
	var proc, dest int
	if avail >= minProc+minDest {
		proc = minProc + (avail-minProc-minDest)/3
		if proc > 28 {
			proc = 28
		}
		dest = avail - proc
	} else {
		// Too tight for both minimums: split the exact remaining width so the
		// table still fits the box rather than overflowing the terminal.
		proc = avail / 2
		dest = avail - proc
	}
	cols[procIdx].Width, cols[destIdx].Width = proc, dest
	return cols
}

// dashboardRowCells builds the ordered bordered cells for one candidate,
// matching dashboardColumns. The ROLE and STATE cells are colour-coded.
func dashboardRowCells(c shared.Candidate) []common.BorderedCell {
	roleFamily := normalizeDashboardRole(shared.RoleFamily(c.Role))
	roleLabel := displayRoleLabel(roleFamily)
	if shared.CandidateState(c) == "analyzing" {
		roleLabel = "-"
	}
	roleStyle := roleCellStyle(roleFamily)

	state := shared.CandidateStateDisplay(c)
	stateStyle := stateCellStyle(state)

	pid, user := "-", "-"
	if c.Proc != nil {
		if c.Proc.Pid > 0 {
			pid = fmt.Sprintf("%d", c.Proc.Pid)
		}
		if u := strings.TrimSpace(c.Proc.UserName); u != "" {
			// Show the last path component (drops NT AUTHORITY\ / DOMAIN\).
			if i := strings.LastIndex(u, "\\"); i >= 0 {
				u = u[i+1:]
			}
			user = u
		}
	}
	age := formatDashboardAge(dashboardCandidateAgeSeconds(c))

	return []common.BorderedCell{
		{Text: shared.DisplayHost(c.Host)},
		{Text: shared.DisplayProcessName(c.Proc)},
		{Text: dashboardDest(c)},
		{Text: pid},
		{Text: user},
		{Text: age},
		{Text: protoMixLabel(c)},
		{Text: roleLabel, Style: &roleStyle},
		{Text: state, Style: &stateStyle},
	}
}

// roleCellStyle colours the ROLE cell by role family: control channels red,
// pivots amber, tunnels gold, listeners sage, benign outbound neutral.
func roleCellStyle(family string) lipgloss.Style {
	base := lipgloss.NewStyle().Background(common.ColorBg)
	switch family {
	case "beacon":
		return base.Foreground(common.ColorAlert).Bold(true)
	case "pivot":
		return base.Foreground(common.ColorOrange).Bold(true)
	case "tunnel":
		return base.Foreground(common.ColorWarn).Bold(true)
	case "listener":
		return base.Foreground(common.ColorCyan)
	case "outbound":
		return base.Foreground(common.ColorText)
	default:
		return base.Foreground(common.ColorMuted)
	}
}

// stateCellStyle colours the STATUS cell using military-style indicators:
// ACTIVE (red), ALERT (amber), TRACKING/COLD (dim), NOMINAL (green).
func stateCellStyle(state string) lipgloss.Style {
	base := lipgloss.NewStyle().Background(common.ColorBg)
	switch {
	case strings.Contains(state, "ACTIVE"):
		return base.Foreground(common.ColorAlert).Bold(true)
	case strings.Contains(state, "ALERT"):
		return base.Foreground(common.ColorWarn).Bold(true)
	case strings.Contains(state, "TRACKING"), strings.Contains(state, "COLD"):
		return base.Foreground(common.ColorDim)
	case strings.Contains(state, "NOMINAL"):
		return base.Foreground(common.ColorCyan)
	default:
		return base.Foreground(common.ColorText)
	}
}

// scoreSeverity maps a 0–100 threat score to a severity label + kind.
func scoreSeverity(score int) (label, kind string) {
	switch {
	case score >= 80:
		return "CRITICAL", "critical"
	case score >= 60:
		return "HIGH", "high"
	case score >= 35:
		return "MEDIUM", "medium"
	default:
		return "LOW", "low"
	}
}

// severityColor returns just the foreground colour for a severity kind (for
// meters and inline severity text, where the filled critical pill is unwanted).
func severityColor(kind string) lipgloss.Color {
	switch kind {
	case "critical", "high":
		return common.ColorAlert
	case "medium":
		return common.ColorWarn
	default:
		return common.ColorCyan
	}
}

// severityCellStyle returns the colour for a SEVERITY cell. Critical is a
// filled pill (dark text on dusty red); the rest are coloured text.
func severityCellStyle(kind string) lipgloss.Style {
	switch kind {
	case "critical":
		return lipgloss.NewStyle().Foreground(common.ColorBg).Background(common.ColorAlert).Bold(true)
	case "high":
		return lipgloss.NewStyle().Foreground(common.ColorAlert).Bold(true).Background(common.ColorBg)
	case "medium":
		return lipgloss.NewStyle().Foreground(common.ColorWarn).Background(common.ColorBg)
	default: // low
		return lipgloss.NewStyle().Foreground(common.ColorDim).Background(common.ColorBg)
	}
}

// dashboardDest returns the primary destination for the row. It consults, in
// order: the confirmed control channel, a live outbound socket, raw-socket
// formatGridIP is now a no-op - returns IP as-is without grid notation
func formatGridIP(ip string) string {
	return ip
}

// remotes, a delegated-egress broker, then a local listen socket — so any
// candidate with observable network activity shows an address instead of "-".
func dashboardDest(c shared.Candidate) string {
	if c.ControlChannel != nil && c.ControlChannel.RemoteAddress != "" {
		return fmt.Sprintf("%s:%d", formatGridIP(c.ControlChannel.RemoteAddress), c.ControlChannel.RemotePort)
	}
	for _, cn := range c.Conns {
		if cn.RemoteAddress != "" {
			return fmt.Sprintf("%s:%d", formatGridIP(cn.RemoteAddress), cn.RemotePort)
		}
	}
	for _, rc := range c.RawConns {
		if r := strings.TrimSpace(rc.Remote); r != "" {
			// Parse IP:port and format
			if idx := strings.LastIndex(r, ":"); idx > 0 {
				return formatGridIP(r[:idx]) + r[idx:]
			}
			return r
		}
	}
	if c.DelegatedEgress && c.DelegatedOwner != "" {
		if c.DelegatedOwnerPID > 0 {
			return fmt.Sprintf("VIA %s(%d)", strings.ToUpper(c.DelegatedOwner), c.DelegatedOwnerPID)
		}
		return "VIA " + strings.ToUpper(c.DelegatedOwner)
	}
	for _, l := range c.Listeners {
		if l.LocalPort > 0 {
			addr := l.LocalAddress
			if addr == "" {
				addr = "*"
			} else {
				addr = formatGridIP(addr)
			}
			// No "listen" prefix — the ROLE column already shows "listener".
			return fmt.Sprintf("%s:%d", addr, l.LocalPort)
		}
	}
	return "-"
}

// protoMixLabel produces a compact protocol label for the dashboard's
// PROTO column. Resolution chain (strongest signal wins):
//
//	JA3S/ALPN cache  →  /etc/services lookup  →  hardcoded port table  →
//	process-capability hint  →  fallback ":port"
//
// Multiple distinct flows collapse to "mixed (N)". Internal RFC1918
// destinations show their port directly. Nothing connected returns
// "—".
func protoMixLabel(c shared.Candidate) string {
	type kv struct {
		label string
		count int
	}
	// PCAP-mode override: ssh-banner-* signals are stamped by the SSH
	// banner enricher when the actual SSH protocol bytes are observed
	// on a flow. They prove the protocol regardless of port. Operator-
	// confirmed FP 2026-05-04: adap.pcapng has sshd listening on port
	// 2049, and the wellKnownProtoName table maps 2049→NFS — the row
	// rendered "NFS" even though every flow carried SSH banners. The
	// signal-driven override fixes this for synthetic pcap PIDs where
	// the live-mode process-name check (sshd / libssh) doesn't apply.
	if pcapProtoFromSignals(c.Signals) == "SSH" {
		return "SSH"
	}
	// Process capability hint (libssh / libssl / etc.) trumps the
	// /etc/services lookup for non-well-known ports. Operator-confirmed
	// 2026-05-04: an sshd binary listening on port 2049 was getting
	// labeled "NFS" because /etc/services maps 2049 → nfs. The
	// process clearly speaks SSH (libssh loaded, name == sshd), so we
	// trust THAT over the port-number-only IANA mapping.
	procHint := processCapabilityProto(c)
	tally := make(map[string]int)
	for _, conn := range c.Conns {
		port := conn.RemotePort
		if port <= 0 {
			continue
		}
		label := ""
		// Curated well-known port table (includes 22=SSH, 443=HTTPS,
		// etc.) wins over /etc/services. wellKnownProtoName returns
		// "" when port isn't on the curated list, leaving ambiguous
		// ports for the procHint / services fallback.
		if label == "" {
			label = wellKnownProtoName(port)
		}
		// Process capability hint for AMBIGUOUS ports — port not in
		// the curated table, but the process clearly speaks the
		// protocol. Strips the trailing "?" since we have a port
		// number to anchor it.
		if label == "" && procHint != "" {
			label = strings.TrimSuffix(procHint, "?")
		}
		if label == "" {
			if svc := shared.ServiceForPort(port, "tcp"); svc != "" {
				label = strings.ToUpper(svc)
			}
		}
		if label == "" {
			label = fmt.Sprintf(":%d", port)
		}
		tally[label]++
	}
	// Listener side: surface listening port labels too, so a row with
	// a listener but no current connections still has something
	// useful in PROTO instead of "—".
	for _, l := range c.Listeners {
		if l.LocalPort <= 0 {
			continue
		}
		label := wellKnownProtoName(l.LocalPort)
		if label == "" {
			label = fmt.Sprintf(":%d", l.LocalPort)
		}
		tally[label]++
	}
	if len(tally) == 0 {
		// Capability-hint fallback from loaded libs / process name.
		if hint := processCapabilityProto(c); hint != "" {
			return hint
		}
		return "—"
	}
	if len(tally) == 1 {
		for k := range tally {
			return k
		}
	}
	// Collapse multi-protocol to "mixed (N)" so the column stays narrow.
	return fmt.Sprintf("mixed (%d)", len(tally))
}

// wellKnownProtoName maps a port number to a short protocol label.
// Returns "" when the port isn't on the small hardcoded list — caller
// falls through to the /etc/services lookup or to the bare ":port"
// form.
func wellKnownProtoName(port int) string {
	switch port {
	case 20, 21:
		return "FTP"
	case 22:
		return "SSH"
	case 23:
		return "TELNET"
	case 25, 587, 465:
		return "SMTP"
	case 53:
		return "DNS"
	case 67, 68:
		return "DHCP"
	case 80, 8080, 8000, 8008, 8888:
		return "HTTP"
	case 88:
		return "Kerberos"
	case 110, 995:
		return "POP3"
	case 119, 563:
		return "NNTP"
	case 123:
		return "NTP"
	case 135:
		return "RPC"
	case 137, 138, 139:
		return "NetBIOS"
	case 143, 993:
		return "IMAP"
	case 161, 162:
		return "SNMP"
	case 389, 636:
		return "LDAP"
	case 443, 8443:
		return "HTTPS"
	case 445:
		return "SMB"
	case 500, 4500:
		return "IPsec"
	case 514:
		return "syslog"
	case 873:
		return "rsync"
	case 1080:
		return "SOCKS"
	case 1194:
		return "OpenVPN"
	case 1433, 1434:
		return "MSSQL"
	case 1521:
		return "Oracle"
	case 1723:
		return "PPTP"
	case 1883, 8883:
		return "MQTT"
	case 2049:
		return "NFS"
	case 2375, 2376:
		return "Docker"
	case 3306:
		return "MySQL"
	case 3389:
		return "RDP"
	case 5060, 5061:
		return "SIP"
	case 5222, 5223:
		return "XMPP"
	case 5353:
		return "mDNS"
	case 5432:
		return "Postgres"
	case 5672, 5671:
		return "AMQP"
	case 5900:
		return "VNC"
	case 5985, 5986:
		return "WinRM"
	case 6379:
		return "Redis"
	case 6443:
		return "kube-API"
	case 8009:
		return "AJP13"
	case 8086:
		return "InfluxDB"
	case 9000, 9001:
		return "Sonar"
	case 9090:
		return "Prom"
	case 9092:
		return "Kafka"
	case 9200, 9300:
		return "Elastic"
	case 11211:
		return "memcache"
	case 27017:
		return "Mongo"
	}
	return ""
}

// pcapProtoFromSignals checks for protocol-confirming pcap signals
// stamped by the byte-content enrichers (e.g. ssh_enrich.go's
// ssh-banner-* family). These signals are *observations*, not guesses,
// so they outrank the port-number table. Returns "" when no
// confirming signal is present.
func pcapProtoFromSignals(signals []string) string {
	for _, s := range signals {
		if strings.HasPrefix(s, "ssh-banner-") {
			return "SSH"
		}
	}
	return ""
}

// processCapabilityProto guesses the protocol from the process's
// loaded libs + name when no flow / listener evidence is available.
// Returns a short capability hint suffixed with "?" so operators can
// see it's a guess, not an observation.
func processCapabilityProto(c shared.Candidate) string {
	if c.Proc == nil {
		return ""
	}
	// Process-name signal — `sshd` / `openssh` etc. talk SSH
	// regardless of the port they happen to listen on. Operator-
	// confirmed FP 2026-05-04: sshd on port 2049 was getting labeled
	// NFS because /etc/services maps 2049 to nfs.
	name := strings.ToLower(c.Proc.Name)
	switch {
	case strings.Contains(name, "sshd"), strings.HasPrefix(name, "ssh"):
		return "SSH?"
	}
	for _, lib := range c.Proc.LoadedLibs {
		l := strings.ToLower(lib)
		switch {
		case strings.Contains(l, "libssh"):
			return "SSH?"
		case strings.Contains(l, "libssl"), strings.Contains(l, "schannel"), strings.Contains(l, "winhttp"):
			return "TLS?"
		case strings.Contains(l, "libcurl"):
			return "HTTP?"
		}
	}
	return ""
}

// displayRoleLabel maps the canonical RoleFamily to the operator-
// facing label shown in any view's ROLE column. Operator-confirmed
// 2026-05-04: "Beacon" / "Pivot" / "Tunnel" read better than the
// internal "beacon" / "pivot" / "tunnel" terms.
// Used by the dashboard process view AND the PCAP findings table —
// any future role column should call this so labels stay consistent.
//
// Family names are unchanged in memory and on the wire — this is
// render-only. Callers handle the "analyzing" placeholder ("-")
// themselves; the function maps any non-displayed family back to
// itself so unknown roles aren't silently lost.
func displayRoleLabel(roleFamily string) string {
	switch roleFamily {
	case "beacon":
		return "Beacon"
	case "pivot":
		return "Pivot"
	case "tunnel":
		return "Tunnel"
	default:
		return roleFamily
	}
}

// renderWhitelistPanel renders the whitelist overlay panel for the dashboard.
func (m DashboardModel) renderWhitelistPanel(w int) string {
	items := m.app.WhitelistItems
	panelW := min(60, w-4)
	if panelW < 30 {
		panelW = 30
	}

	titleStyle := lgTextB
	textStyle := lgText
	dimStyle := lgDim

	var lines []string
	lines = append(lines, "")
	lines = append(lines, titleStyle.Render("  WHITELISTED PROCESSES"))
	lines = append(lines, dimStyle.Render("  Press W on a candidate to whitelist"))
	lines = append(lines, dimStyle.Render("  Press ENTER here to remove selected"))
	lines = append(lines, "")

	if len(items) == 0 {
		lines = append(lines, dimStyle.Render("  (no whitelisted items)"))
	} else {
		maxShow := 10
		sel := m.app.WhitelistSelected
		if sel < 0 {
			sel = 0
		}
		if sel >= len(items) {
			sel = len(items) - 1
		}

		start := 0
		if sel >= maxShow {
			start = sel - maxShow + 1
		}

		for i := start; i < len(items) && i < start+maxShow; i++ {
			entry := formatWhitelistEntry(items[i], panelW-6)
			prefix := "  "
			style := textStyle
			if i == sel {
				prefix = "> "
				style = titleStyle
			}
			lines = append(lines, style.Render(prefix+entry))
		}

		if len(items) > maxShow {
			lines = append(lines, dimStyle.Render(fmt.Sprintf("  ... %d total", len(items))))
		}
	}

	lines = append(lines, "")
	lines = append(lines, dimStyle.Render("  w close   ENTER remove   Esc close"))
	lines = append(lines, "")

	content := strings.Join(lines, "\n")
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("240")).
		Padding(0, 1).
		Width(panelW)
	return box.Render(content)
}
