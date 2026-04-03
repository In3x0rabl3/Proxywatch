package views

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"proxywatch/internal/shared"
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
	if w <= 0 || h <= 0 {
		return ""
	}

	var sections []string

	sections = append(sections, m.renderHeader(w))

	if banner := m.renderStatusBanners(w); banner != "" {
		sections = append(sections, banner)
	}

	if len(m.app.HostSummaries) > 1 {
		sections = append(sections, m.renderMultiHostSummary(w))
	}

	headerUsed := 0
	for _, s := range sections {
		headerUsed += lipgloss.Height(s)
	}
	bodyH := h - headerUsed
	if m.app.ShowQuitConfirm || m.app.LastError != "" {
		bodyH -= 2
	}
	if bodyH < 4 {
		bodyH = 4
	}
	sections = append(sections, m.renderBody(w, bodyH))

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

// ── Header ──────────────────────────────────────────────────────────────────

func (m DashboardModel) renderHeader(w int) string {
	utcValue := time.Now().UTC().Format(UTCTimeFormat)
	roleVal := safeRolePreset(m.app)
	refreshVal := m.app.RefreshInt.String()

	contentW := w - 2
	if contentW < 20 {
		contentW = 20
	}

	helpPlain := "? menu"
	utcPlain := "UTC: " + utcValue
	gap1 := max(1, contentW-len(helpPlain)-len(utcPlain))
	line1 := dimText.Render(helpPlain) + bgSp(gap1) +
		rightLabelStyle.Render("UTC: ") + sectionLabel.Render(utcValue)

	sortVal := m.app.SortPreset
	if sortVal == "" {
		sortVal = "default"
	}
	rolesPlain := "Roles: " + roleVal + "   Sort: " + sortVal + "   Refresh: " + refreshVal
	gap2 := max(0, contentW-len(rolesPlain))
	line2 := bgSp(gap2) +
		rightLabelStyle.Render("Roles: ") + sectionLabel.Render(roleVal) +
		rightLabelStyle.Render("   Sort: ") + sectionLabel.Render(sortVal) +
		rightLabelStyle.Render("   Refresh: ") + sectionLabel.Render(refreshVal)

	var extraLines []string
	if m.app.CalibrateAnalyzing {
		_ = dialSpinFrames
		frame := dialSpinFrame()
		extraLines = append(extraLines, sectionLabel.Render("  Calibration analyzing "+frame))
	} else if m.app.CalibrateActive {
		total := m.app.CalibrateUntil.Sub(m.app.CalibrateStartedAt)
		elapsed := time.Since(m.app.CalibrateStartedAt)
		remaining := time.Until(m.app.CalibrateUntil).Round(time.Second)
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
		barW := contentW - 30
		if barW < 10 {
			barW = 10
		}
		filled := int(float64(barW) * pct)
		bar := statusPass.Render(strings.Repeat("━", filled)) +
			dimText.Render(strings.Repeat("─", barW-filled))
		extraLines = append(extraLines,
			sectionLabel.Render(" Calibrating ")+bar+
				dimText.Render(fmt.Sprintf(" %s remaining", remaining)))
	}
	if m.app.SIEMGenerating {
		_ = dialSpinFrames
		frame := dialSpinFrame()
		extraLines = append(extraLines, sectionLabel.Render("  SIEM: Generating Detections "+frame))
	}
	if m.app.CollectActive {
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
		barW := contentW - 30
		if barW < 10 {
			barW = 10
		}
		filled := int(float64(barW) * pct)
		bar := statusPass.Render(strings.Repeat("━", filled)) +
			dimText.Render(strings.Repeat("─", barW-filled))
		extraLines = append(extraLines,
			sectionLabel.Render("  ProxyHound ")+bar+
				dimText.Render(fmt.Sprintf(" %s remaining", remaining)))
	}

	content := line1 + "\n" + line2
	headerH := 4
	for _, extra := range extraLines {
		content += "\n" + extra
		headerH++
	}

	return renderPanel(w, headerH, "Dashboard", "proxywatch", "", content)
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
	panelTitle := "PROCESS VIEW"
	if dashboardHostListMode(m.app) {
		panelTitle = "HOST VIEW"
	}

	var content string
	var posLabel string
	if dashboardHostListMode(m.app) {
		content = m.renderHostList(w, bodyH)
		posLabel = fmt.Sprintf("%d/%d", m.app.DashboardHostSelected+1, len(m.app.HostSummaries))
	} else {
		content = m.renderProcessList(w, bodyH)
		view := dashboardProcessCandidates(m.app)
		idx := selectedDashboardProcessIndex(m.app, view)
		posLabel = fmt.Sprintf("%d/%d", max(0, idx+1), len(view))
	}

	return renderPanel(w, bodyH, panelTitle, "", posLabel, content)
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

	const (
		statusW    = 12
		seenW      = 6
		processesW = 9
		watchW     = 5
		strongW    = 6
		rolesW     = 5
		activeW    = 6
	)
	fixedW := 6 + statusW + seenW + processesW + watchW + strongW + rolesW + activeW + 7*2
	hostNeed := 10
	for i := range m.app.HostSummaries {
		if n := len(strings.TrimSpace(m.app.HostSummaries[i].Host)); n > hostNeed {
			hostNeed = n
		}
	}
	hostW := max(5, min(hostNeed, max(5, w-2-fixedW)))

	header := fmt.Sprintf("  %-*s  %-*s  %-*s  %*s  %*s  %*s  %*s  %*s",
		hostW, "HOST",
		statusW, "STATUS",
		seenW, "SEEN",
		processesW, "PROCESSES",
		watchW, "WATCH",
		strongW, "STRONG",
		rolesW, "ROLES",
		activeW, "ACTIVE",
	)
	var lines []string
	lines = append(lines, lgTextB.Render(header))

	maxRows := bodyH - 3
	if maxRows < 1 {
		maxRows = 1
	}
	start := 0
	if m.app.DashboardHostSelected >= maxRows {
		start = m.app.DashboardHostSelected - maxRows + 1
	}
	maxStart := max(0, len(m.app.HostSummaries)-maxRows)
	if start > maxStart {
		start = maxStart
	}
	if start < 0 {
		start = 0
	}

	for row, i := 0, start; i < len(m.app.HostSummaries) && row < maxRows; i, row = i+1, row+1 {
		item := m.app.HostSummaries[i]
		sel := i == m.app.DashboardHostSelected
		connected := strings.EqualFold(strings.TrimSpace(item.Status), "connected")

		seen := "now"
		if !connected && !item.LastSeen.IsZero() {
			age := max(0, int(time.Since(item.LastSeen).Seconds()))
			seen = formatDashboardAge(age)
		} else if !connected {
			seen = "-"
		}

		prefix := " "
		prefixStyle := lgText
		hostStyle := lgText
		if sel {
			prefix = ">"
			prefixStyle = lgWatch
			hostStyle = lgTextB
		}

		statusStyle := lgWatch
		if !connected {
			statusStyle = lgAlert
		}

		gap := applySelectBg(bg(), sel)
		rowStr := applySelectBg(prefixStyle, sel).Render(prefix) + gap.Render(" ") +
			applySelectBg(hostStyle, sel).Render(fmt.Sprintf("%-*s", hostW, TruncateToWidth(item.Host, hostW))) + gap.Render("  ") +
			applySelectBg(statusStyle, sel).Render(fmt.Sprintf("%-*s", statusW, TruncateToWidth(item.Status, statusW))) + gap.Render("  ") +
			applySelectBg(lgDim, sel).Render(fmt.Sprintf("%-*s", seenW, TruncateToWidth(seen, seenW))) + gap.Render("  ") +
			applySelectBg(lgText, sel).Render(fmt.Sprintf("%*d", processesW, item.Processes)) + gap.Render("  ") +
			applySelectBg(lgWatch, sel).Render(fmt.Sprintf("%*d", watchW, item.Watch)) + gap.Render("  ") +
			applySelectBg(lgWarn, sel).Render(fmt.Sprintf("%*d", strongW, item.Strong)) + gap.Render("  ") +
			applySelectBg(lgCyanB, sel).Render(fmt.Sprintf("%*d", rolesW, item.Roles)) + gap.Render("  ") +
			applySelectBg(lgAlert, sel).Render(fmt.Sprintf("%*d", activeW, item.Active))

		if sel {
			rowStr = lgSelectBg.Width(w - 2).Render(rowStr)
		}

		lines = append(lines, rowStr)
	}

	return strings.Join(lines, "\n")
}

// ── Process list view ───────────────────────────────────────────────────────

func (m DashboardModel) renderProcessList(w, bodyH int) string {
	view := dashboardProcessCandidates(m.app)
	if len(view) == 0 {
		return lgText.Render("Nothing in the current view matches the active filter yet.") + "\n" +
			lgMuted.Render("Roles: "+safeRolePreset(m.app)) + "\n" +
			lgMuted.Render("Try waiting for the next refresh or widening the view with the role/sort menu (c).")
	}

	selectedViewIdx := selectedDashboardProcessIndex(m.app, view)

	const (
		pidW     = 7
		roleW    = 16
		ageW     = 5
		stateW   = 7
		minHostW = 5
		minProcW = 8
	)
	hostNeed := minHostW
	procNeed := minProcW
	for i := range view {
		host := shared.DisplayHost(view[i].Host)
		if len(host) > hostNeed {
			hostNeed = len(host)
		}
		name := shared.DisplayProcessName(view[i].Proc)
		if len(name) > procNeed {
			procNeed = len(name)
		}
	}
	base := 6 + pidW + roleW + ageW + stateW + 6*2
	avail := max(8, w-2-base)
	hostW := minHostW
	procW := minProcW
	if avail >= minHostW+minProcW {
		remaining := avail - (minHostW + minProcW)
		hostExtraNeed := max(0, hostNeed-minHostW)
		hostExtra := min(remaining, hostExtraNeed)
		hostW += hostExtra
		remaining -= hostExtra
		procExtraNeed := max(0, procNeed-minProcW)
		procExtra := min(remaining, procExtraNeed)
		procW += procExtra
	} else {
		procW = max(4, avail/2)
		hostW = max(4, avail-procW)
	}

	header := fmt.Sprintf("  %-*s  %-*s  %-*s  %-*s  %-*s  %-*s",
		hostW, "HOST",
		pidW, "PID",
		procW, "PROCESS",
		roleW, "ROLE",
		ageW, "AGE",
		stateW, "STATE",
	)
	var lines []string
	lines = append(lines, lgTextB.Render(header))

	maxRows := bodyH - 3
	if maxRows < 1 {
		maxRows = 1
	}
	start := 0
	if selectedViewIdx >= maxRows {
		start = selectedViewIdx - maxRows + 1
	}
	maxStart := max(0, len(view)-maxRows)
	if start > maxStart {
		start = maxStart
	}
	if start < 0 {
		start = 0
	}

	for row, i := 0, start; i < len(view) && row < maxRows; i, row = i+1, row+1 {
		c := view[i]
		host := shared.DisplayHost(c.Host)
		name := shared.DisplayProcessName(c.Proc)
		pid := 0
		if c.Proc != nil {
			pid = c.Proc.Pid
		}
		role := normalizeDashboardRole(c.Role)
		age := formatDashboardAge(dashboardCandidateAgeSeconds(c))
		state := shared.CandidateState(c)

		sel := i == selectedViewIdx

		prefix := " "
		prefixStyle := lgText
		hostStyle := lgText
		processStyle := lgText
		pidStyle := lgDim
		ageStyle := lgDim
		if sel {
			prefix = ">"
			prefixStyle = lgWatch
			hostStyle = lgTextB
			processStyle = lgTextB
			pidStyle = lgDimB
			ageStyle = lgDimB
		}

		gap := applySelectBg(bg(), sel)
		rowStr := applySelectBg(prefixStyle, sel).Render(prefix) + gap.Render(" ") +
			applySelectBg(hostStyle, sel).Render(fmt.Sprintf("%-*s", hostW, TruncateToWidth(host, hostW))) + gap.Render("  ") +
			applySelectBg(pidStyle, sel).Render(fmt.Sprintf("%-*s", pidW, TruncateToWidth(fmt.Sprintf("%d", pid), pidW))) + gap.Render("  ") +
			applySelectBg(processStyle, sel).Render(fmt.Sprintf("%-*s", procW, ClipToWidth(name, procW))) + gap.Render("  ") +
			applySelectBg(lgRoleStyle(role), sel).Render(fmt.Sprintf("%-*s", roleW, TruncateToWidth(role, roleW))) + gap.Render("  ") +
			applySelectBg(ageStyle, sel).Render(fmt.Sprintf("%-*s", ageW, TruncateToWidth(age, ageW))) + gap.Render("  ") +
			applySelectBg(lgStateStyle(state), sel).Render(fmt.Sprintf("%-*s", stateW, TruncateToWidth(state, stateW)))

		if sel {
			rowStr = lgSelectBg.Width(w - 2).Render(rowStr)
		}

		lines = append(lines, rowStr)
	}

	return strings.Join(lines, "\n")
}
