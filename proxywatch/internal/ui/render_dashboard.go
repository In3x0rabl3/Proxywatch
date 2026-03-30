package ui

import (
	"fmt"
	"strings"
	"time"

	"proxywatch/internal/shared"

	"github.com/gdamore/tcell/v2"
)

func DrawDashboard(app *shared.AppState) {
	s := app.Screen
	clearScreen(s)
	w, h := s.Size()

	headerH := 4
	drawPanel(s, 0, 0, w, headerH, "Dashboard", "proxywatch")
	PutStringStyle(s, 2, 1, "? menu", styleDim)
	utcLabel := "UTC: "
	utcValue := time.Now().UTC().Format(utcTimeFormat)
	utcLen := len(utcLabel) + len(utcValue)
	roleVal := safeRolePreset(app)
	refreshVal := app.RefreshInt.String()
	rolesLabel := "Roles: "
	refreshLabel := "   Refresh: "
	totalLen := len(rolesLabel) + len(roleVal) + len(refreshLabel) + len(refreshVal)
	blockWidth := max(utcLen, totalLen)
	blockStart := max(2, w-2-blockWidth)
	PutStringStyle(s, blockStart, 1, utcLabel, styleCyanB)
	PutStringStyle(s, blockStart+len(utcLabel), 1, utcValue, styleTextB)
	start := blockStart
	PutStringStyle(s, start, 2, rolesLabel, styleCyanB)
	start += len(rolesLabel)
	PutStringStyle(s, start, 2, roleVal, styleTextB)
	start += len(roleVal)
	PutStringStyle(s, start, 2, refreshLabel, styleCyanB)
	start += len(refreshLabel)
	PutStringStyle(s, start, 2, refreshVal, styleTextB)

	bodyY := headerH
	if app.CalibrateAnalyzing {
		PutStringStyle(s, 2, bodyY, TruncateToWidth("gpt analyzing...", w-4), styleTextB)
		bodyY++
	} else if app.CalibrateActive {
		remaining := time.Until(app.CalibrateUntil).Round(time.Second)
		if remaining < 0 {
			remaining = 0
		}
		PutStringStyle(s, 2, bodyY, TruncateToWidth("calibration collection in progress   "+remaining.String()+" remaining", w-4), styleAlertB)
		bodyY++
	} else if app.CalibrateStatusText != "" && time.Now().Before(app.CalibrateStatusUntil) {
		st := styleText
		if app.CalibrateStatusError {
			st = styleAlert
		}
		PutStringStyle(s, 2, bodyY, TruncateToWidth(app.CalibrateStatusText, w-4), st)
		bodyY++
	}
	if len(app.HostSummaries) > 1 {
		summaryLine := buildMultiHostSummary(app)
		titleLine := fmt.Sprintf("HOST SUMMARY (%d hosts)", len(app.HostSummaries))
		PutStringStyle(s, 2, bodyY, titleLine, styleCyanB)
		bodyY++
		PutStringStyle(s, 4, bodyY, TruncateToWidth(summaryLine, w-6), styleText)
		bodyY++
		bodyY++ // blank separator line
	}
	bodyH := h - bodyY
	if bodyH < 4 {
		return
	}
	panelTitle := "PROCESS VIEW"
	if dashboardHostListMode(app) {
		panelTitle = "HOST VIEW"
	}
	drawPanel(s, 0, bodyY, w, bodyH, panelTitle, "")
	if dashboardHostListMode(app) {
		drawDashboardHostView(app, bodyY, bodyH, w, h)
	} else {
		drawDashboardProcessView(app, bodyY, bodyH, w, h)
	}

	drawDashboardOverlays(app, w, h)
}

func buildMultiHostSummary(app *shared.AppState) string {
	// Count roles per host from current candidates.
	type hostRoles struct {
		total   int
		session int
		beacon  int
		tunnel  int
	}
	perHost := make(map[string]*hostRoles)
	for _, hs := range app.HostSummaries {
		perHost[strings.ToLower(strings.TrimSpace(hs.Host))] = &hostRoles{}
	}
	for _, c := range app.Candidates {
		key := strings.ToLower(strings.TrimSpace(c.Host))
		hr := perHost[key]
		if hr == nil {
			hr = &hostRoles{}
			perHost[key] = hr
		}
		hr.total++
		switch c.Role {
		case "session":
			hr.session++
		case "beacon":
			hr.beacon++
		case "tunnel":
			hr.tunnel++
		}
	}
	parts := make([]string, 0, len(app.HostSummaries))
	for _, hs := range app.HostSummaries {
		key := strings.ToLower(strings.TrimSpace(hs.Host))
		hr := perHost[key]
		count := 0
		if hr != nil {
			count = hr.total
		}
		entry := fmt.Sprintf("%s: %d processes", shared.DisplayHost(hs.Host), count)
		var roleParts []string
		if hr != nil {
			if hr.session > 0 {
				roleParts = append(roleParts, fmt.Sprintf("%d session", hr.session))
			}
			if hr.beacon > 0 {
				roleParts = append(roleParts, fmt.Sprintf("%d beacon", hr.beacon))
			}
			if hr.tunnel > 0 {
				roleParts = append(roleParts, fmt.Sprintf("%d tunnel", hr.tunnel))
			}
		}
		if len(roleParts) > 0 {
			entry += " (" + strings.Join(roleParts, ", ") + ")"
		}
		parts = append(parts, entry)
	}
	return strings.Join(parts, "  |  ")
}

func drawDashboardHostView(app *shared.AppState, bodyY, bodyH, w, h int) {
	s := app.Screen
	if len(app.HostSummaries) == 0 {
		PutStringStyle(s, 2, bodyY+1, "No connected hosts yet.", styleText)
		PutStringStyle(s, 2, bodyY+2, "Start agents and wait for telemetry updates.", styleMuted)
		PutStringStyle(s, max(2, w-8), h-1, "0/0", styleCyanB)
		return
	}

	if app.DashboardHostSelected < 0 || app.DashboardHostSelected >= len(app.HostSummaries) {
		app.DashboardHostSelected = 0
	}
	if strings.TrimSpace(app.DashboardHostKey) == "" {
		app.DashboardHostKey = app.HostSummaries[app.DashboardHostSelected].Host
	}
	for i := range app.HostSummaries {
		if strings.EqualFold(app.HostSummaries[i].Host, app.DashboardHostKey) {
			app.DashboardHostSelected = i
			break
		}
	}

	const (
		colPrefix  = 2
		colHost    = 4
		statusW    = 12
		seenW      = 6
		processesW = 9
		watchW     = 5
		strongW    = 6
		rolesW     = 5
		activeW    = 6
	)
	baseNoHost := colHost + 2 + statusW + 2 + seenW + 2 + processesW + 2 + watchW + 2 + strongW + 2 + rolesW + 2 + activeW
	hostAvail := max(5, w-2-baseNoHost)
	hostNeed := 10
	for i := range app.HostSummaries {
		if n := len(strings.TrimSpace(app.HostSummaries[i].Host)); n > hostNeed {
			hostNeed = n
		}
	}
	hostW := hostAvail
	if hostW > hostNeed {
		hostW = hostNeed
	}
	if hostW < 5 {
		hostW = 5
	}
	colStatus := colHost + hostW + 2
	colSeen := colStatus + statusW + 2
	colProcesses := colSeen + seenW + 2
	colWatch := colProcesses + processesW + 2
	colStrong := colWatch + watchW + 2
	colRoles := colStrong + strongW + 2
	colActive := colRoles + rolesW + 2

	PutStringStyle(s, colHost, bodyY+1, "HOST", styleTextB)
	PutStringStyle(s, colStatus, bodyY+1, "STATUS", styleTextB)
	PutStringStyle(s, colSeen, bodyY+1, "SEEN", styleTextB)
	PutStringStyle(s, colProcesses, bodyY+1, "PROCESSES", styleTextB)
	PutStringStyle(s, colWatch, bodyY+1, "WATCH", styleTextB)
	PutStringStyle(s, colStrong, bodyY+1, "STRONG", styleTextB)
	PutStringStyle(s, colRoles, bodyY+1, "ROLES", styleTextB)
	PutStringStyle(s, colActive, bodyY+1, "ACTIVE", styleTextB)

	maxRows := bodyH - 4
	if maxRows < 1 {
		PutStringStyle(s, max(2, w-8), h-1, fmt.Sprintf("%d/%d", app.DashboardHostSelected+1, len(app.HostSummaries)), styleCyanB)
		return
	}
	start := 0
	if app.DashboardHostSelected >= maxRows {
		start = app.DashboardHostSelected - maxRows + 1
	}
	maxStart := max(0, len(app.HostSummaries)-maxRows)
	if start > maxStart {
		start = maxStart
	}
	if start < 0 {
		start = 0
	}
	for row, i := 0, start; i < len(app.HostSummaries) && row < maxRows; i, row = i+1, row+1 {
		item := app.HostSummaries[i]
		rowY := bodyY + 2 + row
		rowSelected := i == app.DashboardHostSelected
		prefix := " "
		prefixStyle := styleText
		hostStyle := styleText
		if rowSelected {
			prefix = ">"
			prefixStyle = styleWatch
			hostStyle = styleTextB
		}
		fillSelectedRowBar(s, rowY, 2, w-3, rowSelected)

		connected := strings.EqualFold(strings.TrimSpace(item.Status), "connected")
		seen := "now"
		if !connected && !item.LastSeen.IsZero() {
			age := max(0, int(time.Since(item.LastSeen).Seconds()))
			seen = formatDashboardAge(age)
		} else if !connected {
			seen = "-"
		}

		PutStringStyle(s, colPrefix, rowY, prefix, applySelectedRowStyle(prefixStyle, rowSelected))
		PutStringStyle(s, colHost, rowY, fmt.Sprintf("%-*s", hostW, TruncateToWidth(item.Host, hostW)), applySelectedRowStyle(hostStyle, rowSelected))
		statusStyle := styleWatch
		if !connected {
			statusStyle = styleAlertB
		}
		PutStringStyle(s, colStatus, rowY, fmt.Sprintf("%-*s", statusW, TruncateToWidth(item.Status, statusW)), applySelectedRowStyle(statusStyle, rowSelected))
		PutStringStyle(s, colSeen, rowY, fmt.Sprintf("%-*s", seenW, TruncateToWidth(seen, seenW)), applySelectedRowStyle(styleDim, rowSelected))
		PutStringStyle(s, colProcesses, rowY, fmt.Sprintf("%*d", processesW, item.Processes), applySelectedRowStyle(styleText, rowSelected))
		PutStringStyle(s, colWatch, rowY, fmt.Sprintf("%*d", watchW, item.Watch), applySelectedRowStyle(styleWatch, rowSelected))
		PutStringStyle(s, colStrong, rowY, fmt.Sprintf("%*d", strongW, item.Strong), applySelectedRowStyle(styleWarn, rowSelected))
		PutStringStyle(s, colRoles, rowY, fmt.Sprintf("%*d", rolesW, item.Roles), applySelectedRowStyle(styleCyanB, rowSelected))
		PutStringStyle(s, colActive, rowY, fmt.Sprintf("%*d", activeW, item.Active), applySelectedRowStyle(styleAlertB, rowSelected))
	}
	PutStringStyle(s, max(2, w-8), h-1, fmt.Sprintf("%d/%d", app.DashboardHostSelected+1, len(app.HostSummaries)), styleCyanB)
}

func drawDashboardProcessView(app *shared.AppState, bodyY, bodyH, w, h int) {
	s := app.Screen
	view := dashboardProcessCandidates(app)
	if len(view) == 0 {
		PutStringStyle(s, 2, bodyY+1, "Nothing in the current view matches the active filter yet.", styleText)
		PutStringStyle(s, 2, bodyY+2, "Roles: "+safeRolePreset(app), styleMuted)
		PutStringStyle(s, 2, bodyY+3, "Try waiting for the next refresh or widening the view with the role/sort menu (c).", styleMuted)
		PutStringStyle(s, max(2, w-8), h-1, "0/0", styleCyanB)
		return
	}

	selectedViewIdx := selectedDashboardProcessIndex(app, view)

	// Adaptive column grid so HOST can display full names when terminal width allows.
	const (
		colPrefix = 2
		colHost   = 4
		pidW      = 7
		roleW     = 10
		ageW      = 5
		stateW    = 7
		minHostW  = 5
		minProcW  = 8
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
	base := colHost + 2 + pidW + 2 + 2 + roleW + 2 + ageW + 2 + stateW
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
	colPID := colHost + hostW + 2
	colProc := colPID + pidW + 2
	colRole := colProc + procW + 2
	colAge := colRole + roleW + 2
	colState := colAge + ageW + 2
	PutStringStyle(s, colHost, bodyY+1, "HOST", styleTextB)
	PutStringStyle(s, colPID, bodyY+1, "PID", styleTextB)
	PutStringStyle(s, colProc, bodyY+1, "PROCESS", styleTextB)
	PutStringStyle(s, colRole, bodyY+1, "ROLE", styleTextB)
	PutStringStyle(s, colAge, bodyY+1, "AGE", styleTextB)
	PutStringStyle(s, colState, bodyY+1, "STATE", styleTextB)
	maxRows := bodyH - 4
	if maxRows < 1 {
		PutStringStyle(s, max(2, w-8), h-1, fmt.Sprintf("%d/%d", max(0, selectedViewIdx+1), len(view)), styleCyanB)
		return
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
		rowY := bodyY + 2 + row
		rowSelected := i == selectedViewIdx
		prefix := " "
		prefixStyle := styleText
		hostStyle := styleText
		processStyle := styleText
		pidStyle := styleDim
		ageStyle := styleDim
		if rowSelected {
			prefix = ">"
			prefixStyle = styleWatch
			hostStyle = styleTextB
			processStyle = styleTextB
			pidStyle = styleDimB
			ageStyle = styleDimB
		}
		fillSelectedRowBar(s, rowY, 2, w-3, rowSelected)
		PutStringStyle(s, colPrefix, rowY, prefix, applySelectedRowStyle(prefixStyle, rowSelected))
		PutStringStyle(s, colHost, rowY, fmt.Sprintf("%-*s", hostW, TruncateToWidth(host, hostW)), applySelectedRowStyle(hostStyle, rowSelected))
		PutStringStyle(s, colPID, rowY, fmt.Sprintf("%-*s", pidW, TruncateToWidth(fmt.Sprintf("%d", pid), pidW)), applySelectedRowStyle(pidStyle, rowSelected))
		PutStringStyle(s, colProc, rowY, fmt.Sprintf("%-*s", procW, ClipToWidth(name, procW)), applySelectedRowStyle(processStyle, rowSelected))
		PutStringStyle(s, colRole, rowY, fmt.Sprintf("%-*s", roleW, TruncateToWidth(role, roleW)), applySelectedRowStyle(roleStyle(role), rowSelected))
		PutStringStyle(s, colAge, rowY, fmt.Sprintf("%-*s", ageW, TruncateToWidth(age, ageW)), applySelectedRowStyle(ageStyle, rowSelected))
		PutStringStyle(s, colState, rowY, fmt.Sprintf("%-*s", stateW, TruncateToWidth(state, stateW)), applySelectedRowStyle(stateStyle(state), rowSelected))
	}
	PutStringStyle(s, max(2, w-8), h-1, fmt.Sprintf("%d/%d", max(0, selectedViewIdx+1), len(view)), styleCyanB)
}

func drawDashboardOverlays(app *shared.AppState, w, h int) {
	if app.ShowHelp {
		help := dashboardMenuHelpOptions()
		drawMenuPanel(app.Screen, w, h, "Dashboard Menu", help, clampIndex(app.HelpMenuIndex, len(help)), "")
	}
	if app.ShowRoleMenu {
		opts := roleSortMenuLabels()
		drawMenuPanel(app.Screen, w, h, "Roles + Sort", opts, clampIndex(app.RoleMenuIndex, len(opts)), "Enter apply   f role/sort menu   Esc close")
	}
	if app.ShowRefreshMenu {
		opts := refreshPresetOptions()
		drawMenuPanel(app.Screen, w, h, "Refresh Rate", opts, clampIndex(app.RefreshMenuIndex, len(opts)), "Enter apply   Esc close")
	}
}

// --- inspector view (merged from render_inspector.go) ---

func DrawInspector(app *shared.AppState) {
	s := app.Screen
	clearScreen(s)

	w, h := s.Size()
	const headerH = 3
	drawPanel(s, 0, 0, w, headerH, "Inspector", "proxywatch")
	PutStringStyle(s, 2, 1, "? menu   esc dashboard   q quit", styleDim)

	var cand *shared.Candidate
	for i := range app.Candidates {
		if shared.CandidateKey(app.Candidates[i]) == app.InspectKey {
			cand = &app.Candidates[i]
			break
		}
	}
	if cand == nil {
		PutStringStyle(s, 2, 2, "Process no longer present. Press ESC.", styleAlert)
		return
	}

	role := normalizeDashboardRole(cand.Role)
	rs := roleStyle(role)
	state := "watch"
	if cand.ActiveProxying {
		state = "active"
	} else if cand.StrongEvidence {
		state = "strong"
	}
	ss := stateStyle(state)

	line1 := "UTC: " + time.Now().UTC().Format(utcTimeFormat)
	blockWidth := len(line1)
	blockX := max(2, w-2-blockWidth)

	PutStringStyle(s, blockX, 1, "UTC: ", styleCyanB)
	PutStringStyle(s, blockX+5, 1, time.Now().UTC().Format(utcTimeFormat), styleTextB)

	bodyY := headerH
	bodyH := h - bodyY
	if bodyH < 6 {
		return
	}
	name := "(unknown)"
	pid := 0
	if cand.Proc != nil {
		name = shared.DisplayProcessName(cand.Proc)
		pid = cand.Proc.Pid
	}
	drawPanel(s, 0, bodyY, w, bodyH, "PROCESS DETAILS", "")
	contentTop := bodyY + 1
	contentBottom := bodyY + bodyH - 2
	if contentBottom < contentTop {
		return
	}
	if app.InspectScroll < 0 {
		app.InspectScroll = 0
	}
	visibleRows := contentBottom - contentTop + 1
	putContent := func(x, row int, text string, st tcell.Style) {
		sy := contentTop + row - app.InspectScroll
		if sy < contentTop || sy > contentBottom || x > w-2 {
			return
		}
		PutStringStyle(s, x, sy, TruncateToWidth(text, w-x-2), st)
	}
	scopeTextStyle := func(scope string) tcell.Style {
		switch strings.ToLower(strings.TrimSpace(scope)) {
		case "external":
			return styleWarn
		default:
			return styleMuted
		}
	}
	connectionStateStyle := func(state string) tcell.Style {
		switch strings.ToUpper(strings.TrimSpace(state)) {
		case "ESTABLISHED", "LISTEN":
			return styleTextB
		case "SYN_SENT", "SYN_RECV", "CLOSE_WAIT", "TIME_WAIT", "FIN_WAIT1", "FIN_WAIT2":
			return styleMuted
		case "UNKNOWN", "":
			return styleDim
		default:
			return styleText
		}
	}
	formatIO := func(read, write, other uint64, rate bool) string {
		formatMetric := FormatBytes
		if rate {
			formatMetric = FormatBytesPerSec
		}
		total := read + write + other
		s := formatMetric(total)
		if total > 0 {
			parts := make([]string, 0, 3)
			if read > 0 {
				parts = append(parts, "R "+formatMetric(read))
			}
			if write > 0 {
				parts = append(parts, "W "+formatMetric(write))
			}
			if other > 0 {
				parts = append(parts, "O "+formatMetric(other))
			}
			if len(parts) > 0 {
				s += "  (" + strings.Join(parts, "  ") + ")"
			}
		}
		return s
	}

	host := shared.DisplayHost(cand.Host)
	age := "0s"
	ageSeconds := dashboardCandidateAgeSeconds(*cand)
	if ageSeconds > 0 {
		age = (time.Duration(ageSeconds) * time.Second).Round(time.Second).String()
	}
	path := "(unknown)"
	user := "(unknown)"
	parentPID := "(unknown)"
	integrity := "(unknown)"
	var ioRead, ioWrite, ioOther uint64
	var ioReadRate, ioWriteRate, ioOtherRate uint64
	if cand.Proc != nil {
		if strings.TrimSpace(cand.Proc.ExePath) != "" {
			path = cand.Proc.ExePath
		}
		if strings.TrimSpace(cand.Proc.UserName) != "" {
			user = cand.Proc.UserName
		}
		if cand.Proc.ParentPid > 0 {
			parentPID = fmt.Sprintf("%d", cand.Proc.ParentPid)
		}
		if strings.TrimSpace(cand.Proc.Integrity) != "" {
			integrity = cand.Proc.Integrity
		}
		ioRead = cand.Proc.IOReadBytes
		ioWrite = cand.Proc.IOWriteBytes
		ioOther = cand.Proc.IOOtherBytes
		ioReadRate = cand.Proc.IOReadBps
		ioWriteRate = cand.Proc.IOWriteBps
		ioOtherRate = cand.Proc.IOOtherBps
	}
	established := 0
	for _, cn := range cand.Conns {
		if cn.State == "ESTABLISHED" {
			established++
		}
	}

	row := 0
	sectionStarts := make([]int, 0, 8)
	vx := 11 // value column start

	// ── Header ──────────────────────────────────────────────
	sectionStarts = append(sectionStarts, row)
	putContent(2, row, "Name:", styleMuted)
	putContent(vx, row, name, styleTextB)
	row++
	putContent(2, row, "Path:", styleMuted)
	putContent(vx, row, path, styleMuted)
	row++
	// Command line (truncated to available width).
	if cand.Proc != nil && strings.TrimSpace(cand.Proc.CmdLine) != "" {
		cmdLine := strings.TrimSpace(cand.Proc.CmdLine)
		putContent(2, row, "Cmd:", styleMuted)
		putContent(vx, row, cmdLine, styleMuted)
		row++
	}
	// Company/publisher (Windows).
	if cand.Proc != nil && strings.TrimSpace(cand.Proc.Company) != "" {
		putContent(2, row, "Vendor:", styleMuted)
		putContent(vx, row, strings.TrimSpace(cand.Proc.Company), styleTextB)
		row++
	}
	putContent(2, row, "Role:", styleMuted)
	putContent(vx, row, role, rs)
	row++
	putContent(2, row, "State:", styleMuted)
	putContent(vx, row, state, ss)
	row++
	sinceLabel := fmt.Sprintf("%ds at current role", cand.SeenSeconds)
	putContent(2, row, "Since:", styleMuted)
	putContent(vx, row, sinceLabel, styleText)
	row += 2

	// ── Process ─────────────────────────────────────────────
	sectionStarts = append(sectionStarts, row)
	col2 := max(24, w/3)
	putContent(2, row, "PID:", styleMuted)
	putContent(vx, row, fmt.Sprintf("%d", pid), styleTextB)
	putContent(col2, row, "Host:", styleMuted)
	putContent(col2+vx-2, row, host, styleTextB)
	row++
	putContent(2, row, "User:", styleMuted)
	putContent(vx, row, user, styleTextB)
	putContent(col2, row, "Integrity:", styleMuted)
	putContent(col2+vx-2, row, integrity, styleTextB)
	row++
	putContent(2, row, "Parent:", styleMuted)
	parentLabel := parentPID
	parentNavigable := false
	if cand.Proc != nil && cand.Proc.ParentPid > 0 {
		for _, pc := range app.Candidates {
			if pc.Proc != nil && pc.Proc.Pid == cand.Proc.ParentPid {
				parentNavigable = true
				break
			}
		}
	}
	if parentNavigable {
		parentLabel += "  (press p to inspect parent)"
	}
	putContent(vx, row, parentLabel, styleTextB)
	putContent(col2, row, "Age:", styleMuted)
	putContent(col2+vx-2, row, age, styleTextB)
	row += 2

	// ── Traffic ─────────────────────────────────────────────
	sectionStarts = append(sectionStarts, row)
	putContent(2, row, "TCP:", styleMuted)
	putContent(vx, row, fmt.Sprintf("%d in  /  %d out  (%d established)", cand.InboundTotal, cand.OutTotal, established), styleTextB)
	row++
	putContent(2, row, "UDP:", styleMuted)
	putContent(vx, row, fmt.Sprintf("%d listeners", len(cand.UDPListeners)), styleTextB)
	row++
	putContent(2, row, "IO:", styleMuted)
	putContent(vx, row, formatIO(ioRead, ioWrite, ioOther, false), styleTextB)
	row++
	if ioReadRate+ioWriteRate+ioOtherRate > 0 {
		putContent(2, row, "Rate:", styleMuted)
		putContent(vx, row, formatIO(ioReadRate, ioWriteRate, ioOtherRate, true), styleTextB)
		row++
	}
	// Listener ports.
	if len(cand.Listeners) > 0 {
		ports := make([]string, 0, len(cand.Listeners))
		seen := make(map[int]bool)
		for _, l := range cand.Listeners {
			if l.LocalPort > 0 && !seen[l.LocalPort] {
				seen[l.LocalPort] = true
				scope := "local"
				if shared.IsWildcardIP(l.LocalAddress) {
					scope = "any"
				}
				ports = append(ports, fmt.Sprintf("%d/%s", l.LocalPort, scope))
			}
		}
		if len(ports) > 0 {
			putContent(2, row, "Listen:", styleMuted)
			putContent(vx, row, strings.Join(ports, ", "), styleTextB)
			row++
		}
	}
	// Delegated egress.
	if cand.DelegatedEgress {
		putContent(2, row, "Broker:", styleMuted)
		owner := cand.DelegatedOwner
		if owner == "" {
			owner = "(unknown)"
		}
		label := owner
		if cand.DelegatedOwnerPID > 0 {
			label = fmt.Sprintf("%s (pid %d)", owner, cand.DelegatedOwnerPID)
		}
		if cand.DelegatedStrong {
			label += "  [strong]"
		}
		putContent(vx, row, label, styleWarn)
		row++
	}
	orgs, pending, _ := inspectorExternalOrgs(cand)
	if len(orgs) > 0 {
		for i, org := range orgs {
			if i == 0 {
				putContent(2, row, "ASN:", styleMuted)
			}
			putContent(vx, row, org, styleTextB)
			row++
		}
	} else if pending > 0 {
		putContent(2, row, "ASN:", styleMuted)
		putContent(vx, row, fmt.Sprintf("resolving %d...", pending), styleDim)
		row++
	}
	// Loaded libraries (notable DLLs / shared objects).
	if cand.Proc != nil && len(cand.Proc.LoadedLibs) > 0 {
		libs := cand.Proc.LoadedLibs
		if len(libs) > 5 {
			libs = libs[:5]
		}
		putContent(2, row, "Libs:", styleMuted)
		putContent(vx, row, strings.Join(libs, ", "), styleText)
		row++
	}
	row++

	// ── Analysis ────────────────────────────────────────────
	sectionStarts = append(sectionStarts, row)
	if cand.ControlChannel != nil {
		cn := cand.ControlChannel
		scope := "external"
		scopeSt := styleWarn
		if shared.IsInternalIP(cn.RemoteAddress) {
			scope = "internal"
			scopeSt = styleCyan
		}
		putContent(2, row, "Control:", styleWarn)
		putContent(vx, row, fmt.Sprintf("%s:%d", cn.RemoteAddress, cn.RemotePort), styleTextB)
		row++
		putContent(vx, row, fmt.Sprintf("%s  |  %ds  |  %s", cn.State, cand.ControlDurationSeconds, scope), scopeSt)
		row++
	}
	flowParts := make([]string, 0, 4)
	if cand.OutInternal > 0 {
		flowParts = append(flowParts, fmt.Sprintf("%d internal", cand.OutInternal))
	}
	if cand.OutExternal > 0 {
		flowParts = append(flowParts, fmt.Sprintf("%d external", cand.OutExternal))
	}
	if cand.OutLoopback > 0 {
		flowParts = append(flowParts, fmt.Sprintf("%d loopback", cand.OutLoopback))
	}
	if cand.InboundTotal > 0 {
		flowParts = append(flowParts, fmt.Sprintf("%d inbound", cand.InboundTotal))
	}
	if len(flowParts) > 0 {
		putContent(2, row, "Flows:", styleMuted)
		putContent(vx, row, strings.Join(flowParts, ",  "), styleTextB)
		row++
	}
	if cand.OutLongLived > 0 || cand.OutShortLived > 0 {
		putContent(2, row, "Duration:", styleMuted)
		putContent(vx, row, fmt.Sprintf("%d long-lived,  %d short-lived", cand.OutLongLived, cand.OutShortLived), styleTextB)
		row++
	}
	if cand.TrafficVerified {
		putContent(2, row, "Verified:", styleMuted)
		putContent(vx, row, "matches learned baseline (de-emphasized)", styleDim)
		row++
	}
	row++

	// ── Reasons ─────────────────────────────────────────────
	if len(cand.Reasons) > 0 {
		sectionStarts = append(sectionStarts, row)
		putContent(2, row, "Reasons:", styleWarn)
		row++
		for _, reason := range cand.Reasons {
			putContent(4, row, "- "+reason, styleTextB)
			row++
		}
		row++
	}

	// Deduplicate TCP connections before rendering the CONNECTIONS section
	// so we can decide whether to group.
	type connGroup struct {
		remote string
		state  string
		scope  string
		count  int
	}
	seen := make(map[string]struct{})
	var dedupConns []shared.ConnectionInfo
	for _, cn := range cand.Conns {
		scope := ""
		if cn.RemoteAddress != "" && !shared.IsWildcardIP(cn.RemoteAddress) && !shared.IsLoopbackIP(cn.RemoteAddress) {
			if shared.IsInternalIP(cn.RemoteAddress) {
				scope = "internal"
			} else {
				scope = "external"
			}
		}
		local := fmt.Sprintf("%s:%d", cn.LocalAddress, cn.LocalPort)
		remote := fmt.Sprintf("-> %s:%d", cn.RemoteAddress, cn.RemotePort)
		key := fmt.Sprintf("tcp|%s|%s|%s|%s", local, remote, cn.State, scope)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		dedupConns = append(dedupConns, cn)
	}
	groupedConns := len(dedupConns) > 3

	row++
	sectionStarts = append(sectionStarts, row)
	putContent(2, row, "CONNECTIONS", styleAccent)
	row++
	const (
		colProto  = 3
		colLocal  = 9
		colRemote = 35
		colState  = 60
		colScope  = 72
	)
	putContent(colProto, row, "Proto", styleTextB)
	if groupedConns {
		putContent(colLocal, row, "Remote", styleTextB)
		putContent(colRemote, row, "Count", styleTextB)
	} else {
		putContent(colLocal, row, "Local", styleTextB)
		putContent(colRemote, row, "Remote", styleTextB)
	}
	putContent(colState, row, "State", styleTextB)
	putContent(colScope, row, "Scope", styleTextB)
	row++
	putContent(colProto, row, "-----", styleDim)
	putContent(colLocal, row, "----------------------", styleDim)
	putContent(colRemote, row, "----------------------", styleDim)
	putContent(colState, row, "---------", styleDim)
	putContent(colScope, row, "-------", styleDim)
	row++

	if groupedConns {
		// Grouped mode: aggregate by (remote address:port, state, scope).
		groupOrder := make([]string, 0, len(dedupConns))
		groupMap := make(map[string]*connGroup, len(dedupConns))
		for _, cn := range dedupConns {
			scope := ""
			if cn.RemoteAddress != "" && !shared.IsWildcardIP(cn.RemoteAddress) && !shared.IsLoopbackIP(cn.RemoteAddress) {
				if shared.IsInternalIP(cn.RemoteAddress) {
					scope = "internal"
				} else {
					scope = "external"
				}
			}
			remote := fmt.Sprintf("%s:%d", cn.RemoteAddress, cn.RemotePort)
			gk := fmt.Sprintf("%s|%s|%s", remote, cn.State, scope)
			if g, ok := groupMap[gk]; ok {
				g.count++
			} else {
				groupMap[gk] = &connGroup{remote: remote, state: cn.State, scope: scope, count: 1}
				groupOrder = append(groupOrder, gk)
			}
		}
		for _, gk := range groupOrder {
			g := groupMap[gk]
			countLabel := fmt.Sprintf("%d connections", g.count)
			if g.count == 1 {
				countLabel = "1 connection"
			}
			putContent(colProto, row, "TCP", styleTextB)
			putContent(colLocal, row, g.remote, styleDimB)
			putContent(colRemote, row, countLabel, styleText)
			putContent(colState, row, g.state, connectionStateStyle(g.state))
			putContent(colScope, row, g.scope, scopeTextStyle(g.scope))
			row++
		}
	} else {
		// Individual mode: show each connection as a separate row.
		for _, cn := range dedupConns {
			scope := ""
			if cn.RemoteAddress != "" && !shared.IsWildcardIP(cn.RemoteAddress) && !shared.IsLoopbackIP(cn.RemoteAddress) {
				if shared.IsInternalIP(cn.RemoteAddress) {
					scope = "internal"
				} else {
					scope = "external"
				}
			}
			local := fmt.Sprintf("%s:%d", cn.LocalAddress, cn.LocalPort)
			remote := fmt.Sprintf("-> %s:%d", cn.RemoteAddress, cn.RemotePort)
			putContent(colProto, row, "TCP", styleTextB)
			putContent(colLocal, row, local, styleDimB)
			putContent(colRemote, row, remote, styleText)
			putContent(colState, row, cn.State, connectionStateStyle(cn.State))
			putContent(colScope, row, scope, scopeTextStyle(scope))
			row++
		}
	}
	for _, ul := range cand.UDPListeners {
		local := fmt.Sprintf("%s:%d", ul.LocalAddress, ul.LocalPort)
		scope := shared.ScopeLabelForLocalAddress(ul.LocalAddress)
		key := fmt.Sprintf("udp|%s|%s", local, scope)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		putContent(colProto, row, "UDP", styleTextB)
		putContent(colLocal, row, local, styleDimB)
		putContent(colRemote, row, "*:*", styleDim)
		putContent(colState, row, "LISTEN", connectionStateStyle("LISTEN"))
		putContent(colScope, row, scope, scopeTextStyle(scope))
		row++
	}

	totalRows := row + 1
	maxScroll := totalRows - visibleRows
	if maxScroll < 0 {
		maxScroll = 0
	}
	if app.InspectScroll > maxScroll {
		app.InspectScroll = maxScroll
	}
	app.InspectMaxScroll = maxScroll
	filteredStarts := make([]int, 0, len(sectionStarts))
	last := -1
	for _, start := range sectionStarts {
		if start < 0 {
			continue
		}
		if start > maxScroll {
			start = maxScroll
		}
		if start == last {
			continue
		}
		filteredStarts = append(filteredStarts, start)
		last = start
	}
	app.InspectSectionStarts = filteredStarts
	if maxScroll > 0 {
		PutStringStyle(s, max(2, w-12), h-1, fmt.Sprintf("%d/%d", app.InspectScroll, maxScroll), styleCyan)
	}

	// Bottom status line for actions/errors.
	if app.LastError != "" && h >= 2 {
		PutStringStyle(s, 2, h-2, TruncateToWidth(app.LastError, w-4), styleAlert)
	}
	if app.ConfirmKill && app.ConfirmKillKey == app.InspectKey && time.Now().Before(app.ConfirmKillDeadline) && h >= 2 {
		msg := fmt.Sprintf("Confirm kill: press k again or y within %s", app.ConfirmKillTimeout)
		PutStringStyle(s, 2, h-2, TruncateToWidth(msg, w-4), styleWarn)
	}

	drawInspectorOverlays(app, w, h)
}

func drawInspectorOverlays(app *shared.AppState, w, h int) {
	if !app.ShowInspectMenu {
		return
	}
	opts := inspectorMenuOptions()
	drawMenuPanel(app.Screen, w, h, "Inspector Menu", opts, clampIndex(app.InspectMenuIndex, len(opts)), "")
}

func inspectorExternalOrgs(cand *shared.Candidate) (orgs []string, pending int, failed int) {
	if cand == nil {
		return nil, 0, 0
	}
	return shared.ResolveExternalASNOrgs(cand.Conns)
}
