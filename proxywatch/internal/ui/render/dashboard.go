package render

import (
	"fmt"
	"strings"
	"time"

	"proxywatch/internal/shared"
	"proxywatch/internal/ui/common"

	"github.com/gdamore/tcell/v2"
)

func DrawDashboard(app *shared.AppState) {
	s := app.Screen
	common.ClearScreen(s)
	w, h := s.Size()

	headerH := 4
	common.DrawPanel(s, 0, 0, w, headerH, "Dashboard", "proxywatch")
	common.PutStringStyle(s, 2, 1, "? menu", common.StyleDim)
	utcLabel := "UTC: "
	utcValue := time.Now().UTC().Format(common.UTCTimeFormat)
	utcLen := len(utcLabel) + len(utcValue)
	roleVal := common.SafeRolePreset(app)
	refreshVal := app.RefreshInt.String()
	rolesLabel := "Roles: "
	refreshLabel := "   Refresh: "
	totalLen := len(rolesLabel) + len(roleVal) + len(refreshLabel) + len(refreshVal)
	blockWidth := max(utcLen, totalLen)
	blockStart := max(2, w-2-blockWidth)
	common.PutStringStyle(s, blockStart, 1, utcLabel, common.StyleCyanB)
	common.PutStringStyle(s, blockStart+len(utcLabel), 1, utcValue, common.StyleTextB)
	start := blockStart
	common.PutStringStyle(s, start, 2, rolesLabel, common.StyleCyanB)
	start += len(rolesLabel)
	common.PutStringStyle(s, start, 2, roleVal, common.StyleTextB)
	start += len(roleVal)
	common.PutStringStyle(s, start, 2, refreshLabel, common.StyleCyanB)
	start += len(refreshLabel)
	common.PutStringStyle(s, start, 2, refreshVal, common.StyleTextB)

	bodyY := headerH
	if app.CalibrateAnalyzing {
		common.PutStringStyle(s, 2, bodyY, common.TruncateToWidth("gpt analyzing...", w-4), common.StyleTextB)
		bodyY++
	} else if app.CalibrateActive {
		remaining := time.Until(app.CalibrateUntil).Round(time.Second)
		if remaining < 0 {
			remaining = 0
		}
		common.PutStringStyle(s, 2, bodyY, common.TruncateToWidth("calibration collection in progress   "+remaining.String()+" remaining", w-4), common.StyleAlertB)
		bodyY++
	} else if app.CalibrateStatusText != "" && time.Now().Before(app.CalibrateStatusUntil) {
		st := common.StyleText
		if app.CalibrateStatusError {
			st = common.StyleAlert
		}
		common.PutStringStyle(s, 2, bodyY, common.TruncateToWidth(app.CalibrateStatusText, w-4), st)
		bodyY++
	}
	if len(app.HostSummaries) > 1 {
		summaryLine := BuildMultiHostSummary(app)
		titleLine := fmt.Sprintf("HOST SUMMARY (%d hosts)", len(app.HostSummaries))
		common.PutStringStyle(s, 2, bodyY, titleLine, common.StyleCyanB)
		bodyY++
		common.PutStringStyle(s, 4, bodyY, common.TruncateToWidth(summaryLine, w-6), common.StyleText)
		bodyY++
		bodyY++
	}
	bodyH := h - bodyY
	if bodyH < 4 {
		return
	}
	panelTitle := "PROCESS VIEW"
	if dashboardHostListMode(app) {
		panelTitle = "HOST VIEW"
	}
	common.DrawPanel(s, 0, bodyY, w, bodyH, panelTitle, "")
	if dashboardHostListMode(app) {
		drawDashboardHostView(app, bodyY, bodyH, w, h)
	} else {
		drawDashboardProcessView(app, bodyY, bodyH, w, h)
	}

	drawDashboardOverlays(app, w, h)
}

func BuildMultiHostSummary(app *shared.AppState) string {
	type hostRoles struct {
		total     int
		session   int
		beacon    int
		pivot     int
		tunnel    int
		analyzing int
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
		case "control-session":
			hr.session++
		case "control-beacon":
			hr.beacon++
		case "control-pivot":
			hr.pivot++
		case "control-tunnel":
			hr.tunnel++
		case "analyzing":
			hr.analyzing++
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
		common.PutStringStyle(s, 2, bodyY+1, "No connected hosts yet.", common.StyleText)
		common.PutStringStyle(s, 2, bodyY+2, "Start agents and wait for telemetry updates.", common.StyleMuted)
		common.PutStringStyle(s, max(2, w-8), h-1, "0/0", common.StyleCyanB)
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

	common.PutStringStyle(s, colHost, bodyY+1, "HOST", common.StyleTextB)
	common.PutStringStyle(s, colStatus, bodyY+1, "STATUS", common.StyleTextB)
	common.PutStringStyle(s, colSeen, bodyY+1, "SEEN", common.StyleTextB)
	common.PutStringStyle(s, colProcesses, bodyY+1, "PROCESSES", common.StyleTextB)
	common.PutStringStyle(s, colWatch, bodyY+1, "WATCH", common.StyleTextB)
	common.PutStringStyle(s, colStrong, bodyY+1, "STRONG", common.StyleTextB)
	common.PutStringStyle(s, colRoles, bodyY+1, "ROLES", common.StyleTextB)
	common.PutStringStyle(s, colActive, bodyY+1, "ACTIVE", common.StyleTextB)

	maxRows := bodyH - 4
	if maxRows < 1 {
		common.PutStringStyle(s, max(2, w-8), h-1, fmt.Sprintf("%d/%d", app.DashboardHostSelected+1, len(app.HostSummaries)), common.StyleCyanB)
		return
	}
	startIdx := 0
	if app.DashboardHostSelected >= maxRows {
		startIdx = app.DashboardHostSelected - maxRows + 1
	}
	maxStart := max(0, len(app.HostSummaries)-maxRows)
	if startIdx > maxStart {
		startIdx = maxStart
	}
	if startIdx < 0 {
		startIdx = 0
	}
	for row, i := 0, startIdx; i < len(app.HostSummaries) && row < maxRows; i, row = i+1, row+1 {
		item := app.HostSummaries[i]
		rowY := bodyY + 2 + row
		rowSelected := i == app.DashboardHostSelected
		prefix := " "
		prefixStyle := common.StyleText
		hostStyle := common.StyleText
		if rowSelected {
			prefix = ">"
			prefixStyle = common.StyleWatch
			hostStyle = common.StyleTextB
		}
		common.FillSelectedRowBar(s, rowY, 2, w-3, rowSelected)

		connected := strings.EqualFold(strings.TrimSpace(item.Status), "connected")
		seen := "now"
		if !connected && !item.LastSeen.IsZero() {
			age := max(0, int(time.Since(item.LastSeen).Seconds()))
			seen = common.FormatDashboardAge(age)
		} else if !connected {
			seen = "-"
		}

		common.PutStringStyle(s, colPrefix, rowY, prefix, common.ApplySelectedRowStyle(prefixStyle, rowSelected))
		common.PutStringStyle(s, colHost, rowY, fmt.Sprintf("%-*s", hostW, common.TruncateToWidth(item.Host, hostW)), common.ApplySelectedRowStyle(hostStyle, rowSelected))
		statusStyle := common.StyleWatch
		if !connected {
			statusStyle = common.StyleAlertB
		}
		common.PutStringStyle(s, colStatus, rowY, fmt.Sprintf("%-*s", statusW, common.TruncateToWidth(item.Status, statusW)), common.ApplySelectedRowStyle(statusStyle, rowSelected))
		common.PutStringStyle(s, colSeen, rowY, fmt.Sprintf("%-*s", seenW, common.TruncateToWidth(seen, seenW)), common.ApplySelectedRowStyle(common.StyleDim, rowSelected))
		common.PutStringStyle(s, colProcesses, rowY, fmt.Sprintf("%*d", processesW, item.Processes), common.ApplySelectedRowStyle(common.StyleText, rowSelected))
		common.PutStringStyle(s, colWatch, rowY, fmt.Sprintf("%*d", watchW, item.Watch), common.ApplySelectedRowStyle(common.StyleWatch, rowSelected))
		common.PutStringStyle(s, colStrong, rowY, fmt.Sprintf("%*d", strongW, item.Strong), common.ApplySelectedRowStyle(common.StyleWarn, rowSelected))
		common.PutStringStyle(s, colRoles, rowY, fmt.Sprintf("%*d", rolesW, item.Roles), common.ApplySelectedRowStyle(common.StyleCyanB, rowSelected))
		common.PutStringStyle(s, colActive, rowY, fmt.Sprintf("%*d", activeW, item.Active), common.ApplySelectedRowStyle(common.StyleAlertB, rowSelected))
	}
	common.PutStringStyle(s, max(2, w-8), h-1, fmt.Sprintf("%d/%d", app.DashboardHostSelected+1, len(app.HostSummaries)), common.StyleCyanB)
}

func drawDashboardProcessView(app *shared.AppState, bodyY, bodyH, w, h int) {
	s := app.Screen
	view := dashboardProcessCandidates(app)
	if len(view) == 0 {
		common.PutStringStyle(s, 2, bodyY+1, "Nothing in the current view matches the active filter yet.", common.StyleText)
		common.PutStringStyle(s, 2, bodyY+2, "Roles: "+common.SafeRolePreset(app), common.StyleMuted)
		common.PutStringStyle(s, 2, bodyY+3, "Try waiting for the next refresh or widening the view with the role/sort menu (c).", common.StyleMuted)
		common.PutStringStyle(s, max(2, w-8), h-1, "0/0", common.StyleCyanB)
		return
	}

	selectedViewIdx := selectedDashboardProcessIndex(app, view)

	const (
		colPrefix = 2
		colHost   = 4
		pidW      = 7
		roleW     = 16
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
	common.PutStringStyle(s, colHost, bodyY+1, "HOST", common.StyleTextB)
	common.PutStringStyle(s, colPID, bodyY+1, "PID", common.StyleTextB)
	common.PutStringStyle(s, colProc, bodyY+1, "PROCESS", common.StyleTextB)
	common.PutStringStyle(s, colRole, bodyY+1, "ROLE", common.StyleTextB)
	common.PutStringStyle(s, colAge, bodyY+1, "AGE", common.StyleTextB)
	common.PutStringStyle(s, colState, bodyY+1, "STATE", common.StyleTextB)
	maxRows := bodyH - 4
	if maxRows < 1 {
		common.PutStringStyle(s, max(2, w-8), h-1, fmt.Sprintf("%d/%d", max(0, selectedViewIdx+1), len(view)), common.StyleCyanB)
		return
	}
	startIdx := 0
	if selectedViewIdx >= maxRows {
		startIdx = selectedViewIdx - maxRows + 1
	}
	maxStart := max(0, len(view)-maxRows)
	if startIdx > maxStart {
		startIdx = maxStart
	}
	if startIdx < 0 {
		startIdx = 0
	}
	for row, i := 0, startIdx; i < len(view) && row < maxRows; i, row = i+1, row+1 {
		c := view[i]
		host := shared.DisplayHost(c.Host)
		name := shared.DisplayProcessName(c.Proc)
		pid := 0
		if c.Proc != nil {
			pid = c.Proc.Pid
		}
		role := common.NormalizeDashboardRole(c.Role)
		age := common.FormatDashboardAge(common.DashboardCandidateAgeSeconds(c))
		state := shared.CandidateState(c)
		rowY := bodyY + 2 + row
		rowSelected := i == selectedViewIdx
		prefix := " "
		prefixStyle := common.StyleText
		hostStyle := common.StyleText
		processStyle := common.StyleText
		pidStyle := common.StyleDim
		ageStyle := common.StyleDim
		if rowSelected {
			prefix = ">"
			prefixStyle = common.StyleWatch
			hostStyle = common.StyleTextB
			processStyle = common.StyleTextB
			pidStyle = common.StyleDimB
			ageStyle = common.StyleDimB
		}
		common.FillSelectedRowBar(s, rowY, 2, w-3, rowSelected)
		common.PutStringStyle(s, colPrefix, rowY, prefix, common.ApplySelectedRowStyle(prefixStyle, rowSelected))
		common.PutStringStyle(s, colHost, rowY, fmt.Sprintf("%-*s", hostW, common.TruncateToWidth(host, hostW)), common.ApplySelectedRowStyle(hostStyle, rowSelected))
		common.PutStringStyle(s, colPID, rowY, fmt.Sprintf("%-*s", pidW, common.TruncateToWidth(fmt.Sprintf("%d", pid), pidW)), common.ApplySelectedRowStyle(pidStyle, rowSelected))
		common.PutStringStyle(s, colProc, rowY, fmt.Sprintf("%-*s", procW, common.ClipToWidth(name, procW)), common.ApplySelectedRowStyle(processStyle, rowSelected))
		common.PutStringStyle(s, colRole, rowY, fmt.Sprintf("%-*s", roleW, common.TruncateToWidth(role, roleW)), common.ApplySelectedRowStyle(common.RoleStyle(role), rowSelected))
		common.PutStringStyle(s, colAge, rowY, fmt.Sprintf("%-*s", ageW, common.TruncateToWidth(age, ageW)), common.ApplySelectedRowStyle(ageStyle, rowSelected))
		common.PutStringStyle(s, colState, rowY, fmt.Sprintf("%-*s", stateW, common.TruncateToWidth(state, stateW)), common.ApplySelectedRowStyle(common.StateStyle(state), rowSelected))
	}
	common.PutStringStyle(s, max(2, w-8), h-1, fmt.Sprintf("%d/%d", max(0, selectedViewIdx+1), len(view)), common.StyleCyanB)
}

func drawDashboardOverlays(app *shared.AppState, w, h int) {
	if app.ShowHelp {
		help := common.DashboardMenuHelpOptions()
		common.DrawMenuPanel(app.Screen, w, h, "Dashboard Menu", help, common.ClampIndex(app.HelpMenuIndex, len(help)), "")
	}
	if app.ShowRoleMenu {
		opts := roleSortMenuLabels()
		common.DrawMenuPanel(app.Screen, w, h, "Roles + Sort", opts, common.ClampIndex(app.RoleMenuIndex, len(opts)), "Enter apply   f role/sort menu   Esc close")
	}
	if app.ShowRefreshMenu {
		opts := common.RefreshPresetOptions()
		common.DrawMenuPanel(app.Screen, w, h, "Refresh Rate", opts, common.ClampIndex(app.RefreshMenuIndex, len(opts)), "Enter apply   Esc close")
	}
}

// --- inspector view ---

func DrawInspector(app *shared.AppState) {
	s := app.Screen
	common.ClearScreen(s)

	w, h := s.Size()
	const headerH = 3
	common.DrawPanel(s, 0, 0, w, headerH, "Inspector", "proxywatch")
	common.PutStringStyle(s, 2, 1, "? menu   esc dashboard   q quit", common.StyleDim)

	var cand *shared.Candidate
	for i := range app.Candidates {
		if shared.CandidateKey(app.Candidates[i]) == app.InspectKey {
			cand = &app.Candidates[i]
			break
		}
	}
	if cand == nil {
		common.PutStringStyle(s, 2, 2, "Process no longer present. Press ESC.", common.StyleAlert)
		return
	}

	role := common.NormalizeDashboardRole(cand.Role)
	rs := common.RoleStyle(role)
	state := "watch"
	if cand.ActiveProxying {
		state = "active"
	} else if cand.StrongEvidence {
		state = "strong"
	}
	ss := common.StateStyle(state)

	line1 := "UTC: " + time.Now().UTC().Format(common.UTCTimeFormat)
	blockWidth := len(line1)
	blockX := max(2, w-2-blockWidth)

	common.PutStringStyle(s, blockX, 1, "UTC: ", common.StyleCyanB)
	common.PutStringStyle(s, blockX+5, 1, time.Now().UTC().Format(common.UTCTimeFormat), common.StyleTextB)

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
	common.DrawPanel(s, 0, bodyY, w, bodyH, "PROCESS DETAILS", "")
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
		common.PutStringStyle(s, x, sy, common.TruncateToWidth(text, w-x-2), st)
	}
	scopeTextStyle := func(scope string) tcell.Style {
		switch strings.ToLower(strings.TrimSpace(scope)) {
		case "external":
			return common.StyleWarn
		default:
			return common.StyleMuted
		}
	}
	connectionStateStyle := func(connState string) tcell.Style {
		switch strings.ToUpper(strings.TrimSpace(connState)) {
		case "ESTABLISHED", "LISTEN":
			return common.StyleTextB
		case "SYN_SENT", "SYN_RECV", "CLOSE_WAIT", "TIME_WAIT", "FIN_WAIT1", "FIN_WAIT2":
			return common.StyleMuted
		case "UNKNOWN", "":
			return common.StyleDim
		default:
			return common.StyleText
		}
	}
	formatIO := func(read, write, other uint64, rate bool) string {
		formatMetric := common.FormatBytes
		if rate {
			formatMetric = common.FormatBytesPerSec
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
	ageSeconds := common.DashboardCandidateAgeSeconds(*cand)
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
	vx := 11

	sectionStarts = append(sectionStarts, row)
	putContent(2, row, "Name:", common.StyleMuted)
	putContent(vx, row, name, common.StyleTextB)
	row++
	putContent(2, row, "Path:", common.StyleMuted)
	putContent(vx, row, path, common.StyleMuted)
	row++
	if cand.Proc != nil && strings.TrimSpace(cand.Proc.CmdLine) != "" {
		cmdLine := strings.TrimSpace(cand.Proc.CmdLine)
		putContent(2, row, "Cmd:", common.StyleMuted)
		putContent(vx, row, cmdLine, common.StyleMuted)
		row++
	}
	if cand.Proc != nil && strings.TrimSpace(cand.Proc.Company) != "" {
		putContent(2, row, "Vendor:", common.StyleMuted)
		putContent(vx, row, strings.TrimSpace(cand.Proc.Company), common.StyleTextB)
		row++
	}
	putContent(2, row, "Role:", common.StyleMuted)
	putContent(vx, row, role, rs)
	row++
	putContent(2, row, "State:", common.StyleMuted)
	putContent(vx, row, state, ss)
	row++
	sinceLabel := fmt.Sprintf("%ds at current role", cand.SeenSeconds)
	putContent(2, row, "Since:", common.StyleMuted)
	putContent(vx, row, sinceLabel, common.StyleText)
	row += 2

	sectionStarts = append(sectionStarts, row)
	col2 := max(24, w/3)
	putContent(2, row, "PID:", common.StyleMuted)
	putContent(vx, row, fmt.Sprintf("%d", pid), common.StyleTextB)
	putContent(col2, row, "Host:", common.StyleMuted)
	putContent(col2+vx-2, row, host, common.StyleTextB)
	row++
	putContent(2, row, "User:", common.StyleMuted)
	putContent(vx, row, user, common.StyleTextB)
	putContent(col2, row, "Integrity:", common.StyleMuted)
	putContent(col2+vx-2, row, integrity, common.StyleTextB)
	row++
	putContent(2, row, "Parent:", common.StyleMuted)
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
	putContent(vx, row, parentLabel, common.StyleTextB)
	putContent(col2, row, "Age:", common.StyleMuted)
	putContent(col2+vx-2, row, age, common.StyleTextB)
	row += 2

	sectionStarts = append(sectionStarts, row)
	putContent(2, row, "TCP:", common.StyleMuted)
	putContent(vx, row, fmt.Sprintf("%d in  /  %d out  (%d established)", cand.InboundTotal, cand.OutTotal, established), common.StyleTextB)
	row++
	putContent(2, row, "UDP:", common.StyleMuted)
	putContent(vx, row, fmt.Sprintf("%d listeners", len(cand.UDPListeners)), common.StyleTextB)
	row++
	putContent(2, row, "IO:", common.StyleMuted)
	putContent(vx, row, formatIO(ioRead, ioWrite, ioOther, false), common.StyleTextB)
	row++
	if ioReadRate+ioWriteRate+ioOtherRate > 0 {
		putContent(2, row, "Rate:", common.StyleMuted)
		putContent(vx, row, formatIO(ioReadRate, ioWriteRate, ioOtherRate, true), common.StyleTextB)
		row++
	}
	if len(cand.Listeners) > 0 {
		ports := make([]string, 0, len(cand.Listeners))
		seenPort := make(map[int]bool)
		for _, l := range cand.Listeners {
			if l.LocalPort > 0 && !seenPort[l.LocalPort] {
				seenPort[l.LocalPort] = true
				scope := "local"
				if shared.IsWildcardIP(l.LocalAddress) {
					scope = "any"
				}
				ports = append(ports, fmt.Sprintf("%d/%s", l.LocalPort, scope))
			}
		}
		if len(ports) > 0 {
			putContent(2, row, "Listen:", common.StyleMuted)
			putContent(vx, row, strings.Join(ports, ", "), common.StyleTextB)
			row++
		}
	}
	if cand.DelegatedEgress {
		putContent(2, row, "Broker:", common.StyleMuted)
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
		putContent(vx, row, label, common.StyleWarn)
		row++
	}
	orgs, pending, _ := InspectorExternalOrgs(cand)
	if len(orgs) > 0 {
		for i, org := range orgs {
			if i == 0 {
				putContent(2, row, "ASN:", common.StyleMuted)
			}
			putContent(vx, row, org, common.StyleTextB)
			row++
		}
	} else if pending > 0 {
		putContent(2, row, "ASN:", common.StyleMuted)
		putContent(vx, row, fmt.Sprintf("resolving %d...", pending), common.StyleDim)
		row++
	}
	if cand.Proc != nil && len(cand.Proc.LoadedLibs) > 0 {
		libs := cand.Proc.LoadedLibs
		if len(libs) > 5 {
			libs = libs[:5]
		}
		putContent(2, row, "Libs:", common.StyleMuted)
		putContent(vx, row, strings.Join(libs, ", "), common.StyleText)
		row++
	}
	row++

	sectionStarts = append(sectionStarts, row)
	if cand.ControlChannel != nil {
		cn := cand.ControlChannel
		scope := "external"
		scopeSt := common.StyleWarn
		if shared.IsInternalIP(cn.RemoteAddress) {
			scope = "internal"
			scopeSt = common.StyleCyan
		}
		putContent(2, row, "Control:", common.StyleWarn)
		putContent(vx, row, fmt.Sprintf("%s:%d", cn.RemoteAddress, cn.RemotePort), common.StyleTextB)
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
		putContent(2, row, "Flows:", common.StyleMuted)
		putContent(vx, row, strings.Join(flowParts, ",  "), common.StyleTextB)
		row++
	}
	if cand.OutLongLived > 0 || cand.OutShortLived > 0 {
		putContent(2, row, "Duration:", common.StyleMuted)
		putContent(vx, row, fmt.Sprintf("%d long-lived,  %d short-lived", cand.OutLongLived, cand.OutShortLived), common.StyleTextB)
		row++
	}
	if cand.TrafficVerified {
		putContent(2, row, "Verified:", common.StyleMuted)
		putContent(vx, row, "matches learned baseline (de-emphasized)", common.StyleDim)
		row++
	}
	row++

	if len(cand.Reasons) > 0 {
		sectionStarts = append(sectionStarts, row)
		putContent(2, row, "Reasons:", common.StyleWarn)
		row++
		for _, reason := range cand.Reasons {
			putContent(4, row, "- "+reason, common.StyleTextB)
			row++
		}
		row++
	}

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
	putContent(2, row, "CONNECTIONS", common.StyleAccent)
	row++
	const (
		colProto  = 3
		colLocal  = 9
		colRemote = 35
		colState  = 60
		colScope  = 72
	)
	putContent(colProto, row, "Proto", common.StyleTextB)
	if groupedConns {
		putContent(colLocal, row, "Remote", common.StyleTextB)
		putContent(colRemote, row, "Count", common.StyleTextB)
	} else {
		putContent(colLocal, row, "Local", common.StyleTextB)
		putContent(colRemote, row, "Remote", common.StyleTextB)
	}
	putContent(colState, row, "State", common.StyleTextB)
	putContent(colScope, row, "Scope", common.StyleTextB)
	row++
	putContent(colProto, row, "-----", common.StyleDim)
	putContent(colLocal, row, "----------------------", common.StyleDim)
	putContent(colRemote, row, "----------------------", common.StyleDim)
	putContent(colState, row, "---------", common.StyleDim)
	putContent(colScope, row, "-------", common.StyleDim)
	row++

	if groupedConns {
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
			putContent(colProto, row, "TCP", common.StyleTextB)
			putContent(colLocal, row, g.remote, common.StyleDimB)
			putContent(colRemote, row, countLabel, common.StyleText)
			putContent(colState, row, g.state, connectionStateStyle(g.state))
			putContent(colScope, row, g.scope, scopeTextStyle(g.scope))
			row++
		}
	} else {
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
			putContent(colProto, row, "TCP", common.StyleTextB)
			putContent(colLocal, row, local, common.StyleDimB)
			putContent(colRemote, row, remote, common.StyleText)
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
		putContent(colProto, row, "UDP", common.StyleTextB)
		putContent(colLocal, row, local, common.StyleDimB)
		putContent(colRemote, row, "*:*", common.StyleDim)
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
	for _, startVal := range sectionStarts {
		if startVal < 0 {
			continue
		}
		if startVal > maxScroll {
			startVal = maxScroll
		}
		if startVal == last {
			continue
		}
		filteredStarts = append(filteredStarts, startVal)
		last = startVal
	}
	app.InspectSectionStarts = filteredStarts
	if maxScroll > 0 {
		common.PutStringStyle(s, max(2, w-12), h-1, fmt.Sprintf("%d/%d", app.InspectScroll, maxScroll), common.StyleCyan)
	}

	if app.LastError != "" && h >= 2 {
		common.PutStringStyle(s, 2, h-2, common.TruncateToWidth(app.LastError, w-4), common.StyleAlert)
	}
	if app.ConfirmKill && app.ConfirmKillKey == app.InspectKey && time.Now().Before(app.ConfirmKillDeadline) && h >= 2 {
		msg := fmt.Sprintf("Confirm kill: press k again or y within %s", app.ConfirmKillTimeout)
		common.PutStringStyle(s, 2, h-2, common.TruncateToWidth(msg, w-4), common.StyleWarn)
	}

	drawInspectorOverlays(app, w, h)
}

func drawInspectorOverlays(app *shared.AppState, w, h int) {
	if !app.ShowInspectMenu {
		return
	}
	opts := common.InspectorMenuOptions()
	common.DrawMenuPanel(app.Screen, w, h, "Inspector Menu", opts, common.ClampIndex(app.InspectMenuIndex, len(opts)), "")
}

func InspectorExternalOrgs(cand *shared.Candidate) (orgs []string, pending int, failed int) {
	if cand == nil {
		return nil, 0, 0
	}
	return shared.ResolveExternalASNOrgs(cand.Conns)
}
