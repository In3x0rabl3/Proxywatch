package ui

import (
	"fmt"
	"strings"
	"time"

	"proxywatch/internal/shared"
)

func DrawDashboard(app *shared.AppState) {
	s := app.Screen
	clearScreen(s)
	w, h := s.Size()

	headerH := 4
	drawPanel(s, 0, 0, w, headerH, "Dashboard", "proxywatch")
	PutStringStyle(s, 2, 1, "? help", styleDim)
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
		PutStringStyle(s, 2, bodyY+3, "Try waiting for the next refresh or widening the view with the role filter menu (f).", styleMuted)
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
		roleStyle := styleTextB
		switch role {
		case "session":
			roleStyle = styleSession
		case "beacon", "tunnel", "smb-pipe":
			roleStyle = styleAlertB
		}
		stateStyle := styleWatch
		switch state {
		case "active":
			stateStyle = styleAlertB
		case "strong":
			stateStyle = styleWarn
		}

		PutStringStyle(s, colPrefix, rowY, prefix, applySelectedRowStyle(prefixStyle, rowSelected))
		PutStringStyle(s, colHost, rowY, fmt.Sprintf("%-*s", hostW, TruncateToWidth(host, hostW)), applySelectedRowStyle(hostStyle, rowSelected))
		PutStringStyle(s, colPID, rowY, fmt.Sprintf("%-*s", pidW, TruncateToWidth(fmt.Sprintf("%d", pid), pidW)), applySelectedRowStyle(pidStyle, rowSelected))
		PutStringStyle(s, colProc, rowY, fmt.Sprintf("%-*s", procW, ClipToWidth(name, procW)), applySelectedRowStyle(processStyle, rowSelected))
		PutStringStyle(s, colRole, rowY, fmt.Sprintf("%-*s", roleW, TruncateToWidth(role, roleW)), applySelectedRowStyle(roleStyle, rowSelected))
		PutStringStyle(s, colAge, rowY, fmt.Sprintf("%-*s", ageW, TruncateToWidth(age, ageW)), applySelectedRowStyle(ageStyle, rowSelected))
		PutStringStyle(s, colState, rowY, fmt.Sprintf("%-*s", stateW, TruncateToWidth(state, stateW)), applySelectedRowStyle(stateStyle, rowSelected))
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
