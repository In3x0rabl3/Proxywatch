package ui

import (
	"fmt"
	"strings"
	"time"

	"proxywatch/internal/shared"

	"github.com/gdamore/tcell/v2"
)

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
	roleStyle := styleTextB
	switch role {
	case "session":
		roleStyle = styleSession
	case "beacon", "tunnel", "smb-pipe":
		roleStyle = styleAlertB
	}
	state := "watch"
	stateStyle := styleWatch
	if cand.ActiveProxying {
		state = "active"
		stateStyle = styleAlert
	} else if cand.StrongEvidence {
		state = "strong"
		stateStyle = styleWarn
	}
	explain := "no"
	if app.InspectExplain {
		explain = "yes"
	}

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
	drawIOMetric := func(row int, label string, read, write, other uint64, rate bool) {
		formatMetric := FormatBytes
		if rate {
			formatMetric = FormatBytesPerSec
		}
		total := read + write + other
		putContent(3, row, label, styleMuted)
		x := 15
		totalText := formatMetric(total)
		putContent(x, row, totalText, styleTextB)
		x += len(totalText)
		if total == 0 {
			return
		}
		x++
		putContent(x, row, "(", styleDim)
		x++
		if read > 0 {
			putContent(x, row, "R ", styleMuted)
			x += 2
			readText := formatMetric(read)
			putContent(x, row, readText, styleMuted)
			x += len(readText) + 1
		}
		if write > 0 {
			putContent(x, row, "W ", styleMuted)
			x += 2
			writeText := formatMetric(write)
			putContent(x, row, writeText, styleMuted)
			x += len(writeText) + 1
		}
		if other > 0 || (read == 0 && write == 0) {
			putContent(x, row, "O ", styleMuted)
			x += 2
			otherText := formatMetric(other)
			putContent(x, row, otherText, styleMuted)
			x += len(otherText)
		} else if x > 16 {
			x--
		}
		putContent(x, row, ")", styleDim)
	}

	row := 0
	sectionStarts := make([]int, 0, 8)
	sectionStarts = append(sectionStarts, row)
	x := 2
	putContent(x, row, "Role:", styleMuted)
	x += 6
	putContent(x, row, role, roleStyle)
	x += len(role) + 2
	putContent(x, row, "State:", styleMuted)
	x += 7
	putContent(x, row, state, stateStyle)
	x += len(state) + 2
	putContent(x, row, "Explain:", styleMuted)
	x += 9
	putContent(x, row, explain, styleTextB)
	row++

	host := shared.DisplayHost(cand.Host)
	active := "no"
	if cand.ActiveProxying {
		active = "yes"
	}
	age := "0s"
	ageSeconds := dashboardCandidateAgeSeconds(*cand)
	if ageSeconds > 0 {
		age = (time.Duration(ageSeconds) * time.Second).Round(time.Second).String()
	}
	x = 2
	putContent(x, row, "Host:", styleMuted)
	x += 6
	putContent(x, row, host, styleTextB)
	x += len(host) + 2
	putContent(x, row, "Active:", styleMuted)
	x += 8
	putContent(x, row, active, styleTextB)
	x += len(active) + 2
	putContent(x, row, "Age:", styleMuted)
	x += 5
	putContent(x, row, age, styleDimB)
	row++

	path := "(unknown)"
	user := "(unknown)"
	parentPID := "(unknown)"
	sessionName := "(unknown)"
	sessionID := uint32(0)
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
		sessionID = cand.Proc.SessionID
		if strings.TrimSpace(cand.Proc.SessionName) != "" {
			sessionName = cand.Proc.SessionName
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
	putContent(2, row, "Path:", styleMuted)
	putContent(8, row, path, styleTextB)
	row += 2

	rightX := max(28, w/4)
	sectionStarts = append(sectionStarts, row)
	putContent(2, row, "EXECUTION", styleAccent)
	row++
	putContent(3, row, "Name:", styleMuted)
	putContent(10, row, name, styleTextB)
	putContent(rightX, row, "PID:", styleMuted)
	putContent(rightX+10, row, fmt.Sprintf("%d", pid), styleTextB)
	row++
	putContent(3, row, "User:", styleMuted)
	putContent(10, row, user, styleTextB)
	putContent(rightX, row, "Session:", styleMuted)
	putContent(rightX+10, row, fmt.Sprintf("%s (%d)", sessionName, sessionID), styleTextB)
	row++
	putContent(3, row, "Parent PID:", styleMuted)
	putContent(15, row, parentPID, styleTextB)
	putContent(rightX, row, "Integrity:", styleMuted)
	putContent(rightX+12, row, integrity, styleTextB)
	row += 2

	established := 0
	for _, cn := range cand.Conns {
		if cn.State == "ESTABLISHED" {
			established++
		}
	}
	udpInbound := len(cand.UDPListeners)
	udpOutbound := 0
	sectionStarts = append(sectionStarts, row)
	putContent(2, row, "TRAFFIC", styleAccent)
	row++
	putContent(3, row, "TCP in/out:", styleMuted)
	putContent(15, row, fmt.Sprintf("%d/%d", cand.InboundTotal, cand.OutTotal), styleTextB)
	putContent(rightX, row, "Established:", styleMuted)
	putContent(rightX+13, row, fmt.Sprintf("%d", established), styleTextB)
	row++
	putContent(3, row, "UDP in/out:", styleMuted)
	putContent(15, row, fmt.Sprintf("%d/%d", udpInbound, udpOutbound), styleTextB)
	row++
	drawIOMetric(row, "IO bytes:", ioRead, ioWrite, ioOther, false)
	row++
	drawIOMetric(row, "IO rate:", ioReadRate, ioWriteRate, ioOtherRate, true)
	row += 2

	sectionStarts = append(sectionStarts, row)
	putContent(2, row, "EXTERNAL ASN ORGS", styleAccent)
	row++
	orgs, pending, failed := inspectorExternalOrgs(cand)
	if len(orgs) == 0 {
		msg := "(none)"
		if pending > 0 {
			msg = fmt.Sprintf("(resolving %d...)", pending)
		} else if failed > 0 {
			msg = fmt.Sprintf("(unresolved %d)", failed)
		}
		putContent(4, row, msg, styleMuted)
		row++
	} else {
		for _, org := range orgs {
			putContent(4, row, "- "+org, styleTextB)
			row++
		}
	}

	if app.InspectExplain {
		row++
		sectionStarts = append(sectionStarts, row)
		putContent(2, row, "EXPLAIN", styleAccent)
		row++

		boolWord := func(v bool) string {
			if v {
				return "yes"
			}
			return "no"
		}
		putContent(4, row, fmt.Sprintf("Verified: %-3s   Strong: %-3s", boolWord(cand.TrafficVerified), boolWord(cand.StrongEvidence)), styleTextB)
		row++
		putContent(4, row, fmt.Sprintf("Flows:    out %-3d int %-3d ext %-3d lo %-3d in %-3d", cand.OutTotal, cand.OutInternal, cand.OutExternal, cand.OutLoopback, cand.InboundTotal), styleTextB)
		row++
		putContent(4, row, fmt.Sprintf("Durations: long %-3d short %-3d", cand.OutLongLived, cand.OutShortLived), styleTextB)
		row++

		controlLine := "Control:  (none)"
		if cand.ControlChannel != nil {
			controlLine = fmt.Sprintf(
				"Control:  %s:%d -> %s:%d (%s, %ds)",
				cand.ControlChannel.LocalAddress,
				cand.ControlChannel.LocalPort,
				cand.ControlChannel.RemoteAddress,
				cand.ControlChannel.RemotePort,
				cand.ControlChannel.State,
				cand.ControlDurationSeconds,
			)
		}
		putContent(4, row, controlLine, styleTextB)
		row++

		putContent(4, row, "REASONS", styleWarn)
		row++
		if len(cand.Reasons) == 0 {
			putContent(6, row, "(none)", styleDim)
			row++
		} else {
			for _, reason := range cand.Reasons {
				putContent(6, row, "- "+reason, styleTextB)
				row++
			}
		}

		putContent(4, row, "SIGNALS", styleWarn)
		row++
		if len(cand.Signals) == 0 {
			putContent(6, row, "(none)", styleDim)
			row++
		} else {
			for _, signal := range cand.Signals {
				putContent(6, row, "- "+signal, styleTextB)
				row++
			}
		}
	}

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
	putContent(colLocal, row, "Local", styleTextB)
	putContent(colRemote, row, "Remote", styleTextB)
	putContent(colState, row, "State", styleTextB)
	putContent(colScope, row, "Scope", styleTextB)
	row++
	putContent(colProto, row, "-----", styleDim)
	putContent(colLocal, row, "----------------------", styleDim)
	putContent(colRemote, row, "----------------------", styleDim)
	putContent(colState, row, "---------", styleDim)
	putContent(colScope, row, "-------", styleDim)
	row++

	seen := make(map[string]struct{})
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
		putContent(colProto, row, "TCP", styleTextB)
		putContent(colLocal, row, local, styleDimB)
		putContent(colRemote, row, remote, styleText)
		putContent(colState, row, cn.State, connectionStateStyle(cn.State))
		putContent(colScope, row, scope, scopeTextStyle(scope))
		row++
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
