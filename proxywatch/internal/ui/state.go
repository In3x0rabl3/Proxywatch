package ui

import (
	"fmt"
	"strings"
	"time"

	"proxywatch/internal/shared"

	"github.com/gdamore/tcell/v2"
)

/* ---------- helpers ---------- */

func PutString(s tcell.Screen, x, y int, text string) {
	for i, r := range text {
		s.SetContent(x+i, y, r, nil, tcell.StyleDefault)
	}
}

const utcTimeFormat = "2006-01-02 15:04:05"

func drawHeader(s tcell.Screen, w int, subtitle, status string) {
	PutString(s, 0, 0,
		TruncateToWidth(fmt.Sprintf("UTC: %s", time.Now().UTC().Format(utcTimeFormat)), w),
	)
	if subtitle != "" {
		PutString(s, 0, 2, TruncateToWidth(subtitle, w))
	}
	if status != "" {
		PutString(s, 0, 3, TruncateToWidth("Status: "+status, w))
	}
}

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
		label := strings.Fields(parts[0])[0]
		return fmt.Sprintf("%s (%s)", totalStr, label)
	}
	return fmt.Sprintf("%s (%s)", totalStr, strings.Join(parts, " "))
}

var collectDurations = []string{"30s", "1m", "2m", "5m", "10m", "15m"}

func DrawCollect(app *shared.AppState) {
	s := app.Screen
	s.Clear()

	w, _ := s.Size()
	drawHeader(s, w,
		"Collection | UP/DOWN select | ENTER edit/start | LEFT/RIGHT time | ESC back | q quit",
		app.LastError,
	)

	y := 5
	fields := []struct {
		label string
		value string
		edit  bool
	}{
		{"Output", app.CollectOutput, app.CollectEditing && app.CollectField == 0},
		{"Duration", app.CollectDurationStr, false},
		{"Roles", app.CollectRoles, app.CollectEditing && app.CollectField == 2},
		{"Start/Stop", "", false},
	}

	for i, f := range fields {
		prefix := " "
		if i == app.CollectField {
			prefix = ">"
		}
		value := f.value
		if f.label == "Start/Stop" {
			if app.CollectActive {
				value = "Stop"
			} else {
				value = "Start"
			}
		}
		edit := ""
		if f.edit {
			edit = " [edit]"
		}
		line := fmt.Sprintf("%s %-9s: %s%s", prefix, f.label, value, edit)
		PutString(s, 0, y, TruncateToWidth(line, w))
		y++
	}

	y++
	if app.CollectActive {
		remaining := time.Until(app.CollectUntil).Round(time.Second)
		if remaining < 0 {
			remaining = 0
		}
		PutString(s, 0, y, TruncateToWidth(fmt.Sprintf("Status: collecting (%s remaining)", remaining), w))
	} else {
		PutString(s, 0, y, TruncateToWidth("Status: idle", w))
	}
}

func stepDuration(current string, dir int) string {
	if len(collectDurations) == 0 {
		return current
	}
	index := 0
	for i, v := range collectDurations {
		if v == current {
			index = i
			break
		}
	}
	if dir > 0 {
		index = (index + 1) % len(collectDurations)
	} else if dir < 0 {
		index = (index - 1 + len(collectDurations)) % len(collectDurations)
	}
	return collectDurations[index]
}

func DrawDashboard(app *shared.AppState) {
	s := app.Screen
	s.Clear()

	w, _ := s.Size()

	status := app.LastError
	if app.CollectActive {
		remaining := time.Until(app.CollectUntil).Round(time.Second)
		if remaining < 0 {
			remaining = 0
		}
		if status != "" {
			status += " | "
		}
		status += "Collecting (" + remaining.String() + " left)"
	}
	drawHeader(s, w,
		"Use UP/DOWN arrows | ENTER inspect | c collect | w whitelist | W manage whitelist | q quit",
		status,
	)

	y := 5
	if len(app.Candidates) == 0 {
		PutString(s, 0, y, "no candidates matching filters")
		return
	}

	hostWidth := len("HOST")
	pidWidth := len("PID")
	nameWidth := len("NAME")
	roleWidth := len("ROLE")
	intExtWidth := len("INT/EXT/LO")

	for i := range app.Candidates {
		host := shared.DisplayHost(app.Candidates[i].Host)
		if len(host) > hostWidth {
			hostWidth = len(host)
		}
		pidLen := len(fmt.Sprintf("%d", app.Candidates[i].Proc.Pid))
		if pidLen > pidWidth {
			pidWidth = pidLen
		}
		n := shared.TrimName(app.Candidates[i].Proc.Name, 40)
		if len(n) > nameWidth {
			nameWidth = len(n)
		}
		role := shared.RoleFamily(app.Candidates[i].Role)
		if len(role) > roleWidth {
			roleWidth = len(role)
		}
		udpInt, udpExt, udpLo := shared.UDPScopeCounts(app.Candidates[i].UDPListeners)
		intExt := fmt.Sprintf("%d/%d/%d",
			app.Candidates[i].OutInternal+udpInt,
			app.Candidates[i].OutExternal+udpExt,
			app.Candidates[i].OutLoopback+udpLo,
		)
		if len(intExt) > intExtWidth {
			intExtWidth = len(intExt)
		}
	}

	// Cap excessively wide columns to keep UI readable.
	if nameWidth > 32 {
		nameWidth = 32
	}
	if roleWidth < len("ROLE") {
		roleWidth = len("ROLE")
	}

	headerFmt := fmt.Sprintf("%%-1s %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds",
		hostWidth, pidWidth, nameWidth, roleWidth, len("ACTIVE"), intExtWidth)

	PutString(s, 0, y, fmt.Sprintf(headerFmt,
		" ", "HOST", "PID", "NAME", "ROLE", "ACTIVE", "INT/EXT/LO"))
	y++
	PutString(s, 0, y, fmt.Sprintf(headerFmt,
		" ",
		strings.Repeat("-", hostWidth),
		strings.Repeat("-", pidWidth),
		strings.Repeat("-", nameWidth),
		strings.Repeat("-", roleWidth),
		"------",
		strings.Repeat("-", intExtWidth),
	))
	y++

	for i, c := range app.Candidates {
		arrow := " "
		if i == app.SelectedIdx {
			arrow = ">"
		}

		name := shared.TrimName(c.Proc.Name, nameWidth)
		host := shared.DisplayHost(c.Host)
		udpInt, udpExt, udpLo := shared.UDPScopeCounts(c.UDPListeners)
		intExt := fmt.Sprintf("%d/%d/%d",
			c.OutInternal+udpInt,
			c.OutExternal+udpExt,
			c.OutLoopback+udpLo,
		)

		role := shared.RoleFamily(c.Role)
		line := fmt.Sprintf(headerFmt,
			arrow,
			host,
			fmt.Sprintf("%d", c.Proc.Pid),
			name,
			role,
			fmt.Sprintf("%v", c.ActiveProxying),
			intExt,
		)

		PutString(s, 0, y, TruncateToWidth(line, w))
		y++
	}
}

func DrawInspector(app *shared.AppState) {
	s := app.Screen
	s.Clear()

	w, h := s.Size()
	drawHeader(s, w, "", "")

	var cand *shared.Candidate
	for i := range app.Candidates {
		if shared.CandidateKey(app.Candidates[i]) == app.InspectKey {
			cand = &app.Candidates[i]
			break
		}
	}

	if cand == nil {
		PutString(s, 0, 2, "Process no longer present. Press ESC.")
		return
	}

	y := 2
	title := fmt.Sprintf(" %s (PID %d) ", cand.Proc.Name, cand.Proc.Pid)
	sep := strings.Repeat("─", min(len(title), w))

	PutString(s, 0, y, sep)
	y++
	PutString(s, 0, y, TruncateToWidth(title, w))
	y++
	PutString(s, 0, y, sep)
	y += 2

	role := shared.RoleFamily(cand.Role)
	if role != "" && role != "other" {
		PutString(s, 0, y, fmt.Sprintf("Role:  %s (%s)", role, cand.Role))
	} else {
		PutString(s, 0, y, fmt.Sprintf("Role:  %s", cand.Role))
	}
	y++
	PutString(s, 0, y, fmt.Sprintf("Active: %v", cand.ActiveProxying))
	y++
	host := shared.DisplayHost(cand.Host)
	PutString(s, 0, y, fmt.Sprintf("Host:  %s", host))
	y += 2

	user := cand.Proc.UserName
	if user == "" {
		user = "(unknown)"
	}
	PutString(s, 2, y, TruncateToWidth(fmt.Sprintf("User: %s", user), w-2))
	y++

	sessionName := cand.Proc.SessionName
	if sessionName == "" && cand.Proc.SessionID != 0 {
		sessionName = fmt.Sprintf("Session-%d", cand.Proc.SessionID)
	}
	if sessionName == "" {
		sessionName = "(unknown)"
	}
	PutString(s, 2, y, TruncateToWidth(fmt.Sprintf("Session: %s (%d)", sessionName, cand.Proc.SessionID), w-2))
	y++

	parentPID := "unknown"
	if cand.Proc.ParentPid > 0 {
		parentPID = fmt.Sprintf("%d", cand.Proc.ParentPid)
	}
	PutString(s, 2, y, fmt.Sprintf("Parent PID: %s", parentPID))
	y++

	path := cand.Proc.ExePath
	if path == "" {
		path = "(unknown)"
	}
	PutString(s, 2, y, TruncateToWidth(fmt.Sprintf("Path: %s", path), w-2))
	y++

	integrity := cand.Proc.Integrity
	if integrity == "" {
		integrity = "(unknown)"
	}
	PutString(s, 2, y, fmt.Sprintf("Integrity: %s", integrity))
	y += 2

	established := 0
	for _, cn := range cand.Conns {
		if cn.State == "ESTABLISHED" {
			established++
		}
	}

	tcpInbound := cand.InboundTotal
	tcpOutbound := cand.OutTotal
	tcpListeners := len(cand.Listeners)
	udpListeners := len(cand.UDPListeners)

	PutString(s, 2, y, fmt.Sprintf("%-5s %-8s %-11s %-9s", "Proto", "In/Out", "Established", "Listeners"))
	y++
	PutString(s, 2, y, fmt.Sprintf("%-5s %-8s %-11s %-9s", "-----", "------", "-----------", "---------"))
	y++
	PutString(s, 2, y, fmt.Sprintf("%-5s %-8s %-11d %-9d", "TCP", fmt.Sprintf("%d/%d", tcpInbound, tcpOutbound), established, tcpListeners))
	y++
	PutString(s, 2, y, fmt.Sprintf("%-5s %-8s %-11d %-9d", "UDP", "0/0", 0, udpListeners))
	y++
	y++
	y++
	PutString(s, 2, y,
		TruncateToWidth(
			fmt.Sprintf(
				"IO bytes: %s",
				FormatIOBytes(cand.Proc.IOReadBytes, cand.Proc.IOWriteBytes, cand.Proc.IOOtherBytes),
			),
			w-2,
		),
	)
	y++
	PutString(s, 2, y,
		TruncateToWidth(
			fmt.Sprintf(
				"IO rate:  %s",
				FormatIORate(cand.Proc.IOReadBps, cand.Proc.IOWriteBps, cand.Proc.IOOtherBps),
			),
			w-2,
		),
	)
	y++

	if y < h-3 {
		y++
		y = drawInspectorASNSection(s, cand, y, w, h)
	}

	if app.InspectExplain && y < h-3 {
		y++
		y = drawInspectorExplainSection(s, cand, y, w, h)
	}
	y++

	if (len(cand.Conns) > 0 || len(cand.UDPListeners) > 0) && y < h-3 {
		PutString(s, 2, y, "Proto Local                 Remote                State        Scope")
		y++
		PutString(s, 2, y, "----- --------------------  --------------------  -----------  -------")
		y++

		seen := make(map[string]struct{})

		for _, cn := range cand.Conns {
			if y >= h-2 {
				break
			}

			scope := ""
			if cn.RemoteAddress != "" &&
				!shared.IsWildcardIP(cn.RemoteAddress) &&
				!shared.IsLoopbackIP(cn.RemoteAddress) {

				if shared.IsInternalIP(cn.RemoteAddress) {
					scope = "internal"
				} else {
					scope = "external"
				}
			}

			l := fmt.Sprintf("%s:%d", cn.LocalAddress, cn.LocalPort)
			r := fmt.Sprintf("%s:%d", cn.RemoteAddress, cn.RemotePort)
			key := fmt.Sprintf("tcp|%s|%s|%s|%s", l, r, cn.State, scope)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}

			line := fmt.Sprintf("%-5s %-20s %-20s %-11s %-7s", "TCP", l, r, cn.State, scope)
			PutString(s, 2, y, TruncateToWidth(line, w-2))
			y++
		}

		for _, ul := range cand.UDPListeners {
			if y >= h-2 {
				break
			}

			l := fmt.Sprintf("%s:%d", ul.LocalAddress, ul.LocalPort)
			r := "*:*"
			scope := shared.ScopeLabelForLocalAddress(ul.LocalAddress)
			key := fmt.Sprintf("udp|%s|%s|%s", l, r, scope)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			line := fmt.Sprintf("%-5s %-20s %-20s %-11s %-7s", "UDP", l, r, "LISTEN", scope)
			PutString(s, 2, y, TruncateToWidth(line, w-2))
			y++
		}
	}

	if app.LastError != "" && h >= 2 {
		PutString(s, 0, h-2, TruncateToWidth("Status: "+app.LastError, w))
	}

	if app.ConfirmKill && app.ConfirmKillKey == app.InspectKey && time.Now().Before(app.ConfirmKillDeadline) && h >= 2 {
		msg := fmt.Sprintf(
			"Confirm kill %s (%s): press k again or y within %s",
			app.InspectKey,
			cand.Proc.Name,
			app.ConfirmKillTimeout,
		)
		PutString(s, 0, h-2, TruncateToWidth(msg, w))
	}

	explainState := "off"
	if app.InspectExplain {
		explainState = "on"
	}
	PutString(s, 0, h-1, TruncateToWidth(fmt.Sprintf("ESC return | x explain %s | k kill | q quit", explainState), w))
}

func drawInspectorASNSection(s tcell.Screen, cand *shared.Candidate, y, w, h int) int {
	maxY := h - 3
	if y > maxY {
		return y
	}

	PutString(s, 2, y, TruncateToWidth("ASN orgs", w-2))
	y++
	if y > maxY {
		return y
	}

	orgs, pending, failed := inspectorExternalOrgs(cand)
	if len(orgs) == 0 {
		msg := "(none)"
		switch {
		case pending > 0:
			msg = "(resolving...)"
		case failed > 0:
			msg = "(unresolved)"
		}
		PutString(s, 4, y, TruncateToWidth(msg, w-4))
		y++
		return y
	}

	for _, org := range orgs {
		if y > maxY {
			return y
		}
		PutString(s, 4, y, TruncateToWidth("- "+org, w-4))
		y++
	}
	if pending > 0 && y <= maxY {
		PutString(s, 4, y, TruncateToWidth(fmt.Sprintf("+ resolving %d destination(s)...", pending), w-4))
		y++
	}
	if failed > 0 && y <= maxY {
		PutString(s, 4, y, TruncateToWidth(fmt.Sprintf("+ unresolved %d destination(s)", failed), w-4))
		y++
	}
	return y
}

func drawInspectorExplainSection(s tcell.Screen, cand *shared.Candidate, y, w, h int) int {
	maxY := h - 3
	if y > maxY {
		return y
	}

	PutString(s, 2, y, TruncateToWidth("Explain", w-2))
	y++
	if y > maxY {
		return y
	}

	PutString(s, 4, y, TruncateToWidth(
		fmt.Sprintf(
			"Verified %v | Strong evidence %v",
			cand.TrafficVerified, cand.StrongEvidence,
		),
		w-4,
	))
	y++
	if y > maxY {
		return y
	}

	PutString(s, 4, y, TruncateToWidth(
		fmt.Sprintf(
			"Flows out=%d int=%d ext=%d lo=%d | in=%d | long=%d short=%d",
			cand.OutTotal, cand.OutInternal, cand.OutExternal, cand.OutLoopback, cand.InboundTotal, cand.OutLongLived, cand.OutShortLived,
		),
		w-4,
	))
	y++
	if y > maxY {
		return y
	}

	controlLine := "Control channel: (none)"
	if cand.ControlChannel != nil {
		controlLine = fmt.Sprintf(
			"Control channel: %s:%d -> %s:%d (%s, %ds)",
			cand.ControlChannel.LocalAddress,
			cand.ControlChannel.LocalPort,
			cand.ControlChannel.RemoteAddress,
			cand.ControlChannel.RemotePort,
			cand.ControlChannel.State,
			cand.ControlDurationSeconds,
		)
	}
	PutString(s, 4, y, TruncateToWidth(controlLine, w-4))
	y++

	y = drawInspectorStringList(s, 4, y, w-4, maxY, "Reasons", cand.Reasons)
	if y <= maxY {
		y = drawInspectorStringList(s, 4, y, w-4, maxY, "Signals", cand.Signals)
	}
	return y
}

func drawInspectorStringList(s tcell.Screen, x, y, width, maxY int, title string, items []string) int {
	if y > maxY {
		return y
	}
	PutString(s, x, y, TruncateToWidth(title+":", width))
	y++
	if y > maxY {
		return y
	}

	if len(items) == 0 {
		PutString(s, x+2, y, TruncateToWidth("(none)", width-2))
		y++
		return y
	}

	for _, item := range items {
		if y > maxY {
			break
		}
		PutString(s, x+2, y, TruncateToWidth("- "+item, width-2))
		y++
	}
	return y
}

func DrawWhitelist(app *shared.AppState) {
	s := app.Screen
	s.Clear()

	w, _ := s.Size()
	drawHeader(s, w,
		"Whitelist manager | UP/DOWN select | d remove | ESC back | q quit",
		app.LastError,
	)

	y := 5
	if len(app.WhitelistItems) == 0 {
		PutString(s, 0, y, "whitelist is empty")
		return
	}

	for i, entry := range app.WhitelistItems {
		arrow := " "
		if i == app.WhitelistSelected {
			arrow = ">"
		}
		line := fmt.Sprintf("%s %s", arrow, entry)
		PutString(s, 0, y, TruncateToWidth(line, w))
		y++
	}
}
