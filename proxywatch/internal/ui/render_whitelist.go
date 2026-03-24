package ui

import (
	"fmt"
	"strings"
	"time"

	"proxywatch/internal/shared"

	"github.com/gdamore/tcell/v2"
)

func DrawWhitelist(app *shared.AppState) {
	s := app.Screen
	clearScreen(s)

	w, h := s.Size()
	defer drawWhitelistOverlays(app, w, h)
	drawPanel(s, 0, 0, w, 3, "Whitelist", "proxywatch")
	PutStringStyle(s, 2, 1, "? help", styleDim)
	PutStringStyle(s, 10, 1, TruncateToWidth("UTC: "+time.Now().UTC().Format(utcTimeFormat), max(0, w-12)), styleText)
	PutStringStyle(s, max(2, w-16), 1, "Entries: "+fmt.Sprintf("%d", len(app.WhitelistItems)), styleCyan)

	setupY := 3
	setupH := 7
	if setupY+setupH >= h {
		setupH = max(5, h-setupY-1)
	}
	drawPanel(s, 0, setupY, w, setupH, "WHITELIST SETUP", "")

	selectedProc := "none"
	if c, ok := selectedWhitelistProcessCandidate(app); ok && c.Proc != nil {
		selectedProc = shared.DisplayProcessName(c.Proc)
	}
	selectedEntry := "(none stored)"
	if len(app.WhitelistItems) > 0 && app.WhitelistSelected >= 0 && app.WhitelistSelected < len(app.WhitelistItems) {
		selectedEntry = formatWhitelistEntry(app.WhitelistItems[app.WhitelistSelected], w-20)
	}

	drawWhitelistSetupRow(s, w, setupY+1, app.WhitelistField == whitelistFieldProcess, "Process", selectedProc)
	drawWhitelistSetupRow(s, w, setupY+2, app.WhitelistField == whitelistFieldEntry, "Entry", selectedEntry)
	drawWhitelistSetupRow(s, w, setupY+3, app.WhitelistField == whitelistFieldAdd, "Add", "Whitelist selected process")
	drawWhitelistSetupRow(s, w, setupY+4, app.WhitelistField == whitelistFieldRemove, "Remove", "Unwhitelist selected entry")
	if setupY+5 < setupY+setupH-1 {
		PutStringStyle(s, 2, setupY+5, TruncateToWidth("Tab/Shift-Tab or Up/Down: change setup row. Left/Right or J/K: browse focused list.", w-4), styleMuted)
	}

	processY := setupY + setupH
	remaining := h - processY
	if remaining <= 4 {
		return
	}
	processH := max(6, remaining/2)
	if processY+processH > h-4 {
		processH = max(4, h-processY-4)
	}
	if processH < 4 {
		processH = 4
	}
	entriesY := processY + processH
	entriesH := h - entriesY
	if entriesH < 4 {
		entriesH = 4
		entriesY = max(processY+1, h-entriesH)
		processH = max(4, entriesY-processY)
	}

	procs := whitelistProcessCandidates(app)
	drawPanel(s, 0, processY, w, processH, "PROCESS SNAPSHOT", fmt.Sprintf("%d/%d", max(0, app.WhitelistProcessSelected+1), len(procs)))
	if len(procs) == 0 {
		PutStringStyle(s, 2, processY+1, TruncateToWidth("No process snapshot is available yet.", w-4), styleText)
		PutStringStyle(s, 2, processY+2, TruncateToWidth("Wait for refresh or return to dashboard briefly.", w-4), styleMuted)
	} else {
		if app.WhitelistProcessSelected < 0 {
			app.WhitelistProcessSelected = 0
		}
		if app.WhitelistProcessSelected >= len(procs) {
			app.WhitelistProcessSelected = len(procs) - 1
		}
		viewRows := max(1, processH-2)
		if app.WhitelistProcessSelected < app.WhitelistProcessOffset {
			app.WhitelistProcessOffset = app.WhitelistProcessSelected
		}
		if app.WhitelistProcessSelected >= app.WhitelistProcessOffset+viewRows {
			app.WhitelistProcessOffset = app.WhitelistProcessSelected - viewRows + 1
		}
		maxOffset := max(0, len(procs)-viewRows)
		if app.WhitelistProcessOffset > maxOffset {
			app.WhitelistProcessOffset = maxOffset
		}
		if app.WhitelistProcessOffset < 0 {
			app.WhitelistProcessOffset = 0
		}

		y := processY + 1
		baseWidth := len(fmt.Sprintf("%s %-5s %-6d %-8s %-6s", ">", "host", 999999, "outbound", "strong"))
		nameW := max(8, w-4-baseWidth-1)
		for i := app.WhitelistProcessOffset; i < len(procs) && y < processY+processH-1; i++ {
			c := procs[i]
			host := shared.DisplayHost(c.Host)
			pid := 0
			name := "(unknown)"
			if c.Proc != nil {
				pid = c.Proc.Pid
				name = shared.DisplayProcessName(c.Proc)
			}
			role := normalizeDashboardRole(c.Role)
			state := "watch"
			if c.ActiveProxying {
				state = "active"
			} else if c.StrongEvidence {
				state = "strong"
			}
			prefix := " "
			st := styleText
			rowSelected := i == app.WhitelistProcessSelected
			if rowSelected {
				prefix = ">"
				st = styleTextB
			}
			fillSelectedRowBar(s, y, 2, w-3, rowSelected)
			line := fmt.Sprintf("%s %-5s %-6d %-*s %-8s %-6s", prefix, TruncateToWidth(host, 5), pid, nameW, ClipToWidth(name, nameW), TruncateToWidth(role, 8), TruncateToWidth(state, 6))
			PutStringStyle(s, 2, y, ClipToWidth(line, w-4), applySelectedRowStyle(st, rowSelected))
			y++
		}
	}

	drawPanel(s, 0, entriesY, w, entriesH, "SAVED ENTRIES", fmt.Sprintf("%d/%d", max(0, app.WhitelistSelected+1), len(app.WhitelistItems)))
	if len(app.WhitelistItems) == 0 {
		PutStringStyle(s, 2, entriesY+1, TruncateToWidth("No whitelist entries are stored yet.", w-4), styleText)
		PutStringStyle(s, 2, entriesY+2, TruncateToWidth("Select a process above and use Add.", w-4), styleMuted)
		return
	}
	if app.WhitelistSelected < 0 {
		app.WhitelistSelected = 0
	}
	if app.WhitelistSelected >= len(app.WhitelistItems) {
		app.WhitelistSelected = len(app.WhitelistItems) - 1
	}
	viewRows := max(1, entriesH-2)
	if app.WhitelistSelected < app.WhitelistListOffset {
		app.WhitelistListOffset = app.WhitelistSelected
	}
	if app.WhitelistSelected >= app.WhitelistListOffset+viewRows {
		app.WhitelistListOffset = app.WhitelistSelected - viewRows + 1
	}
	maxOffset := max(0, len(app.WhitelistItems)-viewRows)
	if app.WhitelistListOffset > maxOffset {
		app.WhitelistListOffset = maxOffset
	}
	if app.WhitelistListOffset < 0 {
		app.WhitelistListOffset = 0
	}
	y := entriesY + 1
	for i := app.WhitelistListOffset; i < len(app.WhitelistItems) && y < entriesY+entriesH-1; i++ {
		entry := formatWhitelistEntry(app.WhitelistItems[i], w-8)
		prefix := " "
		st := styleText
		rowSelected := i == app.WhitelistSelected
		if rowSelected {
			prefix = ">"
			st = styleTextB
		}
		fillSelectedRowBar(s, y, 2, w-3, rowSelected)
		PutStringStyle(s, 2, y, TruncateToWidth(prefix+" "+entry, w-4), applySelectedRowStyle(st, rowSelected))
		y++
	}

}

func drawWhitelistOverlays(app *shared.AppState, w, h int) {
	if !app.WhitelistShowHelp {
		return
	}
	opts := whitelistMenuHelpOptions()
	drawMenuPanel(app.Screen, w, h, "Whitelist Menu", opts, clampIndex(app.WhitelistHelpIndex, len(opts)), "")
}

func drawWhitelistSetupRow(s tcell.Screen, w, y int, active bool, label, value string) {
	prefix := " "
	labelStyle := styleMuted
	valueStyle := styleText
	prefixStyle := styleText
	if active {
		prefix = ">"
		valueStyle = styleTextB
		prefixStyle = styleTextB
	}
	labelText := fmt.Sprintf("%s %-9s", prefix, label+":")
	labelText = TruncateToWidth(labelText, w-4)
	fillSelectedRowBar(s, y, 2, w-3, active)
	PutStringStyle(s, 2, y, labelText, applySelectedRowStyle(labelStyle, active))
	valueX := 2 + len(labelText) + 2
	if valueX < w-2 {
		PutStringStyle(s, valueX, y, TruncateToWidth(strings.TrimSpace(value), w-valueX-2), applySelectedRowStyle(valueStyle, active))
	}
	PutStringStyle(s, 2, y, string(prefix), applySelectedRowStyle(prefixStyle, active))
}

func formatWhitelistEntry(entry string, width int) string {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return "(none stored)"
	}
	parts := strings.SplitN(entry, "|", 2)
	if len(parts) != 2 {
		return TruncateToWidth(entry, width)
	}
	host := strings.TrimSpace(parts[0])
	spec := strings.TrimSpace(parts[1])
	switch {
	case strings.HasPrefix(spec, "path:"):
		spec = strings.TrimPrefix(spec, "path:")
		return TruncateToWidth(fmt.Sprintf("%s  path  %s", host, spec), width)
	case strings.HasPrefix(spec, "name:"):
		spec = strings.TrimPrefix(spec, "name:")
		return TruncateToWidth(fmt.Sprintf("%s  name  %s", host, spec), width)
	default:
		return TruncateToWidth(entry, width)
	}
}
