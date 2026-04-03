package render

import (
	"fmt"
	"strings"
	"time"

	"proxywatch/internal/shared"
	"proxywatch/internal/ui/common"

	"github.com/gdamore/tcell/v2"
)

func DrawWhitelist(app *shared.AppState) {
	s := app.Screen
	common.ClearScreen(s)

	w, h := s.Size()
	defer drawWhitelistOverlays(app, w, h)
	common.DrawPanel(s, 0, 0, w, 3, "Whitelist", "proxywatch")
	common.PutStringStyle(s, 2, 1, "? help", common.StyleDim)
	common.PutStringStyle(s, 10, 1, common.TruncateToWidth("UTC: "+time.Now().UTC().Format(common.UTCTimeFormat), max(0, w-12)), common.StyleText)
	common.PutStringStyle(s, max(2, w-16), 1, "Entries: "+fmt.Sprintf("%d", len(app.WhitelistItems)), common.StyleCyan)

	setupY := 3
	setupH := 5
	if setupY+setupH >= h {
		setupH = max(4, h-setupY-1)
	}

	selectedProc := "(select below)"
	if c, ok := selectedWhitelistProcessCandidate(app); ok && c.Proc != nil {
		selectedProc = shared.DisplayProcessName(c.Proc)
		if c.Proc.Pid > 0 {
			selectedProc = fmt.Sprintf("%s (pid %d)", selectedProc, c.Proc.Pid)
		}
	}
	common.DrawPanel(s, 0, setupY, w, setupH, "ACTIONS", "")
	drawWhitelistSetupRow(s, w, setupY+1, app.WhitelistField == whitelistFieldAdd, "Add", "Whitelist: "+selectedProc)
	selectedEntry := "(select below)"
	if len(app.WhitelistItems) > 0 && app.WhitelistSelected >= 0 && app.WhitelistSelected < len(app.WhitelistItems) {
		selectedEntry = FormatWhitelistEntry(app.WhitelistItems[app.WhitelistSelected], w-24)
	}
	drawWhitelistSetupRow(s, w, setupY+2, app.WhitelistField == whitelistFieldRemove, "Remove", "Remove: "+selectedEntry)
	if setupY+3 < setupY+setupH-1 {
		common.PutStringStyle(s, 2, setupY+3, common.TruncateToWidth("UP/DOWN navigate  |  LEFT/RIGHT browse lists  |  ENTER execute action", w-4), common.StyleMuted)
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
	common.DrawPanel(s, 0, processY, w, processH, "PROCESSES", fmt.Sprintf("%d/%d", max(0, app.WhitelistProcessSelected+1), len(procs)))
	if len(procs) == 0 {
		common.PutStringStyle(s, 2, processY+1, common.TruncateToWidth("No process snapshot is available yet.", w-4), common.StyleText)
		common.PutStringStyle(s, 2, processY+2, common.TruncateToWidth("Wait for refresh or return to dashboard briefly.", w-4), common.StyleMuted)
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
			role := common.NormalizeDashboardRole(c.Role)
			stateVal := "watch"
			if c.ActiveProxying {
				stateVal = "active"
			} else if c.StrongEvidence {
				stateVal = "strong"
			}
			prefix := " "
			st := common.StyleText
			rowSelected := i == app.WhitelistProcessSelected
			if rowSelected {
				prefix = ">"
				st = common.StyleTextB
			}
			common.FillSelectedRowBar(s, y, 2, w-3, rowSelected)
			line := fmt.Sprintf("%s %-5s %-6d %-*s %-8s %-6s", prefix, common.TruncateToWidth(host, 5), pid, nameW, common.ClipToWidth(name, nameW), common.TruncateToWidth(role, 8), common.TruncateToWidth(stateVal, 6))
			common.PutStringStyle(s, 2, y, common.ClipToWidth(line, w-4), common.ApplySelectedRowStyle(st, rowSelected))
			y++
		}
	}

	common.DrawPanel(s, 0, entriesY, w, entriesH, "WHITELIST ENTRIES", fmt.Sprintf("%d/%d", max(0, app.WhitelistSelected+1), len(app.WhitelistItems)))
	if len(app.WhitelistItems) == 0 {
		common.PutStringStyle(s, 2, entriesY+1, common.TruncateToWidth("No whitelist entries are stored yet.", w-4), common.StyleText)
		common.PutStringStyle(s, 2, entriesY+2, common.TruncateToWidth("Select a process above and use Add.", w-4), common.StyleMuted)
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
		entry := FormatWhitelistEntry(app.WhitelistItems[i], w-8)
		prefix := " "
		st := common.StyleText
		rowSelected := i == app.WhitelistSelected
		if rowSelected {
			prefix = ">"
			st = common.StyleTextB
		}
		common.FillSelectedRowBar(s, y, 2, w-3, rowSelected)
		common.PutStringStyle(s, 2, y, common.TruncateToWidth(prefix+" "+entry, w-4), common.ApplySelectedRowStyle(st, rowSelected))
		y++
	}

}

func drawWhitelistOverlays(app *shared.AppState, w, h int) {
	if !app.WhitelistShowHelp {
		return
	}
	opts := common.WhitelistMenuHelpOptions()
	common.DrawMenuPanel(app.Screen, w, h, "Whitelist Menu", opts, common.ClampIndex(app.WhitelistHelpIndex, len(opts)), "")
}

func drawWhitelistSetupRow(s tcell.Screen, w, y int, active bool, label, value string) {
	prefix := " "
	labelStyle := common.StyleMuted
	valueStyle := common.StyleText
	prefixStyle := common.StyleText
	if active {
		prefix = ">"
		valueStyle = common.StyleTextB
		prefixStyle = common.StyleTextB
	}
	labelText := fmt.Sprintf("%s %-9s", prefix, label+":")
	labelText = common.TruncateToWidth(labelText, w-4)
	common.FillSelectedRowBar(s, y, 2, w-3, active)
	common.PutStringStyle(s, 2, y, labelText, common.ApplySelectedRowStyle(labelStyle, active))
	valueX := 2 + len(labelText) + 2
	if valueX < w-2 {
		common.PutStringStyle(s, valueX, y, common.TruncateToWidth(strings.TrimSpace(value), w-valueX-2), common.ApplySelectedRowStyle(valueStyle, active))
	}
	common.PutStringStyle(s, 2, y, string(prefix), common.ApplySelectedRowStyle(prefixStyle, active))
}

func FormatWhitelistEntry(entry string, width int) string {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return "(none stored)"
	}
	parts := strings.SplitN(entry, "|", 2)
	if len(parts) != 2 {
		return common.TruncateToWidth(entry, width)
	}
	host := strings.TrimSpace(parts[0])
	spec := strings.TrimSpace(parts[1])
	switch {
	case strings.HasPrefix(spec, "path:"):
		spec = strings.TrimPrefix(spec, "path:")
		return common.TruncateToWidth(fmt.Sprintf("%s  path  %s", host, spec), width)
	case strings.HasPrefix(spec, "name:"):
		spec = strings.TrimPrefix(spec, "name:")
		return common.TruncateToWidth(fmt.Sprintf("%s  name  %s", host, spec), width)
	default:
		return common.TruncateToWidth(entry, width)
	}
}
