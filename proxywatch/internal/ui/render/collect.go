package render

import (
	"fmt"
	"strings"
	"time"

	"proxywatch/internal/shared"
	"proxywatch/internal/ui/common"

	"github.com/gdamore/tcell/v2"
)

func DrawCollect(app *shared.AppState) {
	s := app.Screen
	common.ClearScreen(s)
	cursorVisible := false
	cursorX, cursorY := 0, 0

	w, h := s.Size()
	common.DrawPanel(s, 0, 0, w, 4, "ProxyHound", "proxywatch")
	common.PutStringStyle(s, 2, 1, "? help", common.StyleDim)
	utcLabel := "UTC: "
	utcValue := time.Now().UTC().Format(common.UTCTimeFormat)
	blockX := max(2, w-2-len(utcLabel)-len(utcValue))
	common.PutStringStyle(s, blockX, 1, utcLabel, common.StyleCyanB)
	common.PutStringStyle(s, blockX+len(utcLabel), 1, utcValue, common.StyleTextB)
	if app.CollectActive {
		elapsed := common.SpinnerElapsed(app.CollectStartedAt)
		msg := fmt.Sprintf("%s Collecting ProxyHound data... elapsed %s", common.SpinnerFrame(), elapsed.String())
		common.PutStringStyle(s, 2, 2, common.TruncateToWidth(msg, w-4), common.StyleWarn)
	}

	refreshCollectSources(app)
	ingestMode := strings.TrimSpace(app.LocalHost) == ""

	setupY := 4
	setupH := 8
	if !ingestMode {
		setupH = 7
	}
	common.DrawPanel(s, 0, setupY, w, setupH, "SETUP", "")

	sourceValue := strings.TrimSpace(app.CollectSource)
	if sourceValue == "" {
		sourceValue = "all"
	}
	if strings.EqualFold(sourceValue, "all") {
		sourceValue = fmt.Sprintf("all hosts (%d)", max(0, len(app.CollectSourceOpts)-1))
	}

	lines := []struct {
		field int
		label string
		value string
	}{}
	if ingestMode {
		lines = append(lines, struct {
			field int
			label string
			value string
		}{collectFieldSource, "Hosts", sourceValue})
	}
	lines = append(lines,
		struct {
			field int
			label string
			value string
		}{collectFieldOutput, "Output", app.CollectOutput},
		struct {
			field int
			label string
			value string
		}{collectFieldDuration, "Duration", app.CollectDurationStr},
		struct {
			field int
			label string
			value string
		}{collectFieldAction, "Action", common.CollectActionLabel(app)},
	)
	for i, row := range lines {
		rowSelected := row.field == app.CollectField
		prefix := " "
		labelStyle := common.StyleMuted
		valueStyle := common.StyleText
		prefixStyle := common.StyleText
		if rowSelected {
			prefix = ">"
			valueStyle = common.StyleTextB
			prefixStyle = common.StyleTextB
		}
		value := row.value
		rowY := setupY + 1 + i
		common.FillSelectedRowBar(s, rowY, 2, w-3, rowSelected)
		labelText := fmt.Sprintf("%s %-8s", prefix, row.label+":")
		labelText = common.TruncateToWidth(labelText, w-4)
		common.PutStringStyle(s, 2, rowY, labelText, common.ApplySelectedRowStyle(labelStyle, rowSelected))
		valueX := 2 + len(labelText) + 2
		if valueX < w-2 {
			valueW := max(0, w-valueX-2)
			common.PutStringStyle(s, valueX, rowY, common.TruncateToWidth(value, valueW), common.ApplySelectedRowStyle(valueStyle, rowSelected))
			if rowSelected && app.CollectEditing && row.field == collectFieldOutput && !app.CollectShowHelp && !app.CollectShowMenu {
				cursorVisible = true
				cursorX = common.TextCursorX(valueX, value, valueW)
				cursorY = rowY
			}
		}
		common.PutStringStyle(s, 2, rowY, string(prefix), common.ApplySelectedRowStyle(prefixStyle, rowSelected))
		common.DrawEditingTag(s, rowY, w, rowSelected && app.CollectEditing && row.field == collectFieldOutput)
	}

	reportY := setupY + setupH
	reportH := max(4, h-reportY)
	if reportY+reportH > h {
		reportH = h - reportY
	}
	if reportH >= 3 {
		if app.CollectActive {
			common.DrawPanel(s, 0, reportY, w, reportH, "LIVE", "ProxyHound")
			pRow := reportY + 1
			pLines := CollectLiveLines(app)
			visible := reportH - 2
			if visible < 1 {
				visible = 1
			}
			start := 0
			if len(pLines) > visible {
				start = len(pLines) - visible
			}
			end := min(len(pLines), start+visible)
			for idx := start; idx < end && pRow < reportY+reportH-1; idx++ {
				common.PutStringStyle(s, 2, pRow, common.TruncateToWidth(pLines[idx], w-4), collectProgressLineStyle(pLines[idx]))
				pRow++
			}
		} else {
			common.DrawPanel(s, 0, reportY, w, reportH, "REPORT", "ProxyHound")
			common.PutStringStyle(s, 2, reportY+1, common.TruncateToWidth("No collection report yet. Start a collection to build a graph.", w-4), common.StyleMuted)
		}
	}

	statusY := h - 2
	if statusY < h-1 {
		now := time.Now()
		if app.CollectStatusText != "" && now.Before(app.CollectStatusUntil) {
			st := common.StyleText
			if app.CollectStatusError {
				st = common.StyleAlert
			}
			common.PutStringStyle(s, 2, statusY, common.TruncateToWidth(app.CollectStatusText, w-4), st)
		} else if app.LastError != "" {
			common.PutStringStyle(s, 2, statusY, common.TruncateToWidth(app.LastError, w-4), common.StyleAlert)
		}
	}
	if cursorVisible {
		common.ShowInputCursor(s, cursorX, cursorY)
	}

	drawCollectOverlays(app, w, h)
}

func CollectLiveLines(app *shared.AppState) []string {
	lines := make([]string, 0, 16)
	elapsed := time.Since(app.CollectStartedAt).Round(time.Second)
	remaining := time.Until(app.CollectUntil).Round(time.Second)
	if remaining < 0 {
		remaining = 0
	}

	lines = append(lines, fmt.Sprintf("[*] Collection active  |  elapsed %s  |  %s remaining", elapsed, remaining))
	lines = append(lines, fmt.Sprintf("[+] %d samples collected", len(app.CollectData)))

	type pidInfo struct {
		name string
		role string
	}
	seen := make(map[int]pidInfo)
	roleCounts := map[string]int{}
	for _, c := range app.CollectData {
		if c.Proc == nil {
			continue
		}
		if _, ok := seen[c.Proc.Pid]; !ok {
			seen[c.Proc.Pid] = pidInfo{name: c.Proc.Name, role: shared.RoleFamily(c.Role)}
		}
		roleCounts[shared.RoleFamily(c.Role)]++
	}
	lines = append(lines, fmt.Sprintf("[+] %d unique processes", len(seen)))

	parts := make([]string, 0, 6)
	for _, r := range []string{"control-channel", "control-pivot", "listener", "outbound"} {
		if n := roleCounts[r]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", r, n))
		}
	}
	if len(parts) > 0 {
		lines = append(lines, "[+] "+strings.Join(parts, "  "))
	}

	lines = append(lines, "")
	lines = append(lines, "[*] Recent processes:")
	added := 0
	for i := len(app.CollectData) - 1; i >= 0 && added < 6; i-- {
		c := app.CollectData[i]
		if c.Proc == nil {
			continue
		}
		key := c.Proc.Pid
		info := seen[key]
		delete(seen, key)
		if info.name == "" {
			continue
		}
		lines = append(lines, fmt.Sprintf("    %-9d %-20s %8s", c.Proc.Pid, common.ClipToWidth(info.name, 20), info.role))
		added++
	}

	if len(app.CollectProgressLines) > 0 {
		lines = append(lines, "")
		lines = append(lines, app.CollectProgressLines...)
	}

	return lines
}

func collectProgressLineStyle(line string) tcell.Style {
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "[*]") {
		return common.StyleMuted
	}
	if strings.HasPrefix(trimmed, "[+]") {
		return common.StyleCyan
	}
	if strings.HasPrefix(trimmed, "[-]") {
		return common.StyleAlert
	}
	return common.StyleText
}

func drawCollectOverlays(app *shared.AppState, w, h int) {
	if app.CollectShowHelp {
		opts := common.CollectMenuHelpOptions()
		common.DrawMenuPanel(app.Screen, w, h, "ProxyHound Menu", opts, common.ClampIndex(app.CollectHelpIndex, len(opts)), "")
	}
	if app.CollectShowMenu {
		common.DrawMenuPanel(
			app.Screen,
			w,
			h,
			app.CollectMenuTitle,
			app.CollectMenuOptions,
			common.ClampIndex(app.CollectMenuIndex, len(app.CollectMenuOptions)),
			"Enter apply   Esc close",
		)
	}
}
