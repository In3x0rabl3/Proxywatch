package render

import (
	"fmt"
	"strings"
	"time"

	"proxywatch/internal/contour"
	"proxywatch/internal/shared"
	"proxywatch/internal/ui/common"

	"github.com/gdamore/tcell/v2"
)

func DrawContour(app *shared.AppState) {
	s := app.Screen
	common.ClearScreen(s)
	cursorVisible := false
	cursorX, cursorY := 0, 0

	w, h := s.Size()
	common.DrawPanel(s, 0, 0, w, 4, "Contour", "proxywatch")
	common.PutStringStyle(s, 2, 1, "? help", common.StyleDim)
	utcLabel := "UTC: "
	utcValue := time.Now().UTC().Format(common.UTCTimeFormat)
	blockX := max(2, w-2-len(utcLabel)-len(utcValue))
	common.PutStringStyle(s, blockX, 1, utcLabel, common.StyleCyanB)
	common.PutStringStyle(s, blockX+len(utcLabel), 1, utcValue, common.StyleTextB)
	if app.ContourAnalyzing {
		msg := fmt.Sprintf("%s Analyzing contour findings... elapsed %s", common.SpinnerFrame(), common.SpinnerElapsed(app.ContourStartedAt).String())
		if contour.NormalizeProbeRole(app.ContourProbeRole) == contour.ProbeRoleListen {
			msg = fmt.Sprintf("%s Contour listener active... elapsed %s", common.SpinnerFrame(), common.SpinnerElapsed(app.ContourStartedAt).String())
		}
		common.PutStringStyle(s, 2, 2, common.TruncateToWidth(msg, w-4), common.StyleWarn)
	} else if app.ContourActive {
		msg := fmt.Sprintf("%s Collecting contour samples... elapsed %s", common.SpinnerFrame(), common.SpinnerElapsed(app.ContourStartedAt).String())
		if contour.NormalizeProbeRole(app.ContourProbeRole) == contour.ProbeRoleListen {
			msg = fmt.Sprintf("%s Preparing contour listener... elapsed %s", common.SpinnerFrame(), common.SpinnerElapsed(app.ContourStartedAt).String())
		} else if contour.NormalizeProbeMode(app.ContourProbeMode) != contour.ProbeModeOff {
			msg = fmt.Sprintf("%s Preparing contour probe... elapsed %s", common.SpinnerFrame(), common.SpinnerElapsed(app.ContourStartedAt).String())
		}
		common.PutStringStyle(s, 2, 2, common.TruncateToWidth(msg, w-4), common.StyleWarn)
	}

	setupY := 4
	setupH := 8
	if setupY+setupH >= h {
		setupH = max(6, h-setupY-1)
	}
	common.DrawPanel(s, 0, setupY, w, setupH, "CONTOUR SETUP", "")

	rows := []struct {
		field int
		label string
		value string
	}{
		{contourFieldEndpoint, "Target", nonEmptyValue(strings.TrimSpace(app.ContourProbeEndpoint), "127.0.0.1")},
		{contourFieldOutput, "Output", nonEmptyValue(strings.TrimSpace(app.ContourOutput), contour.DefaultOutputPath())},
		{contourFieldAction, "Action", contourActionLabel(app)},
	}
	for i, row := range rows {
		y := setupY + 1 + i
		if y >= setupY+setupH-1 {
			break
		}
		rowSelected := row.field == app.ContourField
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
		common.FillSelectedRowBar(s, y, 2, w-3, rowSelected)
		labelText := fmt.Sprintf("%s %-8s", prefix, row.label+":")
		labelText = common.TruncateToWidth(labelText, w-4)
		common.PutStringStyle(s, 2, y, labelText, common.ApplySelectedRowStyle(labelStyle, rowSelected))
		valueX := 2 + len(labelText) + 2
		if valueX < w-2 {
			valueW := max(0, w-valueX-2)
			common.PutStringStyle(s, valueX, y, common.TruncateToWidth(value, valueW), common.ApplySelectedRowStyle(valueStyle, rowSelected))
			if rowSelected && app.ContourEditing && (row.field == contourFieldEndpoint || row.field == contourFieldOutput) && !app.ContourShowHelp && !app.ContourShowMenu {
				cursorVisible = true
				cursorX = common.TextCursorX(valueX, value, valueW)
				cursorY = y
			}
		}
		common.PutStringStyle(s, 2, y, string(prefix), common.ApplySelectedRowStyle(prefixStyle, rowSelected))
		common.DrawEditingTag(s, y, w, rowSelected && app.ContourEditing && (row.field == contourFieldEndpoint || row.field == contourFieldOutput))
	}

	reportY := setupY + setupH
	reportH := h - reportY
	if reportH < 4 {
		drawContourOverlays(app, w, h)
		return
	}
	panelLabel := "LATEST REPORT"
	lines := app.ContourReportLines
	if (app.ContourActive || app.ContourAnalyzing) && len(app.ContourProgressLines) > 0 {
		panelLabel = "LIVE"
		lines = app.ContourProgressLines
		visible := reportH - 2
		if visible > 0 && len(lines) > visible {
			app.ContourReportScroll = len(lines) - visible
		}
	}
	common.DrawPanel(s, 0, reportY, w, reportH, panelLabel, "Contour")
	row := reportY + 1
	if len(lines) == 0 && !app.ContourActive && !app.ContourAnalyzing {
		app.ContourReportMaxScroll = 0
		common.PutStringStyle(s, 2, row, common.TruncateToWidth("No contour report has been generated yet.", w-4), common.StyleText)
		row++
		if row < reportY+reportH-1 {
			common.PutStringStyle(s, 2, row, common.TruncateToWidth("Start a contour run to discover tunnel and escape patterns.", w-4), common.StyleMuted)
		}
	} else if len(lines) == 0 {
		common.PutStringStyle(s, 2, row, common.TruncateToWidth("Starting...", w-4), common.StyleMuted)
	} else {
		visible := reportH - 2
		if visible < 1 {
			visible = 1
		}
		maxScroll := len(lines) - visible
		if maxScroll < 0 {
			maxScroll = 0
		}
		if app.ContourReportScroll < 0 {
			app.ContourReportScroll = 0
		}
		if app.ContourReportScroll > maxScroll {
			app.ContourReportScroll = maxScroll
		}
		app.ContourReportMaxScroll = maxScroll
		start := app.ContourReportScroll
		end := min(len(lines), start+visible)
		for idx := start; idx < end && row < reportY+reportH-1; idx++ {
			common.PutStringStyle(s, 2, row, common.TruncateToWidth(lines[idx], w-4), contourReportLineStyle(lines[idx]))
			row++
		}
		common.PutStringStyle(s, max(2, w-26), reportY+reportH-1, fmt.Sprintf("Report %d-%d of %d", start+1, end, len(lines)), common.StyleCyanB)
	}

	now := time.Now()
	if app.ContourStatusText != "" && now.Before(app.ContourStatusUntil) {
		st := common.StyleText
		if app.ContourStatusError {
			st = common.StyleAlert
		}
		common.PutStringStyle(s, 2, max(reportY+1, h-2), common.TruncateToWidth(app.ContourStatusText, w-4), st)
	}
	if cursorVisible {
		common.ShowInputCursor(s, cursorX, cursorY)
	}

	drawContourOverlays(app, w, h)
}

func contourActionLabel(app *shared.AppState) string {
	depthLabel := contour.ProbeModeLabel(app.ContourProbeMode)
	if app.ContourAnalyzing {
		return "Stop (analyzing)"
	}
	if app.ContourActive {
		if app.ContourUntil.IsZero() {
			return "Stop (collecting)"
		}
		remaining := time.Until(app.ContourUntil).Round(time.Second)
		if remaining < 0 {
			remaining = 0
		}
		if remaining == 0 {
			return "Stop (starting analysis)"
		}
		return "Stop (" + remaining.String() + " left)"
	}
	return "Start contour (" + depthLabel + ")"
}

func contourReportLineStyle(line string) tcell.Style {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return common.StyleText
	}

	if strings.HasPrefix(trimmed, "ACTIVE") {
		return common.StyleAlertB
	}
	if strings.HasPrefix(trimmed, "STRONG") {
		return common.StyleAlert
	}
	if strings.HasPrefix(trimmed, "WATCH") {
		return common.StyleWarn
	}

	switch trimmed {
	case "tunnels", "exfil", "services", "egress",
		"Activity", "Listener Ports":
		return common.StyleTextB
	}

	if strings.Contains(trimmed, "[PIVOT]") {
		return common.StyleWarn
	}

	if strings.HasPrefix(trimmed, "[-]") {
		return common.StyleAlert
	}
	if strings.HasPrefix(trimmed, "[*]") || strings.HasPrefix(trimmed, "[+]") {
		return common.StyleDim
	}

	if strings.HasPrefix(trimmed, "output") {
		return common.StyleMuted
	}

	return common.StyleText
}

func drawContourOverlays(app *shared.AppState, w, h int) {
	if app.ContourShowHelp {
		opts := common.ContourMenuHelpOptions()
		common.DrawMenuPanel(app.Screen, w, h, "Contour Menu", opts, common.ClampIndex(app.ContourHelpIndex, len(opts)), "")
	}
	if app.ContourShowMenu {
		common.DrawMenuPanel(
			app.Screen,
			w,
			h,
			app.ContourMenuTitle,
			app.ContourMenuOptions,
			common.ClampIndex(app.ContourMenuIndex, len(app.ContourMenuOptions)),
			"Enter apply   Esc close",
		)
	}
}
