package render

import (
	"fmt"
	"strings"
	"time"

	"proxywatch/internal/calibration"
	"proxywatch/internal/shared"
	"proxywatch/internal/siem"
	"proxywatch/internal/ui/common"

	"github.com/gdamore/tcell/v2"
)

func DrawSIEM(app *shared.AppState) {
	s := app.Screen
	common.ClearScreen(s)
	cursorVisible := false
	cursorX, cursorY := 0, 0

	w, h := s.Size()
	common.DrawPanel(s, 0, 0, w, 4, "SIEM", "proxywatch")
	common.PutStringStyle(s, 2, 1, "? help", common.StyleDim)
	utcLabel := "UTC: "
	utcValue := time.Now().UTC().Format(common.UTCTimeFormat)
	blockX := max(2, w-2-len(utcLabel)-len(utcValue))
	common.PutStringStyle(s, blockX, 1, utcLabel, common.StyleCyanB)
	common.PutStringStyle(s, blockX+len(utcLabel), 1, utcValue, common.StyleTextB)

	_ = calibration.DetectProviderAccess()
	provider := calibration.ProviderLabel(app.SIEMProvider)
	if app.SIEMGenerating {
		elapsed := time.Since(app.SIEMStartedAt).Round(time.Second)
		if elapsed < 0 {
			elapsed = 0
		}
		frames := []string{"-", "\\", "|", "/"}
		frame := frames[int(time.Now().UnixNano()/int64(250*time.Millisecond))%len(frames)]
		msg := fmt.Sprintf("%s Generating SIEM output... elapsed %s", frame, elapsed.String())
		common.PutStringStyle(s, 2, 2, common.TruncateToWidth(msg, w-4), common.StyleWarn)
	}

	genY := 4
	genH := 9
	if genY+genH >= h {
		genH = max(7, h-genY-1)
	}
	common.DrawPanel(s, 0, genY, w, genH, "SIEM SETUP", "")
	sourceValue := "(none found - run Calibrate)"
	if len(app.SIEMSourceReports) > 0 {
		selected := nonEmptySIEMValue(app.SIEMSourceReport, app.SIEMSourceReports[0])
		sourceValue = fmt.Sprintf("%s (%d found)", selected, len(app.SIEMSourceReports))
	}
	genRows := []struct {
		field int
		label string
		value string
	}{
		{siemFieldSourceReport, "Source", sourceValue},
		{siemFieldProvider, "Provider", provider},
		{siemFieldModel, "Model", nonEmptySIEMValue(app.SIEMModel, calibration.DefaultModel(app.SIEMProvider))},
		{siemFieldReportOutput, "Report out", nonEmptySIEMValue(app.SIEMReportPath, siem.DefaultSIEMReportPath())},
		{siemFieldJSONOutput, "JSON out", nonEmptySIEMValue(app.SIEMExportPath, siem.DefaultSIEMJSONPath())},
		{siemFieldGenerate, "Generate", siemGenerateLabel(app)},
		{siemFieldCalibrate, "Calibrate", "Open Calibration and start a run"},
	}
	for i, row := range genRows {
		y := genY + 1 + i
		if y >= genY+genH-1 {
			break
		}
		rowSelected := app.SIEMField == row.field
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
		labelText := fmt.Sprintf("%s %-11s", prefix, row.label+":")
		labelText = common.TruncateToWidth(labelText, w-4)
		common.PutStringStyle(s, 2, y, labelText, common.ApplySelectedRowStyle(labelStyle, rowSelected))
		valueX := 2 + len(labelText) + 2
		if valueX < w-2 {
			valueW := max(0, w-valueX-2)
			common.PutStringStyle(s, valueX, y, common.TruncateToWidth(value, valueW), common.ApplySelectedRowStyle(valueStyle, rowSelected))
			if rowSelected && app.SIEMEditing && siemFieldEditable(row.field) && !app.SIEMShowHelp && !app.SIEMShowMenu {
				cursorVisible = true
				cursorX = common.TextCursorX(valueX, value, valueW)
				cursorY = y
			}
		}
		common.PutStringStyle(s, 2, y, string(prefix), common.ApplySelectedRowStyle(prefixStyle, rowSelected))
		common.DrawEditingTag(s, y, w, rowSelected && app.SIEMEditing && siemFieldEditable(row.field))
	}

	reportY := genY + genH
	reportH := max(4, h-reportY)
	if reportY+reportH > h {
		reportH = h - reportY
	}
	if reportH >= 3 {
		siemPanelLabel := "REPORT"
		siemLines := app.SIEMReportLines
		if app.SIEMGenerating && len(app.SIEMProgressLines) > 0 {
			siemPanelLabel = "LIVE"
			siemLines = app.SIEMProgressLines
			visible := reportH - 2
			if visible > 0 && len(siemLines) > visible {
				app.SIEMReportScroll = len(siemLines) - visible
			}
		}
		common.DrawPanel(s, 0, reportY, w, reportH, siemPanelLabel, "SIEM")
		row := reportY + 1
		lines := siemLines
		if len(lines) == 0 {
			app.SIEMReportMaxScroll = 0
			common.PutStringStyle(s, 2, row, common.TruncateToWidth("No SIEM report has been generated yet.", w-4), common.StyleText)
			row++
			if row < reportY+reportH-1 {
				common.PutStringStyle(s, 2, row, common.TruncateToWidth("Select Source report and run Generate to build detections + report.", w-4), common.StyleMuted)
				row++
			}
			if row < reportY+reportH-1 && len(app.SIEMSourceReports) == 0 {
				common.PutStringStyle(s, 2, row, common.TruncateToWidth("No calibration reports found. Select Calibrate to create one.", w-4), common.StyleWarn)
			}
		} else {
			visible := reportH - 2
			if visible < 1 {
				visible = 1
			}
			maxScroll := len(lines) - visible
			if maxScroll < 0 {
				maxScroll = 0
			}
			if app.SIEMReportScroll < 0 {
				app.SIEMReportScroll = 0
			}
			if app.SIEMReportScroll > maxScroll {
				app.SIEMReportScroll = maxScroll
			}
			app.SIEMReportMaxScroll = maxScroll
			start := app.SIEMReportScroll
			end := min(len(lines), start+visible)
			for idx := start; idx < end && row < reportY+reportH-1; idx++ {
				line := lines[idx]
				common.PutStringStyle(s, 2, row, common.TruncateToWidth(line, w-4), siemReportLineStyle(line))
				row++
			}
			common.PutStringStyle(s, max(2, w-26), reportY+reportH-1, fmt.Sprintf("Report %d-%d of %d", start+1, end, len(lines)), common.StyleCyanB)
		}
	}

	now := time.Now()
	if app.SIEMStatusText != "" && now.Before(app.SIEMStatusUntil) && h >= 2 {
		st := common.StyleText
		if app.SIEMStatusError {
			st = common.StyleAlert
		}
		common.PutStringStyle(s, 2, h-2, common.TruncateToWidth(app.SIEMStatusText, w-4), st)
	}
	if cursorVisible {
		common.ShowInputCursor(s, cursorX, cursorY)
	}

	drawSIEMOverlays(app, w, h)
}

func siemGenerateLabel(app *shared.AppState) string {
	if app.SIEMGenerating {
		elapsed := common.SpinnerElapsed(app.SIEMStartedAt)
		return fmt.Sprintf("Stop generation (%s elapsed)", elapsed)
	}
	return "Build SIEM detections from calibration data"
}

func siemReportLineStyle(line string) tcell.Style {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return common.StyleText
	}
	switch trimmed {
	case "Detections", "Notes":
		return common.StyleCyanB
	}
	if strings.Contains(trimmed, "[HIGH]") || strings.Contains(trimmed, "[CRITICAL]") {
		return common.StyleAlert
	}
	if strings.Contains(trimmed, "[MEDIUM]") {
		return common.StyleWarn
	}
	if strings.Contains(trimmed, "[LOW]") {
		return common.StyleCyan
	}
	if strings.Contains(trimmed, "Splunk:") || strings.Contains(trimmed, "KQL:") || strings.Contains(trimmed, "ESQL:") {
		return common.StyleMuted
	}
	if strings.Contains(trimmed, "Role:") && strings.Contains(trimmed, "Processes:") {
		return common.StyleMuted
	}
	if strings.Contains(trimmed, "detections") && strings.Contains(trimmed, "candidates") {
		return common.StyleMuted
	}
	if strings.HasPrefix(trimmed, "- ") {
		return common.StyleText
	}
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

func drawSIEMOverlays(app *shared.AppState, w, h int) {
	if app.SIEMShowHelp {
		opts := common.SiemMenuHelpOptions()
		common.DrawMenuPanel(app.Screen, w, h, "SIEM Menu", opts, common.ClampIndex(app.SIEMHelpIndex, len(opts)), "")
	}
	if app.SIEMShowMenu {
		common.DrawMenuPanel(
			app.Screen,
			w,
			h,
			app.SIEMMenuTitle,
			app.SIEMMenuOptions,
			common.ClampIndex(app.SIEMMenuIndex, len(app.SIEMMenuOptions)),
			"Enter apply   Esc close",
		)
	}
}
