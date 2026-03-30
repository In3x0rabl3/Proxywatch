package ui

import (
	"fmt"
	"strings"
	"time"

	"proxywatch/internal/calibration"
	"proxywatch/internal/contour"
	"proxywatch/internal/keystore"
	"proxywatch/internal/shared"
	"proxywatch/internal/siem"

	"github.com/gdamore/tcell/v2"
)

func DrawCollect(app *shared.AppState) {
	s := app.Screen
	clearScreen(s)
	cursorVisible := false
	cursorX, cursorY := 0, 0

	w, h := s.Size()
	drawPanel(s, 0, 0, w, 4, "BloodHound", "proxywatch")
	PutStringStyle(s, 2, 1, "? help", styleDim)
	utcLabel := "UTC: "
	utcValue := time.Now().UTC().Format(utcTimeFormat)
	blockX := max(2, w-2-len(utcLabel)-len(utcValue))
	PutStringStyle(s, blockX, 1, utcLabel, styleCyanB)
	PutStringStyle(s, blockX+len(utcLabel), 1, utcValue, styleTextB)
	if app.CollectActive {
		elapsed := spinnerElapsed(app.CollectStartedAt)
		msg := fmt.Sprintf("%s Collecting BloodHound data... elapsed %s", spinnerFrame(), elapsed.String())
		PutStringStyle(s, 2, 2, TruncateToWidth(msg, w-4), styleWarn)
	}

	refreshCollectSources(app)
	setupY := 4
	setupH := 8
	drawPanel(s, 0, setupY, w, setupH, "COLLECTION SETUP", "")

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
	}{
		{collectFieldSource, "Source", sourceValue},
		{collectFieldOutput, "Output", app.CollectOutput},
		{collectFieldDuration, "Duration", app.CollectDurationStr},
		{collectFieldAction, "Action", collectActionLabel(app)},
	}
	for i, row := range lines {
		rowSelected := row.field == app.CollectField
		prefix := " "
		labelStyle := styleMuted
		valueStyle := styleText
		prefixStyle := styleText
		if rowSelected {
			prefix = ">"
			valueStyle = styleTextB
			prefixStyle = styleTextB
		}
		value := row.value
		rowY := setupY + 1 + i
		fillSelectedRowBar(s, rowY, 2, w-3, rowSelected)
		labelText := fmt.Sprintf("%s %-8s", prefix, row.label+":")
		labelText = TruncateToWidth(labelText, w-4)
		PutStringStyle(s, 2, rowY, labelText, applySelectedRowStyle(labelStyle, rowSelected))
		valueX := 2 + len(labelText) + 2
		if valueX < w-2 {
			valueW := max(0, w-valueX-2)
			PutStringStyle(s, valueX, rowY, TruncateToWidth(value, valueW), applySelectedRowStyle(valueStyle, rowSelected))
			if rowSelected && app.CollectEditing && row.field == collectFieldOutput && !app.CollectShowHelp && !app.CollectShowMenu {
				cursorVisible = true
				cursorX = textCursorX(valueX, value, valueW)
				cursorY = rowY
			}
		}
		PutStringStyle(s, 2, rowY, string(prefix), applySelectedRowStyle(prefixStyle, rowSelected))
		drawEditingTag(s, rowY, w, rowSelected && app.CollectEditing && row.field == collectFieldOutput)
	}

	reportY := setupY + setupH
	reportH := max(4, h-reportY)
	if reportY+reportH > h {
		reportH = h - reportY
	}
	if reportH >= 3 {
		// Show live collection progress during active run.
		if app.CollectActive {
			drawPanel(s, 0, reportY, w, reportH, "LIVE", "BloodHound")
			pRow := reportY + 1
			pLines := collectLiveLines(app)
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
				PutStringStyle(s, 2, pRow, TruncateToWidth(pLines[idx], w-4), collectProgressLineStyle(pLines[idx]))
				pRow++
			}
		} else {
			drawPanel(s, 0, reportY, w, reportH, "REPORT", "BloodHound")
			PutStringStyle(s, 2, reportY+1, TruncateToWidth("No collection report yet. Start a collection to build a graph.", w-4), styleMuted)
		}
	}

	statusY := h - 2
	if statusY < h-1 {
		now := time.Now()
		if app.CollectStatusText != "" && now.Before(app.CollectStatusUntil) {
			st := styleText
			if app.CollectStatusError {
				st = styleAlert
			}
			PutStringStyle(s, 2, statusY, TruncateToWidth(app.CollectStatusText, w-4), st)
		} else if app.LastError != "" {
			PutStringStyle(s, 2, statusY, TruncateToWidth(app.LastError, w-4), styleAlert)
		}
	}
	if cursorVisible {
		showInputCursor(s, cursorX, cursorY)
	}

	drawCollectOverlays(app, w, h)
}

func DrawContour(app *shared.AppState) {
	s := app.Screen
	clearScreen(s)
	cursorVisible := false
	cursorX, cursorY := 0, 0

	w, h := s.Size()
	drawPanel(s, 0, 0, w, 4, "Contour", "proxywatch")
	PutStringStyle(s, 2, 1, "? help", styleDim)
	utcLabel := "UTC: "
	utcValue := time.Now().UTC().Format(utcTimeFormat)
	blockX := max(2, w-2-len(utcLabel)-len(utcValue))
	PutStringStyle(s, blockX, 1, utcLabel, styleCyanB)
	PutStringStyle(s, blockX+len(utcLabel), 1, utcValue, styleTextB)
	if app.ContourAnalyzing {
		msg := fmt.Sprintf("%s Analyzing contour findings... elapsed %s", spinnerFrame(), spinnerElapsed(app.ContourStartedAt).String())
		if contour.NormalizeProbeRole(app.ContourProbeRole) == contour.ProbeRoleListen {
			msg = fmt.Sprintf("%s Contour listener active... elapsed %s", spinnerFrame(), spinnerElapsed(app.ContourStartedAt).String())
		}
		PutStringStyle(s, 2, 2, TruncateToWidth(msg, w-4), styleWarn)
	} else if app.ContourActive {
		msg := fmt.Sprintf("%s Collecting contour samples... elapsed %s", spinnerFrame(), spinnerElapsed(app.ContourStartedAt).String())
		if contour.NormalizeProbeRole(app.ContourProbeRole) == contour.ProbeRoleListen {
			msg = fmt.Sprintf("%s Preparing contour listener... elapsed %s", spinnerFrame(), spinnerElapsed(app.ContourStartedAt).String())
		} else if contour.NormalizeProbeMode(app.ContourProbeMode) != contour.ProbeModeOff {
			msg = fmt.Sprintf("%s Preparing contour probe... elapsed %s", spinnerFrame(), spinnerElapsed(app.ContourStartedAt).String())
		}
		PutStringStyle(s, 2, 2, TruncateToWidth(msg, w-4), styleWarn)
	}

	setupY := 4
	setupH := 8
	if setupY+setupH >= h {
		setupH = max(6, h-setupY-1)
	}
	drawPanel(s, 0, setupY, w, setupH, "CONTOUR SETUP", "")

	rows := []struct {
		field int
		label string
		value string
	}{
		{contourFieldEndpoint, "Target", nonEmptySIEMValue(strings.TrimSpace(app.ContourProbeEndpoint), "127.0.0.1")},
		{contourFieldOutput, "Output", nonEmptySIEMValue(strings.TrimSpace(app.ContourOutput), contour.DefaultOutputPath())},
		{contourFieldAction, "Action", contourActionLabel(app)},
	}
	for i, row := range rows {
		y := setupY + 1 + i
		if y >= setupY+setupH-1 {
			break
		}
		rowSelected := row.field == app.ContourField
		prefix := " "
		labelStyle := styleMuted
		valueStyle := styleText
		prefixStyle := styleText
		if rowSelected {
			prefix = ">"
			valueStyle = styleTextB
			prefixStyle = styleTextB
		}
		value := row.value
		fillSelectedRowBar(s, y, 2, w-3, rowSelected)
		labelText := fmt.Sprintf("%s %-8s", prefix, row.label+":")
		labelText = TruncateToWidth(labelText, w-4)
		PutStringStyle(s, 2, y, labelText, applySelectedRowStyle(labelStyle, rowSelected))
		valueX := 2 + len(labelText) + 2
		if valueX < w-2 {
			valueW := max(0, w-valueX-2)
			PutStringStyle(s, valueX, y, TruncateToWidth(value, valueW), applySelectedRowStyle(valueStyle, rowSelected))
			if rowSelected && app.ContourEditing && (row.field == contourFieldEndpoint || row.field == contourFieldOutput) && !app.ContourShowHelp && !app.ContourShowMenu {
				cursorVisible = true
				cursorX = textCursorX(valueX, value, valueW)
				cursorY = y
			}
		}
		PutStringStyle(s, 2, y, string(prefix), applySelectedRowStyle(prefixStyle, rowSelected))
		drawEditingTag(s, y, w, rowSelected && app.ContourEditing && (row.field == contourFieldEndpoint || row.field == contourFieldOutput))
	}

	reportY := setupY + setupH
	reportH := h - reportY
	if reportH < 4 {
		drawContourOverlays(app, w, h)
		return
	}
	// During an active run, show live progress in the report panel.
	panelLabel := "LATEST REPORT"
	lines := app.ContourReportLines
	if (app.ContourActive || app.ContourAnalyzing) && len(app.ContourProgressLines) > 0 {
		panelLabel = "LIVE"
		lines = app.ContourProgressLines
		// Auto-scroll to bottom of live output.
		visible := reportH - 2
		if visible > 0 && len(lines) > visible {
			app.ContourReportScroll = len(lines) - visible
		}
	}
	drawPanel(s, 0, reportY, w, reportH, panelLabel, "Contour")
	row := reportY + 1
	if len(lines) == 0 && !app.ContourActive && !app.ContourAnalyzing {
		app.ContourReportMaxScroll = 0
		PutStringStyle(s, 2, row, TruncateToWidth("No contour report has been generated yet.", w-4), styleText)
		row++
		if row < reportY+reportH-1 {
			PutStringStyle(s, 2, row, TruncateToWidth("Start a contour run to discover tunnel and escape patterns.", w-4), styleMuted)
		}
	} else if len(lines) == 0 {
		PutStringStyle(s, 2, row, TruncateToWidth("Starting...", w-4), styleMuted)
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
			PutStringStyle(s, 2, row, TruncateToWidth(lines[idx], w-4), contourReportLineStyle(lines[idx]))
			row++
		}
		PutStringStyle(s, max(2, w-26), reportY+reportH-1, fmt.Sprintf("Report %d-%d of %d", start+1, end, len(lines)), styleCyanB)
	}

	now := time.Now()
	if app.ContourStatusText != "" && now.Before(app.ContourStatusUntil) {
		st := styleText
		if app.ContourStatusError {
			st = styleAlert
		}
		PutStringStyle(s, 2, max(reportY+1, h-2), TruncateToWidth(app.ContourStatusText, w-4), st)
	}
	if cursorVisible {
		showInputCursor(s, cursorX, cursorY)
	}

	drawContourOverlays(app, w, h)
}

func DrawCalibration(app *shared.AppState) {
	s := app.Screen
	clearScreen(s)
	cursorVisible := false
	cursorX, cursorY := 0, 0

	w, h := s.Size()
	drawPanel(s, 0, 0, w, 4, "Calibration", "proxywatch")
	PutStringStyle(s, 2, 2, "? help", styleDim)
	utcLabel := "UTC: "
	utcValue := time.Now().UTC().Format(utcTimeFormat)
	scopeLabel := "Scope: "
	scopeValue := safeRolePreset(app)
	providerLabel := calibration.ProviderLabel(app.CalibrateProvider)
	blockWidth := max(len(utcLabel)+len(utcValue), len(scopeLabel)+len(scopeValue))
	blockX := max(2, w-2-blockWidth)
	PutStringStyle(s, blockX, 1, utcLabel, styleCyanB)
	PutStringStyle(s, blockX+len(utcLabel), 1, utcValue, styleTextB)
	PutStringStyle(s, blockX, 2, scopeLabel, styleCyanB)
	PutStringStyle(s, blockX+len(scopeLabel), 2, scopeValue, styleTextB)
	if app.CalibrateAnalyzing || app.CalibrateActive {
		elapsed := spinnerElapsed(app.CalibrateStartedAt)
		phase := "Calibration in progress"
		if app.CalibrateAnalyzing {
			phase = "Analyzing calibration data"
		}
		msg := fmt.Sprintf("%s %s... elapsed %s", spinnerFrame(), phase, elapsed.String())
		statusW := max(0, blockX-4)
		if statusW > 0 {
			PutStringStyle(s, 2, 1, TruncateToWidth(msg, statusW), styleWarn)
		}
	} else if app.CalibrateStatusText != "" && time.Now().Before(app.CalibrateStatusUntil) {
		statusW := max(0, blockX-4)
		if statusW > 0 {
			st := styleText
			if app.CalibrateStatusError {
				st = styleAlert
			}
			PutStringStyle(s, 2, 1, TruncateToWidth(app.CalibrateStatusText, statusW), st)
		}
	}

	setupY := 4
	setupH := 10
	if setupY+setupH >= h {
		setupH = max(6, h-setupY-1)
	}
	drawPanel(s, 0, setupY, w, setupH, "CALIBRATION SETUP", "")

	profileValue := "Current config: " + app.CalibrateAppliedProfile
	setupLines := []struct {
		label string
		value string
	}{
		{"Provider", providerLabel},
		{"Output", app.CalibrateOutput},
		{"Duration", app.CalibrateDuration},
		{"Model", app.CalibrateModel},
		{"Profile", profileValue},
		{"Action", calibrationActionLabel(app)},
		{"Apply", "Apply selected profile"},
	}
	for i, ln := range setupLines {
		row := setupY + 1 + i
		if row >= setupY+setupH-1 {
			break
		}
		rowSelected := i == app.CalibrateField
		prefix := " "
		labelStyle := styleMuted
		valueStyle := styleText
		prefixStyle := styleText
		if rowSelected {
			prefix = ">"
			valueStyle = styleTextB
			prefixStyle = styleTextB
		}
		value := ln.value
		fillSelectedRowBar(s, row, 2, w-3, rowSelected)
		labelText := fmt.Sprintf("%s %-9s", prefix, ln.label+":")
		labelText = TruncateToWidth(labelText, w-4)
		PutStringStyle(s, 2, row, labelText, applySelectedRowStyle(labelStyle, rowSelected))
		valueX := 2 + len(labelText) + 2
		if valueX < w-2 {
			valueW := max(0, w-valueX-2)
			PutStringStyle(s, valueX, row, TruncateToWidth(value, valueW), applySelectedRowStyle(valueStyle, rowSelected))
			if rowSelected && app.CalibrateEditing && i == calibrateFieldOutput && !app.ShowCalibrateHelp && !app.ShowCalibrateMenu {
				cursorVisible = true
				cursorX = textCursorX(valueX, value, valueW)
				cursorY = row
			}
		}
		PutStringStyle(s, 2, row, string(prefix), applySelectedRowStyle(prefixStyle, rowSelected))
		drawEditingTag(s, row, w, rowSelected && app.CalibrateEditing && i == calibrateFieldOutput)
	}

	accessY := setupY + setupH
	accessH := 7
	if accessY+accessH >= h {
		accessH = max(5, h-accessY-1)
	}
	drawPanel(s, 0, accessY, w, accessH, "PROVIDER ACCESS", "")
	access := calibration.DetectProviderAccess()
	accessRows := []struct {
		label string
		ok    bool
	}{
		{"OpenAI key", access.OpenAIKey},
		{"Anthropic key", access.AnthropicKey},
		{"Local LLM URL", access.LocalLLMURL},
		{"Local LLM API key", access.LocalLLMKey},
	}
	labelWidth := 0
	for _, item := range accessRows {
		if n := len(item.label) + 1; n > labelWidth {
			labelWidth = n
		}
	}
	labelWidth = max(labelWidth, 18)
	for i, item := range accessRows {
		y := accessY + 1 + i
		if y >= accessY+accessH-1 || y >= h {
			break
		}
		labelText := fmt.Sprintf(" %-*s", labelWidth, item.label+":")
		labelText = TruncateToWidth(labelText, w-4)
		PutStringStyle(s, 2, y, labelText, styleMuted)

		value := "missing"
		valueStyle := styleAlert
		if item.ok {
			value = "present"
			valueStyle = styleWatch
		}
		valueX := 2 + len(labelText) + 2
		if valueX < w-2 {
			PutStringStyle(s, valueX, y, TruncateToWidth(value, w-valueX-2), valueStyle)
		}
	}

	reportY := accessY + accessH
	reportH := h - reportY
	if reportH < 4 {
		drawCalibrationOverlays(app, w, h)
		return
	}
	// During active collection or analysis, show live progress.
	calibPanelLabel := "LATEST REPORT"
	if app.CalibrateActive || app.CalibrateAnalyzing {
		calibPanelLabel = "LIVE"
	}
	drawPanel(s, 0, reportY, w, reportH, calibPanelLabel, "")
	row := reportY + 1
	lines := app.CalibrateReportLines
	if (app.CalibrateActive || app.CalibrateAnalyzing) && len(app.CalibrateProgressLines) > 0 {
		lines = app.CalibrateProgressLines
		// Auto-scroll to bottom of live output.
		visible := reportH - 2
		if visible > 0 && len(lines) > visible {
			app.CalibrateReportScroll = len(lines) - visible
		}
	} else if app.CalibrateActive && !app.CalibrateAnalyzing {
		lines = calibrationCollectionLines(app)
	} else if len(lines) == 0 && strings.TrimSpace(app.CalibrateReportSummary) != "" {
		lines = []string{app.CalibrateReportSummary}
		for _, rec := range app.CalibrateRecommendations {
			lines = append(lines, "- "+rec)
		}
	}
	lines = normalizeCalibrationReportLines(lines, max(10, w-4))
	if len(lines) == 0 {
		app.CalibrateReportMaxScroll = 0
		PutStringStyle(s, 2, row, TruncateToWidth("No calibration report has been generated yet.", w-4), styleText)
		row++
		if row < reportY+reportH-1 {
			PutStringStyle(s, 2, row, TruncateToWidth("Choose a duration, provider, and optional model override, then run Start calibration.", w-4), styleMuted)
			row++
		}
		if row < reportY+reportH-1 {
			PutStringStyle(s, 2, row, TruncateToWidth("You can still select a saved profile above and use Apply.", w-4), styleMuted)
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
		if app.CalibrateReportScroll < 0 {
			app.CalibrateReportScroll = 0
		}
		if app.CalibrateReportScroll > maxScroll {
			app.CalibrateReportScroll = maxScroll
		}
		app.CalibrateReportMaxScroll = maxScroll
		start := app.CalibrateReportScroll
		end := min(len(lines), start+visible)
		for idx := start; idx < end && row < reportY+reportH-1; idx++ {
			line := lines[idx]
			drawCalibrationReportRow(s, 2, row, w-4, line)
			row++
		}
		startDisp := start + 1
		if len(lines) == 0 {
			startDisp = 0
		}
		endDisp := end
		PutStringStyle(s, max(2, w-26), reportY+reportH-1, fmt.Sprintf("Report %d-%d of %d", startDisp, endDisp, len(lines)), styleCyanB)
	}

	now := time.Now()
	if app.CalibrateStatusText != "" && now.Before(app.CalibrateStatusUntil) {
		st := styleText
		if app.CalibrateStatusError {
			st = styleAlert
		}
		PutStringStyle(s, 2, reportY+reportH-2, TruncateToWidth(app.CalibrateStatusText, w-4), st)
	}
	if cursorVisible {
		showInputCursor(s, cursorX, cursorY)
	}

	drawCalibrationOverlays(app, w, h)
}

func DrawSIEM(app *shared.AppState) {
	s := app.Screen
	clearScreen(s)
	cursorVisible := false
	cursorX, cursorY := 0, 0

	w, h := s.Size()
	drawPanel(s, 0, 0, w, 4, "SIEM", "proxywatch")
	PutStringStyle(s, 2, 1, "? help", styleDim)
	utcLabel := "UTC: "
	utcValue := time.Now().UTC().Format(utcTimeFormat)
	blockX := max(2, w-2-len(utcLabel)-len(utcValue))
	PutStringStyle(s, blockX, 1, utcLabel, styleCyanB)
	PutStringStyle(s, blockX+len(utcLabel), 1, utcValue, styleTextB)

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
		PutStringStyle(s, 2, 2, TruncateToWidth(msg, w-4), styleWarn)
	}

	genY := 4
	genH := 9
	if genY+genH >= h {
		genH = max(7, h-genY-1)
	}
	drawPanel(s, 0, genY, w, genH, "SIEM SETUP", "")
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
		labelStyle := styleMuted
		valueStyle := styleText
		prefixStyle := styleText
		if rowSelected {
			prefix = ">"
			valueStyle = styleTextB
			prefixStyle = styleTextB
		}
		value := row.value
		fillSelectedRowBar(s, y, 2, w-3, rowSelected)
		labelText := fmt.Sprintf("%s %-11s", prefix, row.label+":")
		labelText = TruncateToWidth(labelText, w-4)
		PutStringStyle(s, 2, y, labelText, applySelectedRowStyle(labelStyle, rowSelected))
		valueX := 2 + len(labelText) + 2
		if valueX < w-2 {
			valueW := max(0, w-valueX-2)
			PutStringStyle(s, valueX, y, TruncateToWidth(value, valueW), applySelectedRowStyle(valueStyle, rowSelected))
			if rowSelected && app.SIEMEditing && siemFieldEditable(row.field) && !app.SIEMShowHelp && !app.SIEMShowMenu {
				cursorVisible = true
				cursorX = textCursorX(valueX, value, valueW)
				cursorY = y
			}
		}
		PutStringStyle(s, 2, y, string(prefix), applySelectedRowStyle(prefixStyle, rowSelected))
		drawEditingTag(s, y, w, rowSelected && app.SIEMEditing && siemFieldEditable(row.field))
	}

	reportY := genY + genH
	reportH := max(4, h-reportY)
	if reportY+reportH > h {
		reportH = h - reportY
	}
	if reportH >= 3 {
		// During an active generation, show live progress in the report panel.
		siemPanelLabel := "REPORT"
		siemLines := app.SIEMReportLines
		if app.SIEMGenerating && len(app.SIEMProgressLines) > 0 {
			siemPanelLabel = "LIVE"
			siemLines = app.SIEMProgressLines
			// Auto-scroll to bottom of live output.
			visible := reportH - 2
			if visible > 0 && len(siemLines) > visible {
				app.SIEMReportScroll = len(siemLines) - visible
			}
		}
		drawPanel(s, 0, reportY, w, reportH, siemPanelLabel, "SIEM")
		row := reportY + 1
		lines := siemLines
		if len(lines) == 0 {
			app.SIEMReportMaxScroll = 0
			PutStringStyle(s, 2, row, TruncateToWidth("No SIEM report has been generated yet.", w-4), styleText)
			row++
			if row < reportY+reportH-1 {
				PutStringStyle(s, 2, row, TruncateToWidth("Select Source report and run Generate to build detections + report.", w-4), styleMuted)
				row++
			}
			if row < reportY+reportH-1 && len(app.SIEMSourceReports) == 0 {
				PutStringStyle(s, 2, row, TruncateToWidth("No calibration reports found. Select Calibrate to create one.", w-4), styleWarn)
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
				PutStringStyle(s, 2, row, TruncateToWidth(line, w-4), siemReportLineStyle(line))
				row++
			}
			PutStringStyle(s, max(2, w-26), reportY+reportH-1, fmt.Sprintf("Report %d-%d of %d", start+1, end, len(lines)), styleCyanB)
		}
	}

	now := time.Now()
	if app.SIEMStatusText != "" && now.Before(app.SIEMStatusUntil) && h >= 2 {
		st := styleText
		if app.SIEMStatusError {
			st = styleAlert
		}
		PutStringStyle(s, 2, h-2, TruncateToWidth(app.SIEMStatusText, w-4), st)
	}
	if cursorVisible {
		showInputCursor(s, cursorX, cursorY)
	}

	drawSIEMOverlays(app, w, h)
}

func nonEmptySIEMValue(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value != "" {
		return value
	}
	return fallback
}

func spinnerFrame() string {
	frames := []string{"-", "\\", "|", "/"}
	return frames[int(time.Now().UnixNano()/int64(250*time.Millisecond))%len(frames)]
}

func spinnerElapsed(start time.Time) time.Duration {
	if start.IsZero() {
		return 0
	}
	elapsed := time.Since(start).Round(time.Second)
	if elapsed < 0 {
		return 0
	}
	return elapsed
}

func DrawKeystore(app *shared.AppState) {
	s := app.Screen
	clearScreen(s)
	cursorVisible := false
	cursorX, cursorY := 0, 0

	w, h := s.Size()
	drawPanel(s, 0, 0, w, 4, "Keystore", "proxywatch")
	PutStringStyle(s, 2, 1, "? help", styleDim)
	utcLabel := "UTC: "
	utcValue := time.Now().UTC().Format(utcTimeFormat)
	stateLabel := "State: "
	stateValue := "locked"
	if app.KeystoreUnlocked {
		stateValue = "unlocked"
	}
	blockWidth := max(len(utcLabel)+len(utcValue), len(stateLabel)+len(stateValue))
	blockX := max(2, w-2-blockWidth)
	PutStringStyle(s, blockX, 1, utcLabel, styleCyanB)
	PutStringStyle(s, blockX+len(utcLabel), 1, utcValue, styleTextB)
	PutStringStyle(s, blockX, 2, stateLabel, styleCyanB)
	PutStringStyle(s, blockX+len(stateLabel), 2, stateValue, styleTextB)

	// All rows indexed by field constant. Hidden fields are skipped at render time.
	allRows := map[int]struct{ label, value string }{
		keystoreFieldOpenAIKey:         {"OpenAI key", keystore.MaskValue("OPENAI_API_KEY", app.KeystoreValues["OPENAI_API_KEY"])},
		keystoreFieldOpenAIBaseURL:     {"OpenAI base URL", keystore.MaskValue("OPENAI_BASE_URL", app.KeystoreValues["OPENAI_BASE_URL"])},
		keystoreFieldAnthropicKey:      {"Anthropic key", keystore.MaskValue("ANTHROPIC_API_KEY", app.KeystoreValues["ANTHROPIC_API_KEY"])},
		keystoreFieldAnthropicBaseURL:  {"Anthropic base URL", keystore.MaskValue("ANTHROPIC_BASE_URL", app.KeystoreValues["ANTHROPIC_BASE_URL"])},
		keystoreFieldLocalLLMURL:       {"Local LLM URL", keystore.MaskValue("LOCAL_LLM_URL", app.KeystoreValues["LOCAL_LLM_URL"])},
		keystoreFieldLocalLLMAPIKey:    {"Local LLM key", keystore.MaskValue("LOCAL_LLM_API_KEY", app.KeystoreValues["LOCAL_LLM_API_KEY"])},
		keystoreFieldCalibrationTimeout: {"Calibration timeout", keystore.MaskValue("CALIBRATION_HTTP_TIMEOUT", app.KeystoreValues["CALIBRATION_HTTP_TIMEOUT"])},
		keystoreFieldBloodhoundURL:     {"BH URL", keystore.MaskValue("BLOODHOUND_API_URL", app.KeystoreValues["BLOODHOUND_API_URL"])},
		keystoreFieldBloodhoundToken:   {"BH token", keystore.MaskValue("BLOODHOUND_API_TOKEN", app.KeystoreValues["BLOODHOUND_API_TOKEN"])},
		keystoreFieldBloodhoundTokenID: {"BH token ID", keystore.MaskValue("BLOODHOUND_API_TOKEN_ID", app.KeystoreValues["BLOODHOUND_API_TOKEN_ID"])},
		keystoreFieldTLSDir:            {"TLS dir", keystore.MaskValue("PROXYWATCH_TLS_DIR", app.KeystoreValues["PROXYWATCH_TLS_DIR"])},
		keystoreFieldAgentToken:        {"Agent token", keystore.MaskValue("PROXYWATCH_AGENT_TOKEN", app.KeystoreValues["PROXYWATCH_AGENT_TOKEN"])},
		keystoreFieldDisableClientCert: {"Disable client cert", keystore.MaskValue("PROXYWATCH_DISABLE_CLIENT_CERT", app.KeystoreValues["PROXYWATCH_DISABLE_CLIENT_CERT"])},
		keystoreFieldTrustOnFirstUse:   {"Trust on first use", keystore.MaskValue("PROXYWATCH_TRUST_ON_FIRST_USE", app.KeystoreValues["PROXYWATCH_TRUST_ON_FIRST_USE"])},
		keystoreFieldLoad:              {"Load", "Load encrypted keystore"},
		keystoreFieldSave:              {"Save", "Save encrypted keystore"},
		keystoreFieldApply:             {"Apply", "Apply values to runtime"},
	}

	// Build visible rows in display order.
	type ksRow struct {
		field int
		label string
		value string
	}
	rows := make([]ksRow, 0, 16)
	fieldOrder := []int{
		keystoreFieldOpenAIKey, keystoreFieldOpenAIBaseURL,
		keystoreFieldAnthropicKey, keystoreFieldAnthropicBaseURL,
		keystoreFieldLocalLLMURL, keystoreFieldLocalLLMAPIKey,
		keystoreFieldCalibrationTimeout,
		keystoreFieldBloodhoundURL, keystoreFieldBloodhoundToken, keystoreFieldBloodhoundTokenID,
		keystoreFieldTLSDir, keystoreFieldAgentToken,
		keystoreFieldDisableClientCert, keystoreFieldTrustOnFirstUse,
		keystoreFieldLoad, keystoreFieldSave, keystoreFieldApply,
	}
	for _, f := range fieldOrder {
		if !keystoreFieldVisible(f) {
			continue
		}
		r := allRows[f]
		rows = append(rows, ksRow{field: f, label: r.label, value: r.value})
	}

	setupY := 4
	setupH := len(rows) + 4
	if setupY+setupH >= h {
		setupH = max(10, h-setupY-1)
	}
	if setupY+setupH > h {
		setupH = max(3, h-setupY)
	}
	drawPanel(s, 0, setupY, w, setupH, "KEYSTORE", "")
	fileLabel := fmt.Sprintf(" %-20s", "File:")
	fileLabel = TruncateToWidth(fileLabel, w-4)
	PutStringStyle(s, 2, setupY+1, fileLabel, styleMuted)
	fileValueX := 2 + len(fileLabel) + 2
	if fileValueX < w-2 {
		PutStringStyle(s, fileValueX, setupY+1, TruncateToWidth(keystore.NormalizePath(app.KeystorePath), w-fileValueX-2), styleText)
	}
	keyLabel := fmt.Sprintf(" %-20s", "Key:")
	keyLabel = TruncateToWidth(keyLabel, w-4)
	PutStringStyle(s, 2, setupY+2, keyLabel, styleMuted)
	keyValueX := 2 + len(keyLabel) + 2
	if keyValueX < w-2 {
		PutStringStyle(s, keyValueX, setupY+2, TruncateToWidth(keystore.KeyPath(app.KeystorePath), w-keyValueX-2), styleText)
	}
	maxVisibleRows := max(0, setupH-4)
	// Find the display index of the selected field.
	selectedDisplayIdx := 0
	for i, row := range rows {
		if row.field == app.KeystoreField {
			selectedDisplayIdx = i
			break
		}
	}
	rowStart := 0
	if maxVisibleRows > 0 && len(rows) > maxVisibleRows {
		rowStart = selectedDisplayIdx - maxVisibleRows + 1
		if rowStart < 0 {
			rowStart = 0
		}
		maxStart := len(rows) - maxVisibleRows
		if rowStart > maxStart {
			rowStart = maxStart
		}
	}
	for i := rowStart; i < len(rows) && i < rowStart+maxVisibleRows; i++ {
		row := rows[i]
		y := setupY + 3 + (i - rowStart)
		rowSelected := row.field == app.KeystoreField
		prefix := " "
		labelStyle := styleMuted
		valueStyle := styleText
		prefixStyle := styleText
		if rowSelected {
			prefix = ">"
			valueStyle = styleTextB
			prefixStyle = styleTextB
		}
		value := row.value
		fillSelectedRowBar(s, y, 2, w-3, rowSelected)
		labelText := fmt.Sprintf("%s %-15s", prefix, row.label+":")
		labelText = TruncateToWidth(labelText, w-4)
		PutStringStyle(s, 2, y, labelText, applySelectedRowStyle(labelStyle, rowSelected))
		valueX := 2 + len(labelText) + 2
		if valueX < w-2 {
			valueW := max(0, w-valueX-2)
			PutStringStyle(s, valueX, y, TruncateToWidth(value, valueW), applySelectedRowStyle(valueStyle, rowSelected))
			if rowSelected && app.KeystoreEditing && !app.KeystoreShowHelp {
				if _, editable := keystoreFieldEnvKey(row.field); editable {
					cursorVisible = true
					cursorX = textCursorX(valueX, value, valueW)
					cursorY = y
				}
			}
		}
		PutStringStyle(s, 2, y, string(prefix), applySelectedRowStyle(prefixStyle, rowSelected))
		_, keystoreEditable := keystoreFieldEnvKey(row.field)
		drawEditingTag(s, y, w, rowSelected && app.KeystoreEditing && keystoreEditable)
	}

	notesY := setupY + setupH
	notesH := max(4, h-notesY)
	if notesY+notesH > h {
		notesH = h - notesY
	}
	if notesH >= 3 {
		drawPanel(s, 0, notesY, w, notesH, "", "Keystore")
		noteRow := notesY + 1
		notes := []string{
			"Values are encrypted on disk with AES-GCM using a machine key.",
			"Load reads the encrypted keystore. Save writes it. Apply pushes values to runtime.",
			"Keys are used by Calibration (AI providers), SIEM, BloodHound, and agent transport.",
		}
		for _, note := range notes {
			if noteRow >= notesY+notesH-1 {
				break
			}
			PutStringStyle(s, 2, noteRow, TruncateToWidth(note, w-4), styleMuted)
			noteRow++
		}
	}

	now := time.Now()
	if app.KeystoreStatusText != "" && now.Before(app.KeystoreStatusUntil) && h >= 2 {
		st := styleText
		if app.KeystoreStatusError {
			st = styleAlert
		}
		PutStringStyle(s, 2, h-2, TruncateToWidth(app.KeystoreStatusText, w-4), st)
	}
	if cursorVisible {
		showInputCursor(s, cursorX, cursorY)
	}

	drawKeystoreOverlays(app, w, h)
}

const calibrationReportLabelWidth = 18

func normalizeCalibrationReportLines(lines []string, width int) []string {
	if len(lines) == 0 {
		return lines
	}
	summaryWidth := max(12, width-calibrationReportLabelWidth-2)
	normalized := make([]string, 0, len(lines)+8)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Mode:") || strings.HasPrefix(trimmed, "Scope:") {
			continue
		}
		if strings.HasPrefix(trimmed, "Summary:") {
			summary := strings.TrimSpace(strings.TrimPrefix(trimmed, "Summary:"))
			wrapped := wrapWords(summary, summaryWidth)
			if len(wrapped) == 0 {
				normalized = append(normalized, "Summary:")
				continue
			}
			for _, item := range wrapped {
				normalized = append(normalized, "Summary: "+item)
			}
			continue
		}
		normalized = append(normalized, line)
	}
	return normalized
}

func wrapWords(text string, width int) []string {
	text = strings.TrimSpace(text)
	if text == "" {
		return []string{""}
	}
	if width < 1 {
		return []string{text}
	}
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{""}
	}
	lines := make([]string, 0, 4)
	current := ""
	for _, word := range words {
		for len(word) > width {
			if current != "" {
				lines = append(lines, current)
				current = ""
			}
			lines = append(lines, word[:width])
			word = word[width:]
		}
		if current == "" {
			current = word
			continue
		}
		if len(current)+1+len(word) <= width {
			current += " " + word
		} else {
			lines = append(lines, current)
			current = word
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}

func drawCalibrationReportRow(s tcell.Screen, x, y, width int, line string) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || width <= 0 {
		return
	}
	if !strings.HasPrefix(trimmed, "- ") && !strings.HasPrefix(line, "  ") && strings.Contains(line, ":") {
		colon := strings.Index(line, ":")
		if colon > 0 {
			label := ClipToWidth(strings.TrimSpace(line[:colon+1]), calibrationReportLabelWidth-1)
			value := strings.TrimSpace(line[colon+1:])
			labelText := fmt.Sprintf(" %-*s", calibrationReportLabelWidth-1, label)
			labelText = TruncateToWidth(labelText, width)
			PutStringStyle(s, x, y, labelText, styleMuted)
			valueX := x + len(labelText) + 1
			if valueX < x+width {
				valueStyle := calibrationReportLineStyle(line)
				if strings.HasPrefix(trimmed, "Summary:") {
					valueStyle = styleTextB
				}
				PutStringStyle(s, valueX, y, TruncateToWidth(value, x+width-valueX), valueStyle)
			}
			return
		}
	}
	PutStringStyle(s, x, y, TruncateToWidth(line, width), calibrationReportLineStyle(line))
}

func calibrationReportLineStyle(line string) tcell.Style {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return styleText
	}
	// Section headers.
	switch trimmed {
	case "Tuning", "Validation", "Recommendations", "Learning", "History", "Reasoning":
		return styleCyanB
	}
	// Collection phase lines.
	if strings.HasPrefix(trimmed, "Collection phase active.") || strings.HasPrefix(trimmed, "Remaining:") ||
		strings.HasPrefix(trimmed, "Samples captured:") || strings.HasPrefix(trimmed, "Unique processes:") ||
		strings.HasPrefix(trimmed, "Roles:") || strings.HasPrefix(trimmed, "States:") {
		return styleText
	}
	if strings.HasPrefix(trimmed, "Recent collected") {
		return styleCyanB
	}
	// Error lines.
	if strings.Contains(trimmed, "[FAIL]") {
		return styleAlert
	}
	// Confidence — label muted, but number+level colored. Since we can only
	// style the whole line, use the level color (it's the important part).
	if strings.HasPrefix(trimmed, "Confidence:") {
		if strings.Contains(trimmed, "(high)") {
			return styleCyan
		}
		if strings.Contains(trimmed, "(moderate)") {
			return styleWarn
		}
		return styleAlert // low
	}
	// Contamination coloring — color the whole line based on level.
	if strings.Contains(trimmed, "Contamination:") {
		if strings.Contains(trimmed, "(clean)") {
			return styleCyan
		}
		if strings.Contains(trimmed, "(low)") {
			return styleWatch
		}
		if strings.Contains(trimmed, "(elevated)") {
			return styleWarn
		}
		return styleAlert // critical
	}
	// Validation verdict.
	if strings.Contains(trimmed, "regressed") {
		return styleAlert
	}
	if strings.Contains(trimmed, "improved") {
		return styleWatch
	}
	// Risk tags.
	if strings.Contains(trimmed, "[RISK]") {
		return styleWarn
	}
	if strings.HasPrefix(trimmed, "- Warning:") {
		return styleWarn
	}
	if strings.HasPrefix(trimmed, "- ") {
		return styleText
	}
	if strings.HasPrefix(line, "  ") {
		return styleMuted
	}
	// Live progress lines.
	if strings.HasPrefix(trimmed, "[*]") {
		return styleMuted
	}
	if strings.HasPrefix(trimmed, "[+]") {
		return styleCyan
	}
	if strings.HasPrefix(trimmed, "[-]") {
		return styleAlert
	}
	return styleText
}

func siemGenerateLabel(app *shared.AppState) string {
	if app.SIEMGenerating {
		elapsed := spinnerElapsed(app.SIEMStartedAt)
		return fmt.Sprintf("Stop generation (%s elapsed)", elapsed)
	}
	return "Build SIEM detections from calibration data"
}

func siemReportLineStyle(line string) tcell.Style {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return styleText
	}
	// Section headers.
	switch trimmed {
	case "Detections", "Notes":
		return styleCyanB
	}
	// Severity tags.
	if strings.Contains(trimmed, "[HIGH]") || strings.Contains(trimmed, "[CRITICAL]") {
		return styleAlert
	}
	if strings.Contains(trimmed, "[MEDIUM]") {
		return styleWarn
	}
	if strings.Contains(trimmed, "[LOW]") {
		return styleCyan
	}
	// Query lines (Splunk:, KQL:, ESQL:).
	if strings.Contains(trimmed, "Splunk:") || strings.Contains(trimmed, "KQL:") || strings.Contains(trimmed, "ESQL:") {
		return styleMuted
	}
	// Role/Process metadata lines.
	if strings.Contains(trimmed, "Role:") && strings.Contains(trimmed, "Processes:") {
		return styleMuted
	}
	// Stats line.
	if strings.Contains(trimmed, "detections") && strings.Contains(trimmed, "candidates") {
		return styleMuted
	}
	// Bullet points.
	if strings.HasPrefix(trimmed, "- ") {
		return styleText
	}
	// Live progress lines.
	if strings.HasPrefix(trimmed, "[*]") {
		return styleMuted
	}
	if strings.HasPrefix(trimmed, "[+]") {
		return styleCyan
	}
	if strings.HasPrefix(trimmed, "[-]") {
		return styleAlert
	}
	return styleText
}

func collectLiveLines(app *shared.AppState) []string {
	lines := make([]string, 0, 16)
	elapsed := time.Since(app.CollectStartedAt).Round(time.Second)
	remaining := time.Until(app.CollectUntil).Round(time.Second)
	if remaining < 0 {
		remaining = 0
	}

	lines = append(lines, fmt.Sprintf("[*] Collection active  |  elapsed %s  |  %s remaining", elapsed, remaining))
	lines = append(lines, fmt.Sprintf("[+] %d samples collected", len(app.CollectData)))

	// Count unique processes and roles.
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

	// Role breakdown.
	parts := make([]string, 0, 6)
	for _, r := range []string{"session", "beacon", "tunnel", "smb-pipe", "listen", "outbound"} {
		if n := roleCounts[r]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", r, n))
		}
	}
	if len(parts) > 0 {
		lines = append(lines, "[+] "+strings.Join(parts, "  "))
	}

	// Recent processes (last 6 unique).
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
		lines = append(lines, fmt.Sprintf("    %-9d %-20s %8s", c.Proc.Pid, ClipToWidth(info.name, 20), info.role))
		added++
	}

	// Append any finalization progress lines.
	if len(app.CollectProgressLines) > 0 {
		lines = append(lines, "")
		lines = append(lines, app.CollectProgressLines...)
	}

	return lines
}

func collectProgressLineStyle(line string) tcell.Style {
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "[*]") {
		return styleMuted
	}
	if strings.HasPrefix(trimmed, "[+]") {
		return styleCyan
	}
	if strings.HasPrefix(trimmed, "[-]") {
		return styleAlert
	}
	return styleText
}

func calibrationCollectionLines(app *shared.AppState) []string {
	remaining := time.Until(app.CalibrateUntil).Round(time.Second)
	if remaining < 0 {
		remaining = 0
	}

	type stats struct {
		key   string
		host  string
		pid   int
		name  string
		role  string
		state string
		age   string
	}
	seen := make(map[string]stats)
	order := make([]string, 0, len(app.CalibrateSamples))
	roleCounts := map[string]int{
		"session":  0,
		"beacon":   0,
		"tunnel":   0,
		"listen":   0,
		"outbound": 0,
	}
	stateCounts := map[string]int{
		"watch":  0,
		"strong": 0,
		"active": 0,
	}

	for _, sample := range app.CalibrateSamples {
		if sample.Proc == nil {
			continue
		}
		family := shared.RoleFamily(sample.Role)
		roleCounts[family]++
		state := "watch"
		if sample.ActiveProxying {
			state = "active"
		} else if sample.StrongEvidence {
			state = "strong"
		}
		stateCounts[state]++
		key := shared.CandidateKey(sample)
		if _, ok := seen[key]; ok {
			continue
		}
		age := sample.SeenSeconds
		if age <= 0 {
			age = sample.ControlDurationSeconds
		}
		seen[key] = stats{
			key:   key,
			host:  shared.DisplayHost(sample.Host),
			pid:   sample.Proc.Pid,
			name:  sample.Proc.Name,
			role:  family,
			state: state,
			age:   formatDashboardAge(age),
		}
		order = append(order, key)
	}

	elapsed := time.Since(app.CalibrateStartedAt).Round(time.Second)
	lines := make([]string, 0, 20)
	lines = append(lines, fmt.Sprintf("[*] Collecting calibration data  |  elapsed %s  |  %s remaining", elapsed, remaining))
	lines = append(lines, fmt.Sprintf("[+] %d samples  |  %d unique processes", len(app.CalibrateSamples), len(order)))

	// Role/state summary.
	roleParts := make([]string, 0, 6)
	for _, r := range []string{"session", "beacon", "tunnel", "smb-pipe", "listen", "outbound"} {
		if n := roleCounts[r]; n > 0 {
			roleParts = append(roleParts, fmt.Sprintf("%s %d", r, n))
		}
	}
	if len(roleParts) > 0 {
		lines = append(lines, "[+] "+strings.Join(roleParts, "  "))
	}
	lines = append(lines, fmt.Sprintf("[+] watch %d  strong %d  active %d", stateCounts["watch"], stateCounts["strong"], stateCounts["active"]))

	// Recent processes.
	lines = append(lines, "")
	lines = append(lines, "[*] Recent processes:")
	added := 0
	for i := len(order) - 1; i >= 0 && added < 8; i-- {
		item := seen[order[i]]
		lines = append(lines, fmt.Sprintf("    %-5s %-9d %-20s %8s %-6s %s", item.host, item.pid, ClipToWidth(item.name, 20), item.role, item.state, item.age))
		added++
	}
	if added == 0 {
		lines = append(lines, "- none captured yet")
	}
	return lines
}

func drawCalibrationOverlays(app *shared.AppState, w, h int) {
	if app.ShowCalibrateHelp {
		opts := calibrationMenuHelpOptions()
		drawMenuPanel(app.Screen, w, h, "Calibration Menu", opts, clampIndex(app.CalibrateHelpIndex, len(opts)), "")
	}
	if app.ShowCalibrateMenu {
		drawMenuPanel(
			app.Screen,
			w,
			h,
			app.CalibrateMenuTitle,
			app.CalibrateMenuOptions,
			clampIndex(app.CalibrateMenuIndex, len(app.CalibrateMenuOptions)),
			"Enter apply   Esc close",
		)
	}
}

func drawCollectOverlays(app *shared.AppState, w, h int) {
	if app.CollectShowHelp {
		opts := collectMenuHelpOptions()
		drawMenuPanel(app.Screen, w, h, "BloodHound Menu", opts, clampIndex(app.CollectHelpIndex, len(opts)), "")
	}
	if app.CollectShowMenu {
		drawMenuPanel(
			app.Screen,
			w,
			h,
			app.CollectMenuTitle,
			app.CollectMenuOptions,
			clampIndex(app.CollectMenuIndex, len(app.CollectMenuOptions)),
			"Enter apply   Esc close",
		)
	}
}

func drawContourOverlays(app *shared.AppState, w, h int) {
	if app.ContourShowHelp {
		opts := contourMenuHelpOptions()
		drawMenuPanel(app.Screen, w, h, "Contour Menu", opts, clampIndex(app.ContourHelpIndex, len(opts)), "")
	}
	if app.ContourShowMenu {
		drawMenuPanel(
			app.Screen,
			w,
			h,
			app.ContourMenuTitle,
			app.ContourMenuOptions,
			clampIndex(app.ContourMenuIndex, len(app.ContourMenuOptions)),
			"Enter apply   Esc close",
		)
	}
}

func drawSIEMOverlays(app *shared.AppState, w, h int) {
	if app.SIEMShowHelp {
		opts := siemMenuHelpOptions()
		drawMenuPanel(app.Screen, w, h, "SIEM Menu", opts, clampIndex(app.SIEMHelpIndex, len(opts)), "")
	}
	if app.SIEMShowMenu {
		drawMenuPanel(
			app.Screen,
			w,
			h,
			app.SIEMMenuTitle,
			app.SIEMMenuOptions,
			clampIndex(app.SIEMMenuIndex, len(app.SIEMMenuOptions)),
			"Enter apply   Esc close",
		)
	}
}

func drawKeystoreOverlays(app *shared.AppState, w, h int) {
	if !app.KeystoreShowHelp {
		return
	}
	opts := keystoreMenuHelpOptions()
	drawMenuPanel(app.Screen, w, h, "Keystore Menu", opts, clampIndex(app.KeystoreHelpIndex, len(opts)), "")
}

func calibrationActionLabel(app *shared.AppState) string {
	if app.CalibrateAnalyzing {
		return "Stop calibration (cancel analysis)"
	}
	if app.CalibrateActive {
		remaining := time.Until(app.CalibrateUntil).Round(time.Second)
		if remaining < 0 {
			remaining = 0
		}
		return "Stop calibration (" + remaining.String() + " left)"
	}
	return "Start calibration"
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
		return styleText
	}

	// Finding severity — the only colored lines in the report.
	if strings.HasPrefix(trimmed, "ACTIVE") {
		return styleAlertB
	}
	if strings.HasPrefix(trimmed, "STRONG") {
		return styleAlert
	}
	if strings.HasPrefix(trimmed, "WATCH") {
		return styleWarn
	}

	// Section labels — subtle emphasis.
	switch trimmed {
	case "tunnels", "exfil", "services", "egress",
		"Activity", "Listener Ports":
		return styleTextB
	}

	// Proxy pivot lines.
	if strings.Contains(trimmed, "[PIVOT]") {
		return styleWarn
	}

	// Live progress lines (during active run).
	if strings.HasPrefix(trimmed, "[-]") {
		return styleAlert
	}
	if strings.HasPrefix(trimmed, "[*]") || strings.HasPrefix(trimmed, "[+]") {
		return styleDim
	}

	// Output path.
	if strings.HasPrefix(trimmed, "output") {
		return styleMuted
	}

	// Default — uniform text.
	return styleText
}

// --- whitelist view (merged from render_whitelist.go) ---

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
	setupH := 5
	if setupY+setupH >= h {
		setupH = max(4, h-setupY-1)
	}

	// Show selected process and entry context in the panel title area.
	selectedProc := "(select below)"
	if c, ok := selectedWhitelistProcessCandidate(app); ok && c.Proc != nil {
		selectedProc = shared.DisplayProcessName(c.Proc)
		if c.Proc.Pid > 0 {
			selectedProc = fmt.Sprintf("%s (pid %d)", selectedProc, c.Proc.Pid)
		}
	}
	drawPanel(s, 0, setupY, w, setupH, "ACTIONS", "")
	drawWhitelistSetupRow(s, w, setupY+1, app.WhitelistField == whitelistFieldAdd, "Add", "Whitelist: "+selectedProc)
	selectedEntry := "(select below)"
	if len(app.WhitelistItems) > 0 && app.WhitelistSelected >= 0 && app.WhitelistSelected < len(app.WhitelistItems) {
		selectedEntry = formatWhitelistEntry(app.WhitelistItems[app.WhitelistSelected], w-24)
	}
	drawWhitelistSetupRow(s, w, setupY+2, app.WhitelistField == whitelistFieldRemove, "Remove", "Remove: "+selectedEntry)
	if setupY+3 < setupY+setupH-1 {
		PutStringStyle(s, 2, setupY+3, TruncateToWidth("UP/DOWN navigate  |  LEFT/RIGHT browse lists  |  ENTER execute action", w-4), styleMuted)
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
	drawPanel(s, 0, processY, w, processH, "PROCESSES", fmt.Sprintf("%d/%d", max(0, app.WhitelistProcessSelected+1), len(procs)))
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

	drawPanel(s, 0, entriesY, w, entriesH, "WHITELIST ENTRIES", fmt.Sprintf("%d/%d", max(0, app.WhitelistSelected+1), len(app.WhitelistItems)))
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
