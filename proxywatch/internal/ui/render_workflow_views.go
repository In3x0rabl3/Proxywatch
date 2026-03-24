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
		if rowSelected && app.CollectEditing {
			value += " [edit]"
		}
		rowY := setupY + 1 + i
		fillSelectedRowBar(s, rowY, 2, w-3, rowSelected)
		labelText := fmt.Sprintf("%s %-8s", prefix, row.label+":")
		labelText = TruncateToWidth(labelText, w-4)
		PutStringStyle(s, 2, rowY, labelText, applySelectedRowStyle(labelStyle, rowSelected))
		valueX := 2 + len(labelText) + 2
		if valueX < w-2 {
			PutStringStyle(s, valueX, rowY, TruncateToWidth(value, w-valueX-2), applySelectedRowStyle(valueStyle, rowSelected))
		}
		PutStringStyle(s, 2, rowY, string(prefix), applySelectedRowStyle(prefixStyle, rowSelected))
	}

	notesY := setupY + setupH
	drawPanel(s, 0, notesY, w, 4, "NOTES", "BloodHound")
	PutStringStyle(s, 2, notesY+1, TruncateToWidth("Source lets you collect from all hosts or a specific host.", w-4), styleMuted)
	PutStringStyle(s, 2, notesY+2, TruncateToWidth("Role metadata is omitted from BloodHound collection output.", w-4), styleMuted)

	statusY := notesY + 4
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

	drawCollectOverlays(app, w, h)
}

func DrawContour(app *shared.AppState) {
	s := app.Screen
	clearScreen(s)

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
		{contourFieldEndpoint, "Endpoint", nonEmptySIEMValue(strings.TrimSpace(app.ContourProbeEndpoint), "127.0.0.1")},
		{contourFieldOutput, "Output", nonEmptySIEMValue(strings.TrimSpace(app.ContourOutput), contour.DefaultOutputPath())},
	}
	if contour.NormalizeProbeRole(app.ContourProbeRole) != contour.ProbeRoleListen {
		rows = append(rows, struct {
			field int
			label string
			value string
		}{contourFieldProbeMode, "Probe", contour.ProbeModeLabel(app.ContourProbeMode)})
	}
	rows = append(rows,
		struct {
			field int
			label string
			value string
		}{contourFieldProbeRole, "Role", contour.ProbeRoleLabel(app.ContourProbeRole)},
		struct {
			field int
			label string
			value string
		}{contourFieldAction, "Action", contourActionLabel(app)},
	)
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
		if app.ContourEditing && rowSelected {
			value += " [edit]"
		}
		fillSelectedRowBar(s, y, 2, w-3, rowSelected)
		labelText := fmt.Sprintf("%s %-8s", prefix, row.label+":")
		labelText = TruncateToWidth(labelText, w-4)
		PutStringStyle(s, 2, y, labelText, applySelectedRowStyle(labelStyle, rowSelected))
		valueX := 2 + len(labelText) + 2
		if valueX < w-2 {
			PutStringStyle(s, valueX, y, TruncateToWidth(value, w-valueX-2), applySelectedRowStyle(valueStyle, rowSelected))
		}
		PutStringStyle(s, 2, y, string(prefix), applySelectedRowStyle(prefixStyle, rowSelected))
	}

	reportY := setupY + setupH
	reportH := h - reportY
	if reportH < 4 {
		drawContourOverlays(app, w, h)
		return
	}
	drawPanel(s, 0, reportY, w, reportH, "LATEST REPORT", "Contour")
	row := reportY + 1
	lines := app.ContourReportLines
	if len(lines) == 0 {
		app.ContourReportMaxScroll = 0
		PutStringStyle(s, 2, row, TruncateToWidth("No contour report has been generated yet.", w-4), styleText)
		row++
		if row < reportY+reportH-1 {
			PutStringStyle(s, 2, row, TruncateToWidth("Start a contour run to discover tunnel and escape patterns.", w-4), styleMuted)
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

	drawContourOverlays(app, w, h)
}

func DrawCalibration(app *shared.AppState) {
	s := app.Screen
	clearScreen(s)

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
		if app.CalibrateEditing && rowSelected {
			value += " [edit]"
		}
		fillSelectedRowBar(s, row, 2, w-3, rowSelected)
		labelText := fmt.Sprintf("%s %-9s", prefix, ln.label+":")
		labelText = TruncateToWidth(labelText, w-4)
		PutStringStyle(s, 2, row, labelText, applySelectedRowStyle(labelStyle, rowSelected))
		valueX := 2 + len(labelText) + 2
		if valueX < w-2 {
			PutStringStyle(s, valueX, row, TruncateToWidth(value, w-valueX-2), applySelectedRowStyle(valueStyle, rowSelected))
		}
		PutStringStyle(s, 2, row, string(prefix), applySelectedRowStyle(prefixStyle, rowSelected))
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
	for i, item := range accessRows {
		y := accessY + 1 + i
		if y >= accessY+accessH-1 || y >= h {
			break
		}
		labelText := fmt.Sprintf(" %-17s", item.label+":")
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
	drawPanel(s, 0, reportY, w, reportH, "LATEST REPORT", "")
	row := reportY + 1
	lines := app.CalibrateReportLines
	if app.CalibrateActive && !app.CalibrateAnalyzing {
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

	drawCalibrationOverlays(app, w, h)
}

func DrawSIEM(app *shared.AppState) {
	s := app.Screen
	clearScreen(s)

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
	genH := 11
	if genY+genH >= h {
		genH = max(9, h-genY-1)
	}
	drawPanel(s, 0, genY, w, genH, "SIEM GENERATION", "")
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
		{siemFieldSourceReport, "Source report", sourceValue},
		{siemFieldProvider, "Provider", provider},
		{siemFieldModel, "Model", nonEmptySIEMValue(app.SIEMModel, calibration.DefaultModel(app.SIEMProvider))},
		{siemFieldReportOutput, "Report out", nonEmptySIEMValue(app.SIEMReportPath, siem.DefaultSIEMReportPath())},
		{siemFieldJSONOutput, "JSON out", nonEmptySIEMValue(app.SIEMExportPath, siem.DefaultSIEMJSONPath())},
		{siemFieldGenerate, "Generate", "Build SIEM report + JSON from calibration data"},
		{siemFieldSaveGeneration, "Save", "Save generation settings to keystore"},
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
		if app.SIEMEditing && rowSelected {
			value += " [edit]"
		}
		fillSelectedRowBar(s, y, 2, w-3, rowSelected)
		labelText := fmt.Sprintf("%s %-13s", prefix, row.label+":")
		labelText = TruncateToWidth(labelText, w-4)
		PutStringStyle(s, 2, y, labelText, applySelectedRowStyle(labelStyle, rowSelected))
		valueX := 2 + len(labelText) + 2
		if valueX < w-2 {
			PutStringStyle(s, valueX, y, TruncateToWidth(value, w-valueX-2), applySelectedRowStyle(valueStyle, rowSelected))
		}
		PutStringStyle(s, 2, y, string(prefix), applySelectedRowStyle(prefixStyle, rowSelected))
	}

	expY := genY + genH
	expH := 8
	if expY+expH >= h {
		expH = max(6, h-expY-1)
	}
	drawPanel(s, 0, expY, w, expH, "RUNTIME EXPORTS", "")
	debugValue := nonEmptySIEMValue(app.SIEMDebugLogPath, "(disabled)")
	rulesValue := nonEmptySIEMValue(app.SIEMRulesJSONPath, "(disabled)")
	expRows := []struct {
		field int
		label string
		value string
	}{
		{siemFieldDebugLog, "Debug log", debugValue},
		{siemFieldRulesJSON, "Rules JSON", rulesValue},
		{siemFieldApply, "Apply", "Apply export paths to runtime"},
		{siemFieldSave, "Save", "Save export paths to keystore + apply"},
		{siemFieldDisable, "Disable", "Clear runtime export paths"},
	}
	for i, row := range expRows {
		y := expY + 1 + i
		if y >= expY+expH-1 {
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
		if app.SIEMEditing && rowSelected {
			value += " [edit]"
		}
		fillSelectedRowBar(s, y, 2, w-3, rowSelected)
		labelText := fmt.Sprintf("%s %-13s", prefix, row.label+":")
		labelText = TruncateToWidth(labelText, w-4)
		PutStringStyle(s, 2, y, labelText, applySelectedRowStyle(labelStyle, rowSelected))
		valueX := 2 + len(labelText) + 2
		if valueX < w-2 {
			PutStringStyle(s, valueX, y, TruncateToWidth(value, w-valueX-2), applySelectedRowStyle(valueStyle, rowSelected))
		}
		PutStringStyle(s, 2, y, string(prefix), applySelectedRowStyle(prefixStyle, rowSelected))
	}

	reportY := expY + expH
	reportH := max(4, h-reportY)
	if reportY+reportH > h {
		reportH = h - reportY
	}
	if reportH >= 3 {
		drawPanel(s, 0, reportY, w, reportH, "REPORT", "SIEM")
		row := reportY + 1
		lines := app.SIEMReportLines
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

	rows := []struct {
		label string
		value string
	}{
		{"OpenAI key", keystore.MaskValue("OPENAI_API_KEY", app.KeystoreValues["OPENAI_API_KEY"])},
		{"OpenAI base URL", keystore.MaskValue("OPENAI_BASE_URL", app.KeystoreValues["OPENAI_BASE_URL"])},
		{"Anthropic key", keystore.MaskValue("ANTHROPIC_API_KEY", app.KeystoreValues["ANTHROPIC_API_KEY"])},
		{"Anthropic base URL", keystore.MaskValue("ANTHROPIC_BASE_URL", app.KeystoreValues["ANTHROPIC_BASE_URL"])},
		{"Local LLM URL", keystore.MaskValue("LOCAL_LLM_URL", app.KeystoreValues["LOCAL_LLM_URL"])},
		{"Local LLM API key", keystore.MaskValue("LOCAL_LLM_API_KEY", app.KeystoreValues["LOCAL_LLM_API_KEY"])},
		{"Calibration timeout", keystore.MaskValue("CALIBRATION_HTTP_TIMEOUT", app.KeystoreValues["CALIBRATION_HTTP_TIMEOUT"])},
		{"BloodHound URL", keystore.MaskValue("BLOODHOUND_API_URL", app.KeystoreValues["BLOODHOUND_API_URL"])},
		{"BloodHound token", keystore.MaskValue("BLOODHOUND_API_TOKEN", app.KeystoreValues["BLOODHOUND_API_TOKEN"])},
		{"BloodHound token ID", keystore.MaskValue("BLOODHOUND_API_TOKEN_ID", app.KeystoreValues["BLOODHOUND_API_TOKEN_ID"])},
		{"TLS dir", keystore.MaskValue("PROXYWATCH_TLS_DIR", app.KeystoreValues["PROXYWATCH_TLS_DIR"])},
		{"Agent token", keystore.MaskValue("PROXYWATCH_AGENT_TOKEN", app.KeystoreValues["PROXYWATCH_AGENT_TOKEN"])},
		{"Disable client cert", keystore.MaskValue("PROXYWATCH_DISABLE_CLIENT_CERT", app.KeystoreValues["PROXYWATCH_DISABLE_CLIENT_CERT"])},
		{"Trust on first use", keystore.MaskValue("PROXYWATCH_TRUST_ON_FIRST_USE", app.KeystoreValues["PROXYWATCH_TRUST_ON_FIRST_USE"])},
		{"Load", "Load encrypted keystore"},
		{"Save", "Save encrypted keystore"},
		{"Apply", "Apply values to runtime"},
	}
	setupY := 4
	setupH := len(rows) + 4
	if setupY+setupH >= h {
		setupH = max(10, h-setupY-1)
	}
	if setupY+setupH > h {
		setupH = max(3, h-setupY)
	}
	drawPanel(s, 0, setupY, w, setupH, "KEYSTORE SETUP", "")
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
	rowStart := 0
	if maxVisibleRows > 0 && len(rows) > maxVisibleRows {
		rowStart = app.KeystoreField - maxVisibleRows + 1
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
		rowSelected := i == app.KeystoreField
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
		if app.KeystoreEditing && rowSelected {
			value += " [edit]"
		}
		fillSelectedRowBar(s, y, 2, w-3, rowSelected)
		labelText := fmt.Sprintf("%s %-20s", prefix, row.label+":")
		labelText = TruncateToWidth(labelText, w-4)
		PutStringStyle(s, 2, y, labelText, applySelectedRowStyle(labelStyle, rowSelected))
		valueX := 2 + len(labelText) + 2
		if valueX < w-2 {
			PutStringStyle(s, valueX, y, TruncateToWidth(value, w-valueX-2), applySelectedRowStyle(valueStyle, rowSelected))
		}
		PutStringStyle(s, 2, y, string(prefix), applySelectedRowStyle(prefixStyle, rowSelected))
	}

	notesY := setupY + setupH
	notesH := max(4, h-notesY)
	if notesY+notesH > h {
		notesH = h - notesY
	}
	if notesH >= 3 {
		drawPanel(s, 0, notesY, w, notesH, "NOTES", "Keystore")
		if notesY+1 < h {
			PutStringStyle(s, 2, notesY+1, TruncateToWidth("Load/Save encrypts values on disk using AES-GCM and a local machine key file.", w-4), styleMuted)
		}
		if notesY+2 < h {
			PutStringStyle(s, 2, notesY+2, TruncateToWidth("Applied values update BloodHound, Calibration, and transport security runtime config.", w-4), styleMuted)
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
	switch trimmed {
	case "Overview", "Tuning", "Validation", "Risks", "Learning", "Memory", "Reasoning", "Similar runs:":
		return styleCyanB
	}
	if strings.HasPrefix(trimmed, "Summary:") {
		return styleTextB
	}
	if trimmed == "Successful checks:" || trimmed == "Failed checks:" {
		return styleTextB
	}
	if trimmed == "Successful checks:" || trimmed == "Failed checks:" {
		return styleTextB
	}
	if strings.HasPrefix(trimmed, "Mode: fallback") {
		return styleWarn
	}
	if strings.HasPrefix(trimmed, "Analysis error:") {
		return styleAlert
	}
	if strings.HasPrefix(trimmed, "Collection phase active.") || strings.HasPrefix(trimmed, "Remaining:") || strings.HasPrefix(trimmed, "Samples captured:") || strings.HasPrefix(trimmed, "Unique processes:") || strings.HasPrefix(trimmed, "Roles:") || strings.HasPrefix(trimmed, "States:") {
		return styleText
	}
	if strings.HasPrefix(trimmed, "Recent collected processes:") {
		return styleCyanB
	}
	if strings.HasPrefix(trimmed, "Mode:") || strings.HasPrefix(trimmed, "Scope:") || strings.HasPrefix(trimmed, "Provider:") || strings.HasPrefix(trimmed, "Observed:") || strings.HasPrefix(trimmed, "Quality:") || strings.HasPrefix(trimmed, "Precision/Recall:") || strings.HasPrefix(trimmed, "False positives/negatives:") || strings.HasPrefix(trimmed, "Samples:") || strings.HasPrefix(trimmed, "Runs:") || strings.HasPrefix(trimmed, "Validated calibrations:") {
		return styleText
	}
	if strings.HasPrefix(trimmed, "Dataset:") || strings.HasPrefix(trimmed, "Report:") || strings.HasPrefix(trimmed, "Model:") || strings.HasPrefix(trimmed, "Training dataset:") || strings.HasPrefix(trimmed, "Top processes:") || strings.HasPrefix(trimmed, "Normal baseline:") {
		return styleMuted
	}
	if strings.Contains(strings.ToLower(trimmed), "regressed") {
		return styleAlert
	}
	if strings.Contains(strings.ToLower(trimmed), "improved") {
		return styleWatch
	}
	if strings.HasPrefix(trimmed, "- ") {
		return styleText
	}
	if strings.HasPrefix(line, "  ") {
		return styleMuted
	}
	return styleText
}

func siemReportLineStyle(line string) tcell.Style {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return styleText
	}
	if strings.HasPrefix(trimmed, "# ") || strings.HasPrefix(trimmed, "## ") || strings.HasPrefix(trimmed, "### ") {
		return styleCyanB
	}
	if strings.HasPrefix(trimmed, "Generated:") || strings.HasPrefix(trimmed, "Mode:") || strings.HasPrefix(trimmed, "Provider/Model:") || strings.HasPrefix(trimmed, "Source calibration ") || strings.HasPrefix(trimmed, "Scope:") {
		return styleMuted
	}
	if strings.HasPrefix(trimmed, "Role:") || strings.HasPrefix(trimmed, "Description:") {
		return styleTextB
	}
	if strings.HasPrefix(trimmed, "Processes:") || strings.HasPrefix(trimmed, "Signals:") || strings.HasPrefix(trimmed, "Reasons:") {
		return styleText
	}
	if strings.HasSuffix(trimmed, "query:") {
		return styleWarn
	}
	if strings.HasPrefix(trimmed, "```") {
		return styleMuted
	}
	if strings.HasPrefix(trimmed, "- ") {
		return styleText
	}
	if strings.Contains(trimmed, "[HIGH]") || strings.Contains(trimmed, "[CRITICAL]") {
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
		"listener": 0,
		"outbound": 0,
		"other":    0,
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
		seen[key] = stats{
			key:   key,
			host:  shared.DisplayHost(sample.Host),
			pid:   sample.Proc.Pid,
			name:  sample.Proc.Name,
			role:  family,
			state: state,
			age:   formatDashboardAge(sample.ControlDurationSeconds),
		}
		order = append(order, key)
	}

	lines := make([]string, 0, 20)
	lines = append(lines, "Collection phase active. Analysis starts after collection timer completes.")
	lines = append(lines, "Remaining: "+remaining.String())
	lines = append(lines, fmt.Sprintf("Samples captured: %d", len(app.CalibrateSamples)))
	lines = append(lines, fmt.Sprintf("Unique processes: %d", len(order)))
	lines = append(lines, fmt.Sprintf("Roles: session %d   beacon %d   tunnel %d   listener %d   outbound %d", roleCounts["session"], roleCounts["beacon"], roleCounts["tunnel"], roleCounts["listener"], roleCounts["outbound"]))
	lines = append(lines, fmt.Sprintf("States: watch %d   strong %d   active %d", stateCounts["watch"], stateCounts["strong"], stateCounts["active"]))
	lines = append(lines, "")
	lines = append(lines, "Recent collected processes:")

	added := 0
	for i := len(order) - 1; i >= 0 && added < 8; i-- {
		item := seen[order[i]]
		lines = append(lines, fmt.Sprintf("- %-5s %-6d %-24s role=%-8s state=%-6s age=%s", item.host, item.pid, ClipToWidth(item.name, 24), item.role, item.state, item.age))
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
	isListener := contour.NormalizeProbeRole(app.ContourProbeRole) == contour.ProbeRoleListen
	if app.ContourAnalyzing {
		if isListener {
			return "Stop contour (listener active)"
		}
		return "Stop contour (cancel run)"
	}
	if app.ContourActive {
		if isListener {
			return "Stop contour (starting listener)"
		}
		if app.ContourUntil.IsZero() {
			return "Stop contour (collecting)"
		}
		remaining := time.Until(app.ContourUntil).Round(time.Second)
		if remaining < 0 {
			remaining = 0
		}
		if remaining == 0 {
			return "Stop contour (starting run)"
		}
		return "Stop contour (" + remaining.String() + " left)"
	}
	if isListener {
		return "Start contour (" + contour.ProbeRoleLabel(app.ContourProbeRole) + ")"
	}
	return "Start contour (" + contour.ProbeRoleLabel(app.ContourProbeRole) + " / " + contour.ProbeModeLabel(app.ContourProbeMode) + ")"
}

func contourReportLineStyle(line string) tcell.Style {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return styleText
	}
	switch trimmed {
	case "Overview", "Probe Matrix", "Probe Methods", "Tunnel Methods", "Exfiltration Methods", "Probe Ports", "Probe Checks", "Probe Discoveries", "Listener Ports", "Listener Checks", "Findings":
		return styleCyanB
	}
	if strings.HasPrefix(trimmed, "Summary:") {
		return styleTextB
	}
	if trimmed == "Successful checks:" || trimmed == "Failed checks:" {
		return styleTextB
	}
	if strings.Contains(trimmed, "[PASS]") {
		return styleCyan
	}
	if strings.Contains(trimmed, "[UP]") {
		return styleCyan
	}
	if strings.Contains(trimmed, "[PIVOT]") {
		return styleWarn
	}
	if strings.Contains(trimmed, "[FAIL]") {
		return styleAlert
	}
	if strings.Contains(trimmed, "[MIXED]") {
		return styleWarn
	}
	if strings.Contains(trimmed, "[NONE]") {
		return styleMuted
	}
	if strings.Contains(trimmed, "[ACTIVE]") {
		return styleAlertB
	}
	if strings.Contains(trimmed, "[STRONG]") {
		return styleWarn
	}
	if strings.HasPrefix(trimmed, "Report:") || strings.HasPrefix(trimmed, "Duration:") || strings.HasPrefix(trimmed, "Sample every:") || strings.HasPrefix(trimmed, "Source:") || strings.HasPrefix(trimmed, "Endpoint:") || strings.HasPrefix(trimmed, "Role:") || strings.HasPrefix(trimmed, "Captured samples:") || strings.HasPrefix(trimmed, "Unique processes:") || strings.HasPrefix(trimmed, "Findings:") || strings.HasPrefix(trimmed, "Calibration hints exported:") || strings.HasPrefix(trimmed, "Probe mode:") || strings.HasPrefix(trimmed, "Probe matrix") || strings.HasPrefix(trimmed, "Probe checks:") || strings.HasPrefix(trimmed, "Probe routes:") || strings.HasPrefix(trimmed, "Probe proxies:") || strings.HasPrefix(trimmed, "Probe config endpoints:") || strings.HasPrefix(trimmed, "Probe listener:") || strings.HasPrefix(trimmed, "Probe ports:") || strings.HasPrefix(trimmed, "Probe protocols:") || strings.HasPrefix(trimmed, "Internet-routable subnets:") || strings.HasPrefix(trimmed, "Proxy candidates:") || strings.HasPrefix(trimmed, "Config endpoints:") || strings.HasPrefix(trimmed, "Ports unavailable:") || strings.HasPrefix(trimmed, "Listener exchanges:") || strings.HasPrefix(trimmed, "Listener checks:") || strings.HasPrefix(trimmed, "Tunnel checks:") || strings.HasPrefix(trimmed, "Exfil checks:") || strings.HasPrefix(trimmed, "Ports bound:") {
		return styleMuted
	}
	if strings.HasPrefix(trimmed, "- ") {
		return styleText
	}
	return styleText
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
