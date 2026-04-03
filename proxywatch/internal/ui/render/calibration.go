package render

import (
	"fmt"
	"strings"
	"time"

	"proxywatch/internal/calibration"
	"proxywatch/internal/shared"
	"proxywatch/internal/ui/common"

	"github.com/gdamore/tcell/v2"
)

func DrawCalibration(app *shared.AppState) {
	s := app.Screen
	common.ClearScreen(s)
	cursorVisible := false
	cursorX, cursorY := 0, 0

	w, h := s.Size()
	common.DrawPanel(s, 0, 0, w, 4, "Calibration", "proxywatch")
	common.PutStringStyle(s, 2, 2, "? help", common.StyleDim)
	utcLabel := "UTC: "
	utcValue := time.Now().UTC().Format(common.UTCTimeFormat)
	scopeLabel := "Scope: "
	scopeValue := common.SafeRolePreset(app)
	providerLabel := calibration.ProviderLabel(app.CalibrateProvider)
	blockWidth := max(len(utcLabel)+len(utcValue), len(scopeLabel)+len(scopeValue))
	blockX := max(2, w-2-blockWidth)
	common.PutStringStyle(s, blockX, 1, utcLabel, common.StyleCyanB)
	common.PutStringStyle(s, blockX+len(utcLabel), 1, utcValue, common.StyleTextB)
	common.PutStringStyle(s, blockX, 2, scopeLabel, common.StyleCyanB)
	common.PutStringStyle(s, blockX+len(scopeLabel), 2, scopeValue, common.StyleTextB)
	if app.CalibrateAnalyzing || app.CalibrateActive {
		elapsed := common.SpinnerElapsed(app.CalibrateStartedAt)
		phase := "Calibration in progress"
		if app.CalibrateAnalyzing {
			phase = "Analyzing calibration data"
		}
		msg := fmt.Sprintf("%s %s... elapsed %s", common.SpinnerFrame(), phase, elapsed.String())
		statusW := max(0, blockX-4)
		if statusW > 0 {
			common.PutStringStyle(s, 2, 1, common.TruncateToWidth(msg, statusW), common.StyleWarn)
		}
	} else if app.CalibrateStatusText != "" && time.Now().Before(app.CalibrateStatusUntil) {
		statusW := max(0, blockX-4)
		if statusW > 0 {
			st := common.StyleText
			if app.CalibrateStatusError {
				st = common.StyleAlert
			}
			common.PutStringStyle(s, 2, 1, common.TruncateToWidth(app.CalibrateStatusText, statusW), st)
		}
	}

	setupY := 4
	setupH := 10
	if setupY+setupH >= h {
		setupH = max(6, h-setupY-1)
	}
	common.DrawPanel(s, 0, setupY, w, setupH, "CALIBRATION SETUP", "")

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
		{"Action", CalibrationActionLabel(app)},
		{"Apply", "Apply selected profile"},
	}
	for i, ln := range setupLines {
		row := setupY + 1 + i
		if row >= setupY+setupH-1 {
			break
		}
		rowSelected := i == app.CalibrateField
		prefix := " "
		labelStyle := common.StyleMuted
		valueStyle := common.StyleText
		prefixStyle := common.StyleText
		if rowSelected {
			prefix = ">"
			valueStyle = common.StyleTextB
			prefixStyle = common.StyleTextB
		}
		value := ln.value
		common.FillSelectedRowBar(s, row, 2, w-3, rowSelected)
		labelText := fmt.Sprintf("%s %-9s", prefix, ln.label+":")
		labelText = common.TruncateToWidth(labelText, w-4)
		common.PutStringStyle(s, 2, row, labelText, common.ApplySelectedRowStyle(labelStyle, rowSelected))
		valueX := 2 + len(labelText) + 2
		if valueX < w-2 {
			valueW := max(0, w-valueX-2)
			common.PutStringStyle(s, valueX, row, common.TruncateToWidth(value, valueW), common.ApplySelectedRowStyle(valueStyle, rowSelected))
			if rowSelected && app.CalibrateEditing && i == calibrateFieldOutput && !app.ShowCalibrateHelp && !app.ShowCalibrateMenu {
				cursorVisible = true
				cursorX = common.TextCursorX(valueX, value, valueW)
				cursorY = row
			}
		}
		common.PutStringStyle(s, 2, row, string(prefix), common.ApplySelectedRowStyle(prefixStyle, rowSelected))
		common.DrawEditingTag(s, row, w, rowSelected && app.CalibrateEditing && i == calibrateFieldOutput)
	}

	accessY := setupY + setupH
	accessH := 7
	if accessY+accessH >= h {
		accessH = max(5, h-accessY-1)
	}
	common.DrawPanel(s, 0, accessY, w, accessH, "PROVIDER ACCESS", "")
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
		labelText = common.TruncateToWidth(labelText, w-4)
		common.PutStringStyle(s, 2, y, labelText, common.StyleMuted)

		value := "missing"
		valueStyle := common.StyleAlert
		if item.ok {
			value = "present"
			valueStyle = common.StyleWatch
		}
		valueX := 2 + len(labelText) + 2
		if valueX < w-2 {
			common.PutStringStyle(s, valueX, y, common.TruncateToWidth(value, w-valueX-2), valueStyle)
		}
	}

	reportY := accessY + accessH
	reportH := h - reportY
	if reportH < 4 {
		drawCalibrationOverlays(app, w, h)
		return
	}
	calibPanelLabel := "LATEST REPORT"
	if app.CalibrateActive || app.CalibrateAnalyzing {
		calibPanelLabel = "LIVE"
	}
	common.DrawPanel(s, 0, reportY, w, reportH, calibPanelLabel, "")
	row := reportY + 1
	lines := app.CalibrateReportLines
	if (app.CalibrateActive || app.CalibrateAnalyzing) && len(app.CalibrateProgressLines) > 0 {
		lines = app.CalibrateProgressLines
		visible := reportH - 2
		if visible > 0 && len(lines) > visible {
			app.CalibrateReportScroll = len(lines) - visible
		}
	} else if app.CalibrateActive && !app.CalibrateAnalyzing {
		lines = CalibrationCollectionLines(app)
	} else if len(lines) == 0 && strings.TrimSpace(app.CalibrateReportSummary) != "" {
		lines = []string{app.CalibrateReportSummary}
		for _, rec := range app.CalibrateRecommendations {
			lines = append(lines, "- "+rec)
		}
	}
	lines = NormalizeCalibrationReportLines(lines, max(10, w-4))
	if len(lines) == 0 {
		app.CalibrateReportMaxScroll = 0
		common.PutStringStyle(s, 2, row, common.TruncateToWidth("No calibration report has been generated yet.", w-4), common.StyleText)
		row++
		if row < reportY+reportH-1 {
			common.PutStringStyle(s, 2, row, common.TruncateToWidth("Choose a duration, provider, and optional model override, then run Start calibration.", w-4), common.StyleMuted)
			row++
		}
		if row < reportY+reportH-1 {
			common.PutStringStyle(s, 2, row, common.TruncateToWidth("You can still select a saved profile above and use Apply.", w-4), common.StyleMuted)
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
		common.PutStringStyle(s, max(2, w-26), reportY+reportH-1, fmt.Sprintf("Report %d-%d of %d", startDisp, endDisp, len(lines)), common.StyleCyanB)
	}

	now := time.Now()
	if app.CalibrateStatusText != "" && now.Before(app.CalibrateStatusUntil) {
		st := common.StyleText
		if app.CalibrateStatusError {
			st = common.StyleAlert
		}
		common.PutStringStyle(s, 2, reportY+reportH-2, common.TruncateToWidth(app.CalibrateStatusText, w-4), st)
	}
	if cursorVisible {
		common.ShowInputCursor(s, cursorX, cursorY)
	}

	drawCalibrationOverlays(app, w, h)
}

func NormalizeCalibrationReportLines(lines []string, width int) []string {
	if len(lines) == 0 {
		return lines
	}
	summaryWidth := max(12, width-common.CalibrationReportLabelWidth-2)
	normalized := make([]string, 0, len(lines)+8)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Mode:") || strings.HasPrefix(trimmed, "Scope:") {
			continue
		}
		if strings.HasPrefix(trimmed, "Summary:") {
			summary := strings.TrimSpace(strings.TrimPrefix(trimmed, "Summary:"))
			wrapped := common.WrapWords(summary, summaryWidth)
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

func drawCalibrationReportRow(s tcell.Screen, x, y, width int, line string) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || width <= 0 {
		return
	}
	if !strings.HasPrefix(trimmed, "- ") && !strings.HasPrefix(line, "  ") && strings.Contains(line, ":") {
		colon := strings.Index(line, ":")
		if colon > 0 {
			label := common.ClipToWidth(strings.TrimSpace(line[:colon+1]), common.CalibrationReportLabelWidth-1)
			value := strings.TrimSpace(line[colon+1:])
			labelText := fmt.Sprintf(" %-*s", common.CalibrationReportLabelWidth-1, label)
			labelText = common.TruncateToWidth(labelText, width)
			common.PutStringStyle(s, x, y, labelText, common.StyleMuted)
			valueX := x + len(labelText) + 1
			if valueX < x+width {
				valueStyle := calibrationReportLineStyle(line)
				if strings.HasPrefix(trimmed, "Summary:") {
					valueStyle = common.StyleTextB
				}
				common.PutStringStyle(s, valueX, y, common.TruncateToWidth(value, x+width-valueX), valueStyle)
			}
			return
		}
	}
	common.PutStringStyle(s, x, y, common.TruncateToWidth(line, width), calibrationReportLineStyle(line))
}

func calibrationReportLineStyle(line string) tcell.Style {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return common.StyleText
	}
	switch trimmed {
	case "Tuning", "Validation", "Recommendations", "Learning", "History", "Reasoning":
		return common.StyleCyanB
	}
	if strings.HasPrefix(trimmed, "Collection phase active.") || strings.HasPrefix(trimmed, "Remaining:") ||
		strings.HasPrefix(trimmed, "Samples captured:") || strings.HasPrefix(trimmed, "Unique processes:") ||
		strings.HasPrefix(trimmed, "Roles:") || strings.HasPrefix(trimmed, "States:") {
		return common.StyleText
	}
	if strings.HasPrefix(trimmed, "Recent collected") {
		return common.StyleCyanB
	}
	if strings.Contains(trimmed, "[FAIL]") {
		return common.StyleAlert
	}
	if strings.HasPrefix(trimmed, "Confidence:") {
		if strings.Contains(trimmed, "(high)") {
			return common.StyleCyan
		}
		if strings.Contains(trimmed, "(moderate)") {
			return common.StyleWarn
		}
		return common.StyleAlert
	}
	if strings.Contains(trimmed, "Contamination:") {
		if strings.Contains(trimmed, "(clean)") {
			return common.StyleCyan
		}
		if strings.Contains(trimmed, "(low)") {
			return common.StyleWatch
		}
		if strings.Contains(trimmed, "(elevated)") {
			return common.StyleWarn
		}
		return common.StyleAlert
	}
	if strings.Contains(trimmed, "regressed") {
		return common.StyleAlert
	}
	if strings.Contains(trimmed, "improved") {
		return common.StyleWatch
	}
	if strings.Contains(trimmed, "[RISK]") {
		return common.StyleWarn
	}
	if strings.HasPrefix(trimmed, "- Warning:") {
		return common.StyleWarn
	}
	if strings.HasPrefix(trimmed, "- ") {
		return common.StyleText
	}
	if strings.HasPrefix(line, "  ") {
		return common.StyleMuted
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

func CalibrationCollectionLines(app *shared.AppState) []string {
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
		"control-session": 0,
		"control-beacon":  0,
		"control-pivot":   0,
		"control-tunnel":  0,
		"analyzing":       0,
		"listen":          0,
		"outbound":        0,
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
			age:   common.FormatDashboardAge(age),
		}
		order = append(order, key)
	}

	elapsed := time.Since(app.CalibrateStartedAt).Round(time.Second)
	lines := make([]string, 0, 20)
	lines = append(lines, fmt.Sprintf("[*] Collecting calibration data  |  elapsed %s  |  %s remaining", elapsed, remaining))
	lines = append(lines, fmt.Sprintf("[+] %d samples  |  %d unique processes", len(app.CalibrateSamples), len(order)))

	roleParts := make([]string, 0, 6)
	for _, r := range []string{"control-session", "control-beacon", "control-pivot", "control-tunnel", "analyzing", "listen", "outbound"} {
		if n := roleCounts[r]; n > 0 {
			roleParts = append(roleParts, fmt.Sprintf("%s %d", r, n))
		}
	}
	if len(roleParts) > 0 {
		lines = append(lines, "[+] "+strings.Join(roleParts, "  "))
	}
	lines = append(lines, fmt.Sprintf("[+] watch %d  strong %d  active %d", stateCounts["watch"], stateCounts["strong"], stateCounts["active"]))

	lines = append(lines, "")
	lines = append(lines, "[*] Recent processes:")
	added := 0
	for i := len(order) - 1; i >= 0 && added < 8; i-- {
		item := seen[order[i]]
		lines = append(lines, fmt.Sprintf("    %-5s %-9d %-20s %8s %-6s %s", item.host, item.pid, common.ClipToWidth(item.name, 20), item.role, item.state, item.age))
		added++
	}
	if added == 0 {
		lines = append(lines, "- none captured yet")
	}
	return lines
}

func drawCalibrationOverlays(app *shared.AppState, w, h int) {
	if app.ShowCalibrateHelp {
		opts := common.CalibrationMenuHelpOptions()
		common.DrawMenuPanel(app.Screen, w, h, "Calibration Menu", opts, common.ClampIndex(app.CalibrateHelpIndex, len(opts)), "")
	}
	if app.ShowCalibrateMenu {
		common.DrawMenuPanel(
			app.Screen,
			w,
			h,
			app.CalibrateMenuTitle,
			app.CalibrateMenuOptions,
			common.ClampIndex(app.CalibrateMenuIndex, len(app.CalibrateMenuOptions)),
			"Enter apply   Esc close",
		)
	}
}

func CalibrationActionLabel(app *shared.AppState) string {
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
