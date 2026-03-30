package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/gdamore/tcell/v2"

	"proxywatch/internal/calibration"
	"proxywatch/internal/shared"
	"proxywatch/internal/siem"
)

// SIEMModel is the native bubbletea model for the SIEM view.
type SIEMModel struct {
	app        *shared.AppState
	viewport   viewport.Model
	width      int
	height     int
	ready      bool
	contentKey uint64
}

func NewSIEMModel(app *shared.AppState) SIEMModel {
	return SIEMModel{app: app}
}

func (m SIEMModel) Init() tea.Cmd { return nil }

func (m SIEMModel) Update(msg tea.Msg) (SIEMModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.initViewport()
		m.refreshContent()

	case tea.KeyMsg:
		tev := convertKeyMsg(msg)

		// Quit confirm.
		handled, shouldQuit := handleQuitConfirmKey(m.app, tev)
		if handled {
			if shouldQuit {
				return m, tea.Quit
			}
			return m, nil
		}

		// Workflow cycling.
		switch tev.Key() {
		case tcell.KeyLeft:
			if stepWorkflowMenu(m.app, -1) {
				return m, nil
			}
		case tcell.KeyRight:
			if stepWorkflowMenu(m.app, 1) {
				return m, nil
			}
		}

		// Scroll the report viewport.
		if m.ready && !m.app.SIEMShowMenu && !m.app.SIEMShowHelp && !m.app.SIEMEditing {
			if m.handleScroll(tev) {
				return m, nil
			}
		}

		// Delegate to legacy SIEM key handler.
		if handleSIEMKey(m.app, tev) {
			return m, tea.Quit
		}
	}

	m.refreshContent()
	return m, nil
}

func (m *SIEMModel) handleScroll(tev *tcell.EventKey) bool {
	if !m.ready {
		return false
	}
	switch tev.Key() {
	case tcell.KeyPgUp:
		m.viewport.LineUp(m.viewport.VisibleLineCount())
		return true
	case tcell.KeyPgDn:
		m.viewport.LineDown(m.viewport.VisibleLineCount())
		return true
	case tcell.KeyHome:
		m.viewport.GotoTop()
		return true
	case tcell.KeyEnd:
		m.viewport.GotoBottom()
		return true
	}
	switch tev.Rune() {
	case '[':
		m.viewport.LineUp(1)
		return true
	case ']':
		m.viewport.LineDown(1)
		return true
	}
	return false
}

func (m SIEMModel) View() string {
	w := m.width
	h := m.height
	if w <= 0 {
		w = 80
	}
	if h <= 0 {
		h = 24
	}

	var sections []string
	sections = append(sections, m.renderHeader())
	sections = append(sections, m.renderSetup())
	sections = append(sections, m.renderReportPanel())

	view := lipgloss.JoinVertical(lipgloss.Left, sections...)

	if m.app.SIEMShowMenu {
		view = overlayCenter(view, renderMenuPanel(
			m.app.SIEMMenuTitle,
			m.app.SIEMMenuOptions,
			m.app.SIEMMenuIndex,
			"", w), w, h)
	}
	if m.app.SIEMShowHelp {
		view = overlayCenter(view, renderHelpPanel("SIEM Menu", siemMenuHelpOptions(), w), w, h)
	}
	if m.app.ShowQuitConfirm && m.app.QuitConfirmDeadline.After(time.Now()) {
		view += "\n" + renderQuitConfirm(m.app.QuitConfirmDeadline, w)
	}
	return view
}

func (m SIEMModel) renderHeader() string {
	w := m.width
	if w <= 0 {
		w = 80
	}
	contentW := w - 2
	helpPlain := "? help"
	utcPlain := "UTC: " + time.Now().UTC().Format(utcTimeFormat)
	gap := max(1, contentW-len(helpPlain)-len(utcPlain))
	line := dimText.Render(helpPlain) + bgSp(gap) +
		rightLabelStyle.Render("UTC: ") + sectionLabel.Render(time.Now().UTC().Format(utcTimeFormat))
	return renderPanel(w, 3, "SIEM", "proxywatch", "", line)
}

func (m SIEMModel) headerHeight() int { return 3 }

// ── Setup panel ──────────────────────────────────────────────────────────────

func (m SIEMModel) setupHeight() int {
	h := 7 // border + 5 fields + border
	if len(m.app.SIEMSourceReports) == 0 {
		h++ // Calibrate row
	}
	return h
}

func (m SIEMModel) renderSetup() string {
	_ = calibration.DetectProviderAccess()
	provider := calibration.ProviderLabel(m.app.SIEMProvider)

	sourceValue := "(none found)"
	if len(m.app.SIEMSourceReports) > 0 {
		selected := nonEmptySIEMValue(m.app.SIEMSourceReport, m.app.SIEMSourceReports[0])
		sourceValue = fmt.Sprintf("%s (%d found)", selected, len(m.app.SIEMSourceReports))
	}

	genLabel := "▶ Build SIEM detections"
	if m.app.SIEMGenerating {
		genLabel = fmt.Sprintf("■ Stop generation (%s elapsed)", spinnerElapsed(m.app.SIEMStartedAt))
	}

	rows := []FormRow{
		{Field: siemFieldProvider, Label: "Provider", Value: provider},
		{Field: siemFieldModel, Label: "Model", Value: nonEmptySIEMValue(m.app.SIEMModel, calibration.DefaultModel(m.app.SIEMProvider))},
		{Field: siemFieldSourceReport, Label: "Profile", Value: sourceValue},
		{Field: siemFieldJSONOutput, Label: "Output", Value: nonEmptySIEMValue(m.app.SIEMExportPath, siem.DefaultSIEMJSONPath()), Editable: true},
		{Field: siemFieldGenerate, Label: "Generate", Value: genLabel},
	}

	// Only show Calibrate option when no calibration reports exist.
	if len(m.app.SIEMSourceReports) == 0 {
		rows = append(rows, FormRow{Field: siemFieldCalibrate, Label: "Calibrate", Value: "Open Calibration"})
	}

	w := m.width
	if w <= 0 {
		w = 80
	}
	return renderSetupPanel("SETUP", rows, m.app.SIEMField, m.app.SIEMEditing, w)
}

// ── Report panel ─────────────────────────────────────────────────────────────

func (m *SIEMModel) initViewport() {
	if m.width <= 0 || m.height <= 0 {
		return
	}
	reportH := m.height - m.headerHeight() - m.setupHeight()
	// Always reserve 1 line for the status bar below the panel.
	reportH--
	if reportH < 4 {
		reportH = 4
	}
	if !m.ready {
		m.viewport = viewport.New(m.width-4, reportH-2)
		m.viewport.Style = lipgloss.NewStyle()
		m.ready = true
	} else {
		m.viewport.Width = m.width - 4
		m.viewport.Height = reportH - 2
	}
}

func (m *SIEMModel) refreshContent() {
	if !m.ready {
		return
	}
	content := m.buildContent()
	h := quickHash(content)
	if h != m.contentKey {
		m.contentKey = h
		m.viewport.SetContent(content)
	}
}

func (m SIEMModel) buildContent() string {
	// Snapshot progress lines under lock.
	m.app.ProgressMu.Lock()
	progressLines := append([]string(nil), m.app.SIEMProgressLines...)
	m.app.ProgressMu.Unlock()

	// Live generation: show task checklist like calibration.
	if m.app.SIEMGenerating && len(progressLines) == 0 {
		spinFrames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		frame := spinFrames[int(time.Now().UnixMilli()/120)%len(spinFrames)]
		spinner := lipgloss.NewStyle().Foreground(colorCyan).Bold(true).Render(frame)
		return "  " + spinner + " " + sectionLabel.Render("Starting generation...")
	}
	if m.app.SIEMGenerating && len(progressLines) > 0 {
		var out []string
		plines := progressLines
		for i, line := range plines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "[*]") {
				task := strings.TrimSpace(strings.TrimPrefix(trimmed, "[*]"))
				if i == len(plines)-1 {
					// Last pending task: show spinner.
					spinFrames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
					frame := spinFrames[int(time.Now().UnixMilli()/120)%len(spinFrames)]
					spinner := lipgloss.NewStyle().Foreground(colorCyan).Bold(true).Render(frame)
					out = append(out, "  "+spinner+" "+sectionLabel.Render(task))
				} else {
					out = append(out, statusPass.Render("  ● ")+bodyText.Render(task))
				}
			} else if strings.HasPrefix(trimmed, "[+]") {
				task := strings.TrimSpace(strings.TrimPrefix(trimmed, "[+]"))
				out = append(out, statusPass.Render("  ● ")+bodyText.Render(task))
			} else if strings.HasPrefix(trimmed, "[-]") {
				task := strings.TrimSpace(strings.TrimPrefix(trimmed, "[-]"))
				out = append(out, statusFail.Render("  ✗ ")+statusFail.Render(task))
			} else {
				out = append(out, "    "+bodyText.Render(trimmed))
			}
		}
		return strings.Join(out, "\n")
	}

	// Completed report — styled with section bars and severity badges.
	if len(m.app.SIEMReportLines) > 0 {
		return m.buildStyledReport()
	}

	// Empty state.
	return inspValue.Render("No SIEM report has been generated yet.") + "\n" +
		dimText.Render("Select a source report and run Build SIEM detections.") + "\n" +
		func() string {
			if len(m.app.SIEMSourceReports) == 0 {
				return statusFail.Render("No calibration reports found. Run Calibration first.")
			}
			return ""
		}()
}

func (m SIEMModel) buildStyledReport() string {
	sevHigh := lipgloss.NewStyle().Foreground(colorAlert).Bold(true)
	sevMed := lipgloss.NewStyle().Foreground(colorWarn).Bold(true)
	sevLow := lipgloss.NewStyle().Foreground(colorCyan).Bold(true)

	w := m.width - 4
	if w < 20 {
		w = 20
	}

	// Parse lines into sections.
	var summaryLines []string
	var detectionLines []string
	var noteLines []string
	currentSection := "summary" // everything before Detections is summary

	for _, line := range m.app.SIEMReportLines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// Section transitions.
		if trimmed == "Detections" {
			currentSection = "detections"
			continue
		}
		if trimmed == "Notes" {
			currentSection = "notes"
			continue
		}

		switch currentSection {
		case "summary":
			// First line with stats gets highlighted, rest is dim.
			if strings.Contains(trimmed, "detection") && (strings.Contains(trimmed, "candidate") || strings.Contains(trimmed, "|")) {
				summaryLines = append(summaryLines, "  "+inspValue.Render(trimmed))
			} else {
				summaryLines = append(summaryLines, "  "+dimText.Render(trimmed))
			}

		case "detections":
			// Severity-tagged detection titles.
			if strings.Contains(trimmed, "[CRITICAL]") || strings.Contains(trimmed, "[HIGH]") {
				if len(detectionLines) > 0 {
					detectionLines = append(detectionLines, "")
				}
				detectionLines = append(detectionLines, "  "+sevHigh.Render(trimmed))
				continue
			}
			if strings.Contains(trimmed, "[MEDIUM]") {
				if len(detectionLines) > 0 {
					detectionLines = append(detectionLines, "")
				}
				detectionLines = append(detectionLines, "  "+sevMed.Render(trimmed))
				continue
			}
			if strings.Contains(trimmed, "[LOW]") {
				if len(detectionLines) > 0 {
					detectionLines = append(detectionLines, "")
				}
				detectionLines = append(detectionLines, "  "+sevLow.Render(trimmed))
				continue
			}
			// Role/Process/MITRE metadata.
			if strings.Contains(trimmed, "Role:") || strings.Contains(trimmed, "MITRE:") {
				detectionLines = append(detectionLines, "    "+dimText.Render(trimmed))
				continue
			}
			// Description (skip queries/rules — those are in the JSON).
			isQuery := strings.HasPrefix(trimmed, "Splunk:") || strings.HasPrefix(trimmed, "KQL:") ||
				strings.HasPrefix(trimmed, "ESQL:") || strings.HasPrefix(trimmed, "Suricata:") ||
				strings.HasPrefix(trimmed, "YARA:") || strings.HasPrefix(trimmed, "alert ") ||
				strings.HasPrefix(trimmed, "| ") || strings.HasPrefix(trimmed, "where ") ||
				strings.HasPrefix(trimmed, "summarize ") || strings.HasPrefix(trimmed, "stats ") ||
				strings.HasPrefix(trimmed, "meta:") || strings.HasPrefix(trimmed, "strings:") ||
				strings.HasPrefix(trimmed, "condition:") || strings.HasPrefix(trimmed, "$") ||
				strings.HasPrefix(trimmed, "rule ") || trimmed == "}"
			if !isQuery {
				detectionLines = append(detectionLines, "    "+bodyText.Render(trimmed))
			}

		case "notes":
			if strings.HasPrefix(trimmed, "- ") {
				noteLines = append(noteLines, "  "+statusPass.Render("+")+bodyText.Render("  "+strings.TrimPrefix(trimmed, "- ")))
			} else {
				noteLines = append(noteLines, "  "+dimText.Render(trimmed))
			}
		}
	}

	// Build boxes.
	var out []string

	if len(summaryLines) > 0 {
		content := strings.Join(summaryLines, "\n")
		h := len(summaryLines) + 2
		out = append(out, renderAccentPanel(w, h, "SUMMARY", content))
	}

	if len(detectionLines) > 0 {
		content := strings.Join(detectionLines, "\n")
		h := len(detectionLines) + 2
		out = append(out, renderAccentPanel(w, h, "DETECTIONS", content))
	}

	if len(noteLines) > 0 {
		content := strings.Join(noteLines, "\n")
		h := len(noteLines) + 2
		out = append(out, renderAccentPanel(w, h, "NOTES", content))
	}

	if len(out) == 0 {
		return dimText.Render("  No detections generated.")
	}

	return strings.Join(out, "\n")
}

func (m SIEMModel) renderReportPanel() string {
	w := m.width
	if w <= 0 {
		w = 80
	}
	reportH := m.height - m.headerHeight() - m.setupHeight()
	// Always reserve 1 line for the status bar below the panel.
	reportH--
	if reportH < 4 {
		reportH = 4
	}

	panelTitle := "DISPLAY"
	if m.app.SIEMGenerating {
		panelTitle = "GENERATING"
	}

	opts := ReportPanelOpts{
		Title:       panelTitle,
		RightLabel:  "",
		Width:       w,
		Height:      reportH,
		StatusText:  m.app.SIEMStatusText,
		StatusError: m.app.SIEMStatusError,
		StatusUntil: m.app.SIEMStatusUntil,
	}
	if m.ready {
		opts.Content = m.viewport.View()
		total := m.viewport.TotalLineCount()
		visible := m.viewport.VisibleLineCount()
		opts.ScrollTotal = total
		opts.ScrollVisible = visible
		opts.ScrollTop = m.viewport.YOffset + 1
		opts.ScrollBottom = m.viewport.YOffset + visible
		if opts.ScrollBottom > total {
			opts.ScrollBottom = total
		}
	}
	return renderReportPanel(opts)
}

// siemReportLineStyleLipgloss returns a lipgloss-styled version of a SIEM
// report line, matching the legacy tcell color scheme.
func siemReportLineStyleLipgloss(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return bodyText.Render(line)
	}
	// Section headers.
	switch trimmed {
	case "Detections", "Notes":
		return statusPass.Render(line)
	}
	// Severity tags.
	if strings.Contains(trimmed, "[HIGH]") || strings.Contains(trimmed, "[CRITICAL]") {
		return statusFail.Render(line)
	}
	if strings.Contains(trimmed, "[MEDIUM]") {
		return statusMixed.Render(line)
	}
	if strings.Contains(trimmed, "[LOW]") {
		return statusPass.Render(line)
	}
	// Query lines (Splunk:, KQL:, ESQL:).
	if strings.Contains(trimmed, "Splunk:") || strings.Contains(trimmed, "KQL:") || strings.Contains(trimmed, "ESQL:") {
		return dimText.Render(line)
	}
	// Role/Process metadata lines.
	if strings.Contains(trimmed, "Role:") && strings.Contains(trimmed, "Processes:") {
		return dimText.Render(line)
	}
	// Stats line.
	if strings.Contains(trimmed, "detections") && strings.Contains(trimmed, "candidates") {
		return dimText.Render(line)
	}
	// Bullet points.
	if strings.HasPrefix(trimmed, "- ") {
		return bodyText.Render(line)
	}
	// Live progress lines.
	if strings.HasPrefix(trimmed, "[*]") {
		return dimText.Render(line)
	}
	if strings.HasPrefix(trimmed, "[+]") {
		return statusPass.Render(line)
	}
	if strings.HasPrefix(trimmed, "[-]") {
		return statusFail.Render(line)
	}
	return bodyText.Render(line)
}
