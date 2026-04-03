package views

import (
	"fmt"
	"proxywatch/internal/ui/platform"
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

type SIEMModel struct {
	app            *shared.AppState
	viewport       viewport.Model
	width          int
	height         int
	ready          bool
	contentKey     uint64
	dynamicReportH int
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
		m.InitViewport()
		m.RefreshContent()

	case tea.KeyMsg:
		tev := convertKeyMsg(msg)

		handled, shouldQuit := handleQuitConfirmKey(m.app, tev)
		if handled {
			if shouldQuit {
				return m, tea.Quit
			}
			return m, nil
		}

		// Number key workflow jumping.
		if !m.app.SIEMEditing {
			if jumpToWorkflow(m.app, tev.Rune()) {
				return m, nil
			}
		}

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

		if m.ready && !m.app.SIEMShowMenu && !m.app.SIEMShowHelp && !m.app.SIEMEditing {
			if m.handleScroll(tev) {
				return m, nil
			}
		}

		if handleSIEMKey(m.app, tev) {
			return m, tea.Quit
		}
	}

	m.RefreshContent()
	return m, nil
}

func (m *SIEMModel) handleScroll(tev *tcell.EventKey) bool {
	if !m.ready {
		return false
	}
	switch tev.Key() {
	case tcell.KeyPgUp:
		m.viewport.ScrollUp(m.viewport.VisibleLineCount())
		return true
	case tcell.KeyPgDn:
		m.viewport.ScrollDown(m.viewport.VisibleLineCount())
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
		m.viewport.ScrollUp(1)
		return true
	case ']':
		m.viewport.ScrollDown(1)
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

	used := 0
	for _, s := range sections {
		used += lipgloss.Height(s)
	}
	m.dynamicReportH = h - used
	if m.dynamicReportH < 4 {
		m.dynamicReportH = 4
	}

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
		quitPanel := renderQuitConfirm(m.app.QuitConfirmDeadline, w)
		view = overlayCenter(view, quitPanel, w, m.height)
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
	utcPlain := "UTC: " + time.Now().UTC().Format(UTCTimeFormat)
	gap := max(1, contentW-len(helpPlain)-len(utcPlain))
	line := dimText.Render(helpPlain) + bgSp(gap) +
		rightLabelStyle.Render("UTC: ") + sectionLabel.Render(time.Now().UTC().Format(UTCTimeFormat))

	content := line
	h := 3
	if m.app.SIEMStatusError && m.app.SIEMStatusText != "" &&
		time.Now().Before(m.app.SIEMStatusUntil) {
		content += "\n" + statusFail.Render("  "+m.app.SIEMStatusText)
		h++
	}
	return renderPanel(w, h, "SIEM", "proxywatch", "", content)
}

func (m SIEMModel) headerHeight() int {
	if m.app.SIEMStatusError && m.app.SIEMStatusText != "" &&
		time.Now().Before(m.app.SIEMStatusUntil) {
		return 4
	}
	return 3
}

func (m SIEMModel) setupHeight() int {
	h := 7
	if len(m.app.SIEMSourceReports) == 0 {
		h++
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

	genLabel := platform.IconPlay + " Build SIEM detections"
	if m.app.SIEMGenerating {
		genLabel = fmt.Sprintf(platform.IconStop+" Stop generation (%s elapsed)", spinnerElapsed(m.app.SIEMStartedAt))
	}

	rows := []FormRow{
		{Field: siemFieldProvider, Label: "Provider", Value: provider},
		{Field: siemFieldModel, Label: "Model", Value: nonEmptySIEMValue(m.app.SIEMModel, calibration.DefaultModel(m.app.SIEMProvider))},
		{Field: siemFieldSourceReport, Label: "Profile", Value: sourceValue},
		{Field: siemFieldJSONOutput, Label: "Output", Value: nonEmptySIEMValue(m.app.SIEMExportPath, siem.DefaultSIEMJSONPath()), Editable: true},
		{Field: siemFieldGenerate, Label: "Generate", Value: genLabel},
	}

	if len(m.app.SIEMSourceReports) == 0 {
		rows = append(rows, FormRow{Field: siemFieldCalibrate, Label: "Calibrate", Value: "Open Calibration"})
	}

	w := m.width
	if w <= 0 {
		w = 80
	}
	return renderSetupPanel("SETUP", rows, m.app.SIEMField, m.app.SIEMEditing, w)
}

func (m *SIEMModel) InitViewport() {
	if m.width <= 0 || m.height <= 0 {
		return
	}
	var above []string
	above = append(above, m.renderHeader())
	above = append(above, m.renderSetup())
	used := 0
	for _, s := range above {
		used += lipgloss.Height(s)
	}
	reportH := m.height - used
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

func (m *SIEMModel) RefreshContent() {
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
	m.app.ProgressMu.Lock()
	progressLines := append([]string(nil), m.app.SIEMProgressLines...)
	m.app.ProgressMu.Unlock()

	if m.app.SIEMGenerating && len(progressLines) == 0 {
		_ = dotSpinFrames
		frame := dotSpinFrame()
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
					_ = dotSpinFrames
					frame := dotSpinFrame()
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

	if len(m.app.SIEMReportLines) > 0 {
		return m.buildStyledReport()
	}

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
	// Severity styles
	sevCritical := lipgloss.NewStyle().Foreground(colorAlert).Bold(true)
	sevHigh := lipgloss.NewStyle().Foreground(colorAlert)
	sevMed := lipgloss.NewStyle().Foreground(colorWarn).Bold(true)
	sevLow := lipgloss.NewStyle().Foreground(colorDim)
	// Structural styles
	frameStyle := lipgloss.NewStyle().Foreground(colorFrame)
	accentBold := lipgloss.NewStyle().Foreground(colorAccent).Bold(true)
	queryStyle := lipgloss.NewStyle().Foreground(colorMuted)
	bulletStyle := lipgloss.NewStyle().Foreground(colorCyan)
	numStyle := lipgloss.NewStyle().Foreground(colorAccent)

	var out []string

	for _, line := range m.app.SIEMReportLines {
		trimmed := strings.TrimSpace(line)

		// Empty lines pass through for spacing
		if trimmed == "" {
			out = append(out, "")
			continue
		}

		// ═══ Double-line borders (header)
		if len(trimmed) > 2 && trimmed == strings.Repeat("\u2550", len(trimmed)) {
			out = append(out, frameStyle.Render(line))
			continue
		}

		// Section headers: "  SUMMARY", "  KEY FINDINGS", "  DEFENDER NOTES", "  SIEM DETECTION REPORT"
		if isSIEMSectionHeader(trimmed) {
			out = append(out, accentBold.Render(line))
			continue
		}

		// Section underlines: lines that are only ─ characters (after trim and leading spaces)
		stripped := strings.TrimSpace(trimmed)
		if len(stripped) > 1 && stripped == strings.Repeat("\u2500", len(stripped)) {
			out = append(out, frameStyle.Render(line))
			continue
		}

		// Box drawing: lines starting with box chars ┌ ┐ └ ┘ │
		if isSIEMBoxLine(trimmed) {
			// Check for severity title lines inside boxes: "│  ▲ CRITICAL", "│  ● HIGH", etc.
			if strings.Contains(trimmed, "\u25b2") && strings.Contains(trimmed, "CRITICAL") {
				styled := styleSIEMCardLine(line, sevCritical, frameStyle)
				out = append(out, styled)
				continue
			}
			if strings.Contains(trimmed, "\u25cf") && strings.Contains(trimmed, "HIGH") {
				styled := styleSIEMCardLine(line, sevHigh, frameStyle)
				out = append(out, styled)
				continue
			}
			if strings.Contains(trimmed, "\u25c6") && strings.Contains(trimmed, "MEDIUM") {
				styled := styleSIEMCardLine(line, sevMed, frameStyle)
				out = append(out, styled)
				continue
			}
			if strings.Contains(trimmed, "\u25cb") && (strings.Contains(trimmed, "LOW") || strings.Contains(trimmed, "\u2014")) {
				styled := styleSIEMCardLine(line, sevLow, frameStyle)
				out = append(out, styled)
				continue
			}

			// Query lines inside cards (├─ Splunk:, └─ KQL:, etc.)
			if strings.Contains(trimmed, "Splunk:") || strings.Contains(trimmed, "KQL:") ||
				strings.Contains(trimmed, "ESQL:") || strings.Contains(trimmed, "Sigma:") ||
				strings.Contains(trimmed, "Suricata:") || strings.Contains(trimmed, "YARA:") {
				out = append(out, styleSIEMQueryLine(line, queryStyle, frameStyle))
				continue
			}

			// Signal bullet lines inside cards
			if strings.Contains(trimmed, "\u2022") { // •
				out = append(out, styleSIEMBulletInBox(line, bulletStyle, frameStyle))
				continue
			}

			// Label lines: Role:, Severity:, Processes:, MITRE:, Tactics:, Description:, Signals:, Queries:
			if isSIEMFieldLine(trimmed) {
				out = append(out, styleSIEMFieldLine(line, frameStyle))
				continue
			}

			// Default box content
			out = append(out, styleSIEMBoxContent(line, frameStyle))
			continue
		}

		// Stats subtitle in header (detections | candidates | ...)
		if strings.Contains(trimmed, "detections") && strings.Contains(trimmed, "|") && strings.Contains(trimmed, "candidates") {
			out = append(out, inspValue.Render(line))
			continue
		}

		// Bullet points outside cards (key findings)
		if strings.HasPrefix(trimmed, "\u2022") { // •
			out = append(out, bulletStyle.Render(line))
			continue
		}

		// Numbered notes: "  1. ..."
		if len(trimmed) > 2 && trimmed[0] >= '1' && trimmed[0] <= '9' && strings.Contains(trimmed[:3], ".") {
			dotIdx := strings.Index(trimmed, ".")
			if dotIdx > 0 && dotIdx < 3 {
				prefix := line[:strings.Index(line, trimmed)+dotIdx+1]
				rest := line[strings.Index(line, trimmed)+dotIdx+1:]
				out = append(out, numStyle.Render(prefix)+bodyText.Render(rest))
				continue
			}
		}

		// Default: body text
		out = append(out, bodyText.Render(line))
	}

	if len(out) == 0 {
		return dimText.Render("  No detections generated.")
	}

	return strings.Join(out, "\n")
}

// isSIEMSectionHeader returns true for section title lines in the report.
func isSIEMSectionHeader(trimmed string) bool {
	headers := []string{
		"SIEM DETECTION REPORT",
		"SUMMARY",
		"KEY FINDINGS",
		"DEFENDER NOTES",
	}
	for _, h := range headers {
		if trimmed == h {
			return true
		}
	}
	return false
}

// isSIEMBoxLine returns true if a line begins with a Unicode box-drawing character.
func isSIEMBoxLine(trimmed string) bool {
	if trimmed == "" {
		return false
	}
	for _, r := range trimmed {
		switch r {
		case '\u250c', '\u2510', '\u2514', '\u2518', '\u2502', '\u2500', '\u251c', '\u2524':
			return true
		}
		// Skip leading whitespace
		if r == ' ' {
			continue
		}
		return false
	}
	return false
}

// styleSIEMCardLine styles a severity title line inside a card box.
// It colors the box characters in frame color and the content in severity color.
func styleSIEMCardLine(line string, sevStyle, frameStyle lipgloss.Style) string {
	// Find the │ prefix and style it separately
	idx := strings.Index(line, "\u2502")
	if idx < 0 {
		return sevStyle.Render(line)
	}
	prefix := line[:idx+len("\u2502")]
	rest := line[idx+len("\u2502"):]
	return frameStyle.Render(prefix) + sevStyle.Render(rest)
}

// styleSIEMQueryLine styles query lines (├─ Splunk: ...) inside cards.
func styleSIEMQueryLine(line string, qStyle, frameStyle lipgloss.Style) string {
	idx := strings.Index(line, "\u2502")
	if idx < 0 {
		return qStyle.Render(line)
	}
	prefix := line[:idx+len("\u2502")]
	rest := line[idx+len("\u2502"):]
	return frameStyle.Render(prefix) + qStyle.Render(rest)
}

// styleSIEMBulletInBox styles bullet lines inside card boxes.
func styleSIEMBulletInBox(line string, bStyle, frameStyle lipgloss.Style) string {
	idx := strings.Index(line, "\u2502")
	if idx < 0 {
		return bStyle.Render(line)
	}
	prefix := line[:idx+len("\u2502")]
	rest := line[idx+len("\u2502"):]
	return frameStyle.Render(prefix) + bStyle.Render(rest)
}

// isSIEMFieldLine returns true for labeled field lines inside detection cards.
func isSIEMFieldLine(trimmed string) bool {
	// After stripping the │ prefix, check for field labels
	after := trimmed
	if idx := strings.Index(after, "\u2502"); idx >= 0 {
		after = strings.TrimSpace(after[idx+len("\u2502"):])
	}
	fields := []string{"Role:", "Severity:", "Processes:", "MITRE:", "Tactics:", "Description:", "Signals:", "Queries:"}
	for _, f := range fields {
		if strings.HasPrefix(after, f) {
			return true
		}
	}
	return false
}

// styleSIEMFieldLine styles field label lines inside detection cards.
func styleSIEMFieldLine(line string, frameStyle lipgloss.Style) string {
	idx := strings.Index(line, "\u2502")
	if idx < 0 {
		return dimText.Render(line)
	}
	prefix := line[:idx+len("\u2502")]
	rest := line[idx+len("\u2502"):]
	return frameStyle.Render(prefix) + dimText.Render(rest)
}

// styleSIEMBoxContent styles generic content inside box lines, coloring the
// box character in frame color and the rest as body text.
func styleSIEMBoxContent(line string, frameStyle lipgloss.Style) string {
	// Handle pure border lines (┌───┐, └───┘)
	trimmed := strings.TrimSpace(line)
	if len(trimmed) > 0 {
		first := []rune(trimmed)[0]
		if first == '\u250c' || first == '\u2514' {
			return frameStyle.Render(line)
		}
	}
	// Lines starting with │
	idx := strings.Index(line, "\u2502")
	if idx < 0 {
		return bodyText.Render(line)
	}
	prefix := line[:idx+len("\u2502")]
	rest := line[idx+len("\u2502"):]
	return frameStyle.Render(prefix) + bodyText.Render(rest)
}

func (m SIEMModel) renderReportPanel() string {
	w := m.width
	if w <= 0 {
		w = 80
	}
	reportH := m.dynamicReportH
	if reportH <= 0 {
		reportH = m.height - m.headerHeight() - m.setupHeight()
	}
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
