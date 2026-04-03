package views

import (
	"fmt"
	"proxywatch/internal/ui/platform"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/gdamore/tcell/v2"

	"proxywatch/internal/calibration"
	"proxywatch/internal/model"
	"proxywatch/internal/shared"
)

// CalibrationModel is the native bubbletea model for the Calibration view.
type CalibrationModel struct {
	app            *shared.AppState
	viewport       viewport.Model
	width          int
	height         int
	ready          bool
	contentKey     uint64
	dynamicReportH int // computed in View() from actual rendered panel heights
}

func NewCalibrationModel(app *shared.AppState) CalibrationModel {
	return CalibrationModel{app: app}
}

func (m CalibrationModel) Init() tea.Cmd { return nil }

func (m CalibrationModel) Update(msg tea.Msg) (CalibrationModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.InitViewport()
		m.RefreshContent()

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

		// Number key workflow jumping.
		if !m.app.CalibrateEditing {
			if jumpToWorkflow(m.app, tev.Rune()) {
				return m, nil
			}
		}

		// Cursor movement when editing a text field.
		if m.app.CalibrateEditing {
			switch tev.Key() {
			case tcell.KeyLeft:
				if m.app.CalibrateEditCursor > 0 {
					m.app.CalibrateEditCursor--
				}
				return m, nil
			case tcell.KeyRight:
				val := calibrateEditValue(m.app)
				if m.app.CalibrateEditCursor < len(val) {
					m.app.CalibrateEditCursor++
				}
				return m, nil
			}
		} else {
			// Workflow cycling (only when not editing).
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
		}

		// Scroll the report viewport.
		if m.ready && !m.app.ShowCalibrateMenu && !m.app.ShowCalibrateHelp && !m.app.CalibrateEditing {
			if m.handleScroll(tev) {
				return m, nil
			}
		}

		// Delegate to legacy calibration key handler.
		if handleCalibrationKey(m.app, tev) {
			return m, tea.Quit
		}
	}

	m.RefreshContent()
	return m, nil
}

func (m *CalibrationModel) handleScroll(tev *tcell.EventKey) bool {
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

func (m CalibrationModel) View() string {
	w := m.width
	if w <= 0 {
		w = 80
	}
	// Ensure viewport is initialized even if we missed the initial WindowSizeMsg.
	if !m.ready && m.width > 0 && m.height > 0 {
		m.InitViewport()
		m.RefreshContent()
	}

	var sections []string

	// Header.
	sections = append(sections, m.renderHeader())
	sections = append(sections, m.renderSetup())
	sections = append(sections, m.renderAccessPanel())
	sections = append(sections, m.renderModelPerformance())

	used := 0
	for _, s := range sections {
		used += lipgloss.Height(s)
	}
	m.dynamicReportH = m.height - used
	if m.dynamicReportH < 4 {
		m.dynamicReportH = 4
	}
	// Keep viewport height in sync with dynamic report height.
	if m.ready {
		m.viewport.Width = m.width - 4
		m.viewport.Height = m.dynamicReportH - 2
	}

	sections = append(sections, m.renderReportPanel())

	view := lipgloss.JoinVertical(lipgloss.Left, sections...)

	h := m.height
	if h <= 0 {
		h = 24
	}
	if m.app.ShowCalibrateHelp {
		view = overlayCenter(view, renderHelpPanel("Calibration Menu", calibrationMenuHelpOptions(), w), w, h)
	} else if m.app.ShowCalibrateMenu {
		view = overlayCenter(view, renderMenuPanel(
			m.app.CalibrateMenuTitle,
			m.app.CalibrateMenuOptions,
			m.app.CalibrateMenuIndex,
			"", w), w, h)
	}

	if m.app.ShowQuitConfirm && m.app.QuitConfirmDeadline.After(time.Now()) {
		quitPanel := renderQuitConfirm(m.app.QuitConfirmDeadline, w)
		view = overlayCenter(view, quitPanel, w, m.height)
	}
	return view
}

// ── Header ───────────────────────────────────────────────────────────────────

func (m CalibrationModel) renderHeader() string {
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
	if m.app.CalibrateStatusError && m.app.CalibrateStatusText != "" &&
		time.Now().Before(m.app.CalibrateStatusUntil) {
		content += "\n" + statusFail.Render("  "+m.app.CalibrateStatusText)
		h++
	}

	return renderPanel(w, h, "Calibration", "proxywatch", "", content)
}

// ── Setup panel ──────────────────────────────────────────────────────────────

func (m CalibrationModel) headerHeight() int {
	if m.app.CalibrateStatusError && m.app.CalibrateStatusText != "" &&
		time.Now().Before(m.app.CalibrateStatusUntil) {
		return 4
	}
	return 3
}
func (m CalibrationModel) setupHeight() int { return 12 }

func (m CalibrationModel) renderSetup() string {
	w := m.width
	if w <= 0 {
		w = 80
	}

	providerLabel := calibration.ProviderLabel(m.app.CalibrateProvider)
	profileValue := m.app.CalibrateAppliedProfile

	actionLabel := calibrationActionLabel(m.app)
	actionIcon := platform.IconPlay
	if m.app.CalibrateActive || m.app.CalibrateAnalyzing {
		actionIcon = platform.IconStop
	}

	rows := []FormRow{
		{Field: calibrateFieldProvider, Label: "Provider", Value: providerLabel},
	}
	if strings.TrimSpace(m.app.LocalHost) == "" {
		rows = append(rows, FormRow{Field: calibrateFieldHostScope, Label: "Host", Value: calibrateHostScopeLabel(m.app)})
	}
	rows = append(rows,
		FormRow{Field: calibrateFieldModel, Label: "Model", Value: m.app.CalibrateModel},
		FormRow{Field: calibrateFieldProfile, Label: "Profile", Value: profileValue},
		FormRow{Field: calibrateFieldOutput, Label: "Output", Value: m.app.CalibrateOutput, Editable: true, CursorPos: m.app.CalibrateEditCursor},
		FormRow{Field: calibrateFieldDuration, Label: "Duration", Value: m.app.CalibrateDuration},
		FormRow{Field: calibrateFieldAction, Label: "Action", Value: actionIcon + " " + actionLabel},
		FormRow{Field: calibrateFieldApply, Label: "Apply", Value: "Apply selected profile"},
		FormRow{Field: calibrateFieldReset, Label: "Reset", Value: calibrateResetLabel(m.app)},
	)
	return renderSetupPanel("SETUP", rows, m.app.CalibrateField, m.app.CalibrateEditing, w)
}

// ── Provider access panel ────────────────────────────────────────────────────

func (m CalibrationModel) accessHeight() int { return 3 }

func (m CalibrationModel) renderAccessPanel() string {
	w := m.width
	if w <= 0 {
		w = 80
	}

	access := calibration.DetectProviderAccess()
	type accessRow struct {
		label string
		ok    bool
	}
	accessRows := []accessRow{
		{"OpenAI", access.OpenAIKey},
		{"Anthropic", access.AnthropicKey},
		{"Local LLM URL", access.LocalLLMURL},
		{"Local LLM Key", access.LocalLLMKey},
	}

	// Render as a compact horizontal row of status badges.
	var badges []string
	for _, item := range accessRows {
		if item.ok {
			badge := lipgloss.NewStyle().
				Foreground(colorCyan).Bold(true).
				Render("✓ " + item.label)
			badges = append(badges, badge)
		} else {
			badge := lipgloss.NewStyle().
				Foreground(colorDim).
				Render("✗ " + item.label)
			badges = append(badges, badge)
		}
	}

	content := "  " + strings.Join(badges, "    ")
	return renderPanel(w, 3, "PROVIDERS", "", "", content)
}

// ── Model performance panel ──────────────────────────────────────────────────

func (m CalibrationModel) renderModelPerformance() string {
	w := m.width
	if w <= 0 {
		w = 80
	}
	dm := model.Get()
	if dm == nil {
		return ""
	}
	barW := w - 30
	if barW < 20 {
		barW = 20
	}

	confidence := 0.0

	profileCount := 0
	stableCount := 0
	totalExperienced := 0
	countProfiles := func(profiles map[string]*model.ProcessProfile) {
		for _, p := range profiles {
			if p == nil {
				continue
			}
			profileCount++
			if p.ExperienceObservations >= 5000 {
				totalExperienced++
				if p.RoleStability > 0.7 {
					stableCount++
				}
			}
		}
	}
	countProfiles(dm.Processes)
	for _, overlay := range dm.HostOverlays {
		if overlay != nil {
			countProfiles(overlay.Processes)
		}
	}

	signalCount := 0
	for _, ss := range dm.SignalStats {
		if ss != nil && ss.Total >= 10 {
			signalCount++
		}
	}
	patternCount := len(dm.TrainingPatterns)
	egressCount := len(dm.EgressPaths)

	// Stability & population (up to 25%): requires 200+ experienced profiles for full credit.
	if totalExperienced > 0 {
		stabilityRatio := float64(stableCount) / float64(totalExperienced)
		populationScale := float64(totalExperienced) / 200
		if populationScale > 1 {
			populationScale = 1
		}
		confidence += stabilityRatio * populationScale * 25
	}

	// Operator feedback (up to 25%): requires 20+ feedback actions for full credit.
	feedbackTotal := dm.Quality.ConfirmedCorrect + dm.Quality.Contradictions
	if feedbackTotal >= 20 {
		confidence += dm.Quality.ConfirmationRate * 25
	} else if feedbackTotal >= 5 {
		confidence += dm.Quality.ConfirmationRate * 25 * float64(feedbackTotal) / 20
	}

	// Experience volume (up to 20%): requires 200+ experienced profiles for full credit.
	if totalExperienced >= 200 {
		confidence += 20
	} else {
		confidence += float64(totalExperienced) / 200 * 20
	}

	// Calibration & egress intelligence (up to 15%): only applies with 100+ experienced profiles.
	if totalExperienced >= 100 {
		ext := 0.0
		if dm.CalibrationRuns >= 10 {
			ext += 7.5
		} else {
			ext += float64(dm.CalibrationRuns) / 10 * 7.5
		}
		if egressCount >= 20 {
			ext += 7.5
		} else {
			ext += float64(egressCount) / 20 * 7.5
		}
		confidence += ext
	}

	// Signal & pattern depth (up to 15%): requires observed signal diversity and training patterns.
	if signalCount >= 10 {
		confidence += 7.5
	} else {
		confidence += float64(signalCount) / 10 * 7.5
	}
	if patternCount >= 5 {
		confidence += 7.5
	} else {
		confidence += float64(patternCount) / 5 * 7.5
	}

	// Penalty for contradictions.
	penalty := float64(dm.Quality.Contradictions) * 3
	if penalty > 25 {
		penalty = 25
	}
	confidence -= penalty
	if confidence < 0 {
		confidence = 0
	}
	if confidence > 100 {
		confidence = 100
	}

	barColor := lipgloss.Color("#5EBC8E")
	label := "strong"
	if confidence < 25 {
		barColor = lipgloss.Color("#E06C75")
		label = "low"
	} else if confidence < 50 {
		barColor = lipgloss.Color("#D19A66")
		label = "building"
	} else if confidence < 75 {
		barColor = lipgloss.Color("#61AFEF")
		label = "moderate"
	}

	bar := sparkGauge(confidence, barW, barColor)
	var lines []string
	lines = append(lines, fmt.Sprintf("  %s  %.0f%% %s", bar, confidence, dimText.Render("("+label+")")))
	lines = append(lines, dimText.Render(fmt.Sprintf("  Profiles: %d (%d experienced)  |  Stability: %d/%d  |  Signals: %d  |  Patterns: %d",
		profileCount, totalExperienced, stableCount, totalExperienced, signalCount, patternCount)))
	lines = append(lines, dimText.Render(fmt.Sprintf("  Egress paths: %d  |  Calibrations: %d  |  Feedback: %d actions  |  Contradictions: %d",
		egressCount, dm.CalibrationRuns, dm.Quality.TotalFeedback, dm.Quality.Contradictions)))

	content := strings.Join(lines, "\n")
	return renderPanel(w, len(lines)+2, "MODEL", "", "", content)
}

// ── Report panel ─────────────────────────────────────────────────────────────

func (m *CalibrationModel) InitViewport() {
	if m.width <= 0 || m.height <= 0 {
		return
	}
	reportH := m.dynamicReportH
	if reportH <= 0 {
		reportH = m.height - m.headerHeight() - m.setupHeight() - m.accessHeight()
	}
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

func (m *CalibrationModel) RefreshContent() {
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

func (m CalibrationModel) buildContent() string {
	app := m.app

	sectionHead := lipgloss.NewStyle().Foreground(colorAccent).Bold(true)
	dividerStyle := lipgloss.NewStyle().Foreground(colorFrame)

	calSectionBar := func(title string) string {
		w := m.width - 8
		if w < 20 {
			w = 20
		}
		label := " " + title + " "
		fill := w - len(label) - 1
		if fill < 0 {
			fill = 0
		}
		return dividerStyle.Render("─") + sectionHead.Render(label) + dividerStyle.Render(strings.Repeat("─", fill))
	}

	// Snapshot progress lines under lock to avoid races with background goroutines.
	app.ProgressMu.Lock()
	progressLines := append([]string(nil), app.CalibrateProgressLines...)
	app.ProgressMu.Unlock()

	// During collection or analysis, show live view.
	if app.CalibrateActive || app.CalibrateAnalyzing {
		var out []string

		// Collection phase: show progress gauge + stats.
		if app.CalibrateActive && !app.CalibrateAnalyzing {
			remaining := time.Until(app.CalibrateUntil).Round(time.Second)
			if remaining < 0 {
				remaining = 0
			}
			elapsed := time.Since(app.CalibrateStartedAt).Round(time.Second)
			total := elapsed + remaining
			pct := float64(0)
			if total > 0 {
				pct = float64(elapsed) / float64(total) * 100
			}
			out = append(out,
				"  "+sparkGauge(pct, 40, lipgloss.Color("#5EBC8E"))+
					"  "+sectionLabel.Render(elapsed.String())+
					dimText.Render(" / "+total.String()))
			out = append(out, "")

			lines := calibrationCollectionLines(app)
			for _, line := range lines {
				out = append(out, calibrationProgressLineStyle(line))
			}
		}

		// Analysis phase: render as a task checklist.
		if app.CalibrateAnalyzing && len(progressLines) > 0 {
			plines := progressLines
			for i, line := range plines {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "[*]") {
					if i == len(plines)-1 {
						task := strings.TrimSpace(strings.TrimPrefix(trimmed, "[*]"))
						_ = dotSpinFrames
						frame := dotSpinFrame()
						spinner := lipgloss.NewStyle().Foreground(colorCyan).Bold(true).Render(frame)
						out = append(out, "  "+spinner+" "+sectionLabel.Render(task))
					} else {
						task := strings.TrimPrefix(trimmed, "[*]")
						out = append(out, statusPass.Render("  ● ")+bodyText.Render(strings.TrimSpace(task)))
					}
				} else {
					out = append(out, calibrationAnalysisLineStyle(line))
				}
			}
		}

		if len(out) > 0 {
			return strings.Join(out, "\n")
		}
	}

	// Show report lines if available.
	lines := app.CalibrateReportLines
	if len(lines) == 0 && strings.TrimSpace(app.CalibrateReportSummary) != "" {
		lines = []string{app.CalibrateReportSummary}
		for _, rec := range app.CalibrateRecommendations {
			lines = append(lines, "- "+rec)
		}
	}
	if len(lines) > 0 {
		return m.buildReportContent(lines, calSectionBar)
	}

	// Show profile preview if one was selected.
	if len(app.CalibrateProfilePreview) > 0 {
		return m.buildReportContent(app.CalibrateProfilePreview, calSectionBar)
	}

	return inspValue.Render("No calibration report has been generated yet.") + "\n" +
		dimText.Render("Choose a duration, provider, and optional model override, then run Start calibration.") + "\n" +
		dimText.Render("You can still select a saved profile above and use Apply.")
}

// buildReportContent renders calibration report with styled sections,
// each wrapped in an orange-bordered box like contour's sub-panels.
func (m CalibrationModel) buildReportContent(rawLines []string, _ func(string) string) string {
	w := m.width - 4
	if w < 10 {
		w = 10
	}
	rawLines = normalizeCalibrationReportLines(rawLines, w)

	sectionNames := map[string]bool{
		"Tuning": true, "Recommendations": true, "Learning": true,
		"History": true, "Summary": true, "Validation": true,
		"Reasoning": true,
	}

	kv := func(label, value string, vs lipgloss.Style) string {
		return dimText.Render("  "+label+"  ") + vs.Render(value)
	}

	// Group lines by section.
	type section struct {
		name  string
		lines []string
	}
	var sections []section
	current := section{name: "RESULTS"}

	for _, line := range rawLines {
		trimmed := strings.TrimSpace(line)

		if sectionNames[trimmed] {
			if len(current.lines) > 0 {
				sections = append(sections, current)
			}
			current = section{name: strings.ToUpper(trimmed)}
			continue
		}

		// Confidence -> gauge (starts Results section).
		if strings.HasPrefix(trimmed, "Confidence:") {
			if len(current.lines) > 0 {
				sections = append(sections, current)
			}
			current = section{name: "CONFIDENCE"}
			current.lines = append(current.lines, calibrationConfidenceLine(trimmed))
			continue
		}

		// Style lines based on current section.
		switch current.name {
		case "TUNING":
			if strings.Contains(trimmed, "->") && !strings.HasPrefix(trimmed, "Quality") && !strings.HasPrefix(trimmed, "FP") {
				parts := strings.SplitN(trimmed, ":", 2)
				if len(parts) == 2 {
					current.lines = append(current.lines, kv(strings.TrimSpace(parts[0])+":", strings.TrimSpace(parts[1]), inspValue))
					continue
				}
			}
			if strings.HasPrefix(trimmed, "Quality:") {
				current.lines = append(current.lines, calibrationQualityLine("  "+trimmed))
				continue
			}
			if strings.HasPrefix(trimmed, "FP:") {
				current.lines = append(current.lines, dimText.Render("  ")+bodyText.Render(trimmed))
				continue
			}
			if strings.HasPrefix(trimmed, "No changes") || strings.HasPrefix(trimmed, "Changed:") {
				current.lines = append(current.lines, "  "+dimText.Render(trimmed))
				continue
			}

		case "RECOMMENDATIONS":
			if strings.HasPrefix(trimmed, "- [RISK]") {
				risk := strings.TrimPrefix(trimmed, "- [RISK]")
				if len(current.lines) > 0 {
					current.lines = append(current.lines, "")
				}
				current.lines = append(current.lines,
					"  "+statusFail.Render("RISK"),
					"  "+bodyText.Render(strings.TrimSpace(risk)))
				continue
			}
			if strings.HasPrefix(trimmed, "-") {
				rec := strings.TrimPrefix(trimmed, "-")
				if len(current.lines) > 0 {
					current.lines = append(current.lines, "")
				}
				current.lines = append(current.lines,
					"  "+statusPass.Render("+")+bodyText.Render("  "+strings.TrimSpace(rec)))
				continue
			}
			if len(trimmed) > 0 {
				current.lines = append(current.lines, "     "+dimText.Render(trimmed))
				continue
			}

		case "LEARNING":
			if strings.HasPrefix(trimmed, "Runs:") {
				contamPct := 0
				if idx := strings.Index(trimmed, "Contamination:"); idx >= 0 {
					sub := strings.TrimSpace(trimmed[idx+len("Contamination:"):])
					for _, ch := range sub {
						if ch >= '0' && ch <= '9' {
							contamPct = contamPct*10 + int(ch-'0')
						} else {
							break
						}
					}
				}
				contamColor := lipgloss.Color("#5EBC8E")
				if contamPct >= 35 {
					contamColor = lipgloss.Color("#C67682")
				} else if contamPct >= 20 {
					contamColor = lipgloss.Color("#C9AD5E")
				}
				current.lines = append(current.lines, "  "+bodyText.Render(trimmed))
				current.lines = append(current.lines, "  "+dimText.Render("Contamination  ")+sparkGauge(float64(contamPct), 20, contamColor))
				continue
			}
			if strings.HasPrefix(trimmed, "Baseline:") {
				current.lines = append(current.lines, kv("Baseline:", strings.TrimSpace(strings.TrimPrefix(trimmed, "Baseline:")), dimText))
				continue
			}
			if strings.HasPrefix(trimmed, "Environment:") {
				current.lines = append(current.lines, kv("Env:", strings.TrimSpace(strings.TrimPrefix(trimmed, "Environment:")), inspWarn))
				continue
			}
			if strings.HasPrefix(trimmed, "Contaminating:") {
				current.lines = append(current.lines, kv("Contam:", strings.TrimSpace(strings.TrimPrefix(trimmed, "Contaminating:")), inspAlert))
				continue
			}
			if strings.HasPrefix(trimmed, "Suggestion:") {
				current.lines = append(current.lines, "  "+statusPass.Render(">")+dimText.Render(" "+strings.TrimSpace(strings.TrimPrefix(trimmed, "Suggestion:"))))
				continue
			}

		case "HISTORY":
			if strings.Contains(trimmed, "match") && strings.Contains(trimmed, "confidence") {
				if strings.Contains(trimmed, "applied") && !strings.Contains(trimmed, "not applied") {
					current.lines = append(current.lines, "  "+statusPass.Render("+")+bodyText.Render(" "+trimmed))
				} else {
					current.lines = append(current.lines, "  "+dimText.Render("- "+trimmed))
				}
				continue
			}

		case "REASONING":
			if strings.HasPrefix(trimmed, "-") {
				current.lines = append(current.lines, "  "+dimText.Render(trimmed))
				continue
			}
		}

		// Default.
		if trimmed == "" {
			continue
		}
		current.lines = append(current.lines, calibrationProgressLineStyle(line))
	}
	if len(current.lines) > 0 {
		sections = append(sections, current)
	}

	// Render each section as an orange-bordered box.
	var out []string
	for _, sec := range sections {
		if len(sec.lines) == 0 {
			continue
		}
		content := strings.Join(sec.lines, "\n")
		h := len(sec.lines) + 2
		out = append(out, renderAccentPanel(w, h, sec.name, content))
	}
	return strings.Join(out, "\n")
}

// calibrationAnalysisLineStyle renders analysis progress as a task checklist.
func calibrationAnalysisLineStyle(line string) string {
	trimmed := strings.TrimSpace(line)
	switch {
	case strings.HasPrefix(trimmed, "[*]"):
		task := strings.TrimPrefix(trimmed, "[*]")
		return dimText.Render("  ◌ ") + dimText.Render(strings.TrimSpace(task))
	case strings.HasPrefix(trimmed, "[+]"):
		task := strings.TrimPrefix(trimmed, "[+]")
		return statusPass.Render("  ● ") + bodyText.Render(strings.TrimSpace(task))
	case strings.HasPrefix(trimmed, "[-]"):
		task := strings.TrimPrefix(trimmed, "[-]")
		return statusFail.Render("  ✗ ") + statusFail.Render(strings.TrimSpace(task))
	default:
		return bodyText.Render("    " + trimmed)
	}
}

// calibrationConfidenceLine renders "Confidence: 72 (high)" with a gauge bar.
func calibrationConfidenceLine(line string) string {
	conf := 0
	var level string
	n, _ := parseConfidence(line)
	conf = n
	switch {
	case conf >= 70:
		level = "high"
	case conf >= 45:
		level = "moderate"
	default:
		level = "low"
	}

	color := lipgloss.Color("#C67682") // low = red
	if conf >= 70 {
		color = lipgloss.Color("#5EBC8E") // high = green
	} else if conf >= 45 {
		color = lipgloss.Color("#C9AD5E") // moderate = yellow
	}

	gauge := sparkGauge(float64(conf), 20, color)
	label := lipgloss.NewStyle().Foreground(color).Bold(true).Render(
		strings.ToUpper(level))

	return "  " + dimText.Render("Confidence  ") + gauge + "  " +
		sectionLabel.Render(strconv.Itoa(conf)+"%") + "  " + label
}

// calibrationQualityLine renders the quality delta with color.
func calibrationQualityLine(line string) string {
	if strings.Contains(line, "improved") {
		return statusPass.Render(line)
	}
	if strings.Contains(line, "regressed") {
		return statusFail.Render(line)
	}
	return bodyText.Render(line)
}

// parseConfidence extracts the integer from "Confidence: 72 (high)".
func parseConfidence(line string) (int, string) {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "Confidence:")
	line = strings.TrimSpace(line)
	n := 0
	for _, ch := range line {
		if ch >= '0' && ch <= '9' {
			n = n*10 + int(ch-'0')
		} else {
			break
		}
	}
	return n, line
}

func (m CalibrationModel) renderReportPanel() string {
	w := m.width
	if w <= 0 {
		w = 80
	}
	reportH := m.dynamicReportH
	if reportH < 4 {
		reportH = 4
	}

	panelTitle := "DISPLAY"
	if m.app.CalibrateAnalyzing {
		panelTitle = "ANALYZING"
	} else if m.app.CalibrateActive {
		panelTitle = "COLLECTING"
	}

	opts := ReportPanelOpts{
		Title:       panelTitle,
		RightLabel:  "",
		Width:       w,
		Height:      reportH,
		StatusText:  m.app.CalibrateStatusText,
		StatusError: m.app.CalibrateStatusError,
		StatusUntil: m.app.CalibrateStatusUntil,
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

// calibrationProgressLineStyle returns a lipgloss-styled version of a
// calibration progress line, matching the legacy tcell color scheme.
func calibrationProgressLineStyle(line string) string {
	trimmed := strings.TrimSpace(line)
	switch {
	case strings.HasPrefix(trimmed, "[*]"):
		replaced := strings.Replace(line, "[*]", " ·", 1)
		return dimText.Render(replaced)
	case strings.HasPrefix(trimmed, "[+]"):
		replaced := strings.Replace(line, "[+]", " ✓", 1)
		return statusPass.Render(replaced)
	case strings.HasPrefix(trimmed, "[-]"):
		replaced := strings.Replace(line, "[-]", " ✗", 1)
		return statusFail.Render(replaced)
	default:
		return bodyText.Render(line)
	}
}
