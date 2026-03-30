package ui

import (
	"fmt"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/gdamore/tcell/v2"

	"proxywatch/internal/contour"
	"proxywatch/internal/shared"
)

// ContourModel is the native bubbletea model for the contour view.
type ContourModel struct {
	app        *shared.AppState
	viewport   viewport.Model
	width      int
	height     int
	ready      bool
	live       liveProgressModel
	panelTitle string
	contentKey uint64 // hash of last content set on viewport
}

func NewContourModel(app *shared.AppState) ContourModel {
	return ContourModel{
		app:  app,
		live: newLiveProgressModel(),
	}
}

func (m ContourModel) Init() tea.Cmd { return nil }

func (m ContourModel) Update(msg tea.Msg) (ContourModel, tea.Cmd) {
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

		// Scroll — handled here, returned immediately.
		if m.ready && !m.app.ContourShowMenu && !m.app.ContourShowHelp && !m.app.ContourEditing {
			if m.handleScroll(tev) {
				return m, nil
			}
		}

		// Everything else to legacy contour key handler.
		if handleContourKey(m.app, tev) {
			return m, tea.Quit
		}
		m.refreshContent()

	case tea.MouseMsg:
		if m.ready {
			m.viewport, _ = m.viewport.Update(msg)
		}
	}

	// Spinner tick.
	m.live.active = m.app.ContourActive || m.app.ContourAnalyzing
	if m.live.active {
		var cmd tea.Cmd
		m.live, cmd = m.live.Update(msg)
		// Always ensure a tick is queued while active. The spinner's
		// Update only returns a cmd for TickMsg — without this, a key
		// event can break the tick chain and freeze the spinners.
		if cmd == nil {
			cmd = m.live.spinner.Tick
		}
		m.refreshContent()
		return m, cmd
	}

	return m, nil
}

// handleScroll processes scroll keys. Returns true if handled.
func (m *ContourModel) handleScroll(tev *tcell.EventKey) bool {
	switch tev.Key() {
	case tcell.KeyPgUp:
		m.viewport.HalfViewUp()
		return true
	case tcell.KeyPgDn:
		m.viewport.HalfViewDown()
		return true
	case tcell.KeyHome:
		m.viewport.GotoTop()
		return true
	case tcell.KeyEnd:
		m.viewport.GotoBottom()
		return true
	}
	if tev.Key() == tcell.KeyRune {
		switch tev.Rune() {
		case 'j', ']':
			m.viewport.LineDown(1)
			return true
		case 'k', '[':
			m.viewport.LineUp(1)
			return true
		}
	}
	return false
}

// initViewport creates or resizes the viewport.
func (m *ContourModel) initViewport() {
	reportH := m.height - m.headerHeight() - m.setupHeight() - 2
	if reportH < 4 {
		reportH = 4
	}
	reportW := m.width - 2
	if !m.ready {
		m.viewport = viewport.New(reportW, reportH)
		m.viewport.Style = lipgloss.NewStyle()
		m.ready = true
	} else {
		m.viewport.Width = reportW
		m.viewport.Height = reportH
	}
}

// refreshContent rebuilds the panel content and pushes it to the viewport
// only if the content actually changed.
func (m *ContourModel) refreshContent() {
	if !m.ready {
		return
	}
	content, title := m.buildContent()
	m.panelTitle = title

	h := quickHash(content)
	if h != m.contentKey {
		m.contentKey = h
		m.viewport.SetContent(content)
	}
}

// buildContent generates the report/scanning panel text.
func (m *ContourModel) buildContent() (string, string) {
	// Snapshot progress lines under lock.
	m.app.ProgressMu.Lock()
	progressLines := append([]string(nil), m.app.ContourProgressLines...)
	m.app.ProgressMu.Unlock()

	if m.app.ContourReport != nil {
		if _, ok := m.app.ContourReport.(*contour.Report); ok {
			if len(progressLines) > 0 {
				return renderTaskMatrix(progressLines, m.live.spinner, m.app, m.width-4), "COMPLETED"
			}
			return dimText.Render("  Scan complete."), "COMPLETED"
		}
	}
	if (m.app.ContourActive || m.app.ContourAnalyzing) && len(progressLines) > 0 {
		return renderTaskMatrix(progressLines, m.live.spinner, m.app, m.width-4), "SCANNING"
	}
	if m.app.ContourActive || m.app.ContourAnalyzing {
		return dimText.Render("  Starting..."), "SCANNING"
	}
	return dimText.Render("  No contour report yet. Configure target and start a run."), "DISPLAY"
}

func quickHash(s string) uint64 {
	var h uint64 = 5381
	for _, c := range s {
		h = h*33 + uint64(c)
	}
	return h
}

// ── View ────────────────────────────────────────────────────────────────────

func (m ContourModel) View() string {
	w := m.width
	h := m.height
	if w <= 0 || h <= 0 {
		return ""
	}

	var sections []string
	sections = append(sections, m.renderHeader())
	sections = append(sections, m.renderSetup())
	sections = append(sections, m.renderReportPanel())

	view := lipgloss.JoinVertical(lipgloss.Left, sections...)

	if m.app.ContourShowMenu && len(m.app.ContourMenuOptions) > 0 {
		view = overlayCenter(view, renderMenuPanel(
			m.app.ContourMenuTitle,
			m.app.ContourMenuOptions,
			m.app.ContourMenuIndex,
			"Enter apply   Esc close", w), w, h)
	}
	if m.app.ContourShowHelp {
		view = overlayCenter(view, renderHelpPanel("Contour Menu", contourMenuHelpOptions(), w), w, h)
	}
	return view
}

func (m ContourModel) renderHeader() string {
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
	return renderPanel(w, 3, "Contour", "proxywatch", "", line)
}

func (m ContourModel) headerHeight() int { return 3 }

func (m ContourModel) renderReportPanel() string {
	w := m.width
	if w <= 0 {
		w = 80
	}
	reportH := m.height - m.headerHeight() - m.setupHeight() - 2
	reportH--
	if reportH < 4 {
		reportH = 4
	}

	opts := ReportPanelOpts{
		Title:       m.panelTitle,
		Width:       w,
		Height:      reportH,
		StatusText:  m.app.ContourStatusText,
		StatusError: m.app.ContourStatusError,
		StatusUntil: m.app.ContourStatusUntil,
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

// ── Setup panel ─────────────────────────────────────────────────────────────

func (m ContourModel) setupHeight() int { return 5 } // 3 fields + top/bottom border

func (m ContourModel) renderSetup() string {
	w := m.width
	if w <= 0 {
		w = 80
	}

	actionIcon := "▶"
	if m.app.ContourActive || m.app.ContourAnalyzing {
		actionIcon = "■"
	}

	rows := []FormRow{
		{Field: contourFieldEndpoint, Label: "Target", Value: m.app.ContourProbeEndpoint, Editable: true},
		{Field: contourFieldOutput, Label: "Output", Value: m.app.ContourOutput, Editable: true},
		{Field: contourFieldAction, Label: "Action", Value: actionIcon + " " + m.actionLabel()},
	}
	return renderSetupPanel("SETUP", rows, m.app.ContourField, m.app.ContourEditing, w)
}

func (m ContourModel) actionLabel() string {
	if m.app.ContourActive || m.app.ContourAnalyzing {
		elapsed := time.Since(m.app.ContourStartedAt).Round(time.Second)
		if m.app.ContourAnalyzing {
			return fmt.Sprintf("Analyzing... (%s)", elapsed)
		}
		remaining := time.Until(m.app.ContourUntil).Round(time.Second)
		if remaining < 0 {
			remaining = 0
		}
		return fmt.Sprintf("Running %s  |  %s remaining", elapsed, remaining)
	}
	return "Start Scan"
}

// Ensure imports are used.
var (
	_ = tcell.KeyUp
)
