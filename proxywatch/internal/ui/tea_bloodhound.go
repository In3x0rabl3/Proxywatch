package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/gdamore/tcell/v2"

	"proxywatch/internal/shared"
)

// BloodHoundModel is the native bubbletea model for the BloodHound collection view.
type BloodHoundModel struct {
	app        *shared.AppState
	viewport   viewport.Model
	width      int
	height     int
	ready      bool
	contentKey uint64
}

func NewBloodHoundModel(app *shared.AppState) BloodHoundModel {
	return BloodHoundModel{app: app}
}

func (m BloodHoundModel) Init() tea.Cmd { return nil }

func (m BloodHoundModel) Update(msg tea.Msg) (BloodHoundModel, tea.Cmd) {
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

		// Cursor movement when editing.
		if m.app.CollectEditing {
			switch tev.Key() {
			case tcell.KeyLeft, tcell.KeyRight:
				return m, nil
			}
		} else {
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
		}

		// Scroll the report viewport.
		if m.ready && !m.app.CollectShowMenu && !m.app.CollectShowHelp && !m.app.CollectEditing {
			if m.handleScroll(tev) {
				return m, nil
			}
		}

		// Delegate to legacy collect key handler.
		if handleCollectKey(m.app, tev) {
			return m, tea.Quit
		}
	}

	m.refreshContent()
	return m, nil
}

func (m *BloodHoundModel) handleScroll(tev *tcell.EventKey) bool {
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

func (m BloodHoundModel) View() string {
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

	if m.app.CollectShowHelp {
		view = overlayCenter(view, renderHelpPanel("BloodHound Menu", collectMenuHelpOptions(), w), w, h)
	} else if m.app.CollectShowMenu {
		view = overlayCenter(view, renderMenuPanel(
			m.app.CollectMenuTitle,
			m.app.CollectMenuOptions,
			m.app.CollectMenuIndex,
			"", w), w, h)
	}

	if m.app.ShowQuitConfirm && m.app.QuitConfirmDeadline.After(time.Now()) {
		view += "\n" + renderQuitConfirm(m.app.QuitConfirmDeadline, w)
	}
	return view
}

// ── Header ───────────────────────────────────────────────────────────────────

func (m BloodHoundModel) renderHeader() string {
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
	return renderPanel(w, 3, "BloodHound", "proxywatch", "", line)
}

func (m BloodHoundModel) headerHeight() int { return 3 }

// ── Setup panel ──────────────────────────────────────────────────────────────

func (m BloodHoundModel) setupHeight() int { return 6 } // border + 4 fields + border

func (m BloodHoundModel) renderSetup() string {
	w := m.width
	if w <= 0 {
		w = 80
	}

	refreshCollectSources(m.app)
	sourceValue := strings.TrimSpace(m.app.CollectSource)
	if sourceValue == "" {
		sourceValue = "all"
	}
	if strings.EqualFold(sourceValue, "all") {
		sourceValue = fmt.Sprintf("all hosts (%d)", max(0, len(m.app.CollectSourceOpts)-1))
	}

	actionIcon := "▶"
	if m.app.CollectActive {
		actionIcon = "■"
	}

	rows := []FormRow{
		{Field: collectFieldSource, Label: "Source", Value: sourceValue},
		{Field: collectFieldOutput, Label: "Output", Value: m.app.CollectOutput, Editable: true},
		{Field: collectFieldDuration, Label: "Duration", Value: m.app.CollectDurationStr},
		{Field: collectFieldAction, Label: "Action", Value: actionIcon + " " + collectActionLabel(m.app)},
	}
	return renderSetupPanel("SETUP", rows, m.app.CollectField, m.app.CollectEditing, w)
}

// ── Report panel ─────────────────────────────────────────────────────────────

func (m *BloodHoundModel) initViewport() {
	if m.width <= 0 || m.height <= 0 {
		return
	}
	reportH := m.height - m.headerHeight() - m.setupHeight()
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

func (m *BloodHoundModel) refreshContent() {
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

func (m BloodHoundModel) buildContent() string {
	// Live collection.
	if m.app.CollectActive {
		pLines := collectLiveLines(m.app)
		if len(pLines) == 0 {
			spinFrames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
			frame := spinFrames[int(time.Now().UnixMilli()/120)%len(spinFrames)]
			spinner := lipgloss.NewStyle().Foreground(colorCyan).Bold(true).Render(frame)
			return "  " + spinner + " " + sectionLabel.Render("Starting collection...")
		}
		var out []string
		for i, line := range pLines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "[*]") {
				task := strings.TrimSpace(strings.TrimPrefix(trimmed, "[*]"))
				if i == len(pLines)-1 {
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

	// Show results if available.
	if m.app.CollectResultHasData {
		return m.buildResultContent()
	}

	// Empty state.
	return inspValue.Render("No collection report yet.") + "\n" +
		dimText.Render("Configure source and duration, then start a collection.")
}

func (m BloodHoundModel) buildResultContent() string {
	w := m.width - 4
	if w < 20 {
		w = 20
	}

	kv := func(label, value string) string {
		return dimText.Render(fmt.Sprintf("  %-14s", label)) + bodyText.Render(value)
	}

	// ── GRAPH box ──
	var graphLines []string
	graphLines = append(graphLines, kv("Nodes", fmt.Sprintf("%d", m.app.CollectResultNodes)))
	graphLines = append(graphLines, kv("Edges", fmt.Sprintf("%d", m.app.CollectResultEdges)))
	graphLines = append(graphLines, kv("Candidates", fmt.Sprintf("%d", m.app.CollectResultCandidates)))
	graphLines = append(graphLines, kv("Hosts", fmt.Sprintf("%d", m.app.CollectResultHosts)))

	// ── NETWORK box ──
	var netLines []string
	netLines = append(netLines, kv("External", fmt.Sprintf("%d connections", m.app.CollectResultExternal)))
	netLines = append(netLines, kv("Internal", fmt.Sprintf("%d connections", m.app.CollectResultInternal)))
	netLines = append(netLines, kv("Listeners", fmt.Sprintf("%d", m.app.CollectResultListeners)))
	netLines = append(netLines, kv("Duration", m.app.CollectResultDuration))

	// ── OUTPUT box ──
	var outputLines []string
	outputLines = append(outputLines, "  "+bodyText.Render(m.app.CollectResultOutput))
	if m.app.CollectResultUploaded {
		outputLines = append(outputLines, "  "+statusPass.Render("Uploaded to BloodHound"))
	} else {
		outputLines = append(outputLines, "  "+dimText.Render("Not uploaded"))
	}

	var out []string
	graphContent := strings.Join(graphLines, "\n")
	out = append(out, renderAccentPanel(w, len(graphLines)+2, "GRAPH", graphContent))

	netContent := strings.Join(netLines, "\n")
	out = append(out, renderAccentPanel(w, len(netLines)+2, "NETWORK", netContent))

	outputContent := strings.Join(outputLines, "\n")
	out = append(out, renderAccentPanel(w, len(outputLines)+2, "OUTPUT", outputContent))

	return strings.Join(out, "\n")
}

func (m BloodHoundModel) renderReportPanel() string {
	w := m.width
	if w <= 0 {
		w = 80
	}
	reportH := m.height - m.headerHeight() - m.setupHeight()
	reportH--
	if reportH < 4 {
		reportH = 4
	}

	panelTitle := "DISPLAY"
	if m.app.CollectActive {
		panelTitle = "COLLECTING"
	}

	opts := ReportPanelOpts{
		Title:       panelTitle,
		Width:       w,
		Height:      reportH,
		StatusText:  m.app.CollectStatusText,
		StatusError: m.app.CollectStatusError,
		StatusUntil: m.app.CollectStatusUntil,
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

// Ensure imports are used.
var _ = tcell.KeyUp
