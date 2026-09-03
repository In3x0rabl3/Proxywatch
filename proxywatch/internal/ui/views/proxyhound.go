package views

import (
	"fmt"
	"net"
	"os"
	"proxywatch/internal/ui/platform"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/gdamore/tcell/v2"

	"proxywatch/internal/shared"
)

func getDomainName() string {
	name, _ := os.Hostname()
	if parts := strings.SplitN(name, ".", 2); len(parts) > 1 {
		return parts[1]
	}
	addrs, err := net.LookupAddr("127.0.0.1")
	if err == nil {
		for _, a := range addrs {
			if parts := strings.SplitN(strings.TrimSuffix(a, "."), ".", 2); len(parts) > 1 {
				return parts[1]
			}
		}
	}
	return ""
}

type ProxyhoundModel struct {
	app            *shared.AppState
	viewport       viewport.Model
	width          int
	height         int
	ready          bool
	contentKey     uint64
	dynamicReportH int
}

func NewProxyhoundModel(app *shared.AppState) ProxyhoundModel {
	return ProxyhoundModel{app: app}
}

func (m ProxyhoundModel) Init() tea.Cmd { return nil }

func (m ProxyhoundModel) Update(msg tea.Msg) (ProxyhoundModel, tea.Cmd) {
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
		if !m.app.CollectEditing {
			if jumpToWorkflow(m.app, tev.Rune()) {
				return m, nil
			}
		}

		if m.app.CollectEditing {
			switch tev.Key() {
			case tcell.KeyLeft, tcell.KeyRight:
				return m, nil
			}
		} else {
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

		if m.ready && !m.app.CollectShowMenu && !m.app.CollectShowHelp && !m.app.CollectEditing {
			if m.handleScroll(tev) {
				return m, nil
			}
		}

		if handleCollectKey(m.app, tev) {
			return m, tea.Quit
		}
	}

	m.RefreshContent()
	return m, nil
}

func (m *ProxyhoundModel) handleScroll(tev *tcell.EventKey) bool {
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

func (m ProxyhoundModel) View() string {
	w := m.width
	h := m.height
	if w <= 0 || h <= 0 {
		return ""
	}

	var sections []string
	sections = append(sections, m.renderHeader())
	sections = append(sections, m.renderSetup())

	bottom := m.renderBottomBar(w)

	used := 0
	for _, s := range sections {
		used += lipgloss.Height(s)
	}
	used += lipgloss.Height(bottom)
	m.dynamicReportH = h - used
	if m.dynamicReportH < 4 {
		m.dynamicReportH = 4
	}

	sections = append(sections, m.renderReportPanel())
	sections = append(sections, bottom)

	view := lipgloss.JoinVertical(lipgloss.Left, sections...)

	if m.app.CollectShowHelp {
		view = overlayCenter(view, renderHelpPanel("ProxyHound Menu", collectMenuHelpOptions(), w), w, h)
	} else if m.app.CollectShowMenu {
		view = overlayCenter(view, renderMenuPanel(
			m.app.CollectMenuTitle,
			m.app.CollectMenuOptions,
			m.app.CollectMenuIndex,
			"", w), w, h)
	}

	if m.app.ShowQuitConfirm && m.app.QuitConfirmDeadline.After(time.Now()) {
		quitPanel := renderQuitConfirm(m.app.QuitConfirmDeadline, w)
		view = overlayCenter(view, quitPanel, w, m.height)
	}
	return view
}

func (m ProxyhoundModel) renderHeader() string {
	w := m.width
	if w <= 0 {
		w = 80
	}
	return shellBanner(w)
}

func (m ProxyhoundModel) renderBottomBar(w int) string {
	line := bgSp(1) + dimText.Render("esc dashboard    ↑↓ select    enter start/stop    ? menu")
	if pad := w - lipgloss.Width(line); pad > 0 {
		line += bgSp(pad)
	}
	return line
}

func (m ProxyhoundModel) renderSetup() string {
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

	actionIcon := platform.IconPlay
	if m.app.CollectActive {
		actionIcon = platform.IconStop
	}

	rows := []FormRow{}
	if strings.TrimSpace(m.app.LocalHost) == "" {
		rows = append(rows, FormRow{Field: collectFieldSource, Label: "Hosts", Value: sourceValue})
	}
	rows = append(rows,
		FormRow{Field: collectFieldOutput, Label: "Output", Value: m.app.CollectOutput, Editable: true},
		FormRow{Field: collectFieldAction, Label: "Action", Value: actionIcon + " " + collectActionLabel(m.app)},
	)
	return renderSetupPanel("SETUP", rows, m.app.CollectField, m.app.CollectEditing, w)
}

func (m *ProxyhoundModel) InitViewport() {
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
	// Account for the bottom bar (1 line)
	used += 1
	reportH := m.height - used
	if reportH < 4 {
		reportH = 4
	}
	reportW := m.width - 2
	vpH := reportH - 2
	if vpH < 2 {
		vpH = 2
	}
	if !m.ready {
		m.viewport = viewport.New(reportW, vpH)
		m.viewport.Style = lipgloss.NewStyle()
		m.ready = true
	} else {
		m.viewport.Width = reportW
		m.viewport.Height = vpH
	}
}

func (m *ProxyhoundModel) RefreshContent() {
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

func (m ProxyhoundModel) buildContent() string {
	if m.app.CollectActive {
		pLines := collectLiveLines(m.app)
		if len(pLines) == 0 {
			_ = dotSpinFrames
			frame := dotSpinFrame()
			spinner := lipgloss.NewStyle().Foreground(colorCyan).Bold(true).Render(frame)
			return "  " + spinner + " " + sectionLabel.Render("STARTING COLLECTION...")
		}
		var out []string
		for i, line := range pLines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "[*]") {
				task := strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(trimmed, "[*]")))
				if i == len(pLines)-1 {
					_ = dotSpinFrames
					frame := dotSpinFrame()
					spinner := lipgloss.NewStyle().Foreground(colorCyan).Bold(true).Render(frame)
					out = append(out, "  "+spinner+" "+sectionLabel.Render(task))
				} else {
					out = append(out, "  "+statusPass.Render(task))
				}
			} else if strings.HasPrefix(trimmed, "[+]") {
				task := strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(trimmed, "[+]")))
				out = append(out, "  "+statusPass.Render(task))
			} else if strings.HasPrefix(trimmed, "[-]") {
				task := strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(trimmed, "[-]")))
				out = append(out, "  "+statusFail.Render("ERROR: "+task))
			} else {
				out = append(out, "    "+bodyText.Render(strings.ToUpper(trimmed)))
			}
		}
		return strings.Join(out, "\n")
	}

	if m.app.CollectResultHasData {
		return m.buildResultContent()
	}

	return inspValue.Render("NO COLLECTION REPORT YET.") + "\n" +
		dimText.Render("CONFIGURE SOURCE AND DURATION, THEN START A COLLECTION.")
}

func (m ProxyhoundModel) buildResultContent() string {
	w := m.width - 4
	if w < 20 {
		w = 20
	}

	// Military-style kv with dot leaders
	kv := func(label, value string) string {
		label = strings.ToUpper(label)
		const totalWidth = 20
		dotsNeeded := totalWidth - len(label) - 1
		if dotsNeeded < 2 {
			dotsNeeded = 2
		}
		dots := " " + strings.Repeat(".", dotsNeeded) + " "
		return "  " + inspLabel.Render(label) + dimText.Render(dots) + bodyText.Render(value)
	}

	var graphLines []string
	graphLines = append(graphLines, kv("Nodes", fmt.Sprintf("%04d", m.app.CollectResultNodes)))
	graphLines = append(graphLines, kv("Edges", fmt.Sprintf("%04d", m.app.CollectResultEdges)))
	graphLines = append(graphLines, kv("Candidates", fmt.Sprintf("%04d", m.app.CollectResultCandidates)))
	graphLines = append(graphLines, kv("Hosts", fmt.Sprintf("%04d", m.app.CollectResultHosts)))

	hostname := strings.ToUpper(shared.DefaultHostID("UNKNOWN"))
	var envLines []string
	envLines = append(envLines, kv("Hostname", hostname))
	if domain := getDomainName(); domain != "" {
		envLines = append(envLines, kv("Domain", strings.ToUpper(domain)))
	}
	envLines = append(envLines, kv("Hosts", fmt.Sprintf("%04d", m.app.CollectResultHosts)))

	// Parse duration and format as tactical time
	durationStr := m.app.CollectResultDuration
	if d, err := time.ParseDuration(durationStr); err == nil {
		totalSec := int(d.Seconds())
		min := totalSec / 60
		sec := totalSec % 60
		durationStr = fmt.Sprintf("T+%02d:%02d", min, sec)
	}

	var netLines []string
	netLines = append(netLines, kv("External", fmt.Sprintf("%04d CONNECTIONS", m.app.CollectResultExternal)))
	netLines = append(netLines, kv("Internal", fmt.Sprintf("%04d CONNECTIONS", m.app.CollectResultInternal)))
	netLines = append(netLines, kv("Listeners", fmt.Sprintf("%04d", m.app.CollectResultListeners)))
	netLines = append(netLines, kv("Duration", durationStr))

	var outputLines []string
	outputLines = append(outputLines, "  "+bodyText.Render(m.app.CollectResultOutput))
	if m.app.CollectResultUploaded {
		outputLines = append(outputLines, "  "+statusPass.Render("UPLOADED TO PROXYHOUND"))
	} else {
		outputLines = append(outputLines, "  "+dimText.Render("NOT UPLOADED"))
	}

	var out []string
	graphContent := strings.Join(graphLines, "\n")
	out = append(out, renderAccentPanel(w, len(graphLines)+2, "GRAPH", graphContent))

	envContent := strings.Join(envLines, "\n")
	out = append(out, renderAccentPanel(w, len(envLines)+2, "ENVIRONMENT", envContent))

	netContent := strings.Join(netLines, "\n")
	out = append(out, renderAccentPanel(w, len(netLines)+2, "NETWORK", netContent))

	outputContent := strings.Join(outputLines, "\n")
	out = append(out, renderAccentPanel(w, len(outputLines)+2, "OUTPUT", outputContent))

	return strings.Join(out, "\n")
}

func (m ProxyhoundModel) renderReportPanel() string {
	w := m.width
	if w <= 0 {
		w = 80
	}
	reportH := m.dynamicReportH
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
