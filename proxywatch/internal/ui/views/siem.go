package views

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/gdamore/tcell/v2"

	"proxywatch/internal/shared"
	"proxywatch/internal/ui/platform"
)

// SIEMPlatforms lists the five detection rule formats exported in every
// generated JSON bundle.
var SIEMPlatforms = []string{"Splunk", "KQL", "Sigma", "YARA", "Suricata"}

// SIEMRoleFilters retained for legacy callers — TUI pins to control-* only.
var SIEMRoleFilters = []string{"", "control", "pivot", "listener", "outbound"}

// Setup form fields, ordered to match their visual layout (Output above
// Action) so UP/DOWN navigation feels natural.
const (
	siemFieldOutput = iota
	siemFieldAction
)

const siemFieldMax = siemFieldAction

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

		if jumpToWorkflow(m.app, tev.Rune()) {
			return m, nil
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

		if m.ready && !m.app.SiemShowHelp {
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
	if w <= 0 || h <= 0 {
		return ""
	}

	var sections []string
	sections = append(sections, m.renderHeader())
	sections = append(sections, m.renderSetup())

	used := 0
	for _, s := range sections {
		used += lipgloss.Height(s)
	}
	reportH := h - used
	if reportH < 4 {
		reportH = 4
	}
	sections = append(sections, m.renderReportPanel(reportH))

	view := lipgloss.JoinVertical(lipgloss.Left, sections...)

	if m.app.SiemShowHelp {
		view = overlayCenter(view, renderHelpPanel("SIEM Menu", siemMenuHelpOptions(), w), w, h)
	}
	if m.app.ShowQuitConfirm && m.app.QuitConfirmDeadline.After(time.Now()) {
		view = overlayCenter(view, renderQuitConfirm(m.app.QuitConfirmDeadline, w), w, h)
	}
	return view
}

// ── header ──────────────────────────────────────────────────────────────────

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
	return renderPanel(w, 3, "SIEM", "proxywatch", "", line)
}

// ── setup: Output + Action only, proxyhound-style ──────────────────────────

func (m SIEMModel) renderSetup() string {
	w := m.width
	if w <= 0 {
		w = 80
	}

	if strings.TrimSpace(m.app.SiemOutputPath) == "" {
		m.app.SiemOutputPath = defaultSIEMOutputPath(m.app)
	}

	action := platform.IconPlay + " Generate & Export"

	field := m.app.SiemField
	if field < 0 || field > siemFieldMax {
		field = siemFieldAction
	}

	rows := []FormRow{
		{Field: siemFieldOutput, Label: "Output", Value: m.app.SiemOutputPath, Editable: true},
		{Field: siemFieldAction, Label: "Action", Value: action},
	}
	return renderSetupPanel("SETUP", rows, field, false, w)
}

// defaultSIEMOutputPath is the view-side mirror of the keys-package helper
// of the same name. Duplicated (lowercase, unexported) to avoid a views→keys
// import cycle.
func defaultSIEMOutputPath(app *shared.AppState) string {
	if p := strings.TrimSpace(app.SiemOutputPath); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "."
	}
	host := shared.DisplayHost(app.LocalHost)
	if host == "" || host == "local" {
		host = shared.DefaultHostID("local")
	}
	return filepath.Join(home, ".proxywatch", "siem",
		fmt.Sprintf("siem-%s.json", host))
}

// ── report panel ────────────────────────────────────────────────────────────

func (m SIEMModel) renderReportPanel(reportH int) string {
	w := m.width
	if w <= 0 {
		w = 80
	}
	right := ""
	if m.app.SiemGenerated {
		right = fmt.Sprintf("%d detection%s", len(m.app.SiemGeneratedSet), plural(len(m.app.SiemGeneratedSet)))
	}
	opts := ReportPanelOpts{
		Title:       "DETECTIONS",
		RightLabel:  right,
		Width:       w,
		Height:      reportH,
		StatusText:  m.app.SiemStatusText,
		StatusError: m.app.SiemStatusError,
		StatusUntil: m.app.SiemStatusUntil,
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

// ── viewport lifecycle ──────────────────────────────────────────────────────

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

// ── content ─────────────────────────────────────────────────────────────────
//
// Display model is intentionally minimal: nothing before Action runs, and
// after Action runs a single summary line + a plain table. No badges, no
// per-detection cards, no per-format checkmarks — every row exports every
// platform so listing them is noise.

func (m SIEMModel) buildContent() string {
	if !m.app.SiemGenerated {
		return ""
	}
	if len(m.app.SiemGeneratedSet) == 0 {
		return "  No control-* processes were observed at generate time."
	}

	count := len(m.app.SiemGeneratedSet)
	rules := count * len(SIEMPlatforms)
	dest := strings.TrimSpace(m.app.SiemLastExportPath)
	if dest == "" {
		dest = m.app.SiemOutputPath
	}
	ts := m.app.SiemGeneratedAt.UTC().Format("2006-01-02 15:04:05 UTC")

	var b strings.Builder
	b.WriteString("  ")
	b.WriteString(bodyText.Render(fmt.Sprintf(
		"%d detection%s · %d rules · %s",
		count, plural(count), rules, ts)))
	b.WriteByte('\n')
	b.WriteString("  ")
	b.WriteString(dimText.Render(shortenHome(dest)))
	b.WriteString("\n\n")

	b.WriteString(m.renderTable())
	return b.String()
}

func (m SIEMModel) renderTable() string {
	const (
		nameW    = 28
		pidW     = 6
		roleW    = 18
		channelW = 22
	)
	var b strings.Builder

	header := fmt.Sprintf("  %-*s  %-*s  %-*s  %-*s  %s",
		nameW, "PROCESS", pidW, "PID", roleW, "ROLE", channelW, "CHANNEL", "TOP SIGNAL")
	b.WriteString(dimText.Render(header))
	b.WriteByte('\n')

	for _, c := range m.app.SiemGeneratedSet {
		name := "(unknown)"
		pid := 0
		if c.Proc != nil {
			if strings.TrimSpace(c.Proc.Name) != "" {
				name = c.Proc.Name
			}
			pid = c.Proc.Pid
		}
		role := c.Role
		channel := "—"
		if c.ControlChannel != nil && c.ControlChannel.RemoteAddress != "" {
			channel = fmt.Sprintf("%s:%d",
				c.ControlChannel.RemoteAddress, c.ControlChannel.RemotePort)
		}
		topSig := "—"
		if len(c.Signals) > 0 {
			topSig = c.Signals[0]
		}
		row := fmt.Sprintf("  %-*s  %-*d  %-*s  %-*s  %s",
			nameW, truncStr(name, nameW),
			pidW, pid,
			roleW, truncStr(role, roleW),
			channelW, truncStr(channel, channelW),
			truncStr(topSig, 40))
		b.WriteString(bodyText.Render(row))
		b.WriteByte('\n')
	}
	return b.String()
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func shortenHome(p string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return p
	}
	if strings.HasPrefix(p, home) {
		return "~" + strings.TrimPrefix(p, home)
	}
	return p
}

func truncStr(s string, w int) string {
	if lipgloss.Width(s) <= w {
		return s
	}
	if w <= 1 {
		return s[:w]
	}
	return s[:w-1] + "…"
}

// HandleSIEMKey is wired by the ui package at startup.
var HandleSIEMKey func(*shared.AppState, *tcell.EventKey) bool

func handleSIEMKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if HandleSIEMKey != nil {
		return HandleSIEMKey(app, tev)
	}
	return false
}
