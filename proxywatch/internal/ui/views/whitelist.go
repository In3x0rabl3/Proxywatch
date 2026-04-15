package views

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/gdamore/tcell/v2"

	"proxywatch/internal/shared"
)

type WhitelistModel struct {
	app    *shared.AppState
	width  int
	height int
}

func NewWhitelistModel(app *shared.AppState) WhitelistModel {
	return WhitelistModel{app: app}
}

func (m WhitelistModel) Init() tea.Cmd { return nil }

func (m WhitelistModel) Update(msg tea.Msg) (WhitelistModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

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
		if jumpToWorkflow(m.app, tev.Rune()) {
			return m, nil
		}

		if handleWhitelistKey(m.app, tev) {
			return m, tea.Quit
		}
	}

	return m, nil
}

func (m WhitelistModel) View() string {
	w := m.width
	h := m.height
	if w <= 0 || h <= 0 {
		return ""
	}

	var sections []string
	sections = append(sections, m.renderHeader(w))
	sections = append(sections, m.renderProcesses(w, h))
	sections = append(sections, m.renderEntries(w, h))

	view := lipgloss.JoinVertical(lipgloss.Left, sections...)

	if m.app.ShowQuitConfirm && m.app.QuitConfirmDeadline.After(time.Now()) {
		quitPanel := renderQuitConfirm(m.app.QuitConfirmDeadline, w)
		view = overlayCenter(view, quitPanel, w, m.height)
	}
	if m.app.WhitelistShowHelp {
		view = overlayCenter(view, renderHelpPanel("Whitelist Menu", whitelistMenuHelpOptions(), w), w, h)
	}
	return view
}

func (m WhitelistModel) renderHeader(w int) string {
	contentW := w - 2
	helpPlain := "? help"
	utcPlain := "UTC: " + time.Now().UTC().Format(UTCTimeFormat)
	gap := max(1, contentW-len(helpPlain)-len(utcPlain))

	line := dimText.Render(helpPlain) + bgSp(gap) +
		rightLabelStyle.Render("UTC: ") + sectionLabel.Render(time.Now().UTC().Format(UTCTimeFormat))

	return renderPanel(w, 3, "Whitelist", "proxywatch", "", line)
}

func (m WhitelistModel) renderProcesses(w, totalH int) string {
	procs := whitelistProcessCandidates(m.app)
	processH := m.processListHeight(totalH)
	focused := m.app.WhitelistField == whitelistFieldProcess

	counter := fmt.Sprintf("%d/%d", max(0, m.app.WhitelistProcessSelected+1), len(procs))

	titleLabel := "PROCESSES"
	if focused {
		titleLabel = "PROCESSES · ENTER to whitelist"
	}

	if len(procs) == 0 {
		body := bodyText.Render("  No process snapshot available yet.") + "\n" +
			dimText.Render("  Waiting for telemetry refresh...")
		return renderPanel(w, processH, titleLabel, counter, "", body)
	}

	if m.app.WhitelistProcessSelected < 0 {
		m.app.WhitelistProcessSelected = 0
	}
	if m.app.WhitelistProcessSelected >= len(procs) {
		m.app.WhitelistProcessSelected = len(procs) - 1
	}

	viewRows := max(1, processH-2)
	offset := m.app.WhitelistProcessOffset
	if m.app.WhitelistProcessSelected < offset {
		offset = m.app.WhitelistProcessSelected
	}
	if m.app.WhitelistProcessSelected >= offset+viewRows {
		offset = m.app.WhitelistProcessSelected - viewRows + 1
	}
	maxOffset := max(0, len(procs)-viewRows)
	if offset > maxOffset {
		offset = maxOffset
	}
	if offset < 0 {
		offset = 0
	}
	m.app.WhitelistProcessOffset = offset

	const (
		hostW  = 6
		pidW   = 7
		roleW  = 10
		stateW = 6
	)
	nameW := max(8, min(20, w-4-hostW-pidW-roleW-stateW-10))

	var lines []string
	for i := offset; i < len(procs) && len(lines) < viewRows; i++ {
		c := procs[i]
		host := shared.DisplayHost(c.Host)
		pid := 0
		name := "(unknown)"
		if c.Proc != nil {
			pid = c.Proc.Pid
			name = shared.DisplayProcessName(c.Proc)
		}
		role := normalizeDashboardRole(c.Role)
		state := shared.CandidateState(c)
		sel := focused && i == m.app.WhitelistProcessSelected
		gap := applySelectBg(bg(), sel)
		prefix := " "
		prefixStyle := bg()
		hostStyle := lgText
		nameStyle := lgTextB
		pidStyle := lgDim
		if sel {
			prefix = ">"
			prefixStyle = lipgloss.NewStyle().Foreground(colorCyan).Bold(true)
			hostStyle = lgTextB
		}

		row := applySelectBg(prefixStyle, sel).Render(prefix) + gap.Render(" ") +
			applySelectBg(hostStyle, sel).Render(fmt.Sprintf("%-*s", hostW, TruncateToWidth(host, hostW))) + gap.Render(" ") +
			applySelectBg(pidStyle, sel).Render(fmt.Sprintf("%-*d", pidW, pid)) + gap.Render(" ") +
			applySelectBg(nameStyle, sel).Render(fmt.Sprintf("%-*s", nameW, ClipToWidth(name, nameW))) + gap.Render("  ") +
			applySelectBg(lgRoleStyle(role), sel).Render(fmt.Sprintf("%-*s", roleW, TruncateToWidth(role, roleW))) + gap.Render(" ") +
			applySelectBg(lgStateStyle(state), sel).Render(fmt.Sprintf("%-*s", stateW, TruncateToWidth(state, stateW)))

		if sel {
			row = lgSelectBg.Width(w - 2).Render(row)
		}
		lines = append(lines, row)
	}

	body := strings.Join(lines, "\n")
	return renderPanel(w, processH, titleLabel, counter, "", body)
}

func (m WhitelistModel) renderEntries(w, totalH int) string {
	entriesH := m.entriesListHeight(totalH)
	items := m.app.WhitelistItems
	focused := m.app.WhitelistField == whitelistFieldEntry

	counter := fmt.Sprintf("%d/%d", max(0, m.app.WhitelistSelected+1), len(items))

	titleLabel := "WHITELISTED"
	if focused {
		titleLabel = "WHITELISTED · ENTER to remove"
	}

	if len(items) == 0 {
		body := bodyText.Render("  No whitelisted processes yet.") + "\n" +
			dimText.Render("  Select a process above and press ENTER.")
		return renderPanel(w, entriesH, titleLabel, counter, "", body)
	}

	if m.app.WhitelistSelected < 0 {
		m.app.WhitelistSelected = 0
	}
	if m.app.WhitelistSelected >= len(items) {
		m.app.WhitelistSelected = len(items) - 1
	}

	viewRows := max(1, entriesH-2)
	offset := m.app.WhitelistListOffset
	if m.app.WhitelistSelected < offset {
		offset = m.app.WhitelistSelected
	}
	if m.app.WhitelistSelected >= offset+viewRows {
		offset = m.app.WhitelistSelected - viewRows + 1
	}
	maxOffset := max(0, len(items)-viewRows)
	if offset > maxOffset {
		offset = maxOffset
	}
	if offset < 0 {
		offset = 0
	}
	m.app.WhitelistListOffset = offset

	var lines []string
	for i := offset; i < len(items) && len(lines) < viewRows; i++ {
		entry := formatWhitelistEntry(items[i], w-8)
		sel := focused && i == m.app.WhitelistSelected
		gap := applySelectBg(bg(), sel)
		prefix := " "
		prefixStyle := bg()
		if sel {
			prefix = ">"
			prefixStyle = lipgloss.NewStyle().Foreground(colorCyan).Bold(true)
		}
		row := applySelectBg(prefixStyle, sel).Render(prefix) + gap.Render(" ") + applySelectBg(bodyText, sel).Render(entry)
		if sel {
			row = lgSelectBg.Width(w - 2).Render(row)
		}
		lines = append(lines, row)
	}

	body := strings.Join(lines, "\n")
	return renderPanel(w, entriesH, titleLabel, counter, "", body)
}

func (m WhitelistModel) processListHeight(totalH int) int {
	available := totalH - 3
	if available < 8 {
		return max(4, available/2)
	}
	return available / 2
}

func (m WhitelistModel) entriesListHeight(totalH int) int {
	available := totalH - 3
	processH := m.processListHeight(totalH)
	entriesH := available - processH
	if entriesH < 4 {
		entriesH = 4
	}
	return entriesH
}

// Ensure imports used.
var _ = tcell.KeyUp
