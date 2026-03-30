package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// ── Color Palette ───────────────────────────────────────────────────────────

var (
	colorBg      = lipgloss.Color("#1E1E1E")
	colorText    = lipgloss.Color("#E2EAF2")
	colorTextHi  = lipgloss.Color("#F5FAFF")
	colorFrame   = lipgloss.Color("#845CB6")
	colorAccent  = lipgloss.Color("#A57D52")
	colorCyan    = lipgloss.Color("#5EBC8E")
	colorDim     = lipgloss.Color("#7E8EA8")
	colorMuted   = lipgloss.Color("#7082A0")
	colorAlert   = lipgloss.Color("#C67682")
	colorWarn    = lipgloss.Color("#C9AD5E")
	colorSelect  = lipgloss.Color("#2A3444")
	colorSession = lipgloss.Color("#C67682")
)

func bg() lipgloss.Style { return lipgloss.NewStyle().Background(colorBg) }

func bgSp(n int) string {
	if n <= 0 {
		return ""
	}
	return lipgloss.NewStyle().Background(colorBg).Render(strings.Repeat(" ", n))
}

// ── Shared Styles ───────────────────────────────────────────────────────────

var panelBorder = lipgloss.NewStyle().
	Border(lipgloss.RoundedBorder()).
	BorderForeground(colorFrame).
	BorderBackground(colorBg).
	Background(colorBg)

var (
	titleStyle      = lipgloss.NewStyle().Foreground(colorAccent).Bold(true).Background(colorBg)
	rightLabelStyle = lipgloss.NewStyle().Foreground(colorCyan).Bold(true).Background(colorBg)
	sectionLabel    = lipgloss.NewStyle().Foreground(colorText).Bold(true).Background(colorBg)
	bodyText        = lipgloss.NewStyle().Foreground(colorText).Background(colorBg)
	mutedText       = lipgloss.NewStyle().Foreground(colorMuted).Background(colorBg)
	dimText         = lipgloss.NewStyle().Foreground(colorDim).Background(colorBg)
	statusBar       = lipgloss.NewStyle().Foreground(colorDim).Background(colorBg)
	scrollIndicator = lipgloss.NewStyle().Foreground(colorCyan).Bold(true).Background(colorBg)
)

var (
	fieldLabel    = lipgloss.NewStyle().Foreground(colorDim).Background(colorBg)
	fieldValue    = lipgloss.NewStyle().Foreground(colorText).Background(colorBg)
	fieldSelected = lipgloss.NewStyle().Foreground(colorText).Bold(true).Background(colorSelect)
	fieldCursor   = lipgloss.NewStyle().Foreground(colorCyan).Bold(true).Background(colorBg)
)

var (
	sevActive = lipgloss.NewStyle().Foreground(colorAlert).Bold(true).Background(colorBg)
	sevStrong = lipgloss.NewStyle().Foreground(colorAlert).Background(colorBg)
	sevWatch  = lipgloss.NewStyle().Foreground(colorWarn).Bold(true).Background(colorBg)
)

var (
	statusPass  = lipgloss.NewStyle().Foreground(colorCyan).Background(colorBg)
	statusFail  = lipgloss.NewStyle().Foreground(colorAlert).Background(colorBg)
	statusMixed = lipgloss.NewStyle().Foreground(colorWarn).Background(colorBg)
	statusPivot = lipgloss.NewStyle().Foreground(colorWarn).Background(colorBg)
)

// ── FormRow ──────────────────────────────────────────────────────────────────

// FormRow represents a single row in a setup panel form.
type FormRow struct {
	Field      int
	Label      string
	Value      string
	Editable   bool
	CursorPos  int // cursor position within Value when editing
}

// ── renderSetupPanel ─────────────────────────────────────────────────────────

// renderSetupPanel renders a bordered setup panel with form rows.
func renderSetupPanel(title string, rows []FormRow, selectedField int, editing bool, w int) string {
	if w <= 0 {
		w = 80
	}

	labelW := 15
	contentW := w - 2
	selBg := lipgloss.NewStyle().Background(colorSelect)
	cursorStyle := lipgloss.NewStyle().Foreground(colorCyan).Bold(true).Background(colorSelect)
	selLabel := lipgloss.NewStyle().Foreground(colorText).Bold(true).Background(colorSelect)
	selValue := lipgloss.NewStyle().Foreground(colorTextHi).Bold(true).Background(colorSelect)
	normalLabel := lipgloss.NewStyle().Foreground(colorMuted)
	normalValue := lipgloss.NewStyle().Foreground(colorText)

	var lines []string
	for _, r := range rows {
		selected := r.Field == selectedField
		value := r.Value
		if value == "" {
			value = "-"
		}
		label := fmt.Sprintf("%-*s", labelW, r.Label+":")

		if selected {
			var row string
			if editing && r.Editable {
				// Show value with cursor block at CursorPos.
				pos := r.CursorPos
				if pos > len(r.Value) {
					pos = len(r.Value)
				}
				if pos < 0 {
					pos = 0
				}
				before := r.Value[:pos]
				after := r.Value[pos:]
				cursorBlock := lipgloss.NewStyle().Foreground(colorBg).Background(colorCyan).Render(" ")
				if len(after) > 0 {
					cursorBlock = lipgloss.NewStyle().Foreground(colorBg).Background(colorCyan).Render(string(after[0]))
					after = after[1:]
				}
				editValue := selValue.Render(before) + cursorBlock + selValue.Render(after)
				row = cursorStyle.Render("> ") + selLabel.Render(label) + selBg.Render(" ") + editValue
			} else {
				row = cursorStyle.Render("> ") + selLabel.Render(label) + selBg.Render(" ") + selValue.Render(value)
			}
			lines = append(lines, selBg.Width(contentW).Render(row))
		} else {
			lines = append(lines, bg().Render("  ")+normalLabel.Render(label)+bg().Render(" ")+normalValue.Render(value))
		}
	}
	content := strings.Join(lines, "\n")
	h := len(lines) + 2
	return renderPanel(w, h, title, "", "", content)
}

// ── ReportPanelOpts ──────────────────────────────────────────────────────────

// ReportPanelOpts configures a report panel.
type ReportPanelOpts struct {
	Title         string
	RightLabel    string
	Width         int
	Height        int
	Content       string
	StatusText    string
	StatusError   bool
	StatusUntil   time.Time
	ScrollTotal   int
	ScrollVisible int
	ScrollTop     int
	ScrollBottom  int
}

// renderReportPanel renders a bordered report/results panel with optional
// scroll indicator and status line.
func renderReportPanel(opts ReportPanelOpts) string {
	w := opts.Width
	if w <= 0 {
		w = 80
	}
	h := opts.Height
	if h < 4 {
		h = 4
	}

	// Build scroll label for bottom border.
	bottomRight := ""
	if opts.ScrollTotal > opts.ScrollVisible && opts.ScrollVisible > 0 {
		bottomRight = fmt.Sprintf("%d-%d of %d", opts.ScrollTop, opts.ScrollBottom, opts.ScrollTotal)
	}

	panel := renderPanel(w, h, opts.Title, opts.RightLabel, bottomRight, opts.Content)

	// Status line.
	if opts.StatusText != "" && time.Now().Before(opts.StatusUntil) {
		st := bodyText
		if opts.StatusError {
			st = statusFail
		}
		panel += "\n" + st.Render("  "+opts.StatusText)
	}

	return panel
}

// ── renderPanel ─────────────────────────────────────────────────────────────
// overlayCenter renders a panel centered on the screen over the base view.
func overlayCenter(base string, overlay string, screenW, screenH int) string {
	baseLines := strings.Split(base, "\n")
	overlayLines := strings.Split(overlay, "\n")

	overlayH := len(overlayLines)
	overlayW := 0
	for _, l := range overlayLines {
		if lw := lipgloss.Width(l); lw > overlayW {
			overlayW = lw
		}
	}

	// Ensure base fills the screen.
	for len(baseLines) < screenH {
		baseLines = append(baseLines, bgSp(screenW))
	}

	startY := (screenH - overlayH) / 2
	if startY < 0 {
		startY = 0
	}
	startX := (screenW - overlayW) / 2
	if startX < 0 {
		startX = 0
	}

	// Replace only overlay lines, keeping base above and below.
	for i, ol := range overlayLines {
		y := startY + i
		if y >= len(baseLines) {
			break
		}
		olW := lipgloss.Width(ol)
		// Construct: leftPad + overlay + rightPad (all on black bg to cover base)
		leftPad := bgSp(startX)
		rightPad := ""
		rightRemaining := screenW - startX - olW
		if rightRemaining > 0 {
			rightPad = bgSp(rightRemaining)
		}
		baseLines[y] = leftPad + ol + rightPad
	}

	if len(baseLines) > screenH {
		baseLines = baseLines[:screenH]
	}
	return strings.Join(baseLines, "\n")
}

//
// renderPanel builds a bordered panel that matches the tcell drawPanel look:
// titles are embedded in the top border line, and an optional bottom-right
// label is embedded in the bottom border line.
//
//	┌─ Title ──────────────────────── RightTitle ─┐
//	│ content                                      │
//	└──────────────────────────────────────── 2/6 ─┘
//
// It uses lipgloss panelBorder for reliable side-border rendering, then
// replaces the auto-generated top/bottom border lines with custom ones
// that embed the title text.
//
func renderPanel(w, h int, title, rightTitle, bottomRight, content string) string {
	if w < 6 {
		w = 6
	}
	if h < 3 {
		h = 3
	}

	// Let lipgloss render the full bordered panel (reliable side borders).
	bordered := panelBorder.Width(w - 2).Height(h - 2).Render(content)
	lines := strings.Split(bordered, "\n")

	frameStyle := lipgloss.NewStyle().Foreground(colorFrame).Background(colorBg)
	accentStyle := lipgloss.NewStyle().Foreground(colorAccent).Bold(true).Background(colorBg)
	cyanBold := lipgloss.NewStyle().Foreground(colorCyan).Bold(true).Background(colorBg)

	// ── Replace top border with title-embedded version ───────────────
	// Build a plain string first, then style segments, to ensure
	// the total visible width exactly matches w.
	if len(lines) > 0 && (title != "" || rightTitle != "") {
		topInner := w - 2
		var styled strings.Builder
		used := 0

		if title != "" {
			label := " " + title + " "
			labelW := lipgloss.Width(label)
			styled.WriteString(frameStyle.Render("─"))
			styled.WriteString(accentStyle.Render(label))
			used += 1 + labelW
		}
		if rightTitle != "" {
			label := " " + rightTitle + " "
			labelW := lipgloss.Width(label)
			fill := topInner - used - 1 - labelW
			if fill < 0 {
				fill = 0
			}
			styled.WriteString(frameStyle.Render(strings.Repeat("─", fill)))
			styled.WriteString(cyanBold.Render(label))
			styled.WriteString(frameStyle.Render("─"))
			used += fill + labelW + 1
		}
		remaining := topInner - used
		if remaining > 0 {
			styled.WriteString(frameStyle.Render(strings.Repeat("─", remaining)))
		}
		lines[0] = frameStyle.Render("╭") + styled.String() + frameStyle.Render("╮")
	}

	// ── Replace bottom border with label-embedded version ────────────
	if bottomRight != "" && len(lines) > 1 {
		botInner := w - 2
		label := " " + bottomRight + " "
		labelW := lipgloss.Width(label)
		fill := botInner - 1 - labelW
		if fill < 0 {
			fill = 0
		}
		lines[len(lines)-1] = frameStyle.Render("╰"+strings.Repeat("─", fill)) +
			cyanBold.Render(label) +
			frameStyle.Render("─╯")
	}

	return strings.Join(lines, "\n")
}

// renderAccentPanel renders a bordered panel with orange (accent) borders
// and a title embedded in the top border.  Used for contour sub-panels
// (MATRIX, SERVICES, ROUTES, ENDPOINTS, MISC).
func renderAccentPanel(w, h int, title, content string) string {
	if w < 6 {
		w = 6
	}
	if h < 3 {
		h = 3
	}

	accentBorder := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorAccent).
		BorderBackground(colorBg).
		Background(colorBg)

	bordered := accentBorder.Width(w - 2).Height(h - 2).Render(content)
	lines := strings.Split(bordered, "\n")

	frameStyle := lipgloss.NewStyle().Foreground(colorAccent).Background(colorBg)
	titleStyle := lipgloss.NewStyle().Foreground(colorAccent).Bold(true).Background(colorBg)

	if len(lines) > 0 && title != "" {
		topInner := w - 2
		label := " " + title + " "
		labelW := lipgloss.Width(label)
		var styled strings.Builder
		styled.WriteString(frameStyle.Render("─"))
		styled.WriteString(titleStyle.Render(label))
		remaining := topInner - 1 - labelW
		if remaining > 0 {
			styled.WriteString(frameStyle.Render(strings.Repeat("─", remaining)))
		}
		lines[0] = frameStyle.Render("╭") + styled.String() + frameStyle.Render("╮")
	}

	return strings.Join(lines, "\n")
}

// ── renderQuitConfirm ────────────────────────────────────────────────────────

// renderQuitConfirm renders the quit confirmation overlay.
func renderQuitConfirm(deadline time.Time, w int) string {
	remaining := time.Until(deadline).Truncate(time.Second)
	if remaining < 0 {
		remaining = 0
	}
	msg := fmt.Sprintf("  Press q again to quit (%ds)", int(remaining.Seconds()))
	return statusFail.Render(msg)
}

// ── renderMenuPanel ──────────────────────────────────────────────────────────

// renderMenuPanel renders a centered, auto-sized menu overlay.
func renderMenuPanel(title string, options []string, selected int, footer string, screenW int) string {
	if screenW <= 0 {
		screenW = 80
	}

	// Compute content width from longest option.
	maxLen := len(title) + 4
	for _, opt := range options {
		if n := len(opt) + 4; n > maxLen {
			maxLen = n
		}
	}
	if footer != "" {
		if n := len(footer) + 4; n > maxLen {
			maxLen = n
		}
	}
	panelW := maxLen + 6 // padding + border
	if panelW > screenW-4 {
		panelW = screenW - 4
	}
	if panelW < 20 {
		panelW = 20
	}

	selBg := lipgloss.NewStyle().Background(colorSelect)
	cursorStyle := lipgloss.NewStyle().Foreground(colorCyan).Bold(true).Background(colorSelect)
	selText := lipgloss.NewStyle().Foreground(colorTextHi).Bold(true).Background(colorSelect)

	var lines []string
	for i, opt := range options {
		if i == selected {
			row := cursorStyle.Render("> ") + selText.Render(opt)
			lines = append(lines, selBg.Width(panelW-2).Render(row))
		} else {
			lines = append(lines, dimText.Render("  ")+bodyText.Render(opt))
		}
	}
	content := strings.Join(lines, "\n")
	if footer != "" {
		content += "\n" + dimText.Render("  "+footer)
	}

	h := len(lines) + 2
	if footer != "" {
		h++
	}
	panel := renderPanel(panelW, h, title, "", "", content)

	// Center horizontally.
	return lipgloss.PlaceHorizontal(screenW, lipgloss.Center, panel)
}

// ── renderHelpPanel ──────────────────────────────────────────────────────────

// helpSection groups a section header with its key-description entries.
type helpSection struct {
	title   string
	entries []helpEntry
}

type helpEntry struct {
	key  string
	desc string
}

// parseHelpSections groups flat options into sections.
func parseHelpSections(options []string) []helpSection {
	var sections []helpSection
	var cur *helpSection
	for _, opt := range options {
		if opt == "" {
			continue
		}
		if len(opt) > 2 && opt[0] == '[' && opt[len(opt)-1] == ']' {
			sections = append(sections, helpSection{title: opt[1 : len(opt)-1]})
			cur = &sections[len(sections)-1]
			continue
		}
		if cur == nil {
			sections = append(sections, helpSection{})
			cur = &sections[len(sections)-1]
		}
		key := opt
		desc := ""
		for i := 1; i < len(opt)-1; i++ {
			if opt[i] == ' ' && opt[i+1] == ' ' {
				key = strings.TrimRight(opt[:i], " ")
				desc = strings.TrimLeft(opt[i:], " ")
				break
			}
		}
		cur.entries = append(cur.entries, helpEntry{key, desc})
	}
	return sections
}

// renderHelpPanel renders a styled two-column help overlay.
func renderHelpPanel(title string, options []string, w int) string {
	if w <= 0 {
		w = 80
	}

	navKeyStyle := lipgloss.NewStyle().Foreground(colorText).Bold(true)
	workflowKeyStyle := lipgloss.NewStyle().Foreground(colorCyan).Bold(true)
	actionKeyStyle := lipgloss.NewStyle().Foreground(colorWarn).Bold(true)
	descStyle := lipgloss.NewStyle().Foreground(colorDim)
	sectionStyle := lipgloss.NewStyle().Foreground(colorAccent).Bold(true)

	sections := parseHelpSections(options)

	// Choose key style based on section name.
	keyStyleFor := func(sectionTitle string) lipgloss.Style {
		switch strings.ToLower(sectionTitle) {
		case "workflows":
			return workflowKeyStyle
		case "actions":
			return actionKeyStyle
		default:
			return navKeyStyle
		}
	}

	// Two-column layout: split sections between left and right columns.
	// Put Navigation on the left, Workflows + Actions on the right.
	var leftSections, rightSections []helpSection
	for _, s := range sections {
		switch strings.ToLower(s.title) {
		case "navigation":
			leftSections = append(leftSections, s)
		default:
			rightSections = append(rightSections, s)
		}
	}

	const keyColW = 14
	const gap = 4
	// Compute column widths from actual content, not screen width.
	colW := keyColW + 26 // key column + typical description

	renderColumn := func(secs []helpSection, colWidth int) []string {
		var lines []string
		for i, sec := range secs {
			if i > 0 {
				lines = append(lines, "")
			}
			lines = append(lines, sectionStyle.Render(sec.title))
			ks := keyStyleFor(sec.title)
			for _, e := range sec.entries {
				kw := min(keyColW, colWidth/2)
				if e.desc != "" {
					lines = append(lines, ks.Render(fmt.Sprintf(" %-*s", kw, e.key))+descStyle.Render(e.desc))
				} else {
					lines = append(lines, descStyle.Render(" "+e.key))
				}
			}
		}
		return lines
	}

	leftLines := renderColumn(leftSections, colW)
	rightLines := renderColumn(rightSections, colW)

	// Merge left and right columns side by side.
	maxRows := max(len(leftLines), len(rightLines))
	var merged []string
	for i := 0; i < maxRows; i++ {
		left := ""
		if i < len(leftLines) {
			left = leftLines[i]
		}
		right := ""
		if i < len(rightLines) {
			right = rightLines[i]
		}
		// Pad left column to fixed width.
		leftVis := lipgloss.Width(left)
		pad := colW - leftVis
		if pad < 0 {
			pad = 0
		}
		merged = append(merged, left+bgSp(pad)+bgSp(gap)+right)
	}

	// Measure actual content width for auto-sizing.
	maxContentW := 0
	for _, line := range merged {
		if lw := lipgloss.Width(line); lw > maxContentW {
			maxContentW = lw
		}
	}
	panelW := maxContentW + 4 // border + small padding
	if panelW > w-4 {
		panelW = w - 4
	}
	if panelW < 40 {
		panelW = 40
	}

	content := strings.Join(merged, "\n")
	h := len(merged) + 2
	return renderPanel(panelW, h, title, "? close", "", content)
}
