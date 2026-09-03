package common

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// ── Color Palette ───────────────────────────────────────────────────────────

// Color palette: chrome is monochrome/neutral gray so the eye is never
// pulled by decoration. Color is spent almost entirely on threat severity —
// red (high) / yellow (watch) / green (ok). Frames, titles, labels and
// selection are all neutral grays.
var (
	ColorBg      = lipgloss.Color("#121212") // panel/base background
	ColorText    = lipgloss.Color("#C8C8C8") // body text — neutral gray
	ColorTextHi  = lipgloss.Color("#FFFFFF") // emphasis / column headers
	ColorFrame   = lipgloss.Color("#333333") // borders, rules, underlines
	ColorAccent  = lipgloss.Color("#E6E6E6") // panel titles (bold, near-white)
	ColorCyan    = lipgloss.Color("#6F9B78") // SEVERITY: ok / pass — muted sage
	ColorDim     = lipgloss.Color("#6E6E6E") // de-emphasised text
	ColorMuted   = lipgloss.Color("#828282") // secondary labels
	ColorAlert   = lipgloss.Color("#B4696A") // SEVERITY: high / alert — dusty red
	ColorWarn    = lipgloss.Color("#B39A63") // SEVERITY: watch — muted gold
	ColorSelect  = lipgloss.Color("#1a1a1a") // selected-row background
	ColorSession = lipgloss.Color("#9AA0A6") // session marks — neutral
	ColorOrange  = lipgloss.Color("#B08A57") // SEVERITY: elevated — muted amber
	ColorLogo    = lipgloss.Color("#9E7BEA") // PROXYWATCH banner — vivid purple
	ColorLogoDim = lipgloss.Color("#6E5AA6") // banner shading — deeper purple
)

func Bg() lipgloss.Style { return lipgloss.NewStyle().Background(ColorBg) }

func BgSp(n int) string {
	if n <= 0 {
		return ""
	}
	return lipgloss.NewStyle().Background(ColorBg).Render(strings.Repeat(" ", n))
}

// ── Shared Styles ───────────────────────────────────────────────────────────

var PanelBorder = lipgloss.NewStyle().
	Border(lipgloss.NormalBorder()).
	BorderForeground(ColorFrame).
	BorderBackground(ColorBg).
	Background(ColorBg)

var (
	TitleStyle      = lipgloss.NewStyle().Foreground(ColorAccent).Bold(true).Background(ColorBg)
	RightLabelStyle = lipgloss.NewStyle().Foreground(ColorTextHi).Bold(true).Background(ColorBg)
	SectionLabel    = lipgloss.NewStyle().Foreground(ColorText).Bold(true).Background(ColorBg)
	BodyText        = lipgloss.NewStyle().Foreground(ColorText).Background(ColorBg)
	MutedText       = lipgloss.NewStyle().Foreground(ColorMuted).Background(ColorBg)
	DimText         = lipgloss.NewStyle().Foreground(ColorDim).Background(ColorBg)
	StatusBar       = lipgloss.NewStyle().Foreground(ColorDim).Background(ColorBg)
	ScrollIndicator = lipgloss.NewStyle().Foreground(ColorMuted).Bold(true).Background(ColorBg)
)

var (
	FieldLabel    = lipgloss.NewStyle().Foreground(ColorDim).Background(ColorBg)
	FieldValue    = lipgloss.NewStyle().Foreground(ColorText).Background(ColorBg)
	FieldSelected = lipgloss.NewStyle().Foreground(ColorText).Bold(true).Background(ColorSelect)
	FieldCursor   = lipgloss.NewStyle().Foreground(ColorTextHi).Bold(true).Background(ColorBg)
)

var (
	SevActive = lipgloss.NewStyle().Foreground(ColorAlert).Bold(true).Background(ColorBg)
	SevStrong = lipgloss.NewStyle().Foreground(ColorAlert).Background(ColorBg)
	SevWatch  = lipgloss.NewStyle().Foreground(ColorWarn).Bold(true).Background(ColorBg)
)

var (
	StatusPass  = lipgloss.NewStyle().Foreground(ColorCyan).Background(ColorBg)
	StatusFail  = lipgloss.NewStyle().Foreground(ColorAlert).Background(ColorBg)
	StatusMixed = lipgloss.NewStyle().Foreground(ColorWarn).Background(ColorBg)
	StatusPivot = lipgloss.NewStyle().Foreground(ColorWarn).Background(ColorBg)
)

// Shared matrix/service mark style — muted red for fail marks.
var MatrixFailStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#804040")).Background(ColorBg)

// Spinner frame helpers — avoid duplicating frame arrays everywhere.
//
// Windows console fonts (Consolas / Lucida Console / the new Cascadia
// fallback shipped with conhost) don't include the Braille block
// (U+2800–U+28FF) used by the dot spinner, nor the circle-with-pie
// glyphs (U+25D0–U+25D3) used by the dial spinner. Both render as
// missing-glyph boxes in the operator's view, which the user
// explicitly flagged. Use ASCII frames on Windows; keep the unicode
// frames on every other platform where the font support is fine.
var (
	DotSpinFrames  = pickSpinnerFrames([]string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}, []string{"|", "/", "-", "\\"})
	DialSpinFrames = pickSpinnerFrames([]string{"◐", "◓", "◑", "◒"}, []string{"-", "\\", "|", "/"})
)

func pickSpinnerFrames(unicodeFrames, asciiFrames []string) []string {
	if UIWindows {
		return asciiFrames
	}
	return unicodeFrames
}

func DotSpinFrame() string {
	return DotSpinFrames[int(time.Now().UnixMilli()/120)%len(DotSpinFrames)]
}

// ── FormRow ──────────────────────────────────────────────────────────────────

// FormRow represents a single row in a setup panel form.
type FormRow struct {
	Field     int
	Label     string
	Value     string
	Editable  bool
	CursorPos int // cursor position within Value when editing
}

// ── RenderSetupPanel ─────────────────────────────────────────────────────────

// RenderSetupPanel renders a bordered setup panel with form rows.
func RenderSetupPanel(title string, rows []FormRow, selectedField int, editing bool, w int) string {
	if w <= 0 {
		w = 80
	}

	labelW := 18
	contentW := w - 2
	selBg := lipgloss.NewStyle().Background(ColorSelect)
	// Cursor "> " uses ColorAccent so every selection bar across
	// the dashboards (process view, host view, pcap findings, every
	// SETUP form, every menu overlay) shares the same accent-coloured
	// glyph. Was ColorCyan; unified 2026-04-30.
	cursorStyle := lipgloss.NewStyle().Foreground(ColorAccent).Bold(true).Background(ColorSelect)
	selLabel := lipgloss.NewStyle().Foreground(ColorText).Bold(true).Background(ColorSelect)
	selValue := lipgloss.NewStyle().Foreground(ColorTextHi).Bold(true).Background(ColorSelect)
	normalLabel := lipgloss.NewStyle().Foreground(ColorMuted)
	normalValue := lipgloss.NewStyle().Foreground(ColorText)
	dotStyle := lipgloss.NewStyle().Foreground(ColorDim)
	selDotStyle := lipgloss.NewStyle().Foreground(ColorDim).Background(ColorSelect)

	// Dot leader helper
	kvDots := func(lbl string, totalW int) string {
		dotsNeeded := totalW - len(lbl) - 1
		if dotsNeeded < 2 {
			dotsNeeded = 2
		}
		return lbl + " " + strings.Repeat(".", dotsNeeded) + " "
	}

	var lines []string
	for _, r := range rows {
		selected := r.Field == selectedField
		value := r.Value
		if value == "" {
			value = "--"
		}
		labelText := kvDots(r.Label, labelW)

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
				cursorBlock := lipgloss.NewStyle().Foreground(ColorBg).Background(ColorCyan).Render(" ")
				if len(after) > 0 {
					cursorBlock = lipgloss.NewStyle().Foreground(ColorBg).Background(ColorCyan).Render(string(after[0]))
					after = after[1:]
				}
				editValue := selValue.Render(before) + cursorBlock + selValue.Render(after)
				row = cursorStyle.Render("> ") + selLabel.Render(r.Label+" ") + selDotStyle.Render(strings.Repeat(".", labelW-len(r.Label)-1)+" ") + editValue
			} else {
				row = cursorStyle.Render("> ") + selLabel.Render(r.Label+" ") + selDotStyle.Render(strings.Repeat(".", labelW-len(r.Label)-1)+" ") + selValue.Render(value)
			}
			lines = append(lines, selBg.Width(contentW).Render(row))
		} else {
			lines = append(lines, Bg().Render("  ")+normalLabel.Render(r.Label+" ")+dotStyle.Render(strings.Repeat(".", labelW-len(r.Label)-1)+" ")+normalValue.Render(value))
		}
		_ = labelText
	}
	content := strings.Join(lines, "\n")
	h := len(lines) + 2
	return RenderPanel(w, h, title, "", "", content)
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

// RenderReportPanel renders a bordered report/results panel with optional
// scroll indicator and status line.
func RenderReportPanel(opts ReportPanelOpts) string {
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

	panel := RenderPanel(w, h, opts.Title, opts.RightLabel, bottomRight, opts.Content)

	// Status line.
	if opts.StatusText != "" && time.Now().Before(opts.StatusUntil) {
		st := BodyText
		if opts.StatusError {
			st = StatusFail
		}
		panel += "\n" + st.Render("  "+opts.StatusText)
	}

	return panel
}

// ── RenderPanel ─────────────────────────────────────────────────────────────
// OverlayCenter renders a panel centered on the screen over the base view.
func OverlayCenter(base string, overlay string, screenW, screenH int) string {
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
		baseLines = append(baseLines, BgSp(screenW))
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
		leftPad := BgSp(startX)
		rightPad := ""
		rightRemaining := screenW - startX - olW
		if rightRemaining > 0 {
			rightPad = BgSp(rightRemaining)
		}
		baseLines[y] = leftPad + ol + rightPad
	}

	if len(baseLines) > screenH {
		baseLines = baseLines[:screenH]
	}
	return strings.Join(baseLines, "\n")
}

// RenderPanel builds a bordered panel that matches the tcell drawPanel look:
// titles are embedded in the top border line, and an optional bottom-right
// label is embedded in the bottom border line.
//
//	┌─ Title ──────────────────────── RightTitle ─┐
//	│ content                                      │
//	└──────────────────────────────────────── 2/6 ─┘
//
// It uses lipgloss PanelBorder for reliable side-border rendering, then
// replaces the auto-generated top/bottom border lines with custom ones
// that embed the title text.
func RenderPanel(w, h int, title, rightTitle, bottomRight, content string) string {
	if w < 6 {
		w = 6
	}
	if h < 3 {
		h = 3
	}

	// Let lipgloss render the full bordered panel (reliable side borders).
	bordered := PanelBorder.Width(w - 2).Height(h - 2).Render(content)
	lines := strings.Split(bordered, "\n")

	frameStyle := lipgloss.NewStyle().Foreground(ColorFrame).Background(ColorBg)
	accentStyle := lipgloss.NewStyle().Foreground(ColorAccent).Bold(true).Background(ColorBg)
	labelStyle := lipgloss.NewStyle().Foreground(ColorMuted).Background(ColorBg)

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
			styled.WriteString(labelStyle.Render(label))
			styled.WriteString(frameStyle.Render("─"))
			used += fill + labelW + 1
		}
		remaining := topInner - used
		if remaining > 0 {
			styled.WriteString(frameStyle.Render(strings.Repeat("─", remaining)))
		}
		lines[0] = frameStyle.Render("┌") + styled.String() + frameStyle.Render("┐")
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
		lines[len(lines)-1] = frameStyle.Render("└"+strings.Repeat("─", fill)) +
			labelStyle.Render(label) +
			frameStyle.Render("─┘")
	}

	return strings.Join(lines, "\n")
}

// RenderAccentReportPanel is a variant of RenderReportPanel whose
// border is rendered in ColorAccent (orange) instead of ColorFrame
// (gray). Used by the PCAP analyzer + Model dashboard sub-boxes so
// their bordered sections match the Inspector's accent style. Same
// option struct as RenderReportPanel — supports right title, status
// line, and bottom-right scroll indicator.
func RenderAccentReportPanel(opts ReportPanelOpts) string {
	w := opts.Width
	if w <= 0 {
		w = 80
	}
	h := opts.Height
	if h < 4 {
		h = 4
	}

	bottomRight := ""
	if opts.ScrollTotal > opts.ScrollVisible && opts.ScrollVisible > 0 {
		bottomRight = fmt.Sprintf("%d-%d of %d", opts.ScrollTop, opts.ScrollBottom, opts.ScrollTotal)
	}

	panel := renderAccentPanelWithLabels(w, h, opts.Title, opts.RightLabel, bottomRight, opts.Content)

	if opts.StatusText != "" && time.Now().Before(opts.StatusUntil) {
		st := BodyText
		if opts.StatusError {
			st = StatusFail
		}
		panel += "\n" + st.Render("  "+opts.StatusText)
	}
	return panel
}

// renderAccentPanelWithLabels is the inner builder used by
// RenderAccentReportPanel and RenderAccentPanel. Returns a panel with
// accent-colored borders and the supplied labels embedded in the top
// border (left=title, right=rightTitle) and bottom border (right=bottomRight).
func renderAccentPanelWithLabels(w, h int, title, rightTitle, bottomRight, content string) string {
	if w < 6 {
		w = 6
	}
	if h < 3 {
		h = 3
	}

	accentBorder := lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(ColorFrame).
		BorderBackground(ColorBg).
		Background(ColorBg)

	bordered := accentBorder.Width(w - 2).Height(h - 2).Render(content)
	lines := strings.Split(bordered, "\n")

	frameStyle := lipgloss.NewStyle().Foreground(ColorFrame).Background(ColorBg)
	titleStyle := lipgloss.NewStyle().Foreground(ColorAccent).Bold(true).Background(ColorBg)
	rightStyle := lipgloss.NewStyle().Foreground(ColorMuted).Background(ColorBg)

	if len(lines) > 0 && (title != "" || rightTitle != "") {
		topInner := w - 2
		var styled strings.Builder
		used := 0
		if title != "" {
			label := " " + title + " "
			labelW := lipgloss.Width(label)
			styled.WriteString(frameStyle.Render("─"))
			styled.WriteString(titleStyle.Render(label))
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
			styled.WriteString(rightStyle.Render(label))
			styled.WriteString(frameStyle.Render("─"))
			used += fill + labelW + 1
		}
		remaining := topInner - used
		if remaining > 0 {
			styled.WriteString(frameStyle.Render(strings.Repeat("─", remaining)))
		}
		lines[0] = frameStyle.Render("┌") + styled.String() + frameStyle.Render("┐")
	}

	if bottomRight != "" && len(lines) > 1 {
		botInner := w - 2
		label := " " + bottomRight + " "
		labelW := lipgloss.Width(label)
		fill := botInner - 1 - labelW
		if fill < 0 {
			fill = 0
		}
		lines[len(lines)-1] = frameStyle.Render("└"+strings.Repeat("─", fill)) +
			rightStyle.Render(label) +
			frameStyle.Render("─┘")
	}

	return strings.Join(lines, "\n")
}

// RenderAccentPanel renders a bordered panel with orange (accent) borders
// and a title embedded in the top border.  Used for contour sub-panels
// (MATRIX, SERVICES, ROUTES, ENDPOINTS, MISC).
func RenderAccentPanel(w, h int, title, content string) string {
	if w < 6 {
		w = 6
	}
	_ = h // height is auto-sized from content to avoid truncating wrapped lines

	accentBorder := lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(ColorFrame).
		BorderBackground(ColorBg).
		Background(ColorBg)

	bordered := accentBorder.Width(w - 2).Render(content)
	lines := strings.Split(bordered, "\n")

	frameStyle := lipgloss.NewStyle().Foreground(ColorFrame).Background(ColorBg)
	localTitleStyle := lipgloss.NewStyle().Foreground(ColorAccent).Bold(true).Background(ColorBg)

	if len(lines) > 0 && title != "" {
		topInner := w - 2
		label := " " + title + " "
		labelW := lipgloss.Width(label)
		var styled strings.Builder
		styled.WriteString(frameStyle.Render("─"))
		styled.WriteString(localTitleStyle.Render(label))
		remaining := topInner - 1 - labelW
		if remaining > 0 {
			styled.WriteString(frameStyle.Render(strings.Repeat("─", remaining)))
		}
		lines[0] = frameStyle.Render("┌") + styled.String() + frameStyle.Render("┐")
	}

	return strings.Join(lines, "\n")
}

// ── RenderMenuPanel ──────────────────────────────────────────────────────────

// RenderMenuPanel renders a centered, auto-sized menu overlay.
func RenderMenuPanel(title string, options []string, selected int, footer string, screenW int) string {
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

	selBg := lipgloss.NewStyle().Background(ColorSelect)
	// Cursor "> " uses ColorAccent — same accent used by the
	// process-view / host-view / pcap-findings cursors so every
	// selection bar across the app reads consistently.
	cursorStyle := lipgloss.NewStyle().Foreground(ColorAccent).Bold(true).Background(ColorSelect)
	selText := lipgloss.NewStyle().Foreground(ColorTextHi).Bold(true).Background(ColorSelect)

	var lines []string
	for i, opt := range options {
		if i == selected {
			row := cursorStyle.Render("> ") + selText.Render(opt)
			lines = append(lines, selBg.Width(panelW-2).Render(row))
		} else {
			lines = append(lines, DimText.Render("  ")+BodyText.Render(opt))
		}
	}
	content := strings.Join(lines, "\n")
	if footer != "" {
		content += "\n" + DimText.Render("  "+footer)
	}

	h := len(lines) + 2
	if footer != "" {
		h++
	}
	panel := RenderPanel(panelW, h, title, "", "", content)

	// Center horizontally.
	return lipgloss.PlaceHorizontal(screenW, lipgloss.Center, panel)
}

// ── RenderHelpPanel ──────────────────────────────────────────────────────────

// HelpSection groups a section header with its key-description entries.
type HelpSection struct {
	Title   string
	Entries []HelpEntry
}

type HelpEntry struct {
	Key  string
	Desc string
}

// ParseHelpSections groups flat options into sections.
func ParseHelpSections(options []string) []HelpSection {
	var sections []HelpSection
	var cur *HelpSection
	for _, opt := range options {
		if opt == "" {
			continue
		}
		if len(opt) > 2 && opt[0] == '[' && opt[len(opt)-1] == ']' {
			sections = append(sections, HelpSection{Title: opt[1 : len(opt)-1]})
			cur = &sections[len(sections)-1]
			continue
		}
		if cur == nil {
			sections = append(sections, HelpSection{})
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
		cur.Entries = append(cur.Entries, HelpEntry{key, desc})
	}
	return sections
}

// RenderHelpPanel renders a styled two-column help overlay.
func RenderHelpPanel(title string, options []string, w int) string {
	if w <= 0 {
		w = 80
	}

	navKeyStyle := lipgloss.NewStyle().Foreground(ColorText).Bold(true)
	workflowKeyStyle := lipgloss.NewStyle().Foreground(ColorCyan).Bold(true)
	actionKeyStyle := lipgloss.NewStyle().Foreground(ColorWarn).Bold(true)
	descStyle := lipgloss.NewStyle().Foreground(ColorDim)
	sectionStyle := lipgloss.NewStyle().Foreground(ColorAccent).Bold(true)

	sections := ParseHelpSections(options)

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
	var leftSections, rightSections []HelpSection
	for _, s := range sections {
		switch strings.ToLower(s.Title) {
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

	renderColumn := func(secs []HelpSection, colWidth int) []string {
		var lines []string
		for i, sec := range secs {
			if i > 0 {
				lines = append(lines, "")
			}
			lines = append(lines, sectionStyle.Render(sec.Title))
			ks := keyStyleFor(sec.Title)
			for _, e := range sec.Entries {
				kw := min(keyColW, colWidth/2)
				if e.Desc != "" {
					lines = append(lines, ks.Render(fmt.Sprintf(" %-*s", kw, e.Key))+descStyle.Render(e.Desc))
				} else {
					lines = append(lines, descStyle.Render(" "+e.Key))
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
		merged = append(merged, left+BgSp(pad)+BgSp(gap)+right)
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
	return RenderPanel(panelW, h, title, "? close", "", content)
}
