package common

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Tables: no box borders. A bold header row sits above a thin underline rule,
// and rows are plain monospace columns. Colour is reserved for threat severity
// (see SeverityStyle / SeverityForScore); the table chrome stays neutral gray.

// TableGutter is the spacing rendered between adjacent columns.
const TableGutter = 2

// Col describes one column of a table.
type Col struct {
	Title string // header label
	Width int    // fixed column width in cells
	Right bool   // right-align the cell content (numbers)
}

// PadCell clips s to w and pads it to exactly w cells, honouring alignment.
func PadCell(s string, w int, right bool) string {
	if w <= 0 {
		return ""
	}
	s = ClipToWidth(s, w)
	gap := w - lipgloss.Width(s)
	if gap < 0 {
		gap = 0
	}
	if right {
		return strings.Repeat(" ", gap) + s
	}
	return s + strings.Repeat(" ", gap)
}

// gutter renders the inter-column spacing on the panel background.
func gutter() string { return BgSp(TableGutter) }

// RitaHeader renders the header row and its underline rule as two lines:
//
//	SCORE   SOURCE        CONNS  DURATION  VERDICT
//	─────   ──────        ─────  ────────  ───────
//
// The header is bold near-white; the rule is neutral gray.
func RitaHeader(cols []Col) string {
	headStyle := lipgloss.NewStyle().Foreground(ColorTextHi).Bold(true).Background(ColorBg)
	ruleStyle := lipgloss.NewStyle().Foreground(ColorFrame).Background(ColorBg)

	var head, rule strings.Builder
	for i, c := range cols {
		if i > 0 {
			head.WriteString(gutter())
			rule.WriteString(gutter())
		}
		head.WriteString(headStyle.Render(PadCell(c.Title, c.Width, c.Right)))
		rule.WriteString(ruleStyle.Render(strings.Repeat("─", c.Width)))
	}
	return head.String() + "\n" + rule.String()
}

// RitaRow renders one data row. cells are aligned/padded per the column
// spec. styles[i], when non-nil, styles cell i (used to colour a severity
// cell); a nil entry falls back to BodyText so the rest of the row stays
// neutral.
func RitaRow(cols []Col, cells []string, styles []*lipgloss.Style) string {
	var b strings.Builder
	for i, c := range cols {
		if i > 0 {
			b.WriteString(gutter())
		}
		txt := ""
		if i < len(cells) {
			txt = cells[i]
		}
		st := BodyText
		if i < len(styles) && styles[i] != nil {
			st = *styles[i]
		}
		b.WriteString(st.Render(PadCell(txt, c.Width, c.Right)))
	}
	return b.String()
}

// ── Severity colouring ───────────────────────────────────────────────────────
// The only place colour is meant to appear in the table UI.

// SeverityStyle maps a verdict/severity keyword to its colour. Recognised:
// high/alert/critical/c2/malicious → red; watch/warn/suspicious/elevated →
// yellow; ok/pass/safe/benign/clean → green. Anything else → neutral body.
func SeverityStyle(kind string) lipgloss.Style {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "high", "alert", "critical", "crit", "c2", "malicious", "bad", "fail":
		return lipgloss.NewStyle().Foreground(ColorAlert).Bold(true).Background(ColorBg)
	case "elevated", "amber":
		return lipgloss.NewStyle().Foreground(ColorOrange).Bold(true).Background(ColorBg)
	case "watch", "warn", "warning", "suspicious", "medium", "mixed":
		return lipgloss.NewStyle().Foreground(ColorWarn).Bold(true).Background(ColorBg)
	case "ok", "pass", "safe", "benign", "clean", "low", "good":
		return lipgloss.NewStyle().Foreground(ColorCyan).Background(ColorBg)
	default:
		return BodyText
	}
}

// SeverityForScore colours a 0.0–1.0 threat score: ≥0.75 red, ≥0.50 yellow,
// otherwise green. Higher = more threatening.
func SeverityForScore(score float64) lipgloss.Style {
	switch {
	case score >= 0.75:
		return SeverityStyle("high")
	case score >= 0.50:
		return SeverityStyle("watch")
	default:
		return SeverityStyle("ok")
	}
}

// ── Bordered table ───────────────────────────────────────────────────────────
// A full-grid boxed table: a gray frame with vertical rules between every
// column in every row, ┬/┼/┴ corner joints, and a rule beneath the header.
// Each column is rendered as " content " (one pad cell on each side), so a
// cell occupies Width+2 and columns are joined by "│".

// BorderedCell is one data cell. Style, when non-nil, overrides the neutral
// body style (used for the coloured severity cell). KeepBg keeps the cell's own
// background even on the selected row — used for the filled "pill" cell so the
// selection bar doesn't repaint it (and its side pads stay filled too).
type BorderedCell struct {
	Text   string
	Style  *lipgloss.Style
	KeepBg bool
}

func borderedFrame() lipgloss.Style {
	return lipgloss.NewStyle().Foreground(ColorFrame).Background(ColorBg)
}

func borderedBody(sel bool) lipgloss.Style {
	if sel {
		return lipgloss.NewStyle().Foreground(ColorTextHi).Bold(true).Background(ColorSelect)
	}
	return lipgloss.NewStyle().Foreground(ColorText).Background(ColorBg)
}

// RenderBorderedTable renders the header + data rows as a full grid.
// selected is the row index (into rows) to highlight, or -1 for none.
func RenderBorderedTable(w int, cols []Col, rows [][]BorderedCell, selected int) string {
	_ = w // width is defined by the (already-sized) column widths
	frame := borderedFrame()

	// A border line: left + "─"*(colW+2) joined by mid, closed by right.
	border := func(left, mid, right string) string {
		var b strings.Builder
		b.WriteString(left)
		for i, c := range cols {
			if i > 0 {
				b.WriteString(mid)
			}
			b.WriteString(strings.Repeat("─", c.Width+2))
		}
		b.WriteString(right)
		return frame.Render(b.String())
	}

	hdrStyle := lipgloss.NewStyle().Foreground(ColorTextHi).Bold(true).Background(ColorBg)
	headerCells := make([]BorderedCell, len(cols))
	for i, c := range cols {
		s := hdrStyle
		headerCells[i] = BorderedCell{Text: c.Title, Style: &s}
	}

	var b strings.Builder
	b.WriteString(border("┌", "┬", "┐") + "\n")
	b.WriteString(borderedLine(cols, headerCells, frame, false) + "\n")
	b.WriteString(border("├", "┼", "┤") + "\n")
	for idx, row := range rows {
		b.WriteString(borderedLine(cols, row, frame, idx == selected) + "\n")
	}
	b.WriteString(border("└", "┴", "┘"))
	return b.String()
}

// borderedLine renders one grid row: "│ cell │ cell │ … │".
func borderedLine(cols []Col, cells []BorderedCell, frame lipgloss.Style, sel bool) string {
	rowBg := Bg()
	if sel {
		rowBg = lipgloss.NewStyle().Background(ColorSelect)
	}
	var b strings.Builder
	b.WriteString(frame.Render("│"))
	for i, c := range cols {
		var cell BorderedCell
		if i < len(cells) {
			cell = cells[i]
		}
		st := borderedBody(sel)
		pad := rowBg
		if cell.Style != nil {
			st = *cell.Style
			if cell.KeepBg {
				// Filled pill: side pads share the cell's own background.
				pad = lipgloss.NewStyle().Background(cell.Style.GetBackground())
			} else if sel {
				st = st.Background(ColorSelect)
			}
		}
		b.WriteString(pad.Render(" "))
		b.WriteString(st.Render(PadCell(cell.Text, c.Width, c.Right)))
		b.WriteString(pad.Render(" "))
		b.WriteString(frame.Render("│"))
	}
	return b.String()
}

// BorderedChrome returns the fixed horizontal overhead of a full-grid table for
// nCols columns: one "│" per column plus the closing "│" (nCols+1), and one
// pad cell on each side of every column (2*nCols). Callers size flex columns
// against w - chrome so the whole grid fits the terminal.
func BorderedChrome(nCols int) int {
	if nCols < 1 {
		return 2
	}
	return (nCols + 1) + 2*nCols
}
