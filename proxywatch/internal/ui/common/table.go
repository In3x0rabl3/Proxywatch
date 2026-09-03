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
