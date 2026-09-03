package common

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Full-width bars. The top bar carries identity/status (view, host, record
// count, sort, clock); the key bar carries the persistent keybinding hints
// along the bottom. Both render on a slightly-raised gray background so they
// read as application chrome, distinct from the table.

var barBg = lipgloss.Color("#2A2A2A")

var (
	barText = lipgloss.NewStyle().Foreground(ColorTextHi).Background(barBg)
	barDim  = lipgloss.NewStyle().Foreground(ColorMuted).Background(barBg)
)

// renderBar lays out left- and right-aligned text on a single full-width
// bar, filling the middle with the bar background.
func renderBar(left, right string, w int, leftStyle, rightStyle lipgloss.Style) string {
	if w < 4 {
		w = 4
	}
	// Reserve one leading + one trailing space.
	inner := w - 2
	// Always keep at least this many spaces between the two segments so they
	// never visually collide on narrow terminals.
	const minGap = 3
	lw := lipgloss.Width(left)
	rw := lipgloss.Width(right)
	if lw+rw > inner-minGap {
		// Trim the left segment first; trim the right if still too wide.
		left = ClipToWidth(left, max(0, inner-minGap-rw))
		lw = lipgloss.Width(left)
		if lw+rw > inner-minGap {
			right = ClipToWidth(right, max(0, inner-minGap-lw))
			rw = lipgloss.Width(right)
		}
	}
	fill := inner - lw - rw
	if fill < 0 {
		fill = 0
	}
	return leftStyle.Render(" "+left) +
		rightStyle.Render(strings.Repeat(" ", fill)) +
		rightStyle.Render(right+" ")
}

// RenderTopBar renders the identity/status bar: bright left text, muted
// right text.
func RenderTopBar(left, right string, w int) string {
	return renderBar(left, right, w, barText, barDim)
}

// RenderKeyBar renders the bottom keybinding hint bar (all muted).
func RenderKeyBar(left, right string, w int) string {
	return renderBar(left, right, w, barDim, barDim)
}
