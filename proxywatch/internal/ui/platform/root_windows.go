//go:build windows

package platform

import "strings"

// padViewToTerminal fills the terminal with the app background on Windows.
// Uses ANSI reset replacement instead of lipgloss.Place to avoid adding
// extra lines that confuse bubbletea's view diff on Windows consoles.
func PadViewToTerminal(view string, w, h int) string {
	if h <= 0 || w <= 0 {
		return view
	}

	// Replace bare ANSI resets with reset + background color (#1E1E1E)
	// so gaps between styled spans show dark grey instead of black.
	view = strings.ReplaceAll(view, "\033[0m", "\033[0m\033[48;2;30;30;30m")

	lines := strings.Split(view, "\n")
	if len(lines) > h {
		lines = lines[:h]
	}
	for len(lines) < h {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}
