//go:build linux

package platform

import "strings"

// padViewToTerminal clamps/pads the view to the terminal dimensions.
// On Linux the terminal background color is set via OSC escape, so
// empty lines are sufficient for padding.
func PadViewToTerminal(view string, w, h int) string {
	if h <= 0 {
		return view
	}
	lines := strings.Split(view, "\n")
	if len(lines) > h {
		lines = lines[:h]
	}
	for len(lines) < h {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}
