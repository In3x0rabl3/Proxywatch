//go:build !windows

package platform

import (
	"os/exec"
	"strings"
)

// OpenFileDialog opens a native file picker dialog and returns the selected path.
// Returns empty string if cancelled or unavailable.
// Tries zenity first (GTK), then kdialog (KDE).
func OpenFileDialog(title string, startDir string, filters ...string) string {
	// Try zenity first (GTK/GNOME)
	if path, _ := exec.LookPath("zenity"); path != "" {
		args := []string{
			"--file-selection",
			"--title=" + title,
		}
		if startDir != "" {
			args = append(args, "--filename="+startDir+"/")
		}
		for _, f := range filters {
			args = append(args, "--file-filter="+f)
		}
		cmd := exec.Command("zenity", args...)
		out, err := cmd.Output()
		if err == nil {
			return strings.TrimSpace(string(out))
		}
		return ""
	}

	// Try kdialog (KDE)
	if path, _ := exec.LookPath("kdialog"); path != "" {
		args := []string{
			"--getopenfilename",
			startDir,
		}
		if len(filters) > 0 {
			args = append(args, strings.Join(filters, " "))
		}
		if title != "" {
			args = append(args, "--title", title)
		}
		cmd := exec.Command("kdialog", args...)
		out, err := cmd.Output()
		if err == nil {
			return strings.TrimSpace(string(out))
		}
		return ""
	}

	return ""
}

// HasNativeDialog returns true if a native file dialog is available.
func HasNativeDialog() bool {
	if path, _ := exec.LookPath("zenity"); path != "" {
		return true
	}
	if path, _ := exec.LookPath("kdialog"); path != "" {
		return true
	}
	return false
}
