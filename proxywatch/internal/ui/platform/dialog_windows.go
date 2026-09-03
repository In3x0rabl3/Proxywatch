//go:build windows

package platform

import (
	"os/exec"
	"strings"
)

// OpenFileDialog opens a native file picker dialog and returns the selected path.
// Returns empty string if cancelled or unavailable.
// Uses PowerShell's OpenFileDialog on Windows.
func OpenFileDialog(title string, startDir string, filters ...string) string {
	// Build PowerShell script for file dialog
	script := `
Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.OpenFileDialog
$dialog.Title = "` + title + `"
`
	if startDir != "" {
		script += `$dialog.InitialDirectory = "` + strings.ReplaceAll(startDir, `"`, `\"`) + `"` + "\n"
	}

	// Convert filters to Windows format: "PCAP files (*.pcap;*.pcapng)|*.pcap;*.pcapng"
	if len(filters) > 0 {
		var winFilters []string
		for _, f := range filters {
			// Simple conversion: "*.pcap *.pcapng" -> "PCAP files|*.pcap;*.pcapng"
			parts := strings.Fields(f)
			if len(parts) > 0 {
				winFilters = append(winFilters, "Files|"+strings.Join(parts, ";"))
			}
		}
		if len(winFilters) > 0 {
			script += `$dialog.Filter = "` + strings.Join(winFilters, "|") + `"` + "\n"
		}
	}

	script += `
if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
    Write-Output $dialog.FileName
}
`
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	out, err := cmd.Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}
	return ""
}

// HasNativeDialog returns true if a native file dialog is available.
// Always true on Windows (PowerShell is built-in).
func HasNativeDialog() bool {
	return true
}
