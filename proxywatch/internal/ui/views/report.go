package views

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"proxywatch/internal/contour"
)

func renderFinishedReport(report *contour.Report, width int) string {
	if report == nil {
		return ""
	}
	if width <= 0 {
		width = 70
	}
	var sections []string

	if report.Probe == nil || !report.Probe.Enabled {
		if p := strings.TrimSpace(report.OutputPath); p != "" {
			sections = append(sections, mutedText.Render("  output  "+p))
		}
		return joinSections(sections)
	}

	probe := report.Probe

	tunnelExfil := renderTunnelExfilMatrix(probe, width)
	gridW := width
	if tunnelExfil != "" {
		sections = append(sections, tunnelExfil)
		if w := lipgloss.Width(tunnelExfil); w > 0 {
			gridW = w
		}
	}

	grid := renderContourGrid(probe, gridW)
	if grid != "" {
		sections = append(sections, grid)
	}

	{
		var info []string
		if probe.TLSIntercepted {
			info = append(info, "TLS intercepted ("+probe.TLSInterceptOrg+")")
		}
		if probe.AvgLatencyMs > 0 {
			info = append(info, fmt.Sprintf("latency ~%dms", probe.AvgLatencyMs))
		}
		if len(info) > 0 {
			sections = append(sections, dimText.Render("  "+strings.Join(info, "  |  ")))
		}
	}

	if p := strings.TrimSpace(report.OutputPath); p != "" {
		sections = append(sections, mutedText.Render("  output  "+p))
	}

	return joinSections(sections)
}

func joinSections(sections []string) string {
	return strings.Join(sections, "\n\n")
}
