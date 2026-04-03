package views

import (
	"fmt"
	"strings"

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
	if tunnelExfil != "" {
		sections = append(sections, tunnelExfil)
	}

	svcMatrix := renderServiceMatrix(probe)
	if svcMatrix != "" {
		sections = append(sections, svcMatrix)
	}

	infoPanel := renderInfoPanels(probe, width)
	if infoPanel != "" {
		sections = append(sections, infoPanel)
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
