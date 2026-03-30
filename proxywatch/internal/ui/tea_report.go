package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"proxywatch/internal/contour"
	"proxywatch/internal/shared"
)

// renderContourReport produces lipgloss-styled report content from a contour
// Report. Returns a single string suitable for a bubbletea viewport.
func renderContourReport(report contour.Report, width int) string {
	if width <= 0 {
		width = 80
	}
	contentW := width - 4 // padding inside panel

	var sections []string

	// ── Findings ────────────────────────────────────────────────
	if len(report.Findings) > 0 {
		var rows []string
		shown := 0
		for _, f := range report.Findings {
			if shown >= 6 {
				rows = append(rows, dimText.Render(fmt.Sprintf("  +%d more", len(report.Findings)-shown)))
				break
			}
			sev := strings.ToUpper(shared.NormalizeContourSeverity(f.Severity))
			tag := reportSevTagStyled(sev)
			reason := truncate(f.Reason, contentW-10)
			rows = append(rows, fmt.Sprintf("  %s  %s", tag, bodyText.Render(reason)))
			shown++
		}
		sections = append(sections, strings.Join(rows, "\n"))
	}

	if report.Probe == nil || !report.Probe.Enabled {
		if p := strings.TrimSpace(report.OutputPath); p != "" {
			sections = append(sections, mutedText.Render("  output  "+p))
		}
		return joinSections(sections)
	}

	probe := report.Probe

	// ── Network / Probe overview ────────────────────────────────
	{
		target := nonEmptyStr(strings.TrimSpace(probe.Endpoint), "-")
		mode := contour.ProbeModeLabel(probe.Mode)

		portsOpen := 0
		for _, pr := range probe.PortResults {
			if pr.TunnelSuccess > 0 {
				portsOpen++
			}
		}
		totalPorts := len(probe.Ports)
		if totalPorts == 0 {
			totalPorts = 100 // default probe port count
		}

		var kv []string
		kv = append(kv, kvLine("target", target))
		kv = append(kv, kvLine("mode", mode))
		kv = append(kv, kvLine("ports", fmt.Sprintf("%d open / %d tested", portsOpen, totalPorts)))
		if len(probe.InternalRoutes) > 0 || len(probe.InternetSubnets) > 0 {
			kv = append(kv, kvLine("routes", fmt.Sprintf("%d internal, %d internet", len(probe.InternalRoutes), len(probe.InternetSubnets))))
		}
		if probe.AvgLatencyMs > 0 {
			kv = append(kv, kvLine("latency", fmt.Sprintf("~%dms", probe.AvgLatencyMs)))
		}
		if probe.TLSIntercepted {
			kv = append(kv, kvLine("tls", fmt.Sprintf("intercepted (%s)", probe.TLSInterceptOrg)))
		}
		sections = append(sections, strings.Join(kv, "\n"))
	}

	// ── Tunnels ─────────────────────────────────────────────────
	if probe.TunnelAttempts > 0 {
		var rows []string
		rows = append(rows, sectionLabel.Render("  tunnels"))

		for _, m := range probe.MethodResults {
			if m.TunnelAttempts <= 0 {
				continue
			}
			method := strings.ToLower(strings.TrimSpace(m.Method))
			if !contour.IsCarrierTunnelMethod(method) {
				continue
			}
			status := contour.ProbeStatusLabel(m.TunnelSuccess, m.TunnelAttempts)
			label := formatMethodStatus(m.Method, status, m.TunnelSuccess, m.TunnelAttempts)
			rows = append(rows, label)
		}
		if probe.DomainFrontingPossible {
			rows = append(rows, bodyText.Render(fmt.Sprintf("    domain fronting via %s", probe.DomainFrontingSNI)))
		}
		if len(rows) > 1 {
			sections = append(sections, strings.Join(rows, "\n"))
		}
	}

	// ── Exfiltration ────────────────────────────────────────────
	if probe.ExfilAttempts > 0 {
		var pass, partial []string
		fail := 0
		for _, m := range probe.MethodResults {
			if m.ExfilAttempts <= 0 {
				continue
			}
			status := contour.ProbeStatusLabel(m.ExfilSuccess, m.ExfilAttempts)
			switch status {
			case "PASS":
				pass = append(pass, m.Method)
			case "MIXED":
				partial = append(partial, fmt.Sprintf("%s %d/%d", m.Method, m.ExfilSuccess, m.ExfilAttempts))
			default:
				fail++
			}
		}
		if len(pass) > 0 || len(partial) > 0 || probe.DNSExfilViable {
			var rows []string
			rows = append(rows, sectionLabel.Render("  exfil"))
			if len(pass) > 0 {
				rows = append(rows, bodyText.Render("    pass  "+wrapItems(pass, contentW-10)))
			}
			if len(partial) > 0 {
				rows = append(rows, statusMixed.Render("    part  "+wrapItems(partial, contentW-10)))
			}
			if fail > 0 {
				rows = append(rows, statusFail.Render(fmt.Sprintf("    fail  %d protocols blocked", fail)))
			}
			if probe.DNSExfilViable {
				rows = append(rows, bodyText.Render("    DNS TXT to external resolvers"))
			}
			sections = append(sections, strings.Join(rows, "\n"))
		}
	}

	// ── Proxies ─────────────────────────────────────────────────
	if len(probe.Proxies) > 0 {
		var rows []string
		rows = append(rows, sectionLabel.Render(fmt.Sprintf("  proxies  %d found, %d reachable", len(probe.Proxies), probe.ReachableProxyCount)))
		for _, ep := range probe.Proxies {
			host := strings.TrimSpace(ep.Host)
			if host == "" {
				continue
			}
			addr := fmt.Sprintf("%s:%d", host, ep.Port)
			if ep.PivotReachable {
				target := nonEmptyStr(strings.TrimSpace(ep.PivotTarget), "internal")
				rows = append(rows, statusPivot.Render(fmt.Sprintf("    %s  pivot -> %s", addr, target)))
			} else if ep.Reachable {
				tried := strings.TrimSpace(ep.ProxyTried)
				if tried != "" {
					rows = append(rows, bodyText.Render(fmt.Sprintf("    %s  %s", addr, tried)))
				} else {
					rows = append(rows, bodyText.Render(fmt.Sprintf("    %s", addr)))
				}
			}
		}
		sections = append(sections, strings.Join(rows, "\n"))
	}

	// ── Services ────────────────────────────────────────────────
	if len(probe.ServiceReachable) > 0 || len(probe.ServiceBlocked) > 0 {
		var rows []string
		rows = append(rows, sectionLabel.Render("  services"))
		if len(probe.ServiceReachable) > 0 {
			rows = append(rows, bodyText.Render("    reach  "+wrapItems(probe.ServiceReachable, contentW-12)))
		}
		if len(probe.ServiceBlocked) > 0 {
			rows = append(rows, statusFail.Render("    block  "+wrapItems(probe.ServiceBlocked, contentW-12)))
		}
		sections = append(sections, strings.Join(rows, "\n"))
	}

	// ── Output path ─────────────────────────────────────────────
	if p := strings.TrimSpace(report.OutputPath); p != "" {
		sections = append(sections, mutedText.Render("  output  "+p))
	}

	return joinSections(sections)
}

// renderFinishedReport renders the completed report — sweep grid, tunnels,
// proxies, services. No findings list (those are in the scan task matrix).
func renderFinishedReport(report *contour.Report, width int) string {
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

	// ── Tunnels + Exfiltration matrix ────────────────────────────
	tunnelExfil := renderTunnelExfilMatrix(probe, width)
	if tunnelExfil != "" {
		sections = append(sections, tunnelExfil)
	}

	// ── Services matrix ─────────────────────────────────────────
	svcMatrix := renderServiceMatrix(probe)
	if svcMatrix != "" {
		sections = append(sections, svcMatrix)
	}

	// ── Info panel (routes, proxies, config, domain fronting, DNS) ──
	infoPanel := renderInfoPanels(probe)
	if infoPanel != "" {
		sections = append(sections, infoPanel)
	}

	// ── Info line ───────────────────────────────────────────────
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

	// ── Output path ─────────────────────────────────────────────
	if p := strings.TrimSpace(report.OutputPath); p != "" {
		sections = append(sections, mutedText.Render("  output  "+p))
	}

	return joinSections(sections)
}

// sectionHeader renders a section title with a subtle underline.
func sectionHeader(title string, width int) string {
	t := sectionLabel.Render("  " + title)
	lineW := width - 2
	if lineW < 4 {
		lineW = 4
	}
	line := dimText.Render("  " + strings.Repeat("─", lineW))
	return t + "\n" + line
}

// renderContourLiveProgress styles live progress lines during an active run.
func renderContourLiveProgress(lines []string) string {
	var styled []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "[-]"):
			styled = append(styled, statusFail.Render(line))
		case strings.HasPrefix(trimmed, "[*]"), strings.HasPrefix(trimmed, "[+]"):
			styled = append(styled, dimText.Render(line))
		default:
			styled = append(styled, bodyText.Render(line))
		}
	}
	return strings.Join(styled, "\n")
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func joinSections(sections []string) string {
	return strings.Join(sections, "\n\n")
}

func kvLine(key, value string) string {
	label := dimText.Render(fmt.Sprintf("  %-9s", key))
	val := bodyText.Render(value)
	return label + val
}

func reportSevTagStyled(sev string) string {
	tag := fmt.Sprintf("%-6s", sev)
	switch sev {
	case "ACTIVE":
		return sevActive.Render(tag)
	case "STRONG":
		return sevStrong.Render(tag)
	default:
		return sevWatch.Render(tag)
	}
}

func formatMethodStatus(method, status string, success, attempts int) string {
	name := fmt.Sprintf("    %-10s", method)
	switch status {
	case "PASS":
		return bodyText.Render(name) + statusPass.Render("pass")
	case "MIXED":
		return bodyText.Render(name) + statusMixed.Render(fmt.Sprintf("%d/%d", success, attempts))
	case "FAIL":
		return bodyText.Render(name) + statusFail.Render("fail")
	default:
		return bodyText.Render(name) + dimText.Render("-")
	}
}

func wrapItems(items []string, maxW int) string {
	if maxW <= 0 {
		maxW = 60
	}
	joined := strings.Join(items, ", ")
	if len(joined) <= maxW {
		return joined
	}
	// Simple word-wrap at comma boundaries.
	var lines []string
	line := ""
	for i, item := range items {
		add := item
		if i < len(items)-1 {
			add += ", "
		}
		if len(line)+len(add) > maxW && line != "" {
			lines = append(lines, line)
			line = "           " // indent continuation
		}
		line += add
	}
	if line != "" {
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func truncate(s string, maxLen int) string {
	if maxLen <= 0 || len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

func nonEmptyStr(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

// lipglossLineCount returns the number of visual lines in a lipgloss-rendered string.
func lipglossLineCount(s string) int {
	if s == "" {
		return 0
	}
	return strings.Count(s, "\n") + 1
}

// Ensure lipgloss import is used.
var _ = lipgloss.NewStyle
