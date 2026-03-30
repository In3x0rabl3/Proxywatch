package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"proxywatch/internal/contour"
	"proxywatch/internal/shared"
)

// taskState tracks the status of a single probe task.
type taskState int

const (
	taskPending taskState = iota
	taskRunning
	taskPass
	taskFail
	taskSkipped
)

// probeTask defines one step in the probe workflow.
type probeTask struct {
	name    string   // display name
	starts  []string // substrings in progress lines that mark this task as running
	passes  []string // substrings that mark it as passed
	fails   []string // substrings that mark it as failed
}

// probeTasks is the ordered list of tasks for Quick and Deep scans.
// Quick-only tasks are always shown; Deep-only tasks appear only if matched.
var probeTasks = []probeTask{
	{
		name:   "Analyze samples",
		starts: []string{"Analyzing"},
		passes: []string{"candidate profiles"},
	},
	{
		name:   "Classify services",
		starts: []string{"Resolving external IPs"},
		passes: []string{"Classified"},
	},
	{
		name:   "Behavioral findings",
		starts: []string{"Building behavioral findings"},
		passes: []string{"behavioral findings generated"},
	},
	{
		name:   "Tunnel verification",
		starts: []string{"Verifying tunnels"},
		passes: []string{"Tunnel matrix:"},
	},
	{
		name:   "Exfiltration verification",
		starts: []string{"Verifying tunnels"},
		passes: []string{"Exfil matrix:"},
	},
	{
		name:   "Route discovery",
		starts: []string{"Discovering network routes"},
		passes: []string{"Routes:"},
	},
	{
		name:   "Proxy discovery",
		starts: []string{"Scanning environment for proxy", "Scanning config files"},
		passes: []string{"proxy candidates"},
	},
	{
		name:   "Proxy reachability",
		starts: []string{"Testing proxy reachability"},
		passes: []string{"Proxies:"},
	},
	{
		name:   "Endpoint verification",
		starts: []string{"Testing config endpoint reachability"},
		passes: []string{"Found endpoints:"},
	},
	{
		name:   "Endpoint pivot verification",
		starts: []string{"Testing config endpoints for pivot"},
		passes: []string{"Testing reachability of exfil", "Inspecting TLS"},
	},
	{
		name:   "Service reachability",
		starts: []string{"Testing reachability of exfil"},
		passes: []string{"services reachable", "services blocked"},
		fails:  []string{},
	},
	{
		name:   "TLS inspection",
		starts: []string{"Inspecting TLS certificates"},
		passes: []string{"No TLS interception", "TLS interception detected"},
	},
	{
		name:   "Domain fronting",
		starts: []string{"Testing domain fronting"},
		passes: []string{"Domain fronting possible"},
		fails:  []string{"Domain fronting not detected"},
	},
	{
		name:   "DNS exfil",
		starts: []string{"Testing DNS exfil"},
		passes: []string{"DNS exfil viable"},
		fails:  []string{"DNS exfil blocked"},
	},
	{
		name:   "HTTP methods",
		starts: []string{"Testing HTTP methods"},
		passes: []string{"HTTP methods allowed"},
		fails:  []string{"No HTTP methods accepted"},
	},
	{
		name:   "Building report",
		starts: []string{"Building report"},
		passes: []string{"Report complete"},
	},
}

// liveProgressModel tracks spinning state for live progress rendering.
type liveProgressModel struct {
	spinner spinner.Model
	active  bool
}

func newLiveProgressModel() liveProgressModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(colorCyan)
	return liveProgressModel{spinner: s}
}

func (m liveProgressModel) Update(msg tea.Msg) (liveProgressModel, tea.Cmd) {
	if !m.active {
		return m, nil
	}
	var cmd tea.Cmd
	m.spinner, cmd = m.spinner.Update(msg)
	return m, cmd
}

// renderTaskMatrix produces the styled task list and sweep matrix from progress.
func renderTaskMatrix(lines []string, spin spinner.Model, app *shared.AppState, width int) string {
	allText := strings.Join(lines, "\n")

	// Determine state of each task.
	type entry struct {
		name   string
		state  taskState
		detail string
	}
	var entries []entry

	for _, task := range probeTasks {
		st := taskPending

		for _, pat := range task.passes {
			if strings.Contains(allText, pat) {
				st = taskPass
				break
			}
		}
		if st != taskPass {
			for _, pat := range task.fails {
				if strings.Contains(allText, pat) {
					st = taskFail
					break
				}
			}
		}
		if st == taskPending {
			for _, pat := range task.starts {
				if strings.Contains(allText, pat) {
					st = taskRunning
					break
				}
			}
		}

		// Skip tasks that were never started.
		if st == taskPending {
			seen := false
			for _, pat := range task.starts {
				if strings.Contains(allText, pat) {
					seen = true
					break
				}
			}
			if !seen {
				continue
			}
		}

		detail := ""
		if st == taskPass || st == taskFail {
			detail = extractDetail(lines, task)
		}

		entries = append(entries, entry{name: task.name, state: st, detail: detail})
	}

	if len(entries) == 0 {
		return dimText.Render("  Starting...")
	}

	// Render task list.
	var rows []string
	for _, e := range entries {
		icon := renderTaskIcon(e.state, spin)
		name := bodyText.Render(e.name)
		if e.detail != "" {
			name += dimText.Render("  " + e.detail)
		}
		rows = append(rows, "  "+icon+" "+name)
	}
	out := strings.Join(rows, "\n")

	// Show matrices and detail sections as results arrive.
	if app != nil && app.ContourPartialProbe != nil {
		if probe, ok := app.ContourPartialProbe.(*contour.ProbeSummary); ok && probe != nil {
			tunnelExfil := renderTunnelExfilMatrix(probe, width)
			if tunnelExfil != "" {
				out += "\n\n" + tunnelExfil
			}
			svcMatrix := renderServiceMatrix(probe)
			if svcMatrix != "" {
				out += "\n\n" + svcMatrix
			}
			infoPanel := renderInfoPanels(probe)
			if infoPanel != "" {
				out += "\n\n" + infoPanel
			}
		}
	}

	return out
}

// renderTunnelExfilMatrix renders a combined tunnel + exfiltration matrix.
// Tunnel carriers (http, https, ws, wss, ssh) on top, all exfil protocols below,
// sharing the same port columns, inside one bordered box.
func renderTunnelExfilMatrix(probe *contour.ProbeSummary, width int) string {
	ports := probe.Ports
	if len(ports) == 0 || len(probe.Protocols) == 0 {
		return ""
	}

	// Build lookups: "kind:method:port" -> pass/fail/untested
	type checkState int
	const (
		checkUntested checkState = iota
		checkPass
		checkFail
	)
	checks := map[string]checkState{}
	for _, c := range probe.FailedChecks {
		key := strings.ToLower(strings.TrimSpace(c.Kind)) + ":" +
			strings.ToLower(strings.TrimSpace(c.Method)) + ":" +
			fmt.Sprintf("%d", c.Port)
		checks[key] = checkFail
	}
	for _, c := range probe.SuccessfulChecks {
		key := strings.ToLower(strings.TrimSpace(c.Kind)) + ":" +
			strings.ToLower(strings.TrimSpace(c.Method)) + ":" +
			fmt.Sprintf("%d", c.Port)
		checks[key] = checkPass
	}
	// Keep old results map for counting.
	results := map[string]bool{}
	for k, v := range checks {
		if v == checkPass {
			results[k] = true
		}
	}

	// Tunnel carrier protocols and all exfil protocols.
	var tunnelProtos, exfilProtos []string
	seenT, seenE := map[string]bool{}, map[string]bool{}
	if len(probe.MethodResults) > 0 {
		for _, mr := range probe.MethodResults {
			m := strings.ToLower(strings.TrimSpace(mr.Method))
			if mr.TunnelAttempts > 0 && contour.IsCarrierTunnelMethod(m) && !seenT[m] {
				tunnelProtos = append(tunnelProtos, m)
				seenT[m] = true
			}
			if mr.ExfilAttempts > 0 && !seenE[m] {
				exfilProtos = append(exfilProtos, m)
				seenE[m] = true
			}
		}
	} else {
		// Before results arrive, derive from the protocol list.
		for _, p := range probe.Protocols {
			m := strings.ToLower(strings.TrimSpace(p))
			if contour.IsCarrierTunnelMethod(m) && !seenT[m] {
				tunnelProtos = append(tunnelProtos, m)
				seenT[m] = true
			} else if !seenE[m] {
				exfilProtos = append(exfilProtos, m)
				seenE[m] = true
			}
		}
	}

	if len(tunnelProtos) == 0 && len(exfilProtos) == 0 {
		return ""
	}

	const colW = 6
	const protoW = 10
	passMark := statusPass.Render("✓")
	failMark := statusFail.Render("✗")
	untestedMark := statusFail.Render("·")
	sep := " "

	centerCol := func(s string, w int) string {
		n := lipgloss.Width(s)
		if n >= w {
			return s
		}
		left := (w - n) / 2
		right := w - n - left
		return strings.Repeat(" ", left) + s + strings.Repeat(" ", right)
	}

	innerW := protoW + 1 + colW*len(ports)
	divider := dimText.Render(strings.Repeat("─", innerW))

	var matrixRows []string

	// Port header with PROTOCOLS label in the protocol-name column.
	var hdr strings.Builder
	hdr.WriteString(sectionLabel.Render(fmt.Sprintf("%-*s", protoW, "PROTOCOLS")))
	hdr.WriteString(sep)
	for _, port := range ports {
		hdr.WriteString(dimText.Render(centerCol(fmt.Sprintf("%d", port), colW)))
	}
	matrixRows = append(matrixRows, hdr.String())
	matrixRows = append(matrixRows, divider)

	// renderRow builds a matrix row with three-state marks.
	renderRow := func(kind, proto string) string {
		var row strings.Builder
		row.WriteString(bodyText.Render(fmt.Sprintf("%-*s", protoW, proto)))
		row.WriteString(sep)
		for _, port := range ports {
			key := kind + ":" + proto + ":" + fmt.Sprintf("%d", port)
			switch checks[key] {
			case checkPass:
				row.WriteString(centerCol(passMark, colW))
			case checkFail:
				row.WriteString(centerCol(failMark, colW))
			default:
				row.WriteString(centerCol(untestedMark, colW))
			}
		}
		return row.String()
	}

	// ── Tunnel section ──
	if len(tunnelProtos) > 0 {
		matrixRows = append(matrixRows, sectionLabel.Render("TUNNELS"))
		for _, proto := range tunnelProtos {
			matrixRows = append(matrixRows, renderRow("tunnel", proto))
		}
	}

	// ── Exfil section ──
	if len(exfilProtos) > 0 {
		matrixRows = append(matrixRows, divider)
		matrixRows = append(matrixRows, sectionLabel.Render("EXFILTRATION"))
		for _, proto := range exfilProtos {
			matrixRows = append(matrixRows, renderRow("exfil", proto))
		}
	}

	// Count successful checks.
	matrixReach := len(results)
	matrixTotal := (len(tunnelProtos) + len(exfilProtos)) * len(ports)
	matrixRows = append(matrixRows, divider)
	matrixRows = append(matrixRows, dimText.Render(fmt.Sprintf("%d/%d reachable", matrixReach, matrixTotal)))

	// Wrap in orange border with MATRIX title.
	matrixContent := strings.Join(matrixRows, "\n")
	h := len(matrixRows) + 2
	contentW := 0
	for _, row := range matrixRows {
		if w := lipgloss.Width(row); w > contentW {
			contentW = w
		}
	}
	w := contentW + 4
	return renderAccentPanel(w, h, "MATRIX", matrixContent)
}

// renderInfoPanels renders three side-by-side bordered boxes:
// Left: routes. Center: proxies + config endpoints. Right: TLS/DNS/HTTP checks.
func renderInfoPanels(probe *contour.ProbeSummary) string {
	if probe == nil {
		return ""
	}

	// ── Box 1: Routes ──
	var routesBox []string
	if len(probe.InternalRoutes) > 0 || len(probe.InternetSubnets) > 0 {
		routesBox = append(routesBox, sectionLabel.Render(fmt.Sprintf("ROUTES  %d internal, %d external", len(probe.InternalRoutes), len(probe.InternetSubnets))))
		for _, r := range probe.InternetSubnets {
			routesBox = append(routesBox, bodyText.Render("  "+r))
		}
		for _, r := range probe.InternalRoutes {
			routesBox = append(routesBox, dimText.Render("  "+r))
		}
	}

	// ── Box 2: Proxies + Config Endpoints ──
	var proxiesBox []string
	if len(probe.Proxies) > 0 {
		proxiesBox = append(proxiesBox, sectionLabel.Render(fmt.Sprintf("PROXIES  %d found, %d reachable", len(probe.Proxies), probe.ReachableProxyCount)))
		for _, ep := range probe.Proxies {
			host := strings.TrimSpace(ep.Host)
			if host == "" {
				continue
			}
			addr := fmt.Sprintf("%s:%d", host, ep.Port)
			if ep.PivotReachable {
				target := strings.TrimSpace(ep.PivotTarget)
				if target == "" {
					target = "internal"
				}
				proxiesBox = append(proxiesBox, statusPass.Render(fmt.Sprintf("  ✓ %s → %s", addr, target)))
			} else if ep.Reachable {
				proxiesBox = append(proxiesBox, bodyText.Render(fmt.Sprintf("  ✓ %s", addr)))
			}
		}
		if probe.PivotProxyCount > 0 && probe.ProxyPivotTarget != "" {
			proxiesBox = append(proxiesBox, dimText.Render(fmt.Sprintf("  %d can pivot to %s", probe.PivotProxyCount, probe.ProxyPivotTarget)))
		}
	}
	if probe.ReachableConfigCount > 0 {
		if len(proxiesBox) > 0 {
			proxiesBox = append(proxiesBox, "")
		}
		total := len(probe.ConfigEndpoints)
		proxiesBox = append(proxiesBox, sectionLabel.Render(fmt.Sprintf("CONFIG ENDPOINTS  %d reachable of %d", probe.ReachableConfigCount, total)))
		shown := 0
		for _, ep := range probe.ConfigEndpoints {
			if !ep.Reachable {
				continue
			}
			if shown >= 10 {
				proxiesBox = append(proxiesBox, dimText.Render(fmt.Sprintf("  +%d more", probe.ReachableConfigCount-shown)))
				break
			}
			addr := strings.TrimSpace(ep.Endpoint)
			if addr == "" {
				addr = fmt.Sprintf("%s:%d", ep.Host, ep.Port)
			}
			if ep.PivotReachable {
				proxiesBox = append(proxiesBox, statusPass.Render(fmt.Sprintf("  ✓ %s → %s", addr, ep.PivotTarget)))
			} else {
				proxiesBox = append(proxiesBox, bodyText.Render(fmt.Sprintf("  ✓ %s", addr)))
			}
			shown++
		}
	}

	// ── Box 3: TLS + DNS Exfil + HTTP Methods ──
	var checksBox []string
	checksBox = append(checksBox, sectionLabel.Render("TLS INSPECTION"))
	if probe.TLSIntercepted {
		checksBox = append(checksBox, statusFail.Render(fmt.Sprintf("  Intercepted by: %s", probe.TLSInterceptOrg)))
		checksBox = append(checksBox, dimText.Render("  TLS is being re-signed by a proxy."))
	} else if probe.TLSChecked {
		checksBox = append(checksBox, statusPass.Render("  No interception detected"))
	} else {
		checksBox = append(checksBox, dimText.Render("  Scanning..."))
	}
	checksBox = append(checksBox, "")
	checksBox = append(checksBox, sectionLabel.Render("DOMAIN FRONTING"))
	if probe.DomainFrontingPossible {
		checksBox = append(checksBox, statusPass.Render(fmt.Sprintf("  SNI mismatch: %s", probe.DomainFrontingSNI)))
	} else if probe.TLSChecked {
		checksBox = append(checksBox, dimText.Render("  Not detected"))
	} else {
		checksBox = append(checksBox, dimText.Render("  Scanning..."))
	}
	checksBox = append(checksBox, "")
	checksBox = append(checksBox, sectionLabel.Render("DNS EXFILTRATION"))
	if probe.DNSExfilViable {
		checksBox = append(checksBox, statusPass.Render("  TXT queries reach external resolvers"))
		checksBox = append(checksBox, dimText.Render("  Data can be exfiltrated via DNS to attacker NS."))
	} else if probe.DNSExfilChecked {
		checksBox = append(checksBox, statusFail.Render("  Blocked — TXT queries to external resolver failed"))
	} else {
		checksBox = append(checksBox, dimText.Render("  Scanning..."))
	}
	checksBox = append(checksBox, "")
	checksBox = append(checksBox, sectionLabel.Render("HTTP METHODS"))
	if len(probe.HTTPMethodsAllowed) > 0 {
		checksBox = append(checksBox, statusPass.Render("  "+strings.Join(probe.HTTPMethodsAllowed, ", ")))
	} else if probe.HTTPMethodsChecked {
		checksBox = append(checksBox, statusFail.Render("  No methods accepted"))
	} else {
		checksBox = append(checksBox, dimText.Render("  Scanning..."))
	}

	// Always render all boxes — show "Scanning..." placeholders for empty ones.
	if len(routesBox) == 0 {
		routesBox = append(routesBox, sectionLabel.Render("ROUTES"))
		routesBox = append(routesBox, dimText.Render("  Scanning..."))
	}
	if len(proxiesBox) == 0 {
		proxiesBox = append(proxiesBox, sectionLabel.Render("PROXIES"))
		proxiesBox = append(proxiesBox, dimText.Render("  Scanning..."))
	}

	// ── Layout: all three boxes same size, titled ROUTES / ENDPOINTS / MISC ──
	titles := []string{"ROUTES", "ENDPOINTS", "MISC"}
	allContent := [][]string{routesBox, proxiesBox, checksBox}

	// Find the widest line across all boxes.
	maxContentW := 0
	for _, box := range allContent {
		for _, line := range box {
			if w := lipgloss.Width(line); w > maxContentW {
				maxContentW = w
			}
		}
	}
	boxW := maxContentW + 4 // border + padding

	// Equalize height to the tallest box.
	maxLines := 0
	for _, b := range allContent {
		if len(b) > maxLines {
			maxLines = len(b)
		}
	}
	h := maxLines + 2 // content + border top/bottom
	var rendered []string
	for i, b := range allContent {
		for len(b) < maxLines {
			b = append(b, "")
		}
		rendered = append(rendered, renderAccentPanel(boxW, h, titles[i], strings.Join(b, "\n")))
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, rendered[0], " ", rendered[1], " ", rendered[2])
}

// renderServiceMatrix renders a service reachability grid that matches
// the width of the tunnel/exfil matrix above it.
func renderServiceMatrix(probe *contour.ProbeSummary) string {
	if len(probe.ServiceResults) == 0 {
		return ""
	}

	passMark := statusPass.Render("✓")
	failMark := statusFail.Render("✗")
	untestedMark := statusFail.Render("·")

	// Match tunnel/exfil matrix inner width: protoW(10) + sep(1) + colW(6)*ports.
	const tunnelProtoW = 10
	const tunnelColW = 6
	nPorts := len(probe.Ports)
	if nPorts == 0 {
		nPorts = 25
	}
	innerW := tunnelProtoW + 1 + tunnelColW*nPorts

	// Each service cell: name + mark, padded to svcColW.
	const svcColW = 9 // fits 7-char names + spacing
	cols := max(1, innerW/svcColW)

	centerCol := func(s string, w int) string {
		n := lipgloss.Width(s)
		if n >= w {
			return s
		}
		left := (w - n) / 2
		right := w - n - left
		return strings.Repeat(" ", left) + s + strings.Repeat(" ", right)
	}

	var matrixRows []string

	totalReach, totalCount := 0, 0

	// Cap to full rows so the grid is clean.
	displayed := probe.ServiceResults
	if remainder := len(displayed) % cols; remainder != 0 && len(displayed) > cols {
		displayed = displayed[:len(displayed)-remainder]
	}

	// Render services in rows, each row: name header + status line.
	for i := 0; i < len(displayed); i += cols {
		end := i + cols
		if end > len(displayed) {
			end = len(displayed)
		}
		batch := displayed[i:end]

		// Name row.
		var hdr strings.Builder
		for _, svc := range batch {
			hdr.WriteString(dimText.Render(centerCol(svc.Name, svcColW)))
		}
		matrixRows = append(matrixRows, hdr.String())

		// Status row.
		var row strings.Builder
		for _, svc := range batch {
			totalCount++
			if !svc.Tested {
				row.WriteString(centerCol(untestedMark, svcColW))
			} else if svc.Reachable {
				totalReach++
				row.WriteString(centerCol(passMark, svcColW))
			} else {
				row.WriteString(centerCol(failMark, svcColW))
			}
		}
		matrixRows = append(matrixRows, row.String())
	}

	matrixRows = append(matrixRows, dimText.Render(strings.Repeat("─", innerW)))
	matrixRows = append(matrixRows, dimText.Render(fmt.Sprintf("%d/%d reachable", totalReach, totalCount)))

	matrixContent := strings.Join(matrixRows, "\n")
	h := len(matrixRows) + 2
	contentW := 0
	for _, row := range matrixRows {
		if w := lipgloss.Width(row); w > contentW {
			contentW = w
		}
	}
	w := contentW + 4
	return renderAccentPanel(w, h, "SERVICES", matrixContent)
}

// packGrid arranges cells into rows of `cols` columns with left indent.
func packGrid(cells []string, cols int) []string {
	var rows []string
	for i := 0; i < len(cells); i += cols {
		end := i + cols
		if end > len(cells) {
			end = len(cells)
		}
		rows = append(rows, "  "+strings.Join(cells[i:end], " "))
	}
	return rows
}

func renderTaskIcon(st taskState, spin spinner.Model) string {
	switch st {
	case taskRunning:
		return spin.View()
	case taskPass:
		return statusPass.Render("✓")
	case taskFail:
		return statusFail.Render("✗")
	case taskSkipped:
		return dimText.Render("·")
	default: // pending
		return dimText.Render("·")
	}
}

// extractDetail pulls a short result summary from the progress lines.
func extractDetail(lines []string, task probeTask) string {
	// Search backwards for the last [+] or [-] line matching any pass/fail pattern.
	patterns := append(task.passes, task.fails...)
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "[+]") && !strings.HasPrefix(trimmed, "[-]") && !strings.HasPrefix(trimmed, "[!]") {
			continue
		}
		for _, pat := range patterns {
			if strings.Contains(trimmed, pat) {
				// Strip the prefix tag.
				detail := trimmed
				for _, prefix := range []string{"[+] ", "[-] ", "[!] "} {
					detail = strings.TrimPrefix(detail, prefix)
				}
				// Keep it short.
				if len(detail) > 50 {
					detail = detail[:47] + "..."
				}
				return detail
			}
		}
	}
	return ""
}
