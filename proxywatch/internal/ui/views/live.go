package views

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
	name   string
	starts []string
	passes []string
	fails  []string
}

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
		name:   "Protocol verification",
		starts: []string{"Verifying tunnels"},
		passes: []string{"Protocol matrix:"},
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
		passes: []string{"Endpoint pivot:"},
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
		fails:  []string{"Domain fronting not viable"},
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

func renderTaskMatrix(lines []string, spin spinner.Model, app *shared.AppState, width int) string {
	allText := strings.Join(lines, "\n")

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
			infoPanel := renderInfoPanels(probe, width)
			if infoPanel != "" {
				out += "\n\n" + infoPanel
			}
		}
	}

	return out
}

func renderTunnelExfilMatrix(probe *contour.ProbeSummary, width int) string {
	ports := probe.Ports
	if len(ports) == 0 || len(probe.Protocols) == 0 {
		return ""
	}

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
	results := map[string]bool{}
	for k, v := range checks {
		if v == checkPass {
			results[k] = true
		}
	}

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
	const protoW = 15
	_ = matrixFailStyle
	passMark := statusPass.Render("✓")
	failMark := matrixFailStyle.Render("✗")
	untestedMark := dimText.Render("—")
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

	var hdr strings.Builder
	hdr.WriteString(sectionLabel.Render(fmt.Sprintf("%-*s", protoW, "PROTOCOLS")))
	hdr.WriteString(sep)
	for _, port := range ports {
		hdr.WriteString(dimText.Render(centerCol(fmt.Sprintf("%d", port), colW)))
	}
	matrixRows = append(matrixRows, hdr.String())
	matrixRows = append(matrixRows, divider)

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

	type protoGroup struct {
		label  string
		protos []string
		kind   string
	}

	carrierSet := map[string]bool{
		"http": true, "https": true, "ws": true, "wss": true,
		"ssh": true,
	}
	hideSet := map[string]bool{}
	serviceSet := map[string]bool{
		"openai-api": true, "github-api": true, "buildkite-api": true,
		"aws-api": true, "azure-api": true, "gcp-api": true,
	}

	var carriers, protocols, services []string
	seen := make(map[string]bool)

	allProtos := append(append([]string(nil), tunnelProtos...), exfilProtos...)
	for _, p := range allProtos {
		if seen[p] || hideSet[p] {
			continue
		}
		seen[p] = true
		if serviceSet[p] {
			services = append(services, p)
		} else if carrierSet[p] {
			carriers = append(carriers, p)
		} else {
			protocols = append(protocols, p)
		}
	}

	groups := []protoGroup{
		{"TUNNEL CARRIERS", carriers, "tunnel"},
		{"PROTOCOL TUNNELS", protocols, ""},
		{"SERVICE TUNNELS", services, ""},
	}

	for _, g := range groups {
		if len(g.protos) == 0 {
			continue
		}
		for _, proto := range g.protos {
			kind := g.kind
			if kind == "" {
				for _, tp := range tunnelProtos {
					if tp == proto {
						kind = "tunnel"
						break
					}
				}
				if kind == "" {
					kind = "exfil"
				}
			}
			matrixRows = append(matrixRows, renderRow(kind, proto))
		}
	}

	matrixReach := len(results)
	matrixTotal := (len(tunnelProtos) + len(exfilProtos)) * len(ports)
	matrixRows = append(matrixRows, divider)
	matrixRows = append(matrixRows, dimText.Render(fmt.Sprintf("%d/%d reachable", matrixReach, matrixTotal)))

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

func renderInfoPanels(probe *contour.ProbeSummary, screenWidth ...int) string {
	if probe == nil {
		return ""
	}

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

	var checksBox []string
	checksBox = append(checksBox, sectionLabel.Render("TLS INSPECTION"))
	if probe.TLSIntercepted {
		checksBox = append(checksBox, statusFail.Render(fmt.Sprintf("  INTERCEPTED — cert signed by: %s", probe.TLSInterceptOrg)))
		if probe.TLSInterceptIssuer != "" {
			checksBox = append(checksBox, dimText.Render(fmt.Sprintf("  Issuer CN: %s", probe.TLSInterceptIssuer)))
		}
		checksBox = append(checksBox, dimText.Render(fmt.Sprintf("  Expected: %s", probe.TLSInterceptExpectedOrg)))
		checksBox = append(checksBox, "")
		checksBox = append(checksBox, dimText.Render("  A proxy/firewall is terminating TLS and re-signing with its"))
		checksBox = append(checksBox, dimText.Render("  own certificate. All HTTPS content is visible to the proxy."))
		checksBox = append(checksBox, dimText.Render("  Proof: the certificate issuer does not match any known public CA."))
	} else if probe.TLSChecked {
		checksBox = append(checksBox, statusPass.Render("  No interception detected"))
		checksBox = append(checksBox, dimText.Render("  TLS certificates are signed by legitimate public CAs."))
		checksBox = append(checksBox, dimText.Render("  End-to-end encryption is intact — no MITM proxy observed."))
	} else {
		checksBox = append(checksBox, dimText.Render("  Scanning..."))
	}

	checksBox = append(checksBox, "")
	checksBox = append(checksBox, sectionLabel.Render("DOMAIN FRONTING"))
	if probe.DomainFrontingPossible {
		checksBox = append(checksBox, statusPass.Render(fmt.Sprintf("  VIABLE via %s CDN", probe.DomainFrontingCDN)))
		checksBox = append(checksBox, "")
		checksBox = append(checksBox, dimText.Render(fmt.Sprintf("  Connected to %s CDN IP %s on port 443.", probe.DomainFrontingCDN, probe.DomainFrontingCDNIP)))
		checksBox = append(checksBox, dimText.Render(fmt.Sprintf("  Presented SNI: %s (a high-reputation domain).", probe.DomainFrontingSNI)))
		checksBox = append(checksBox, dimText.Render("  The CDN accepted the TLS handshake without validating that"))
		checksBox = append(checksBox, dimText.Render("  the SNI matches the HTTP Host header."))
		if probe.DomainFrontingCertIssuer != "" {
			checksBox = append(checksBox, dimText.Render(fmt.Sprintf("  Cert issuer: %s", probe.DomainFrontingCertIssuer)))
		}
		checksBox = append(checksBox, "")
		checksBox = append(checksBox, dimText.Render("  Impact: An attacker can route C2 traffic through this CDN."))
		checksBox = append(checksBox, dimText.Render("  The network sees connections to the CDN's IP with a trusted"))
		checksBox = append(checksBox, dimText.Render("  SNI, but the actual HTTP request targets the attacker's backend."))
	} else if probe.TLSChecked {
		checksBox = append(checksBox, dimText.Render("  Not viable"))
		checksBox = append(checksBox, dimText.Render("  Tested CDNs rejected TLS handshakes with mismatched SNI."))
		checksBox = append(checksBox, dimText.Render("  Domain fronting is blocked on this network."))
	} else {
		checksBox = append(checksBox, dimText.Render("  Scanning..."))
	}

	checksBox = append(checksBox, "")
	checksBox = append(checksBox, sectionLabel.Render("CDN REACHABILITY"))
	cdnNames := []string{"CFlare", "CFront", "Fastly", "Akamai", "AzCDN", "GoogCDN"}
	var reachableCDNs, blockedCDNs []string
	for _, svc := range probe.ServiceResults {
		for _, cdn := range cdnNames {
			if svc.Name == cdn {
				if svc.Reachable {
					reachableCDNs = append(reachableCDNs, svc.Name)
				} else if svc.Tested {
					blockedCDNs = append(blockedCDNs, svc.Name)
				}
			}
		}
	}
	if len(reachableCDNs) > 0 {
		checksBox = append(checksBox, statusPass.Render("  Allowed: "+strings.Join(reachableCDNs, ", ")))
	}
	if len(blockedCDNs) > 0 {
		checksBox = append(checksBox, statusFail.Render("  Blocked: "+strings.Join(blockedCDNs, ", ")))
	}
	if len(reachableCDNs) == 0 && len(blockedCDNs) == 0 {
		checksBox = append(checksBox, dimText.Render("  Scanning..."))
	}

	checksBox = append(checksBox, "")
	checksBox = append(checksBox, sectionLabel.Render("HTTP METHODS"))
	if len(probe.HTTPMethodsAllowed) > 0 {
		checksBox = append(checksBox, statusPass.Render("  "+strings.Join(probe.HTTPMethodsAllowed, ", ")))
		// Describe the risk of each method
		for _, m := range probe.HTTPMethodsAllowed {
			switch m {
			case "CONNECT":
				checksBox = append(checksBox, dimText.Render("  CONNECT: proxy tunnels arbitrary TCP — enables full C2 channels"))
			case "POST":
				checksBox = append(checksBox, dimText.Render("  POST: send data to external servers — enables data exfiltration"))
			case "PUT":
				checksBox = append(checksBox, dimText.Render("  PUT: upload files to external servers — enables staging"))
			case "DELETE":
				checksBox = append(checksBox, dimText.Render("  DELETE: remove remote resources — enables evidence cleanup"))
			case "PATCH":
				checksBox = append(checksBox, dimText.Render("  PATCH: modify remote data — enables C2 command delivery"))
			}
		}
	} else if probe.HTTPMethodsChecked {
		checksBox = append(checksBox, statusFail.Render("  No methods accepted"))
	} else {
		checksBox = append(checksBox, dimText.Render("  Scanning..."))
	}

	if len(routesBox) == 0 {
		routesBox = append(routesBox, sectionLabel.Render("ROUTES"))
		routesBox = append(routesBox, dimText.Render("  Scanning..."))
	}
	if len(proxiesBox) == 0 {
		proxiesBox = append(proxiesBox, sectionLabel.Render("PROXIES"))
		proxiesBox = append(proxiesBox, dimText.Render("  Scanning..."))
	}

	titles := []string{"ROUTES", "ENDPOINTS", "MISC"}
	allContent := [][]string{routesBox, proxiesBox, checksBox}

	termW := 120
	if len(screenWidth) > 0 && screenWidth[0] > 0 {
		termW = screenWidth[0]
	}
	availW := termW - 4
	boxWidths := make([]int, 3)
	for i, box := range allContent {
		maxW := 0
		for _, line := range box {
			if w := lipgloss.Width(line); w > maxW {
				maxW = w
			}
		}
		boxWidths[i] = maxW + 4
	}
	totalW := boxWidths[0] + boxWidths[1] + boxWidths[2]
	if totalW > availW && availW > 30 {
		for i := range boxWidths {
			boxWidths[i] = boxWidths[i] * availW / totalW
			if boxWidths[i] < 20 {
				boxWidths[i] = 20
			}
		}
	}

	maxLines := 0
	for _, b := range allContent {
		if len(b) > maxLines {
			maxLines = len(b)
		}
	}
	h := maxLines + 2
	var rendered []string
	for i, b := range allContent {
		for len(b) < maxLines {
			b = append(b, "")
		}
		rendered = append(rendered, renderAccentPanel(boxWidths[i], h, titles[i], strings.Join(b, "\n")))
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, rendered[0], " ", rendered[1], " ", rendered[2])
}

func renderServiceMatrix(probe *contour.ProbeSummary) string {
	if len(probe.ServiceResults) == 0 {
		return ""
	}

	hasFronting := probe.DomainFrontingPossible

	type serviceInfo struct {
		name      string
		reachable bool
		tested    bool
		hasKey    bool
	}

	totalReach := 0
	var services []serviceInfo
	for _, svc := range probe.ServiceResults {
		if !contour.DeadDropServices[svc.Name] {
			continue
		}
		hasKey := contour.GetServiceKeyExported(svc.Name) != ""
		services = append(services, serviceInfo{
			name:      svc.Name,
			reachable: svc.Reachable,
			tested:    svc.Tested,
			hasKey:    hasKey,
		})
		if svc.Reachable {
			totalReach++
		}
	}

	if len(services) == 0 {
		return ""
	}

	readyStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#5EBC8E")).Bold(true)
	reachStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#5EBC8E"))
	blockStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#E06C75"))
	keyYes := lipgloss.NewStyle().Foreground(lipgloss.Color("#5EBC8E"))
	keyNo := dimText

	const nameW = 11
	const statusW = 12
	const methodW = 15
	const keyW = 4

	var matrixRows []string

	// Header
	hdr := fmt.Sprintf(" %-*s %-*s %-*s %s", nameW, "Service", statusW, "Status", methodW, "Method", "Key")
	matrixRows = append(matrixRows, sectionLabel.Render(hdr))

	innerW := lipgloss.Width(hdr) + 1
	matrixRows = append(matrixRows, dimText.Render(strings.Repeat("─", innerW)))

	// Rows
	for _, svc := range services {
		var statusStr string
		if svc.reachable && svc.hasKey {
			statusStr = readyStyle.Render("✓ READY")
			// Pad to statusW accounting for rendered width
			statusStr += strings.Repeat(" ", max(0, statusW-lipgloss.Width("✓ READY")))
		} else if svc.reachable {
			statusStr = reachStyle.Render("✓ reach")
			statusStr += strings.Repeat(" ", max(0, statusW-lipgloss.Width("✓ reach")))
		} else if svc.tested {
			statusStr = blockStyle.Render("✗ blocked")
			statusStr += strings.Repeat(" ", max(0, statusW-lipgloss.Width("✗ blocked")))
		} else {
			statusStr = dimText.Render("○ untested")
			statusStr += strings.Repeat(" ", max(0, statusW-lipgloss.Width("○ untested")))
		}

		methodStr := dimText.Render(fmt.Sprintf("%-*s", methodW, "dead drop"))

		var keyStr string
		if svc.hasKey {
			keyStr = keyYes.Render("✓")
		} else {
			keyStr = keyNo.Render("✗")
		}

		namePad := svc.name + strings.Repeat(" ", max(0, nameW-len(svc.name)))
		row := " " + bodyText.Render(namePad) + " " + statusStr + " " + methodStr + " " + keyStr
		matrixRows = append(matrixRows, row)
	}

	// Footer
	matrixRows = append(matrixRows, dimText.Render(strings.Repeat("─", innerW)))
	var parts []string
	parts = append(parts, fmt.Sprintf("%d/%d reachable", totalReach, len(services)))
	if hasFronting {
		cdns := strings.Join(probe.DomainFrontingViableCDNs, ", ")
		if cdns == "" {
			cdns = probe.DomainFrontingCDN
		}
		parts = append(parts, "fronting: "+cdns)
	}
	matrixRows = append(matrixRows, dimText.Render(strings.Join(parts, "  |  ")))

	matrixContent := strings.Join(matrixRows, "\n")
	h := len(matrixRows) + 2
	contentW := 0
	for _, row := range matrixRows {
		if rw := lipgloss.Width(row); rw > contentW {
			contentW = rw
		}
	}
	panelW := contentW + 4
	if panelW < 30 {
		panelW = 30
	}
	return renderAccentPanel(panelW, h, "SERVICES", matrixContent)
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
	default:
		return dimText.Render("·")
	}
}

func extractDetail(lines []string, task probeTask) string {
	patterns := append(task.passes, task.fails...)
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "[+]") && !strings.HasPrefix(trimmed, "[-]") && !strings.HasPrefix(trimmed, "[!]") {
			continue
		}
		for _, pat := range patterns {
			if strings.Contains(trimmed, pat) {
				detail := trimmed
				for _, prefix := range []string{"[+] ", "[-] ", "[!] "} {
					detail = strings.TrimPrefix(detail, prefix)
				}
				if len(detail) > 50 {
					detail = detail[:47] + "..."
				}
				return detail
			}
		}
	}
	return ""
}
