package views

import (
	"fmt"
	"sort"
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
		return dimText.Render("  STARTING...")
	}

	var rows []string
	for _, e := range entries {
		icon := renderTaskIcon(e.state, spin)
		// Format with dot leaders: TASK NAME .......... STATUS  detail
		taskName := strings.ToUpper(e.name)
		const totalWidth = 28
		dotsNeeded := totalWidth - len(taskName) - 1
		if dotsNeeded < 2 {
			dotsNeeded = 2
		}
		dots := " " + strings.Repeat(".", dotsNeeded) + " "
		line := "  " + inspLabel.Render(taskName) + dimText.Render(dots) + icon
		if e.detail != "" {
			line += dimText.Render("  " + e.detail)
		}
		rows = append(rows, line)
	}
	out := strings.Join(rows, "\n")

	if app != nil && app.ContourPartialProbe != nil {
		if probe, ok := app.ContourPartialProbe.(*contour.ProbeSummary); ok && probe != nil {
			tunnelExfil := renderTunnelExfilMatrix(probe, width)
			gridW := width
			if tunnelExfil != "" {
				out += "\n\n" + tunnelExfil
				if w := lipgloss.Width(tunnelExfil); w > 0 {
					gridW = w
				}
			}
			grid := renderContourGrid(probe, gridW)
			if grid != "" {
				out += "\n\n" + grid
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

	const colW = 5
	const protoW = 12
	passMark := statusPass.Render("OK")
	failMark := dimText.Render("--")
	untestedMark := dimText.Render("--")

	centerCol := func(s string, w int) string {
		n := lipgloss.Width(s)
		if n >= w {
			return s
		}
		left := (w - n) / 2
		right := w - n - left
		return strings.Repeat(" ", left) + s + strings.Repeat(" ", right)
	}

	innerW := protoW + colW*len(ports)
	divider := dimText.Render(strings.Repeat("─", innerW))

	var matrixRows []string

	var hdr strings.Builder
	hdr.WriteString(sectionLabel.Render(fmt.Sprintf("  %-*s", protoW, "PROTOCOL")))
	for _, port := range ports {
		hdr.WriteString(dimText.Render(centerCol(fmt.Sprintf("%d", port), colW)))
	}
	matrixRows = append(matrixRows, hdr.String())
	matrixRows = append(matrixRows, "  "+divider)

	renderRow := func(kind, proto string) string {
		var row strings.Builder
		row.WriteString(bodyText.Render(fmt.Sprintf("  %-*s", protoW, strings.ToUpper(proto))))
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
	_ = innerW

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
		{"CARRIERS", carriers, "tunnel"},
		{"PROTOCOLS", protocols, ""},
		{"SERVICES", services, ""},
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
	matrixRows = append(matrixRows, "  "+divider)
	matrixRows = append(matrixRows, dimText.Render(fmt.Sprintf("  %04d/%04d REACHABLE", matrixReach, matrixTotal)))

	// Build available summary
	var available []string
	for key := range results {
		parts := strings.Split(key, ":")
		if len(parts) >= 3 {
			proto := strings.ToUpper(parts[1])
			port := parts[2]
			available = append(available, fmt.Sprintf("%s:%s", proto, port))
		}
	}
	if len(available) > 0 {
		sort.Strings(available)
		matrixRows = append(matrixRows, "")
		matrixRows = append(matrixRows, statusPass.Render("  AVAILABLE: ")+bodyText.Render(strings.Join(available, "  ")))
	}

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

// routesContent builds the ROUTES panel body.
func routesContent(probe *contour.ProbeSummary) []string {
	if probe == nil {
		return nil
	}
	const maxLines = 4
	var rows []string
	overflow := 0
	push := func(line string) {
		if len(rows) < maxLines {
			rows = append(rows, line)
		} else {
			overflow++
		}
	}
	kvDots := func(label string, totalW int) string {
		if len(label) > totalW-4 {
			label = label[:totalW-4]
		}
		dotsNeeded := totalW - len(label) - 1
		if dotsNeeded < 2 {
			dotsNeeded = 2
		}
		return label + " " + strings.Repeat(".", dotsNeeded) + " "
	}

	for _, r := range probe.InternetSubnets {
		// Parse "iface addr" format
		parts := strings.SplitN(r, " ", 2)
		if len(parts) == 2 {
			iface := strings.ToUpper(parts[0])
			addr := strings.ToUpper(parts[1])
			push(inspLabel.Render(kvDots(iface, 12)) + bodyText.Render(addr))
		} else {
			push(bodyText.Render(strings.ToUpper(r)))
		}
	}
	for _, r := range probe.InternalRoutes {
		parts := strings.SplitN(r, " ", 2)
		if len(parts) == 2 {
			iface := strings.ToUpper(parts[0])
			addr := strings.ToUpper(parts[1])
			push(inspLabel.Render(kvDots(iface, 12)) + dimText.Render(addr))
		} else {
			push(dimText.Render(strings.ToUpper(r)))
		}
	}
	if overflow > 0 {
		rows = append(rows, dimText.Render(fmt.Sprintf("+%d MORE", overflow)))
	}
	return rows
}

// endpointsContent builds the ENDPOINTS panel body.
func endpointsContent(probe *contour.ProbeSummary, maxW int) []string {
	if probe == nil {
		return nil
	}
	const maxLines = 5
	var rows []string
	overflow := 0
	totalEP := 0
	push := func(line string) {
		totalEP++
		if len(rows) < maxLines {
			rows = append(rows, line)
		} else {
			overflow++
		}
	}

	kvDots := func(addr string, totalW int) string {
		if len(addr) > totalW-12 {
			addr = addr[:totalW-15] + "..."
		}
		dotsNeeded := totalW - len(addr) - 1
		if dotsNeeded < 2 {
			dotsNeeded = 2
		}
		return addr + " " + strings.Repeat(".", dotsNeeded) + " "
	}

	for _, ep := range probe.Proxies {
		host := strings.TrimSpace(ep.Host)
		if host == "" {
			continue
		}
		addr := fmt.Sprintf("%s:%d", host, ep.Port)
		switch {
		case ep.PivotReachable:
			target := strings.TrimSpace(ep.PivotTarget)
			if target == "" {
				target = "INTERNET"
			}
			push(bodyText.Render(kvDots(strings.ToUpper(addr), 30)) + statusPass.Render("PIVOT → "+strings.ToUpper(target)))
		case ep.Reachable:
			push(bodyText.Render(kvDots(strings.ToUpper(addr), 30)) + statusPass.Render("REACHABLE"))
		}
	}
	for _, ep := range probe.ConfigEndpoints {
		if !ep.Reachable {
			continue
		}
		addr := strings.TrimSpace(ep.Endpoint)
		if addr == "" {
			addr = fmt.Sprintf("%s:%d", ep.Host, ep.Port)
		}
		if ep.PivotReachable {
			push(bodyText.Render(kvDots(strings.ToUpper(addr), 30)) + statusPass.Render("PIVOT → "+strings.ToUpper(ep.PivotTarget)))
		} else {
			push(bodyText.Render(kvDots(strings.ToUpper(addr), 30)) + statusPass.Render("REACHABLE"))
		}
	}
	if overflow > 0 {
		rows = append(rows, dimText.Render(fmt.Sprintf("%04d ENDPOINTS  +%d MORE", totalEP, overflow)))
	} else if totalEP > 0 {
		rows = append(rows, dimText.Render(fmt.Sprintf("%04d ENDPOINTS", totalEP)))
	}
	return rows
}

// tlsContent builds the TLS-INSPECTION panel body.
func tlsContent(probe *contour.ProbeSummary) []string {
	kvDots := func(label string, totalW int) string {
		dotsNeeded := totalW - len(label) - 1
		if dotsNeeded < 2 {
			dotsNeeded = 2
		}
		return label + " " + strings.Repeat(".", dotsNeeded) + " "
	}

	var rows []string
	if probe.TLSIntercepted {
		rows = append(rows, inspLabel.Render(kvDots("STATUS", 16))+statusFail.Render("INTERCEPTED"))
		rows = append(rows, inspLabel.Render(kvDots("INTERCEPT", 16))+statusFail.Render(strings.ToUpper(probe.TLSInterceptOrg)))
		if probe.TLSInterceptIssuer != "" {
			rows = append(rows, inspLabel.Render(kvDots("ISSUER", 16))+dimText.Render(strings.ToUpper(probe.TLSInterceptIssuer)))
		}
		rows = append(rows, inspLabel.Render(kvDots("EXPECTED", 16))+dimText.Render(strings.ToUpper(probe.TLSInterceptExpectedOrg)))
	} else if probe.TLSChecked {
		rows = append(rows, inspLabel.Render(kvDots("STATUS", 16))+statusPass.Render("CLEAR"))
		rows = append(rows, inspLabel.Render(kvDots("INTERCEPT", 16))+statusPass.Render("NONE DETECTED"))
	} else {
		rows = append(rows, inspLabel.Render(kvDots("STATUS", 16))+dimText.Render("SCANNING..."))
	}
	return rows
}

// cdnContent builds the CDN-reachability panel body.
func cdnContent(probe *contour.ProbeSummary) []string {
	cdnNames := []string{"CFlare", "CFront", "AWS", "Fastly", "Akamai", "AzCDN", "GoogCDN"}
	var reachable, blocked []string
	for _, svc := range probe.ServiceResults {
		for _, cdn := range cdnNames {
			if svc.Name != cdn {
				continue
			}
			switch {
			case svc.Reachable:
				reachable = append(reachable, svc.Name)
			case svc.Tested:
				blocked = append(blocked, svc.Name)
			}
		}
	}
	var rows []string
	if len(reachable) > 0 {
		cdnList := strings.ToUpper(strings.Join(reachable, "  "))
		rows = append(rows, statusPass.Render("ALLOWED: ")+bodyText.Render(cdnList))
	}
	if len(blocked) > 0 {
		cdnList := strings.ToUpper(strings.Join(blocked, "  "))
		rows = append(rows, statusFail.Render("BLOCKED: ")+dimText.Render(cdnList))
	}
	if len(rows) == 0 {
		rows = append(rows, dimText.Render("SCANNING..."))
	}
	return rows
}

// servicesContent builds the body of the SERVICES box.
func servicesContent(probe *contour.ProbeSummary) []string {
	if len(probe.ServiceResults) == 0 {
		return nil
	}

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
		return nil
	}

	readyStyle := lipgloss.NewStyle().Foreground(colorCyan).Bold(true)
	reachStyle := lipgloss.NewStyle().Foreground(colorCyan)
	blockStyle := lipgloss.NewStyle().Foreground(colorAlert)
	keyYes := lipgloss.NewStyle().Foreground(colorCyan)
	keyNo := dimText

	// Dot leader helper
	kvDots := func(label string, totalW int) string {
		label = strings.ToUpper(label)
		dotsNeeded := totalW - len(label) - 1
		if dotsNeeded < 2 {
			dotsNeeded = 2
		}
		return label + " " + strings.Repeat(".", dotsNeeded) + " "
	}

	var rows []string

	for _, svc := range services {
		var statusStr string
		switch {
		case svc.reachable && svc.hasKey:
			statusStr = readyStyle.Render("READY")
		case svc.reachable:
			statusStr = reachStyle.Render("REACH")
		case svc.tested:
			statusStr = blockStyle.Render("BLOCKED")
		default:
			statusStr = dimText.Render("UNTESTED")
		}
		keyStr := keyNo.Render("-")
		if svc.hasKey {
			keyStr = keyYes.Render("+")
		}
		line := inspLabel.Render(kvDots(svc.name, 14)) + statusStr + dimText.Render("  DEAD DROP  ") + keyStr
		rows = append(rows, line)
	}

	rows = append(rows, dimText.Render(strings.Repeat("─", 40)))
	rows = append(rows, dimText.Render(fmt.Sprintf("%04d/%04d REACHABLE", totalReach, len(services))))
	return rows
}

// miscContent builds the body of the MISC box — HTTP methods.
func miscContent(probe *contour.ProbeSummary) []string {
	var rows []string

	kvDots := func(label string, totalW int) string {
		dotsNeeded := totalW - len(label) - 1
		if dotsNeeded < 2 {
			dotsNeeded = 2
		}
		return label + " " + strings.Repeat(".", dotsNeeded) + " "
	}

	if len(probe.HTTPMethodsAllowed) > 0 {
		methods := strings.Join(probe.HTTPMethodsAllowed, "  ")
		rows = append(rows, inspLabel.Render(kvDots("HTTP METHODS", 18))+statusPass.Render(methods))
		for _, m := range probe.HTTPMethodsAllowed {
			switch m {
			case "CONNECT":
				rows = append(rows, dimText.Render("  CONNECT: TUNNELS ARBITRARY TCP"))
			case "POST":
				rows = append(rows, dimText.Render("  POST: EXFILTRATION PATH"))
			case "PUT":
				rows = append(rows, dimText.Render("  PUT: STAGING PATH"))
			}
		}
	} else if probe.HTTPMethodsChecked {
		rows = append(rows, inspLabel.Render(kvDots("HTTP METHODS", 18))+statusFail.Render("NONE ACCEPTED"))
	} else {
		rows = append(rows, inspLabel.Render(kvDots("HTTP METHODS", 18))+dimText.Render("SCANNING..."))
	}
	return rows
}

// renderContourGrid lays out the post-matrix summary as a uniform 2×3
// grid: row 1 is SERVICES | ROUTES | ENDPOINTS, row 2 is TLS
// INSPECTION | CDN | MISC. All six boxes share a single column width
// (= matrix-row-width / 3); each row has its own shared height equal
// to its tallest member.
//
// Tabular boxes (SERVICES / ROUTES / ENDPOINTS) clip-truncate so
// columns stay aligned. Prose boxes (TLS / CDN / MISC) word-wrap so
// long sentences flow onto extra lines without forcing the box wider.
func renderContourGrid(probe *contour.ProbeSummary, totalW int) string {
	if probe == nil {
		return ""
	}
	if totalW < 60 {
		totalW = 60
	}

	const gap = 1
	colW := (totalW - 2*gap) / 3
	if colW < 18 {
		colW = 18
	}
	contentW := colW - 4 // accent-panel chrome (2 border + 2 padding)

	clipBody := func(rows []string) []string {
		out := make([]string, 0, len(rows))
		for _, r := range rows {
			if lipgloss.Width(r) <= contentW {
				out = append(out, r)
				continue
			}
			out = append(out, truncRight(r, contentW))
		}
		return out
	}

	// wrapBody hard-wraps each input row to contentW columns, preserving
	// any embedded ANSI styling. Used by the prose boxes (TLS / CDN /
	// MISC) so long descriptions flow onto extra lines instead of
	// stretching the column. Implemented via lipgloss's Width-based
	// auto-wrap (reflow internally) which is ANSI-safe.
	wrapStyle := lipgloss.NewStyle().Width(contentW)
	wrapBody := func(rows []string) []string {
		if contentW <= 0 {
			return rows
		}
		out := make([]string, 0, len(rows))
		for _, r := range rows {
			if r == "" {
				out = append(out, "")
				continue
			}
			if lipgloss.Width(r) <= contentW {
				out = append(out, r)
				continue
			}
			wrapped := wrapStyle.Render(r)
			out = append(out, strings.Split(wrapped, "\n")...)
		}
		return out
	}

	// Row 1: SERVICES, ROUTES, ENDPOINTS — tabular, clip-truncate.
	svc := clipBody(servicesContent(probe))
	if len(svc) == 0 {
		svc = []string{dimText.Render("  Scanning...")}
	}
	rt := clipBody(routesContent(probe))
	if len(rt) == 0 {
		rt = []string{dimText.Render("  Scanning...")}
	}
	ep := endpointsContent(probe, contentW)
	if len(ep) == 0 {
		ep = []string{dimText.Render("  No proxy/endpoint reachable")}
	}

	// Row 2: TLS, CDN, MISC — prose, word-wrap.
	tls := wrapBody(tlsContent(probe))
	cdn := wrapBody(cdnContent(probe))
	mc := wrapBody(miscContent(probe))

	// Each row gets a single shared height = max(content) + chrome.
	rowH := func(bodies ...[]string) int {
		m := 0
		for _, b := range bodies {
			if len(b) > m {
				m = len(b)
			}
		}
		return m + 2
	}

	row1H := rowH(svc, rt, ep)
	row2H := rowH(tls, cdn, mc)

	pad := func(rows []string, h int) []string {
		for len(rows) < h-2 {
			rows = append(rows, "")
		}
		return rows
	}

	svc = pad(svc, row1H)
	rt = pad(rt, row1H)
	ep = pad(ep, row1H)
	tls = pad(tls, row2H)
	cdn = pad(cdn, row2H)
	mc = pad(mc, row2H)

	r1a := renderAccentPanel(colW, row1H, "SERVICES", strings.Join(svc, "\n"))
	r1b := renderAccentPanel(colW, row1H, "ROUTES", strings.Join(rt, "\n"))
	r1c := renderAccentPanel(colW, row1H, "ENDPOINTS", strings.Join(ep, "\n"))
	r2a := renderAccentPanel(colW, row2H, "TLS INSPECTION", strings.Join(tls, "\n"))
	r2b := renderAccentPanel(colW, row2H, "CDN", strings.Join(cdn, "\n"))
	r2c := renderAccentPanel(colW, row2H, "MISC", strings.Join(mc, "\n"))

	row1 := lipgloss.JoinHorizontal(lipgloss.Top, r1a, " ", r1b, " ", r1c)
	row2 := lipgloss.JoinHorizontal(lipgloss.Top, r2a, " ", r2b, " ", r2c)
	return row1 + "\n" + row2
}

func renderTaskIcon(st taskState, spin spinner.Model) string {
	switch st {
	case taskRunning:
		return spin.View()
	case taskPass:
		return statusPass.Render("COMPLETE")
	case taskFail:
		return statusFail.Render("FAILED")
	case taskSkipped:
		return dimText.Render("PENDING")
	default:
		return dimText.Render("PENDING")
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
