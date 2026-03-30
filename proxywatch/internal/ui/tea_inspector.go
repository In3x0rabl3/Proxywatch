package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/gdamore/tcell/v2"

	"proxywatch/internal/shared"
)

// InspectorModel is the native bubbletea model for the Inspector (process detail) view.
type InspectorModel struct {
	app        *shared.AppState
	viewport   viewport.Model
	width      int
	height     int
	ready      bool
	contentKey uint64 // hash of last content set on viewport
}

// NewInspectorModel creates an InspectorModel bound to the given app state.
func NewInspectorModel(app *shared.AppState) InspectorModel {
	return InspectorModel{app: app}
}

func (m InspectorModel) Init() tea.Cmd { return nil }

func (m InspectorModel) Update(msg tea.Msg) (InspectorModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.initViewport()
		m.refreshContent()

	case tea.KeyMsg:
		tev := convertKeyMsg(msg)

		// Quit confirm.
		handled, shouldQuit := handleQuitConfirmKey(m.app, tev)
		if handled {
			if shouldQuit {
				return m, tea.Quit
			}
			return m, nil
		}

		// Cycle through processes with Left/Right.
		switch tev.Key() {
		case tcell.KeyLeft:
			cycleInspectProcess(m.app, -1)
			m.refreshContent()
			if m.ready {
				m.viewport.GotoTop()
			}
			return m, nil
		case tcell.KeyRight:
			cycleInspectProcess(m.app, 1)
			m.refreshContent()
			if m.ready {
				m.viewport.GotoTop()
			}
			return m, nil
		}

		// Viewport scrolling when no overlay is open.
		if m.ready && !m.app.ShowInspectMenu {
			if m.handleScroll(tev) {
				return m, nil
			}
		}

		// Delegate to legacy inspect key handler.
		if handleInspectKey(m.app, tev) {
			return m, tea.Quit
		}
	}

	m.refreshContent()
	return m, nil
}

// handleScroll processes scroll keys for the viewport. Returns true if consumed.
func (m *InspectorModel) handleScroll(tev *tcell.EventKey) bool {
	if !m.ready {
		return false
	}
	switch tev.Key() {
	case tcell.KeyUp:
		m.viewport.LineUp(1)
		return true
	case tcell.KeyDown:
		m.viewport.LineDown(1)
		return true
	case tcell.KeyPgUp:
		m.viewport.LineUp(m.viewport.VisibleLineCount())
		return true
	case tcell.KeyPgDn:
		m.viewport.LineDown(m.viewport.VisibleLineCount())
		return true
	case tcell.KeyHome:
		m.viewport.GotoTop()
		return true
	case tcell.KeyEnd:
		m.viewport.GotoBottom()
		return true
	case tcell.KeyTab:
		m.jumpSection(1)
		return true
	case tcell.KeyBacktab:
		m.jumpSection(-1)
		return true
	}
	switch tev.Rune() {
	case '[':
		m.viewport.LineUp(1)
		return true
	case ']':
		m.viewport.LineDown(1)
		return true
	}
	return false
}

// jumpSection moves the viewport to the next or previous section marker.
func (m *InspectorModel) jumpSection(dir int) {
	if !m.ready || dir == 0 {
		return
	}
	starts := m.app.InspectSectionStarts
	if len(starts) == 0 {
		return
	}
	current := m.viewport.YOffset
	if dir > 0 {
		for _, row := range starts {
			if row > current {
				m.viewport.SetYOffset(row)
				return
			}
		}
	} else {
		for i := len(starts) - 1; i >= 0; i-- {
			if starts[i] < current {
				m.viewport.SetYOffset(starts[i])
				return
			}
		}
	}
}

func (m InspectorModel) View() string {
	w := m.width
	if w <= 0 {
		w = 80
	}

	var sections []string
	sections = append(sections, m.renderHeader())

	sections = append(sections, m.renderBody())

	view := lipgloss.JoinVertical(lipgloss.Left, sections...)

	if m.app.ShowInspectMenu {
		h := m.height
		if h <= 0 {
			h = 24
		}
		view = overlayCenter(view, renderHelpPanel("Inspector Menu", inspectorMenuOptions(), w), w, h)
	}

	// Kill confirmation overlay.
	if m.app.ConfirmKill && m.app.ConfirmKillKey == m.app.InspectKey && time.Now().Before(m.app.ConfirmKillDeadline) {
		msg := fmt.Sprintf("Confirm kill: press k again or y within %s", m.app.ConfirmKillTimeout)
		view += "\n" + sevWatch.Render("  "+msg)
	}

	// Error status.
	if m.app.LastError != "" {
		view += "\n" + statusFail.Render("  "+m.app.LastError)
	}

	// Quit confirmation overlay.
	if m.app.ShowQuitConfirm && m.app.QuitConfirmDeadline.After(time.Now()) {
		view += "\n" + renderQuitConfirm(m.app.QuitConfirmDeadline, w)
	}

	return view
}

// ── Header ───────────────────────────────────────────────────────────────────

func (m InspectorModel) renderHeader() string {
	w := m.width
	if w <= 0 {
		w = 80
	}
	contentW := w - 2
	helpPlain := "? menu   esc dashboard   q quit"
	utcPlain := "UTC: " + time.Now().UTC().Format(utcTimeFormat)
	gap := max(1, contentW-len(helpPlain)-len(utcPlain))
	headerContent := dimText.Render(helpPlain) + bgSp(gap) +
		rightLabelStyle.Render("UTC: ") + sectionLabel.Render(time.Now().UTC().Format(utcTimeFormat))
	return renderPanel(w, 3, "Inspector", "proxywatch", "", headerContent)
}

// ── Body ─────────────────────────────────────────────────────────────────────

func (m *InspectorModel) initViewport() {
	if m.width <= 0 || m.height <= 0 {
		return
	}
	// Reserve space for the header panel (~4 lines) and footer status.
	bodyH := m.height - 7
	if bodyH < 4 {
		bodyH = 4
	}
	if !m.ready {
		m.viewport = viewport.New(m.width-4, bodyH)
		m.viewport.Style = lipgloss.NewStyle()
		m.ready = true
	} else {
		m.viewport.Width = m.width - 4
		m.viewport.Height = bodyH
	}
}

func (m *InspectorModel) refreshContent() {
	if !m.ready {
		return
	}
	content := m.buildContent()
	h := quickHash(content)
	if h != m.contentKey {
		m.contentKey = h
		m.viewport.SetContent(content)
	}
}

func (m InspectorModel) renderBody() string {
	w := m.width
	if w <= 0 {
		w = 80
	}
	bodyH := m.height - 7
	if bodyH < 4 {
		bodyH = 4
	}

	opts := ReportPanelOpts{
		Title:      "PROCESS DETAILS",
		RightLabel: "proxywatch",
		Width:      w,
		Height:     bodyH,
	}
	if m.ready {
		opts.Content = m.viewport.View()
		total := m.viewport.TotalLineCount()
		visible := m.viewport.VisibleLineCount()
		opts.ScrollTotal = total
		opts.ScrollVisible = visible
		opts.ScrollTop = m.viewport.YOffset + 1
		opts.ScrollBottom = m.viewport.YOffset + visible
		if opts.ScrollBottom > total {
			opts.ScrollBottom = total
		}
	}
	return renderReportPanel(opts)
}

// ── Content builder ──────────────────────────────────────────────────────────

// Lipgloss helpers for inspector content.
var (
	inspLabel   = lipgloss.NewStyle().Foreground(colorMuted).Background(colorBg)
	inspValue   = lipgloss.NewStyle().Foreground(colorText).Bold(true).Background(colorBg)
	inspDim     = lipgloss.NewStyle().Foreground(colorDim).Background(colorBg)
	inspWarn    = lipgloss.NewStyle().Foreground(colorWarn).Bold(true).Background(colorBg)
	inspAlert   = lipgloss.NewStyle().Foreground(colorAlert).Bold(true).Background(colorBg)
	inspCyan    = lipgloss.NewStyle().Foreground(colorCyan).Background(colorBg)
	inspAccent  = lipgloss.NewStyle().Foreground(colorAccent).Bold(true).Background(colorBg)
	inspSession = lipgloss.NewStyle().Foreground(colorSession).Bold(true).Background(colorBg)
)

func inspRoleStyle(role string) lipgloss.Style {
	switch role {
	case "session":
		return inspSession
	case "beacon":
		return inspWarn
	case "tunnel":
		return inspAlert
	default:
		return inspValue
	}
}

func inspStateStyle(state string) lipgloss.Style {
	switch state {
	case "active":
		return inspAlert
	case "strong":
		return inspWarn
	default:
		return lipgloss.NewStyle().Foreground(colorCyan).Bold(true)
	}
}

func inspScopeStyle(scope string) lipgloss.Style {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "external":
		return inspWarn
	default:
		return inspLabel
	}
}

// ── Visual helpers ──────────────────────────────────────────────────────────

// miniBar renders a horizontal bar chart using block characters.
// Each segment has a value, label, and color. Total width is barW chars.
func miniBar(segments []barSegment, barW int) string {
	if barW < 4 {
		barW = 4
	}
	total := 0
	for _, s := range segments {
		total += s.value
	}
	if total == 0 {
		return lipgloss.NewStyle().Foreground(colorDim).Render(strings.Repeat("░", barW))
	}
	var bar string
	used := 0
	for i, s := range segments {
		w := (s.value * barW) / total
		if i == len(segments)-1 {
			w = barW - used // last segment takes remaining
		}
		if w <= 0 && s.value > 0 {
			w = 1
		}
		if used+w > barW {
			w = barW - used
		}
		bar += lipgloss.NewStyle().Foreground(s.color).Render(strings.Repeat("█", w))
		used += w
	}
	// Fill remainder with dim blocks.
	if used < barW {
		bar += lipgloss.NewStyle().Foreground(colorDim).Render(strings.Repeat("░", barW-used))
	}
	return bar
}

// miniBarLegend renders labels for each segment: "█ label (N)"
func miniBarLegend(segments []barSegment) string {
	var parts []string
	for _, s := range segments {
		if s.value > 0 {
			block := lipgloss.NewStyle().Foreground(s.color).Render("█")
			parts = append(parts, fmt.Sprintf("%s %s %d", block, s.label, s.value))
		}
	}
	return strings.Join(parts, "   ")
}

type barSegment struct {
	label string
	value int
	color lipgloss.Color
}

// sparkGauge renders a simple percentage gauge: [████░░░░] 42%
func sparkGauge(pct float64, w int, fg lipgloss.Color) string {
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	filled := int(pct * float64(w) / 100)
	empty := w - filled
	bar := lipgloss.NewStyle().Foreground(fg).Render(strings.Repeat("█", filled)) +
		lipgloss.NewStyle().Foreground(colorDim).Render(strings.Repeat("░", empty))
	return bar
}

func inspConnStateStyle(state string) lipgloss.Style {
	switch strings.ToUpper(strings.TrimSpace(state)) {
	case "ESTABLISHED", "LISTEN":
		return inspValue
	case "SYN_SENT", "SYN_RECV", "CLOSE_WAIT", "TIME_WAIT", "FIN_WAIT1", "FIN_WAIT2":
		return inspLabel
	case "UNKNOWN", "":
		return inspDim
	default:
		return bodyText
	}
}

func (m InspectorModel) buildContent() string {
	var cand *shared.Candidate
	for i := range m.app.Candidates {
		if shared.CandidateKey(m.app.Candidates[i]) == m.app.InspectKey {
			cand = &m.app.Candidates[i]
			break
		}
	}
	if cand == nil {
		return inspAlert.Render("Process no longer present. Press ESC.")
	}

	role := normalizeDashboardRole(cand.Role)
	state := "watch"
	if cand.ActiveProxying {
		state = "active"
	} else if cand.StrongEvidence {
		state = "strong"
	}

	name := "(unknown)"
	pid := 0
	if cand.Proc != nil {
		name = shared.DisplayProcessName(cand.Proc)
		pid = cand.Proc.Pid
	}
	host := shared.DisplayHost(cand.Host)
	age := "0s"
	ageSeconds := dashboardCandidateAgeSeconds(*cand)
	if ageSeconds > 0 {
		age = (time.Duration(ageSeconds) * time.Second).Round(time.Second).String()
	}
	path := "(unknown)"
	user := "(unknown)"
	parentPID := "(unknown)"
	integrity := "(unknown)"
	var ioRead, ioWrite, ioOther uint64
	var ioReadRate, ioWriteRate, ioOtherRate uint64
	if cand.Proc != nil {
		if strings.TrimSpace(cand.Proc.ExePath) != "" {
			path = cand.Proc.ExePath
		}
		if strings.TrimSpace(cand.Proc.UserName) != "" {
			user = cand.Proc.UserName
		}
		if cand.Proc.ParentPid > 0 {
			parentPID = fmt.Sprintf("%d", cand.Proc.ParentPid)
		}
		if strings.TrimSpace(cand.Proc.Integrity) != "" {
			integrity = cand.Proc.Integrity
		}
		ioRead = cand.Proc.IOReadBytes
		ioWrite = cand.Proc.IOWriteBytes
		ioOther = cand.Proc.IOOtherBytes
		ioReadRate = cand.Proc.IOReadBps
		ioWriteRate = cand.Proc.IOWriteBps
		ioOtherRate = cand.Proc.IOOtherBps
	}
	established := 0
	for _, cn := range cand.Conns {
		if cn.State == "ESTABLISHED" {
			established++
		}
	}

	// Style helpers.
	w := m.width - 4
	if w < 20 {
		w = 20
	}
	kv := func(label, value string, vs lipgloss.Style) string {
		return inspLabel.Render(fmt.Sprintf("  %-10s", label)) + vs.Render(value)
	}
	kvPair := func(l1, v1 string, s1 lipgloss.Style, l2, v2 string, s2 lipgloss.Style) string {
		left := inspLabel.Render(fmt.Sprintf("  %-10s", l1)) + s1.Render(fmt.Sprintf("%-14s", v1))
		right := inspLabel.Render(fmt.Sprintf("%-12s", l2)) + s2.Render(v2)
		return left + "  " + right
	}

	type section struct {
		name  string
		lines []string
	}
	var sections []section

	// ── IDENTITY ──
	var identity []string
	identity = append(identity, kv("Name:", name, inspValue))
	identity = append(identity, kv("Role:", role, inspRoleStyle(role)))
	identity = append(identity, kv("State:", state, inspStateStyle(state)))
	identity = append(identity, kv("Path:", path, inspDim))
	if cand.Proc != nil && strings.TrimSpace(cand.Proc.CmdLine) != "" {
		identity = append(identity, kv("Cmd:", strings.TrimSpace(cand.Proc.CmdLine), inspDim))
	}
	if cand.Proc != nil && strings.TrimSpace(cand.Proc.Company) != "" {
		identity = append(identity, kv("Vendor:", strings.TrimSpace(cand.Proc.Company), inspValue))
	}
	identity = append(identity, kv("Since:", fmt.Sprintf("%ds at current role", cand.SeenSeconds), inspDim))
	sections = append(sections, section{"IDENTITY", identity})

	// ── PROCESS ──
	var proc []string
	proc = append(proc, kvPair("PID:", fmt.Sprintf("%d", pid), inspValue, "Host:", host, inspValue))
	proc = append(proc, kvPair("User:", user, inspValue, "Integrity:", integrity, inspValue))
	parentLabel := parentPID
	if cand.Proc != nil && cand.Proc.ParentPid > 0 {
		for _, pc := range m.app.Candidates {
			if pc.Proc != nil && pc.Proc.Pid == cand.Proc.ParentPid {
				parentLabel += "  " + inspCyan.Render("(p to inspect)")
				break
			}
		}
	}
	proc = append(proc, kvPair("Parent:", parentLabel, inspValue, "Age:", age, inspValue))
	sections = append(sections, section{"PROCESS", proc})

	// ── NETWORK ──
	var network []string
	tcpSummary := fmt.Sprintf("%d in / %d out", cand.InboundTotal, cand.OutTotal)
	if established > 0 {
		tcpSummary += fmt.Sprintf("  (%d established)", established)
	}
	network = append(network, kv("TCP:", tcpSummary, inspValue))
	if len(cand.UDPListeners) > 0 {
		network = append(network, kv("UDP:", fmt.Sprintf("%d listeners", len(cand.UDPListeners)), inspValue))
	}
	if len(cand.Listeners) > 0 {
		ports := make([]string, 0, len(cand.Listeners))
		seen := make(map[int]bool)
		for _, l := range cand.Listeners {
			if l.LocalPort > 0 && !seen[l.LocalPort] {
				seen[l.LocalPort] = true
				scope := "local"
				if shared.IsWildcardIP(l.LocalAddress) {
					scope = "any"
				}
				ports = append(ports, fmt.Sprintf("%d/%s", l.LocalPort, scope))
			}
		}
		if len(ports) > 0 {
			network = append(network, kv("Listen:", strings.Join(ports, ", "), inspValue))
		}
	}
	if cand.RawSocket {
		network = append(network, kv("Raw:", fmt.Sprintf("active (%d sockets)", len(cand.RawConns)), inspWarn))
	}
	if cand.DelegatedEgress {
		owner := cand.DelegatedOwner
		if owner == "" {
			owner = "(unknown)"
		}
		label := owner
		if cand.DelegatedOwnerPID > 0 {
			label = fmt.Sprintf("%s (pid %d)", owner, cand.DelegatedOwnerPID)
		}
		if cand.DelegatedStrong {
			label += "  [strong]"
		}
		network = append(network, kv("Broker:", label, inspWarn))
	}
	// IO
	ioTotal := ioRead + ioWrite + ioOther
	if ioTotal > 0 {
		network = append(network, kv("IO:", FormatIOBytes(ioRead, ioWrite, ioOther), inspValue))
		readPct := float64(ioRead) / float64(ioTotal) * 100
		writePct := float64(ioWrite) / float64(ioTotal) * 100
		network = append(network, "            "+
			lipgloss.NewStyle().Foreground(lipgloss.Color("#5EBC8E")).Render("R ")+sparkGauge(readPct, 12, lipgloss.Color("#5EBC8E"))+" "+inspDim.Render(FormatBytes(ioRead))+
			"   "+
			lipgloss.NewStyle().Foreground(lipgloss.Color("#C9AD5E")).Render("W ")+sparkGauge(writePct, 12, lipgloss.Color("#C9AD5E"))+" "+inspDim.Render(FormatBytes(ioWrite)))
		network = append(network, kv("Rate:", FormatIORate(ioReadRate, ioWriteRate, ioOtherRate), inspValue))
	} else {
		network = append(network, kv("IO:", inspDim.Render("N/A"), inspValue))
	}
	// ASN
	orgs, pending, _ := inspectorExternalOrgs(cand)
	if len(orgs) > 0 {
		for i, org := range orgs {
			if i == 0 {
				network = append(network, kv("ASN:", org, inspValue))
			} else {
				network = append(network, inspLabel.Render("            ")+inspValue.Render(org))
			}
		}
	} else if pending > 0 {
		network = append(network, kv("ASN:", fmt.Sprintf("resolving %d...", pending), inspDim))
	}
	sections = append(sections, section{"NETWORK", network})

	// ── ANALYSIS ──
	var analysis []string
	if cand.ControlChannel != nil {
		cn := cand.ControlChannel
		scope := "external"
		scopeSt := inspWarn
		if shared.IsInternalIP(cn.RemoteAddress) {
			scope = "internal"
			scopeSt = inspCyan
		}
		analysis = append(analysis, kv("Control:", fmt.Sprintf("%s:%d", cn.RemoteAddress, cn.RemotePort), inspAlert))
		analysis = append(analysis, inspLabel.Render("            ")+scopeSt.Render(fmt.Sprintf("%s  |  %ds  |  %s", cn.State, cand.ControlDurationSeconds, scope)))
	}
	if cand.OutLongLived > 0 || cand.OutShortLived > 0 {
		analysis = append(analysis, kv("Duration:", fmt.Sprintf("%d long-lived,  %d short-lived", cand.OutLongLived, cand.OutShortLived), inspValue))
	}
	if cand.TrafficVerified {
		analysis = append(analysis, kv("Verified:", "matches learned baseline", inspDim))
	}
	if len(analysis) > 0 {
		sections = append(sections, section{"ANALYSIS", analysis})
	}

	// ── REASONS ──
	if len(cand.Reasons) > 0 {
		var reasons []string
		for _, reason := range cand.Reasons {
			reasons = append(reasons, "  "+inspWarn.Render(">>")+inspValue.Render(" "+reason))
		}
		sections = append(sections, section{"REASONS", reasons})
	}

	// ── CONNECTIONS ──
	var connLines []string
	type connGroup struct {
		remote string
		state  string
		scope  string
		count  int
	}
	connSeen := make(map[string]struct{})
	var dedupConns []shared.ConnectionInfo
	for _, cn := range cand.Conns {
		scope := ""
		if cn.RemoteAddress != "" && !shared.IsWildcardIP(cn.RemoteAddress) && !shared.IsLoopbackIP(cn.RemoteAddress) {
			if shared.IsInternalIP(cn.RemoteAddress) {
				scope = "internal"
			} else {
				scope = "external"
			}
		}
		local := fmt.Sprintf("%s:%d", cn.LocalAddress, cn.LocalPort)
		remote := fmt.Sprintf("-> %s:%d", cn.RemoteAddress, cn.RemotePort)
		key := fmt.Sprintf("tcp|%s|%s|%s|%s", local, remote, cn.State, scope)
		if _, ok := connSeen[key]; ok {
			continue
		}
		connSeen[key] = struct{}{}
		dedupConns = append(dedupConns, cn)
	}
	grouped := len(dedupConns) > 3

	divider := lipgloss.NewStyle().Foreground(colorFrame)
	if grouped {
		connLines = append(connLines, inspValue.Render(fmt.Sprintf("  %-6s %-26s %-16s %-12s %-8s", "Proto", "Remote", "Count", "State", "Scope")))
		connLines = append(connLines, divider.Render(fmt.Sprintf("  %-6s %-26s %-16s %-12s %-8s", "-----", strings.Repeat("─", 22), strings.Repeat("─", 8), strings.Repeat("─", 9), strings.Repeat("─", 7))))
		groupOrder := make([]string, 0, len(dedupConns))
		groupMap := make(map[string]*connGroup, len(dedupConns))
		for _, cn := range dedupConns {
			scope := ""
			if cn.RemoteAddress != "" && !shared.IsWildcardIP(cn.RemoteAddress) && !shared.IsLoopbackIP(cn.RemoteAddress) {
				if shared.IsInternalIP(cn.RemoteAddress) {
					scope = "internal"
				} else {
					scope = "external"
				}
			}
			remote := fmt.Sprintf("%s:%d", cn.RemoteAddress, cn.RemotePort)
			gk := fmt.Sprintf("%s|%s|%s", remote, cn.State, scope)
			if g, ok := groupMap[gk]; ok {
				g.count++
			} else {
				groupMap[gk] = &connGroup{remote: remote, state: cn.State, scope: scope, count: 1}
				groupOrder = append(groupOrder, gk)
			}
		}
		for _, gk := range groupOrder {
			g := groupMap[gk]
			countLabel := fmt.Sprintf("%d connections", g.count)
			if g.count == 1 {
				countLabel = "1 connection"
			}
			connLines = append(connLines, inspValue.Render(fmt.Sprintf("  %-6s", "TCP"))+
				inspDim.Render(fmt.Sprintf(" %-26s", g.remote))+
				bodyText.Render(fmt.Sprintf(" %-16s", countLabel))+
				inspConnStateStyle(g.state).Render(fmt.Sprintf(" %-12s", g.state))+
				inspScopeStyle(g.scope).Render(fmt.Sprintf(" %-8s", g.scope)))
		}
	} else {
		connLines = append(connLines, inspValue.Render(fmt.Sprintf("  %-6s %-22s %-22s %-12s %-8s", "Proto", "Local", "Remote", "State", "Scope")))
		connLines = append(connLines, divider.Render(fmt.Sprintf("  %-6s %-22s %-22s %-12s %-8s", "-----", strings.Repeat("─", 22), strings.Repeat("─", 22), strings.Repeat("─", 9), strings.Repeat("─", 7))))
		for _, cn := range dedupConns {
			scope := ""
			if cn.RemoteAddress != "" && !shared.IsWildcardIP(cn.RemoteAddress) && !shared.IsLoopbackIP(cn.RemoteAddress) {
				if shared.IsInternalIP(cn.RemoteAddress) {
					scope = "internal"
				} else {
					scope = "external"
				}
			}
			local := fmt.Sprintf("%s:%d", cn.LocalAddress, cn.LocalPort)
			remote := fmt.Sprintf("-> %s:%d", cn.RemoteAddress, cn.RemotePort)
			connLines = append(connLines, inspValue.Render(fmt.Sprintf("  %-6s", "TCP"))+
				inspDim.Render(fmt.Sprintf(" %-22s", local))+
				bodyText.Render(fmt.Sprintf(" %-22s", remote))+
				inspConnStateStyle(cn.State).Render(fmt.Sprintf(" %-12s", cn.State))+
				inspScopeStyle(scope).Render(fmt.Sprintf(" %-8s", scope)))
		}
	}
	for _, ul := range cand.UDPListeners {
		local := fmt.Sprintf("%s:%d", ul.LocalAddress, ul.LocalPort)
		scope := shared.ScopeLabelForLocalAddress(ul.LocalAddress)
		key := fmt.Sprintf("udp|%s|%s", local, scope)
		if _, ok := connSeen[key]; ok {
			continue
		}
		connSeen[key] = struct{}{}
		connLines = append(connLines, inspValue.Render(fmt.Sprintf("  %-6s", "UDP"))+
			inspDim.Render(fmt.Sprintf(" %-22s", local))+
			inspDim.Render(fmt.Sprintf(" %-22s", "*:*"))+
			inspConnStateStyle("LISTEN").Render(fmt.Sprintf(" %-12s", "LISTEN"))+
			inspScopeStyle(scope).Render(fmt.Sprintf(" %-8s", scope)))
	}
	// Show raw/packet socket entries for processes with raw sockets.
	for _, rc := range cand.RawConns {
		scope := ""
		remote := rc.Remote
		if remote == "" || remote == "*" || remote == "0.0.0.0" {
			remote = "*"
		} else if shared.IsInternalIP(remote) {
			scope = "internal"
		} else {
			scope = "external"
		}
		connLines = append(connLines,
			inspValue.Render(fmt.Sprintf("  %-6s", "RAW"))+
				inspDim.Render(fmt.Sprintf(" %-22s", rc.Local))+
				inspWarn.Render(fmt.Sprintf(" %-22s", remote))+
				inspConnStateStyle(rc.State).Render(fmt.Sprintf(" %-12s", rc.State))+
				inspScopeStyle(scope).Render(fmt.Sprintf(" %-8s", scope)))
	}
	if len(connLines) > 0 {
		sections = append(sections, section{"CONNECTIONS", connLines})
	}

	// Render all sections as orange boxes.
	var boxOut []string
	sectionStarts := make([]int, 0, len(sections))
	row := 0
	for _, sec := range sections {
		sectionStarts = append(sectionStarts, row)
		content := strings.Join(sec.lines, "\n")
		h := len(sec.lines) + 2
		panel := renderAccentPanel(w, h, sec.name, content)
		boxOut = append(boxOut, panel)
		row += h
	}
	m.app.InspectSectionStarts = sectionStarts

	return strings.Join(boxOut, "\n")
}
