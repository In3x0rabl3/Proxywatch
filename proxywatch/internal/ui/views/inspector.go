package views

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/gdamore/tcell/v2"

	"proxywatch/internal/detection"
	"proxywatch/internal/detection/model"
	"proxywatch/internal/shared"
)

// InspectorModel is the native bubbletea model for the Inspector (process detail) view.
type InspectorModel struct {
	app         *shared.AppState
	viewport    viewport.Model
	width       int
	height      int
	ready       bool
	contentKey  uint64
	lastRefresh time.Time
}

func NewInspectorModel(app *shared.AppState) InspectorModel {
	return InspectorModel{app: app}
}

func (m InspectorModel) Init() tea.Cmd { return nil }

func (m InspectorModel) Update(msg tea.Msg) (InspectorModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.InitViewport()
		m.RefreshContent()

	case tea.KeyMsg:
		tev := convertKeyMsg(msg)

		handled, shouldQuit := handleQuitConfirmKey(m.app, tev)
		if handled {
			if shouldQuit {
				return m, tea.Quit
			}
			return m, nil
		}

		switch tev.Key() {
		case tcell.KeyLeft:
			cycleInspectProcess(m.app, -1)
			m.RefreshContent()
			if m.ready {
				m.viewport.GotoTop()
			}
			return m, nil
		case tcell.KeyRight:
			cycleInspectProcess(m.app, 1)
			m.RefreshContent()
			if m.ready {
				m.viewport.GotoTop()
			}
			return m, nil
		}

		if m.ready && !m.app.ShowInspectMenu {
			if m.handleScroll(tev) {
				return m, nil
			}
		}

		if handleInspectKey(m.app, tev) {
			return m, tea.Quit
		}
	}

	m.RefreshContent()
	return m, nil
}

func (m *InspectorModel) handleScroll(tev *tcell.EventKey) bool {
	if !m.ready {
		return false
	}
	switch tev.Key() {
	case tcell.KeyUp:
		m.viewport.ScrollUp(1)
		return true
	case tcell.KeyDown:
		m.viewport.ScrollDown(1)
		return true
	case tcell.KeyPgUp:
		m.viewport.ScrollUp(m.viewport.VisibleLineCount())
		return true
	case tcell.KeyPgDn:
		m.viewport.ScrollDown(m.viewport.VisibleLineCount())
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
		m.viewport.ScrollUp(1)
		return true
	case ']':
		m.viewport.ScrollDown(1)
		return true
	}
	return false
}

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

	if m.app.ConfirmKill && m.app.ConfirmKillKey == m.app.InspectKey && time.Now().Before(m.app.ConfirmKillDeadline) {
		msg := fmt.Sprintf("Confirm kill: press k again or y within %s", m.app.ConfirmKillTimeout)
		view += "\n" + sevWatch.Render("  "+msg)
	}

	if m.app.LastError != "" {
		view += "\n" + statusFail.Render("  "+m.app.LastError)
	}

	if m.app.ShowQuitConfirm && m.app.QuitConfirmDeadline.After(time.Now()) {
		quitPanel := renderQuitConfirm(m.app.QuitConfirmDeadline, w)
		view = overlayCenter(view, quitPanel, w, m.height)
	}

	return view
}

func (m InspectorModel) renderHeader() string {
	w := m.width
	if w <= 0 {
		w = 80
	}
	contentW := w - 2
	helpPlain := "? menu   esc dashboard   q quit"
	utcPlain := "UTC: " + time.Now().UTC().Format(UTCTimeFormat)
	gap := max(1, contentW-len(helpPlain)-len(utcPlain))
	headerContent := dimText.Render(helpPlain) + bgSp(gap) +
		rightLabelStyle.Render("UTC: ") + sectionLabel.Render(time.Now().UTC().Format(UTCTimeFormat))
	return renderPanel(w, 3, "Inspector", "proxywatch", "", headerContent)
}

func (m *InspectorModel) InitViewport() {
	if m.width <= 0 || m.height <= 0 {
		return
	}
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

func (m *InspectorModel) RefreshContent() {
	if !m.ready {
		return
	}
	now := time.Now()
	stateChange := m.app.ShowQuitConfirm || m.app.LastError != ""
	if !stateChange && !m.lastRefresh.IsZero() && now.Sub(m.lastRefresh) < 2*time.Second {
		return
	}
	content := m.buildContent()
	h := quickHash(content)
	if h != m.contentKey {
		m.contentKey = h
		m.viewport.SetContent(content)
		m.lastRefresh = now
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

func inspRoleStyle(role string) lipgloss.Style {
	switch shared.RoleFamily(role) {
	case "control-channel":
		return inspSession
	case "control-pivot":
		return inspPivot
	default:
		return inspValue
	}
}

func inspStateStyle(state string) lipgloss.Style {
	switch state {
	case "tunneling":
		return inspAlert
	case "exited":
		return inspDim
	default: // "watch"
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

	role := shared.RoleFamily(cand.Role)
	role = normalizeDashboardRole(role)
	state := "watch"
	state = shared.CandidateState(*cand)

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

	w := m.width - 4
	if w < 20 {
		w = 20
	}
	kv := func(label, value string, vs lipgloss.Style) string {
		return inspLabel.Render(fmt.Sprintf("  %-10s", label)) + vs.Render(value)
	}
	const rightColStart = 34
	kvPair := func(l1, v1 string, s1 lipgloss.Style, l2, v2 string, s2 lipgloss.Style) string {
		left := inspLabel.Render(fmt.Sprintf("  %-10s", l1)) + s1.Render(v1)
		leftW := lipgloss.Width(left)
		pad := rightColStart - leftW
		if pad < 2 {
			pad = 2
		}
		right := inspLabel.Render(fmt.Sprintf("%-12s", l2)) + s2.Render(v2)
		return left + strings.Repeat(" ", pad) + right
	}

	type section struct {
		name  string
		lines []string
	}
	var sections []section

	// IDENTITY
	var identity []string
	identity = append(identity, kv("Name:", name, inspValue))
	roleDisplay := role
	if cand.ControlSubtype != "" && role == "control-pivot" {
		roleDisplay = role + " (" + cand.ControlSubtype + ")"
	}
	identity = append(identity, kv("Role:", roleDisplay, inspRoleStyle(role)))
	if cand.Exited {
		identity = append(identity, kv("State:", "exited", inspDim))
	} else {
		identity = append(identity, kv("State:", state, inspStateStyle(state)))
	}
	identity = append(identity, kv("Path:", path, inspDim))
	if cand.Proc != nil && strings.TrimSpace(cand.Proc.CmdLine) != "" {
		identity = append(identity, kv("Cmd:", strings.TrimSpace(cand.Proc.CmdLine), inspDim))
	}
	if cand.Proc != nil && strings.TrimSpace(cand.Proc.Company) != "" {
		identity = append(identity, kv("Vendor:", strings.TrimSpace(cand.Proc.Company), inspValue))
	}
	identity = append(identity, kv("Since:", fmt.Sprintf("%ds at current role", cand.SeenSeconds), inspDim))
	sections = append(sections, section{"IDENTITY", identity})

	// PROCESS
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

	// NETWORK
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
	if cand.Proc != nil && len(cand.Proc.LoadedLibs) > 0 {
		libs := cand.Proc.LoadedLibs
		if len(libs) > 5 {
			libs = libs[:5]
		}
		network = append(network, kv("Libs:", strings.Join(libs, ", "), inspDim))
	}
	sections = append(sections, section{"NETWORK", network})

	// CONTOUR — egress intelligence from contour probes, shown as a separate
	// section so operators can distinguish probe-verified findings from
	// signal-based analysis.
	{
		var contourLines []string
		egressSigs, _, _ := model.EgressSignals(cand.Conns)
		for _, sig := range egressSigs {
			label := "tunnel-capable"
			if strings.Contains(sig, "exfil") {
				label = "exfil-capable"
			}
			contourLines = append(contourLines, kv("Egress:", label+" (contour confirmed)", inspValue))
		}
		// Pull contour reasons from the candidate's reasons list.
		for _, reason := range cand.Reasons {
			if strings.Contains(reason, "contour") || strings.Contains(reason, "Contour") {
				contourLines = append(contourLines, kv("Finding:", reason, inspValue))
			}
		}
		if len(contourLines) > 0 {
			sections = append(sections, section{"CONTOUR", contourLines})
		}
	}

	// EVIDENCE — combines structured signal findings with scoring reasons.
	// Formatted like the MODEL box (label:value style). Capped at 6 items.
	{
		type evidenceLine struct {
			label string
			value string
			style lipgloss.Style
		}
		var lines []evidenceLine

		sigSet := make(map[string]bool, len(cand.Signals))
		for _, s := range cand.Signals {
			sigSet[s] = true
		}
		isSuspicious := strings.HasPrefix(role, "control-")

		_ = isSuspicious // used by signal-driven evidence below

		// Special formatted evidence (always shown first if applicable).
		if cand.ControlChannel != nil {
			cn := cand.ControlChannel
			dest := fmt.Sprintf("%s:%d", cn.RemoteAddress, cn.RemotePort)
			if cand.ControlDurationSeconds >= 60 {
				lines = append(lines, evidenceLine{"Persistent control", fmt.Sprintf("%s held %dm%ds", dest, cand.ControlDurationSeconds/60, cand.ControlDurationSeconds%60), inspValue})
			} else if cand.ControlDurationSeconds > 0 {
				lines = append(lines, evidenceLine{"Active connection", fmt.Sprintf("%s for %ds", dest, cand.ControlDurationSeconds), inspValue})
			}
		}
		beaconMs := cand.BeaconIntervalMs
		beaconJitter := cand.BeaconJitter
		if beaconMs == 0 && cand.Proc != nil {
			if bp := model.ResolveProfile(detection.ProcessBehaviorKey(cand)); bp != nil && bp.BeaconIntervalMs > 0 {
				beaconMs = bp.BeaconIntervalMs
				beaconJitter = bp.BeaconJitter
			}
		}
		if beaconMs > 0 {
			intervalSec := float64(beaconMs) / 1000.0
			var intervalStr string
			if intervalSec >= 60 {
				intervalStr = fmt.Sprintf("%.0fm%.0fs", intervalSec/60, float64(int(intervalSec)%60))
			} else {
				intervalStr = fmt.Sprintf("%.1fs", intervalSec)
			}
			jitterStr := fmt.Sprintf("%.0f%%", beaconJitter*100)
			lines = append(lines, evidenceLine{"Callback", fmt.Sprintf("%s interval, %s jitter", intervalStr, jitterStr), inspAlert})
		}

		// Signal-driven evidence: pick up to 3 network + 3 host signals.
		// Each signal maps to a human-readable label + description.
		type evidenceMapping struct {
			signal string
			label  string
			desc   string
			isHost bool
		}
		mappings := []evidenceMapping{
			// Network signals
			{"beacon-interval-confirmed", "Callback timing", "Periodic callback with measured interval", false},
			{"beacon-syn-cycle-cadence", "SYN cycling", "Repeated failed connection attempts (C2 may be down)", false},
			{"beacon-target-lock", "Target locked", "All connections to single remote endpoint", false},
			{"beacon-http-channel", "HTTP channel", "All callbacks over HTTP/HTTPS", false},
			{"beacon-endpoint-rotation", "C2 rotation", "Multiple IPs contacted on same port (failover)", false},
			{"session-control-channel-persistent", "Persistent control", "Long-held external control channel", false},
			{"session-single-target-persistence", "Pinned target", "Traffic pinned to stable remote target", false},
			{"session-conn-churn", "Connection churn", "Repeated connect/disconnect pattern", false},
			{"session-exfil-write-heavy", "Exfiltration shape", "Write-heavy outbound data flow", false},
			{"session-asn-mismatch", "ASN mismatch", "Destination doesn't match vendor network", false},
			{"pivot-listener-plus-outbound", "Relay shape", "Listener accepting + forwarding traffic", false},
			{"pivot-loopback-listener-external-out", "SOCKS shape", "Loopback listener with external outbound", false},
			{"pivot-multiplex-relay", "Multiplex relay", "External channel relaying to internal targets", false},
			{"pivot-throughput-symmetry", "Relay symmetry", "Balanced read/write throughput (forwarding)", false},
			{"pivot-socks-candidate", "SOCKS proxy", "Loopback listener with diverse destinations", false},
			{"outbound-standard-ports-only", "Standard ports", "All connections on HTTP/HTTPS only", false},
			{"outbound-asn-org-aligned", "ASN aligned", "Destination matches vendor network", false},
			{"outbound-cdn-destination", "CDN traffic", "Connecting to CDN infrastructure", false},
			{"listener-wildcard-bind", "Wildcard bind", "Listening on all interfaces (0.0.0.0)", false},
			{"listener-inbound-external", "External inbound", "Accepting connections from outside", false},
			// Host signals
			{"beacon-sleep-wake-cycle", "Dormant implant", "Long sleep intervals with brief activity", true},
			{"beacon-micro-payload", "Micro payload", "Tiny data exchange despite long runtime", true},
			{"beacon-low-cpu-long-life", "Low CPU", "Long-lived process with near-zero CPU usage", true},
			{"beacon-no-children", "No children", "Never spawns child processes", true},
			{"beacon-crypto-lib-loaded", "Crypto loaded", "Encryption library loaded with minimal IO", true},
			{"session-shell-spawn", "Shell spawned", "Spawned interactive shell processes", true},
			{"session-lolbin-children", "LOLBin children", "Spawned system binary child processes", true},
			{"session-elevated-external", "Elevated C2", "SYSTEM/High integrity with external connection", true},
			{"session-encoding-in-cmdline", "Encoded cmdline", "Base64/encoded command in command line", true},
			{"session-bursty-io-pattern", "Bursty IO", "Command → output → idle pattern", true},
			{"session-rare-parent-network", "Rare parent", "Unusual parent-child chain with network", true},
			{"session-covert-channel", "Covert channel", "IO activity without visible connections", true},
			{"session-rwx-memory", "RWX memory", "Read-write-execute memory regions detected", true},
			{"session-impersonation-token", "Impersonation", "Impersonation token detected", true},
			{"pivot-named-pipe-c2-pattern", "C2 named pipe", "Named pipe matching C2 framework pattern", true},
			{"pivot-admin-share-smb", "Admin SMB", "Accessing admin share pipes (srvsvc/svcctl)", true},
			{"pivot-ssh-tunnel-flags", "SSH tunnel", "Tunnel flags in command line (-L/-R/-D)", true},
			{"pivot-proxy-lib-loaded", "Proxy library", "Proxy/tunnel library loaded", true},
			{"pivot-elevated-relay", "Elevated relay", "SYSTEM integrity relaying to internal targets", true},
			{"pivot-anon-exec-memory", "Anon exec mem", "Anonymous executable memory (reflective loading)", true},
			{"outbound-known-vendor", "Known vendor", "Recognized software publisher", true},
			{"outbound-system-path", "System path", "Running from protected OS directory", true},
			{"outbound-download-heavy", "Download heavy", "95%+ read ratio (downloading)", true},
			{"listener-service-context", "Service context", "Running as system service", true},
			{"listener-long-idle", "Long idle", "Listening but minimal activity", true},
			{"listener-named-pipe-server", "Pipe server", "Serving named pipes", true},
		}

		netCount, hostCount := 0, 0
		for _, em := range mappings {
			if !sigSet[em.signal] {
				continue
			}
			if em.isHost && hostCount >= 3 {
				continue
			}
			if !em.isHost && netCount >= 3 {
				continue
			}
			style := inspValue
			if em.isHost {
				style = inspSession
				hostCount++
			} else {
				netCount++
			}
			lines = append(lines, evidenceLine{em.label, em.desc, style})
			if netCount >= 3 && hostCount >= 3 {
				break
			}
		}

		// Publisher info for context.
		if cand.Proc != nil && strings.TrimSpace(cand.Proc.Company) != "" {
			lines = append(lines, evidenceLine{"Known publisher", strings.TrimSpace(cand.Proc.Company), inspSession})
		}

		// Categorize reasons into host-based vs network-based, pick 3 of each.
		// Host keywords: library, command, proxy flags, raw socket, parent, memory,
		//   child, shell, script, encoded, integrity, CPU, thread, pipe, module.
		// Network keywords: connection, port, outbound, inbound, listener, SMB,
		//   SSH, control, channel, target, DNS, proxy, tunnel, relay, beacon.
		var netReasons, hostReasons []string
		for _, reason := range cand.Reasons {
			r := strings.ToLower(reason)
			if strings.Contains(r, "contour") || strings.Contains(r, "model:") ||
				strings.Contains(r, "experience consensus") || strings.Contains(r, "user-writable") ||
				strings.Contains(r, "de-emphasized") || strings.Contains(r, "baseline") ||
				strings.Contains(r, "verified destinations") {
				continue
			}
			isHost := strings.Contains(r, "library") || strings.Contains(r, "command line") ||
				strings.Contains(r, "proxy/tunnel flags") || strings.Contains(r, "raw socket") ||
				strings.Contains(r, "parent") || strings.Contains(r, "memory") ||
				strings.Contains(r, "child") || strings.Contains(r, "shell") ||
				strings.Contains(r, "script") || strings.Contains(r, "encoded") ||
				strings.Contains(r, "integrity") || strings.Contains(r, "module") ||
				strings.Contains(r, "pipe")
			if isHost {
				hostReasons = append(hostReasons, reason)
			} else {
				netReasons = append(netReasons, reason)
			}
		}
		netR, hostR := 0, 0
		for _, reason := range netReasons {
			if netR >= 3 {
				break
			}
			lines = append(lines, evidenceLine{"Reason", reason, inspValue})
			netR++
		}
		for _, reason := range hostReasons {
			if hostR >= 3 {
				break
			}
			lines = append(lines, evidenceLine{"Reason", reason, inspSession})
			hostR++
		}

		// When signal debug is OFF, cap at 6 curated items.
		// When ON, show all curated items + raw signal list.
		if !m.app.InspectShowAllSignals {
			if len(lines) > 6 {
				lines = lines[:6]
			}
		}

		var evidence []string
		for _, line := range lines {
			evidence = append(evidence, kv(line.label+":", line.value, line.style))
		}

		// Signal debug mode: append ALL raw signals from the candidate.
		if m.app.InspectShowAllSignals && len(cand.Signals) > 0 {
			evidence = append(evidence, kv("", "── Signals (x to hide) ──", inspDim))
			for _, sig := range cand.Signals {
				// Color-code by role prefix.
				style := inspDim
				switch {
				case strings.HasPrefix(sig, "beacon-"):
					style = inspAlert
				case strings.HasPrefix(sig, "session-"):
					style = inspSession
				case strings.HasPrefix(sig, "pivot-"):
					style = inspValue
				case strings.HasPrefix(sig, "outbound-"):
					style = inspCyan
				case strings.HasPrefix(sig, "listener-"):
					style = inspDim
				}
				evidence = append(evidence, kv("Signal:", sig, style))
			}
		}

		if len(evidence) == 0 {
			evidence = append(evidence, kv("Status:", "No evidence collected yet", inspDim))
		}
		sectionName := "EVIDENCE"
		if m.app.InspectShowAllSignals {
			sectionName = "EVIDENCE (debug)"
		}
		sections = append(sections, section{sectionName, evidence})
	}

	// MODEL
	{
		var modelLines []string
		// Don't call FlushExperience from UI — it acquires mu.Lock and
		// contends with the classifier background thread, causing freezes.
		dm := model.Get()

		if dm != nil && cand.Proc != nil {
			key := detection.ProcessBehaviorKey(cand)
			userVerdict, _, _ := model.ProcessVerdict(key)
			expProfile := model.ResolveProfile(key)
			trainLabel := model.GetTrainingLabel(key)

			// ML vs Rule — always show both perspectives, even when they agree.
			// This makes it clear what each subsystem decided and whether they
			// reinforce or conflict. When they differ, the signal override
			// (classifier.go) chose one — visible in the final Role field above.
			ruleRole := cand.SuggestedRole
			if ruleRole == "" {
				ruleRole = shared.InferRoleFromSignals(cand.Signals, cand.ControlSubtype, cand.Role)
			}
			// Rule label shows the committed role suffix when rules were
			// overridden downstream (demoted by shape-only guard, signal
			// override, etc.). Prevents the confusing case where Rule
			// says "control-channel" but the process is labeled
			// "outbound" — now it reads "control-channel → outbound".
			ruleLabel := ruleRole
			if ruleRole != "" && cand.Role != "" && ruleRole != cand.Role {
				ruleLabel = ruleRole + " → " + cand.Role
			}
			if cand.MLActive && cand.MLRole != "" {
				mlConfPct := int(cand.MLConfidence * 100)
				mlStyle := inspDim
				if mlConfPct >= 60 {
					mlStyle = inspValue
				} else if mlConfPct <= 30 {
					mlStyle = inspWarn
				}
				modelLines = append(modelLines, kv("ML:", fmt.Sprintf("%s (%d%%)", cand.MLRole, mlConfPct), mlStyle))
				if ruleLabel != "" {
					modelLines = append(modelLines, kv("Rule:", ruleLabel, inspDim))
				}
			} else if ruleLabel != "" {
				// No ML prediction — show rule engine suggestion only.
				modelLines = append(modelLines, kv("ML:", "(no prediction)", inspDim))
				modelLines = append(modelLines, kv("Rule:", ruleLabel, inspDim))
			}

			// Decision reasoning — collect all model-related reasons into a
			// single multi-line entry to avoid repeating the "Reasoning:"
			// label. A process often has multiple "model:" reasons (role
			// decision + beacon timing + experience stats).
			var reasoningParts []string
			for _, reason := range cand.Reasons {
				r := strings.ToLower(reason)
				if strings.Contains(r, "model:") || strings.Contains(r, "experience consensus") {
					display := reason
					if strings.HasPrefix(strings.ToLower(display), "model: ") {
						display = display[7:]
					} else if strings.HasPrefix(strings.ToLower(display), "model:") {
						display = display[6:]
					}
					reasoningParts = append(reasoningParts, display)
				}
			}
			if len(reasoningParts) > 0 {
				modelLines = append(modelLines, kv("Reasoning:", strings.Join(reasoningParts, " · "), inspValue))
			}

			// Observations and experience.
			if expProfile != nil && expProfile.ExperienceObservations > 0 {
				dominant := expProfile.DominantRole
				if dominant == "" {
					dominant = "unknown"
				}
				modelLines = append(modelLines, kv("Observations:", fmt.Sprintf("%d", expProfile.ExperienceObservations), inspValue))

				// Beacon timing — show callback interval and jitter if detected.
				if expProfile.BeaconIntervalMs > 0 {
					intervalSec := float64(expProfile.BeaconIntervalMs) / 1000.0
					var intervalStr string
					if intervalSec >= 60 {
						intervalStr = fmt.Sprintf("%.0fm%.0fs", intervalSec/60, float64(int(intervalSec)%60))
					} else {
						intervalStr = fmt.Sprintf("%.1fs", intervalSec)
					}
					jitterStr := fmt.Sprintf("%.0f%%", expProfile.BeaconJitter*100)
					modelLines = append(modelLines, kv("Callback:", fmt.Sprintf("%s interval, %s jitter", intervalStr, jitterStr), inspAlert))
				} else if cand.BeaconIntervalMs > 0 {
					intervalSec := float64(cand.BeaconIntervalMs) / 1000.0
					var intervalStr string
					if intervalSec >= 60 {
						intervalStr = fmt.Sprintf("%.0fm%.0fs", intervalSec/60, float64(int(intervalSec)%60))
					} else {
						intervalStr = fmt.Sprintf("%.1fs", intervalSec)
					}
					jitterStr := fmt.Sprintf("%.0f%%", cand.BeaconJitter*100)
					modelLines = append(modelLines, kv("Callback:", fmt.Sprintf("%s interval, %s jitter", intervalStr, jitterStr), inspAlert))
				}
			} else {
				modelLines = append(modelLines, kv("Observations:", "collecting initial data", inspDim))
			}

			// Operator feedback.
			if trainLabel != "" {
				modelLines = append(modelLines, kv("Label:", trainLabel+" (t to change)", inspAlert))
			}
			if userVerdict != "" {
				verdictStyle := inspDim
				switch userVerdict {
				case "malicious":
					verdictStyle = inspAlert
				case "benign":
					verdictStyle = inspCyan
				case "contested":
					verdictStyle = inspWarn
				}
				modelLines = append(modelLines, kv("Verdict:", userVerdict, verdictStyle))
			}
			if expProfile != nil && (expProfile.KillCount > 0 || expProfile.WhitelistCount > 0) {
				modelLines = append(modelLines, kv("Feedback:", fmt.Sprintf("%d kills, %d whitelists", expProfile.KillCount, expProfile.WhitelistCount), inspDim))
			}

			// Per-process learning state.
			if expProfile != nil {
				obs := expProfile.ExperienceObservations
				stab := expProfile.RoleStability
				procState := "analyzing"
				procStyle := inspDim
				switch {
				case obs < 30:
					procState = "analyzing"
				case obs < 200 || stab < 0.50:
					procState = "learning"
					procStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#D19A66")).Background(colorBg)
				default:
					procState = fmt.Sprintf("monitoring (%d obs)", obs)
					procStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#56B6C2")).Background(colorBg)
				}
				// Never say "confirmed" — any process can be compromised at any time.
				modelLines = append(modelLines, kv("Status:", procState, procStyle))
			}
		}

		if len(modelLines) > 0 {
			sections = append(sections, section{"MODEL", modelLines})
		}
	}

	// CONNECTIONS
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
