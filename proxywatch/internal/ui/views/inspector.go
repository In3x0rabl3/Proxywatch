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
	"proxywatch/internal/ui/common"
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
	sections = append(sections, m.renderBottomBar(w))

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
	return shellBanner(w)
}

// renderBottomBar draws the inspector's bottom nav bar (mirrors the dashboard).
func (m InspectorModel) renderBottomBar(w int) string {
	line := bgSp(1) + dimText.Render("esc dashboard    tab section    ← → prev / next    ? menu")
	if pad := w - lipgloss.Width(line); pad > 0 {
		line += bgSp(pad)
	}
	return line
}

// inspectorReserved is the number of rows consumed by the flat header (identity
// line + nav line + rule) plus a bottom margin — everything that is not the
// scrolling body.
func inspectorReserved(w int) int {
	return shellBannerHeight(w) + 2 // banner + bottom bar + margin
}

func (m *InspectorModel) InitViewport() {
	if m.width <= 0 || m.height <= 0 {
		return
	}
	bodyH := m.height - inspectorReserved(m.width)
	if bodyH < 4 {
		bodyH = 4
	}
	if !m.ready {
		m.viewport = viewport.New(m.width, bodyH)
		m.viewport.Style = lipgloss.NewStyle()
		m.ready = true
	} else {
		m.viewport.Width = m.width
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
	if !m.ready {
		return ""
	}
	body := m.viewport.View()

	// Thin scroll indicator, only when the content overflows.
	total := m.viewport.TotalLineCount()
	visible := m.viewport.VisibleLineCount()
	if total > visible {
		label := fmt.Sprintf("%d-%d of %d", m.viewport.YOffset+1, min(m.viewport.YOffset+visible, total), total)
		ind := lipgloss.NewStyle().Foreground(common.ColorMuted).Background(common.ColorBg).Render(label)
		pad := m.width - lipgloss.Width(ind) - 1
		if pad < 0 {
			pad = 0
		}
		body += "\n" + bgSp(pad) + ind
	}
	return body
}

func inspScopeStyle(scope string) lipgloss.Style {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "external":
		return inspWarn
	default:
		return inspLabel
	}
}

// connStateRank orders TCP connection states by "liveness" so the
// inspector's CONNECTIONS panel can collapse same-tuple entries with
// mixed states to a single row, displaying the most active state.
// Higher rank wins.
func connStateRank(state string) int {
	switch strings.ToUpper(strings.TrimSpace(state)) {
	case "ESTABLISHED":
		return 5
	case "SYN_SENT", "SYN_RECEIVED":
		return 4
	case "FIN_WAIT", "FIN_WAIT_1", "FIN_WAIT_2":
		return 3
	case "TIME_WAIT", "LAST_ACK":
		return 2
	case "CLOSE_WAIT", "CLOSING":
		return 1
	default:
		return 0
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

	name := "(unknown)"
	pid := 0
	if cand.Proc != nil {
		name = shared.DisplayProcessName(cand.Proc)
		pid = cand.Proc.Pid
	}
	host := shared.DisplayHost(cand.Host)
	age := "+000s"
	ageSeconds := dashboardCandidateAgeSeconds(*cand)
	if ageSeconds > 0 {
		age = formatTacticalAge(ageSeconds)
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

	// Every box spans the full terminal width, stacked one per row (matching the
	// dashboard's full-width table).
	colW := m.width
	if colW < 24 {
		colW = 24
	}
	// Military-style formatting with dot leaders for alignment
	val := lipgloss.NewStyle().Foreground(common.ColorText).Background(common.ColorBg)
	dimVal := lipgloss.NewStyle().Foreground(common.ColorDim).Background(common.ColorBg)
	const labelW = 12 // fixed uppercase label column with dot leaders
	ul := func(label string) string {
		return strings.ToUpper(label)
	}
	// kv renders label with dot leaders and value
	kv := func(label, value string, _ lipgloss.Style) string {
		labelText := ul(label)
		dotsNeeded := labelW - len(labelText)
		if dotsNeeded < 1 {
			dotsNeeded = 1
		}
		lab := fmt.Sprintf("  %s%s ", labelText, strings.Repeat(".", dotsNeeded))
		avail := (colW - 2) - lipgloss.Width(lab)
		if avail < 6 {
			avail = 6
		}
		return inspLabel.Render(lab) + val.Render(TruncateToWidth(value, avail))
	}
	// kvDim renders with dimmed value (for zero/empty values)
	kvDim := func(label, value string) string {
		labelText := ul(label)
		dotsNeeded := labelW - len(labelText)
		if dotsNeeded < 1 {
			dotsNeeded = 1
		}
		lab := fmt.Sprintf("  %s%s ", labelText, strings.Repeat(".", dotsNeeded))
		avail := (colW - 2) - lipgloss.Width(lab)
		if avail < 6 {
			avail = 6
		}
		return inspLabel.Render(lab) + dimVal.Render(TruncateToWidth(value, avail))
	}

	type section struct {
		name  string
		lines []string
	}
	var sections []section

	// IDENTITY — full process identity (name/PID/host/user/role/state) plus the
	// process facts. There is no separate TARGET box; this is the primary box.
	userShort := user
	if i := strings.LastIndex(userShort, "\\"); i >= 0 {
		userShort = userShort[i+1:]
	}
	parentLabel := parentPID
	if cand.Proc != nil && cand.Proc.ParentPid > 0 {
		for _, pc := range m.app.Candidates {
			if pc.Proc != nil && pc.Proc.Pid == cand.Proc.ParentPid {
				pname := strings.ToUpper(pc.Proc.Name)
				if pname != "" {
					parentLabel = fmt.Sprintf("%s → %s", pname, parentPID)
				}
				parentLabel += "  " + inspCyan.Render("(p to inspect)")
				break
			}
		}
	}

	var identity []string
	identity = append(identity, kv("NAME:", name, inspValue))
	identity = append(identity, kv("PID:", fmt.Sprintf("%d", pid), inspValue))
	identity = append(identity, kv("PARENT:", parentLabel, inspValue))
	identity = append(identity, kv("USER:", userShort, inspValue))
	identity = append(identity, kv("HOST:", host, inspValue))
	identity = append(identity, kv("AGE:", age, inspValue))
	identity = append(identity, kv("PATH:", path, inspValue))
	if cand.Proc != nil && strings.TrimSpace(cand.Proc.CmdLine) != "" {
		identity = append(identity, kv("CMD:", strings.TrimSpace(cand.Proc.CmdLine), inspValue))
	}
	if cand.Proc != nil && strings.TrimSpace(cand.Proc.Company) != "" {
		identity = append(identity, kv("VENDOR:", strings.TrimSpace(cand.Proc.Company), inspValue))
	}
	if integrity != "(unknown)" {
		identity = append(identity, kv("INTEGRITY:", integrity, inspValue))
	}
	sections = append(sections, section{"IDENTITY", identity})

	// NETWORK
	var network []string
	// Compact TCP summary with arrows
	tcpSummary := fmt.Sprintf("%d↓ %d↑", cand.InboundTotal, cand.OutTotal)
	if established > 0 {
		tcpSummary += fmt.Sprintf(" (%d est)", established)
	}
	network = append(network, kv("TCP:", tcpSummary, inspValue))
	// Listeners as port badges
	if len(cand.Listeners) > 0 {
		var portBadges []string
		seen := make(map[int]bool)
		for _, l := range cand.Listeners {
			if l.LocalPort > 0 && !seen[l.LocalPort] {
				seen[l.LocalPort] = true
				portBadges = append(portBadges, fmt.Sprintf("[%d]", l.LocalPort))
			}
		}
		if len(portBadges) > 0 {
			network = append(network, kv("LISTEN:", strings.Join(portBadges, " "), inspValue))
		}
	}
	if len(cand.UDPListeners) > 0 {
		network = append(network, kv("UDP:", fmt.Sprintf("%d listeners", len(cand.UDPListeners)), inspValue))
	}
	if cand.RawSocket {
		network = append(network, kv("RAW:", fmt.Sprintf("active (%d sockets)", len(cand.RawConns)), inspWarn))
	}
	if cand.DelegatedEgress {
		owner := cand.DelegatedOwner
		if owner == "" {
			owner = "(unknown)"
		}
		label := owner
		if cand.DelegatedOwnerPID > 0 {
			label = fmt.Sprintf("%s (%d)", owner, cand.DelegatedOwnerPID)
		}
		network = append(network, kv("BROKER:", label, inspWarn))
	}
	// Compact IO with dimmed zero
	ioTotal := ioRead + ioWrite + ioOther
	if ioTotal > 0 {
		network = append(network, kv("IO:", formatCompactIO(ioRead, ioWrite), inspValue))
		if ioReadRate+ioWriteRate+ioOtherRate > 0 {
			network = append(network, kv("RATE:", formatCompactIORate(ioReadRate, ioWriteRate), inspValue))
		} else {
			network = append(network, kvDim("RATE:", "0 B/s"))
		}
	} else {
		network = append(network, kvDim("IO:", "0 B"))
	}
	// ASN as compact tags
	orgs, pending, _ := inspectorExternalOrgs(cand)
	if len(orgs) > 0 {
		var tags []string
		for _, org := range orgs {
			// Extract short name (first part before " - ")
			shortName := org
			if idx := strings.Index(org, " - "); idx > 0 {
				shortName = org[:idx]
			}
			tags = append(tags, "["+shortName+"]")
		}
		network = append(network, kv("ASN:", strings.Join(tags, " "), inspValue))
	} else if pending > 0 {
		network = append(network, kvDim("ASN:", fmt.Sprintf("resolving %d...", pending)))
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
	// Formatted with severity bullets. Capped at 6 items.
	{
		type evidenceLine struct {
			label    string
			value    string
			style    lipgloss.Style
			severity int // 0=low, 1=medium, 2=high, 3=critical
		}
		var lines []evidenceLine

		sigSet := make(map[string]bool, len(cand.Signals))
		for _, s := range cand.Signals {
			sigSet[s] = true
		}
		isSuspicious := strings.HasPrefix(role, "beacon") || role == "pivot"

		_ = isSuspicious // used by signal-driven evidence below

		// Special formatted evidence (always shown first if applicable).
		if cand.ControlChannel != nil {
			cn := cand.ControlChannel
			dest := fmt.Sprintf("%s:%d", formatGridIPInspector(cn.RemoteAddress), cn.RemotePort)
			if cand.ControlDurationSeconds >= 60 {
				lines = append(lines, evidenceLine{"Persistent control", fmt.Sprintf("%s held %dm%ds", dest, cand.ControlDurationSeconds/60, cand.ControlDurationSeconds%60), inspValue, 2})
			} else if cand.ControlDurationSeconds > 0 {
				lines = append(lines, evidenceLine{"Active connection", fmt.Sprintf("%s for %ds", dest, cand.ControlDurationSeconds), inspValue, 1})
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
			lines = append(lines, evidenceLine{"Callback", fmt.Sprintf("%s interval, %s jitter", intervalStr, jitterStr), inspAlert, 3})
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
			{"beacon-interval-confirmed", "Callback timing", "Regular check-ins at fixed intervals indicate automated C2 beaconing", false},
			{"beacon-syn-cycle-cadence", "SYN cycling", "Repeated connection failures suggest C2 server offline or network blocked", false},
			{"beacon-target-lock", "Target locked", "Single destination focus typical of dedicated C2 implant communication", false},
			{"beacon-http-channel", "HTTP channel", "Web protocol usage for C2 blends with normal traffic to evade detection", false},
			{"beacon-endpoint-rotation", "C2 rotation", "Failover between IPs on same port indicates resilient C2 infrastructure", false},
			{"session-persistent-channel", "Persistent control", "Maintained connection allows real-time operator control and tasking", false},
			{"session-single-target-persistence", "Pinned target", "Stable remote endpoint suggests established C2 server relationship", false},
			{"session-conn-churn", "Connection churn", "Frequent reconnects mimic beacon sleep cycles or evade idle timeouts", false},
			{"session-exfil-write-heavy", "Exfiltration shape", "High outbound data ratio suggests data theft in progress", false},
			{"session-asn-mismatch", "ASN mismatch", "Traffic to unexpected network may indicate rogue infrastructure", false},
			{"pivot-listener-plus-outbound", "Relay shape", "Inbound listener with outbound tunneling enables lateral movement", false},
			{"pivot-loopback-listener-external-out", "SOCKS shape", "Local proxy forwarding to external C2 bypasses egress controls", false},
			{"pivot-multiplex-relay", "Multiplex relay", "Channel multiplexing spreads C2 traffic across internal network", false},
			{"pivot-throughput-symmetry", "Relay symmetry", "Equal read/write indicates pass-through proxy or tunnel operation", false},
			{"pivot-socks-candidate", "SOCKS proxy", "Dynamic port forwarding enables flexible network pivoting", false},
			{"outbound-standard-ports-only", "Standard ports", "Port 80/443 only usage attempts to bypass firewall restrictions", false},
			{"outbound-asn-org-aligned", "ASN aligned", "Traffic to expected vendor network reduces suspicion score", false},
			{"outbound-cdn-destination", "CDN traffic", "CDN fronting can mask true C2 destination behind legitimate hosts", false},
			{"cdn-fronted-c2-candidate", "CDN-fronted C2", "Unsigned process using CDN infrastructure suggests domain fronting evasion", false},
			{"listener-wildcard-bind", "Wildcard bind", "Binding 0.0.0.0 accepts connections from any network interface", false},
			{"listener-inbound-external", "External inbound", "Accepting external connections may indicate backdoor or RAT listener", false},
			// Host signals
			{"beacon-sleep-wake-cycle", "Dormant implant", "Extended sleep with brief wake patterns evade activity monitoring", true},
			{"beacon-micro-payload", "Micro payload", "Minimal data exchange suggests heartbeat-only or staged implant", true},
			{"beacon-low-cpu-long-life", "Low CPU", "Idle process with network activity indicates passive monitoring implant", true},
			{"beacon-no-children", "No children", "No subprocess spawning suggests single-purpose implant or stager", true},
			{"beacon-crypto-lib-loaded", "Crypto loaded", "Encryption capability with low IO suggests encrypted C2 channel", true},
			{"beacon-interval-confirmed", "Confirmed cadence", "Stable callback interval detected via burst tracking", true},
			{"beacon-tight-cadence", "Tight cadence", "Short interval (<5min) with low jitter indicates automated beacon", true},
			{"beacon-syn-cycle-cadence", "SYN cycling", "Repeated connection attempts reveal beacon sleep timing", true},
			{"beacon-target-lock", "Target lock", "Single persistent external target with no internal traffic", true},
			{"beacon-http-channel", "HTTP-only", "All traffic on HTTP/HTTPS ports to evade firewall inspection", true},
			{"beacon-endpoint-rotation", "Endpoint rotation", "Multiple IPs on same port suggests C2 infrastructure rotation", true},
			{"beacon-port-rotation", "Port rotation", "Many ports to single IP indicates multi-channel C2 tunnel", true},
			{"beacon-non-standard-port", "Non-standard port", "Unusual port may evade standard security monitoring", true},
			{"beacon-reconnecting-unknown-vendor", "Reconnecting", "Recurring short-lived callbacks match beacon sleep pattern", true},
			{"beacon-short-lived-callback", "Short callback", "Brief connection-then-disconnect matches beacon profile", true},
			{"beacon-io-read-dominant", "Read dominant", "High read ratio suggests command fetch and task polling", true},
			{"beacon-memory-stable", "Memory stable", "Consistent memory footprint indicates simple persistent implant", true},
			{"beacon-thread-minimal", "Minimal threads", "Few threads suggests pure callback implant without payload", true},
			{"beacon-static-crypto-likely", "Static crypto", "No system crypto DLLs suggests Go/Rust/Nim beacon binary", true},
			{"dns-tunnel-shape", "DNS tunnel", "DNS-only traffic pattern indicates DNS-based C2 channel", true},
			{"session-shell-spawn", "Shell spawned", "Interactive shell indicates hands-on-keyboard operator activity", true},
			{"session-lolbin-children", "LOLBin children", "Living-off-the-land binaries enable fileless attack techniques", true},
			{"session-elevated-external", "Elevated C2", "SYSTEM privileges with external comms indicates compromised service", true},
			{"session-encoding-in-cmdline", "Encoded cmdline", "Obfuscated commands hide malicious payloads from logging", true},
			{"session-bursty-io-pattern", "Bursty IO", "Task-response pattern matches interactive C2 operator behavior", true},
			{"session-rare-parent-network", "Rare parent", "Atypical process lineage with networking suggests process injection", true},
			{"session-covert-channel", "Covert channel", "Hidden communication via alternate data channels or steganography", true},
			{"session-rwx-memory", "RWX memory", "Executable heap/stack enables shellcode execution and evasion", true},
			{"session-impersonation-token", "Impersonation", "Token theft allows lateral movement under stolen credentials", true},
			{"pivot-named-pipe-c2-pattern", "C2 named pipe", "Cobalt Strike, Meterpreter, or similar framework pipe signature", true},
			{"pivot-admin-share-smb", "Admin SMB", "Admin pipe access enables remote service control and execution", true},
			{"pivot-ssh-tunnel-flags", "SSH tunnel", "Port forwarding flags create encrypted pivoting channels", true},
			{"pivot-proxy-lib-loaded", "Proxy library", "Tunneling capability suggests network pivoting preparation", true},
			{"pivot-elevated-relay", "Elevated relay", "High-privilege relay enables unrestricted internal movement", true},
			{"pivot-anon-exec-memory", "Anon exec mem", "Reflective DLL injection or in-memory payload execution", true},
			{"outbound-known-vendor", "Known vendor", "Signed binary from recognized publisher reduces threat score", true},
			{"outbound-system-path", "System path", "Protected OS location suggests legitimate system component", true},
			{"outbound-download-heavy", "Download heavy", "High download ratio may indicate staging or tool retrieval", true},
			{"listener-service-context", "Service context", "Service execution provides persistence and elevated privileges", true},
			{"listener-long-idle", "Long idle", "Dormant listener may await operator connection or trigger", true},
			{"listener-named-pipe-server", "Pipe server", "IPC server enables local privilege escalation or lateral movement", true},
			// SSH baseline signals
			{"ssh-first-time-destination", "New SSH target", "First time this user has SSH'd to this destination", false},
			{"ssh-new-internal-target", "New internal SSH", "SSH to internal host not in user's baseline", false},
			{"ssh-new-external-target", "New external SSH", "SSH to external host not in user's baseline", false},
			{"ssh-known-destination", "Known SSH target", "SSH to destination in user's established baseline", false},
			{"ssh-baseline-established", "SSH baseline ready", "User's SSH pattern baseline is now established", false},
		}

		// Filter signals to only show those relevant to the assigned role.
		// Signals are prefixed by role type (beacon-, session-, pivot-, listener-, outbound-).
		// SSH signals are always relevant as they indicate lateral movement patterns.
		isRelevantSignal := func(signal, assignedRole string) bool {
			// SSH signals are relevant to all roles
			if strings.HasPrefix(signal, "ssh-") {
				return true
			}
			// Map role to its signal prefix(es)
			switch assignedRole {
			case "beacon":
				return strings.HasPrefix(signal, "beacon-") || strings.HasPrefix(signal, "session-")
			case "pivot", "tunnel":
				return strings.HasPrefix(signal, "pivot-")
			case "session":
				return strings.HasPrefix(signal, "session-") || strings.HasPrefix(signal, "beacon-")
			case "listener", "listen":
				return strings.HasPrefix(signal, "listener-") || strings.HasPrefix(signal, "pivot-")
			case "outbound":
				return strings.HasPrefix(signal, "outbound-")
			default:
				return true // show all for unknown roles
			}
		}

		netCount, hostCount := 0, 0
		for _, em := range mappings {
			if !sigSet[em.signal] {
				continue
			}
			// Only show signals relevant to the assigned role
			if !isRelevantSignal(em.signal, role) {
				continue
			}
			if em.isHost && hostCount >= 3 {
				continue
			}
			if !em.isHost && netCount >= 3 {
				continue
			}
			style := inspValue
			severity := 1 // medium for network
			if em.isHost {
				style = inspSession
				severity = 0 // low for host
				hostCount++
			} else {
				netCount++
			}
			lines = append(lines, evidenceLine{em.label, em.desc, style, severity})
			if netCount >= 3 && hostCount >= 3 {
				break
			}
		}

		// Publisher (Company) is already shown as Vendor in the IDENTITY box —
		// omitted here to avoid repeating it.

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
			lines = append(lines, evidenceLine{"Reason", reason, inspValue, 1})
			netR++
		}
		for _, reason := range hostReasons {
			if hostR >= 3 {
				break
			}
			lines = append(lines, evidenceLine{"Reason", reason, inspSession, 0})
			hostR++
		}

		// When signal debug is OFF, cap at 6 curated items.
		// When ON, show all curated items + raw signal list.
		if !m.app.InspectShowAllSignals {
			if len(lines) > 6 {
				lines = lines[:6]
			}
		}

		// Render evidence with severity bullets
		var evidence []string
		for _, line := range lines {
			// Determine severity bullet based on severity level
			bullet := "○" // default: low (0)
			bulletStyle := inspDim
			switch line.severity {
			case 3: // critical
				bullet = "◉"
				bulletStyle = inspAlert
			case 2: // high
				bullet = "◎"
				bulletStyle = inspWarn
			case 1: // medium
				bullet = "●"
				bulletStyle = inspValue
			}
			labelText := ul(line.label)
			avail := colW - 20
			if avail < 20 {
				avail = 20
			}
			evidence = append(evidence, fmt.Sprintf("  %s %s - %s",
				bulletStyle.Render(bullet),
				inspLabel.Render(labelText),
				val.Render(TruncateToWidth(line.value, avail))))
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
			// says "beacon" but the process is labeled
			// "outbound" — now it reads "beacon → outbound".
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
				modelLines = append(modelLines, kv("Reasoning:", strings.Join(reasoningParts, "; "), inspValue))
			}

			// Observations and experience.
			if expProfile != nil && expProfile.ExperienceObservations > 0 {
				dominant := expProfile.DominantRole
				if dominant == "" {
					dominant = "unknown"
				}
				modelLines = append(modelLines, kv("Samples:", fmt.Sprintf("%d", expProfile.ExperienceObservations), inspValue))

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
				modelLines = append(modelLines, kv("Samples:", "collecting initial data", inspDim))
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

		// MODEL section disabled for cleaner military UI
		_ = modelLines
	}

	// CONNECTIONS
	var connLines []string
	type connGroup struct {
		remote      string
		state       string
		count       int
		sources     map[string]struct{} // distinct local IPs in this group
		firstSource string              // first observed source IP (display anchor)
	}
	// Pull the per-PID sticky connection list — the cache is updated
	// continuously by shared.RecordCandidateConnsForInspector on every
	// scanner refresh (see ApplySelection), so closed connections from
	// previous beacons remain visible for the full 10-minute sticky
	// window even if this inspector view wasn't open when they fired.
	stickyLive := shared.InspectorStickyConns(pid, cand.Conns)
	connSeen := make(map[string]struct{})
	var dedupConns []shared.ConnectionInfo
	for _, cn := range stickyLive {
		local := fmt.Sprintf("%s:%d", cn.LocalAddress, cn.LocalPort)
		remote := fmt.Sprintf("-> %s:%d", cn.RemoteAddress, cn.RemotePort)
		key := fmt.Sprintf("tcp|%s|%s|%s", local, remote, cn.State)
		if _, ok := connSeen[key]; ok {
			continue
		}
		connSeen[key] = struct{}{}
		dedupConns = append(dedupConns, cn)
	}
	grouped := len(dedupConns) > 3

	divider := lipgloss.NewStyle().Foreground(colorFrame)
	if grouped {
		// Military-style grouped table with vertical separators
		connLines = append(connLines, inspValue.Render(fmt.Sprintf("  %-6s │ %-20s │ %-24s │ %-14s │ %-11s", "PROTO", "ORIGIN", "DESTINATION", "COUNT", "STATUS")))
		connLines = append(connLines, divider.Render(fmt.Sprintf("  %s─┼─%s─┼─%s─┼─%s─┼─%s", strings.Repeat("─", 6), strings.Repeat("─", 20), strings.Repeat("─", 24), strings.Repeat("─", 14), strings.Repeat("─", 11))))
		groupOrder := make([]string, 0, len(dedupConns))
		groupMap := make(map[string]*connGroup, len(dedupConns))
		for _, cn := range dedupConns {
			remote := fmt.Sprintf("%s:%d", formatGridIPInspector(cn.RemoteAddress), cn.RemotePort)
			gk := remote
			if g, ok := groupMap[gk]; ok {
				g.count++
				if connStateRank(cn.State) > connStateRank(g.state) {
					g.state = cn.State
				}
				if cn.LocalAddress != "" {
					if _, dup := g.sources[cn.LocalAddress]; !dup {
						g.sources[cn.LocalAddress] = struct{}{}
					}
				}
			} else {
				g := &connGroup{
					remote:      remote,
					state:       cn.State,
					count:       1,
					sources:     make(map[string]struct{}),
					firstSource: cn.LocalAddress,
				}
				if cn.LocalAddress != "" {
					g.sources[cn.LocalAddress] = struct{}{}
				}
				groupMap[gk] = g
				groupOrder = append(groupOrder, gk)
			}
		}
		for _, gk := range groupOrder {
			g := groupMap[gk]
			countLabel := fmt.Sprintf("%d conn", g.count)
			if g.count == 1 {
				countLabel = "1 conn"
			}
			source := formatGridIPInspector(g.firstSource)
			if extra := len(g.sources) - 1; extra > 0 {
				source = fmt.Sprintf("%s +%d", source, extra)
			}
			if source == "" {
				source = "—"
			}
			connLines = append(connLines, inspValue.Render(fmt.Sprintf("  %-6s", "TCP"))+
				inspDim.Render(" │ ")+inspDim.Render(fmt.Sprintf("%-20s", TruncateToWidth(source, 20)))+
				inspDim.Render(" │ ")+bodyText.Render(fmt.Sprintf("%-24s", g.remote))+
				inspDim.Render(" │ ")+bodyText.Render(fmt.Sprintf("%-14s", countLabel))+
				inspDim.Render(" │ ")+inspConnStateStyle(g.state).Render(fmt.Sprintf("%-11s", g.state)))
		}
	} else {
		// Military-style table with vertical separators
		connLines = append(connLines, inspValue.Render(fmt.Sprintf("  %-6s │ %-22s │ %-22s │ %-12s", "PROTO", "ORIGIN", "DESTINATION", "STATUS")))
		connLines = append(connLines, divider.Render(fmt.Sprintf("  %s─┼─%s─┼─%s─┼─%s", strings.Repeat("─", 6), strings.Repeat("─", 22), strings.Repeat("─", 22), strings.Repeat("─", 12))))
		for _, cn := range dedupConns {
			localIP := formatGridIPInspector(cn.LocalAddress)
			remoteIP := formatGridIPInspector(cn.RemoteAddress)
			local := fmt.Sprintf("%s:%d", localIP, cn.LocalPort)
			remote := fmt.Sprintf("%s:%d", remoteIP, cn.RemotePort)
			connLines = append(connLines, inspValue.Render(fmt.Sprintf("  %-6s", "TCP"))+
				inspDim.Render(" │ ")+inspDim.Render(fmt.Sprintf("%-22s", local))+
				inspDim.Render(" │ ")+bodyText.Render(fmt.Sprintf("%-22s", remote))+
				inspDim.Render(" │ ")+inspConnStateStyle(cn.State).Render(fmt.Sprintf("%-12s", cn.State)))
		}
	}
	for _, ul := range cand.UDPListeners {
		localIP := formatGridIPInspector(ul.LocalAddress)
		local := fmt.Sprintf("%s:%d", localIP, ul.LocalPort)
		key := fmt.Sprintf("udp|%s", local)
		if _, ok := connSeen[key]; ok {
			continue
		}
		connSeen[key] = struct{}{}
		connLines = append(connLines, inspValue.Render(fmt.Sprintf("  %-6s", "UDP"))+
			inspDim.Render(fmt.Sprintf(" %-22s", local))+
			inspDim.Render(fmt.Sprintf(" %-22s", "*:*"))+
			inspConnStateStyle("LISTEN").Render(fmt.Sprintf(" %-12s", "LISTEN")))
	}
	for _, rc := range cand.RawConns {
		remote := rc.Remote
		if remote == "" || remote == "*" || remote == "0.0.0.0" {
			remote = "*"
		}
		connLines = append(connLines,
			inspValue.Render(fmt.Sprintf("  %-6s", "RAW"))+
				inspDim.Render(fmt.Sprintf(" %-22s", rc.Local))+
				inspWarn.Render(fmt.Sprintf(" %-22s", remote))+
				inspConnStateStyle(rc.State).Render(fmt.Sprintf(" %-12s", rc.State)))
	}
	if len(connLines) > 0 {
		sections = append(sections, section{"CONNECTIONS", connLines})
	}

	// Full-width layout: every section is its own bordered box spanning the
	// terminal width, stacked one per row.
	var out []string
	sectionStarts := make([]int, 0, len(sections))
	row := 0
	for _, sec := range sections {
		sectionStarts = append(sectionStarts, row)
		h := len(sec.lines) + 2
		out = append(out, renderAccentPanel(colW, h, sec.name, strings.Join(sec.lines, "\n")))
		row += h
	}
	m.app.InspectSectionStarts = sectionStarts
	return strings.Join(out, "\n")
}

// formatTacticalAge formats age in military style: +XXXs, +XXXm, +XXXh, +XXXd
func formatTacticalAge(seconds int) string {
	if seconds <= 0 {
		return "+000s"
	}
	d := time.Duration(seconds) * time.Second
	if d < time.Minute {
		return fmt.Sprintf("+%03ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("+%03dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("+%03dh", int(d.Hours()))
	}
	return fmt.Sprintf("+%03dd", int(d.Hours()/24))
}

// formatGridIPInspector is now a no-op - returns IP as-is without grid notation
func formatGridIPInspector(ip string) string {
	return ip
}

// formatCompactIO formats IO bytes compactly: "1.2 MB (R:368K W:732K)"
func formatCompactIO(read, write uint64) string {
	total := read + write
	totalStr := formatBytesCompact(total)
	if read > 0 && write > 0 {
		return fmt.Sprintf("%s (R:%s W:%s)", totalStr, formatBytesCompact(read), formatBytesCompact(write))
	} else if read > 0 {
		return fmt.Sprintf("%s (R)", totalStr)
	} else if write > 0 {
		return fmt.Sprintf("%s (W)", totalStr)
	}
	return totalStr
}

// formatCompactIORate formats IO rate compactly
func formatCompactIORate(readRate, writeRate uint64) string {
	total := readRate + writeRate
	if total == 0 {
		return "0 B/s"
	}
	totalStr := formatBytesCompact(total) + "/s"
	if readRate > 0 && writeRate > 0 {
		return fmt.Sprintf("%s (R:%s W:%s)", totalStr, formatBytesCompact(readRate)+"/s", formatBytesCompact(writeRate)+"/s")
	}
	return totalStr
}

// formatBytesCompact formats bytes in compact form: 1K, 1.2M, 3.5G
func formatBytesCompact(b uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case b >= GB:
		return fmt.Sprintf("%.1fG", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.1fM", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.0fK", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%dB", b)
	}
}
