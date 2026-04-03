package views

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/gdamore/tcell/v2"

	classifier "proxywatch/internal/detection"
	"proxywatch/internal/model"
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
	switch role {
	case "control-session", "control-beacon":
		return inspSession
	case "control-pivot":
		return inspPivot
	case "control-tunnel":
		return inspTunnel
	case "analyzing":
		return inspDim
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
	case "exited":
		return inspDim
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
	if cand.ControlSubtype != "" && (role == "control-pivot" || role == "control-tunnel") {
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

	// ANALYSIS
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

	// EVIDENCE — structured, numbered evidence items with severity indicators.
	{
		type evidenceItem struct {
			severity string // "CRITICAL", "HIGH", "MEDIUM", "LOW", "OK"
			finding  string
			detail   string
		}
		var items []evidenceItem

		sigSet := make(map[string]bool, len(cand.Signals))
		for _, s := range cand.Signals {
			sigSet[s] = true
		}
		isSuspicious := strings.HasPrefix(role, "control-") || role == "analyzing"

		if isSuspicious {
			if cand.ControlChannel != nil {
				cn := cand.ControlChannel
				dest := fmt.Sprintf("%s:%d", cn.RemoteAddress, cn.RemotePort)
				if cand.ControlDurationSeconds >= 300 {
					items = append(items, evidenceItem{"CRITICAL", "Persistent control channel",
						fmt.Sprintf("Connection to %s held for %dm%ds", dest, cand.ControlDurationSeconds/60, cand.ControlDurationSeconds%60)})
				} else if cand.ControlDurationSeconds >= 60 {
					items = append(items, evidenceItem{"HIGH", "Long-lived connection",
						fmt.Sprintf("Connection to %s held for %dm%ds", dest, cand.ControlDurationSeconds/60, cand.ControlDurationSeconds%60)})
				} else if cand.ControlDurationSeconds > 0 {
					items = append(items, evidenceItem{"MEDIUM", "Active connection held open",
						fmt.Sprintf("Connection to %s for %ds", dest, cand.ControlDurationSeconds)})
				}
			}

			if sigSet["beacon-confirmed"] {
				items = append(items, evidenceItem{"CRITICAL", "Beacon cadence confirmed",
					"Regular callback interval with consistent jitter detected"})
			} else if sigSet["beacon-model-recalled"] {
				items = append(items, evidenceItem{"CRITICAL", "Known beacon (model recall)",
					"This process identity was previously confirmed as a beacon"})
			}

			if sigSet["cdn-control-channel"] {
				items = append(items, evidenceItem{"CRITICAL", "Domain fronting detected",
					"Control channel routes through CDN — traffic hides behind trusted domains"})
			} else if sigSet["cdn-destination"] {
				items = append(items, evidenceItem{"MEDIUM", "CDN-routed traffic",
					"External traffic routes through CDN infrastructure"})
			}

			if cand.ActiveProxying {
				items = append(items, evidenceItem{"CRITICAL", "Active relay / proxy",
					"Simultaneous inbound and outbound with symmetric I/O — actively forwarding traffic"})
			}

			if cand.DelegatedStrong {
				items = append(items, evidenceItem{"HIGH", "Delegated egress",
					fmt.Sprintf("Traffic exits through PID %d (%s)", cand.DelegatedOwnerPID, cand.DelegatedOwner)})
			}

			if cand.OutExternal > 0 && cand.OutInternal > 0 {
				items = append(items, evidenceItem{"HIGH", "Lateral + external",
					fmt.Sprintf("%d external + %d internal targets — C2 with lateral movement", cand.OutExternal, cand.OutInternal)})
			} else if cand.OutLongLived > 0 {
				items = append(items, evidenceItem{"MEDIUM", "Persistent outbound",
					fmt.Sprintf("%d long-lived connection(s) — not transient request/response", cand.OutLongLived)})
			}

			if sigSet["contour-egress-tunnel-port"] {
				items = append(items, evidenceItem{"HIGH", "Contour-verified tunnel port",
					"Port confirmed capable of carrying tunnel traffic on this network"})
			}

			if sigSet["suspicious-exe-path"] {
				items = append(items, evidenceItem{"MEDIUM", "Suspicious executable path",
					"Runs from user-writable temp/download location"})
			}

			if sigSet["rare-parent"] || sigSet["suspicious-parent-chain"] {
				items = append(items, evidenceItem{"MEDIUM", "Unusual parent process",
					"Execution chain does not match normal software behavior"})
			}

			if len(cand.NamedPipes) > 0 {
				items = append(items, evidenceItem{"MEDIUM", "Named pipes open",
					fmt.Sprintf("%d pipe(s) — used by C2 frameworks for IPC", len(cand.NamedPipes))})
			}

			if sigSet["asn-org-mismatch"] {
				items = append(items, evidenceItem{"LOW", "ASN mismatch",
					"Destination network org does not match process publisher"})
			}

			if sigSet["model-role-override"] {
				items = append(items, evidenceItem{"HIGH", "Model override active",
					"Detection model overrode signal-based role from prior intelligence"})
			}
		} else if role == "listen" || role == "outbound" {
			if cand.TrafficVerified {
				items = append(items, evidenceItem{"OK", "Baseline verified",
					"Traffic matches learned behavioral baseline — consistently benign"})
			}
			if sigSet["asn-org-aligned"] {
				items = append(items, evidenceItem{"OK", "ASN aligned",
					"Destination network matches process publisher"})
			}
			if sigSet["baseline-verified"] {
				items = append(items, evidenceItem{"OK", "Stable profile",
					"Behavioral profile stable over extended observation"})
			}
			if cand.Proc != nil && strings.TrimSpace(cand.Proc.Company) != "" {
				items = append(items, evidenceItem{"OK", "Known publisher",
					strings.TrimSpace(cand.Proc.Company)})
			}
		}

		if len(items) > 0 {
			var evidence []string
			for _, item := range items {
				var marker string
				var findStyle, detailStyle lipgloss.Style
				switch item.severity {
				case "CRITICAL":
					marker = inspAlert.Render("  !! ")
					findStyle = inspAlert
					detailStyle = inspWarn
				case "HIGH":
					marker = inspWarn.Render("  !  ")
					findStyle = inspWarn
					detailStyle = inspDim
				case "MEDIUM":
					marker = lipgloss.NewStyle().Foreground(lipgloss.Color("#D19A66")).Render("  >  ")
					findStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#D19A66"))
					detailStyle = inspDim
				case "LOW":
					marker = inspDim.Render("  -  ")
					findStyle = inspDim
					detailStyle = inspDim
				case "OK":
					marker = inspSession.Render("  +  ")
					findStyle = inspSession
					detailStyle = inspDim
				default:
					marker = inspDim.Render("  -  ")
					findStyle = inspDim
					detailStyle = inspDim
				}
				evidence = append(evidence, marker+findStyle.Render(item.finding))
				evidence = append(evidence, inspLabel.Render("     ")+detailStyle.Render(item.detail))
			}

			sections = append(sections, section{"EVIDENCE", evidence})
		}
	}

	// MODEL
	{
		var modelLines []string
		model.FlushExperience()
		dm := model.Get()
		if dm != nil && cand.Proc != nil {
			key := classifier.ProcessBehaviorKey(cand)
			userVerdict, calVerdict, confidence := model.ProcessVerdict(key)
			expProfile := model.ResolveProfile(key)

			trainLabel := model.GetTrainingLabel(key)
			if trainLabel != "" {
				modelLines = append(modelLines, kv("Training:", trainLabel+" (press 't' to change)", inspAlert))
			} else {
				modelLines = append(modelLines, kv("Training:", "none (press 't' to label)", inspDim))
			}

			if calVerdict != "" {
				calStyle := inspDim
				if calVerdict == "suspicious" {
					calStyle = inspWarn
				} else if calVerdict == "benign" {
					calStyle = inspSession
				}
				modelLines = append(modelLines, kv("Calibration:", calVerdict, calStyle))
			}
			if userVerdict != "" {
				verdictStyle := inspDim
				if userVerdict == "malicious" {
					verdictStyle = inspAlert
				} else if userVerdict == "benign" {
					verdictStyle = inspSession
				} else if userVerdict == "contested" {
					verdictStyle = inspWarn
				}
				modelLines = append(modelLines, kv("Operator:", userVerdict, verdictStyle))
			}

			confPct := int((confidence + 1.0) * 50)
			confLabel := "uncertain"
			confStyle := inspDim
			if confPct >= 60 {
				confLabel = "likely benign"
				confStyle = inspSession
			} else if confPct <= 40 {
				confLabel = "likely malicious"
				confStyle = inspAlert
			}
			modelLines = append(modelLines, kv("Confidence:", fmt.Sprintf("%d%% (%s)", confPct, confLabel), confStyle))

			if expProfile != nil && expProfile.ExperienceObservations > 0 {
				dominant := expProfile.DominantRole
				if dominant == "" {
					dominant = "unknown"
				}
				modelLines = append(modelLines, kv("Experience:", fmt.Sprintf("%d observations, %.0f%% stable, dominant: %s",
					expProfile.ExperienceObservations,
					expProfile.RoleStability*100,
					dominant), inspDim))
			} else {
				modelLines = append(modelLines, kv("Experience:", "collecting...", inspDim))
			}

			egressSigs, _, _ := model.EgressSignals(cand.Conns)
			if len(egressSigs) > 0 {
				for _, sig := range egressSigs {
					label := "tunnel-capable"
					if strings.Contains(sig, "exfil") {
						label = "exfil-capable"
					}
					modelLines = append(modelLines, kv("Egress:", label+" (contour confirmed)", inspWarn))
				}
			}

			if expProfile != nil && (expProfile.KillCount > 0 || expProfile.WhitelistCount > 0) {
				modelLines = append(modelLines, kv("Feedback:", fmt.Sprintf("%d kills, %d whitelists", expProfile.KillCount, expProfile.WhitelistCount), inspDim))
			}
		}
		if len(modelLines) > 0 {
			sections = append(sections, section{"MODEL", modelLines})
		}
	}

	// REASONS — contour reasons always shown, others capped at 5, max total 7.
	if len(cand.Reasons) > 0 {
		var contourReasons, otherReasons []string
		for _, reason := range cand.Reasons {
			if strings.Contains(reason, "contour") || strings.Contains(reason, "Contour") {
				contourReasons = append(contourReasons, reason)
			} else {
				otherReasons = append(otherReasons, reason)
			}
		}
		if len(otherReasons) > 5 {
			otherReasons = otherReasons[:5]
		}
		combined := append(contourReasons, otherReasons...)
		if len(combined) > 7 {
			combined = combined[:7]
		}
		var reasons []string
		for _, reason := range combined {
			reasons = append(reasons, "  "+inspWarn.Render(">>")+inspValue.Render(" "+reason))
		}
		sections = append(sections, section{"REASONS", reasons})
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
