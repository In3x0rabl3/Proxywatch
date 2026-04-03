package views

import (
	"fmt"
	"proxywatch/internal/ui/platform"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/gdamore/tcell/v2"

	"proxywatch/internal/contour"
	"proxywatch/internal/shared"
)

// ContourModel is the native bubbletea model for the contour view.
type ContourModel struct {
	app            *shared.AppState
	viewport       viewport.Model
	width          int
	height         int
	ready          bool
	live           liveProgressModel
	panelTitle     string
	contentKey     uint64
	dynamicReportH int
}

func NewContourModel(app *shared.AppState) ContourModel {
	return ContourModel{
		app:  app,
		live: newLiveProgressModel(),
	}
}

func (m ContourModel) Init() tea.Cmd { return nil }

func (m ContourModel) Update(msg tea.Msg) (ContourModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.InitViewport()
		m.RefreshContent()

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

		// Number key workflow jumping.
		if !m.app.ContourEditing && !m.app.ContourNewEditing {
			if jumpToWorkflow(m.app, tev.Rune()) {
				return m, nil
			}
		}

		// Tab toggles between Scan and Contour (Tunnel/Services) modes.
		if tev.Key() == tcell.KeyTab && !m.app.ContourEditing && !m.app.ContourNewEditing {
			if m.app.ContourDashMode == contourDashScan {
				m.app.ContourDashMode = contourDashContour
				contourPopulateMethods(m.app)
				contourPopulateServices(m.app)
				if m.app.ContourNewRole == "" {
					m.app.ContourNewRole = "Client"
				}
				if m.app.ContourNewMode == "" {
					m.app.ContourNewMode = "Tunnel"
				}
			} else {
				m.app.ContourDashMode = contourDashScan
			}
			m.dynamicReportH = 0
			m.contentKey = 0
			m.ready = false
			return m, nil
		}

		// Workflow cycling.
		switch tev.Key() {
		case tcell.KeyLeft:
			if stepWorkflowMenu(m.app, -1) {
				return m, nil
			}
		case tcell.KeyRight:
			if stepWorkflowMenu(m.app, 1) {
				return m, nil
			}
		}

		// Scroll.
		if m.ready && !m.app.ContourShowMenu && !m.app.ContourShowHelp && !m.app.ContourEditing {
			if m.handleScroll(tev) {
				return m, nil
			}
		}

		// Contour mode key handling.
		if m.app.ContourDashMode == contourDashContour {
			if handleContourModeKey(m.app, tev) {
				// fall through to spinner check
			} else if tev.Rune() == 'q' {
				if requestQuit(m.app) {
					return m, tea.Quit
				}
				return m, nil
			}
		}

		// Everything else to legacy contour key handler (Scan mode).
		if m.app.ContourDashMode == contourDashScan {
			if handleContourKey(m.app, tev) {
				return m, tea.Quit
			}
		}
		m.RefreshContent()

	case tea.MouseMsg:
		if m.ready {
			m.viewport, _ = m.viewport.Update(msg)
		}
	}

	// Spinner tick.
	m.live.active = m.app.ContourActive || m.app.ContourAnalyzing || m.app.ContourNewActive
	if m.live.active {
		var cmd tea.Cmd
		m.live, cmd = m.live.Update(msg)
		if cmd == nil {
			cmd = m.live.spinner.Tick
		}
		m.RefreshContent()
		return m, cmd
	}

	return m, nil
}

func (m *ContourModel) handleScroll(tev *tcell.EventKey) bool {
	switch tev.Key() {
	case tcell.KeyPgUp:
		m.viewport.HalfPageUp()
		return true
	case tcell.KeyPgDn:
		m.viewport.HalfPageDown()
		return true
	case tcell.KeyHome:
		m.viewport.GotoTop()
		return true
	case tcell.KeyEnd:
		m.viewport.GotoBottom()
		return true
	}
	if tev.Key() == tcell.KeyRune {
		switch tev.Rune() {
		case 'j', ']':
			m.viewport.ScrollDown(1)
			return true
		case 'k', '[':
			m.viewport.ScrollUp(1)
			return true
		}
	}
	return false
}

func (m *ContourModel) InitViewport() {
	var above []string
	above = append(above, m.renderHeader())
	switch m.app.ContourDashMode {
	case contourDashContour:
		if m.app.ContourNewMode == "Services" {
			above = append(above, m.renderServicesSetup())
		} else {
			above = append(above, m.renderContourSetup())
		}
	default:
		above = append(above, m.renderScanSetup())
	}
	used := 0
	for _, s := range above {
		used += lipgloss.Height(s)
	}
	reportH := m.height - used
	if reportH < 4 {
		reportH = 4
	}
	reportW := m.width - 2
	vpH := reportH - 2
	if vpH < 2 {
		vpH = 2
	}
	if !m.ready {
		m.viewport = viewport.New(reportW, vpH)
		m.viewport.Style = lipgloss.NewStyle()
		m.ready = true
	} else {
		m.viewport.Width = reportW
		m.viewport.Height = vpH
	}
}

func (m *ContourModel) RefreshContent() {
	if !m.ready {
		return
	}
	if m.app.ContourActive || m.app.ContourAnalyzing || m.app.ContourNewActive {
		contourPopulateMethods(m.app)
	}
	content, title := m.buildContent()
	m.panelTitle = title

	h := quickHash(content)
	if h != m.contentKey {
		m.contentKey = h
		m.viewport.SetContent(content)
	}
}

func (m *ContourModel) buildContent() (string, string) {
	m.app.ProgressMu.Lock()
	progressLines := append([]string(nil), m.app.ContourProgressLines...)
	m.app.ProgressMu.Unlock()

	if m.app.ContourDashMode == contourDashContour && m.app.ContourNewMode == "Services" {
		if len(progressLines) > 0 {
			var out []string
			for _, line := range progressLines {
				trimmed := strings.TrimSpace(line)
				switch {
				case strings.HasPrefix(trimmed, "[+]"):
					task := strings.TrimPrefix(trimmed, "[+]")
					out = append(out, statusPass.Render("  + ")+bodyText.Render(strings.TrimSpace(task)))
				case strings.HasPrefix(trimmed, "[-]"):
					task := strings.TrimPrefix(trimmed, "[-]")
					out = append(out, statusFail.Render("  - ")+bodyText.Render(strings.TrimSpace(task)))
				case strings.HasPrefix(trimmed, "[*]"):
					task := strings.TrimPrefix(trimmed, "[*]")
					out = append(out, dimText.Render("  * ")+bodyText.Render(strings.TrimSpace(task)))
				default:
					out = append(out, "  "+bodyText.Render(trimmed))
				}
			}
			title := "DISPLAY"
			if m.app.ContourNewActive {
				title = "ACTIVE"
			}
			return strings.Join(out, "\n"), title
		}
		if len(m.app.ContourNewServices) == 0 {
			return inspValue.Render("No services discovered yet.") + "\n" +
				dimText.Render("Run a scan first."), "DISPLAY"
		}
		return dimText.Render("  Select a service and start."), "DISPLAY"
	}

	if m.app.ContourDashMode == contourDashContour {
		if len(progressLines) > 0 {
			var out []string
			for _, line := range progressLines {
				trimmed := strings.TrimSpace(line)
				switch {
				case strings.HasPrefix(trimmed, "[+]"):
					task := strings.TrimPrefix(trimmed, "[+]")
					out = append(out, statusPass.Render("  + ")+bodyText.Render(strings.TrimSpace(task)))
				case strings.HasPrefix(trimmed, "[-]"):
					task := strings.TrimPrefix(trimmed, "[-]")
					out = append(out, statusFail.Render("  - ")+bodyText.Render(strings.TrimSpace(task)))
				case strings.HasPrefix(trimmed, "[*]"):
					task := strings.TrimPrefix(trimmed, "[*]")
					out = append(out, dimText.Render("  * ")+bodyText.Render(strings.TrimSpace(task)))
				default:
					out = append(out, "  "+bodyText.Render(trimmed))
				}
			}
			title := "DISPLAY"
			if m.app.ContourNewActive {
				title = "ACTIVE"
			}
			return strings.Join(out, "\n"), title
		}
		if m.app.ContourNewActive {
			return dimText.Render("  Starting..."), "ACTIVE"
		}
		return inspValue.Render("No contour report yet.") + "\n" +
			dimText.Render("Configure target and start a run."), "DISPLAY"
	}

	// Scan mode display — completed scan.
	if m.app.ContourReport != nil {
		if report, ok := m.app.ContourReport.(*contour.Report); ok {
			// Show the finished report if available.
			return renderFinishedReport(report, m.width-4), "COMPLETED"
		}
	}
	if (m.app.ContourActive || m.app.ContourAnalyzing) && len(progressLines) > 0 {
		return renderTaskMatrix(progressLines, m.live.spinner, m.app, m.width-4), "SCANNING"
	}
	if m.app.ContourActive || m.app.ContourAnalyzing {
		return dimText.Render("  Starting..."), "SCANNING"
	}

	return inspValue.Render("No contour report yet.") + "\n" +
		dimText.Render("Configure target and start a run."), "DISPLAY"
}

// ── View ────────────────────────────────────────────────────────────────────

func (m ContourModel) View() string {
	w := m.width
	h := m.height
	if w <= 0 || h <= 0 {
		return ""
	}

	var sections []string
	sections = append(sections, m.renderHeader())

	switch m.app.ContourDashMode {
	case contourDashContour:
		if m.app.ContourNewMode == "Services" {
			sections = append(sections, m.renderServicesSetup())
		} else {
			sections = append(sections, m.renderContourSetup())
		}
	default:
		sections = append(sections, m.renderScanSetup())
	}

	used := 0
	for _, s := range sections {
		used += lipgloss.Height(s)
	}
	m.dynamicReportH = h - used
	if m.dynamicReportH < 4 {
		m.dynamicReportH = 4
	}

	sections = append(sections, m.renderReportPanel())

	view := lipgloss.JoinVertical(lipgloss.Left, sections...)

	if m.app.ContourNewShowMenu && len(m.app.ContourNewMenuOptions) > 0 {
		view = overlayCenter(view, renderMenuPanel(
			m.app.ContourNewMenuTitle,
			m.app.ContourNewMenuOptions,
			m.app.ContourNewMenuIndex,
			"Enter select   Esc cancel", w), w, h)
	} else if m.app.ContourShowMenu && len(m.app.ContourMenuOptions) > 0 {
		view = overlayCenter(view, renderMenuPanel(
			m.app.ContourMenuTitle,
			m.app.ContourMenuOptions,
			m.app.ContourMenuIndex,
			"Enter apply   Esc close", w), w, h)
	}
	if m.app.ContourShowHelp {
		view = overlayCenter(view, renderHelpPanel("Contour Menu", contourMenuHelpOptions(), w), w, h)
	}
	if m.app.ShowQuitConfirm && m.app.QuitConfirmDeadline.After(time.Now()) {
		quitPanel := renderQuitConfirm(m.app.QuitConfirmDeadline, w)
		view = overlayCenter(view, quitPanel, w, m.height)
	}
	return view
}

func (m ContourModel) renderHeader() string {
	w := m.width
	if w <= 0 {
		w = 80
	}
	contentW := w - 2
	helpPlain := "? help"
	utcPlain := "UTC: " + time.Now().UTC().Format(UTCTimeFormat)
	gap := max(1, contentW-len(helpPlain)-len(utcPlain))
	line := dimText.Render(helpPlain) + bgSp(gap) +
		rightLabelStyle.Render("UTC: ") + sectionLabel.Render(time.Now().UTC().Format(UTCTimeFormat))
	return renderPanel(w, 3, "Contour", "proxywatch", "", line)
}

func (m ContourModel) renderReportPanel() string {
	w := m.width
	if w <= 0 {
		w = 80
	}
	reportH := m.dynamicReportH
	if reportH < 4 {
		reportH = 4
	}

	opts := ReportPanelOpts{
		Title:       m.panelTitle,
		Width:       w,
		Height:      reportH,
		StatusText:  m.app.ContourStatusText,
		StatusError: m.app.ContourStatusError,
		StatusUntil: m.app.ContourStatusUntil,
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

// ── Setup panel ─────────────────────────────────────────────────────────────

func (m ContourModel) renderScanSetup() string {
	w := m.width
	if w <= 0 {
		w = 80
	}

	actionIcon := platform.IconPlay
	if m.app.ContourActive || m.app.ContourAnalyzing {
		actionIcon = platform.IconStop
	}

	var rows []FormRow
	if strings.TrimSpace(m.app.LocalHost) == "" {
		sourceLabel := m.app.ContourSource
		if sourceLabel == "" {
			sourceLabel = "all"
		}
		rows = append(rows, FormRow{Field: contourFieldSource, Label: "Host", Value: sourceLabel})
	}
	rows = append(rows,
		FormRow{Field: contourFieldEndpoint, Label: "Target", Value: m.app.ContourProbeEndpoint, Editable: true},
		FormRow{Field: contourFieldOutput, Label: "Output", Value: m.app.ContourOutput, Editable: true},
		FormRow{Field: contourFieldAction, Label: "Action", Value: actionIcon + " " + m.actionLabel()},
	)
	return renderSetupPanel("SETUP [Scan] Tab to switch", rows, m.app.ContourField, m.app.ContourEditing, w)
}

func (m ContourModel) actionLabel() string {
	if m.app.ContourActive || m.app.ContourAnalyzing {
		elapsed := time.Since(m.app.ContourStartedAt).Round(time.Second)
		if m.app.ContourAnalyzing {
			return fmt.Sprintf("Analyzing... (%s)", elapsed)
		}
		remaining := time.Until(m.app.ContourUntil).Round(time.Second)
		if remaining < 0 {
			remaining = 0
		}
		return fmt.Sprintf("Running %s  |  %s remaining", elapsed, remaining)
	}
	return "Start Scan"
}

// ── Contour mode setup panel ────────────────────────────────────────────────

func (m ContourModel) renderContourSetup() string {
	w := m.width
	if w <= 0 {
		w = 80
	}

	role := m.app.ContourNewRole
	if role == "" {
		role = "Client"
	}
	mode := m.app.ContourNewMode
	if mode == "" {
		mode = "Tunnel"
	}

	method := m.app.ContourNewMethod
	if method == "" {
		if len(m.app.ContourNewMethods) > 0 {
			method = m.app.ContourNewMethods[0]
			m.app.ContourNewMethod = method
		} else {
			method = "(run Scan first)"
		}
	}

	methodDisplay := method
	if ports, ok := m.app.ContourNewMethodPorts[method]; ok && len(ports) > 0 {
		methodDisplay = fmt.Sprintf("%s (%d ports)", method, len(ports))
	}
	if len(m.app.ContourNewMethods) > 1 {
		methodDisplay += fmt.Sprintf("  [%d methods]", len(m.app.ContourNewMethods))
	}

	actionLabel := platform.IconPlay + " Start Tunnel"
	if role == "Server" {
		actionLabel = platform.IconPlay + " Start Listener"
	}
	if m.app.ContourNewActive {
		actionLabel = platform.IconStop + " Stop"
	}

	var rows []FormRow

	if mode == "Scan" || mode == "Listen" {
		rows = []FormRow{
			{Field: 0, Label: "Mode", Value: mode},
			{Field: 1, Label: "Action", Value: func() string {
				if m.app.ContourNewActive {
					return platform.IconStop + " Stop Listener"
				}
				return platform.IconPlay + " Start Listener"
			}()},
		}
		return renderSetupPanel("SETUP [Contour] Tab to switch", rows, m.app.ContourNewField, m.app.ContourNewEditing, w)
	}

	portDisplay := "auto"
	if m.app.ContourNewPort > 0 {
		portDisplay = fmt.Sprintf("%d", m.app.ContourNewPort)
	}
	verifiedPorts := m.app.ContourNewMethodPorts[method]
	if len(verifiedPorts) > 0 {
		portDisplay += fmt.Sprintf("  [%d available]", len(verifiedPorts))
	}

	direction := m.app.ContourNewDirection
	if direction == "" {
		direction = "Forward"
	}

	reverseValue := "false"
	if direction == "Reverse" {
		reverseValue = "true"
	}

	rows = []FormRow{
		{Field: 0, Label: "Role", Value: role},
		{Field: 1, Label: "Mode", Value: mode},
		{Field: 2, Label: "Protocol", Value: methodDisplay},
		{Field: 3, Label: "Port", Value: portDisplay},
		{Field: 4, Label: "Reverse", Value: reverseValue},
	}

	actionIdx := len(rows)
	rows = append(rows, FormRow{Field: actionIdx, Label: "Action", Value: actionLabel})

	return renderSetupPanel("SETUP [Contour] Tab to switch", rows, m.app.ContourNewField, m.app.ContourNewEditing, w)
}

func (m ContourModel) renderServicesSetup() string {
	w := m.width
	if w <= 0 {
		w = 80
	}

	role := m.app.ContourNewRole
	if role == "" {
		role = "Client"
	}

	service := m.app.ContourNewService
	if service == "" {
		if len(m.app.ContourNewServices) > 0 {
			service = m.app.ContourNewServices[0]
			m.app.ContourNewService = service
		} else {
			service = "(run Scan first)"
		}
	}

	// Check what methods are available for the selected service.
	hasKey := false
	if service != "" && service != "(run Scan first)" {
		proto := contour.ServiceMethodToProto(service)
		_ = proto
		svcKey := contour.GetServiceKeyExported(service)
		hasKey = svcKey != ""
	}
	hasFronting := false
	m.app.ProgressMu.Lock()
	if probeRef := m.app.ContourPartialProbe; probeRef != nil {
		if probe, ok := probeRef.(*contour.ProbeSummary); ok && probe != nil {
			hasFronting = probe.DomainFrontingPossible
		}
	}
	m.app.ProgressMu.Unlock()

	// Show availability next to service name.
	serviceDisplay := service
	if service != "(run Scan first)" {
		var tags []string
		if hasKey {
			tags = append(tags, "key set")
		}
		if hasFronting {
			tags = append(tags, "fronting viable")
		}
		if len(tags) > 0 {
			serviceDisplay += "  [" + strings.Join(tags, ", ") + "]"
		}
	}

	method := m.app.ContourNewServiceMethod
	if method == "" {
		method = "Route Through"
		m.app.ContourNewServiceMethod = method
	}

	// Show availability next to method.
	methodDisplay := method
	if method == "Route Through" && !hasKey {
		methodDisplay += "  (no key — set in Keystore)"
	} else if method == "Domain Front" && !hasFronting {
		methodDisplay += "  (not viable — scan showed no fronting)"
	}

	direction := m.app.ContourNewDirection
	if direction == "" {
		direction = "Forward"
	}
	reverseValue := "false"
	if direction == "Reverse" {
		reverseValue = "true"
	}

	actionLabel := platform.IconPlay + " Start"
	if m.app.ContourNewActive {
		actionLabel = platform.IconStop + " Stop"
	}

	rows := []FormRow{
		{Field: 0, Label: "Role", Value: role},
		{Field: 1, Label: "Mode", Value: "Services"},
		{Field: 2, Label: "Service", Value: serviceDisplay},
		{Field: 3, Label: "Method", Value: methodDisplay},
		{Field: 4, Label: "Reverse", Value: reverseValue},
		{Field: 5, Label: "Action", Value: actionLabel},
	}

	return renderSetupPanel("SETUP [Contour] Tab to switch", rows, m.app.ContourNewField, m.app.ContourNewEditing, w)
}

func contourPopulateMethods(app *shared.AppState) {
	app.ProgressMu.Lock()
	probeRef := app.ContourPartialProbe
	app.ProgressMu.Unlock()

	if probeRef == nil {
		return
	}
	probe, ok := probeRef.(*contour.ProbeSummary)
	if !ok || probe == nil {
		return
	}

	verifiedPorts := make(map[string]map[int]bool)
	allPortSet := make(map[int]bool)
	for _, check := range probe.SuccessfulChecks {
		if check.Port <= 0 || check.Method == "" {
			continue
		}
		allPortSet[check.Port] = true
		if verifiedPorts[check.Method] == nil {
			verifiedPorts[check.Method] = make(map[int]bool)
		}
		verifiedPorts[check.Method][check.Port] = true
	}
	for _, p := range probe.Ports {
		allPortSet[p] = true
	}

	allPorts := make([]int, 0, len(allPortSet))
	for p := range allPortSet {
		allPorts = append(allPorts, p)
	}
	sort.Ints(allPorts)

	// Only show protocols that the scan verified work on this network.
	// If a protocol wasn't tested or didn't pass, it's not offered.
	protoNames := contour.DefaultProtocolNames()
	var methods []string
	portMap := make(map[string][]int, len(protoNames))
	for _, proto := range protoNames {
		vset := verifiedPorts[proto]
		if len(vset) > 0 {
			var verified []int
			for _, p := range allPorts {
				if vset[p] {
					verified = append(verified, p)
				}
			}
			portMap[proto] = verified
			methods = append(methods, proto)
		}
	}

	app.ContourNewMethods = methods
	app.ContourNewMethodPorts = portMap
	if app.ContourNewMethod == "" && len(methods) > 0 {
		app.ContourNewMethod = methods[0]
	}
}

func contourPopulateServices(app *shared.AppState) {
	app.ProgressMu.Lock()
	probeRef := app.ContourPartialProbe
	app.ProgressMu.Unlock()

	var services []string

	if probeRef != nil {
		if probe, ok := probeRef.(*contour.ProbeSummary); ok && probe != nil {
			// Client side: show only reachable services with dead drop transports.
			for _, svc := range probe.ServiceResults {
				if svc.Reachable && contour.DeadDropServices[svc.Name] {
					services = append(services, svc.Name)
				}
			}
		}
	}

	// Server side (no scan): show only services with dead drop transports.
	if len(services) == 0 {
		for name := range contour.DeadDropServices {
			services = append(services, name)
		}
		sort.Strings(services)
	}

	app.ContourNewServices = services
	if app.ContourNewService == "" && len(services) > 0 {
		app.ContourNewService = services[0]
	}
}

// Ensure imports are used.
var (
	_ = tcell.KeyUp
)
