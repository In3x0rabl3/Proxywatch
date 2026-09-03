package keys

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"proxywatch/internal/contour"
	"proxywatch/internal/detection/model"
	"proxywatch/internal/shared"

	"github.com/gdamore/tcell/v2"
)

const ContourListenRunDuration = 24 * time.Hour

type ContourExecResult struct {
	Result contour.RunResult
	Err    error
}

// HandleContourModeKey handles keys for the Contour mode (transfer/tunnel).
func HandleContourModeKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if app.ContourNewShowMenu {
		switch tev.Key() {
		case tcell.KeyUp:
			if app.ContourNewMenuIndex > 0 {
				app.ContourNewMenuIndex--
			}
		case tcell.KeyDown:
			if app.ContourNewMenuIndex < len(app.ContourNewMenuOptions)-1 {
				app.ContourNewMenuIndex++
			}
		case tcell.KeyEnter:
			if app.ContourNewMenuIndex >= 0 && app.ContourNewMenuIndex < len(app.ContourNewMenuOptions) {
				choice := app.ContourNewMenuOptions[app.ContourNewMenuIndex]
				switch app.ContourNewMenuKind {
				case "role":
					app.ContourNewRole = choice
					app.ContourNewField = 0
				case "method":
					app.ContourNewMethod = choice
					app.ContourNewPort = 0
				case "port":
					if choice == "auto" {
						app.ContourNewPort = 0
					} else {
						var p int
						fmt.Sscanf(choice, "%d", &p)
						app.ContourNewPort = p
					}
				case "mode":
					StopContourNewOp(app)
					app.ContourNewMode = choice
					app.ContourNewField = 0
				case "direction":
					app.ContourNewDirection = choice
				case "service":
					app.ContourNewService = choice
				case "service-method":
					app.ContourNewServiceMethod = choice
				}
			}
			app.ContourNewShowMenu = false
		case tcell.KeyEscape:
			app.ContourNewShowMenu = false
		}
		return true
	}

	// Services mode key handling.
	// Fields: 0=Role, 1=Service, 2=Method, 3=Direction, 4=Action
	if app.ContourNewMode == "Services" {
		const servicesMaxField = 4
		switch tev.Key() {
		case tcell.KeyUp:
			if app.ContourNewField > 0 {
				app.ContourNewField--
			}
			return true
		case tcell.KeyDown:
			if app.ContourNewField < servicesMaxField {
				app.ContourNewField++
			}
			return true
		case tcell.KeyEnter:
			switch app.ContourNewField {
			case 0: // Role
				app.ContourNewShowMenu = true
				app.ContourNewMenuKind = "role"
				app.ContourNewMenuTitle = "Role"
				app.ContourNewMenuOptions = []string{"Client", "Server"}
				idx := 0
				for i, o := range app.ContourNewMenuOptions {
					if o == app.ContourNewRole {
						idx = i
					}
				}
				app.ContourNewMenuIndex = idx
			case 1: // Service
				if len(app.ContourNewServices) > 0 {
					app.ContourNewShowMenu = true
					app.ContourNewMenuKind = "service"
					app.ContourNewMenuTitle = "Service"
					app.ContourNewMenuOptions = app.ContourNewServices
					idx := 0
					for i, o := range app.ContourNewMenuOptions {
						if o == app.ContourNewService {
							idx = i
						}
					}
					app.ContourNewMenuIndex = idx
				}
			case 2: // Method
				app.ContourNewShowMenu = true
				app.ContourNewMenuKind = "service-method"
				app.ContourNewMenuTitle = "Method"
				app.ContourNewMenuOptions = []string{"Route Through", "Domain Front"}
				idx := 0
				for i, o := range app.ContourNewMenuOptions {
					if o == app.ContourNewServiceMethod {
						idx = i
					}
				}
				app.ContourNewMenuIndex = idx
			case 3: // Direction
				app.ContourNewShowMenu = true
				app.ContourNewMenuKind = "direction"
				app.ContourNewMenuTitle = "Direction"
				app.ContourNewMenuOptions = []string{"Forward", "Reverse"}
				idx := 0
				if app.ContourNewDirection == "Reverse" {
					idx = 1
				}
				app.ContourNewMenuIndex = idx
			case 4: // Action
				StartContourTunnel(app)
			}
			return true
		case tcell.KeyEscape:
			return false
		}

		if tev.Key() == tcell.KeyRune {
			r := tev.Rune()
			if r == 'q' {
				return false
			}
			if r == '?' {
				app.ContourShowHelp = true
				return true
			}
		}

		return false
	}

	mode := app.ContourNewMode
	if mode == "" {
		mode = "Tunnel"
	}
	role := app.ContourNewRole
	if role == "" {
		role = "Client"
	}

	maxField := ContourNewMaxField(mode, role)

	switch tev.Key() {
	case tcell.KeyUp:
		if app.ContourNewField > 0 {
			app.ContourNewField--
		}
		return true
	case tcell.KeyDown:
		if app.ContourNewField < maxField {
			app.ContourNewField++
		}
		return true
	case tcell.KeyEnter:
		if mode == "Scan" || mode == "Listen" {
			switch app.ContourNewField {
			case 0:
				StartContourListener(app)
			}
			return true
		}
		// Field order: 0=Role, 1=Protocol, 2=Direction, 3=Action
		switch app.ContourNewField {
		case 0: // Role
			app.ContourNewShowMenu = true
			app.ContourNewMenuKind = "role"
			app.ContourNewMenuTitle = "Role"
			app.ContourNewMenuOptions = []string{"Client", "Server"}
			idx := 0
			for i, o := range app.ContourNewMenuOptions {
				if o == app.ContourNewRole {
					idx = i
				}
			}
			app.ContourNewMenuIndex = idx
		case 1: // Protocol
			if len(app.ContourNewMethods) > 0 {
				app.ContourNewShowMenu = true
				app.ContourNewMenuKind = "method"
				app.ContourNewMenuTitle = "Protocol"
				app.ContourNewMenuOptions = app.ContourNewMethods
				idx := 0
				for i, o := range app.ContourNewMenuOptions {
					if o == app.ContourNewMethod {
						idx = i
					}
				}
				app.ContourNewMenuIndex = idx
			}
		case 2: // Direction
			app.ContourNewShowMenu = true
			app.ContourNewMenuKind = "direction"
			app.ContourNewMenuTitle = "Direction"
			app.ContourNewMenuOptions = []string{"Forward", "Reverse"}
			idx := 0
			if app.ContourNewDirection == "Reverse" {
				idx = 1
			}
			app.ContourNewMenuIndex = idx
		case 3: // Action
			StartContourTunnel(app)
		}
		return true
	case tcell.KeyEscape:
		return false
	}

	if tev.Key() == tcell.KeyRune {
		r := tev.Rune()
		if r == 'q' {
			return false
		}
		if r == '?' {
			app.ContourShowHelp = true
			return true
		}
	}

	return false
}

func StopContourNewOp(app *shared.AppState) {
	if !app.ContourNewActive {
		// Clear any stale done channel without blocking.
		if app.ContourNewDone != nil {
			select {
			case <-app.ContourNewDone:
			default:
			}
			app.ContourNewDone = nil
		}
		return
	}

	// Cancel the context first.
	if app.ContourNewCancel != nil {
		app.ContourNewCancel()
		app.ContourNewCancel = nil
	}
	app.ContourNewActive = false

	// Wait for done with timeout to prevent UI freeze.
	if app.ContourNewDone != nil {
		select {
		case <-app.ContourNewDone:
		case <-time.After(2 * time.Second):
			// Tunnel didn't exit in time - proceed anyway.
		}
		app.ContourNewDone = nil
	}
}

func ContourNewMaxField(mode, role string) int {
	if mode == "Scan" || mode == "Listen" {
		return 0
	}
	if mode == "Services" {
		return 4 // Role, Service, Method, Direction, Action
	}
	return 3 // Role, Protocol, Direction, Action
}

func StartContourTunnel(app *shared.AppState) {
	if app.ContourNewActive {
		StopContourNewOp(app)
		setWorkflowStatus(app, &app.ContourStatusText, &app.ContourStatusError, &app.ContourStatusUntil,
			"operation stopped", false)
		return
	}
	StopContourNewOp(app)

	role := app.ContourNewRole
	if role == "" {
		role = "Client"
	}

	// Determine method and ports based on mode (Services vs normal Tunnel).
	var method string
	var ports []int
	if app.ContourNewMode == "Services" {
		// Services mode: derive tunnel protocol from selected service.
		service := app.ContourNewService
		if service == "" {
			setWorkflowStatus(app, &app.ContourStatusText, &app.ContourStatusError, &app.ContourStatusUntil,
				"no service selected", true)
			return
		}
		// Default to Route Through if not explicitly set.
		if app.ContourNewServiceMethod == "" {
			app.ContourNewServiceMethod = "Route Through"
		}
		// Route Through uses dead drop (API-only relay, no direct TCP).
		if app.ContourNewServiceMethod == "Route Through" {
			method = contour.ServiceMethodToProtoDeadDrop(service)
		} else {
			method = contour.ServiceMethodToProto(service)
		}
		// Service tunnels use standard HTTPS ports as fallback.
		// Dead drop tunnels don't need ports but we still set them
		// so the ports-empty check doesn't block dead drop launches.
		ports = app.ContourNewMethodPorts[app.ContourNewMethod]
		if len(ports) == 0 {
			ports = []int{443, 8443}
		}
	} else {
		method = app.ContourNewMethod
		ports = app.ContourNewMethodPorts[method]
	}

	if app.ContourNewPort > 0 {
		ports = []int{app.ContourNewPort}
	}

	// Check for "All Protocols" mode (server only).
	isAllProtocols := strings.EqualFold(method, "all") || strings.EqualFold(method, "All Protocols")

	if !isAllProtocols && len(ports) == 0 {
		setWorkflowStatus(app, &app.ContourStatusText, &app.ContourStatusError, &app.ContourStatusUntil,
			"no ports available — run a scan first", true)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	app.ContourNewCancel = cancel
	app.ContourNewDone = done
	app.ContourNewActive = true

	app.ProgressMu.Lock()
	app.ContourProgressLines = nil
	app.ProgressMu.Unlock()

	emit := func(line string) {
		app.ProgressMu.Lock()
		app.ContourProgressLines = append(app.ContourProgressLines, line)
		app.ProgressMu.Unlock()
	}

	target := app.ContourProbeEndpoint
	direction := app.ContourNewDirection
	if direction == "" {
		direction = "Forward"
	}

	go func() {
		var result contour.TunnelResult

		if isAllProtocols && role == "Server" {
			// Multi-port server mode: listen on all protocol ports.
			emit("[*] Starting multi-protocol tunnel server...")
			protocolPorts := contour.DefaultProtocolPorts()
			result = contour.RunMultiPortTunnelServer(ctx, contour.MultiPortServerInput{
				ProtocolPorts: protocolPorts,
				Direction:     direction,
				Emit:          emit,
			})
		} else {
			emit(fmt.Sprintf("[*] %s tunnel — %s", direction, role))
			result = contour.RunTunnel(ctx, contour.TunnelInput{
				Role:      role,
				Method:    method,
				Ports:     ports,
				Target:    target,
				Direction: direction,
				Emit:      emit,
			})
		}

		if result.Error != nil {
			emit(fmt.Sprintf("[-] Tunnel error: %s", result.Error))
			setWorkflowStatus(app, &app.ContourStatusText, &app.ContourStatusError, &app.ContourStatusUntil,
				result.Error.Error(), true)
		}
		app.ContourNewActive = false
		close(done)
	}()

	statusMsg := fmt.Sprintf("%s tunnel starting...", role)
	if isAllProtocols {
		statusMsg = "multi-protocol server starting..."
	}
	setWorkflowStatus(app, &app.ContourStatusText, &app.ContourStatusError, &app.ContourStatusUntil, statusMsg, false)
}

func HandleContourKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if app.ContourShowHelp || app.ContourShowMenu {
		return handleContourOverlayKey(app, tev)
	}
	NormalizeContourFieldSelection(app)
	switch tev.Key() {
	case tcell.KeyUp:
		MoveContourField(app, -1)
	case tcell.KeyDown:
		MoveContourField(app, 1)
	case tcell.KeyBackspace, tcell.KeyBackspace2:
		handleContourBackspace(app)
	case tcell.KeyEnter:
		handleContourEnter(app)
	case tcell.KeyEscape:
		if app.ContourEditing {
			app.ContourEditing = false
		} else {
			app.Mode = shared.ModeDashboard
		}
	}

	switch tev.Rune() {
	case '?':
		if !app.ContourEditing {
			app.ContourShowHelp = true
			app.ContourHelpIndex = 0
			return false
		}
	case 'q':
		if app.ContourEditing {
			break
		}
		return requestQuit(app)
	}

	if tev.Key() == tcell.KeyRune && tev.Rune() != 0 {
		handleContourRuneInput(app, tev.Rune())
	}
	return false
}

func handleContourOverlayKey(app *shared.AppState, tev *tcell.EventKey) bool {
	return handleOverlayKey(app, tev, overlayState{
		showHelp: &app.ContourShowHelp, showMenu: &app.ContourShowMenu,
		helpIndex: &app.ContourHelpIndex, menuIndex: &app.ContourMenuIndex,
		menuOptions: &app.ContourMenuOptions, menuKind: &app.ContourMenuKind,
		menuTitle: &app.ContourMenuTitle, helpOptions: contourMenuHelpOptions,
		applyMenu: func(a *shared.AppState) { applyContourMenuSelection(a) },
	})
}

func contourMenuHelpOptions() []string {
	return []string{
		"[Navigation]",
		"UP/DOWN      Move field",
		"TAB/BTAB     Next / prev field",
		"LEFT/RIGHT   Cycle workflows",
		"",
		"[Editing]",
		"ENTER        Edit / open / start",
		"BACKSPACE    Delete while editing",
		"",
		"[Report]",
		"PGUP/PGDN    Scroll report page",
		"[ / ]        Scroll report line",
		"",
		"[Actions]",
		"?            Close this menu",
		"ESC          Back to dashboard",
		"q            Quit",
	}
}

func openContourMenu(app *shared.AppState, kind, title string, options []string, selected int) {
	openWorkflowMenu(kind, title, options, selected, &app.ContourShowHelp, &app.ContourShowMenu, &app.ContourMenuKind, &app.ContourMenuTitle, &app.ContourMenuOptions, &app.ContourMenuIndex)
}

func applyContourMenuSelection(app *shared.AppState) {
	if len(app.ContourMenuOptions) == 0 {
		return
	}
	choice := app.ContourMenuOptions[clampChoice(app.ContourMenuIndex, len(app.ContourMenuOptions))]
	switch app.ContourMenuKind {
	case "source":
		app.ContourSource = choice
		app.ContourSourceIndex = clampChoice(app.ContourMenuIndex, len(app.ContourMenuOptions))
	case "duration":
		app.ContourDuration = choice
	case "probe-mode":
		app.ContourProbeMode = contour.ProbeModeChecks
		app.ContourProbeRole = contour.ProbeRoleClient
	}
	NormalizeContourFieldSelection(app)
}

func ContourProbeModeOptionsForRole(_ string) []string {
	return []string{contour.ProbeModeChecks}
}

func ContourNormalizeProbeModeForRole(mode, role string) string {
	mode = contour.NormalizeProbeMode(mode)
	opts := ContourProbeModeOptionsForRole(role)
	if len(opts) == 0 {
		return contour.NormalizeProbeMode(mode)
	}
	if findIndex(opts, mode) >= 0 {
		return mode
	}
	return opts[0]
}

func handleContourBackspace(app *shared.AppState) {
	if !app.ContourEditing {
		return
	}
	switch app.ContourField {
	case ContourFieldEndpoint:
		app.ContourProbeEndpoint = trimLastRune(app.ContourProbeEndpoint)
	case ContourFieldOutput:
		app.ContourOutput = trimLastRune(app.ContourOutput)
	}
}

func handleContourEnter(app *shared.AppState) {
	NormalizeContourFieldSelection(app)
	switch app.ContourField {
	case ContourFieldSource:
		if app.ContourActive || app.ContourAnalyzing {
			return
		}
		RefreshContourSources(app)
		opts := app.ContourSourceOpts
		if len(opts) == 0 {
			return
		}
		openContourMenu(app, "source", "Select Host", opts, app.ContourSourceIndex)
	case ContourFieldEndpoint:
		if app.ContourActive || app.ContourAnalyzing {
			return
		}
		if !app.ContourEditing {
			app.ContourProbeEndpoint = ""
		}
		app.ContourEditing = !app.ContourEditing
	case ContourFieldOutput:
		if app.ContourActive || app.ContourAnalyzing {
			return
		}
		app.ContourEditing = !app.ContourEditing
	case ContourFieldDuration:
		if app.ContourActive || app.ContourAnalyzing {
			return
		}
		openContourMenu(app, "duration", "Select Duration", contour.DurationOptions(), findIndex(contour.DurationOptions(), app.ContourDuration))
	case ContourFieldProbeMode:
		if app.ContourActive || app.ContourAnalyzing {
			return
		}
		displayOpts := []string{"Deep"}
		openContourMenu(app, "probe-mode", "Select Depth", displayOpts, 0)
	case ContourFieldAction:
		if app.ContourActive {
			StopContour(app)
			return
		}
		StartContour(app)
	}
}

func ContourFieldVisible(app *shared.AppState, field int) bool {
	if field < ContourFieldSource || field > ContourFieldMax {
		return false
	}
	if field == ContourFieldSource && strings.TrimSpace(app.LocalHost) != "" {
		return false
	}
	// Hide fields not rendered in the simplified Scan setup panel.
	if field == ContourFieldOutput || field == ContourFieldDuration || field == ContourFieldProbeMode || field == ContourFieldProbeRole {
		return false
	}
	return true
}

func NormalizeContourFieldSelection(app *shared.AppState) {
	if app == nil {
		return
	}
	if ContourFieldVisible(app, app.ContourField) {
		return
	}
	app.ContourField = ContourFieldSource
	for app.ContourField <= ContourFieldMax && !ContourFieldVisible(app, app.ContourField) {
		app.ContourField++
	}
	if app.ContourField > ContourFieldMax {
		app.ContourField = ContourFieldSource
	}
}

func MoveContourField(app *shared.AppState, dir int) {
	if app == nil || dir == 0 {
		return
	}
	NormalizeContourFieldSelection(app)
	for tries := 0; tries <= ContourFieldMax; tries++ {
		next := app.ContourField + dir
		if next < ContourFieldSource {
			next = ContourFieldMax
		}
		if next > ContourFieldMax {
			next = ContourFieldSource
		}
		app.ContourField = next
		if ContourFieldVisible(app, app.ContourField) {
			return
		}
	}
}

func handleContourRuneInput(app *shared.AppState, r rune) {
	if !app.ContourEditing || r < 32 || r > 126 {
		return
	}
	switch app.ContourField {
	case ContourFieldEndpoint:
		app.ContourProbeEndpoint += string(r)
	case ContourFieldOutput:
		app.ContourOutput += string(r)
	}
}

func RefreshContourState(app *shared.AppState) {
	if app == nil {
		return
	}
	if strings.TrimSpace(app.ContourOutput) == "" {
		app.ContourOutput = contour.DefaultOutputPath()
	}
	if strings.TrimSpace(app.ContourProbeEndpoint) == "" {
		app.ContourProbeEndpoint = "127.0.0.1"
	}
	if strings.TrimSpace(app.ContourProbeMode) == "" {
		app.ContourProbeMode = contour.DefaultProbeMode()
	}
	if strings.TrimSpace(app.ContourProbeRole) == "" {
		app.ContourProbeRole = contour.DefaultProbeRole()
	}
	app.ContourProbeMode = contour.NormalizeProbeMode(app.ContourProbeMode)
	app.ContourProbeRole = contour.NormalizeProbeRole(app.ContourProbeRole)
	app.ContourProbeMode = ContourNormalizeProbeModeForRole(app.ContourProbeMode, app.ContourProbeRole)
	RefreshContourSources(app)
	if strings.TrimSpace(app.ContourSource) == "" {
		app.ContourSource = "all"
	}

	report, err := contour.LoadReport(app.ContourOutput)
	switch {
	case err == nil:
		app.ContourReportLines = append([]string(nil), report.ReportLines...)
		app.ContourReportPath = report.OutputPath
		app.ContourReportTime = report.GeneratedAt
		app.ContourHints = CloneContourHints(report.Hints)
		app.ContourReportScroll = 0
	case errors.Is(err, os.ErrNotExist):
		app.ContourReportLines = nil
		app.ContourReportPath = ""
		app.ContourReportTime = time.Time{}
		app.ContourHints = nil
		app.ContourReportScroll = 0
	case err != nil:
		setWorkflowStatus(app, &app.ContourStatusText, &app.ContourStatusError, &app.ContourStatusUntil, "contour report load failed: "+err.Error(), true)
	}
}

func StartContourListener(app *shared.AppState) {
	if app.ContourNewActive {
		if app.ContourNewCancel != nil {
			app.ContourNewCancel()
			app.ContourNewCancel = nil
		}
		app.ContourNewActive = false
		// Wait for done with timeout.
		if app.ContourNewDone != nil {
			select {
			case <-app.ContourNewDone:
			case <-time.After(2 * time.Second):
			}
			app.ContourNewDone = nil
		}
		setWorkflowStatus(app, &app.ContourStatusText, &app.ContourStatusError, &app.ContourStatusUntil,
			"listener stopped", false)
		return
	}

	ports := contour.DefaultProbePorts()
	if len(ports) == 0 {
		setWorkflowStatus(app, &app.ContourStatusText, &app.ContourStatusError, &app.ContourStatusUntil,
			"no ports configured", true)
		return
	}

	app.ContourNewActive = true
	setWorkflowStatus(app, &app.ContourStatusText, &app.ContourStatusError, &app.ContourStatusUntil,
		fmt.Sprintf("listener starting on %d ports...", len(ports)), false)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	app.ContourNewCancel = cancel
	app.ContourNewDone = done

	app.ProgressMu.Lock()
	app.ContourProgressLines = []string{fmt.Sprintf("[+] Starting protocol-aware listener on %d ports", len(ports))}
	app.ProgressMu.Unlock()

	go func() {
		result := contour.RunListenerProbe(ctx, ports, func(snap contour.ListenerProbeResult) {
			activePorts := make([]int, 0, len(ports))
			for _, port := range ports {
				unavail := false
				for _, u := range snap.PortsUnavailable {
					if u == port {
						unavail = true
						break
					}
				}
				if !unavail {
					activePorts = append(activePorts, port)
				}
			}

			// Server owns the listener — all supported protocols work on all
			// active ports because the tunnel server handles any protocol.
			// Build checks for every protocol on every active port.
			protoNames := contour.DefaultProtocolNames()
			var checks []contour.ProbeCheck
			for _, proto := range protoNames {
				for _, port := range activePorts {
					checks = append(checks, contour.ProbeCheck{
						Kind:    contour.ClassifyProtoKind(proto),
						Method:  proto,
						Port:    port,
						Success: true,
					})
				}
			}
			summary := &contour.ProbeSummary{
				SuccessfulChecks: checks,
				Ports:            activePorts,
			}

			var lines []string
			lines = append(lines, fmt.Sprintf("[+] Listening on %d/%d ports", len(activePorts), len(ports)))
			for _, port := range snap.PortsUnavailable {
				lines = append(lines, fmt.Sprintf("[-] Port %d: unavailable", port))
			}
			if snap.Exchanges > 0 {
				lines = append(lines, fmt.Sprintf("[+] %d protocol exchange(s) detected", snap.Exchanges))
				seen := make(map[string]bool)
				for _, check := range snap.Checks {
					key := fmt.Sprintf("%s:%d", check.Method, check.Port)
					if !seen[key] {
						seen[key] = true
						lines = append(lines, fmt.Sprintf("[+] %s/%s port %d from %s",
							strings.ToUpper(check.Transport), check.Method, check.Port, check.Peer))
					}
				}
			} else {
				lines = append(lines, "[*] Waiting for scan connections...")
			}

			app.ProgressMu.Lock()
			app.ContourPartialProbe = summary
			app.ContourProgressLines = lines
			app.ProgressMu.Unlock()
		})

		var lines []string
		bound := len(ports) - len(result.PortsUnavailable)
		lines = append(lines, fmt.Sprintf("[*] Listener stopped — %d ports, %d exchanges", bound, result.Exchanges))
		app.ProgressMu.Lock()
		app.ContourProgressLines = lines
		app.ProgressMu.Unlock()
		app.ContourNewActive = false
		close(done)
	}()
}

func StartContour(app *shared.AppState) {
	if app == nil {
		return
	}
	if app.ContourActive || app.ContourAnalyzing {
		setWorkflowStatus(app, &app.ContourStatusText, &app.ContourStatusError, &app.ContourStatusUntil,
			"contour scan is already running", false)
		return
	}
	output := strings.TrimSpace(app.ContourOutput)
	base := strings.ToLower(strings.TrimSpace(filepath.Base(output)))
	if output == "" || strings.EqualFold(output, contour.DefaultOutputPath()) || strings.EqualFold(base, "latest.json") || strings.HasPrefix(base, "proxywatch-contour-") {
		app.ContourOutput = contour.NewRunOutputPath()
	}
	app.ContourProbeRole = contour.ProbeRoleClient
	app.ContourProbeMode = contour.ProbeModeChecks
	if strings.TrimSpace(app.ContourProbeEndpoint) == "" {
		setWorkflowStatus(app, &app.ContourStatusText, &app.ContourStatusError, &app.ContourStatusUntil, "contour failed: endpoint is required", true)
		return
	}

	app.ContourActive = true
	app.ContourAnalyzing = false
	app.ContourCancel = nil
	app.ContourStartedAt = time.Now()
	app.ContourUntil = app.ContourStartedAt
	app.ContourSampleEvery = 5 * time.Second
	app.ContourLastSample = time.Time{}
	app.ContourSamples = nil
	app.ContourEditing = false
	app.ContourShowMenu = false
	app.ContourReportScroll = 0
	app.ContourReportLines = nil
	app.ContourReport = nil
	app.ContourPartialProbe = nil
	app.ContourPartialReportLines = nil
	app.ContourProgressLines = nil
	endpoint := strings.TrimSpace(app.ContourProbeEndpoint)
	if endpoint == "" {
		endpoint = "-"
	}
	startMsg := "contour started (endpoint " + endpoint + ")"
	setWorkflowStatus(app, &app.ContourStatusText, &app.ContourStatusError, &app.ContourStatusUntil, startMsg, false)
}

func StopContour(app *shared.AppState) {
	if app == nil || !app.ContourActive {
		return
	}
	if app.ContourAnalyzing {
		if app.ContourCancel != nil {
			app.ContourCancel()
		}
		setWorkflowStatus(app, &app.ContourStatusText, &app.ContourStatusError, &app.ContourStatusUntil, "stopping contour run...", false)
		return
	}
	app.ContourUntil = time.Now().Add(-time.Second)
	setWorkflowStatus(app, &app.ContourStatusText, &app.ContourStatusError, &app.ContourStatusUntil, "stopping collection, analyzing now...", false)
}

func UpdateContourState(app *shared.AppState, contourCh chan<- ContourExecResult, inFlight *bool) {
	if app == nil || !app.ContourActive || app.ContourAnalyzing {
		return
	}
	if app.ContourSampleEvery <= 0 {
		app.ContourSampleEvery = 5 * time.Second
	}
	now := time.Now()
	if contour.NormalizeProbeRole(app.ContourProbeRole) != contour.ProbeRoleListen {
		if app.ContourLastSample.IsZero() || now.Sub(app.ContourLastSample) >= app.ContourSampleEvery {
			collected := ContourCandidatesForSource(app)
			for _, c := range collected {
				app.ContourSamples = append(app.ContourSamples, CloneCandidate(c))
			}
			app.ContourLastSample = now
		}
	}
	if !app.ContourUntil.IsZero() && now.After(app.ContourUntil) {
		BeginContourAnalysis(app, contourCh, inFlight)
	}
}

func BeginContourAnalysis(app *shared.AppState, contourCh chan<- ContourExecResult, inFlight *bool) {
	if app == nil || !app.ContourActive || app.ContourAnalyzing || *inFlight {
		return
	}
	duration := time.Since(app.ContourStartedAt)
	role := contour.NormalizeProbeRole(app.ContourProbeRole)
	mode := contour.NormalizeProbeMode(app.ContourProbeMode)
	if role == contour.ProbeRoleListen {
		duration = ContourListenRunDuration
	} else if mode != contour.ProbeModeOff {
		if duration < time.Second {
			duration = time.Second
		}
	}
	if duration <= 0 {
		duration = time.Second
	}
	if role == contour.ProbeRoleListen {
		app.ContourUntil = time.Time{}
	}
	app.ContourAnalyzing = true
	app.ContourEditing = false
	if role == contour.ProbeRoleListen {
		setWorkflowStatus(app, &app.ContourStatusText, &app.ContourStatusError, &app.ContourStatusUntil, "listener active; waiting for contour checks...", false)
	} else {
		setWorkflowStatus(app, &app.ContourStatusText, &app.ContourStatusError, &app.ContourStatusUntil, "analyzing contour findings...", false)
	}
	input := contour.RunInput{
		Source:      app.ContourSource,
		Duration:    duration.Round(time.Second),
		SampleEvery: app.ContourSampleEvery,
		Output:      app.ContourOutput,
		ProbeRole:   app.ContourProbeRole,
		ProbeTarget: app.ContourProbeEndpoint,
		ProbeMode:   app.ContourProbeMode,
		Samples:     CloneCalibrationSamples(app.ContourSamples),
		OnProgress: func(lines []string) {
			cp := make([]string, len(lines))
			copy(cp, lines)
			app.ProgressMu.Lock()
			app.ContourProgressLines = cp
			app.ProgressMu.Unlock()
		},
		OnPartial: func(report contour.Report) {
			app.ProgressMu.Lock()
			cp := make([]string, len(report.ReportLines))
			copy(cp, report.ReportLines)
			app.ContourPartialReportLines = cp
			if report.Probe != nil {
				probeCopy := *report.Probe
				app.ContourPartialProbe = &probeCopy
			}
			app.ProgressMu.Unlock()
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	app.ContourCancel = cancel
	*inFlight = true
	go func() {
		result, err := contour.ExecuteContext(ctx, input)
		contourCh <- ContourExecResult{
			Result: result,
			Err:    err,
		}
	}()
}

func ApplyContourExecResult(app *shared.AppState, res ContourExecResult) {
	if app == nil {
		return
	}
	app.ContourCancel = nil
	app.ContourPartialReportLines = nil
	if res.Err != nil {
		if errors.Is(res.Err, context.Canceled) {
			setWorkflowStatus(app, &app.ContourStatusText, &app.ContourStatusError, &app.ContourStatusUntil, "contour stopped.", false)
		} else {
			setWorkflowStatus(app, &app.ContourStatusText, &app.ContourStatusError, &app.ContourStatusUntil, "contour failed: "+res.Err.Error(), true)
		}
	} else {
		result := res.Result
		app.ContourOutput = result.ReportPath
		app.ContourReportPath = result.ReportPath
		app.ContourReportTime = result.Report.GeneratedAt
		app.ContourReportLines = append([]string(nil), result.Report.ReportLines...)
		reportCopy := result.Report
		app.ContourReport = &reportCopy
		app.ContourHints = CloneContourHints(result.Hints)
		app.ContourReportScroll = 0
		// Persist the final probe result so tunnel methods stay populated.
		if result.Report.Probe != nil {
			probeCopy := *result.Report.Probe
			app.ContourPartialProbe = &probeCopy
		}
		if result.Report.Probe != nil && result.Report.Probe.Enabled {
			var egressPaths []model.EgressPath
			for _, pr := range result.Report.Probe.PortResults {
				if pr.TunnelSuccess == 0 && pr.ExfilSuccess == 0 {
					continue
				}
				conf := 0.0
				if pr.TunnelAttempts > 0 {
					conf = float64(pr.TunnelSuccess) / float64(pr.TunnelAttempts)
				} else if pr.ExfilAttempts > 0 {
					conf = float64(pr.ExfilSuccess) / float64(pr.ExfilAttempts)
				}
				egressPaths = append(egressPaths, model.EgressPath{
					Port:          pr.Port,
					TunnelCapable: pr.TunnelSuccess > 0,
					ExfilCapable:  pr.ExfilSuccess > 0,
					Confidence:    conf,
				})
			}
			for _, mr := range result.Report.Probe.MethodResults {
				if mr.TunnelSuccess == 0 && mr.ExfilSuccess == 0 {
					continue
				}
				for i := range egressPaths {
					if egressPaths[i].TunnelCapable || egressPaths[i].ExfilCapable {
						egressPaths[i].Protocols = append(egressPaths[i].Protocols, mr.Method)
					}
				}
			}
			model.IngestContourEgressPaths(egressPaths)
		}
		setWorkflowStatus(app, &app.ContourStatusText, &app.ContourStatusError, &app.ContourStatusUntil, "contour report written: "+result.ReportPath+" (hints exported "+strconv.Itoa(len(result.Hints))+")", false)
	}
	app.ContourActive = false
	app.ContourAnalyzing = false
	app.ContourStartedAt = time.Time{}
	app.ContourLastSample = time.Time{}
	app.ContourSamples = nil
	app.ContourEditing = false
	RefreshContourState(app)
}

func RefreshContourSources(app *shared.AppState) {
	if app == nil {
		return
	}
	opts := CollectSourceOptions(app)
	app.ContourSourceOpts = opts
	if len(opts) == 0 {
		app.ContourSource = "all"
		app.ContourSourceIndex = 0
		return
	}
	current := strings.TrimSpace(app.ContourSource)
	if current == "" {
		current = "all"
	}
	idx := findIndex(opts, current)
	if idx < 0 {
		for i, opt := range opts {
			if strings.EqualFold(opt, current) {
				idx = i
				break
			}
		}
	}
	if idx < 0 {
		idx = 0
	}
	app.ContourSourceIndex = idx
	app.ContourSource = opts[idx]
}

func ContourCandidatesForSource(app *shared.AppState) []shared.Candidate {
	if app == nil {
		return nil
	}
	source := strings.TrimSpace(app.ContourSource)

	if source == "" || strings.EqualFold(source, "all") {
		return app.Candidates
	}
	out := make([]shared.Candidate, 0, len(app.Candidates))
	for _, c := range app.Candidates {
		if strings.EqualFold(shared.DisplayHost(c.Host), source) {
			out = append(out, c)
		}
	}
	return out
}
