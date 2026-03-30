package ui

import (
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"proxywatch/internal/shared"
	"proxywatch/internal/siem"
)

// ── Message types ───────────────────────────────────────────────────────────

// TickMsg fires on the periodic refresh interval.
type TickMsg time.Time

// RefreshResultMsg carries the result of a background candidate refresh.
type RefreshResultMsg struct{ res refreshResult }

// ContourExecResultMsg carries the result of a contour run.
type ContourExecResultMsg struct{ res contourExecResult }

// CalibrationExecResultMsg carries the result of a calibration run.
type CalibrationExecResultMsg struct{ res calibrationExecResult }

// SIEMExecResultMsg carries the result of a SIEM generation.
type SIEMExecResultMsg struct{ res siemExecResult }

// ── Root Model ──────────────────────────────────────────────────────────────

// RootModel is the top-level bubbletea model that owns the terminal.
// It routes input and rendering to either the native ContourModel or the
// LegacyModel (for all other views).
type RootModel struct {
	app     *shared.AppState
	scanner shared.Scanner

	dashboard   DashboardModel
	inspector   InspectorModel
	contour     ContourModel
	calibration CalibrationModel
	siem        SIEMModel
	bloodhound  BloodHoundModel
	keystore    KeystoreModel
	whitelist   WhitelistModel
	legacy      LegacyModel

	width  int
	height int

	// Async work channels — the same pattern as the tcell event loop,
	// but results arrive as tea.Msg via tea.Cmd.
	refreshCh   chan refreshResult
	calibrateCh chan calibrationExecResult
	contourCh   chan contourExecResult
	siemCh      chan siemExecResult

	refreshInFlight   bool
	calibrateInFlight bool
	contourInFlight   bool
	siemInFlight      bool

	// Tracking whether a wait command is already listening on each channel.
	refreshWaiting   bool
	calibrateWaiting bool
	contourWaiting   bool
	siemWaiting      bool
}

// NewRootModel creates the top-level model for the bubbletea program.
func NewRootModel(app *shared.AppState, scanner shared.Scanner) RootModel {
	return RootModel{
		app:         app,
		scanner:     scanner,
		dashboard:   NewDashboardModel(app),
		inspector:   NewInspectorModel(app),
		contour:     NewContourModel(app),
		calibration: NewCalibrationModel(app),
		siem:        NewSIEMModel(app),
		bloodhound:  NewBloodHoundModel(app),
		keystore:    NewKeystoreModel(app),
		whitelist:   NewWhitelistModel(app),
		legacy:      NewLegacyModel(app),
		refreshCh:   make(chan refreshResult, 1),
		calibrateCh: make(chan calibrationExecResult, 1),
		contourCh:   make(chan contourExecResult, 1),
		siemCh:      make(chan siemExecResult, 1),
	}
}

func (m RootModel) Init() tea.Cmd {
	// Only start the tick. Wait commands are started when work is launched.
	return m.tickCmd()
}

func (m RootModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.app.ScreenWidth = msg.Width
		m.app.ScreenHeight = msg.Height

		// Forward to all models.
		m.dashboard, _ = m.dashboard.Update(msg)
		m.inspector, _ = m.inspector.Update(msg)
		m.contour, _ = m.contour.Update(msg)
		m.calibration, _ = m.calibration.Update(msg)
		m.siem, _ = m.siem.Update(msg)
		m.bloodhound, _ = m.bloodhound.Update(msg)
		m.keystore, _ = m.keystore.Update(msg)
		m.whitelist, _ = m.whitelist.Update(msg)
		m.legacy, _ = m.legacy.Update(msg)
		return m, nil

	case TickMsg:
		clearExpiredKillConfirmation(m.app)
		clearExpiredQuitConfirmation(m.app)

		// Auto-calibration.
		if m.app.AutoCalibrateEnabled && m.app.AutoCalibrateInterval > 0 &&
			!m.app.CalibrateActive && !m.app.CalibrateAnalyzing &&
			time.Since(m.app.AutoCalibrateLastRun) >= m.app.AutoCalibrateInterval {
			m.app.AutoCalibrateLastRun = time.Now()
			if m.app.CalibrateProvider != "" {
				beginCalibrationAnalysis(m.app, m.calibrateCh, &m.calibrateInFlight)
			}
		}

		// Periodic refresh.
		if !shouldPausePeriodicRefresh(m.app) {
			beginRefresh(m.app, m.scanner, m.refreshCh, &m.refreshInFlight)
		}
		if m.app.RefreshRequested {
			m.app.RefreshRequested = false
			beginRefresh(m.app, m.scanner, m.refreshCh, &m.refreshInFlight)
		}

		// Check contour state on every tick.
		updateContourState(m.app, m.contourCh, &m.contourInFlight)

		// Refresh view-specific content on every tick so live data updates.
		switch m.app.Mode {
		case shared.ModeInspect:
			m.inspector.refreshContent()
		case shared.ModeCalibration:
			m.calibration.refreshContent()
		case shared.ModeSIEM:
			m.siem.refreshContent()
		case shared.ModeCollect:
			m.bloodhound.refreshContent()
		}

		cmds = append(cmds, m.startPendingWaits()...)
		cmds = append(cmds, m.tickCmd())
		return m, tea.Batch(cmds...)

	case RefreshResultMsg:
		m.refreshInFlight = false
		m.refreshWaiting = false
		applyRefreshResult(m.app, msg.res)
		updateCollectionState(m.app)
		updateContourState(m.app, m.contourCh, &m.contourInFlight)
		updateCalibrationState(m.app, m.calibrateCh, &m.calibrateInFlight)
		cmds = append(cmds, m.startPendingWaits()...)
		return m, tea.Batch(cmds...)

	case ContourExecResultMsg:
		m.contourInFlight = false
		m.contourWaiting = false
		applyContourExecResult(m.app, msg.res)
		m.contour.refreshContent()
		return m, nil

	case CalibrationExecResultMsg:
		m.calibrateInFlight = false
		m.calibrateWaiting = false
		applyCalibrationExecResult(m.app, msg.res)
		return m, nil

	case SIEMExecResultMsg:
		m.siemInFlight = false
		m.siemWaiting = false
		applySIEMExecResult(m.app, msg.res)
		return m, nil
	}

	// Keep contour spinner alive while scan is running, even when
	// viewing another view. Without this the tick chain breaks
	// and spinners freeze when switching back.
	if m.app.Mode != shared.ModeContour && (m.app.ContourActive || m.app.ContourAnalyzing) {
		var cmd tea.Cmd
		m.contour, cmd = m.contour.Update(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	}

	// Route input/other messages to the active view.
	switch m.app.Mode {
	case shared.ModeDashboard:
		var cmd tea.Cmd
		m.dashboard, cmd = m.dashboard.Update(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	case shared.ModeInspect:
		var cmd tea.Cmd
		m.inspector, cmd = m.inspector.Update(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	case shared.ModeContour:
		var cmd tea.Cmd
		m.contour, cmd = m.contour.Update(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	case shared.ModeCalibration:
		var cmd tea.Cmd
		m.calibration, cmd = m.calibration.Update(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	case shared.ModeSIEM:
		var cmd tea.Cmd
		m.siem, cmd = m.siem.Update(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	case shared.ModeCollect:
		var cmd tea.Cmd
		m.bloodhound, cmd = m.bloodhound.Update(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	case shared.ModeKeystore:
		var cmd tea.Cmd
		m.keystore, cmd = m.keystore.Update(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	case shared.ModeWhitelist:
		var cmd tea.Cmd
		m.whitelist, cmd = m.whitelist.Update(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	default:
		var cmd tea.Cmd
		m.legacy, cmd = m.legacy.Update(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	}

	// Ensure viewport-based views have content initialized before first render.
	switch m.app.Mode {
	case shared.ModeInspect:
		m.inspector.initViewport()
		m.inspector.refreshContent()
	case shared.ModeCalibration:
		m.calibration.initViewport()
		m.calibration.refreshContent()
	case shared.ModeSIEM:
		m.siem.initViewport()
		m.siem.refreshContent()
	case shared.ModeContour:
		m.contour.initViewport()
		m.contour.refreshContent()
	case shared.ModeCollect:
		m.bloodhound.initViewport()
		m.bloodhound.refreshContent()
	}

	// After key handling, start wait commands for any newly launched async work.
	cmds = append(cmds, m.startPendingWaits()...)

	if len(cmds) > 0 {
		return m, tea.Batch(cmds...)
	}
	return m, nil
}

func (m RootModel) View() string {
	var view string
	switch m.app.Mode {
	case shared.ModeDashboard:
		view = m.dashboard.View()
	case shared.ModeInspect:
		view = m.inspector.View()
	case shared.ModeContour:
		view = m.contour.View()
	case shared.ModeCalibration:
		view = m.calibration.View()
	case shared.ModeSIEM:
		view = m.siem.View()
	case shared.ModeCollect:
		view = m.bloodhound.View()
	case shared.ModeKeystore:
		view = m.keystore.View()
	case shared.ModeWhitelist:
		view = m.whitelist.View()
	default:
		view = m.legacy.View()
	}
	// Clamp output to terminal height to prevent scrolling.
	if m.height > 0 {
		lines := strings.Split(view, "\n")
		if len(lines) > m.height {
			lines = lines[:m.height]
			view = strings.Join(lines, "\n")
		}
	}

	// Global YubiKey touch prompt — shown on any dashboard.
	if m.app.YubiKeyTouchRequired && m.width > 0 && m.height > 0 {
		touchPanel := renderPanel(36, 3, "", "", "", "  🔑 Touch YubiKey to continue...")
		view = overlayCenter(view, touchPanel, m.width, m.height)
	}

	return view
}

// startPendingWaits checks each async channel and starts a wait command if
// work is in-flight but no wait is active yet.
func (m *RootModel) startPendingWaits() []tea.Cmd {
	var cmds []tea.Cmd
	if m.refreshInFlight && !m.refreshWaiting {
		m.refreshWaiting = true
		cmds = append(cmds, m.waitRefresh())
	}
	if m.calibrateInFlight && !m.calibrateWaiting {
		m.calibrateWaiting = true
		cmds = append(cmds, m.waitCalibrate())
	}
	if m.contourInFlight && !m.contourWaiting {
		m.contourWaiting = true
		cmds = append(cmds, m.waitContour())
	}
	if m.siemInFlight && !m.siemWaiting {
		m.siemWaiting = true
		cmds = append(cmds, m.waitSIEM())
	}
	return cmds
}

// ── tea.Cmd helpers ─────────────────────────────────────────────────────────

func (m RootModel) tickCmd() tea.Cmd {
	d := m.app.RefreshInt
	if d <= 0 {
		d = 250 * time.Millisecond
	}
	return tea.Tick(d, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

func (m RootModel) waitRefresh() tea.Cmd {
	ch := m.refreshCh
	return func() tea.Msg {
		return RefreshResultMsg{res: <-ch}
	}
}

func (m RootModel) waitCalibrate() tea.Cmd {
	ch := m.calibrateCh
	return func() tea.Msg {
		return CalibrationExecResultMsg{res: <-ch}
	}
}

func (m RootModel) waitContour() tea.Cmd {
	ch := m.contourCh
	return func() tea.Msg {
		return ContourExecResultMsg{res: <-ch}
	}
}

func (m RootModel) waitSIEM() tea.Cmd {
	ch := m.siemCh
	return func() tea.Msg {
		return SIEMExecResultMsg{res: <-ch}
	}
}

// wireSIEMCallback sets up app.StartSIEMGeneration to write results into the
// given channel and set the in-flight flag.
func wireSIEMCallback(app *shared.AppState, ch chan siemExecResult, inFlight *bool) {
	app.StartSIEMGeneration = func(sourceReport, provider, model, outputReport, outputJSON string) {
		if *inFlight {
			return
		}
		*inFlight = true
		go func() {
			result, err := siem.ExecuteSIEM(siem.SIEMRunInput{
				SourceReport: sourceReport,
				Provider:     provider,
				Model:        model,
				OutputReport: outputReport,
				OutputJSON:   outputJSON,
				OnProgress: func(lines []string) {
					cp := make([]string, len(lines))
					copy(cp, lines)
					app.ProgressMu.Lock()
					app.SIEMProgressLines = cp
					app.ProgressMu.Unlock()
				},
			})
			ch <- siemExecResult{result: result, err: err}
		}()
	}
}
