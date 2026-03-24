package ui

import (
	"time"

	"proxywatch/internal/calibration"
	"proxywatch/internal/contour"
	"proxywatch/internal/shared"
	"proxywatch/internal/siem"

	"github.com/gdamore/tcell/v2"
)

const quitConfirmTimeout = 5 * time.Second

const (
	collectFieldSource = iota
	collectFieldOutput
	collectFieldDuration
	collectFieldAction
)

const collectFieldMax = collectFieldAction

const (
	whitelistFieldProcess = iota
	whitelistFieldEntry
	whitelistFieldAdd
	whitelistFieldRemove
)

const whitelistFieldMax = whitelistFieldRemove

const (
	calibrateFieldProvider = iota
	calibrateFieldOutput
	calibrateFieldDuration
	calibrateFieldModel
	calibrateFieldProfile
	calibrateFieldAction
	calibrateFieldApply
)

const calibrateFieldMax = calibrateFieldApply

const (
	contourFieldEndpoint = iota
	contourFieldOutput
	contourFieldDuration
	contourFieldProbeMode
	contourFieldProbeRole
	contourFieldAction
)

const contourFieldMax = contourFieldAction

const (
	siemFieldSourceReport = iota
	siemFieldProvider
	siemFieldModel
	siemFieldReportOutput
	siemFieldJSONOutput
	siemFieldGenerate
	siemFieldSaveGeneration
	siemFieldCalibrate
	siemFieldDebugLog
	siemFieldRulesJSON
	siemFieldApply
	siemFieldSave
	siemFieldDisable
)

const siemFieldMax = siemFieldDisable

const (
	keystoreFieldOpenAIKey = iota
	keystoreFieldOpenAIBaseURL
	keystoreFieldAnthropicKey
	keystoreFieldAnthropicBaseURL
	keystoreFieldLocalLLMURL
	keystoreFieldLocalLLMAPIKey
	keystoreFieldCalibrationTimeout
	keystoreFieldBloodhoundURL
	keystoreFieldBloodhoundToken
	keystoreFieldBloodhoundTokenID
	keystoreFieldTLSDir
	keystoreFieldAgentToken
	keystoreFieldDisableClientCert
	keystoreFieldTrustOnFirstUse
	keystoreFieldLoad
	keystoreFieldSave
	keystoreFieldApply
)

const keystoreFieldMax = keystoreFieldApply

var (
	roleMenuChoices    = []string{"recommended", "all", "control", "reverse", "listener", "outbound"}
	sortMenuChoices    = []string{"default", "host", "role", "age", "state", "pid", "process"}
	refreshMenuChoices = []string{"100ms", "250ms", "500ms", "1s", "2s", "5s"}
)

type refreshResult struct {
	candidates          []shared.Candidate
	snapshotCandidates  []shared.Candidate
	hostSummaries       []shared.HostSummary
	lastError           string
	lastUpdate          time.Time
	selectedKey         string
	selectedIdx         int
	selectionKeyAtStart string
}

type calibrationExecResult struct {
	result calibration.RunResult
	err    error
}

type contourExecResult struct {
	result contour.RunResult
	err    error
}

type siemExecResult struct {
	result siem.SIEMRunResult
	err    error
}

func Run(app *shared.AppState, scanner shared.Scanner) error {
	s, err := tcell.NewScreen()
	if err != nil {
		return err
	}
	if err := s.Init(); err != nil {
		return err
	}
	defer s.Fini()

	app.Screen = s
	initAppDefaults(app)

	scanner.Refresh(app)
	resortCandidates(app)
	normalizeInitialWhitelistSelection(app)

	events := startEventPump(s)
	refreshCh := make(chan refreshResult, 1)
	refreshInFlight := false
	calibrateCh := make(chan calibrationExecResult, 1)
	calibrateInFlight := false
	contourCh := make(chan contourExecResult, 1)
	contourInFlight := false
	siemCh := make(chan siemExecResult, 1)
	siemInFlight := false
	app.StartSIEMGeneration = func(sourceReport, provider, model, outputReport, outputJSON string) {
		if siemInFlight {
			return
		}
		siemInFlight = true
		go func() {
			result, err := siem.ExecuteSIEM(siem.SIEMRunInput{
				SourceReport: sourceReport,
				Provider:     provider,
				Model:        model,
				OutputReport: outputReport,
				OutputJSON:   outputJSON,
			})
			siemCh <- siemExecResult{result: result, err: err}
		}()
	}

	tick := time.NewTicker(app.RefreshInt)
	tickDur := app.RefreshInt
	defer tick.Stop()

	for {
		if app.RefreshInt <= 0 {
			app.RefreshInt = 250 * time.Millisecond
		}
		if app.RefreshInt != tickDur {
			tick.Reset(app.RefreshInt)
			tickDur = app.RefreshInt
		}

		clearExpiredKillConfirmation(app)
		clearExpiredQuitConfirmation(app)
		drawCurrentMode(app)
		s.Show()

		if app.RefreshRequested {
			app.RefreshRequested = false
			beginRefresh(app, scanner, refreshCh, &refreshInFlight)
		}

		select {
		case ev := <-events:
			if handleUIEvent(app, s, ev) {
				return nil
			}

		case <-tick.C:
			if shouldPausePeriodicRefresh(app) {
				continue
			}
			beginRefresh(app, scanner, refreshCh, &refreshInFlight)

		case res := <-refreshCh:
			refreshInFlight = false
			applyRefreshResult(app, res)
			updateCollectionState(app)
			updateContourState(app, contourCh, &contourInFlight)
			updateCalibrationState(app, calibrateCh, &calibrateInFlight)

		case res := <-calibrateCh:
			calibrateInFlight = false
			applyCalibrationExecResult(app, res)

		case res := <-contourCh:
			contourInFlight = false
			applyContourExecResult(app, res)

		case res := <-siemCh:
			siemInFlight = false
			applySIEMExecResult(app, res)
		}
	}
}

func initAppDefaults(app *shared.AppState) {
	if app.RefreshInt <= 0 {
		app.RefreshInt = 1 * time.Second
	}
	if app.ConfirmKillTimeout <= 0 {
		app.ConfirmKillTimeout = 3 * time.Second
	}
	app.SelectedIdx = -1
	app.Mode = shared.ModeDashboard
}

func normalizeInitialWhitelistSelection(app *shared.AppState) {
	if app.WhitelistSelected == 0 && len(app.WhitelistItems) == 0 {
		app.WhitelistSelected = -1
	}
}

func startEventPump(s tcell.Screen) chan tcell.Event {
	events := make(chan tcell.Event, 16)
	go func() {
		for {
			events <- s.PollEvent()
		}
	}()
	return events
}

func clearExpiredKillConfirmation(app *shared.AppState) {
	if app.ConfirmKillKey != "" && time.Now().After(app.ConfirmKillDeadline) {
		app.ConfirmKillKey = ""
	}
}

func clearExpiredQuitConfirmation(app *shared.AppState) {
	if app.ShowQuitConfirm && time.Now().After(app.QuitConfirmDeadline) {
		app.ShowQuitConfirm = false
	}
}

func drawCurrentMode(app *shared.AppState) {
	switch app.Mode {
	case shared.ModeDashboard:
		DrawDashboard(app)
	case shared.ModeInspect:
		DrawInspector(app)
	case shared.ModeWhitelist:
		DrawWhitelist(app)
	case shared.ModeCollect:
		DrawCollect(app)
	case shared.ModeCalibration:
		DrawCalibration(app)
	case shared.ModeContour:
		DrawContour(app)
	case shared.ModeKeystore:
		DrawKeystore(app)
	case shared.ModeSIEM:
		DrawSIEM(app)
	}
	drawQuitConfirmOverlay(app)
}

func handleUIEvent(app *shared.AppState, s tcell.Screen, ev tcell.Event) bool {
	switch tev := ev.(type) {
	case *tcell.EventResize:
		s.Sync()
	case *tcell.EventKey:
		handled, shouldQuit := handleQuitConfirmKey(app, tev)
		if handled {
			return shouldQuit
		}
		return handleKeyEvent(app, tev)
	}
	return false
}

func handleKeyEvent(app *shared.AppState, tev *tcell.EventKey) bool {
	switch app.Mode {
	case shared.ModeDashboard:
		return handleDashboardKey(app, tev)
	case shared.ModeInspect:
		return handleInspectKey(app, tev)
	case shared.ModeWhitelist:
		return handleWhitelistKey(app, tev)
	case shared.ModeCollect:
		return handleCollectKey(app, tev)
	case shared.ModeCalibration:
		return handleCalibrationKey(app, tev)
	case shared.ModeContour:
		return handleContourKey(app, tev)
	case shared.ModeKeystore:
		return handleKeystoreKey(app, tev)
	case shared.ModeSIEM:
		return handleSIEMKey(app, tev)
	default:
		return false
	}
}

func requestQuit(app *shared.AppState) bool {
	now := time.Now()
	if app.ShowQuitConfirm && now.Before(app.QuitConfirmDeadline) {
		app.ShowQuitConfirm = false
		return true
	}
	app.ShowQuitConfirm = true
	app.QuitConfirmDeadline = now.Add(quitConfirmTimeout)
	return false
}

func handleQuitConfirmKey(app *shared.AppState, tev *tcell.EventKey) (handled bool, shouldQuit bool) {
	if !app.ShowQuitConfirm {
		return false, false
	}
	switch tev.Key() {
	case tcell.KeyEscape:
		app.ShowQuitConfirm = false
		return true, false
	case tcell.KeyEnter:
		app.ShowQuitConfirm = false
		return true, true
	}
	switch tev.Rune() {
	case 'y', 'Y', 'q', 'Q':
		app.ShowQuitConfirm = false
		return true, true
	case 'n', 'N':
		app.ShowQuitConfirm = false
		return true, false
	default:
		return true, false
	}
}
