package keys

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"proxywatch/internal/calibration"
	"proxywatch/internal/keystore"
	"proxywatch/internal/shared"
	"proxywatch/internal/siem"

	"github.com/gdamore/tcell/v2"
)

type SiemExecResult struct {
	Result siem.SIEMRunResult
	Err    error
}

func HandleSIEMKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if app.SIEMShowHelp || app.SIEMShowMenu {
		return handleSIEMOverlayKey(app, tev)
	}
	switch tev.Key() {
	case tcell.KeyUp:
		cycleField(&app.SIEMField, SiemFieldProvider, SiemFieldMaxFor(app), true)
	case tcell.KeyDown:
		cycleField(&app.SIEMField, SiemFieldProvider, SiemFieldMaxFor(app), false)
	case tcell.KeyBackspace, tcell.KeyBackspace2:
		handleSIEMBackspace(app)
	case tcell.KeyEnter:
		handleSIEMEnter(app)
	case tcell.KeyEscape:
		if app.SIEMEditing {
			app.SIEMEditing = false
		} else {
			app.Mode = shared.ModeDashboard
		}
	case tcell.KeyPgUp:
		if !app.SIEMEditing {
			scrollReport(&app.SIEMReportScroll, app.SIEMReportMaxScroll, -8)
		}
	case tcell.KeyPgDn:
		if !app.SIEMEditing {
			scrollReport(&app.SIEMReportScroll, app.SIEMReportMaxScroll, 8)
		}
	case tcell.KeyHome:
		if !app.SIEMEditing {
			app.SIEMReportScroll = 0
		}
	case tcell.KeyEnd:
		if !app.SIEMEditing {
			app.SIEMReportScroll = app.SIEMReportMaxScroll
		}
	}

	if tev.Key() == tcell.KeyRune && tev.Rune() != 0 {
		if tev.Rune() == '?' && !app.SIEMEditing {
			app.SIEMShowHelp = true
			app.SIEMHelpIndex = 0
			return false
		}
		handleSIEMRuneInput(app, tev.Rune())
		if tev.Rune() == 'q' && app.SIEMEditing {
			return false
		}
	}
	if !app.SIEMEditing {
		switch tev.Rune() {
		case '[':
			scrollReport(&app.SIEMReportScroll, app.SIEMReportMaxScroll, 1)
			return false
		case ']':
			scrollReport(&app.SIEMReportScroll, app.SIEMReportMaxScroll, -1)
			return false
		}
	}
	if tev.Rune() == 'q' && !app.SIEMEditing {
		return requestQuit(app)
	}
	return false
}

func handleSIEMBackspace(app *shared.AppState) {
	if !app.SIEMEditing {
		return
	}
	switch app.SIEMField {
	case SiemFieldModel:
		app.SIEMModel = trimLastRune(app.SIEMModel)
	case SiemFieldReportOutput:
		app.SIEMReportPath = trimLastRune(app.SIEMReportPath)
	case SiemFieldJSONOutput:
		app.SIEMExportPath = trimLastRune(app.SIEMExportPath)
	case SiemFieldDebugLog:
		app.SIEMDebugLogPath = trimLastRune(app.SIEMDebugLogPath)
	case SiemFieldRulesJSON:
		app.SIEMRulesJSONPath = trimLastRune(app.SIEMRulesJSONPath)
	}
}

func handleSIEMEnter(app *shared.AppState) {
	switch app.SIEMField {
	case SiemFieldSourceReport:
		RefreshSIEMSourceReports(app)
		if len(app.SIEMSourceReports) == 0 {
			setWorkflowStatus(app, &app.SIEMStatusText, &app.SIEMStatusError, &app.SIEMStatusUntil, "no calibration reports found; run Calibrate from this menu", true)
			return
		}
		openSIEMMenu(app, "source-report", "Select Source Report", app.SIEMSourceReports, findIndex(app.SIEMSourceReports, app.SIEMSourceReport))
	case SiemFieldProvider:
		opts := calibration.Providers()
		openSIEMMenu(app, "provider", "Select Provider", opts, findIndex(opts, calibration.ProviderLabel(app.SIEMProvider)))
	case SiemFieldModel:
		opts := calibration.ModelOptions(app.SIEMProvider)
		if len(opts) == 0 {
			return
		}
		openSIEMMenu(app, "model", "Select Model", opts, findIndex(opts, app.SIEMModel))
	case SiemFieldGenerate:
		RunSIEMGeneration(app)
	case SiemFieldSaveGeneration:
		ApplySIEMGenerationSettings(app, true)
	case SiemFieldCalibrate:
		KickoffCalibrationFromSIEM(app)
	case SiemFieldApply:
		ApplySIEMRuntimeExportSettings(app, false)
	case SiemFieldSave:
		ApplySIEMRuntimeExportSettings(app, true)
	case SiemFieldDisable:
		app.SIEMDebugLogPath = ""
		app.SIEMRulesJSONPath = ""
		ApplySIEMRuntimeExportSettings(app, false)
	default:
		if SiemFieldEditable(app.SIEMField) {
			app.SIEMEditing = !app.SIEMEditing
		}
	}
}

func handleSIEMRuneInput(app *shared.AppState, r rune) {
	if !app.SIEMEditing || r < 32 || r > 126 {
		return
	}
	switch app.SIEMField {
	case SiemFieldModel:
		app.SIEMModel += string(r)
	case SiemFieldReportOutput:
		app.SIEMReportPath += string(r)
	case SiemFieldJSONOutput:
		app.SIEMExportPath += string(r)
	case SiemFieldDebugLog:
		app.SIEMDebugLogPath += string(r)
	case SiemFieldRulesJSON:
		app.SIEMRulesJSONPath += string(r)
	}
}

func handleSIEMOverlayKey(app *shared.AppState, tev *tcell.EventKey) bool {
	return handleOverlayKey(app, tev, overlayState{
		showHelp: &app.SIEMShowHelp, showMenu: &app.SIEMShowMenu,
		helpIndex: &app.SIEMHelpIndex, menuIndex: &app.SIEMMenuIndex,
		menuOptions: &app.SIEMMenuOptions, menuKind: &app.SIEMMenuKind,
		menuTitle: &app.SIEMMenuTitle, helpOptions: siemMenuHelpOptions,
		applyMenu: func(a *shared.AppState) { applySIEMMenuSelection(a) },
	})
}

func siemMenuHelpOptions() []string {
	return []string{
		"[Navigation]",
		"UP/DOWN      Move field",
		"LEFT/RIGHT   Cycle workflows",
		"",
		"[Editing]",
		"ENTER        Edit / open / run",
		"BACKSPACE    Delete while editing",
		"",
		"[Report]",
		"PGUP/PGDN    Scroll report page",
		"[ / ]        Scroll report line",
		"",
		"?            Close this menu",
		"ESC          Back to dashboard",
		"q            Quit",
	}
}

func openSIEMMenu(app *shared.AppState, kind, title string, options []string, selected int) {
	openWorkflowMenu(kind, title, options, selected, &app.SIEMShowHelp, &app.SIEMShowMenu, &app.SIEMMenuKind, &app.SIEMMenuTitle, &app.SIEMMenuOptions, &app.SIEMMenuIndex)
}

func applySIEMMenuSelection(app *shared.AppState) {
	if len(app.SIEMMenuOptions) == 0 {
		return
	}
	choice := app.SIEMMenuOptions[clampChoice(app.SIEMMenuIndex, len(app.SIEMMenuOptions))]
	switch app.SIEMMenuKind {
	case "source-report":
		app.SIEMSourceReport = choice
		app.SIEMSourceIndex = findIndex(app.SIEMSourceReports, choice)
	case "provider":
		app.SIEMProvider = calibration.ProviderKey(choice)
		opts := calibration.ModelOptions(app.SIEMProvider)
		if !containsString(opts, app.SIEMModel) {
			app.SIEMModel = calibration.DefaultModel(app.SIEMProvider)
		}
	case "model":
		app.SIEMModel = choice
	}
}

func ApplySIEMRuntimeExportSettings(app *shared.AppState, save bool) {
	EnsureKeystoreValues(app)
	app.SIEMDebugLogPath = strings.TrimSpace(app.SIEMDebugLogPath)
	app.SIEMRulesJSONPath = strings.TrimSpace(app.SIEMRulesJSONPath)
	app.KeystoreValues["PROXYWATCH_DETECT_DEBUG_LOG"] = app.SIEMDebugLogPath
	app.KeystoreValues["PROXYWATCH_DETECT_RULES_JSON"] = app.SIEMRulesJSONPath
	keystore.ApplyToRuntime(app.KeystoreValues)
	if err := ApplyDetectionOutputRuntimeConfig(); err != nil {
		setWorkflowStatus(app, &app.SIEMStatusText, &app.SIEMStatusError, &app.SIEMStatusUntil, "apply failed: "+err.Error(), true)
		return
	}
	if save {
		if err := keystore.Save(app.KeystorePath, app.KeystoreValues); err != nil {
			setWorkflowStatus(app, &app.SIEMStatusText, &app.SIEMStatusError, &app.SIEMStatusUntil, "save failed: "+err.Error(), true)
			return
		}
		setWorkflowStatus(app, &app.SIEMStatusText, &app.SIEMStatusError, &app.SIEMStatusUntil, "SIEM paths saved to keystore and applied", false)
		return
	}
	setWorkflowStatus(app, &app.SIEMStatusText, &app.SIEMStatusError, &app.SIEMStatusUntil, "SIEM paths applied to runtime", false)
}

func ApplySIEMGenerationSettings(app *shared.AppState, save bool) {
	app.SIEMSourceReport = strings.TrimSpace(app.SIEMSourceReport)
	app.SIEMProvider = calibration.ProviderKey(app.SIEMProvider)
	if app.SIEMProvider == "" {
		app.SIEMProvider = calibration.ProviderKey("OpenAI")
	}
	app.SIEMModel = strings.TrimSpace(app.SIEMModel)
	if app.SIEMModel == "" {
		app.SIEMModel = calibration.DefaultModel(app.SIEMProvider)
	}
	app.SIEMReportPath = strings.TrimSpace(app.SIEMReportPath)
	app.SIEMExportPath = strings.TrimSpace(app.SIEMExportPath)

	keystore.RuntimeSetValue("PROXYWATCH_SIEM_SOURCE_REPORT", app.SIEMSourceReport)
	keystore.RuntimeSetValue("PROXYWATCH_SIEM_PROVIDER", app.SIEMProvider)
	keystore.RuntimeSetValue("PROXYWATCH_SIEM_MODEL", app.SIEMModel)
	keystore.RuntimeSetValue("PROXYWATCH_SIEM_REPORT_OUTPUT", app.SIEMReportPath)
	keystore.RuntimeSetValue("PROXYWATCH_SIEM_JSON_OUTPUT", app.SIEMExportPath)

	if save {
		if err := keystore.Save(app.KeystorePath, app.KeystoreValues); err != nil {
			setWorkflowStatus(app, &app.SIEMStatusText, &app.SIEMStatusError, &app.SIEMStatusUntil, "save failed: "+err.Error(), true)
			return
		}
		setWorkflowStatus(app, &app.SIEMStatusText, &app.SIEMStatusError, &app.SIEMStatusUntil, "SIEM generation settings saved to keystore", false)
		return
	}
	setWorkflowStatus(app, &app.SIEMStatusText, &app.SIEMStatusError, &app.SIEMStatusUntil, "SIEM generation settings applied to runtime", false)
}

func siemError(app *shared.AppState, msg string) {
	maxLen := app.ScreenWidth - 4
	if maxLen < 20 {
		maxLen = 76
	}
	full := "error: " + msg
	if len(full) > maxLen {
		full = full[:maxLen-3] + "..."
	}
	setWorkflowStatus(app, &app.SIEMStatusText, &app.SIEMStatusError, &app.SIEMStatusUntil, full, true)
}

func RunSIEMGeneration(app *shared.AppState) {
	if app.SIEMGenerating {
		app.SIEMGenerating = false
		app.SIEMProgressLines = nil
		setWorkflowStatus(app, &app.SIEMStatusText, &app.SIEMStatusError, &app.SIEMStatusUntil, "SIEM generation stopped", false)
		return
	}
	RefreshSIEMSourceReports(app)
	if strings.TrimSpace(app.SIEMSourceReport) == "" {
		siemError(app, "no calibration report — run Calibrate first")
		return
	}
	ApplySIEMGenerationSettings(app, false)

	access := calibration.DetectProviderAccess()
	if ready, reason := calibration.ProviderReady(app.SIEMProvider, access); !ready {
		if !app.SIEMDecryptAttempted && app.KeystoreActiveEntry != "" && app.KeystoreSecure {
			app.SIEMDecryptAttempted = true
			if TryDecryptAndRun(app, &app.SIEMStatusText, &app.SIEMStatusError, &app.SIEMStatusUntil, func() {
				RunSIEMGeneration(app)
			}) {
				return
			}
		}
		app.SIEMDecryptAttempted = false
		switch {
		case app.KeystoreActiveEntry == "":
			siemError(app, "no keystore active — press 'a' in Keystore")
		case strings.Contains(reason, "OPENAI"):
			siemError(app, "missing OpenAI API key in active keystore")
		case strings.Contains(reason, "ANTHROPIC"):
			siemError(app, "missing Anthropic API key in active keystore")
		case strings.Contains(reason, "LOCAL_LLM"):
			siemError(app, "missing Local LLM config in active keystore")
		default:
			siemError(app, reason)
		}
		return
	}
	app.SIEMDecryptAttempted = false

	app.SIEMGenerating = true
	app.SIEMStartedAt = time.Now()
	app.SIEMShowMenu = false
	app.SIEMEditing = false
	setWorkflowStatus(app, &app.SIEMStatusText, &app.SIEMStatusError, &app.SIEMStatusUntil, "SIEM generation started", false)
	if app.StartSIEMGeneration != nil {
		app.StartSIEMGeneration(app.SIEMSourceReport, app.SIEMProvider, app.SIEMModel, app.SIEMReportPath, app.SIEMExportPath)
		return
	}

	input := siem.SIEMRunInput{
		SourceReport: app.SIEMSourceReport,
		Provider:     app.SIEMProvider,
		Model:        app.SIEMModel,
		OutputReport: app.SIEMReportPath,
		OutputJSON:   app.SIEMExportPath,
		OnProgress: func(lines []string) {
			cp := make([]string, len(lines))
			copy(cp, lines)
			app.ProgressMu.Lock()
			app.SIEMProgressLines = cp
			app.ProgressMu.Unlock()
		},
	}
	result, err := siem.ExecuteSIEM(input)
	ApplySIEMExecResult(app, SiemExecResult{Result: result, Err: err})
}

func ApplySIEMExecResult(app *shared.AppState, res SiemExecResult) {
	app.SIEMGenerating = false
	app.SIEMStartedAt = time.Time{}
	app.SIEMProgressLines = nil
	if res.Err != nil {
		setWorkflowStatus(app, &app.SIEMStatusText, &app.SIEMStatusError, &app.SIEMStatusUntil, "siem generation failed: "+res.Err.Error(), true)
		return
	}
	result := res.Result
	app.SIEMSourceReport = result.SourceReport
	app.SIEMReportPath = result.ReportPath
	app.SIEMExportPath = result.JSONPath
	if len(result.ReportLines) > 0 {
		app.SIEMReportLines = append([]string(nil), result.ReportLines...)
		app.SIEMReportScroll = 0
		app.SIEMReportMaxScroll = 0
	} else {
		RefreshSIEMReportPreview(app)
	}
	setWorkflowStatus(app, &app.SIEMStatusText, &app.SIEMStatusError, &app.SIEMStatusUntil, fmt.Sprintf("SIEM %s output written: report=%s json=%s detections=%d", result.Mode, result.ReportPath, result.JSONPath, result.DetectionCount), false)
}

func RefreshSIEMSourceReports(app *shared.AppState) {
	if app == nil {
		return
	}
	reports, err := calibration.ListReports()
	if err != nil {
		setWorkflowStatus(app, &app.SIEMStatusText, &app.SIEMStatusError, &app.SIEMStatusUntil, "calibration report list failed: "+err.Error(), true)
		app.SIEMSourceReports = nil
		app.SIEMSourceIndex = -1
		return
	}
	app.SIEMSourceReports = reports
	if len(reports) == 0 {
		app.SIEMSourceReport = ""
		app.SIEMSourceIndex = -1
		return
	}

	current := strings.TrimSpace(app.SIEMSourceReport)
	if current == "" {
		current = strings.TrimSpace(app.CalibrateOutput)
	}
	idx := findIndex(reports, current)
	if idx < 0 {
		currentClean := filepath.Clean(current)
		for i, report := range reports {
			if filepath.Clean(report) == currentClean {
				idx = i
				break
			}
		}
	}
	if idx < 0 {
		idx = 0
	}
	app.SIEMSourceIndex = idx
	app.SIEMSourceReport = reports[idx]
}

func RefreshSIEMReportPreview(app *shared.AppState) {
	if app == nil {
		return
	}
	path := strings.TrimSpace(app.SIEMReportPath)
	if path == "" {
		app.SIEMReportLines = nil
		app.SIEMReportScroll = 0
		app.SIEMReportMaxScroll = 0
		return
	}
	raw, err := os.ReadFile(keystore.NormalizePath(path))
	if err != nil {
		app.SIEMReportLines = nil
		app.SIEMReportScroll = 0
		app.SIEMReportMaxScroll = 0
		return
	}
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	text = strings.TrimRight(text, "\n")
	if strings.TrimSpace(text) == "" {
		app.SIEMReportLines = nil
		app.SIEMReportScroll = 0
		app.SIEMReportMaxScroll = 0
		return
	}
	lines := strings.Split(text, "\n")
	const maxPreviewLines = 2000
	if len(lines) > maxPreviewLines {
		lines = append(lines[:maxPreviewLines], fmt.Sprintf("... truncated (%d total lines)", len(lines)))
	}
	app.SIEMReportLines = lines
	app.SIEMReportScroll = 0
	app.SIEMReportMaxScroll = 0
}

func KickoffCalibrationFromSIEM(app *shared.AppState) {
	EnterCalibrationMode(app)
	if app.CalibrateActive {
		setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil, "calibration already running", false)
		return
	}
	duration := strings.TrimSpace(app.CalibrateDuration)
	if duration == "" || !containsString(calibration.DurationOptions(), duration) {
		app.CalibrateDuration = "30s"
	}
	StartCalibration(app)
}
