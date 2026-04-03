package keys

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"proxywatch/internal/calibration"
	"proxywatch/internal/shared"

	"github.com/gdamore/tcell/v2"
)

func HandleCalibrationKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if app.ShowCalibrateHelp || app.ShowCalibrateMenu {
		return handleCalibrationOverlayKey(app, tev)
	}

	skipHost := strings.TrimSpace(app.LocalHost) != ""
	switch tev.Key() {
	case tcell.KeyUp:
		cycleField(&app.CalibrateField, CalibrateFieldProvider, CalibrateFieldMax, true)
		if skipHost && app.CalibrateField == CalibrateFieldHostScope {
			cycleField(&app.CalibrateField, CalibrateFieldProvider, CalibrateFieldMax, true)
		}
	case tcell.KeyDown:
		cycleField(&app.CalibrateField, CalibrateFieldProvider, CalibrateFieldMax, false)
		if skipHost && app.CalibrateField == CalibrateFieldHostScope {
			cycleField(&app.CalibrateField, CalibrateFieldProvider, CalibrateFieldMax, false)
		}
	case tcell.KeyTab:
		cycleField(&app.CalibrateField, CalibrateFieldProvider, CalibrateFieldMax, false)
		if skipHost && app.CalibrateField == CalibrateFieldHostScope {
			cycleField(&app.CalibrateField, CalibrateFieldProvider, CalibrateFieldMax, false)
		}
	case tcell.KeyBacktab:
		cycleField(&app.CalibrateField, CalibrateFieldProvider, CalibrateFieldMax, true)
		if skipHost && app.CalibrateField == CalibrateFieldHostScope {
			cycleField(&app.CalibrateField, CalibrateFieldProvider, CalibrateFieldMax, true)
		}
	case tcell.KeyBackspace, tcell.KeyBackspace2:
		handleCalibrationBackspace(app)
	case tcell.KeyEnter:
		handleCalibrationEnter(app)
	case tcell.KeyEscape:
		if app.CalibrateEditing {
			app.CalibrateEditing = false
		} else {
			app.Mode = shared.ModeDashboard
		}
	case tcell.KeyPgUp:
		scrollReport(&app.CalibrateReportScroll, app.CalibrateReportMaxScroll, -8)
	case tcell.KeyPgDn:
		scrollReport(&app.CalibrateReportScroll, app.CalibrateReportMaxScroll, 8)
	case tcell.KeyHome:
		app.CalibrateReportScroll = 0
	case tcell.KeyEnd:
		app.CalibrateReportScroll = app.CalibrateReportMaxScroll
	}

	switch tev.Rune() {
	case '[':
		scrollReport(&app.CalibrateReportScroll, app.CalibrateReportMaxScroll, 1)
		return false
	case ']':
		scrollReport(&app.CalibrateReportScroll, app.CalibrateReportMaxScroll, -1)
		return false
	case 'q':
		if app.CalibrateEditing {
			break
		}
		return requestQuit(app)
	case '?':
		app.ShowCalibrateHelp = true
		app.CalibrateHelpIndex = 0
		return false
	}

	if tev.Key() == tcell.KeyRune && tev.Rune() != 0 {
		handleCalibrationRuneInput(app, tev.Rune())
	}
	return false
}

func handleCalibrationOverlayKey(app *shared.AppState, tev *tcell.EventKey) bool {
	return handleOverlayKey(app, tev, overlayState{
		showHelp: &app.ShowCalibrateHelp, showMenu: &app.ShowCalibrateMenu,
		helpIndex: &app.CalibrateHelpIndex, menuIndex: &app.CalibrateMenuIndex,
		menuOptions: &app.CalibrateMenuOptions, menuKind: &app.CalibrateMenuKind,
		menuTitle: &app.CalibrateMenuTitle, helpOptions: calibrationMenuHelpOptions,
		applyMenu: func(a *shared.AppState) { applyCalibrationMenuSelection(a) },
	})
}

func calibrationMenuHelpOptions() []string {
	return []string{
		"[Navigation]",
		"UP/DOWN      Move field",
		"TAB/BTAB     Next / prev field",
		"LEFT/RIGHT   Cycle workflows",
		"",
		"[Editing]",
		"ENTER        Edit / open / apply",
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

func openCalibrationMenu(app *shared.AppState, kind, title string, options []string, selected int) {
	openWorkflowMenu(kind, title, options, selected, &app.ShowCalibrateHelp, &app.ShowCalibrateMenu, &app.CalibrateMenuKind, &app.CalibrateMenuTitle, &app.CalibrateMenuOptions, &app.CalibrateMenuIndex)
}

func applyCalibrationMenuSelection(app *shared.AppState) {
	if len(app.CalibrateMenuOptions) == 0 {
		return
	}
	choice := app.CalibrateMenuOptions[clampChoice(app.CalibrateMenuIndex, len(app.CalibrateMenuOptions))]
	switch app.CalibrateMenuKind {
	case "provider":
		app.CalibrateProvider = calibration.ProviderKey(choice)
		modelOpts := calibration.ModelOptions(app.CalibrateProvider)
		if !containsString(modelOpts, app.CalibrateModel) {
			app.CalibrateModel = calibration.DefaultModel(app.CalibrateProvider)
		}
	case "duration":
		app.CalibrateDuration = choice
	case "model":
		app.CalibrateModel = choice
	case "profile":
		app.CalibrateProfile = choice
		app.CalibrateProfileIndex = findIndex(app.CalibrateProfiles, choice)
		// Load the profile preview (shown in display when no active report).
		if profile, err := calibration.LoadProfile(choice); err == nil {
			var lines []string
			lines = append(lines, "Profile: "+profile.Name)
			lines = append(lines, fmt.Sprintf("Created: %s  |  Provider: %s / %s",
				profile.CreatedAt.UTC().Format("2006-01-02 15:04"), profile.Provider, profile.Model))
			lines = append(lines, fmt.Sprintf("Scope: %s  |  Candidates: %d",
				profile.Scope, profile.CandidateCount))
			if len(profile.Recommendations) > 0 {
				lines = append(lines, "")
				lines = append(lines, "Recommendations")
				for _, rec := range profile.Recommendations {
					lines = append(lines, "  - "+rec)
				}
			}
			if len(profile.RoleCounts) > 0 {
				lines = append(lines, "")
				parts := make([]string, 0, len(profile.RoleCounts))
				for role, count := range profile.RoleCounts {
					parts = append(parts, fmt.Sprintf("%s=%d", role, count))
				}
				lines = append(lines, "Roles: "+strings.Join(parts, "  "))
			}
			app.CalibrateProfilePreview = lines
		}
	case "hostscope":
		app.CalibrateHostScope = choice
		app.CalibrateHostScopeIndex = findIndex(app.CalibrateHostScopeOpts, choice)
	}
}

func CalibrateEditValue(app *shared.AppState) string {
	switch app.CalibrateField {
	case CalibrateFieldOutput:
		return app.CalibrateOutput
	}
	return ""
}

func handleCalibrationBackspace(app *shared.AppState) {
	if !app.CalibrateEditing {
		return
	}
	switch app.CalibrateField {
	case CalibrateFieldOutput:
		if app.CalibrateEditCursor > 0 && len(app.CalibrateOutput) > 0 {
			pos := app.CalibrateEditCursor
			if pos > len(app.CalibrateOutput) {
				pos = len(app.CalibrateOutput)
			}
			app.CalibrateOutput = app.CalibrateOutput[:pos-1] + app.CalibrateOutput[pos:]
			app.CalibrateEditCursor--
		}
	}
}

func handleCalibrationEnter(app *shared.AppState) {
	switch app.CalibrateField {
	case CalibrateFieldProvider:
		opts := calibration.Providers()
		openCalibrationMenu(app, "provider", "Select Provider", opts, findIndex(opts, calibration.ProviderLabel(app.CalibrateProvider)))
	case CalibrateFieldHostScope:
		if app.CalibrateActive {
			return
		}
		RefreshCalibrateHostScopes(app)
		openCalibrationMenu(app, "hostscope", "Select Host Scope", app.CalibrateHostScopeOpts, app.CalibrateHostScopeIndex)
	case CalibrateFieldOutput:
		if app.CalibrateActive {
			return
		}
		app.CalibrateEditing = !app.CalibrateEditing
		if app.CalibrateEditing {
			app.CalibrateEditCursor = len(app.CalibrateOutput)
		}
	case CalibrateFieldDuration:
		opts := calibration.DurationOptions()
		openCalibrationMenu(app, "duration", "Select Duration", opts, findIndex(opts, app.CalibrateDuration))
	case CalibrateFieldModel:
		opts := calibration.ModelOptions(app.CalibrateProvider)
		openCalibrationMenu(app, "model", "Select Model", opts, findIndex(opts, app.CalibrateModel))
	case CalibrateFieldProfile:
		if len(app.CalibrateProfiles) == 0 {
			RefreshCalibrationState(app)
		}
		if len(app.CalibrateProfiles) == 0 {
			setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil, "no saved calibration profiles yet", true)
			return
		}
		openCalibrationMenu(app, "profile", "Select Profile", app.CalibrateProfiles, findIndex(app.CalibrateProfiles, app.CalibrateProfile))
	case CalibrateFieldAction:
		if app.CalibrateActive {
			if app.CalibrateAnalyzing {
				if app.CalibrateCancel != nil {
					app.CalibrateCancel()
					setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil, "canceling calibration analysis...", false)
				}
			} else {
				app.CalibrateUntil = time.Now().Add(-time.Second)
			}
		} else {
			StartCalibration(app)
		}
	case CalibrateFieldApply:
		ApplySelectedCalibrationProfile(app)
	case CalibrateFieldReset:
		if app.CalibrateActive {
			setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil, "cannot reset while calibration is running", true)
			return
		}
		if app.CalibrateResetConfirm && time.Now().Before(app.CalibrateResetDeadline) {
			scope := ResolveCalibrateModelScope(app)
			modelPath := calibration.ResolveLearningModelPath(scope)
			if err := os.Remove(modelPath); err != nil && !os.IsNotExist(err) {
				setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil, "reset failed: "+err.Error(), true)
			} else {
				setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil, "baseline reset for "+scope.Label, false)
			}
			app.CalibrateResetConfirm = false
		} else {
			app.CalibrateResetConfirm = true
			app.CalibrateResetDeadline = time.Now().Add(5 * time.Second)
			setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil, "press ENTER again within 5s to confirm baseline reset", false)
		}
	}
}

func handleCalibrationRuneInput(app *shared.AppState, r rune) {
	if !app.CalibrateEditing || r < 32 || r > 126 {
		return
	}
	switch app.CalibrateField {
	case CalibrateFieldOutput:
		pos := app.CalibrateEditCursor
		if pos > len(app.CalibrateOutput) {
			pos = len(app.CalibrateOutput)
		}
		app.CalibrateOutput = app.CalibrateOutput[:pos] + string(r) + app.CalibrateOutput[pos:]
		app.CalibrateEditCursor++
	}
}

// --- workflow runtime ---

func RefreshCalibrationState(app *shared.AppState) {
	app.CalibrateProvider = calibration.ProviderKey(app.CalibrateProvider)
	if app.CalibrateProvider == "" {
		app.CalibrateProvider = calibration.ProviderKey("OpenAI")
	}
	if app.CalibrateModel == "" || !containsString(calibration.ModelOptions(app.CalibrateProvider), app.CalibrateModel) {
		app.CalibrateModel = calibration.DefaultModel(app.CalibrateProvider)
	}
	if app.CalibrateDuration == "" {
		app.CalibrateDuration = "5m"
	}
	opts := calibration.DurationOptions()
	if findIndex(opts, app.CalibrateDuration) < 0 {
		app.CalibrateDuration = "5m"
	}
	if app.CalibrateOutput == "" {
		app.CalibrateOutput = calibration.DefaultOutputPath()
	}
	if app.CalibrateHostScope == "" {
		app.CalibrateHostScope = "(this host)"
	}
	RefreshCalibrateHostScopes(app)

	profiles, err := calibration.ListProfiles()
	if err != nil {
		setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil, "profile load failed: "+err.Error(), true)
		return
	}
	app.CalibrateProfiles = profiles

	if cfg, err := calibration.LoadActiveConfig(); err == nil {
		if strings.TrimSpace(cfg.Profile) != "" {
			app.CalibrateAppliedProfile = cfg.Profile
		}
	} else {
		setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil, "active profile load failed: "+err.Error(), true)
	}
	if strings.TrimSpace(app.CalibrateAppliedProfile) == "" {
		app.CalibrateAppliedProfile = "tuning.json"
	}

	if len(app.CalibrateProfiles) > 0 {
		idx := findIndex(app.CalibrateProfiles, app.CalibrateProfile)
		if idx < 0 {
			idx = 0
		}
		app.CalibrateProfileIndex = idx
		app.CalibrateProfile = app.CalibrateProfiles[idx]
	} else {
		app.CalibrateProfileIndex = -1
		if strings.TrimSpace(app.CalibrateProfile) == "" {
			app.CalibrateProfile = app.CalibrateAppliedProfile
		}
	}

	if len(app.CalibrateReportLines) == 0 {
		report, err := calibration.LoadReport(app.CalibrateOutput)
		switch {
		case err == nil:
			app.CalibrateReportSummary = report.Summary
			app.CalibrateReportPath = report.OutputPath
			app.CalibrateReportTime = report.GeneratedAt
			app.CalibrateRecommendations = report.Recommendations
			app.CalibrateReportLines = append([]string(nil), report.ReportLines...)
			app.CalibrateReportScroll = 0
		case errors.Is(err, os.ErrNotExist):
			// No report file — keep current state.
		case err != nil:
			setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil, "report load failed: "+err.Error(), true)
		}
	}
}

func calibrationError(app *shared.AppState, msg string) {
	maxLen := app.ScreenWidth - 4
	if maxLen < 20 {
		maxLen = 76
	}
	full := "error: " + msg
	if len(full) > maxLen {
		full = full[:maxLen-3] + "..."
	}
	setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil, full, true)
}

func StartCalibration(app *shared.AppState) {
	if app.CalibrateActive {
		setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil,
			"calibration is already running", false)
		return
	}
	if strings.TrimSpace(app.CalibrateModel) == "" {
		app.CalibrateModel = calibration.DefaultModel(app.CalibrateProvider)
	}
	output := strings.TrimSpace(app.CalibrateOutput)
	if output == "" || strings.EqualFold(output, calibration.DefaultOutputPath()) || strings.EqualFold(filepath.Base(output), "latest.json") {
		app.CalibrateOutput = calibration.NewRunOutputPath()
	}
	dur, err := time.ParseDuration(strings.TrimSpace(app.CalibrateDuration))
	if err != nil || dur <= 0 {
		calibrationError(app, "invalid duration")
		return
	}

	access := calibration.DetectProviderAccess()
	if ready, reason := calibration.ProviderReady(app.CalibrateProvider, access); !ready {
		if !app.CalibrateDecryptAttempted && app.KeystoreActiveEntry != "" && app.KeystoreSecure {
			app.CalibrateDecryptAttempted = true
			if TryDecryptAndRun(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil, func() {
				StartCalibration(app)
			}) {
				return
			}
		}
		app.CalibrateDecryptAttempted = false
		switch {
		case app.KeystoreActiveEntry == "":
			calibrationError(app, "no keystore active — press 'a' in Keystore")
		case strings.Contains(reason, "OPENAI"):
			calibrationError(app, "missing OpenAI API key in active keystore")
		case strings.Contains(reason, "ANTHROPIC"):
			calibrationError(app, "missing Anthropic API key in active keystore")
		case strings.Contains(reason, "LOCAL_LLM"):
			calibrationError(app, "missing Local LLM config in active keystore")
		default:
			calibrationError(app, reason)
		}
		return
	}
	app.CalibrateDecryptAttempted = false

	app.CalibrateActive = true
	app.CalibrateAnalyzing = false
	app.CalibrateCancel = nil
	app.CalibrateStartedAt = time.Now()
	app.CalibrateUntil = app.CalibrateStartedAt.Add(dur)
	app.CalibrateSampleEvery = calibration.SuggestedSampleEvery(dur)
	app.CalibrateLastSample = time.Time{}
	app.CalibrateReportScroll = 0
	app.CalibrateSamples = nil
	app.CalibrateEditing = false
	setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil, "calibration collection started ("+dur.String()+", sample every "+app.CalibrateSampleEvery.String()+")", false)
}

func UpdateCalibrationState(app *shared.AppState, calibrateCh chan<- CalibrationExecResult, inFlight *bool) {
	if !app.CalibrateActive || app.CalibrateAnalyzing {
		return
	}
	if app.CalibrateSampleEvery <= 0 {
		if parsed, err := time.ParseDuration(strings.TrimSpace(app.CalibrateDuration)); err == nil && parsed > 0 {
			app.CalibrateSampleEvery = calibration.SuggestedSampleEvery(parsed)
		} else {
			app.CalibrateSampleEvery = calibration.DefaultSampleEvery()
		}
	}
	now := time.Now()
	if app.CalibrateLastSample.IsZero() || now.Sub(app.CalibrateLastSample) >= app.CalibrateSampleEvery {
		scope := safeRolePreset(app)
		filter := shared.ParseRoleFilter(scope)
		if strings.EqualFold(strings.TrimSpace(scope), "recommended") {
			filter = shared.ParseRoleFilter("all")
		}

		liveCandidates := app.SnapshotCandidates
		if len(liveCandidates) == 0 {
			liveCandidates = app.Candidates
		}

		if len(liveCandidates) > 0 {
			for _, c := range liveCandidates {
				if len(filter) > 0 && !shared.RoleMatchesFilter(c.Role, filter) {
					continue
				}
				app.CalibrateSamples = append(app.CalibrateSamples, CloneCandidate(c))
			}
		} else if app.CalibrationCollect != nil {
			snap, err := app.CalibrationCollect()
			if err != nil {
				setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil, "calibration sample collection warning: "+err.Error(), true)
			} else {
				collected := calibration.SamplesFromSnapshot(snap, app.LocalHost, scope)
				for _, c := range collected {
					app.CalibrateSamples = append(app.CalibrateSamples, CloneCandidate(c))
				}
			}
		}
		app.CalibrateLastSample = now
	}
	if now.After(app.CalibrateUntil) {
		BeginCalibrationAnalysis(app, calibrateCh, inFlight)
	}
}

func BeginCalibrationAnalysis(app *shared.AppState, calibrateCh chan<- CalibrationExecResult, inFlight *bool) {
	if !app.CalibrateActive || app.CalibrateAnalyzing || *inFlight {
		return
	}
	duration := time.Since(app.CalibrateStartedAt)
	if duration <= 0 {
		if parsed, err := time.ParseDuration(strings.TrimSpace(app.CalibrateDuration)); err == nil && parsed > 0 {
			duration = parsed
		} else {
			duration = time.Second
		}
	}
	app.CalibrateAnalyzing = true
	setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil, "gpt analyzing...", false)
	app.CalibrateEditing = false
	ctx, cancel := context.WithCancel(context.Background())
	app.CalibrateCancel = cancel
	input := calibration.RunInput{
		Provider:     app.CalibrateProvider,
		Model:        app.CalibrateModel,
		Scope:        safeRolePreset(app),
		Duration:     duration.Round(time.Second),
		Output:       app.CalibrateOutput,
		SampleEvery:  app.CalibrateSampleEvery,
		Samples:      CloneCalibrationSamples(app.CalibrateSamples),
		ContourHints: CloneContourHints(app.ContourHints),
		HostScope:    ResolveCalibrateModelScope(app),
		OnProgress: func(lines []string) {
			cp := make([]string, len(lines))
			copy(cp, lines)
			app.ProgressMu.Lock()
			app.CalibrateProgressLines = cp
			app.ProgressMu.Unlock()
		},
	}
	*inFlight = true
	go func() {
		result, err := calibration.ExecuteContext(ctx, input)
		calibrateCh <- CalibrationExecResult{
			Result: result,
			Err:    err,
		}
	}()
}

func ApplyCalibrationExecResult(app *shared.AppState, res CalibrationExecResult) {
	app.CalibrateCancel = nil
	app.CalibrateProgressLines = nil
	if res.Err != nil {
		if errors.Is(res.Err, context.Canceled) {
			setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil, "calibration canceled", false)
		} else {
			setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil, "calibration failed: "+res.Err.Error(), true)
		}
	} else {
		result := res.Result
		app.CalibrateProfile = result.Profile.Name
		app.CalibrateOutput = result.ReportPath
		app.CalibrateReportSummary = result.Report.Summary
		app.CalibrateReportPath = result.ReportPath
		app.CalibrateReportTime = result.Report.GeneratedAt
		app.CalibrateRecommendations = result.Report.Recommendations
		app.CalibrateReportLines = append([]string(nil), result.Report.ReportLines...)
		app.CalibrateReportScroll = 0
		setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil, "calibration report written: "+result.ReportPath, false)
	}
	app.CalibrateActive = false
	app.CalibrateAnalyzing = false
	app.CalibrateStartedAt = time.Time{}
	app.CalibrateLastSample = time.Time{}
	app.CalibrateSamples = nil
	app.CalibrateEditing = false
	RefreshCalibrationState(app)
}

func ApplySelectedCalibrationProfile(app *shared.AppState) {
	profileName := strings.TrimSpace(app.CalibrateProfile)
	if profileName == "" {
		setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil, "apply failed: no profile selected", true)
		return
	}
	profile, err := calibration.ApplyProfile(profileName)
	if err != nil {
		setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil, "apply failed: "+err.Error(), true)
		return
	}
	app.CalibrateAppliedProfile = profile.Name
	app.CalibrateProfile = profile.Name
	setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil, "applied profile: "+profile.Name, false)
	RefreshCalibrationState(app)
}
