package ui

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"proxywatch/internal/calibration"
	"proxywatch/internal/contour"
	"proxywatch/internal/shared"
	"strconv"
	"strings"
	"time"
)

func refreshCalibrationState(app *shared.AppState) {
	app.CalibrateProvider = calibration.ProviderKey(app.CalibrateProvider)
	if app.CalibrateProvider == "" {
		app.CalibrateProvider = calibration.ProviderKey("OpenAI")
	}
	if app.CalibrateModel == "" || !containsString(calibration.ModelOptions(app.CalibrateProvider), app.CalibrateModel) {
		app.CalibrateModel = calibration.DefaultModel(app.CalibrateProvider)
	}
	if app.CalibrateDuration == "" {
		app.CalibrateDuration = "1h"
	}
	if app.CalibrateOutput == "" {
		app.CalibrateOutput = calibration.DefaultOutputPath()
	}

	profiles, err := calibration.ListProfiles()
	if err != nil {
		setCalibrationStatus(app, "profile load failed: "+err.Error(), true)
		return
	}
	app.CalibrateProfiles = profiles

	if cfg, err := calibration.LoadActiveConfig(); err == nil {
		if strings.TrimSpace(cfg.Profile) != "" {
			app.CalibrateAppliedProfile = cfg.Profile
		}
	} else {
		setCalibrationStatus(app, "active profile load failed: "+err.Error(), true)
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
		app.CalibrateReportSummary = ""
		app.CalibrateReportPath = ""
		app.CalibrateReportTime = time.Time{}
		app.CalibrateRecommendations = nil
		app.CalibrateReportLines = nil
		app.CalibrateReportScroll = 0
	case err != nil:
		setCalibrationStatus(app, "report load failed: "+err.Error(), true)
	}
}

func startCalibration(app *shared.AppState) {
	if app.CalibrateActive {
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
		setCalibrationStatus(app, "calibration failed: invalid duration", true)
		return
	}

	access := calibration.DetectProviderAccess()
	if ready, reason := calibration.ProviderReady(app.CalibrateProvider, access); !ready {
		setCalibrationStatus(app, "calibration failed: "+reason, true)
		return
	}

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
	setCalibrationStatus(app, "calibration collection started ("+dur.String()+", sample every "+app.CalibrateSampleEvery.String()+")", false)
}

func updateCalibrationState(app *shared.AppState, calibrateCh chan<- calibrationExecResult, inFlight *bool) {
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
		if app.CalibrationCollect != nil {
			snap, err := app.CalibrationCollect()
			if err != nil {
				setCalibrationStatus(app, "calibration sample collection warning: "+err.Error(), true)
			} else {
				collected := calibration.SamplesFromSnapshot(snap, app.LocalHost, scope)
				for _, c := range collected {
					app.CalibrateSamples = append(app.CalibrateSamples, cloneCandidate(c))
				}
			}
		} else {
			filter := shared.ParseRoleFilter(scope)
			if strings.EqualFold(strings.TrimSpace(scope), "recommended") {
				filter = shared.ParseRoleFilter("all")
			}
			for _, c := range app.Candidates {
				if len(filter) > 0 && !shared.RoleMatchesFilter(c.Role, filter) {
					continue
				}
				app.CalibrateSamples = append(app.CalibrateSamples, cloneCandidate(c))
			}
		}
		app.CalibrateLastSample = now
	}
	if now.After(app.CalibrateUntil) {
		beginCalibrationAnalysis(app, calibrateCh, inFlight)
	}
}

func beginCalibrationAnalysis(app *shared.AppState, calibrateCh chan<- calibrationExecResult, inFlight *bool) {
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
	setCalibrationStatus(app, "gpt analyzing...", false)
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
		Samples:      cloneCalibrationSamples(app.CalibrateSamples),
		ContourHints: cloneContourHints(app.ContourHints),
	}
	*inFlight = true
	go func() {
		result, err := calibration.ExecuteContext(ctx, input)
		calibrateCh <- calibrationExecResult{
			result: result,
			err:    err,
		}
	}()
}

func applyCalibrationExecResult(app *shared.AppState, res calibrationExecResult) {
	app.CalibrateCancel = nil
	if res.err != nil {
		if errors.Is(res.err, context.Canceled) {
			setCalibrationStatus(app, "calibration canceled", false)
		} else {
			setCalibrationStatus(app, "calibration failed: "+res.err.Error(), true)
		}
	} else {
		result := res.result
		app.CalibrateProfile = result.Profile.Name
		app.CalibrateOutput = result.ReportPath
		app.CalibrateReportSummary = result.Report.Summary
		app.CalibrateReportPath = result.ReportPath
		app.CalibrateReportTime = result.Report.GeneratedAt
		app.CalibrateRecommendations = result.Report.Recommendations
		app.CalibrateReportLines = append([]string(nil), result.Report.ReportLines...)
		app.CalibrateReportScroll = 0
		setCalibrationStatus(app, "calibration report written: "+result.ReportPath, false)
	}
	app.CalibrateActive = false
	app.CalibrateAnalyzing = false
	app.CalibrateStartedAt = time.Time{}
	app.CalibrateLastSample = time.Time{}
	app.CalibrateSamples = nil
	app.CalibrateEditing = false
	refreshCalibrationState(app)
}

func cloneCalibrationSamples(samples []shared.Candidate) []shared.Candidate {
	if len(samples) == 0 {
		return nil
	}
	out := make([]shared.Candidate, 0, len(samples))
	for _, sample := range samples {
		out = append(out, cloneCandidate(sample))
	}
	return out
}

func applySelectedCalibrationProfile(app *shared.AppState) {
	profileName := strings.TrimSpace(app.CalibrateProfile)
	if profileName == "" {
		setCalibrationStatus(app, "apply failed: no profile selected", true)
		return
	}
	profile, err := calibration.ApplyProfile(profileName)
	if err != nil {
		setCalibrationStatus(app, "apply failed: "+err.Error(), true)
		return
	}
	app.CalibrateAppliedProfile = profile.Name
	app.CalibrateProfile = profile.Name
	setCalibrationStatus(app, "applied profile: "+profile.Name, false)
	refreshCalibrationState(app)
}

func cloneCandidate(c shared.Candidate) shared.Candidate {
	cloned := c
	if c.Proc != nil {
		proc := *c.Proc
		cloned.Proc = &proc
	}
	if len(c.Listeners) > 0 {
		cloned.Listeners = append([]shared.ListenerInfo(nil), c.Listeners...)
	}
	if len(c.Conns) > 0 {
		cloned.Conns = append([]shared.ConnectionInfo(nil), c.Conns...)
	}
	if len(c.UDPListeners) > 0 {
		cloned.UDPListeners = append([]shared.UDPListenerInfo(nil), c.UDPListeners...)
	}
	if len(c.Reasons) > 0 {
		cloned.Reasons = append([]string(nil), c.Reasons...)
	}
	if len(c.Signals) > 0 {
		cloned.Signals = append([]string(nil), c.Signals...)
	}
	return cloned
}

const contourListenRunDuration = 24 * time.Hour

func refreshContourState(app *shared.AppState) {
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
	app.ContourProbeMode = contourNormalizeProbeModeForRole(app.ContourProbeMode, app.ContourProbeRole)
	refreshContourSources(app)
	if strings.TrimSpace(app.ContourSource) == "" {
		app.ContourSource = "all"
	}

	report, err := contour.LoadReport(app.ContourOutput)
	switch {
	case err == nil:
		app.ContourReportLines = append([]string(nil), report.ReportLines...)
		app.ContourReportPath = report.OutputPath
		app.ContourReportTime = report.GeneratedAt
		app.ContourHints = cloneContourHints(report.Hints)
		app.ContourReportScroll = 0
	case errors.Is(err, os.ErrNotExist):
		app.ContourReportLines = nil
		app.ContourReportPath = ""
		app.ContourReportTime = time.Time{}
		app.ContourHints = nil
		app.ContourReportScroll = 0
	case err != nil:
		setContourStatus(app, "contour report load failed: "+err.Error(), true)
	}
}

func startContour(app *shared.AppState) {
	if app == nil || app.ContourActive || app.ContourAnalyzing {
		return
	}
	output := strings.TrimSpace(app.ContourOutput)
	base := strings.ToLower(strings.TrimSpace(filepath.Base(output)))
	if output == "" || strings.EqualFold(output, contour.DefaultOutputPath()) || strings.EqualFold(base, "latest.json") || strings.HasPrefix(base, "proxywatch-contour-") {
		app.ContourOutput = contour.NewRunOutputPath()
	}
	role := contour.NormalizeProbeRole(app.ContourProbeRole)
	mode := contour.NormalizeProbeMode(app.ContourProbeMode)
	app.ContourProbeRole = role
	mode = contourNormalizeProbeModeForRole(mode, role)
	app.ContourProbeMode = mode
	if mode != contour.ProbeModeOff && role != contour.ProbeRoleListen {
		if strings.TrimSpace(app.ContourProbeEndpoint) == "" {
			setContourStatus(app, "contour failed: endpoint is required for client/scan roles", true)
			return
		}
	}

	app.ContourActive = true
	app.ContourAnalyzing = false
	app.ContourCancel = nil
	app.ContourStartedAt = time.Now()
	app.ContourUntil = time.Time{}
	if role == contour.ProbeRoleListen || mode != contour.ProbeModeOff {
		// Listener and sweep roles start immediately in the analysis worker.
		app.ContourUntil = app.ContourStartedAt
	}
	app.ContourSampleEvery = 5 * time.Second
	app.ContourLastSample = time.Time{}
	app.ContourSamples = nil
	app.ContourEditing = false
	app.ContourShowMenu = false
	app.ContourReportScroll = 0
	app.ContourReportLines = nil
	endpoint := strings.TrimSpace(app.ContourProbeEndpoint)
	if endpoint == "" {
		endpoint = "-"
	}
	startMsg := "contour started (role " + contour.ProbeRoleLabel(app.ContourProbeRole) + ", endpoint " + endpoint
	if role != contour.ProbeRoleListen {
		startMsg += ", probe " + contour.ProbeModeLabel(mode)
	}
	startMsg += ")"
	setContourStatus(app, startMsg, false)
}

func stopContour(app *shared.AppState) {
	if app == nil || !app.ContourActive {
		return
	}
	if app.ContourAnalyzing {
		if app.ContourCancel != nil {
			app.ContourCancel()
		}
		setContourStatus(app, "stopping contour run...", false)
		return
	}
	app.ContourUntil = time.Now().Add(-time.Second)
	setContourStatus(app, "stopping collection, analyzing now...", false)
}

func updateContourState(app *shared.AppState, contourCh chan<- contourExecResult, inFlight *bool) {
	if app == nil || !app.ContourActive || app.ContourAnalyzing {
		return
	}
	if app.ContourSampleEvery <= 0 {
		app.ContourSampleEvery = 5 * time.Second
	}
	now := time.Now()
	if contour.NormalizeProbeRole(app.ContourProbeRole) != contour.ProbeRoleListen {
		if app.ContourLastSample.IsZero() || now.Sub(app.ContourLastSample) >= app.ContourSampleEvery {
			collected := contourCandidatesForSource(app)
			for _, c := range collected {
				app.ContourSamples = append(app.ContourSamples, cloneCandidate(c))
			}
			app.ContourLastSample = now
		}
	}
	if !app.ContourUntil.IsZero() && now.After(app.ContourUntil) {
		beginContourAnalysis(app, contourCh, inFlight)
	}
}

func beginContourAnalysis(app *shared.AppState, contourCh chan<- contourExecResult, inFlight *bool) {
	if app == nil || !app.ContourActive || app.ContourAnalyzing || *inFlight {
		return
	}
	duration := time.Since(app.ContourStartedAt)
	role := contour.NormalizeProbeRole(app.ContourProbeRole)
	mode := contour.NormalizeProbeMode(app.ContourProbeMode)
	if role == contour.ProbeRoleListen {
		duration = contourListenRunDuration
	} else if mode != contour.ProbeModeOff {
		// Sweep role runs immediately; keep a small positive duration for report metadata.
		if duration < time.Second {
			duration = time.Second
		}
	}
	if duration <= 0 {
		duration = time.Second
	}
	if role == contour.ProbeRoleListen {
		// Listener runs until operator stop/cancel.
		app.ContourUntil = time.Time{}
	}
	app.ContourAnalyzing = true
	app.ContourEditing = false
	if role == contour.ProbeRoleListen {
		setContourStatus(app, "listener active; waiting for contour checks...", false)
	} else {
		setContourStatus(app, "analyzing contour findings...", false)
	}
	input := contour.RunInput{
		Source:      app.ContourSource,
		Duration:    duration.Round(time.Second),
		SampleEvery: app.ContourSampleEvery,
		Output:      app.ContourOutput,
		ProbeRole:   app.ContourProbeRole,
		ProbeTarget: app.ContourProbeEndpoint,
		ProbeMode:   app.ContourProbeMode,
		Samples:     cloneCalibrationSamples(app.ContourSamples),
	}
	ctx, cancel := context.WithCancel(context.Background())
	app.ContourCancel = cancel
	*inFlight = true
	go func() {
		result, err := contour.ExecuteContext(ctx, input)
		contourCh <- contourExecResult{
			result: result,
			err:    err,
		}
	}()
}

func applyContourExecResult(app *shared.AppState, res contourExecResult) {
	if app == nil {
		return
	}
	app.ContourCancel = nil
	if res.err != nil {
		if errors.Is(res.err, context.Canceled) {
			setContourStatus(app, "contour stopped.", false)
		} else {
			setContourStatus(app, "contour failed: "+res.err.Error(), true)
		}
	} else {
		result := res.result
		app.ContourOutput = result.ReportPath
		app.ContourReportPath = result.ReportPath
		app.ContourReportTime = result.Report.GeneratedAt
		app.ContourReportLines = append([]string(nil), result.Report.ReportLines...)
		app.ContourHints = cloneContourHints(result.Hints)
		app.ContourReportScroll = 0
		setContourStatus(app, "contour report written: "+result.ReportPath+" (hints exported "+strconv.Itoa(len(result.Hints))+")", false)
	}
	app.ContourActive = false
	app.ContourAnalyzing = false
	app.ContourStartedAt = time.Time{}
	app.ContourLastSample = time.Time{}
	app.ContourSamples = nil
	app.ContourEditing = false
	refreshContourState(app)
}

func refreshContourSources(app *shared.AppState) {
	if app == nil {
		return
	}
	opts := collectSourceOptions(app)
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

func contourCandidatesForSource(app *shared.AppState) []shared.Candidate {
	if app == nil {
		return nil
	}
	source := strings.TrimSpace(app.ContourSource)

	if app.CalibrationCollect != nil {
		if snap, err := app.CalibrationCollect(); err == nil && snap != nil {
			collected := calibration.SamplesFromSnapshot(snap, app.LocalHost, "all")
			if source == "" || strings.EqualFold(source, "all") {
				return collected
			}
			out := make([]shared.Candidate, 0, len(collected))
			for _, c := range collected {
				if strings.EqualFold(shared.DisplayHost(c.Host), source) {
					out = append(out, c)
				}
			}
			return out
		}
	}

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

func setContourStatus(app *shared.AppState, msg string, isError bool) {
	app.LastError = msg
	app.ContourStatusText = msg
	app.ContourStatusError = isError
	now := time.Now()
	if isError {
		app.ContourStatusUntil = now.Add(10 * time.Second)
		return
	}
	app.ContourStatusUntil = now.Add(5 * time.Second)
}

func cloneContourHints(hints []shared.ContourHint) []shared.ContourHint {
	if len(hints) == 0 {
		return nil
	}
	out := make([]shared.ContourHint, len(hints))
	copy(out, hints)
	return out
}
