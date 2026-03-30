package ui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"proxywatch/internal/calibration"
	"proxywatch/internal/contour"
	classifier "proxywatch/internal/detection"
	"proxywatch/internal/keystore"
	"proxywatch/internal/shared"
	"proxywatch/internal/siem"
	"proxywatch/internal/telemetry"

	"github.com/gdamore/tcell/v2"
)

func cycleInspectProcess(app *shared.AppState, dir int) {
	if len(app.Candidates) == 0 {
		return
	}
	currentIdx := -1
	for i := range app.Candidates {
		if shared.CandidateKey(app.Candidates[i]) == app.InspectKey {
			currentIdx = i
			break
		}
	}
	next := currentIdx + dir
	if next < 0 {
		next = len(app.Candidates) - 1
	}
	if next >= len(app.Candidates) {
		next = 0
	}
	app.InspectKey = shared.CandidateKey(app.Candidates[next])
	app.InspectScroll = 0
}

func handleInspectKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if tev.Rune() == '?' {
		app.ShowInspectMenu = !app.ShowInspectMenu
		if app.ShowInspectMenu {
			app.InspectMenuIndex = 0
		}
		return false
	}

	if app.ShowInspectMenu {
		maxIdx := len(inspectorMenuOptions()) - 1
		switch tev.Key() {
		case tcell.KeyUp:
			if app.InspectMenuIndex > 0 {
				app.InspectMenuIndex--
			}
			return false
		case tcell.KeyDown:
			if app.InspectMenuIndex < max(0, maxIdx) {
				app.InspectMenuIndex++
			}
			return false
		}
	}

	switch tev.Key() {
	case tcell.KeyUp:
		if app.InspectScroll > 0 {
			app.InspectScroll--
		}
	case tcell.KeyDown:
		if app.InspectScroll < app.InspectMaxScroll {
			app.InspectScroll++
		}
	case tcell.KeyPgUp:
		app.InspectScroll -= 8
		if app.InspectScroll < 0 {
			app.InspectScroll = 0
		}
	case tcell.KeyPgDn:
		app.InspectScroll += 8
		if app.InspectScroll > app.InspectMaxScroll {
			app.InspectScroll = app.InspectMaxScroll
		}
	case tcell.KeyHome:
		app.InspectScroll = 0
	case tcell.KeyEnd:
		app.InspectScroll = app.InspectMaxScroll
	case tcell.KeyTab:
		jumpInspectSection(app, 1)
	case tcell.KeyBacktab:
		jumpInspectSection(app, -1)
	}

	if app.ConfirmKillKey != "" {
		if r := tev.Rune(); r != 'k' && r != 'K' && r != 'y' && r != 'Y' {
			app.ConfirmKillKey = ""
		}
	}

	if tev.Key() == tcell.KeyEscape {
		if app.ShowInspectMenu {
			app.ShowInspectMenu = false
			return false
		}
		app.ConfirmKillKey = ""
		app.ShowInspectMenu = false
		app.Mode = shared.ModeDashboard
	}

	if tev.Rune() == 'q' {
		app.ConfirmKillKey = ""
		app.ShowInspectMenu = false
		return requestQuit(app)
	}

	if tev.Rune() == 'k' || tev.Rune() == 'K' || tev.Rune() == 'y' || tev.Rune() == 'Y' {
		handleKillRequest(app, tev.Rune())
	}

	if tev.Rune() == 'p' || tev.Rune() == 'P' {
		var cand *shared.Candidate
		for i := range app.Candidates {
			if shared.CandidateKey(app.Candidates[i]) == app.InspectKey {
				cand = &app.Candidates[i]
				break
			}
		}
		if cand != nil && cand.Proc != nil && cand.Proc.ParentPid > 0 {
			for _, c := range app.Candidates {
				if c.Proc != nil && c.Proc.Pid == cand.Proc.ParentPid {
					app.InspectKey = shared.CandidateKey(c)
					app.InspectScroll = 0
					break
				}
			}
		}
	}

	return false
}

func jumpInspectSection(app *shared.AppState, dir int) {
	if app == nil || dir == 0 || len(app.InspectSectionStarts) == 0 {
		return
	}
	current := app.InspectScroll
	target := current
	if dir > 0 {
		for _, row := range app.InspectSectionStarts {
			if row > current {
				target = row
				break
			}
		}
	} else {
		for i := len(app.InspectSectionStarts) - 1; i >= 0; i-- {
			row := app.InspectSectionStarts[i]
			if row < current {
				target = row
				break
			}
		}
	}
	if target < 0 {
		target = 0
	}
	if target > app.InspectMaxScroll {
		target = app.InspectMaxScroll
	}
	app.InspectScroll = target
}

func handleKillRequest(app *shared.AppState, keyRune rune) {
	key := app.InspectKey
	if app.ConfirmKill {
		if app.ConfirmKillKey != key || time.Now().After(app.ConfirmKillDeadline) {
			if keyRune == 'y' || keyRune == 'Y' {
				return
			}
			app.ConfirmKillKey = key
			app.ConfirmKillDeadline = time.Now().Add(app.ConfirmKillTimeout)
			return
		}
	}

	idx := FindIndexByKey(app.Candidates, key)
	if idx == -1 {
		app.LastError = "Process no longer present"
		app.ConfirmKillKey = ""
		return
	}

	pid := app.Candidates[idx].Proc.Pid
	host := shared.DisplayHost(app.Candidates[idx].Host)

	if app.LocalHost != "" && host == app.LocalHost {
		if err := telemetry.KillProcess(pid); err != nil {
			app.LastError = "Kill failed: " + err.Error()
		} else {
			app.LastError = "Killed PID " + strconv.Itoa(pid) + " (" + app.Candidates[idx].Proc.Name + ")"
		}
		app.ConfirmKillKey = ""
		return
	}

	if app.RemoteKill == nil {
		app.LastError = "Kill disabled for remote host"
		app.ConfirmKillKey = ""
		return
	}

	if err := app.RemoteKill(host, pid); err != nil {
		app.LastError = "Remote kill failed: " + err.Error()
	} else {
		app.LastError = "Remote kill sent for PID " + strconv.Itoa(pid) + " (" + app.Candidates[idx].Proc.Name + ")"
	}
	app.ConfirmKillKey = ""
}

func handleWhitelistKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if app.WhitelistShowHelp {
		return handleWhitelistOverlayKey(app, tev)
	}
	processCount := len(whitelistProcessCandidates(app))

	switch tev.Key() {
	case tcell.KeyUp:
		// Navigate within the focused panel.
		switch app.WhitelistField {
		case whitelistFieldProcess:
			if app.WhitelistProcessSelected > 0 {
				app.WhitelistProcessSelected--
			}
		case whitelistFieldEntry:
			if app.WhitelistSelected > 0 {
				app.WhitelistSelected--
			}
		}
	case tcell.KeyDown:
		switch app.WhitelistField {
		case whitelistFieldProcess:
			if app.WhitelistProcessSelected < processCount-1 {
				app.WhitelistProcessSelected++
			}
		case whitelistFieldEntry:
			if app.WhitelistSelected < len(app.WhitelistItems)-1 {
				app.WhitelistSelected++
			}
		}
	case tcell.KeyPgUp:
		// Switch to processes panel.
		app.WhitelistField = whitelistFieldProcess
	case tcell.KeyPgDn:
		// Switch to entries panel.
		app.WhitelistField = whitelistFieldEntry
	case tcell.KeyTab:
		// Toggle between panels.
		if app.WhitelistField == whitelistFieldProcess {
			app.WhitelistField = whitelistFieldEntry
		} else {
			app.WhitelistField = whitelistFieldProcess
		}
	case tcell.KeyBacktab:
		if app.WhitelistField == whitelistFieldEntry {
			app.WhitelistField = whitelistFieldProcess
		} else {
			app.WhitelistField = whitelistFieldEntry
		}
	case tcell.KeyEnter:
		switch app.WhitelistField {
		case whitelistFieldProcess:
			whitelistSelectedCandidate(app)
		case whitelistFieldEntry:
			removeSelectedWhitelistEntry(app)
		}
	case tcell.KeyLeft:
		if stepWorkflowMenu(app, -1) {
			return false
		}
	case tcell.KeyRight:
		if stepWorkflowMenu(app, 1) {
			return false
		}
	case tcell.KeyEscape:
		app.Mode = shared.ModeDashboard
	}

	if tev.Rune() == 'q' {
		return requestQuit(app)
	}

	if tev.Rune() == '?' {
		app.WhitelistShowHelp = true
		app.WhitelistHelpIndex = 0
		return false
	}

	if tev.Rune() == ';' {
		switch app.WhitelistField {
		case whitelistFieldProcess:
			if app.WhitelistProcessSelected >= 0 && app.WhitelistProcessSelected < processCount-1 {
				app.WhitelistProcessSelected++
			}
		case whitelistFieldEntry:
			if app.WhitelistSelected >= 0 && app.WhitelistSelected < len(app.WhitelistItems)-1 {
				app.WhitelistSelected++
			}
		}
	}

	if tev.Rune() == '\'' {
		switch app.WhitelistField {
		case whitelistFieldProcess:
			if app.WhitelistProcessSelected > 0 && app.WhitelistProcessSelected < processCount {
				app.WhitelistProcessSelected--
			}
		case whitelistFieldEntry:
			if app.WhitelistSelected > 0 && app.WhitelistSelected < len(app.WhitelistItems) {
				app.WhitelistSelected--
			}
		}
	}

	if tev.Rune() == 'd' || tev.Rune() == 'D' || tev.Rune() == 'u' || tev.Rune() == 'U' || tev.Rune() == 'x' || tev.Rune() == 'X' {
		removeSelectedWhitelistEntry(app)
	}

	if tev.Rune() == 'w' || tev.Rune() == 'W' {
		app.Mode = shared.ModeDashboard
	}

	if app.WhitelistField < whitelistFieldProcess {
		app.WhitelistField = whitelistFieldProcess
	}
	if app.WhitelistField > whitelistFieldMax {
		app.WhitelistField = whitelistFieldMax
	}
	if processCount == 0 {
		app.WhitelistProcessSelected = -1
	} else if app.WhitelistProcessSelected < 0 {
		app.WhitelistProcessSelected = 0
	} else if app.WhitelistProcessSelected >= processCount {
		app.WhitelistProcessSelected = processCount - 1
	}
	if len(app.WhitelistItems) == 0 {
		app.WhitelistSelected = -1
	} else if app.WhitelistSelected < 0 {
		app.WhitelistSelected = 0
	} else if app.WhitelistSelected >= len(app.WhitelistItems) {
		app.WhitelistSelected = len(app.WhitelistItems) - 1
	}
	return false
}

func removeSelectedWhitelistEntry(app *shared.AppState) {
	if app.Whitelist == nil {
		app.LastError = "whitelist not configured"
		return
	}
	if app.WhitelistSelected < 0 || app.WhitelistSelected >= len(app.WhitelistItems) {
		return
	}

	key := app.WhitelistItems[app.WhitelistSelected]
	if err := app.Whitelist.Remove(key); err != nil {
		app.LastError = "unwhitelist failed: " + err.Error()
		return
	}

	app.LastError = "Removed whitelist entry"
	app.WhitelistItems = app.Whitelist.List()
	if len(app.WhitelistItems) == 0 {
		app.WhitelistSelected = -1
		app.WhitelistListOffset = 0
	} else if app.WhitelistSelected >= len(app.WhitelistItems) {
		app.WhitelistSelected = len(app.WhitelistItems) - 1
	}
	app.RefreshRequested = true
}

func selectedWhitelistProcessCandidate(app *shared.AppState) (shared.Candidate, bool) {
	if app == nil {
		return shared.Candidate{}, false
	}
	procs := whitelistProcessCandidates(app)
	if len(procs) == 0 {
		return shared.Candidate{}, false
	}
	if app.WhitelistProcessSelected < 0 {
		app.WhitelistProcessSelected = 0
	}
	if app.WhitelistProcessSelected >= len(procs) {
		app.WhitelistProcessSelected = len(procs) - 1
	}
	if app.WhitelistProcessSelected >= 0 && app.WhitelistProcessSelected < len(procs) {
		return procs[app.WhitelistProcessSelected], true
	}
	return shared.Candidate{}, false
}

func handleCollectKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if app.CollectShowHelp || app.CollectShowMenu {
		return handleCollectOverlayKey(app, tev)
	}
	switch tev.Key() {
	case tcell.KeyUp:
		cycleField(&app.CollectField, collectFieldSource, collectFieldMax, true)
	case tcell.KeyDown:
		cycleField(&app.CollectField, collectFieldSource, collectFieldMax, false)
	case tcell.KeyBackspace, tcell.KeyBackspace2:
		handleCollectBackspace(app)
	case tcell.KeyEnter:
		handleCollectEnter(app)
	case tcell.KeyEscape:
		if app.CollectEditing {
			app.CollectEditing = false
		} else {
			app.Mode = shared.ModeDashboard
		}
	}

	if tev.Key() == tcell.KeyRune && tev.Rune() != 0 {
		if tev.Rune() == '?' && !app.CollectEditing {
			app.CollectShowHelp = true
			app.CollectHelpIndex = 0
			return false
		}
		handleCollectRuneInput(app, tev.Rune())
	}
	if tev.Rune() == 'q' && !app.CollectEditing {
		return requestQuit(app)
	}

	return false
}

func handleCollectOverlayKey(app *shared.AppState, tev *tcell.EventKey) bool {
	return handleOverlayKey(app, tev, overlayState{
		showHelp: &app.CollectShowHelp, showMenu: &app.CollectShowMenu,
		helpIndex: &app.CollectHelpIndex, menuIndex: &app.CollectMenuIndex,
		menuOptions: &app.CollectMenuOptions, menuKind: &app.CollectMenuKind,
		menuTitle: &app.CollectMenuTitle, helpOptions: collectMenuHelpOptions,
		applyMenu: func(a *shared.AppState) { applyCollectMenuSelection(a) },
	})
}

func handleContourKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if app.ContourShowHelp || app.ContourShowMenu {
		return handleContourOverlayKey(app, tev)
	}
	normalizeContourFieldSelection(app)
	switch tev.Key() {
	case tcell.KeyUp:
		moveContourField(app, -1)
	case tcell.KeyDown:
		moveContourField(app, 1)
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

func openContourMenu(app *shared.AppState, kind, title string, options []string, selected int) {
	openWorkflowMenu(kind, title, options, selected, &app.ContourShowHelp, &app.ContourShowMenu, &app.ContourMenuKind, &app.ContourMenuTitle, &app.ContourMenuOptions, &app.ContourMenuIndex)
}

func applyContourMenuSelection(app *shared.AppState) {
	if len(app.ContourMenuOptions) == 0 {
		return
	}
	choice := app.ContourMenuOptions[clampChoice(app.ContourMenuIndex, len(app.ContourMenuOptions))]
	switch app.ContourMenuKind {
	case "duration":
		app.ContourDuration = choice
	case "probe-mode":
		app.ContourProbeMode = contour.ProbeModeChecks
		app.ContourProbeRole = contour.ProbeRoleClient
	}
	normalizeContourFieldSelection(app)
}

func contourProbeModeOptionsForRole(_ string) []string {
	return []string{contour.ProbeModeChecks}
}

// contourRoleOptionsForMode returns the available role choices.
func contourRoleOptionsForMode(_ string) []string {
	return []string{contour.ProbeRoleClient, contour.ProbeRoleListen}
}

func contourNormalizeProbeModeForRole(mode, role string) string {
	mode = contour.NormalizeProbeMode(mode)
	opts := contourProbeModeOptionsForRole(role)
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
	case contourFieldEndpoint:
		app.ContourProbeEndpoint = trimLastRune(app.ContourProbeEndpoint)
	case contourFieldOutput:
		app.ContourOutput = trimLastRune(app.ContourOutput)
	}
}

func handleContourEnter(app *shared.AppState) {
	normalizeContourFieldSelection(app)
	switch app.ContourField {
	case contourFieldEndpoint:
		if app.ContourActive || app.ContourAnalyzing {
			return
		}
		if !app.ContourEditing {
			app.ContourProbeEndpoint = ""
		}
		app.ContourEditing = !app.ContourEditing
	case contourFieldOutput:
		if app.ContourActive || app.ContourAnalyzing {
			return
		}
		app.ContourEditing = !app.ContourEditing
	case contourFieldDuration:
		if app.ContourActive || app.ContourAnalyzing {
			return
		}
		openContourMenu(app, "duration", "Select Duration", contour.DurationOptions(), findIndex(contour.DurationOptions(), app.ContourDuration))
	case contourFieldProbeMode:
		if app.ContourActive || app.ContourAnalyzing {
			return
		}
		displayOpts := []string{"Deep"}
		openContourMenu(app, "probe-mode", "Select Depth", displayOpts, 0)
	case contourFieldAction:
		if app.ContourActive {
			stopContour(app)
			return
		}
		startContour(app)
	}
}

func contourFieldVisible(app *shared.AppState, field int) bool {
	if field < contourFieldEndpoint || field > contourFieldMax {
		return false
	}
	// Duration, probe mode, and probe role are not user-facing.
	if field == contourFieldDuration || field == contourFieldProbeMode || field == contourFieldProbeRole {
		return false
	}
	return true
}

func normalizeContourFieldSelection(app *shared.AppState) {
	if app == nil {
		return
	}
	if contourFieldVisible(app, app.ContourField) {
		return
	}
	app.ContourField = contourFieldEndpoint
	for app.ContourField <= contourFieldMax && !contourFieldVisible(app, app.ContourField) {
		app.ContourField++
	}
	if app.ContourField > contourFieldMax {
		app.ContourField = contourFieldEndpoint
	}
}

func moveContourField(app *shared.AppState, dir int) {
	if app == nil || dir == 0 {
		return
	}
	normalizeContourFieldSelection(app)
	for tries := 0; tries <= contourFieldMax; tries++ {
		next := app.ContourField + dir
		if next < contourFieldEndpoint {
			next = contourFieldMax
		}
		if next > contourFieldMax {
			next = contourFieldEndpoint
		}
		app.ContourField = next
		if contourFieldVisible(app, app.ContourField) {
			return
		}
	}
}

func handleContourRuneInput(app *shared.AppState, r rune) {
	if !app.ContourEditing || r < 32 || r > 126 {
		return
	}
	switch app.ContourField {
	case contourFieldEndpoint:
		app.ContourProbeEndpoint += string(r)
	case contourFieldOutput:
		app.ContourOutput += string(r)
	}
}

func handleSIEMKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if app.SIEMShowHelp || app.SIEMShowMenu {
		return handleSIEMOverlayKey(app, tev)
	}
	switch tev.Key() {
	case tcell.KeyUp:
		cycleField(&app.SIEMField, siemFieldProvider, siemFieldMaxFor(app), true)
	case tcell.KeyDown:
		cycleField(&app.SIEMField, siemFieldProvider, siemFieldMaxFor(app), false)
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
			scrollReport(&app.SIEMReportScroll, app.SIEMReportMaxScroll,-8)
		}
	case tcell.KeyPgDn:
		if !app.SIEMEditing {
			scrollReport(&app.SIEMReportScroll, app.SIEMReportMaxScroll,8)
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
			scrollReport(&app.SIEMReportScroll, app.SIEMReportMaxScroll,1)
			return false
		case ']':
			scrollReport(&app.SIEMReportScroll, app.SIEMReportMaxScroll,-1)
			return false
		}
	}
	if tev.Rune() == 'q' && !app.SIEMEditing {
		return requestQuit(app)
	}
	return false
}

func handleCalibrationKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if app.ShowCalibrateHelp || app.ShowCalibrateMenu {
		return handleCalibrationOverlayKey(app, tev)
	}

	switch tev.Key() {
	case tcell.KeyUp:
		cycleField(&app.CalibrateField, calibrateFieldProvider, calibrateFieldMax, true)
	case tcell.KeyDown:
		cycleField(&app.CalibrateField, calibrateFieldProvider, calibrateFieldMax, false)
	case tcell.KeyTab:
		cycleField(&app.CalibrateField, calibrateFieldProvider, calibrateFieldMax, false)
	case tcell.KeyBacktab:
		cycleField(&app.CalibrateField, calibrateFieldProvider, calibrateFieldMax, true)
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
		scrollReport(&app.CalibrateReportScroll, app.CalibrateReportMaxScroll,-8)
	case tcell.KeyPgDn:
		scrollReport(&app.CalibrateReportScroll, app.CalibrateReportMaxScroll,8)
	case tcell.KeyHome:
		app.CalibrateReportScroll = 0
	case tcell.KeyEnd:
		app.CalibrateReportScroll = app.CalibrateReportMaxScroll
	}

	switch tev.Rune() {
	case '[':
		scrollReport(&app.CalibrateReportScroll, app.CalibrateReportMaxScroll,1)
		return false
	case ']':
		scrollReport(&app.CalibrateReportScroll, app.CalibrateReportMaxScroll,-1)
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

func handleKeystoreKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if app.KeystoreShowHelp {
		return handleKeystoreOverlayKey(app, tev)
	}

	// Handle creation wizard if open.
	if app.KeystoreWizardOpen {
		return handleKeystoreWizardKey(app, tev)
	}

	// Determine which panel is active.
	inFieldsMode := app.KeystoreUnlocked && app.KeystoreActiveEntry != ""
	inListPanel := app.KeystorePanel == 1

	switch tev.Key() {
	case tcell.KeyUp:
		if inListPanel {
			if app.KeystoreSelected > 0 {
				app.KeystoreSelected--
			}
		} else if inFieldsMode {
			cycleKeystoreField(&app.KeystoreField, true)
		}
		// Setup panel has only one field (Create), nothing to cycle.
	case tcell.KeyDown:
		if inListPanel {
			entries := keystore.ListKeystores()
			if app.KeystoreSelected < len(entries)-1 {
				app.KeystoreSelected++
			}
		} else if inFieldsMode {
			cycleKeystoreField(&app.KeystoreField, false)
		}
	case tcell.KeyTab:
		// Toggle between fields/setup and keystores list.
		if app.KeystoreEditing {
			// Stop editing before switching panels.
			app.KeystoreEditing = false
			keystore.ApplyToRuntime(app.KeystoreValues)
		}
		if app.KeystorePanel == 1 {
			app.KeystorePanel = 0
		} else {
			app.KeystorePanel = 1
		}
	case tcell.KeyBacktab:
		if app.KeystoreEditing {
			app.KeystoreEditing = false
			keystore.ApplyToRuntime(app.KeystoreValues)
		}
		if app.KeystorePanel == 0 {
			app.KeystorePanel = 1
		} else {
			app.KeystorePanel = 0
		}
	case tcell.KeyPgUp:
		app.KeystorePanel = 0
	case tcell.KeyPgDn:
		app.KeystorePanel = 1
	case tcell.KeyBackspace, tcell.KeyBackspace2:
		handleKeystoreBackspace(app)
	case tcell.KeyEnter:
		if inListPanel {
			// Select a keystore from the list — works even if one is
			// already unlocked, allowing the user to switch keystores.
			selectKeystoreEntry(app)
		} else {
			handleKeystoreEnter(app)
		}
	case tcell.KeyEscape:
		if app.KeystoreEditing {
			app.KeystoreEditing = false
			// Apply on edit stop.
			keystore.ApplyToRuntime(app.KeystoreValues)
		} else if inListPanel && inFieldsMode {
			// Escape from list back to fields panel.
			app.KeystorePanel = 0
		} else if inFieldsMode {
			// Apply values to runtime and go back to dashboard.
			// Only lock secure keystores on explicit Lock action.
			keystore.ApplyToRuntime(app.KeystoreValues)
			app.Mode = shared.ModeDashboard
		} else {
			app.Mode = shared.ModeDashboard
		}
	}

	// List panel actions.
	if inListPanel {
		if tev.Rune() == 'a' {
			activateSelectedKeystore(app)
			return false
		}
		if tev.Rune() == 'd' {
			deleteSelectedKeystore(app)
			return false
		}
		if tev.Rune() == 'n' {
			app.KeystoreWizardOpen = true
			app.KeystoreWizardField = 0
			app.KeystoreWizardName = ""
			app.KeystoreWizardSecure = false
			app.KeystoreWizardSlot = ""
			app.KeystoreWizardEditing = false
			return false
		}
	}

	if tev.Key() == tcell.KeyRune && tev.Rune() != 0 {
		if tev.Rune() == '?' && !app.KeystoreEditing {
			app.KeystoreShowHelp = true
			app.KeystoreHelpIndex = 0
			return false
		}
		handleKeystoreRuneInput(app, tev.Rune())
		if tev.Rune() == 'q' && app.KeystoreEditing {
			return false
		}
	}
	if tev.Rune() == 'q' && !app.KeystoreEditing {
		return requestQuit(app)
	}
	return false
}

func handleKeystoreOverlayKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if tev.Rune() == 'q' {
		return requestQuit(app)
	}
	if tev.Rune() == '?' || tev.Key() == tcell.KeyEscape {
		app.KeystoreShowHelp = false
		return false
	}
	maxIdx := len(keystoreMenuHelpOptions()) - 1
	switch tev.Key() {
	case tcell.KeyUp:
		if app.KeystoreHelpIndex > 0 {
			app.KeystoreHelpIndex--
		}
	case tcell.KeyDown:
		if app.KeystoreHelpIndex < max(0, maxIdx) {
			app.KeystoreHelpIndex++
		}
	}
	return false
}

func handleWhitelistOverlayKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if tev.Rune() == 'q' {
		return requestQuit(app)
	}
	if tev.Rune() == '?' || tev.Key() == tcell.KeyEscape {
		app.WhitelistShowHelp = false
		return false
	}
	maxIdx := len(whitelistMenuHelpOptions()) - 1
	switch tev.Key() {
	case tcell.KeyUp:
		if app.WhitelistHelpIndex > 0 {
			app.WhitelistHelpIndex--
		}
	case tcell.KeyDown:
		if app.WhitelistHelpIndex < max(0, maxIdx) {
			app.WhitelistHelpIndex++
		}
	}
	return false
}

func handleSIEMBackspace(app *shared.AppState) {
	if !app.SIEMEditing {
		return
	}
	switch app.SIEMField {
	case siemFieldModel:
		app.SIEMModel = trimLastRune(app.SIEMModel)
	case siemFieldReportOutput:
		app.SIEMReportPath = trimLastRune(app.SIEMReportPath)
	case siemFieldJSONOutput:
		app.SIEMExportPath = trimLastRune(app.SIEMExportPath)
	case siemFieldDebugLog:
		app.SIEMDebugLogPath = trimLastRune(app.SIEMDebugLogPath)
	case siemFieldRulesJSON:
		app.SIEMRulesJSONPath = trimLastRune(app.SIEMRulesJSONPath)
	}
}

func handleSIEMEnter(app *shared.AppState) {
	switch app.SIEMField {
	case siemFieldSourceReport:
		refreshSIEMSourceReports(app)
		if len(app.SIEMSourceReports) == 0 {
			setWorkflowStatus(app, &app.SIEMStatusText, &app.SIEMStatusError, &app.SIEMStatusUntil,"no calibration reports found; run Calibrate from this menu", true)
			return
		}
		openSIEMMenu(app, "source-report", "Select Source Report", app.SIEMSourceReports, findIndex(app.SIEMSourceReports, app.SIEMSourceReport))
	case siemFieldProvider:
		opts := calibration.Providers()
		openSIEMMenu(app, "provider", "Select Provider", opts, findIndex(opts, calibration.ProviderLabel(app.SIEMProvider)))
	case siemFieldModel:
		opts := calibration.ModelOptions(app.SIEMProvider)
		if len(opts) == 0 {
			return
		}
		openSIEMMenu(app, "model", "Select Model", opts, findIndex(opts, app.SIEMModel))
	case siemFieldGenerate:
		runSIEMGeneration(app)
	case siemFieldSaveGeneration:
		applySIEMGenerationSettings(app, true)
	case siemFieldCalibrate:
		kickoffCalibrationFromSIEM(app)
	case siemFieldApply:
		applySIEMRuntimeExportSettings(app, false)
	case siemFieldSave:
		applySIEMRuntimeExportSettings(app, true)
	case siemFieldDisable:
		app.SIEMDebugLogPath = ""
		app.SIEMRulesJSONPath = ""
		applySIEMRuntimeExportSettings(app, false)
	default:
		if siemFieldEditable(app.SIEMField) {
			app.SIEMEditing = !app.SIEMEditing
		}
	}
}

func handleSIEMRuneInput(app *shared.AppState, r rune) {
	if !app.SIEMEditing || r < 32 || r > 126 {
		return
	}
	switch app.SIEMField {
	case siemFieldModel:
		app.SIEMModel += string(r)
	case siemFieldReportOutput:
		app.SIEMReportPath += string(r)
	case siemFieldJSONOutput:
		app.SIEMExportPath += string(r)
	case siemFieldDebugLog:
		app.SIEMDebugLogPath += string(r)
	case siemFieldRulesJSON:
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

func applySIEMRuntimeExportSettings(app *shared.AppState, save bool) {
	ensureKeystoreValues(app)
	app.SIEMDebugLogPath = strings.TrimSpace(app.SIEMDebugLogPath)
	app.SIEMRulesJSONPath = strings.TrimSpace(app.SIEMRulesJSONPath)
	app.KeystoreValues["PROXYWATCH_DETECT_DEBUG_LOG"] = app.SIEMDebugLogPath
	app.KeystoreValues["PROXYWATCH_DETECT_RULES_JSON"] = app.SIEMRulesJSONPath
	keystore.ApplyToRuntime(app.KeystoreValues)
	if err := applyDetectionOutputRuntimeConfig(); err != nil {
		setWorkflowStatus(app, &app.SIEMStatusText, &app.SIEMStatusError, &app.SIEMStatusUntil,"apply failed: "+err.Error(), true)
		return
	}
	if save {
		if err := keystore.Save(app.KeystorePath, app.KeystoreValues); err != nil {
			setWorkflowStatus(app, &app.SIEMStatusText, &app.SIEMStatusError, &app.SIEMStatusUntil,"save failed: "+err.Error(), true)
			return
		}
		setWorkflowStatus(app, &app.SIEMStatusText, &app.SIEMStatusError, &app.SIEMStatusUntil,"SIEM paths saved to keystore and applied", false)
		return
	}
	setWorkflowStatus(app, &app.SIEMStatusText, &app.SIEMStatusError, &app.SIEMStatusUntil,"SIEM paths applied to runtime", false)
}

func applySIEMGenerationSettings(app *shared.AppState, save bool) {
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

	// Only set SIEM-specific config in runtime — don't overwrite
	// API keys that may have been loaded from a secure keystore.
	keystore.RuntimeSetValue("PROXYWATCH_SIEM_SOURCE_REPORT", app.SIEMSourceReport)
	keystore.RuntimeSetValue("PROXYWATCH_SIEM_PROVIDER", app.SIEMProvider)
	keystore.RuntimeSetValue("PROXYWATCH_SIEM_MODEL", app.SIEMModel)
	keystore.RuntimeSetValue("PROXYWATCH_SIEM_REPORT_OUTPUT", app.SIEMReportPath)
	keystore.RuntimeSetValue("PROXYWATCH_SIEM_JSON_OUTPUT", app.SIEMExportPath)

	if save {
		if err := keystore.Save(app.KeystorePath, app.KeystoreValues); err != nil {
			setWorkflowStatus(app, &app.SIEMStatusText, &app.SIEMStatusError, &app.SIEMStatusUntil,"save failed: "+err.Error(), true)
			return
		}
		setWorkflowStatus(app, &app.SIEMStatusText, &app.SIEMStatusError, &app.SIEMStatusUntil,"SIEM generation settings saved to keystore", false)
		return
	}
	setWorkflowStatus(app, &app.SIEMStatusText, &app.SIEMStatusError, &app.SIEMStatusUntil,"SIEM generation settings applied to runtime", false)
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

func runSIEMGeneration(app *shared.AppState) {
	if app.SIEMGenerating {
		app.SIEMGenerating = false
		app.SIEMProgressLines = nil
		setWorkflowStatus(app, &app.SIEMStatusText, &app.SIEMStatusError, &app.SIEMStatusUntil, "SIEM generation stopped", false)
		return
	}
	refreshSIEMSourceReports(app)
	if strings.TrimSpace(app.SIEMSourceReport) == "" {
		siemError(app, "no calibration report — run Calibrate first")
		return
	}
	applySIEMGenerationSettings(app, false)

	access := calibration.DetectProviderAccess()
	if ready, reason := calibration.ProviderReady(app.SIEMProvider, access); !ready {
		if !app.SIEMDecryptAttempted && app.KeystoreActiveEntry != "" && app.KeystoreSecure {
			app.SIEMDecryptAttempted = true
			if tryDecryptAndRun(app, &app.SIEMStatusText, &app.SIEMStatusError, &app.SIEMStatusUntil, func() {
				runSIEMGeneration(app)
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
	setWorkflowStatus(app, &app.SIEMStatusText, &app.SIEMStatusError, &app.SIEMStatusUntil,"SIEM generation started", false)
	if app.StartSIEMGeneration != nil {
		app.StartSIEMGeneration(app.SIEMSourceReport, app.SIEMProvider, app.SIEMModel, app.SIEMReportPath, app.SIEMExportPath)
		return
	}

	// Fallback path if async starter is unavailable.
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
	applySIEMExecResult(app, siemExecResult{result: result, err: err})
}

func applySIEMExecResult(app *shared.AppState, res siemExecResult) {
	app.SIEMGenerating = false
	app.SIEMStartedAt = time.Time{}
	app.SIEMProgressLines = nil
	// Clear secrets from runtime so a secure keystore must be
	// decrypted again for the next operation.
	if isActiveKeystoreSecure(app) {
		keystore.ClearSensitiveRuntime()
	}
	if res.err != nil {
		setWorkflowStatus(app, &app.SIEMStatusText, &app.SIEMStatusError, &app.SIEMStatusUntil,"siem generation failed: "+res.err.Error(), true)
		return
	}
	result := res.result
	app.SIEMSourceReport = result.SourceReport
	app.SIEMReportPath = result.ReportPath
	app.SIEMExportPath = result.JSONPath
	if len(result.ReportLines) > 0 {
		app.SIEMReportLines = append([]string(nil), result.ReportLines...)
		app.SIEMReportScroll = 0
		app.SIEMReportMaxScroll = 0
	} else {
		refreshSIEMReportPreview(app)
	}
	setWorkflowStatus(app, &app.SIEMStatusText, &app.SIEMStatusError, &app.SIEMStatusUntil,fmt.Sprintf("SIEM %s output written: report=%s json=%s detections=%d", result.Mode, result.ReportPath, result.JSONPath, result.DetectionCount), false)
}

func siemFieldEditable(field int) bool {
	switch field {
	case siemFieldReportOutput, siemFieldJSONOutput:
		return true
	default:
		return false
	}
}

func refreshSIEMSourceReports(app *shared.AppState) {
	if app == nil {
		return
	}
	reports, err := calibration.ListReports()
	if err != nil {
		setWorkflowStatus(app, &app.SIEMStatusText, &app.SIEMStatusError, &app.SIEMStatusUntil,"calibration report list failed: "+err.Error(), true)
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

func refreshSIEMReportPreview(app *shared.AppState) {
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

func kickoffCalibrationFromSIEM(app *shared.AppState) {
	enterCalibrationMode(app)
	if app.CalibrateActive {
		setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil,"calibration already running", false)
		return
	}
	duration := strings.TrimSpace(app.CalibrateDuration)
	if duration == "" || !containsString(calibration.DurationOptions(), duration) {
		app.CalibrateDuration = "30s"
	}
	startCalibration(app)
}

func handleKeystoreBackspace(app *shared.AppState) {
	if !app.KeystoreEditing {
		return
	}
	key, ok := keystoreFieldEnvKey(app.KeystoreField)
	if !ok {
		return
	}
	ensureKeystoreValues(app)
	app.KeystoreValues[key] = trimLastRune(app.KeystoreValues[key])
	keystore.ApplyToRuntime(app.KeystoreValues)
}

func handleKeystoreEnter(app *shared.AppState) {
	// Create wizard — always available regardless of unlock state.
	if app.KeystoreField == keystoreFieldLoad {
		app.KeystoreWizardOpen = true
		app.KeystoreWizardField = 0
		app.KeystoreWizardName = ""
		app.KeystoreWizardSecure = false
		app.KeystoreWizardSlot = ""
		app.KeystoreWizardEditing = false
		return
	}

	// Fields below require an unlocked keystore.
	if !app.KeystoreUnlocked || app.KeystoreActiveEntry == "" {
		return
	}

	switch app.KeystoreField {
	case keystoreFieldMethod:
		methods := keystore.DetectSecurityMethods()
		opts := make([]string, 0, len(methods))
		for _, m := range methods {
			status := "✓"
			if !m.Available {
				status = "✗"
			}
			opts = append(opts, status+" "+m.Label)
		}
		app.KeystoreShowHelp = false
		app.KeystoreEditing = false
		// Use a simple menu — store options in a temporary field.
		// For now, cycle through methods on Enter.
		currentMethod := strings.TrimSpace(app.KeystoreMethod)
		if currentMethod == "" {
			currentMethod = "local"
		}
		switch currentMethod {
		case "local":
			for _, m := range methods {
				if m.ID == "gpg" && m.Available {
					app.KeystoreMethod = "gpg"
					setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil, "security method changed to GPG Key", false)
					return
				}
			}
			for _, m := range methods {
				if m.ID == "yubikey" && m.Available {
					app.KeystoreMethod = "yubikey"
					setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil, "security method changed to Hardware Key", false)
					return
				}
			}
			setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil, "no other security methods available", true)
		case "gpg":
			for _, m := range methods {
				if m.ID == "yubikey" && m.Available {
					app.KeystoreMethod = "yubikey"
					setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil, "security method changed to Hardware Key", false)
					return
				}
			}
			app.KeystoreMethod = "local"
			setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil, "security method changed to Local Key", false)
		default:
			app.KeystoreMethod = "local"
			setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil, "security method changed to Local Key", false)
		}
	case keystoreFieldLoad:
		loadKeystore(app)
	case keystoreFieldSave:
		saveKeystore(app)
	case keystoreFieldApply:
		applyKeystore(app)
	case keystoreFieldLock:
		lockKeystore(app)
	default:
		wasEditing := app.KeystoreEditing
		app.KeystoreEditing = !app.KeystoreEditing
		// Commit edits immediately to runtime config so token/auth changes
		// take effect without requiring a separate Apply action.
		if wasEditing {
			applyKeystore(app)
		}
	}
}

func handleKeystoreRuneInput(app *shared.AppState, r rune) {
	if !app.KeystoreEditing || r < 32 || r > 126 {
		return
	}
	key, ok := keystoreFieldEnvKey(app.KeystoreField)
	if !ok {
		return
	}
	ensureKeystoreValues(app)
	app.KeystoreValues[key] += string(r)
	// Auto-apply to runtime so other dashboards can use the value immediately.
	keystore.ApplyToRuntime(app.KeystoreValues)
}

func loadKeystore(app *shared.AppState) {
	values, err := keystore.Load(app.KeystorePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,"keystore not found; save to create "+keystore.NormalizePath(app.KeystorePath), true)
			return
		}
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,"load failed: "+err.Error(), true)
		return
	}
	app.KeystoreValues = values
	keystore.ApplyToRuntime(values)
	if err := applyDetectionOutputRuntimeConfig(); err != nil {
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,"load failed: "+err.Error(), true)
		return
	}
	app.KeystoreUnlocked = true
	keystore.SetActiveKeystore(&app.KeystoreValues)
	app.KeystoreEditing = false
	setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,"keystore loaded and applied to runtime config", false)
}

func saveKeystore(app *shared.AppState) {
	ensureKeystoreValues(app)

	if app.KeystoreSecure {
		// Save securely in background (requires YubiKey touch).
		values := make(map[string]string)
		for k, v := range app.KeystoreValues {
			values[k] = v
		}
		path := app.KeystorePath
		entries := keystore.ListKeystores()
		slot := "2"
		for _, e := range entries {
			if e.Name == app.KeystoreActiveEntry && e.Slot != "" {
				slot = e.Slot
			}
		}
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil, "saving — touch YubiKey...", false)
		go func() {
			if err := keystore.SaveSecure(path, slot, values); err != nil {
				setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil, "save failed: "+err.Error(), true)
				return
			}
			keystore.ApplyToRuntime(values)
			setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil, "secure keystore saved (YubiKey)", false)
		}()
		return
	}

	if err := keystore.SaveNonSecure(app.KeystorePath, app.KeystoreValues); err != nil {
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil, "save failed: "+err.Error(), true)
		return
	}
	keystore.ApplyToRuntime(app.KeystoreValues)
	_ = applyDetectionOutputRuntimeConfig()
	app.KeystoreEditing = false
	setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,"keystore saved (encrypted) and applied to runtime config", false)
}

func handleKeystoreWizardKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if tev.Key() == tcell.KeyEscape {
		app.KeystoreWizardOpen = false
		app.KeystoreWizardEditing = false
		return false
	}

	maxField := 2 // name, encryption, create
	if app.KeystoreWizardSecure {
		maxField = 3 // name, encryption, slot, create
	}

	switch tev.Key() {
	case tcell.KeyUp:
		if app.KeystoreWizardField > 0 {
			app.KeystoreWizardField--
		}
	case tcell.KeyDown:
		if app.KeystoreWizardField < maxField {
			app.KeystoreWizardField++
		}
	case tcell.KeyBackspace, tcell.KeyBackspace2:
		if app.KeystoreWizardEditing && app.KeystoreWizardField == 0 {
			if len(app.KeystoreWizardName) > 0 {
				app.KeystoreWizardName = app.KeystoreWizardName[:len(app.KeystoreWizardName)-1]
			}
		}
	case tcell.KeyEnter:
		switch app.KeystoreWizardField {
		case 0: // Name — toggle editing.
			app.KeystoreWizardEditing = !app.KeystoreWizardEditing
		case 1: // Encryption — toggle secure/standard.
			hwAvail, _ := keystore.HardwareKeyAvailable()
			if app.KeystoreWizardSecure {
				app.KeystoreWizardSecure = false
				app.KeystoreWizardSlot = ""
			} else if hwAvail {
				app.KeystoreWizardSecure = true
				// Auto-select first existing credential.
				slots := keystore.DetectKeySlotsCached()
				for _, s := range slots {
					if s.InUse {
						app.KeystoreWizardSlot = s.ID
						break
					}
				}
			} else {
				setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
					"no hardware key detected", true)
			}
		case 2: // Key (if secure) or Create (if not secure).
			if app.KeystoreWizardSecure {
				// Cycle through existing (in-use) credentials only.
				slots := keystore.DetectKeySlotsCached()
				var inUse []keystore.KeySlot
				for _, s := range slots {
					if s.InUse {
						inUse = append(inUse, s)
					}
				}
				if len(inUse) > 0 {
					found := false
					for i, s := range inUse {
						if s.ID == app.KeystoreWizardSlot {
							app.KeystoreWizardSlot = inUse[(i+1)%len(inUse)].ID
							found = true
							break
						}
					}
					if !found {
						app.KeystoreWizardSlot = inUse[0].ID
					}
				}
			} else {
				executeKeystoreWizardCreate(app)
			}
		case 3: // Create (when secure).
			executeKeystoreWizardCreate(app)
		}
	}

	// Rune input for name editing.
	if app.KeystoreWizardEditing && app.KeystoreWizardField == 0 {
		r := tev.Rune()
		if r >= 32 && r <= 126 {
			app.KeystoreWizardName += string(r)
		}
	}

	if tev.Rune() == 'q' && !app.KeystoreWizardEditing {
		return requestQuit(app)
	}
	return false
}

func executeKeystoreWizardCreate(app *shared.AppState) {
	name := strings.TrimSpace(app.KeystoreWizardName)
	if name == "" {
		name = fmt.Sprintf("keystore-%s", time.Now().Format("20060102-150405"))
	}
	secure := app.KeystoreWizardSecure
	slot := app.KeystoreWizardSlot

	if secure {
		// Run in background so UI can render the touch prompt.
		app.KeystoreWizardOpen = false
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
			"creating secure keystore — touch YubiKey...", false)
		go func() {
			entry, err := keystore.CreateKeystore(name, true, slot)
			if err != nil {
				setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
					"create failed: "+err.Error(), true)
				return
			}
			app.KeystoreActiveEntry = entry.Name
			app.KeystoreSecure = true
			app.KeystorePath = entry.Path
			app.KeystoreValues = keystore.EmptyValues()
			app.KeystoreUnlocked = true
			keystore.SetActiveKeystore(&app.KeystoreValues)
			app.KeystoreField = keystoreFieldOpenAIKey
			app.KeystorePanel = 0
			app.KeystoreEditing = false
			app.KeystoreWizardEditing = false
			setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
				"secure keystore created (slot "+slot+"): "+entry.Name, false)
		}()
		return
	}

	entry, err := keystore.CreateKeystore(name, false)
	if err != nil {
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
			"create failed: "+err.Error(), true)
		return
	}

	app.KeystoreWizardOpen = false
	app.KeystoreWizardEditing = false
	app.KeystoreActiveEntry = entry.Name
	app.KeystoreSecure = false
	app.KeystorePath = entry.Path
	app.KeystoreValues = keystore.EmptyValues()
	app.KeystoreUnlocked = true
	keystore.SetActiveKeystore(&app.KeystoreValues)
	app.KeystoreField = keystoreFieldOpenAIKey
	app.KeystorePanel = 0
	app.KeystoreEditing = false

	label := "keystore created: " + entry.Name
	setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil, label, false)
}

func deleteSelectedKeystore(app *shared.AppState) {
	entries := keystore.ListKeystores()
	if app.KeystoreSelected < 0 || app.KeystoreSelected >= len(entries) {
		return
	}
	entry := entries[app.KeystoreSelected]

	// First press: ask for confirmation.
	if !app.KeystoreDeleteConfirm || app.KeystoreDeleteTarget != entry.Name {
		app.KeystoreDeleteConfirm = true
		app.KeystoreDeleteTarget = entry.Name
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
			"press d again to confirm delete: "+entry.Name, true)
		return
	}

	// Second press: confirmed.
	app.KeystoreDeleteConfirm = false
	app.KeystoreDeleteTarget = ""

	if entry.Secure {
		hwAvail, _ := keystore.HardwareKeyAvailable()
		if !hwAvail {
			setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
				"cannot delete secure keystore — hardware key not connected", true)
			return
		}
	}

	if err := keystore.DeleteKeystore(entry.Name); err != nil {
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
			"delete failed: "+err.Error(), true)
		return
	}

	// If we deleted the active keystore, lock it and reset UI state.
	if entry.Name == app.KeystoreActiveEntry {
		app.KeystoreValues = make(map[string]string)
		app.KeystoreUnlocked = false
		keystore.SetActiveKeystore(nil)
		app.KeystoreActiveEntry = ""
		app.KeystoreSecure = false
		app.KeystoreEditing = false
		app.KeystoreField = keystoreFieldLoad
		app.KeystorePanel = 0
	}

	// Clamp selection to remaining entries.
	remaining := keystore.ListKeystores()
	if len(remaining) == 0 {
		app.KeystoreSelected = 0
		app.KeystorePanel = 0
	} else if app.KeystoreSelected >= len(remaining) {
		app.KeystoreSelected = len(remaining) - 1
	}
	setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
		"keystore deleted: "+entry.Name, false)
}

// activateSelectedKeystore marks the selected keystore as the active one
// and loads its values into runtime so other dashboards can use them.
// It does NOT open the fields panel — only Enter does that.
func activateSelectedKeystore(app *shared.AppState) {
	entries := keystore.ListKeystores()
	if app.KeystoreSelected < 0 || app.KeystoreSelected >= len(entries) {
		return
	}
	entry := entries[app.KeystoreSelected]

	if entry.Name == app.KeystoreActiveEntry {
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
			"already active: "+entry.Name, false)
		return
	}

	// Clear previous keystore's secrets from runtime before switching.
	keystore.ClearSensitiveRuntime()

	app.KeystoreSecure = entry.Secure
	app.KeystorePath = entry.Path

	if entry.Secure {
		path := entry.Path
		entryName := entry.Name
		app.KeystoreActiveEntry = entryName
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
			"touch YubiKey to activate...", false)
		go func() {
			values, err := keystore.LoadSecure(path)
			if err != nil {
				setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
					"activate failed: "+err.Error(), true)
				app.KeystoreActiveEntry = ""
				return
			}
			keystore.ApplyToRuntime(values)
			keystore.SetActiveKeystore(nil)
			setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
				"activated and relocked: "+entryName, false)
		}()
	} else {
		values, err := keystore.LoadNonSecure(entry.Path)
		if err != nil {
			setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
				"activate failed: "+err.Error(), true)
			return
		}
		app.KeystoreActiveEntry = entry.Name
		keystore.ApplyToRuntime(values)
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
			"activated: "+entry.Name, false)
	}
}

func selectKeystoreEntry(app *shared.AppState) {
	entries := keystore.ListKeystores()
	if app.KeystoreSelected < 0 || app.KeystoreSelected >= len(entries) {
		return
	}
	entry := entries[app.KeystoreSelected]
	app.KeystoreActiveEntry = entry.Name
	app.KeystoreSecure = entry.Secure
	app.KeystorePath = entry.Path

	if entry.Secure {
		// Secure keystore — decrypt in background so UI can show touch prompt.
		path := entry.Path
		entryName := entry.Name
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
			"touch YubiKey to decrypt...", false)
		go func() {
			values, err := keystore.LoadSecure(path)
			if err != nil {
				// Fall back to regular Load for keystores encrypted
				// with a local master key (old format).
				values, err = keystore.Load(path)
			}
			if err != nil {
				setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
					"decrypt failed: "+err.Error(), true)
				app.KeystoreActiveEntry = ""
				return
			}
			app.KeystoreValues = values
			keystore.ApplyToRuntime(values)
			app.KeystoreUnlocked = true
			keystore.SetActiveKeystore(&app.KeystoreValues)
			app.KeystoreField = keystoreFieldOpenAIKey
			app.KeystorePanel = 0
			app.KeystoreEditing = false
			setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
				"secure keystore decrypted and loaded: "+entryName, false)
		}()
	} else {
		// Non-secure keystore — load plain JSON.
		values, err := keystore.LoadNonSecure(entry.Path)
		if err != nil {
			setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
				"load failed: "+err.Error(), true)
			return
		}
		app.KeystoreValues = values
		keystore.ApplyToRuntime(values)
		app.KeystoreUnlocked = true
		keystore.SetActiveKeystore(&app.KeystoreValues)
		app.KeystoreField = keystoreFieldOpenAIKey
		app.KeystorePanel = 0
		app.KeystoreEditing = false
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
			"keystore loaded", false)
	}
}

func lockKeystore(app *shared.AppState) {
	// Auto-save before locking.
	wasSecure := app.KeystoreSecure
	path := app.KeystorePath
	valuesToSave := app.KeystoreValues
	activeName := app.KeystoreActiveEntry

	// Clear memory and runtime immediately.
	app.KeystoreValues = make(map[string]string)
	keystore.ApplyToRuntime(make(map[string]string))
	app.KeystoreUnlocked = false
	keystore.SetActiveKeystore(nil)
	app.KeystoreEditing = false
	app.KeystoreActiveEntry = ""
	app.KeystorePanel = 0

	if activeName != "" && path != "" && valuesToSave != nil {
		if wasSecure {
			// Re-encrypt in background (requires YubiKey touch).
			setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
				"encrypting — touch YubiKey...", false)
			go func() {
				entries := keystore.ListKeystores()
				slot := "2"
				for _, e := range entries {
					if e.Name == activeName && e.Slot != "" {
						slot = e.Slot
					}
				}
				if err := keystore.SaveSecure(path, slot, valuesToSave); err != nil {
					setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
						"encrypt failed: "+err.Error(), true)
				} else {
					setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
						"secure keystore encrypted and locked — runtime cleared", false)
				}
			}()
		} else {
			_ = keystore.SaveNonSecure(path, valuesToSave)
			setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
				"keystore saved and locked", false)
		}
	} else {
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
			"keystore locked — values cleared from memory", false)
	}
}

func applyKeystore(app *shared.AppState) {
	ensureKeystoreValues(app)
	keystore.ApplyToRuntime(app.KeystoreValues)
	if err := applyDetectionOutputRuntimeConfig(); err != nil {
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,"apply failed: "+err.Error(), true)
		return
	}
	setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,"runtime config updated from keystore values", false)
}

func applyDetectionOutputRuntimeConfig() error {
	debugOutputPath := keystore.RuntimeValue("PROXYWATCH_DETECT_DEBUG_LOG")
	defenderOutputPath := keystore.RuntimeValue("PROXYWATCH_DETECT_RULES_JSON")
	return classifier.ConfigureDetectionOutputs(debugOutputPath, defenderOutputPath)
}

func ensureKeystoreValues(app *shared.AppState) {
	if app.KeystoreValues == nil {
		app.KeystoreValues = keystore.ValuesFromRuntime()
	}
	// Keep the active keystore pointer in sync so RuntimeValue() reads
	// from the same map that the UI edits.  This is essential after a
	// secure keystore was decrypted in the Keystore view — without this,
	// other dashboards would find an empty runtimeValues fallback.
	if app.KeystoreUnlocked && len(app.KeystoreValues) > 0 {
		keystore.ApplyToRuntime(app.KeystoreValues)
		keystore.SetActiveKeystore(&app.KeystoreValues)
	}
}

// autoLoadKeystore attempts to load the first registered keystore when no
// keystore is currently unlocked.  Non-secure keystores are loaded
// synchronously; secure keystores are decrypted in a background goroutine
// so the UI can render the YubiKey touch prompt.  statusText / statusError /
// statusUntil point to the calling dashboard's status bar fields so the
// user sees feedback regardless of which view they are in.
// tryDecryptAndRun decrypts the active secure keystore in the background,
// applies values to runtime, relocks, then calls onSuccess. Returns true
// if a background decrypt was started, false if the keystore isn't secure
// or can't be found.
func tryDecryptAndRun(app *shared.AppState, statusText *string, statusError *bool, statusUntil *time.Time, onSuccess func()) bool {
	if app.KeystoreActiveEntry == "" || !app.KeystoreSecure {
		return false
	}
	path := app.KeystorePath
	if path == "" {
		entries := keystore.ListKeystores()
		for _, e := range entries {
			if e.Name == app.KeystoreActiveEntry {
				path = e.Path
				break
			}
		}
	}
	if path == "" {
		return false
	}

	setWorkflowStatus(app, statusText, statusError, statusUntil,
		"touch YubiKey to decrypt keystore...", false)
	go func() {
		values, err := keystore.LoadSecure(path)
		if err != nil {
			setWorkflowStatus(app, statusText, statusError, statusUntil,
				"decrypt failed: "+err.Error(), true)
			return
		}
		keystore.ApplyToRuntime(values)
		keystore.SetActiveKeystore(nil)
		onSuccess()
	}()
	return true
}

func autoLoadKeystore(app *shared.AppState, statusText *string, statusError *bool, statusUntil *time.Time) {
	if app.KeystoreUnlocked && app.KeystoreValues != nil && len(app.KeystoreValues) > 0 {
		// Already unlocked — just make sure runtime is in sync.
		keystore.ApplyToRuntime(app.KeystoreValues)
		keystore.SetActiveKeystore(&app.KeystoreValues)
		return
	}

	entries := keystore.ListKeystores()
	if len(entries) == 0 {
		setWorkflowStatus(app, statusText, statusError, statusUntil,
			"no keystore found — create one in the Keystore view", true)
		return
	}

	// Prefer loading the previously active entry if it still exists.
	var target *keystore.KeystoreEntry
	if app.KeystoreActiveEntry != "" {
		for i := range entries {
			if entries[i].Name == app.KeystoreActiveEntry {
				target = &entries[i]
				break
			}
		}
	}
	// Otherwise pick the first non-secure, falling back to the first secure.
	if target == nil {
		for i := range entries {
			if !entries[i].Secure {
				target = &entries[i]
				break
			}
		}
	}
	if target == nil {
		target = &entries[0]
	}

	app.KeystoreActiveEntry = target.Name
	app.KeystoreSecure = target.Secure
	app.KeystorePath = target.Path

	if target.Secure {
		path := target.Path
		entryName := target.Name
		setWorkflowStatus(app, statusText, statusError, statusUntil,
			"touch YubiKey to decrypt keystore \""+entryName+"\"...", false)
		go func() {
			values, err := keystore.LoadSecure(path)
			if err != nil {
				setWorkflowStatus(app, statusText, statusError, statusUntil,
					"keystore decrypt failed: "+err.Error(), true)
				app.KeystoreActiveEntry = ""
				return
			}
			// Apply values to runtime then immediately relock — the
			// plaintext values stay in the runtime map for the current
			// operation but are not held in app memory.
			keystore.ApplyToRuntime(values)
			keystore.SetActiveKeystore(nil)
			setWorkflowStatus(app, statusText, statusError, statusUntil,
				"keystore \""+entryName+"\" applied and relocked", false)
		}()
	} else {
		values, err := keystore.LoadNonSecure(target.Path)
		if err != nil {
			setWorkflowStatus(app, statusText, statusError, statusUntil,
				"keystore load failed: "+err.Error(), true)
			return
		}
		keystore.ApplyToRuntime(values)
		setWorkflowStatus(app, statusText, statusError, statusUntil,
			"keystore \""+target.Name+"\" loaded", false)
	}
}

// keystoreFieldVisible returns false for fields removed from the UI.
// The field constants are kept for backwards compatibility with saved data.
func keystoreFieldVisible(field int) bool {
	switch field {
	case keystoreFieldOpenAIBaseURL, keystoreFieldAnthropicBaseURL,
		keystoreFieldCalibrationTimeout,
		keystoreFieldDisableClientCert, keystoreFieldTrustOnFirstUse,
		keystoreFieldMethod, keystoreFieldNew:
		return false
	}
	return field >= keystoreFieldOpenAIKey && field <= keystoreFieldMax
}

func cycleKeystoreField(field *int, up bool) {
	start := *field
	for {
		if up {
			*field--
			if *field < keystoreFieldOpenAIKey {
				*field = keystoreFieldMax
			}
		} else {
			*field++
			if *field > keystoreFieldMax {
				*field = keystoreFieldOpenAIKey
			}
		}
		if keystoreFieldVisible(*field) {
			return
		}
		if *field == start {
			return
		}
	}
}

func keystoreFieldEnvKey(field int) (string, bool) {
	switch field {
	case keystoreFieldOpenAIKey:
		return "OPENAI_API_KEY", true
	case keystoreFieldOpenAIBaseURL:
		return "OPENAI_BASE_URL", true
	case keystoreFieldAnthropicKey:
		return "ANTHROPIC_API_KEY", true
	case keystoreFieldAnthropicBaseURL:
		return "ANTHROPIC_BASE_URL", true
	case keystoreFieldLocalLLMURL:
		return "LOCAL_LLM_URL", true
	case keystoreFieldLocalLLMAPIKey:
		return "LOCAL_LLM_API_KEY", true
	case keystoreFieldCalibrationTimeout:
		return "CALIBRATION_HTTP_TIMEOUT", true
	case keystoreFieldBloodhoundURL:
		return "BLOODHOUND_API_URL", true
	case keystoreFieldBloodhoundToken:
		return "BLOODHOUND_API_TOKEN", true
	case keystoreFieldBloodhoundTokenID:
		return "BLOODHOUND_API_TOKEN_ID", true
	case keystoreFieldTLSDir:
		return "PROXYWATCH_TLS_DIR", true
	case keystoreFieldAgentToken:
		return "PROXYWATCH_AGENT_TOKEN", true
	case keystoreFieldDisableClientCert:
		return "PROXYWATCH_DISABLE_CLIENT_CERT", true
	case keystoreFieldTrustOnFirstUse:
		return "PROXYWATCH_TRUST_ON_FIRST_USE", true
	default:
		return "", false
	}
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
	}
}

// calibrateEditValue returns the current editable field value.
func calibrateEditValue(app *shared.AppState) string {
	switch app.CalibrateField {
	case calibrateFieldOutput:
		return app.CalibrateOutput
	}
	return ""
}

func handleCalibrationBackspace(app *shared.AppState) {
	if !app.CalibrateEditing {
		return
	}
	switch app.CalibrateField {
	case calibrateFieldOutput:
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
	case calibrateFieldProvider:
		opts := calibration.Providers()
		openCalibrationMenu(app, "provider", "Select Provider", opts, findIndex(opts, calibration.ProviderLabel(app.CalibrateProvider)))
	case calibrateFieldOutput:
		if app.CalibrateActive {
			return
		}
		app.CalibrateEditing = !app.CalibrateEditing
		if app.CalibrateEditing {
			app.CalibrateEditCursor = len(app.CalibrateOutput)
		}
	case calibrateFieldDuration:
		opts := calibration.DurationOptions()
		openCalibrationMenu(app, "duration", "Select Duration", opts, findIndex(opts, app.CalibrateDuration))
	case calibrateFieldModel:
		opts := calibration.ModelOptions(app.CalibrateProvider)
		openCalibrationMenu(app, "model", "Select Model", opts, findIndex(opts, app.CalibrateModel))
	case calibrateFieldProfile:
		if len(app.CalibrateProfiles) == 0 {
			refreshCalibrationState(app)
		}
		if len(app.CalibrateProfiles) == 0 {
			setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil,"no saved calibration profiles yet", true)
			return
		}
		openCalibrationMenu(app, "profile", "Select Profile", app.CalibrateProfiles, findIndex(app.CalibrateProfiles, app.CalibrateProfile))
	case calibrateFieldAction:
		if app.CalibrateActive {
			if app.CalibrateAnalyzing {
				if app.CalibrateCancel != nil {
					app.CalibrateCancel()
					setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil,"canceling calibration analysis...", false)
				}
			} else {
				app.CalibrateUntil = time.Now().Add(-time.Second)
			}
		} else {
			startCalibration(app)
		}
	case calibrateFieldApply:
		applySelectedCalibrationProfile(app)
	}
}

func handleCalibrationRuneInput(app *shared.AppState, r rune) {
	if !app.CalibrateEditing || r < 32 || r > 126 {
		return
	}
	switch app.CalibrateField {
	case calibrateFieldOutput:
		pos := app.CalibrateEditCursor
		if pos > len(app.CalibrateOutput) {
			pos = len(app.CalibrateOutput)
		}
		app.CalibrateOutput = app.CalibrateOutput[:pos] + string(r) + app.CalibrateOutput[pos:]
		app.CalibrateEditCursor++
	}
}

func handleCollectBackspace(app *shared.AppState) {
	if !app.CollectEditing {
		return
	}
	switch app.CollectField {
	case collectFieldOutput:
		app.CollectOutput = trimLastRune(app.CollectOutput)
	}
}

func handleCollectEnter(app *shared.AppState) {
	switch app.CollectField {
	case collectFieldSource:
		if app.CollectActive {
			setWorkflowStatus(app, &app.CollectStatusText, &app.CollectStatusError, &app.CollectStatusUntil,
				"cannot change source while collection is running", false)
			return
		}
		refreshCollectSources(app)
		openCollectMenu(app, "source", "Select Source", app.CollectSourceOpts, findIndex(app.CollectSourceOpts, app.CollectSource))
	case collectFieldOutput:
		if app.CollectActive {
			setWorkflowStatus(app, &app.CollectStatusText, &app.CollectStatusError, &app.CollectStatusUntil,
				"cannot change output while collection is running", false)
			return
		}
		app.CollectEditing = !app.CollectEditing
	case collectFieldDuration:
		if app.CollectActive {
			setWorkflowStatus(app, &app.CollectStatusText, &app.CollectStatusError, &app.CollectStatusUntil,
				"cannot change duration while collection is running", false)
			return
		}
		openCollectMenu(app, "duration", "Select Duration", collectDurations, findIndex(collectDurations, app.CollectDurationStr))

	case collectFieldAction:
		if app.CollectActive {
			finalizeCollection(app)
			return
		}

		dur, err := time.ParseDuration(app.CollectDurationStr)
		if err != nil || dur <= 0 {
			setWorkflowStatus(app, &app.CollectStatusText, &app.CollectStatusError, &app.CollectStatusUntil,"collection failed: invalid duration", true)
			return
		}
		if strings.TrimSpace(app.CollectSource) == "" {
			setWorkflowStatus(app, &app.CollectStatusText, &app.CollectStatusError, &app.CollectStatusUntil,"collection failed: no source selected", true)
			return
		}
		if strings.TrimSpace(app.CollectOutput) == "" {
			setWorkflowStatus(app, &app.CollectStatusText, &app.CollectStatusError, &app.CollectStatusUntil,"collection failed: output path is required", true)
			return
		}

		app.CollectData = nil
		app.CollectActive = true
		app.CollectStartedAt = time.Now()
		app.CollectUntil = time.Now().Add(dur)
		app.CollectEditing = false
		setWorkflowStatus(app, &app.CollectStatusText, &app.CollectStatusError, &app.CollectStatusUntil,
			"collection started ("+dur.String()+", source: "+app.CollectSource+")", false)
	}
}

func openCollectMenu(app *shared.AppState, kind, title string, options []string, selected int) {
	openWorkflowMenu(kind, title, options, selected, &app.CollectShowHelp, &app.CollectShowMenu, &app.CollectMenuKind, &app.CollectMenuTitle, &app.CollectMenuOptions, &app.CollectMenuIndex)
}

func applyCollectMenuSelection(app *shared.AppState) {
	if len(app.CollectMenuOptions) == 0 {
		return
	}
	choice := app.CollectMenuOptions[clampChoice(app.CollectMenuIndex, len(app.CollectMenuOptions))]
	switch app.CollectMenuKind {
	case "source":
		app.CollectSource = choice
		app.CollectSourceIndex = findIndex(app.CollectSourceOpts, choice)
	case "duration":
		app.CollectDurationStr = choice
	}
}

func handleCollectRuneInput(app *shared.AppState, r rune) {
	if !app.CollectEditing || r < 32 || r > 126 {
		return
	}
	switch app.CollectField {
	case collectFieldOutput:
		app.CollectOutput += string(r)
	}
}

// --- workflow runtime (merged from ui_workflow_runtime.go) ---

func refreshCalibrationState(app *shared.AppState) {
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
	// Clamp to valid options if previously saved value is out of range.
	opts := calibration.DurationOptions()
	if findIndex(opts, app.CalibrateDuration) < 0 {
		app.CalibrateDuration = "5m"
	}
	if app.CalibrateOutput == "" {
		app.CalibrateOutput = calibration.DefaultOutputPath()
	}

	profiles, err := calibration.ListProfiles()
	if err != nil {
		setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil,"profile load failed: "+err.Error(), true)
		return
	}
	app.CalibrateProfiles = profiles

	if cfg, err := calibration.LoadActiveConfig(); err == nil {
		if strings.TrimSpace(cfg.Profile) != "" {
			app.CalibrateAppliedProfile = cfg.Profile
		}
	} else {
		setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil,"active profile load failed: "+err.Error(), true)
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
		setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil,"report load failed: "+err.Error(), true)
	}
}

// isActiveKeystoreSecure checks the registry to determine if the currently
// active keystore is hardware-encrypted.  This is more reliable than
// app.KeystoreSecure which can be stale.
func isActiveKeystoreSecure(app *shared.AppState) bool {
	if app.KeystoreActiveEntry == "" {
		return false
	}
	for _, e := range keystore.ListKeystores() {
		if e.Name == app.KeystoreActiveEntry {
			return e.Secure
		}
	}
	return false
}

func calibrationError(app *shared.AppState, msg string) {
	// Truncate to fit in one line — panel width minus padding/prefix.
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

func startCalibration(app *shared.AppState) {
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
		// If there's an active secure keystore that hasn't been decrypted
		// yet this attempt, try decrypting and retrying once.
		if !app.CalibrateDecryptAttempted && app.KeystoreActiveEntry != "" && app.KeystoreSecure {
			app.CalibrateDecryptAttempted = true
			if tryDecryptAndRun(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil, func() {
				startCalibration(app)
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
	setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil,"calibration collection started ("+dur.String()+", sample every "+app.CalibrateSampleEvery.String()+")", false)
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
		filter := shared.ParseRoleFilter(scope)
		if strings.EqualFold(strings.TrimSpace(scope), "recommended") {
			filter = shared.ParseRoleFilter("all")
		}

		// Prefer the main classifier's output (SnapshotCandidates) which has
		// full history context — session roles, strong evidence, and proper age
		// tracking. Fall back to a fresh snapshot classification when no live
		// candidates are available.
		liveCandidates := app.SnapshotCandidates
		if len(liveCandidates) == 0 {
			liveCandidates = app.Candidates
		}

		if len(liveCandidates) > 0 {
			for _, c := range liveCandidates {
				if len(filter) > 0 && !shared.RoleMatchesFilter(c.Role, filter) {
					continue
				}
				app.CalibrateSamples = append(app.CalibrateSamples, cloneCandidate(c))
			}
		} else if app.CalibrationCollect != nil {
			snap, err := app.CalibrationCollect()
			if err != nil {
				setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil, "calibration sample collection warning: "+err.Error(), true)
			} else {
				collected := calibration.SamplesFromSnapshot(snap, app.LocalHost, scope)
				for _, c := range collected {
					app.CalibrateSamples = append(app.CalibrateSamples, cloneCandidate(c))
				}
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
	setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil,"gpt analyzing...", false)
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
		calibrateCh <- calibrationExecResult{
			result: result,
			err:    err,
		}
	}()
}

func applyCalibrationExecResult(app *shared.AppState, res calibrationExecResult) {
	app.CalibrateCancel = nil
	app.CalibrateProgressLines = nil
	if res.err != nil {
		if errors.Is(res.err, context.Canceled) {
			setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil,"calibration canceled", false)
		} else {
			setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil,"calibration failed: "+res.err.Error(), true)
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
		setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil,"calibration report written: "+result.ReportPath, false)
	}
	app.CalibrateActive = false
	app.CalibrateAnalyzing = false
	app.CalibrateStartedAt = time.Time{}
	app.CalibrateLastSample = time.Time{}
	app.CalibrateSamples = nil
	app.CalibrateEditing = false
	// Clear secrets from runtime so a secure keystore must be
	// decrypted again for the next operation.
	if isActiveKeystoreSecure(app) {
		keystore.ClearSensitiveRuntime()
	}
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
		setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil,"apply failed: no profile selected", true)
		return
	}
	profile, err := calibration.ApplyProfile(profileName)
	if err != nil {
		setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil,"apply failed: "+err.Error(), true)
		return
	}
	app.CalibrateAppliedProfile = profile.Name
	app.CalibrateProfile = profile.Name
	setWorkflowStatus(app, &app.CalibrateStatusText, &app.CalibrateStatusError, &app.CalibrateStatusUntil,"applied profile: "+profile.Name, false)
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
		setWorkflowStatus(app, &app.ContourStatusText, &app.ContourStatusError, &app.ContourStatusUntil,"contour report load failed: "+err.Error(), true)
	}
}

func startContour(app *shared.AppState) {
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
	// Single mode: always Deep + Egress.
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
	setWorkflowStatus(app, &app.ContourStatusText, &app.ContourStatusError, &app.ContourStatusUntil,startMsg, false)
}

func stopContour(app *shared.AppState) {
	if app == nil || !app.ContourActive {
		return
	}
	if app.ContourAnalyzing {
		if app.ContourCancel != nil {
			app.ContourCancel()
		}
		setWorkflowStatus(app, &app.ContourStatusText, &app.ContourStatusError, &app.ContourStatusUntil,"stopping contour run...", false)
		return
	}
	app.ContourUntil = time.Now().Add(-time.Second)
	setWorkflowStatus(app, &app.ContourStatusText, &app.ContourStatusError, &app.ContourStatusUntil,"stopping collection, analyzing now...", false)
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
		setWorkflowStatus(app, &app.ContourStatusText, &app.ContourStatusError, &app.ContourStatusUntil,"listener active; waiting for contour checks...", false)
	} else {
		setWorkflowStatus(app, &app.ContourStatusText, &app.ContourStatusError, &app.ContourStatusUntil,"analyzing contour findings...", false)
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
		OnProgress: func(lines []string) {
			cp := make([]string, len(lines))
			copy(cp, lines)
			app.ProgressMu.Lock()
			app.ContourProgressLines = cp
			app.ProgressMu.Unlock()
		},
		OnPartial: func(report contour.Report) {
			cp := make([]string, len(report.ReportLines))
			copy(cp, report.ReportLines)
			app.ContourPartialReportLines = cp
			if report.Probe != nil {
				probeCopy := *report.Probe
				app.ContourPartialProbe = &probeCopy
			}
		},
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
	// Keep ContourProgressLines and ContourPartialProbe so the task list
	// and matrices remain visible in the completed report view.
	app.ContourPartialReportLines = nil
	if res.err != nil {
		if errors.Is(res.err, context.Canceled) {
			setWorkflowStatus(app, &app.ContourStatusText, &app.ContourStatusError, &app.ContourStatusUntil,"contour stopped.", false)
		} else {
			setWorkflowStatus(app, &app.ContourStatusText, &app.ContourStatusError, &app.ContourStatusUntil,"contour failed: "+res.err.Error(), true)
		}
	} else {
		result := res.result
		app.ContourOutput = result.ReportPath
		app.ContourReportPath = result.ReportPath
		app.ContourReportTime = result.Report.GeneratedAt
		app.ContourReportLines = append([]string(nil), result.Report.ReportLines...)
		reportCopy := result.Report
		app.ContourReport = &reportCopy
		app.ContourHints = cloneContourHints(result.Hints)
		app.ContourReportScroll = 0
		setWorkflowStatus(app, &app.ContourStatusText, &app.ContourStatusError, &app.ContourStatusUntil,"contour report written: "+result.ReportPath+" (hints exported "+strconv.Itoa(len(result.Hints))+")", false)
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

func cloneContourHints(hints []shared.ContourHint) []shared.ContourHint {
	if len(hints) == 0 {
		return nil
	}
	out := make([]shared.ContourHint, len(hints))
	copy(out, hints)
	return out
}
