package ui

import (
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

	if tev.Rune() == 'x' || tev.Rune() == 'X' {
		app.InspectExplain = !app.InspectExplain
	}

	if tev.Rune() == 'k' || tev.Rune() == 'K' || tev.Rune() == 'y' || tev.Rune() == 'Y' {
		handleKillRequest(app, tev.Rune())
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
		if app.WhitelistField > whitelistFieldProcess {
			app.WhitelistField--
		} else {
			app.WhitelistField = whitelistFieldMax
		}
	case tcell.KeyDown:
		if app.WhitelistField < whitelistFieldMax {
			app.WhitelistField++
		} else {
			app.WhitelistField = whitelistFieldProcess
		}
	case tcell.KeyLeft:
		if app.WhitelistField == whitelistFieldProcess && app.WhitelistProcessSelected > 0 && app.WhitelistProcessSelected < processCount {
			app.WhitelistProcessSelected--
		}
		if app.WhitelistField == whitelistFieldEntry && app.WhitelistSelected > 0 && app.WhitelistSelected < len(app.WhitelistItems) {
			app.WhitelistSelected--
		}
	case tcell.KeyRight:
		if app.WhitelistField == whitelistFieldProcess && app.WhitelistProcessSelected >= 0 && app.WhitelistProcessSelected < processCount-1 {
			app.WhitelistProcessSelected++
		}
		if app.WhitelistField == whitelistFieldEntry && app.WhitelistSelected >= 0 && app.WhitelistSelected < len(app.WhitelistItems)-1 {
			app.WhitelistSelected++
		}
	case tcell.KeyPgUp:
		switch app.WhitelistField {
		case whitelistFieldProcess:
			app.WhitelistProcessSelected -= 8
			if app.WhitelistProcessSelected < 0 {
				app.WhitelistProcessSelected = 0
			}
		case whitelistFieldEntry:
			app.WhitelistSelected -= 8
			if app.WhitelistSelected < 0 {
				app.WhitelistSelected = 0
			}
		}
	case tcell.KeyPgDn:
		switch app.WhitelistField {
		case whitelistFieldProcess:
			app.WhitelistProcessSelected += 8
			if app.WhitelistProcessSelected >= processCount {
				app.WhitelistProcessSelected = max(0, processCount-1)
			}
		case whitelistFieldEntry:
			app.WhitelistSelected += 8
			if app.WhitelistSelected >= len(app.WhitelistItems) {
				app.WhitelistSelected = max(0, len(app.WhitelistItems)-1)
			}
		}
	case tcell.KeyTab:
		if app.WhitelistField < whitelistFieldMax {
			app.WhitelistField++
		} else {
			app.WhitelistField = whitelistFieldProcess
		}
	case tcell.KeyBacktab:
		if app.WhitelistField > whitelistFieldProcess {
			app.WhitelistField--
		} else {
			app.WhitelistField = whitelistFieldMax
		}
	case tcell.KeyEnter:
		switch app.WhitelistField {
		case whitelistFieldProcess:
			whitelistSelectedCandidate(app)
		case whitelistFieldEntry, whitelistFieldRemove:
			removeSelectedWhitelistEntry(app)
		case whitelistFieldAdd:
			whitelistSelectedCandidate(app)
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

	if tev.Rune() == 'a' || tev.Rune() == 'A' {
		whitelistSelectedCandidate(app)
	}

	if tev.Rune() == 'j' || tev.Rune() == 'J' {
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

	if tev.Rune() == 'k' || tev.Rune() == 'K' {
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
		if app.CollectField > collectFieldSource {
			app.CollectField--
		} else {
			app.CollectField = collectFieldMax
		}
	case tcell.KeyDown:
		if app.CollectField < collectFieldMax {
			app.CollectField++
		} else {
			app.CollectField = collectFieldSource
		}
	case tcell.KeyLeft:
		if app.CollectField == collectFieldSource && !app.CollectActive {
			refreshCollectSources(app)
			app.CollectSource = stepOption(app.CollectSourceOpts, app.CollectSource, -1)
			app.CollectSourceIndex = findIndex(app.CollectSourceOpts, app.CollectSource)
		}
		if app.CollectField == collectFieldDuration && !app.CollectActive {
			app.CollectDurationStr = stepDuration(app.CollectDurationStr, -1)
		}
	case tcell.KeyRight:
		if app.CollectField == collectFieldSource && !app.CollectActive {
			refreshCollectSources(app)
			app.CollectSource = stepOption(app.CollectSourceOpts, app.CollectSource, 1)
			app.CollectSourceIndex = findIndex(app.CollectSourceOpts, app.CollectSource)
		}
		if app.CollectField == collectFieldDuration && !app.CollectActive {
			app.CollectDurationStr = stepDuration(app.CollectDurationStr, 1)
		}
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
	if tev.Rune() == 'q' {
		return requestQuit(app)
	}
	if tev.Rune() == '?' {
		if app.CollectShowHelp {
			app.CollectShowHelp = false
		} else {
			app.CollectShowMenu = false
			app.CollectShowHelp = true
			app.CollectHelpIndex = 0
		}
		return false
	}
	if tev.Key() == tcell.KeyEscape {
		if app.CollectShowHelp {
			app.CollectShowHelp = false
		} else {
			app.CollectShowMenu = false
		}
		return false
	}
	if app.CollectShowHelp {
		maxIdx := len(collectMenuHelpOptions()) - 1
		switch tev.Key() {
		case tcell.KeyUp:
			if app.CollectHelpIndex > 0 {
				app.CollectHelpIndex--
			}
		case tcell.KeyDown:
			if app.CollectHelpIndex < max(0, maxIdx) {
				app.CollectHelpIndex++
			}
		}
		return false
	}
	if !app.CollectShowMenu || len(app.CollectMenuOptions) == 0 {
		return false
	}
	switch tev.Key() {
	case tcell.KeyUp:
		if app.CollectMenuIndex > 0 {
			app.CollectMenuIndex--
		}
	case tcell.KeyDown:
		if app.CollectMenuIndex < len(app.CollectMenuOptions)-1 {
			app.CollectMenuIndex++
		}
	case tcell.KeyEnter:
		applyCollectMenuSelection(app)
		app.CollectShowMenu = false
	}
	return false
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
	case tcell.KeyLeft:
		if !app.ContourEditing {
			stepContourField(app, -1)
		}
	case tcell.KeyRight:
		if !app.ContourEditing {
			stepContourField(app, 1)
		}
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
	case tcell.KeyPgUp:
		scrollContourReport(app, -8)
	case tcell.KeyPgDn:
		scrollContourReport(app, 8)
	case tcell.KeyHome:
		app.ContourReportScroll = 0
	case tcell.KeyEnd:
		app.ContourReportScroll = app.ContourReportMaxScroll
	}

	switch tev.Rune() {
	case 'j', 'J':
		scrollContourReport(app, 1)
		return false
	case 'k', 'K':
		scrollContourReport(app, -1)
		return false
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
	if tev.Rune() == 'q' {
		return requestQuit(app)
	}
	if tev.Rune() == '?' {
		if app.ContourShowHelp {
			app.ContourShowHelp = false
		} else {
			app.ContourShowMenu = false
			app.ContourShowHelp = true
			app.ContourHelpIndex = 0
		}
		return false
	}
	if tev.Key() == tcell.KeyEscape {
		if app.ContourShowHelp {
			app.ContourShowHelp = false
		} else {
			app.ContourShowMenu = false
		}
		return false
	}
	if app.ContourShowHelp {
		maxIdx := len(contourMenuHelpOptions()) - 1
		switch tev.Key() {
		case tcell.KeyUp:
			if app.ContourHelpIndex > 0 {
				app.ContourHelpIndex--
			}
		case tcell.KeyDown:
			if app.ContourHelpIndex < max(0, maxIdx) {
				app.ContourHelpIndex++
			}
		}
		return false
	}
	if !app.ContourShowMenu || len(app.ContourMenuOptions) == 0 {
		return false
	}
	switch tev.Key() {
	case tcell.KeyUp:
		if app.ContourMenuIndex > 0 {
			app.ContourMenuIndex--
		}
	case tcell.KeyDown:
		if app.ContourMenuIndex < len(app.ContourMenuOptions)-1 {
			app.ContourMenuIndex++
		}
	case tcell.KeyEnter:
		applyContourMenuSelection(app)
		app.ContourShowMenu = false
	}
	return false
}

func openContourMenu(app *shared.AppState, kind, title string, options []string, selected int) {
	if len(options) == 0 {
		return
	}
	app.ContourShowMenu = true
	app.ContourMenuKind = kind
	app.ContourMenuTitle = title
	app.ContourMenuOptions = options
	if selected < 0 {
		selected = 0
	}
	if selected >= len(options) {
		selected = len(options) - 1
	}
	app.ContourMenuIndex = selected
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
		mode := contour.NormalizeProbeMode(choice)
		options := contourProbeModeOptionsForRole(app.ContourProbeRole)
		if len(options) == 0 {
			options = contour.ProbeModeOptions()
		}
		if findIndex(options, mode) < 0 {
			mode = options[0]
		}
		app.ContourProbeMode = mode
	case "probe-role":
		role := contour.NormalizeProbeRole(choice)
		app.ContourProbeRole = role
		app.ContourProbeMode = contourNormalizeProbeModeForRole(app.ContourProbeMode, role)
	}
	normalizeContourFieldSelection(app)
}

func contourProbeModeOptionsForRole(role string) []string {
	switch contour.NormalizeProbeRole(role) {
	case contour.ProbeRoleScan:
		return []string{contour.ProbeModeSweep, contour.ProbeModeOff}
	case contour.ProbeRoleListen:
		return []string{contour.ProbeModeChecks}
	default:
		return []string{contour.ProbeModeChecks, contour.ProbeModeOff}
	}
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

func stepContourField(app *shared.AppState, dir int) {
	if dir == 0 || app.ContourActive || app.ContourAnalyzing {
		return
	}
	if !contourFieldVisible(app, app.ContourField) {
		return
	}
	switch app.ContourField {
	case contourFieldDuration:
		app.ContourDuration = stepOption(contour.DurationOptions(), app.ContourDuration, dir)
	case contourFieldProbeMode:
		opts := contourProbeModeOptionsForRole(app.ContourProbeRole)
		if len(opts) == 0 {
			opts = contour.ProbeModeOptions()
		}
		app.ContourProbeMode = contourNormalizeProbeModeForRole(stepOption(opts, app.ContourProbeMode, dir), app.ContourProbeRole)
	case contourFieldProbeRole:
		nextRole := contour.NormalizeProbeRole(stepOption(contour.ProbeRoleOptions(), app.ContourProbeRole, dir))
		app.ContourProbeRole = nextRole
		app.ContourProbeMode = contourNormalizeProbeModeForRole(app.ContourProbeMode, nextRole)
	}
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
		opts := contourProbeModeOptionsForRole(app.ContourProbeRole)
		if len(opts) == 0 {
			opts = contour.ProbeModeOptions()
		}
		current := contourNormalizeProbeModeForRole(app.ContourProbeMode, app.ContourProbeRole)
		app.ContourProbeMode = current
		openContourMenu(app, "probe-mode", "Select Probe Mode", opts, findIndex(opts, current))
	case contourFieldProbeRole:
		if app.ContourActive || app.ContourAnalyzing {
			return
		}
		opts := contour.ProbeRoleOptions()
		openContourMenu(app, "probe-role", "Select Probe Role", opts, findIndex(opts, contour.NormalizeProbeRole(app.ContourProbeRole)))
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
	if field == contourFieldDuration {
		return false
	}
	if field == contourFieldProbeMode && contour.NormalizeProbeRole(app.ContourProbeRole) == contour.ProbeRoleListen {
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
		if app.SIEMField > siemFieldSourceReport {
			app.SIEMField--
		} else {
			app.SIEMField = siemFieldMax
		}
	case tcell.KeyDown:
		if app.SIEMField < siemFieldMax {
			app.SIEMField++
		} else {
			app.SIEMField = siemFieldSourceReport
		}
	case tcell.KeyLeft:
		if !app.SIEMEditing {
			stepSIEMField(app, -1)
		}
	case tcell.KeyRight:
		if !app.SIEMEditing {
			stepSIEMField(app, 1)
		}
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
			scrollSIEMReport(app, -8)
		}
	case tcell.KeyPgDn:
		if !app.SIEMEditing {
			scrollSIEMReport(app, 8)
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
		case 'j', 'J':
			scrollSIEMReport(app, 1)
			return false
		case 'k', 'K':
			scrollSIEMReport(app, -1)
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
		if app.CalibrateField > calibrateFieldProvider {
			app.CalibrateField--
		} else {
			app.CalibrateField = calibrateFieldMax
		}
	case tcell.KeyDown:
		if app.CalibrateField < calibrateFieldMax {
			app.CalibrateField++
		} else {
			app.CalibrateField = calibrateFieldProvider
		}
	case tcell.KeyTab:
		if app.CalibrateField < calibrateFieldMax {
			app.CalibrateField++
		} else {
			app.CalibrateField = calibrateFieldProvider
		}
	case tcell.KeyBacktab:
		if app.CalibrateField > calibrateFieldProvider {
			app.CalibrateField--
		} else {
			app.CalibrateField = calibrateFieldMax
		}
	case tcell.KeyLeft:
		if !app.CalibrateEditing {
			stepCalibrationField(app, -1)
		}
	case tcell.KeyRight:
		if !app.CalibrateEditing {
			stepCalibrationField(app, 1)
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
		scrollCalibrationReport(app, -8)
	case tcell.KeyPgDn:
		scrollCalibrationReport(app, 8)
	case tcell.KeyHome:
		app.CalibrateReportScroll = 0
	case tcell.KeyEnd:
		app.CalibrateReportScroll = app.CalibrateReportMaxScroll
	}

	switch tev.Rune() {
	case 'j', 'J':
		scrollCalibrationReport(app, 1)
		return false
	case 'k', 'K':
		scrollCalibrationReport(app, -1)
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

func scrollCalibrationReport(app *shared.AppState, delta int) bool {
	if delta == 0 || app == nil || app.CalibrateReportMaxScroll <= 0 {
		return false
	}
	before := app.CalibrateReportScroll
	app.CalibrateReportScroll += delta
	if app.CalibrateReportScroll < 0 {
		app.CalibrateReportScroll = 0
	}
	if app.CalibrateReportScroll > app.CalibrateReportMaxScroll {
		app.CalibrateReportScroll = app.CalibrateReportMaxScroll
	}
	return app.CalibrateReportScroll != before
}

func scrollSIEMReport(app *shared.AppState, delta int) bool {
	if delta == 0 || app == nil || app.SIEMReportMaxScroll <= 0 {
		return false
	}
	before := app.SIEMReportScroll
	app.SIEMReportScroll += delta
	if app.SIEMReportScroll < 0 {
		app.SIEMReportScroll = 0
	}
	if app.SIEMReportScroll > app.SIEMReportMaxScroll {
		app.SIEMReportScroll = app.SIEMReportMaxScroll
	}
	return app.SIEMReportScroll != before
}

func scrollContourReport(app *shared.AppState, delta int) bool {
	if delta == 0 || app == nil || app.ContourReportMaxScroll <= 0 {
		return false
	}
	before := app.ContourReportScroll
	app.ContourReportScroll += delta
	if app.ContourReportScroll < 0 {
		app.ContourReportScroll = 0
	}
	if app.ContourReportScroll > app.ContourReportMaxScroll {
		app.ContourReportScroll = app.ContourReportMaxScroll
	}
	return app.ContourReportScroll != before
}

func handleKeystoreKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if app.KeystoreShowHelp {
		return handleKeystoreOverlayKey(app, tev)
	}
	switch tev.Key() {
	case tcell.KeyUp:
		if app.KeystoreField > keystoreFieldOpenAIKey {
			app.KeystoreField--
		} else {
			app.KeystoreField = keystoreFieldMax
		}
	case tcell.KeyDown:
		if app.KeystoreField < keystoreFieldMax {
			app.KeystoreField++
		} else {
			app.KeystoreField = keystoreFieldOpenAIKey
		}
	case tcell.KeyBackspace, tcell.KeyBackspace2:
		handleKeystoreBackspace(app)
	case tcell.KeyEnter:
		handleKeystoreEnter(app)
	case tcell.KeyEscape:
		if app.KeystoreEditing {
			app.KeystoreEditing = false
		} else {
			app.Mode = shared.ModeDashboard
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
			setSIEMStatus(app, "no calibration reports found; run Calibrate from this menu", true)
			return
		}
		openSIEMMenu(app, "source-report", "Select Source Report", app.SIEMSourceReports, findIndex(app.SIEMSourceReports, app.SIEMSourceReport))
	case siemFieldProvider:
		stepSIEMField(app, 1)
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
	if tev.Rune() == 'q' {
		return requestQuit(app)
	}
	if tev.Rune() == '?' {
		if app.SIEMShowHelp {
			app.SIEMShowHelp = false
		} else {
			app.SIEMShowMenu = false
			app.SIEMShowHelp = true
			app.SIEMHelpIndex = 0
		}
		return false
	}
	if tev.Key() == tcell.KeyEscape {
		if app.SIEMShowHelp {
			app.SIEMShowHelp = false
		} else {
			app.SIEMShowMenu = false
		}
		return false
	}
	if app.SIEMShowHelp {
		maxIdx := len(siemMenuHelpOptions()) - 1
		switch tev.Key() {
		case tcell.KeyUp:
			if app.SIEMHelpIndex > 0 {
				app.SIEMHelpIndex--
			}
		case tcell.KeyDown:
			if app.SIEMHelpIndex < max(0, maxIdx) {
				app.SIEMHelpIndex++
			}
		}
		return false
	}
	if !app.SIEMShowMenu || len(app.SIEMMenuOptions) == 0 {
		return false
	}
	switch tev.Key() {
	case tcell.KeyUp:
		if app.SIEMMenuIndex > 0 {
			app.SIEMMenuIndex--
		}
	case tcell.KeyDown:
		if app.SIEMMenuIndex < len(app.SIEMMenuOptions)-1 {
			app.SIEMMenuIndex++
		}
	case tcell.KeyEnter:
		applySIEMMenuSelection(app)
		app.SIEMShowMenu = false
	}
	return false
}

func openSIEMMenu(app *shared.AppState, kind, title string, options []string, selected int) {
	if len(options) == 0 {
		return
	}
	app.SIEMShowMenu = true
	app.SIEMMenuKind = kind
	app.SIEMMenuTitle = title
	app.SIEMMenuOptions = options
	if selected < 0 {
		selected = 0
	}
	if selected >= len(options) {
		selected = len(options) - 1
	}
	app.SIEMMenuIndex = selected
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
		setSIEMStatus(app, "apply failed: "+err.Error(), true)
		return
	}
	if save {
		if err := keystore.Save(app.KeystorePath, app.KeystoreValues); err != nil {
			setSIEMStatus(app, "save failed: "+err.Error(), true)
			return
		}
		setSIEMStatus(app, "SIEM paths saved to keystore and applied", false)
		return
	}
	setSIEMStatus(app, "SIEM paths applied to runtime", false)
}

func applySIEMGenerationSettings(app *shared.AppState, save bool) {
	ensureKeystoreValues(app)
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

	app.KeystoreValues["PROXYWATCH_SIEM_SOURCE_REPORT"] = app.SIEMSourceReport
	app.KeystoreValues["PROXYWATCH_SIEM_PROVIDER"] = app.SIEMProvider
	app.KeystoreValues["PROXYWATCH_SIEM_MODEL"] = app.SIEMModel
	app.KeystoreValues["PROXYWATCH_SIEM_REPORT_OUTPUT"] = app.SIEMReportPath
	app.KeystoreValues["PROXYWATCH_SIEM_JSON_OUTPUT"] = app.SIEMExportPath
	keystore.ApplyToRuntime(app.KeystoreValues)

	if save {
		if err := keystore.Save(app.KeystorePath, app.KeystoreValues); err != nil {
			setSIEMStatus(app, "save failed: "+err.Error(), true)
			return
		}
		setSIEMStatus(app, "SIEM generation settings saved to keystore", false)
		return
	}
	setSIEMStatus(app, "SIEM generation settings applied to runtime", false)
}

func runSIEMGeneration(app *shared.AppState) {
	if app.SIEMGenerating {
		setSIEMStatus(app, "SIEM generation already in progress", false)
		return
	}
	refreshSIEMSourceReports(app)
	if strings.TrimSpace(app.SIEMSourceReport) == "" {
		setSIEMStatus(app, "siem generation failed: no calibration report selected (run Calibrate first)", true)
		return
	}
	applySIEMGenerationSettings(app, false)
	app.SIEMGenerating = true
	app.SIEMStartedAt = time.Now()
	app.SIEMShowMenu = false
	app.SIEMEditing = false
	setSIEMStatus(app, "SIEM generation started", false)
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
	}
	result, err := siem.ExecuteSIEM(input)
	applySIEMExecResult(app, siemExecResult{result: result, err: err})
}

func applySIEMExecResult(app *shared.AppState, res siemExecResult) {
	app.SIEMGenerating = false
	app.SIEMStartedAt = time.Time{}
	if res.err != nil {
		setSIEMStatus(app, "siem generation failed: "+res.err.Error(), true)
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
	setSIEMStatus(app, fmt.Sprintf("SIEM %s output written: report=%s json=%s detections=%d", result.Mode, result.ReportPath, result.JSONPath, result.DetectionCount), false)
}

func stepSIEMField(app *shared.AppState, dir int) {
	if dir == 0 {
		return
	}
	switch app.SIEMField {
	case siemFieldSourceReport:
		refreshSIEMSourceReports(app)
		if len(app.SIEMSourceReports) == 0 {
			setSIEMStatus(app, "no calibration reports found; run Calibrate from this menu", true)
			return
		}
		next := stepOption(app.SIEMSourceReports, app.SIEMSourceReport, dir)
		app.SIEMSourceReport = next
		app.SIEMSourceIndex = findIndex(app.SIEMSourceReports, next)
	case siemFieldProvider:
		opts := calibration.Providers()
		current := calibration.ProviderLabel(app.SIEMProvider)
		next := stepOption(opts, current, dir)
		app.SIEMProvider = calibration.ProviderKey(next)
		modelOpts := calibration.ModelOptions(app.SIEMProvider)
		if !containsString(modelOpts, app.SIEMModel) {
			app.SIEMModel = calibration.DefaultModel(app.SIEMProvider)
		}
	case siemFieldModel:
		app.SIEMModel = stepOption(calibration.ModelOptions(app.SIEMProvider), app.SIEMModel, dir)
	}
}

func siemFieldEditable(field int) bool {
	switch field {
	case siemFieldModel, siemFieldReportOutput, siemFieldJSONOutput, siemFieldDebugLog, siemFieldRulesJSON:
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
		setSIEMStatus(app, "calibration report list failed: "+err.Error(), true)
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
		setCalibrationStatus(app, "calibration already running", false)
		return
	}
	duration := strings.TrimSpace(app.CalibrateDuration)
	if duration == "" || !containsString(calibration.DurationOptions(), duration) {
		app.CalibrateDuration = "30s"
	}
	startCalibration(app)
}

func setSIEMStatus(app *shared.AppState, msg string, isError bool) {
	app.LastError = msg
	app.SIEMStatusText = msg
	app.SIEMStatusError = isError
	now := time.Now()
	if isError {
		app.SIEMStatusUntil = now.Add(10 * time.Second)
		return
	}
	app.SIEMStatusUntil = now.Add(5 * time.Second)
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
}

func handleKeystoreEnter(app *shared.AppState) {
	switch app.KeystoreField {
	case keystoreFieldLoad:
		loadKeystore(app)
	case keystoreFieldSave:
		saveKeystore(app)
	case keystoreFieldApply:
		applyKeystore(app)
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
}

func loadKeystore(app *shared.AppState) {
	values, err := keystore.Load(app.KeystorePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			setKeystoreStatus(app, "keystore not found; save to create "+keystore.NormalizePath(app.KeystorePath), true)
			return
		}
		setKeystoreStatus(app, "load failed: "+err.Error(), true)
		return
	}
	app.KeystoreValues = values
	keystore.ApplyToRuntime(values)
	if err := applyDetectionOutputRuntimeConfig(); err != nil {
		setKeystoreStatus(app, "load failed: "+err.Error(), true)
		return
	}
	app.KeystoreUnlocked = true
	app.KeystoreEditing = false
	setKeystoreStatus(app, "keystore loaded and applied to runtime config", false)
}

func saveKeystore(app *shared.AppState) {
	ensureKeystoreValues(app)
	if err := keystore.Save(app.KeystorePath, app.KeystoreValues); err != nil {
		setKeystoreStatus(app, "save failed: "+err.Error(), true)
		return
	}
	keystore.ApplyToRuntime(app.KeystoreValues)
	if err := applyDetectionOutputRuntimeConfig(); err != nil {
		setKeystoreStatus(app, "save failed: "+err.Error(), true)
		return
	}
	app.KeystoreUnlocked = true
	app.KeystoreEditing = false
	setKeystoreStatus(app, "keystore saved (encrypted) and applied to runtime config", false)
}

func applyKeystore(app *shared.AppState) {
	ensureKeystoreValues(app)
	keystore.ApplyToRuntime(app.KeystoreValues)
	if err := applyDetectionOutputRuntimeConfig(); err != nil {
		setKeystoreStatus(app, "apply failed: "+err.Error(), true)
		return
	}
	setKeystoreStatus(app, "runtime config updated from keystore values", false)
}

func applyDetectionOutputRuntimeConfig() error {
	debugOutputPath := keystore.RuntimeValue("PROXYWATCH_DETECT_DEBUG_LOG")
	defenderOutputPath := keystore.RuntimeValue("PROXYWATCH_DETECT_RULES_JSON")
	return classifier.ConfigureDetectionOutputs(debugOutputPath, defenderOutputPath)
}

func ensureKeystoreValues(app *shared.AppState) {
	if app.KeystoreValues != nil {
		return
	}
	app.KeystoreValues = keystore.ValuesFromRuntime()
}

func setKeystoreStatus(app *shared.AppState, msg string, isError bool) {
	app.LastError = msg
	app.KeystoreStatusText = msg
	app.KeystoreStatusError = isError
	now := time.Now()
	if isError {
		app.KeystoreStatusUntil = now.Add(10 * time.Second)
		return
	}
	app.KeystoreStatusUntil = now.Add(5 * time.Second)
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
	if tev.Rune() == 'q' {
		return requestQuit(app)
	}
	if tev.Key() == tcell.KeyEscape {
		app.ShowCalibrateHelp = false
		app.ShowCalibrateMenu = false
		return false
	}

	if tev.Rune() == '?' {
		if app.ShowCalibrateHelp {
			app.ShowCalibrateHelp = false
		} else {
			app.ShowCalibrateMenu = false
			app.ShowCalibrateHelp = true
			app.CalibrateHelpIndex = 0
		}
		return false
	}

	if app.ShowCalibrateHelp {
		maxIdx := len(calibrationMenuHelpOptions()) - 1
		switch tev.Key() {
		case tcell.KeyUp:
			if app.CalibrateHelpIndex > 0 {
				app.CalibrateHelpIndex--
			}
		case tcell.KeyDown:
			if app.CalibrateHelpIndex < max(0, maxIdx) {
				app.CalibrateHelpIndex++
			}
		}
		return false
	}

	if !app.ShowCalibrateMenu {
		return false
	}
	switch tev.Key() {
	case tcell.KeyUp:
		if app.CalibrateMenuIndex > 0 {
			app.CalibrateMenuIndex--
		}
	case tcell.KeyDown:
		if app.CalibrateMenuIndex < len(app.CalibrateMenuOptions)-1 {
			app.CalibrateMenuIndex++
		}
	case tcell.KeyEnter:
		applyCalibrationMenuSelection(app)
		app.ShowCalibrateMenu = false
	}
	return false
}

func openCalibrationMenu(app *shared.AppState, kind, title string, options []string, selected int) {
	if len(options) == 0 {
		return
	}
	app.ShowCalibrateHelp = false
	app.ShowCalibrateMenu = true
	app.CalibrateMenuKind = kind
	app.CalibrateMenuTitle = title
	app.CalibrateMenuOptions = options
	if selected < 0 {
		selected = 0
	}
	if selected >= len(options) {
		selected = len(options) - 1
	}
	app.CalibrateMenuIndex = selected
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

func stepCalibrationField(app *shared.AppState, dir int) {
	if dir == 0 || app.CalibrateActive {
		return
	}
	switch app.CalibrateField {
	case calibrateFieldProvider:
		opts := calibration.Providers()
		current := calibration.ProviderLabel(app.CalibrateProvider)
		next := stepOption(opts, current, dir)
		app.CalibrateProvider = calibration.ProviderKey(next)
		modelOpts := calibration.ModelOptions(app.CalibrateProvider)
		if !containsString(modelOpts, app.CalibrateModel) {
			app.CalibrateModel = calibration.DefaultModel(app.CalibrateProvider)
		}
	case calibrateFieldDuration:
		app.CalibrateDuration = stepOption(calibration.DurationOptions(), app.CalibrateDuration, dir)
	case calibrateFieldModel:
		app.CalibrateModel = stepOption(calibration.ModelOptions(app.CalibrateProvider), app.CalibrateModel, dir)
	case calibrateFieldProfile:
		if len(app.CalibrateProfiles) == 0 {
			return
		}
		next := stepOption(app.CalibrateProfiles, app.CalibrateProfile, dir)
		app.CalibrateProfile = next
		app.CalibrateProfileIndex = findIndex(app.CalibrateProfiles, next)
	}
}

func handleCalibrationBackspace(app *shared.AppState) {
	if !app.CalibrateEditing {
		return
	}
	switch app.CalibrateField {
	case calibrateFieldOutput:
		app.CalibrateOutput = trimLastRune(app.CalibrateOutput)
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
			setCalibrationStatus(app, "no saved calibration profiles yet", true)
			return
		}
		openCalibrationMenu(app, "profile", "Select Profile", app.CalibrateProfiles, findIndex(app.CalibrateProfiles, app.CalibrateProfile))
	case calibrateFieldAction:
		if app.CalibrateActive {
			if app.CalibrateAnalyzing {
				if app.CalibrateCancel != nil {
					app.CalibrateCancel()
					setCalibrationStatus(app, "canceling calibration analysis...", false)
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
		app.CalibrateOutput += string(r)
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
			return
		}
		refreshCollectSources(app)
		openCollectMenu(app, "source", "Select Source", app.CollectSourceOpts, findIndex(app.CollectSourceOpts, app.CollectSource))
	case collectFieldOutput:
		if app.CollectActive {
			return
		}
		app.CollectEditing = !app.CollectEditing
	case collectFieldDuration:
		if app.CollectActive {
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
			setCollectStatus(app, "collection failed: invalid duration", true)
			return
		}

		app.CollectData = nil
		app.CollectActive = true
		app.CollectStartedAt = time.Now()
		app.CollectUntil = time.Now().Add(dur)
		app.CollectEditing = false
	}
}

func openCollectMenu(app *shared.AppState, kind, title string, options []string, selected int) {
	if len(options) == 0 {
		return
	}
	app.CollectShowMenu = true
	app.CollectMenuKind = kind
	app.CollectMenuTitle = title
	app.CollectMenuOptions = options
	if selected < 0 {
		selected = 0
	}
	if selected >= len(options) {
		selected = len(options) - 1
	}
	app.CollectMenuIndex = selected
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
