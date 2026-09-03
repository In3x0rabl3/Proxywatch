package keys

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"proxywatch/internal/detection"
	"proxywatch/internal/detection/model"
	"proxywatch/internal/detection/telemetry"
	"proxywatch/internal/shared"

	"github.com/gdamore/tcell/v2"
)

func CycleInspectProcess(app *shared.AppState, dir int) {
	if len(app.Candidates) == 0 {
		return
	}
	candidates := app.Candidates
	if strings.TrimSpace(app.LocalHost) == "" && app.DashboardHostProcessView && app.DashboardHostKey != "" {
		filtered := make([]shared.Candidate, 0)
		for _, c := range app.Candidates {
			if strings.EqualFold(strings.TrimSpace(c.Host), app.DashboardHostKey) {
				filtered = append(filtered, c)
			}
		}
		if len(filtered) > 0 {
			candidates = filtered
		}
	}
	currentIdx := -1
	for i := range candidates {
		if shared.CandidateKey(candidates[i]) == app.InspectKey {
			currentIdx = i
			break
		}
	}
	next := currentIdx + dir
	if next < 0 {
		next = len(candidates) - 1
	}
	if next >= len(candidates) {
		next = 0
	}
	app.InspectKey = shared.CandidateKey(candidates[next])
	app.InspectScroll = 0
}

func HandleInspectKey(app *shared.AppState, tev *tcell.EventKey) bool {
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
		JumpInspectSection(app, 1)
	case tcell.KeyBacktab:
		JumpInspectSection(app, -1)
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
		HandleKillRequest(app, tev.Rune())
	}

	// 'p' — navigate to parent process in inspector.
	if tev.Rune() == 'p' || tev.Rune() == 'P' {
		for _, c := range app.Candidates {
			if shared.CandidateKey(c) == app.InspectKey && c.Proc != nil && c.Proc.ParentPid > 0 {
				parentKey := ""
				for _, pc := range app.Candidates {
					if pc.Proc != nil && pc.Proc.Pid == c.Proc.ParentPid {
						parentKey = shared.CandidateKey(pc)
						break
					}
				}
				if parentKey != "" {
					app.InspectKey = parentKey
					app.InspectScroll = 0
				}
				break
			}
		}
	}

	// 'x' — toggle show all signals in evidence.
	if tev.Rune() == 'x' || tev.Rune() == 'X' {
		app.InspectShowAllSignals = !app.InspectShowAllSignals
		// Invalidate evidence cache so it rebuilds.
		app.InspectEvidenceCacheKey = ""
		if app.InspectShowAllSignals {
			app.LastError = "Signal debug: ON — showing all signals"
		} else {
			app.LastError = "Signal debug: OFF"
		}
	}

	if tev.Rune() == 't' || tev.Rune() == 'T' {
		var cand *shared.Candidate
		for i := range app.Candidates {
			if shared.CandidateKey(app.Candidates[i]) == app.InspectKey {
				cand = &app.Candidates[i]
				break
			}
		}
		if cand != nil && cand.Proc != nil {
			key := detection.ProcessBehaviorKey(cand)
			current := model.GetTrainingLabel(key)
			labels := []string{"", "outbound", "listener", "beacon", "pivot"}
			nextIdx := 0
			for i, l := range labels {
				if l == current {
					nextIdx = (i + 1) % len(labels)
					break
				}
			}
			next := labels[nextIdx]
			ctx := BuildTrainingContext(cand)
			model.SetTrainingLabel(key, next, ctx)
			if next == "" {
				app.LastError = "Training label cleared for " + cand.Proc.Name
			} else {
				app.LastError = "Training label set: " + cand.Proc.Name + " → " + next
			}
		}
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

	// L / M / W — operator-label + whitelist shortcuts (plan Track 10).
	// L tags the inspected process as benign, M tags it malicious; both
	// are keyed by SHA256 so the label follows the binary across
	// process restarts. W adds the process to the whitelist and records
	// a model.FeedbackEntry so the learner sees the signal. All three
	// require a current selection; messaging goes through app.LastError.
	if tev.Rune() == 'l' || tev.Rune() == 'L' {
		LabelInspectedCandidate(app, shared.VerdictBenign)
	}
	if tev.Rune() == 'm' || tev.Rune() == 'M' {
		LabelInspectedCandidate(app, shared.VerdictMalicious)
	}
	if tev.Rune() == 'w' || tev.Rune() == 'W' {
		WhitelistInspectedCandidate(app)
	}

	return false
}

// LabelInspectedCandidate applies an operator verdict to the SHA256 of
// the currently-inspected candidate. Safe when no candidate is
// selected or the executable has no SHA256 yet (first-observation
// race — hashing is async).
func LabelInspectedCandidate(app *shared.AppState, verdict string) {
	cand := findInspectedCandidate(app)
	if cand == nil || cand.Proc == nil {
		app.LastError = "no candidate selected"
		return
	}
	sha := strings.TrimSpace(cand.Proc.SHA256)
	if sha == "" {
		app.LastError = "SHA256 not yet computed for " + cand.Proc.Name + " — try again in a second"
		return
	}
	reason := "operator TUI " + verdict
	if err := shared.SetOperatorLabel(sha, verdict, reason); err != nil {
		app.LastError = "label failed: " + err.Error()
		return
	}
	app.LastError = "Operator label " + verdict + " → " + cand.Proc.Name
}

// WhitelistInspectedCandidate adds the inspected candidate to the
// whitelist file and records the action as learner feedback, same as
// the dashboard's W shortcut but sourced from the InspectKey.
func WhitelistInspectedCandidate(app *shared.AppState) {
	if app.Whitelist == nil {
		app.LastError = "whitelist not configured"
		return
	}
	cand := findInspectedCandidate(app)
	if cand == nil || cand.Proc == nil {
		app.LastError = "no candidate selected to whitelist"
		return
	}
	if _, err := app.Whitelist.AddCandidate(*cand); err != nil {
		app.LastError = "whitelist failed: " + err.Error()
		return
	}
	model.RecordFeedback(model.FeedbackEntry{
		Timestamp:   time.Now().UTC(),
		Action:      "whitelist",
		ProcessKey:  detection.ProcessBehaviorKey(cand),
		ProcessName: cand.Proc.Name,
		Role:        cand.Role,
		Score:       cand.Score,
		Signals:     cand.Signals,
	})
	app.LastError = "Whitelisted " + cand.Proc.Name
}

// findInspectedCandidate returns a pointer into app.Candidates for the
// current InspectKey, or nil if the key is unknown.
func findInspectedCandidate(app *shared.AppState) *shared.Candidate {
	for i := range app.Candidates {
		if shared.CandidateKey(app.Candidates[i]) == app.InspectKey {
			return &app.Candidates[i]
		}
	}
	return nil
}

func inspectorMenuOptions() []string {
	return []string{
		"[Navigation]",
		"UP/DOWN      Scroll details",
		"TAB/BTAB     Jump sections",
		"LEFT/RIGHT   Cycle workflows",
		"p            Jump to parent process",
		"",
		"[Actions]",
		"x            Toggle explain view",
		"k            Kill process (k then y)",
		"t            Cycle training label",
		"l            Mark operator-label benign (by SHA256)",
		"m            Mark operator-label malicious (by SHA256)",
		"w            Whitelist this process",
		"",
		"?            Close this menu",
		"ESC          Back to dashboard",
		"q            Quit",
	}
}

func BuildTrainingContext(c *shared.Candidate) string {
	if c == nil || c.Proc == nil {
		return ""
	}
	var parts []string

	parts = append(parts, fmt.Sprintf("name=%s path=%s user=%s integrity=%s",
		c.Proc.Name, shared.NormalizeExePath(c.Proc.ExePath), c.Proc.UserName, c.Proc.Integrity))

	if c.OutTotal > 0 || c.InboundTotal > 0 {
		parts = append(parts, fmt.Sprintf("tcp=%din/%dout ext=%d int=%d",
			c.InboundTotal, c.OutTotal, c.OutExternal, c.OutInternal))
	}
	if c.ControlChannel != nil {
		parts = append(parts, fmt.Sprintf("control=%s:%d(%ds)",
			c.ControlChannel.RemoteAddress, c.ControlChannel.RemotePort, c.ControlDurationSeconds))
	}

	ioTotal := c.Proc.IOReadBytes + c.Proc.IOWriteBytes
	if ioTotal > 1024 {
		parts = append(parts, fmt.Sprintf("io=r:%s/w:%s",
			formatBytesCompact(c.Proc.IOReadBytes), formatBytesCompact(c.Proc.IOWriteBytes)))
	}

	if len(c.Signals) > 0 {
		n := len(c.Signals)
		if n > 8 {
			n = 8
		}
		parts = append(parts, fmt.Sprintf("signals=[%s]", strings.Join(c.Signals[:n], ",")))
	}

	parts = append(parts, fmt.Sprintf("role=%s score=%d", c.Role, c.Score))

	return strings.Join(parts, " | ")
}

func formatBytesCompact(b uint64) string {
	switch {
	case b >= 1024*1024*1024:
		return fmt.Sprintf("%.1fG", float64(b)/(1024*1024*1024))
	case b >= 1024*1024:
		return fmt.Sprintf("%.1fM", float64(b)/(1024*1024))
	case b >= 1024:
		return fmt.Sprintf("%.0fK", float64(b)/1024)
	default:
		return fmt.Sprintf("%dB", b)
	}
}

func JumpInspectSection(app *shared.AppState, dir int) {
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

func HandleKillRequest(app *shared.AppState, keyRune rune) {
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

	recordKillFeedback := func() {
		cand := app.Candidates[idx]
		model.RecordFeedback(model.FeedbackEntry{
			Timestamp:   time.Now().UTC(),
			Action:      "kill",
			ProcessKey:  detection.ProcessBehaviorKey(&cand),
			ProcessName: cand.Proc.Name,
			Role:        cand.Role,
			Score:       cand.Score,
			Signals:     cand.Signals,
		})
	}

	if app.LocalHost != "" && host == app.LocalHost {
		if err := telemetry.KillProcess(pid); err != nil {
			app.LastError = "Kill failed: " + err.Error()
		} else {
			app.LastError = "Killed PID " + strconv.Itoa(pid) + " (" + app.Candidates[idx].Proc.Name + ")"
			recordKillFeedback()
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
		recordKillFeedback()
	}
	app.ConfirmKillKey = ""
}

func HandleWhitelistKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if app.WhitelistShowHelp {
		return handleWhitelistOverlayKey(app, tev)
	}
	processCount := len(WhitelistProcessCandidates(app))

	switch tev.Key() {
	case tcell.KeyUp:
		switch app.WhitelistField {
		case WhitelistFieldProcess:
			if app.WhitelistProcessSelected > 0 {
				app.WhitelistProcessSelected--
			}
		case WhitelistFieldEntry:
			if app.WhitelistSelected > 0 {
				app.WhitelistSelected--
			}
		}
	case tcell.KeyDown:
		switch app.WhitelistField {
		case WhitelistFieldProcess:
			if app.WhitelistProcessSelected < processCount-1 {
				app.WhitelistProcessSelected++
			}
		case WhitelistFieldEntry:
			if app.WhitelistSelected < len(app.WhitelistItems)-1 {
				app.WhitelistSelected++
			}
		}
	case tcell.KeyPgUp:
		app.WhitelistField = WhitelistFieldProcess
	case tcell.KeyPgDn:
		app.WhitelistField = WhitelistFieldEntry
	case tcell.KeyTab:
		if app.WhitelistField == WhitelistFieldProcess {
			app.WhitelistField = WhitelistFieldEntry
		} else {
			app.WhitelistField = WhitelistFieldProcess
		}
	case tcell.KeyBacktab:
		if app.WhitelistField == WhitelistFieldEntry {
			app.WhitelistField = WhitelistFieldProcess
		} else {
			app.WhitelistField = WhitelistFieldEntry
		}
	case tcell.KeyEnter:
		switch app.WhitelistField {
		case WhitelistFieldProcess:
			WhitelistSelectedCandidate(app)
		case WhitelistFieldEntry:
			RemoveSelectedWhitelistEntry(app)
		}
	case tcell.KeyLeft:
		if StepWorkflowMenu(app, -1) {
			return false
		}
	case tcell.KeyRight:
		if StepWorkflowMenu(app, 1) {
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
		case WhitelistFieldProcess:
			if app.WhitelistProcessSelected >= 0 && app.WhitelistProcessSelected < processCount-1 {
				app.WhitelistProcessSelected++
			}
		case WhitelistFieldEntry:
			if app.WhitelistSelected >= 0 && app.WhitelistSelected < len(app.WhitelistItems)-1 {
				app.WhitelistSelected++
			}
		}
	}

	if tev.Rune() == '\'' {
		switch app.WhitelistField {
		case WhitelistFieldProcess:
			if app.WhitelistProcessSelected > 0 && app.WhitelistProcessSelected < processCount {
				app.WhitelistProcessSelected--
			}
		case WhitelistFieldEntry:
			if app.WhitelistSelected > 0 && app.WhitelistSelected < len(app.WhitelistItems) {
				app.WhitelistSelected--
			}
		}
	}

	if tev.Rune() == 'd' || tev.Rune() == 'D' || tev.Rune() == 'u' || tev.Rune() == 'U' || tev.Rune() == 'x' || tev.Rune() == 'X' {
		RemoveSelectedWhitelistEntry(app)
	}

	if tev.Rune() == 'w' || tev.Rune() == 'W' {
		app.Mode = shared.ModeDashboard
	}

	if app.WhitelistField < WhitelistFieldProcess {
		app.WhitelistField = WhitelistFieldProcess
	}
	if app.WhitelistField > WhitelistFieldMax {
		app.WhitelistField = WhitelistFieldMax
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

func RemoveSelectedWhitelistEntry(app *shared.AppState) {
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

func whitelistMenuHelpOptions() []string {
	return []string{
		"[Navigation]",
		"UP/DOWN      Navigate within panel",
		"PGUP         Switch to Processes",
		"PGDN         Switch to Whitelisted",
		"TAB          Toggle panels",
		"LEFT/RIGHT   Cycle workflows",
		"",
		"[Actions]",
		"ENTER        Add (processes) / Remove (whitelisted)",
		"",
		"?            Close this menu",
		"ESC          Back to dashboard",
		"q            Quit",
	}
}
