package ui

import (
	"strconv"
	"time"

	"proxywatch/internal/shared"
	"proxywatch/internal/telemetry"

	"github.com/gdamore/tcell/v2"
)

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
	if app.RefreshInt <= 0 {
		app.RefreshInt = 1 * time.Second
	}
	if app.ConfirmKillTimeout <= 0 {
		app.ConfirmKillTimeout = 3 * time.Second
	}
	app.SelectedIdx = -1
	app.Mode = shared.ModeDashboard

	scanner.Refresh(app)

	events := make(chan tcell.Event, 16)
	go func() {
		for {
			events <- s.PollEvent()
		}
	}()

	type refreshResult struct {
		candidates          []shared.Candidate
		lastError           string
		lastUpdate          time.Time
		selectedKey         string
		selectedIdx         int
		selectionKeyAtStart string
	}

	refreshCh := make(chan refreshResult, 1)
	refreshInFlight := false
	startRefresh := func() {
		if refreshInFlight {
			return
		}
		refreshInFlight = true
		selectionKeyAtStart := app.SelectedKey
		go func() {
			tmp := *app
			tmp.Screen = nil
			scanner.Refresh(&tmp)
			refreshCh <- refreshResult{
				candidates:          tmp.Candidates,
				lastError:           tmp.LastError,
				lastUpdate:          tmp.LastUpdate,
				selectedKey:         tmp.SelectedKey,
				selectedIdx:         tmp.SelectedIdx,
				selectionKeyAtStart: selectionKeyAtStart,
			}
		}()
	}

	tick := time.NewTicker(app.RefreshInt)
	defer tick.Stop()

	for {
		if app.ConfirmKillKey != "" && time.Now().After(app.ConfirmKillDeadline) {
			app.ConfirmKillKey = ""
		}

		switch app.Mode {
		case shared.ModeDashboard:
			DrawDashboard(app)
		case shared.ModeInspect:
			DrawInspector(app)
		}
		s.Show()

		select {
		case ev := <-events:
			switch tev := ev.(type) {
			case *tcell.EventResize:
				s.Sync()

			case *tcell.EventKey:
				switch app.Mode {

				case shared.ModeDashboard:
					switch tev.Key() {
					case tcell.KeyUp:
						if len(app.Candidates) > 0 &&
							app.SelectedIdx > 0 &&
							app.SelectedIdx < len(app.Candidates) {
							app.SelectedIdx--
							app.SelectedKey = shared.CandidateKey(app.Candidates[app.SelectedIdx])
						}
					case tcell.KeyDown:
						if app.SelectedIdx >= 0 &&
							app.SelectedIdx < len(app.Candidates)-1 {
							app.SelectedIdx++
							app.SelectedKey = shared.CandidateKey(app.Candidates[app.SelectedIdx])
						}
					case tcell.KeyEnter:
						if app.SelectedIdx >= 0 &&
							app.SelectedIdx < len(app.Candidates) {
							app.InspectKey = shared.CandidateKey(app.Candidates[app.SelectedIdx])
							app.Mode = shared.ModeInspect
						}
					}

					if tev.Rune() == 'q' {
						return nil
					}

				case shared.ModeInspect:
					if app.ConfirmKillKey != "" {
						if r := tev.Rune(); r != 'k' && r != 'K' && r != 'y' && r != 'Y' {
							app.ConfirmKillKey = ""
						}
					}
					if tev.Key() == tcell.KeyEscape {
						app.ConfirmKillKey = ""
						app.Mode = shared.ModeDashboard
					}
					if tev.Rune() == 'q' {
						app.ConfirmKillKey = ""
						return nil
					}
					if tev.Rune() == 'k' || tev.Rune() == 'K' || tev.Rune() == 'y' || tev.Rune() == 'Y' {
						key := app.InspectKey
						if app.ConfirmKill {
							if app.ConfirmKillKey != key || time.Now().After(app.ConfirmKillDeadline) {
								if tev.Rune() == 'y' || tev.Rune() == 'Y' {
									break
								}
								app.ConfirmKillKey = key
								app.ConfirmKillDeadline = time.Now().Add(app.ConfirmKillTimeout)
								break
							}
						}

						idx := FindIndexByKey(app.Candidates, key)
						if idx == -1 {
							app.LastError = "Process no longer present"
							app.ConfirmKillKey = ""
							break
						}
						if app.LocalHost == "" || app.Candidates[idx].Host != app.LocalHost {
							app.LastError = "Kill disabled for remote host"
							app.ConfirmKillKey = ""
							break
						}

						pid := app.Candidates[idx].Proc.Pid
						if err := telemetry.KillProcess(pid); err != nil {
							app.LastError = "Kill failed: " + err.Error()
						} else {
							app.LastError = "Killed PID " + strconv.Itoa(pid) + " (" + app.Candidates[idx].Proc.Name + ")"
						}
						app.ConfirmKillKey = ""
					}
				}
			}

		case <-tick.C:
			startRefresh()
		case res := <-refreshCh:
			refreshInFlight = false
			app.Candidates = res.candidates
			app.LastError = res.lastError
			app.LastUpdate = res.lastUpdate

			if len(app.Candidates) == 0 {
				app.SelectedIdx = -1
				app.SelectedKey = ""
				break
			}

			if app.SelectedKey != res.selectionKeyAtStart {
				idx := FindIndexByKey(app.Candidates, app.SelectedKey)
				if idx >= 0 {
					app.SelectedIdx = idx
				} else {
					app.SelectedIdx = 0
					app.SelectedKey = shared.CandidateKey(app.Candidates[0])
				}
				break
			}

			app.SelectedKey = res.selectedKey
			app.SelectedIdx = res.selectedIdx
		}
	}
}
