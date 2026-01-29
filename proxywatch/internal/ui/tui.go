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
	if app.WhitelistSelected == 0 && len(app.WhitelistItems) == 0 {
		app.WhitelistSelected = -1
	}

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
		case shared.ModeWhitelist:
			DrawWhitelist(app)
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

					if tev.Rune() == 'w' || tev.Rune() == 'W' {
						if tev.Rune() == 'W' {
							if app.Whitelist == nil {
								app.LastError = "whitelist not configured"
							} else {
								app.WhitelistItems = app.Whitelist.List()
								if len(app.WhitelistItems) == 0 {
									app.WhitelistSelected = -1
								} else if app.WhitelistSelected < 0 || app.WhitelistSelected >= len(app.WhitelistItems) {
									app.WhitelistSelected = 0
								}
								app.Mode = shared.ModeWhitelist
							}
							break
						}
						if app.SelectedIdx >= 0 && app.SelectedIdx < len(app.Candidates) {
							if app.Whitelist == nil {
								app.LastError = "whitelist not configured"
							} else {
								cand := app.Candidates[app.SelectedIdx]
								if _, err := app.Whitelist.AddCandidate(cand); err != nil {
									app.LastError = "whitelist failed: " + err.Error()
								} else {
									app.LastError = "Whitelisted " + cand.Proc.Name
									app.Candidates = app.Whitelist.Filter(app.Candidates)
									if len(app.Candidates) == 0 {
										app.SelectedIdx = -1
										app.SelectedKey = ""
									} else {
										if app.SelectedIdx >= len(app.Candidates) {
											app.SelectedIdx = len(app.Candidates) - 1
										}
										app.SelectedKey = shared.CandidateKey(app.Candidates[app.SelectedIdx])
									}
								}
							}
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
						pid := app.Candidates[idx].Proc.Pid
						host := app.Candidates[idx].Host
						if host == "" {
							host = "local"
						}
						if app.LocalHost != "" && host == app.LocalHost {
							if err := telemetry.KillProcess(pid); err != nil {
								app.LastError = "Kill failed: " + err.Error()
							} else {
								app.LastError = "Killed PID " + strconv.Itoa(pid) + " (" + app.Candidates[idx].Proc.Name + ")"
							}
							app.ConfirmKillKey = ""
							break
						}

						if app.RemoteKill == nil {
							app.LastError = "Kill disabled for remote host"
							app.ConfirmKillKey = ""
							break
						}
						if err := app.RemoteKill(host, pid); err != nil {
							app.LastError = "Remote kill failed: " + err.Error()
						} else {
							app.LastError = "Remote kill sent for PID " + strconv.Itoa(pid) + " (" + app.Candidates[idx].Proc.Name + ")"
						}
						app.ConfirmKillKey = ""
					}
				case shared.ModeWhitelist:
					switch tev.Key() {
					case tcell.KeyUp:
						if app.WhitelistSelected > 0 && app.WhitelistSelected < len(app.WhitelistItems) {
							app.WhitelistSelected--
						}
					case tcell.KeyDown:
						if app.WhitelistSelected >= 0 && app.WhitelistSelected < len(app.WhitelistItems)-1 {
							app.WhitelistSelected++
						}
					case tcell.KeyEscape:
						app.Mode = shared.ModeDashboard
					}
					if tev.Rune() == 'q' {
						return nil
					}
					if tev.Rune() == 'd' || tev.Rune() == 'D' || tev.Rune() == 'u' || tev.Rune() == 'U' {
						if app.Whitelist == nil {
							app.LastError = "whitelist not configured"
							break
						}
						if app.WhitelistSelected >= 0 && app.WhitelistSelected < len(app.WhitelistItems) {
							key := app.WhitelistItems[app.WhitelistSelected]
							if err := app.Whitelist.Remove(key); err != nil {
								app.LastError = "unwhitelist failed: " + err.Error()
							} else {
								app.LastError = "Removed whitelist entry"
								app.WhitelistItems = app.Whitelist.List()
								if len(app.WhitelistItems) == 0 {
									app.WhitelistSelected = -1
								} else if app.WhitelistSelected >= len(app.WhitelistItems) {
									app.WhitelistSelected = len(app.WhitelistItems) - 1
								}
							}
						}
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
