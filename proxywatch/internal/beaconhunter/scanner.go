package beaconhunter

import (
	"time"

	"proxywatch/internal/shared"
)

type RemoteScanner struct {
	Store      *Store
	StaleAfter time.Duration
	MinScore   int
	RoleFilter map[string]bool
	Logger     *shared.JSONLogger
	Whitelist  *shared.Whitelist
}

func (r *RemoteScanner) Refresh(app *shared.AppState) {
	if r.Store == nil {
		app.LastError = "remote store not configured"
		app.Candidates = nil
		app.SelectedIdx = -1
		app.SelectedKey = ""
		app.LastUpdate = time.Now().UTC()
		return
	}

	cands := r.Store.Snapshot(r.StaleAfter)
	if r.MinScore > 0 || len(r.RoleFilter) > 0 {
		filtered := make([]shared.Candidate, 0, len(cands))
		for _, c := range cands {
			if r.MinScore > 0 && c.Score < r.MinScore {
				continue
			}
			if len(r.RoleFilter) > 0 && !r.RoleFilter[c.Role] {
				continue
			}
			filtered = append(filtered, c)
		}
		cands = filtered
	}
	if r.Whitelist != nil {
		cands = r.Whitelist.Filter(cands)
	}
	now := time.Now().UTC()

	app.LastError = ""
	app.Candidates = cands
	app.LastUpdate = now
	if r.Logger != nil {
		if err := r.Logger.WriteSnapshot(nil, cands); err != nil {
			app.LastError = "log write failed: " + err.Error()
		}
	}

	if len(app.Candidates) == 0 {
		app.SelectedIdx = -1
		app.SelectedKey = ""
		return
	}

	if app.SelectedKey != "" {
		for i, c := range app.Candidates {
			if shared.CandidateKey(c) == app.SelectedKey {
				app.SelectedIdx = i
				return
			}
		}
	}

	app.SelectedIdx = 0
	app.SelectedKey = shared.CandidateKey(app.Candidates[0])
}
