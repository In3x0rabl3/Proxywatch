package agent

import (
	"time"

	"proxywatch/internal/shared"
)

type RemoteScanner struct {
	Store      *Store
	StaleAfter time.Duration
	MinScore   int
	RoleFilter map[string]bool
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

	roleFilter := r.RoleFilter
	if app != nil && len(app.RoleFilterOverride) > 0 {
		roleFilter = app.RoleFilterOverride
	}
	cands := r.Store.Snapshot(r.StaleAfter)
	if r.MinScore > 0 || len(roleFilter) > 0 {
		filtered := make([]shared.Candidate, 0, len(cands))
		for _, c := range cands {
			if r.MinScore > 0 && c.Score < r.MinScore {
				continue
			}
			if len(roleFilter) > 0 && !roleFilter[c.Role] {
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
