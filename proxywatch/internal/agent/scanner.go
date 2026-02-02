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
		shared.ResetAppState(app, "remote store not configured")
		return
	}

	roleFilter := r.RoleFilter
	if app != nil && len(app.RoleFilterOverride) > 0 {
		roleFilter = app.RoleFilterOverride
	}
	cands := r.Store.Snapshot(r.StaleAfter)
	cands = shared.ApplyScoreAndRoleFilters(cands, r.MinScore, roleFilter)
	cands = shared.ApplyWhitelist(cands, r.Whitelist)
	shared.ApplySelection(app, cands, time.Now().UTC())
}
