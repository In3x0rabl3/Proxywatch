package shared

import (
	"os"
	"time"

	"github.com/gdamore/tcell/v2"
)

type AppMode int

const (
	ModeDashboard AppMode = iota
	ModeInspect
	ModeWhitelist
	ModeCollect
)

type AppState struct {
	Screen tcell.Screen

	LastError           string
	LastUpdate          time.Time
	RefreshInt          time.Duration
	ConfirmKill         bool
	ConfirmKillTimeout  time.Duration
	ConfirmKillKey      string
	ConfirmKillDeadline time.Time
	LocalHost           string
	Whitelist           *Whitelist
	WhitelistItems      []string
	WhitelistSelected   int
	RemoteKill          func(host string, pid int) error
	RoleFilterOverride  map[string]bool

	CollectActive      bool
	CollectUntil       time.Time
	CollectDurationStr string
	CollectRoles       string
	CollectOutput      string
	CollectRoleFilter  map[string]bool
	CollectData        []Candidate
	CollectField       int
	CollectEditing     bool

	Candidates  []Candidate
	Mode        AppMode
	SelectedKey string
	SelectedIdx int
	InspectKey  string
}

type Scanner interface {
	Refresh(app *AppState)
}

type IOSample struct {
	Read      uint64
	Write     uint64
	Other     uint64
	Timestamp time.Time
}

type ScannerAdapter struct {
	Options   ClassifyOptions
	Cache     ClassifierCache
	LastIO    map[int]IOSample
	HostID    string
	Whitelist *Whitelist
	Collect   func() (*Snapshot, error)
	Classify  ClassifyFunc
}

func (s *ScannerAdapter) Refresh(app *AppState) {
	if s.Collect == nil || s.Classify == nil {
		app.LastError = "scanner not configured"
		app.Candidates = nil
		app.SelectedIdx = -1
		app.SelectedKey = ""
		app.LastUpdate = time.Now().UTC()
		return
	}

	snap, err := s.Collect()
	if err != nil {
		app.LastError = err.Error()
		app.Candidates = nil
		app.SelectedIdx = -1
		app.SelectedKey = ""
		app.LastUpdate = time.Now().UTC()
		return
	}

	opts := s.Options
	if app != nil && len(app.RoleFilterOverride) > 0 {
		opts.RoleFilter = app.RoleFilterOverride
	}
	cands := s.Classify(snap, opts, &s.Cache)
	selfPID := os.Getpid()
	filtered := make([]Candidate, 0, len(cands))
	for _, c := range cands {
		if c.Proc != nil && c.Proc.Pid == selfPID {
			continue
		}
		filtered = append(filtered, c)
	}
	cands = filtered
	now := time.Now().UTC()
	if s.HostID == "" {
		s.HostID = "local"
	}
	for i := range cands {
		cands[i].Host = s.HostID
	}
	ApplyIORates(cands, now, &s.LastIO)
	if s.Whitelist != nil {
		cands = s.Whitelist.Filter(cands)
	}

	app.LastError = ""
	app.Candidates = cands
	app.LastUpdate = now
	// app.LastError already set above

	// maintain selection across refreshes
	if len(app.Candidates) == 0 {
		app.SelectedIdx = -1
		app.SelectedKey = ""
		return
	}

	if app.SelectedKey != "" {
		for i, c := range app.Candidates {
			if CandidateKey(c) == app.SelectedKey {
				app.SelectedIdx = i
				return
			}
		}
	}

	app.SelectedIdx = 0
	app.SelectedKey = CandidateKey(app.Candidates[0])
}

func ApplyIORates(cands []Candidate, now time.Time, prev *map[int]IOSample) {
	if *prev == nil {
		*prev = make(map[int]IOSample, len(cands))
	}

	next := make(map[int]IOSample, len(cands))
	for i := range cands {
		pi := cands[i].Proc
		if pi == nil {
			continue
		}

		sample := IOSample{
			Read:      pi.IOReadBytes,
			Write:     pi.IOWriteBytes,
			Other:     pi.IOOtherBytes,
			Timestamp: now,
		}

		if p, ok := (*prev)[pi.Pid]; ok && now.After(p.Timestamp) {
			dt := now.Sub(p.Timestamp).Seconds()
			if dt > 0 {
				if pi.IOReadBytes >= p.Read {
					pi.IOReadBps = uint64(float64(pi.IOReadBytes-p.Read) / dt)
				}
				if pi.IOWriteBytes >= p.Write {
					pi.IOWriteBps = uint64(float64(pi.IOWriteBytes-p.Write) / dt)
				}
				if pi.IOOtherBytes >= p.Other {
					pi.IOOtherBps = uint64(float64(pi.IOOtherBytes-p.Other) / dt)
				}
			}
		}

		next[pi.Pid] = sample
	}

	*prev = next
}
