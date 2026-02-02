package agent

import (
	"sort"
	"sync"
	"time"

	"proxywatch/internal/shared"
)

type Store struct {
	mu    sync.RWMutex
	hosts map[string]hostState
}

type hostState struct {
	updated time.Time
	cands   []shared.Candidate
}

func NewStore() *Store {
	return &Store{
		hosts: make(map[string]hostState),
	}
}

func (s *Store) Update(host string, ts time.Time, cands []shared.Candidate) {
	if host == "" {
		host = "unknown"
	}
	for i := range cands {
		if cands[i].Host == "" {
			cands[i].Host = host
		}
	}
	s.mu.Lock()
	s.hosts[host] = hostState{
		updated: ts,
		cands:   cands,
	}
	s.mu.Unlock()
}

func (s *Store) Snapshot(staleAfter time.Duration) []shared.Candidate {
	now := time.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []shared.Candidate
	for host, state := range s.hosts {
		if staleAfter > 0 && now.Sub(state.updated) > staleAfter {
			continue
		}
		for i := range state.cands {
			c := state.cands[i]
			if c.Host == "" {
				c.Host = host
			}
			if c.Proc == nil {
				continue
			}
			out = append(out, c)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		return shared.CandidateLess(out[i], out[j])
	})

	return out
}
