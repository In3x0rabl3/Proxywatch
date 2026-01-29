package beaconhunter

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
			out = append(out, c)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		pri := rolePriority(out[i].Role)
		prj := rolePriority(out[j].Role)
		if pri != prj {
			return pri > prj
		}
		if out[i].ActiveProxying != out[j].ActiveProxying {
			return out[i].ActiveProxying && !out[j].ActiveProxying
		}
		if out[i].OutInternal != out[j].OutInternal {
			return out[i].OutInternal > out[j].OutInternal
		}
		if out[i].OutTotal != out[j].OutTotal {
			return out[i].OutTotal > out[j].OutTotal
		}
		if out[i].Score == out[j].Score {
			return out[i].Proc.Pid < out[j].Proc.Pid
		}
		return out[i].Score > out[j].Score
	})

	return out
}

func rolePriority(role string) int {
	switch role {
	case "reverse-transport":
		return 90
	case "reverse-proxy":
		return 80
	case "proxy-listener":
		return 70
	case "susp-tun":
		return 68
	case "susp-session":
		return 66
	case "susp-beacon":
		return 65
	case "listener-with-clients":
		return 60
	case "listener-with-outbound":
		return 50
	case "reverse-control":
		return 40
	case "reverse-tunnel":
		return 35
	case "listener-only":
		return 30
	case "outbound-only":
		return 10
	default:
		return 0
	}
}
