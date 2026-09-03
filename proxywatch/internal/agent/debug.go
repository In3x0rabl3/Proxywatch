package agent

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"proxywatch/internal/detection/output"
	"proxywatch/internal/shared"
)

// clientStateSnapshot caches the agent's most recent local classification
// so the agent-side debug HTTP API can return what was *just* sent to the
// server. Read-only — never mutated by the HTTP handlers.
type clientStateSnapshot struct {
	mu             sync.RWMutex
	hostID         string
	serverAddr     string
	lastClassifyAt time.Time
	lastSendAt     time.Time
	lastCandidates []shared.Candidate
}

var clientState = &clientStateSnapshot{}

func (s *clientStateSnapshot) setIdentity(hostID, addr string) {
	s.mu.Lock()
	s.hostID = hostID
	s.serverAddr = addr
	s.mu.Unlock()
}

func (s *clientStateSnapshot) setLastClassified(at time.Time, cands []shared.Candidate) {
	cp := make([]shared.Candidate, len(cands))
	copy(cp, cands)
	s.mu.Lock()
	s.lastClassifyAt = at
	s.lastCandidates = cp
	s.mu.Unlock()
}

func (s *clientStateSnapshot) setLastSent(at time.Time) {
	s.mu.Lock()
	s.lastSendAt = at
	s.mu.Unlock()
}

func (s *clientStateSnapshot) snapshot() (string, string, time.Time, time.Time, []shared.Candidate) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]shared.Candidate, len(s.lastCandidates))
	copy(out, s.lastCandidates)
	return s.hostID, s.serverAddr, s.lastClassifyAt, s.lastSendAt, out
}

// StartDebugServer exposes the agent's most recent local classification on
// addr. Used to A/B compare what the agent classified locally against what
// the server sees after stream ingestion.
//
// Endpoints:
//
//	GET /             — { host, server, last_classify_at, last_send_at, candidates }
//	GET /candidates   — full snapshot (same JSON as server-side /candidates)
//	GET /candidate/<pid>
//	GET /diff         — compact { pid: {name, role, signals} } map
func StartDebugServer(addr, hostID, serverAddr string) (*http.Server, error) {
	clientState.setIdentity(hostID, serverAddr)

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleAgentDebugHealth)
	mux.HandleFunc("/candidates", handleAgentDebugCandidates)
	mux.HandleFunc("/candidate/", handleAgentDebugCandidateByPID)
	mux.HandleFunc("/diff", handleAgentDebugDiff)
	mux.HandleFunc("/fp-report", handleAgentDebugFPReport)

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "[agent-debug-api] server error: %v\n", err)
		}
	}()
	return srv, nil
}

func handleAgentDebugHealth(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	host, server, classifyAt, sendAt, cands := clientState.snapshot()
	writeAgentJSON(w, map[string]interface{}{
		"ok":               true,
		"host":             host,
		"server":           server,
		"last_classify_at": tsRFC(classifyAt),
		"last_send_at":     tsRFC(sendAt),
		"candidates":       len(cands),
	})
}

func handleAgentDebugCandidates(w http.ResponseWriter, r *http.Request) {
	host, _, _, _, cands := clientState.snapshot()
	shared.ClassifyMu.RLock()
	snap := output.CandidatesToSnapshots(cands)
	shared.ClassifyMu.RUnlock()
	items := agentFilterSnapshots(snap, r)
	writeAgentJSON(w, map[string]interface{}{
		"host":  host,
		"count": len(items),
		"items": items,
	})
}

func handleAgentDebugCandidateByPID(w http.ResponseWriter, r *http.Request) {
	pidStr := strings.TrimPrefix(r.URL.Path, "/candidate/")
	if pidStr == "" {
		http.NotFound(w, r)
		return
	}
	_, _, _, _, cands := clientState.snapshot()
	shared.ClassifyMu.RLock()
	snap := output.CandidatesToSnapshots(cands)
	shared.ClassifyMu.RUnlock()
	for _, c := range snap {
		if fmt.Sprintf("%d", c.PID) == pidStr {
			writeAgentJSON(w, c)
			return
		}
	}
	http.NotFound(w, r)
}

func handleAgentDebugFPReport(w http.ResponseWriter, r *http.Request) {
	host, _, _, _, cands := clientState.snapshot()
	entries := output.BuildFPReport(cands)
	if only := strings.TrimSpace(r.URL.Query().Get("only")); only == "suppressed" {
		kept := entries[:0]
		for _, e := range entries {
			if e.WouldSuppress {
				kept = append(kept, e)
			}
		}
		entries = kept
	}
	suppressed := 0
	for _, e := range entries {
		if e.WouldSuppress {
			suppressed++
		}
	}
	writeAgentJSON(w, map[string]interface{}{
		"host":       host,
		"count":      len(entries),
		"suppressed": suppressed,
		"entries":    entries,
	})
}

func handleAgentDebugDiff(w http.ResponseWriter, r *http.Request) {
	_, _, _, _, cands := clientState.snapshot()
	shared.ClassifyMu.RLock()
	snap := output.CandidatesToSnapshots(cands)
	shared.ClassifyMu.RUnlock()
	writeAgentJSON(w, output.BuildDiffMap(snap))
}

func agentFilterSnapshots(in []output.CandidateSnapshot, r *http.Request) []output.CandidateSnapshot {
	q := r.URL.Query()
	nameFilter := strings.ToLower(strings.TrimSpace(q.Get("name")))
	roleFilter := strings.ToLower(strings.TrimSpace(q.Get("role")))
	stateFilter := strings.ToLower(strings.TrimSpace(q.Get("state")))
	pidFilter := strings.TrimSpace(q.Get("pid"))
	out := make([]output.CandidateSnapshot, 0, len(in))
	for _, c := range in {
		if nameFilter != "" && !strings.Contains(strings.ToLower(c.Name), nameFilter) {
			continue
		}
		if roleFilter != "" && strings.ToLower(c.Role) != roleFilter && strings.ToLower(c.RoleFamily) != roleFilter {
			continue
		}
		if stateFilter != "" && !strings.Contains(strings.ToLower(c.State), stateFilter) {
			continue
		}
		if pidFilter != "" && fmt.Sprintf("%d", c.PID) != pidFilter {
			continue
		}
		out = append(out, c)
	}
	return out
}

func tsRFC(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func writeAgentJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// debugStoreProvider adapts the agent Server + Store to the read-only
// AgentStoreProvider interface consumed by the detection-output debug API.
// All methods are nil-safe so the debug API can register/unregister freely.
type debugStoreProvider struct {
	srv   *Server
	store *Store
}

// NewDebugStoreProvider returns an output.AgentStoreProvider that exposes the
// connected-agent state for inspection through the debug API. Wire from
// main.go after agent.ListenAndServe; pass to output.RegisterAgentStore.
func NewDebugStoreProvider(srv *Server, store *Store) output.AgentStoreProvider {
	return &debugStoreProvider{srv: srv, store: store}
}

func (p *debugStoreProvider) ConnectedHosts() map[string]bool {
	if p == nil || p.srv == nil {
		return nil
	}
	return p.srv.ConnectedHosts()
}

func (p *debugStoreProvider) HostList() []output.AgentHostInfo {
	if p == nil || p.store == nil {
		return nil
	}
	connected := map[string]bool{}
	if p.srv != nil {
		connected = p.srv.ConnectedHosts()
	}
	stats := p.store.HostKeys()
	out := make([]output.AgentHostInfo, 0, len(stats))
	for _, st := range stats {
		out = append(out, output.AgentHostInfo{
			Host:       st.Host,
			Connected:  connected[st.Host],
			FirstSeen:  st.FirstSeen,
			LastSeen:   st.LastSeen,
			Candidates: st.Candidates,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

func (p *debugStoreProvider) HostSnapshot(host string) ([]shared.Candidate, time.Time, bool) {
	if p == nil || p.store == nil {
		return nil, time.Time{}, false
	}
	return p.store.SnapshotHost(host)
}
