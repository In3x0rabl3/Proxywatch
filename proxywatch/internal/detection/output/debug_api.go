package output

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"proxywatch/internal/alerts"
	"proxywatch/internal/detection/model"
	"proxywatch/internal/shared"
)

// DebugAPIServer exposes current detection state over HTTP for testing/debugging.
// Serves localhost only by default. Provides JSON snapshots of all candidates
// with their current role, state, score, signals, and connection topology.
//
// Endpoints (always available):
//   GET /                          — health JSON { ok, cycle, updated, candidates }
//   GET /candidates                — local-scanner candidates (standalone/headless)
//                                    Query params: name=<substr>, role=<role>, state=<state>, pid=<pid>
//   GET /candidate/<pid>           — single candidate by PID
//   GET /metrics                   — counts by role/state
//
// Endpoints (server mode only — when an AgentStoreProvider is registered):
//   GET /agents                    — connected agents + per-host summary
//   GET /agent/<host>/candidates   — candidates streamed from that agent
//   GET /agent/<host>/candidate/<pid>
//   GET /diff/<host>               — compact { pid: {name, role, signals} } map for parity diffing
//   GET /diff/local                — same shape, for the local scanner snapshot

type debugAPIState struct {
	mu        sync.RWMutex
	latest    []CandidateSnapshot
	latestRaw []shared.Candidate
	cycle     uint64
	hostScope string
	updatedAt time.Time
}

// CandidateSnapshot is a JSON-friendly projection of shared.Candidate fields
// relevant for debugging detection behavior.
type CandidateSnapshot struct {
	Host                   string   `json:"host"`
	PID                    int      `json:"pid"`
	Name                   string   `json:"name"`
	ExePath                string   `json:"exe_path,omitempty"`
	Cmd                    string   `json:"cmd,omitempty"`
	User                   string   `json:"user,omitempty"`
	ParentPID              int      `json:"parent_pid,omitempty"`
	Role                   string   `json:"role"`
	RoleFamily             string   `json:"role_family"`
	State                  string   `json:"state"`
	Score                  int      `json:"score"`
	Confidence             int      `json:"confidence,omitempty"`
	ActiveProxying         bool     `json:"active_proxying"`
	StrongEvidence         bool     `json:"strong_evidence"`
	TrafficVerified        bool     `json:"traffic_verified"`
	Signals                []string `json:"signals,omitempty"`
	Reasons                []string `json:"reasons,omitempty"`
	InboundTotal           int      `json:"inbound_total"`
	OutTotal               int      `json:"out_total"`
	OutExternal            int      `json:"out_external"`
	OutInternal            int      `json:"out_internal"`
	OutLoopback            int      `json:"out_loopback"`
	ControlChannelRemote   string   `json:"control_channel_remote,omitempty"`
	ControlDurationSeconds int      `json:"control_duration_seconds,omitempty"`
	// Destinations is the flattened set of remote endpoints this
	// candidate has connections to, used by the LIVE-vs-PCAP parity
	// harness to compare per-destination role decisions across modes.
	// Each entry is "ip:port" — same format as ControlChannelRemote.
	// Populated from c.Conns; ESTABLISHED state preferred but all
	// states are included so closing-but-once-active relays still
	// appear in the truth set.
	Destinations  []string `json:"destinations,omitempty"`
	SeenSeconds   int      `json:"seen_seconds"`
	ListenerCount int      `json:"listener_count"`
	ConnCount     int      `json:"conn_count"`
	IOReadBps     uint64   `json:"io_read_bps"`
	IOWriteBps    uint64   `json:"io_write_bps"`
	MLRole        string   `json:"ml_role,omitempty"`
	MLConfidence  float64  `json:"ml_confidence,omitempty"`
	SuggestedRole string   `json:"suggested_role,omitempty"`
}

var debugAPI = &debugAPIState{}

// CandidatesToSnapshots projects shared.Candidate values into the JSON shape
// the debug API serves. Exported so the agent-side debug server and per-host
// server views render identical payloads for parity diffing.
func CandidatesToSnapshots(scored []shared.Candidate) []CandidateSnapshot {
	snap := make([]CandidateSnapshot, 0, len(scored))
	for i := range scored {
		c := &scored[i]
		if c.Proc == nil {
			continue
		}
		snap = append(snap, candidateToSnapshot(c))
	}
	return snap
}

func candidateToSnapshot(c *shared.Candidate) CandidateSnapshot {
	cs := CandidateSnapshot{
		Host:                   c.Host,
		PID:                    c.Proc.Pid,
		Name:                   c.Proc.Name,
		ExePath:                c.Proc.ExePath,
		Cmd:                    c.Proc.CmdLine,
		User:                   c.Proc.UserName,
		ParentPID:              c.Proc.ParentPid,
		Role:                   c.Role,
		RoleFamily:             shared.RoleFamily(c.Role),
		State:                  shared.CandidateStateUnsafe(*c),
		Score:                  c.Score,
		Confidence:             c.Confidence,
		ActiveProxying:         c.ActiveProxying,
		StrongEvidence:         c.StrongEvidence,
		TrafficVerified:        c.TrafficVerified,
		Signals:                shared.DedupStrings(c.Signals),
		Reasons:                shared.DedupStrings(c.Reasons),
		InboundTotal:           c.InboundTotal,
		OutTotal:               c.OutTotal,
		OutExternal:            c.OutExternal,
		OutInternal:            c.OutInternal,
		OutLoopback:            c.OutLoopback,
		ControlDurationSeconds: c.ControlDurationSeconds,
		SeenSeconds:            c.SeenSeconds,
		ListenerCount:          len(c.Listeners),
		ConnCount:              len(c.Conns),
		IOReadBps:              c.Proc.IOReadBps,
		IOWriteBps:             c.Proc.IOWriteBps,
		MLRole:                 c.MLRole,
		MLConfidence:           c.MLConfidence,
		SuggestedRole:          c.SuggestedRole,
	}
	if c.ControlChannel != nil {
		cs.ControlChannelRemote = fmt.Sprintf("%s:%d", c.ControlChannel.RemoteAddress, c.ControlChannel.RemotePort)
	}
	// Collect distinct remote endpoints. Loopback / wildcard are
	// excluded — the harness compares against PCAP synthetic /16
	// cluster names, none of which key on those.
	if len(c.Conns) > 0 {
		seen := make(map[string]struct{}, len(c.Conns))
		for _, cn := range c.Conns {
			if cn.RemoteAddress == "" || cn.RemotePort <= 0 {
				continue
			}
			if shared.IsLoopbackIP(cn.RemoteAddress) || shared.IsWildcardIP(cn.RemoteAddress) {
				continue
			}
			key := fmt.Sprintf("%s:%d", cn.RemoteAddress, cn.RemotePort)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			cs.Destinations = append(cs.Destinations, key)
		}
	}
	return cs
}

// UpdateDebugAPISnapshot is called each cycle with the full candidate list.
// Maintains an in-memory snapshot that the HTTP API serves.
func UpdateDebugAPISnapshot(cycle uint64, hostScope string, scored []shared.Candidate) {
	snap := CandidatesToSnapshots(scored)

	raw := make([]shared.Candidate, len(scored))
	copy(raw, scored)

	debugAPI.mu.Lock()
	debugAPI.latest = snap
	debugAPI.latestRaw = raw
	debugAPI.cycle = cycle
	debugAPI.hostScope = hostScope
	debugAPI.updatedAt = time.Now().UTC()
	debugAPI.mu.Unlock()

	// Fire outbound webhook alerts for freshly promoted malicious
	// candidates. No-op when PROXYWATCH_WEBHOOK_URL is unset. Must run
	// outside the debugAPI lock — the alerts package dispatches POSTs
	// asynchronously but acquires its own mutex for the dedup map.
	alerts.ScanAndFire(hostScope, scored)

	// Record timeline deltas so /timeline/<pid> can show the
	// role/signal evolution of a candidate over time.
	recordTimeline(hostScope, cycle, scored)
}

// AgentStoreProvider is the read-only interface the debug API uses to inspect
// agent-sourced candidates when running in server mode. Implemented by the
// agent server + store; wired from main.go via RegisterAgentStore.
type AgentStoreProvider interface {
	ConnectedHosts() map[string]bool
	HostList() []AgentHostInfo
	HostSnapshot(host string) ([]shared.Candidate, time.Time, bool)
}

// AgentHostInfo is a minimal per-host record used by the /agents endpoint.
type AgentHostInfo struct {
	Host       string    `json:"host"`
	Connected  bool      `json:"connected"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Candidates int       `json:"candidates"`
}

var (
	agentStoreMu sync.RWMutex
	agentStore   AgentStoreProvider
)

// RegisterAgentStore enables the /agents and /agent/<host>/* routes.
// Pass nil to disable.
func RegisterAgentStore(p AgentStoreProvider) {
	agentStoreMu.Lock()
	agentStore = p
	agentStoreMu.Unlock()
}

func currentAgentStore() AgentStoreProvider {
	agentStoreMu.RLock()
	defer agentStoreMu.RUnlock()
	return agentStore
}

// StartDebugAPIServer starts a localhost HTTP server for state inspection.
// Returns the server for graceful shutdown. Fails silently on listen error
// (logged) to avoid crashing proxywatch for a debug facility.
func StartDebugAPIServer(addr string) (*http.Server, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleHealth)
	mux.HandleFunc("/candidates", handleCandidates)
	mux.HandleFunc("/candidate/", handleCandidateByPID)
	mux.HandleFunc("/metrics", handleMetrics)
	mux.HandleFunc("/metrics/prom", handleMetricsProm)
	mux.HandleFunc("/self", handleSelf)
	mux.HandleFunc("/agents", handleAgents)
	mux.HandleFunc("/agent/", handleAgentScoped)
	mux.HandleFunc("/diff/", handleDiff)
	mux.HandleFunc("/fp-report", handleFPReport)
	mux.HandleFunc("/fp-report/", handleFPReport)
	mux.HandleFunc("/fp-report/summary", handleFPReportSummary)
	mux.HandleFunc("/online/status", handleOnlineStatus)
	mux.HandleFunc("/online/verdict/", handleOnlineVerdict)
	mux.HandleFunc("/operator/labels", handleOperatorLabels)
	mux.HandleFunc("/operator/label", handleOperatorLabel)
	mux.HandleFunc("/operator/label/", handleOperatorLabelByHash)
	mux.HandleFunc("/ml/disagreements", handleMLDisagreements)
	mux.HandleFunc("/ml/shadow", handleMLShadow)
	mux.HandleFunc("/timeline", handleTimeline)
	mux.HandleFunc("/timeline/", handleTimeline)

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "[debug-api] server error: %v\n", err)
		}
	}()
	return srv, nil
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	debugAPI.mu.RLock()
	resp := map[string]interface{}{
		"ok":         true,
		"cycle":      debugAPI.cycle,
		"host":       debugAPI.hostScope,
		"updated":    debugAPI.updatedAt.Format(time.RFC3339),
		"candidates": len(debugAPI.latest),
		"server":     currentAgentStore() != nil,
	}
	debugAPI.mu.RUnlock()
	writeJSON(w, resp)
}

func handleCandidates(w http.ResponseWriter, r *http.Request) {
	debugAPI.mu.RLock()
	items := filterSnapshots(debugAPI.latest, r)
	resp := map[string]interface{}{
		"cycle":   debugAPI.cycle,
		"host":    debugAPI.hostScope,
		"updated": debugAPI.updatedAt.Format(time.RFC3339),
		"count":   len(items),
		"items":   items,
	}
	debugAPI.mu.RUnlock()
	writeJSON(w, resp)
}

func filterSnapshots(in []CandidateSnapshot, r *http.Request) []CandidateSnapshot {
	q := r.URL.Query()
	nameFilter := strings.ToLower(strings.TrimSpace(q.Get("name")))
	roleFilter := strings.ToLower(strings.TrimSpace(q.Get("role")))
	stateFilter := strings.ToLower(strings.TrimSpace(q.Get("state")))
	pidFilter := strings.TrimSpace(q.Get("pid"))

	out := make([]CandidateSnapshot, 0, len(in))
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

func handleCandidateByPID(w http.ResponseWriter, r *http.Request) {
	pidStr := strings.TrimPrefix(r.URL.Path, "/candidate/")
	if pidStr == "" {
		http.NotFound(w, r)
		return
	}
	debugAPI.mu.RLock()
	defer debugAPI.mu.RUnlock()
	for _, c := range debugAPI.latest {
		if fmt.Sprintf("%d", c.PID) == pidStr {
			writeJSON(w, c)
			return
		}
	}
	http.NotFound(w, r)
}

// handleMetricsProm emits Prometheus text-format metrics so standard
// monitoring stacks (Prometheus, VictoriaMetrics, Grafana Agent) can
// scrape ProxyWatch without a translation layer. Zero new counters —
// just reshapes the same state /metrics exposes in JSON.
// handleSelf mirrors /agent/<host>/candidates for local (non-server) mode
// so monitoring tooling can use a stable path regardless of deployment mode.
// In server mode, redirects to /agents; in local mode, returns the same
// shape as /candidates with the host field populated.
func handleSelf(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	debugAPI.mu.RLock()
	items := debugAPI.latest
	resp := map[string]interface{}{
		"host":    debugAPI.hostScope,
		"cycle":   debugAPI.cycle,
		"updated": debugAPI.updatedAt.Format(time.RFC3339),
		"count":   len(items),
		"items":   items,
	}
	debugAPI.mu.RUnlock()
	writeJSON(w, resp)
}

func handleMetricsProm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	// HTTP-handler thread reads latestRaw and calls CandidateStateUnsafe;
	// the live scanner is concurrently writing the global classifier maps
	// from inside detection.Classify. RLock the read so the runtime
	// can never observe a half-written map.
	shared.ClassifyMu.RLock()
	defer shared.ClassifyMu.RUnlock()

	roleCounts := make(map[string]int)
	stateCounts := make(map[string]int)
	signalCounts := make(map[string]int)
	tunnelingCount := 0
	strongEvidenceCount := 0
	activeProxyingCount := 0
	debugAPI.mu.RLock()
	total := len(debugAPI.latest)
	cycle := debugAPI.cycle
	host := debugAPI.hostScope
	for _, c := range debugAPI.latest {
		roleCounts[c.Role]++
		stateCounts[c.State]++
		for _, sig := range c.Signals {
			signalCounts[sig]++
		}
		if c.StrongEvidence {
			strongEvidenceCount++
		}
		if c.ActiveProxying {
			activeProxyingCount++
		}
	}
	latestRaw := append([]shared.Candidate(nil), debugAPI.latestRaw...)
	debugAPI.mu.RUnlock()

	// FP-shape-override counter: how many candidates currently have a
	// soft-override active. Recomputed on each scrape (O(N) over the
	// candidate snapshot) — cheap relative to a network RTT, avoids
	// adding global state for a pure observability read.
	fpShapeSoftOverrideCount := 0
	fpShapeWouldDemoteCount := 0
	for i := range latestRaw {
		shape := shared.EvaluateVendorFPShape(&latestRaw[i], shared.DefaultFPShapeThreshold)
		if shape.SoftOverride {
			fpShapeSoftOverrideCount++
		}
		if shape.WouldDemote {
			fpShapeWouldDemoteCount++
		}
		if shared.CandidateStateUnsafe(latestRaw[i]) == "tunneling" {
			tunnelingCount++
		}
	}

	// Operator labels — stable across restarts.
	labelBenignCount := 0
	labelMaliciousCount := 0
	for _, l := range shared.ListOperatorLabels() {
		switch l.Verdict {
		case shared.VerdictBenign:
			labelBenignCount++
		case shared.VerdictMalicious:
			labelMaliciousCount++
		}
	}

	// Agent-store state (server mode only).
	agentsConnected := 0
	agentsTotal := 0
	if store := currentAgentStore(); store != nil {
		for _, info := range store.HostList() {
			agentsTotal++
			if info.Connected {
				agentsConnected++
			}
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# HELP proxywatch_candidates_total Total candidates classified in the current cycle.\n")
	fmt.Fprintf(&b, "# TYPE proxywatch_candidates_total gauge\n")
	fmt.Fprintf(&b, "proxywatch_candidates_total{host=%q} %d\n", host, total)

	fmt.Fprintf(&b, "# HELP proxywatch_cycle Monotonic classifier cycle counter.\n")
	fmt.Fprintf(&b, "# TYPE proxywatch_cycle counter\n")
	fmt.Fprintf(&b, "proxywatch_cycle{host=%q} %d\n", host, cycle)

	fmt.Fprintf(&b, "# HELP proxywatch_candidates_by_role Candidates grouped by assigned role.\n")
	fmt.Fprintf(&b, "# TYPE proxywatch_candidates_by_role gauge\n")
	for role, n := range roleCounts {
		fmt.Fprintf(&b, "proxywatch_candidates_by_role{host=%q,role=%q} %d\n", host, role, n)
	}

	fmt.Fprintf(&b, "# HELP proxywatch_candidates_by_state Candidates grouped by display state.\n")
	fmt.Fprintf(&b, "# TYPE proxywatch_candidates_by_state gauge\n")
	for state, n := range stateCounts {
		fmt.Fprintf(&b, "proxywatch_candidates_by_state{host=%q,state=%q} %d\n", host, state, n)
	}

	// ML health — single-instance metrics so an alert rule can page on
	// DEGRADED without scraping /ml/shadow separately.
	agree, disagree := model.ShadowCounts()
	shadowTotal := agree + disagree
	rate := 0.0
	if shadowTotal > 0 {
		rate = float64(agree) / float64(shadowTotal)
	}
	fmt.Fprintf(&b, "# HELP proxywatch_ml_shadow_agreement_rate Rolling ML-vs-rule agreement rate [0,1].\n")
	fmt.Fprintf(&b, "# TYPE proxywatch_ml_shadow_agreement_rate gauge\n")
	fmt.Fprintf(&b, "proxywatch_ml_shadow_agreement_rate{host=%q} %f\n", host, rate)

	fmt.Fprintf(&b, "# HELP proxywatch_ml_shadow_total Total ML-vs-rule comparisons in the rolling window.\n")
	fmt.Fprintf(&b, "# TYPE proxywatch_ml_shadow_total gauge\n")
	fmt.Fprintf(&b, "proxywatch_ml_shadow_total{host=%q} %d\n", host, shadowTotal)

	qualified := 0
	if model.MLQualified() {
		qualified = 1
	}
	fmt.Fprintf(&b, "# HELP proxywatch_ml_qualified 1 when the ML predictor is primary; 0 when shadow.\n")
	fmt.Fprintf(&b, "# TYPE proxywatch_ml_qualified gauge\n")
	fmt.Fprintf(&b, "proxywatch_ml_qualified{host=%q} %d\n", host, qualified)

	demoted := 0
	if model.MLDemoted() {
		demoted = 1
	}
	fmt.Fprintf(&b, "# HELP proxywatch_ml_demoted 1 when a previously-qualified ML model dropped below the degrade floor.\n")
	fmt.Fprintf(&b, "# TYPE proxywatch_ml_demoted gauge\n")
	fmt.Fprintf(&b, "proxywatch_ml_demoted{host=%q} %d\n", host, demoted)

	// Per-signal histogram — useful for alert rules that watch shadow
	// signal rates (e.g. injection-rwx-external spikes, cdn-fronted-c2-
	// candidate prevalence) without scraping /candidates end-to-end.
	fmt.Fprintf(&b, "# HELP proxywatch_signal_total Candidates emitting each signal in the current cycle.\n")
	fmt.Fprintf(&b, "# TYPE proxywatch_signal_total gauge\n")
	for sig, n := range signalCounts {
		fmt.Fprintf(&b, "proxywatch_signal_total{host=%q,signal=%q} %d\n", host, sig, n)
	}

	fmt.Fprintf(&b, "# HELP proxywatch_candidates_tunneling Candidates currently classified as tunneling.\n")
	fmt.Fprintf(&b, "# TYPE proxywatch_candidates_tunneling gauge\n")
	fmt.Fprintf(&b, "proxywatch_candidates_tunneling{host=%q} %d\n", host, tunnelingCount)

	fmt.Fprintf(&b, "# HELP proxywatch_candidates_strong_evidence Candidates with StrongEvidence set.\n")
	fmt.Fprintf(&b, "# TYPE proxywatch_candidates_strong_evidence gauge\n")
	fmt.Fprintf(&b, "proxywatch_candidates_strong_evidence{host=%q} %d\n", host, strongEvidenceCount)

	fmt.Fprintf(&b, "# HELP proxywatch_candidates_active_proxying Candidates observed actively relaying.\n")
	fmt.Fprintf(&b, "# TYPE proxywatch_candidates_active_proxying gauge\n")
	fmt.Fprintf(&b, "proxywatch_candidates_active_proxying{host=%q} %d\n", host, activeProxyingCount)

	// FP-shape override instrumentation — Track 7: detect whether the
	// soft-override threshold is firing more often than expected (sign
	// that the vendor-signal bar is too low).
	fmt.Fprintf(&b, "# HELP proxywatch_fp_shape_soft_override_total Candidates with an active FP-shape soft override.\n")
	fmt.Fprintf(&b, "# TYPE proxywatch_fp_shape_soft_override_total gauge\n")
	fmt.Fprintf(&b, "proxywatch_fp_shape_soft_override_total{host=%q} %d\n", host, fpShapeSoftOverrideCount)

	fmt.Fprintf(&b, "# HELP proxywatch_fp_shape_would_demote_total Candidates the FP-shape rule would demote.\n")
	fmt.Fprintf(&b, "# TYPE proxywatch_fp_shape_would_demote_total gauge\n")
	fmt.Fprintf(&b, "proxywatch_fp_shape_would_demote_total{host=%q} %d\n", host, fpShapeWouldDemoteCount)

	fmt.Fprintf(&b, "# HELP proxywatch_operator_labels Operator-applied labels keyed by verdict.\n")
	fmt.Fprintf(&b, "# TYPE proxywatch_operator_labels gauge\n")
	fmt.Fprintf(&b, "proxywatch_operator_labels{host=%q,verdict=%q} %d\n", host, shared.VerdictBenign, labelBenignCount)
	fmt.Fprintf(&b, "proxywatch_operator_labels{host=%q,verdict=%q} %d\n", host, shared.VerdictMalicious, labelMaliciousCount)

	fmt.Fprintf(&b, "# HELP proxywatch_agents_connected Connected agents (server mode only; 0 in local mode).\n")
	fmt.Fprintf(&b, "# TYPE proxywatch_agents_connected gauge\n")
	fmt.Fprintf(&b, "proxywatch_agents_connected{host=%q} %d\n", host, agentsConnected)

	fmt.Fprintf(&b, "# HELP proxywatch_agents_known_total All agents the server has ever seen (server mode only).\n")
	fmt.Fprintf(&b, "# TYPE proxywatch_agents_known_total gauge\n")
	fmt.Fprintf(&b, "proxywatch_agents_known_total{host=%q} %d\n", host, agentsTotal)

	_, _ = w.Write([]byte(b.String()))
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	roleCounts := make(map[string]int)
	stateCounts := make(map[string]int)
	debugAPI.mu.RLock()
	for _, c := range debugAPI.latest {
		roleCounts[c.Role]++
		stateCounts[c.State]++
	}
	resp := map[string]interface{}{
		"cycle":   debugAPI.cycle,
		"host":    debugAPI.hostScope,
		"updated": debugAPI.updatedAt.Format(time.RFC3339),
		"total":   len(debugAPI.latest),
		"roles":   roleCounts,
		"states":  stateCounts,
	}
	debugAPI.mu.RUnlock()
	writeJSON(w, resp)
}

func handleAgents(w http.ResponseWriter, r *http.Request) {
	store := currentAgentStore()
	if store == nil {
		writeNotServerMode(w)
		return
	}
	hosts := store.HostList()
	sort.Slice(hosts, func(i, j int) bool {
		if hosts[i].Connected != hosts[j].Connected {
			return hosts[i].Connected
		}
		return hosts[i].Host < hosts[j].Host
	})
	writeJSON(w, map[string]interface{}{
		"count": len(hosts),
		"hosts": hosts,
	})
}

func handleAgentScoped(w http.ResponseWriter, r *http.Request) {
	store := currentAgentStore()
	if store == nil {
		writeNotServerMode(w)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/agent/")
	if rest == "" {
		http.NotFound(w, r)
		return
	}
	parts := strings.SplitN(rest, "/", 3)
	host := parts[0]
	if host == "" {
		http.NotFound(w, r)
		return
	}
	cands, updated, ok := store.HostSnapshot(host)
	if !ok {
		http.Error(w, "host not found", http.StatusNotFound)
		return
	}
	// CandidatesToSnapshots → candidateToSnapshot → CandidateStateUnsafe
	// reads global classifier maps that detection.Classify writes
	// concurrently; RLock so the read is serialized with that writer.
	shared.ClassifyMu.RLock()
	snap := CandidatesToSnapshots(cands)
	shared.ClassifyMu.RUnlock()

	if len(parts) >= 2 && parts[1] == "candidate" {
		if len(parts) < 3 || parts[2] == "" {
			http.NotFound(w, r)
			return
		}
		pidStr := parts[2]
		for _, c := range snap {
			if fmt.Sprintf("%d", c.PID) == pidStr {
				writeJSON(w, c)
				return
			}
		}
		http.NotFound(w, r)
		return
	}

	if len(parts) >= 2 && parts[1] != "candidates" {
		http.NotFound(w, r)
		return
	}

	items := filterSnapshots(snap, r)
	writeJSON(w, map[string]interface{}{
		"host":    host,
		"updated": updated.UTC().Format(time.RFC3339),
		"count":   len(items),
		"items":   items,
	})
}

// DiffEntry is the compact per-PID record used for parity diffing between
// the agent's local view and the server's view of the same workload. Score
// is intentionally omitted — it can drift between sides while role+signals
// remain stable, which is the parity bar we care about.
type DiffEntry struct {
	Name    string   `json:"name"`
	Role    string   `json:"role"`
	Signals []string `json:"signals,omitempty"`
}

// BuildDiffMap produces the {pid: DiffEntry} map served by /diff/* endpoints.
// Exported so the agent-side debug server emits an identical shape.
func BuildDiffMap(snap []CandidateSnapshot) map[string]DiffEntry {
	out := make(map[string]DiffEntry, len(snap))
	for _, c := range snap {
		signals := shared.DedupStrings(c.Signals)
		sort.Strings(signals)
		out[fmt.Sprintf("%d", c.PID)] = DiffEntry{
			Name:    c.Name,
			Role:    c.Role,
			Signals: signals,
		}
	}
	return out
}

func handleDiff(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimPrefix(r.URL.Path, "/diff/")
	if target == "" {
		http.NotFound(w, r)
		return
	}
	if target == "local" {
		debugAPI.mu.RLock()
		snap := append([]CandidateSnapshot(nil), debugAPI.latest...)
		debugAPI.mu.RUnlock()
		writeJSON(w, BuildDiffMap(snap))
		return
	}
	store := currentAgentStore()
	if store == nil {
		writeNotServerMode(w)
		return
	}
	cands, _, ok := store.HostSnapshot(target)
	if !ok {
		http.Error(w, "host not found", http.StatusNotFound)
		return
	}
	shared.ClassifyMu.RLock()
	snap := CandidatesToSnapshots(cands)
	shared.ClassifyMu.RUnlock()
	writeJSON(w, BuildDiffMap(snap))
}

// FPReportEntry is the per-PID verdict trace returned by /fp-report.
// It is intentionally derived from stateless heuristics so the same function
// can be re-run after a rule change to diff before/after — no hidden state.
type FPReportEntry struct {
	PID                      int      `json:"pid"`
	Host                     string   `json:"host,omitempty"`
	Name                     string   `json:"name"`
	ExePath                  string   `json:"exe_path,omitempty"`
	Company                  string   `json:"company,omitempty"`
	Role                     string   `json:"role"`
	Score                    int      `json:"score"`
	Signals                  []string `json:"signals,omitempty"`
	Reasons                  []string `json:"reasons,omitempty"`
	SHA256                   string   `json:"sha256,omitempty"`
	OperatorLabel            string   `json:"operator_label,omitempty"`
	KnownVendorPath          bool     `json:"known_vendor_path"`
	KnownNetworkActive       bool     `json:"known_network_active"`
	KnownUpdater             bool     `json:"known_updater"`
	Signed                   bool     `json:"signed"`
	SignatureTrust           string   `json:"signature_trust,omitempty"`
	AuthenticodeTrust        string   `json:"authenticode_trust,omitempty"`
	AuthenticodePublisher    string   `json:"authenticode_publisher,omitempty"`
	AuthenticodeOCSPChecked  bool     `json:"authenticode_ocsp_checked"`
	OnlineKnownBenign        bool     `json:"online_known_benign"`
	OnlineKnownMalicious     bool     `json:"online_known_malicious"`
	PkgOwned                 bool     `json:"pkg_owned"`
	PkgOwnerName             string   `json:"pkg_owner_name,omitempty"`
	PublisherDNSAligned      bool     `json:"publisher_dns_aligned"`
	OnlineEvidence           []string `json:"online_evidence,omitempty"`
	BenignControlClient      bool     `json:"benign_control_client"`
	BenignOverridden         bool     `json:"benign_overridden_by_behavior"`
	TrafficVerified          bool     `json:"traffic_verified"`
	StrongEvidence           bool     `json:"strong_evidence"`
	ActiveProxying           bool     `json:"active_proxying"`
	DecisiveSignal           string   `json:"decisive_signal,omitempty"`
	VendorUpdateDemoted      bool     `json:"vendor_update_demoted"`
	FPShapeScore             int      `json:"fp_shape_score"`
	FPShapeReasons           []string `json:"fp_shape_reasons,omitempty"`
	FPShapeBlockers          []string `json:"fp_shape_blockers,omitempty"`
	FPShapeHardBlockers      []string `json:"fp_shape_hard_blockers,omitempty"`
	FPShapeSoftBlockers      []string `json:"fp_shape_soft_blockers,omitempty"`
	FPShapeSoftOverride      bool     `json:"fp_shape_soft_override"`
	FPShapeOverrideReason    string   `json:"fp_shape_override_reason,omitempty"`
	FPShapeVendorSignalCount int      `json:"fp_shape_vendor_signal_count"`
	FPShapeWouldDemote       bool     `json:"fp_shape_would_demote"`
	FPShapeDemoted           bool     `json:"fp_shape_demoted"`
	WouldSuppress            bool     `json:"would_suppress"`
	SuppressReason           string   `json:"suppress_reason,omitempty"`

	// Tier-2 hard-distinguisher trace. Populated from
	// shared.HasHardDistinguisher so operators can see, per candidate,
	// which Tier-2 signals fired (or why none did). Used to diagnose
	// cases where a beacon candidate unexpectedly demotes to
	// outbound — if Tier2Hits is empty, DemoteShapeOnlyControlRole
	// fell through to the demote path.
	Tier2Hits              []string `json:"tier2_hits,omitempty"`
	Tier2Preserved         bool     `json:"tier2_preserved"`
	ShapeOnlyRole          bool     `json:"shape_only_role"`
	BeaconIntervalMs       int      `json:"beacon_interval_ms,omitempty"`
	BeaconJitter           float64  `json:"beacon_jitter,omitempty"`
	HasInternalConn        bool     `json:"has_internal_conn"`
	HasNonLoopbackListener bool     `json:"has_non_loopback_listener"`
	ConnInternalRemotes    int      `json:"conn_internal_remotes"`
	ConnExternalRemotes    int      `json:"conn_external_remotes"`
	TunnelingState         bool     `json:"tunneling_state"`
}

// decisiveFPSignals are the signals that always defeat vendor-identity
// suppression (per roles.go:182). If any is present, WouldSuppress is false.
var decisiveFPSignals = []string{
	"pivot-ssh-tunnel-flags",
	"pivot-named-pipe-c2-pattern",
	"beacon-syn-cycle-cadence",
	"beacon-pattern-confirmed",
	"strong-session",
	"persistent-control",
	"tunnel",
	"tunneling",
	"pivot",
	"lateral-pivot-shape",
}

// BuildFPReport computes per-candidate FP verdict trace from stateless
// heuristics. Shape is stable so /fp-report output can be diffed across
// rule changes to see what a change would suppress (or stop suppressing).
//
// HTTP handler thread; the live scanner concurrently writes the global
// classifier maps via detection.Classify. populateTier2Trace -> CandidateStateUnsafe
// reads those maps, so RLock for the duration to serialize against the writer.
func BuildFPReport(cands []shared.Candidate) []FPReportEntry {
	shared.ClassifyMu.RLock()
	defer shared.ClassifyMu.RUnlock()
	out := make([]FPReportEntry, 0, len(cands))
	for i := range cands {
		c := &cands[i]
		if c.Proc == nil {
			continue
		}
		entry := FPReportEntry{
			PID:                     c.Proc.Pid,
			Host:                    c.Host,
			Name:                    c.Proc.Name,
			ExePath:                 c.Proc.ExePath,
			Company:                 c.Proc.Company,
			Role:                    c.Role,
			Score:                   c.Score,
			Signals:                 shared.DedupStrings(c.Signals),
			Reasons:                 shared.DedupStrings(c.Reasons),
			SHA256:                  c.Proc.SHA256,
			KnownVendorPath:         shared.IsKnownVendorProcess(c.Proc),
			KnownNetworkActive:      shared.IsKnownNetworkActiveProcess(c.Proc),
			KnownUpdater:            shared.IsKnownUpdaterProcess(c.Proc),
			Signed:                  c.Proc.Signed,
			SignatureTrust:          c.Proc.SignatureTrust,
			AuthenticodeTrust:       c.Proc.SignatureTrust,
			AuthenticodePublisher:   c.Proc.Publisher,
			AuthenticodeOCSPChecked: c.Proc.AuthenticodeOCSPSeen,
			OnlineKnownBenign:       c.Proc.Signed && c.Proc.AuthenticodeOCSPSeen,
			OnlineKnownMalicious:    c.Proc.SignatureTrust == shared.SignatureTrustUntrusted,
			PkgOwned:                c.Proc.PkgOwned,
			PkgOwnerName:            c.Proc.PkgOwnerName,
			PublisherDNSAligned:     c.Proc.PublisherDNSAligned,
			OnlineEvidence:          append([]string(nil), c.Proc.OnlineEvidence...),
			BenignControlClient:     shared.IsLikelyBenignControlClient(c.Proc),
			BenignOverridden:        shared.BenignOverriddenByBehavior(c),
			TrafficVerified:         c.TrafficVerified,
			StrongEvidence:          c.StrongEvidence,
			ActiveProxying:          c.ActiveProxying,
		}
		for _, r := range c.Reasons {
			if r == shared.VendorUpdateCadenceReason {
				entry.VendorUpdateDemoted = true
			}
			if r == shared.VendorFPShapeReason {
				entry.FPShapeDemoted = true
			}
		}

		// Re-run the vendor-agnostic FP evaluator for the report so
		// /fp-report shows what a given threshold would catch, regardless
		// of whether the runtime actually demoted. Same code path as the
		// runtime rule — no drift.
		shape := shared.EvaluateVendorFPShape(c, shared.LoadedFPThreshold())
		entry.FPShapeScore = shape.Score
		entry.FPShapeReasons = shape.Reasons
		entry.FPShapeBlockers = shape.Blockers
		entry.FPShapeHardBlockers = shape.HardBlockers
		entry.FPShapeSoftBlockers = shape.SoftBlockers
		entry.FPShapeSoftOverride = shape.SoftOverride
		entry.FPShapeOverrideReason = shape.OverrideReason
		entry.FPShapeVendorSignalCount = shape.VendorSignalCount
		entry.FPShapeWouldDemote = shape.WouldDemote

		if c.Proc.SHA256 != "" {
			if label := shared.LookupOperatorLabel(c.Proc.SHA256); label != nil {
				entry.OperatorLabel = label.Verdict
			}
		}
		entry.DecisiveSignal = firstSignalMatch(c.Signals, decisiveFPSignals)
		entry.WouldSuppress, entry.SuppressReason = evaluateSuppression(&entry)
		entry.populateTier2Trace(c)
		out = append(out, entry)
	}
	return out
}

// populateTier2Trace mirrors the DemoteShapeOnlyControlRole Tier-2 evaluation
// so operators can curl /fp-report and see *why* a specific beacon
// was or wasn't preserved. Read-only — never mutates the candidate.
func (e *FPReportEntry) populateTier2Trace(c *shared.Candidate) {
	preserved, hits := shared.HasHardDistinguisher(c)
	e.Tier2Hits = hits
	e.Tier2Preserved = preserved
	e.ShapeOnlyRole = shared.IsShapeOnlyCandidateRoleForReport(c.Role)
	e.BeaconIntervalMs = c.BeaconIntervalMs
	e.BeaconJitter = c.BeaconJitter
	e.HasNonLoopbackListener = shared.HasNonLoopbackListenerForReport(c)
	e.TunnelingState = shared.CandidateStateUnsafe(*c) == "tunneling"
	internal := map[string]bool{}
	external := map[string]bool{}
	for _, conn := range c.Conns {
		if conn.RemoteAddress == "" {
			continue
		}
		if shared.IsLoopbackIP(conn.RemoteAddress) {
			continue
		}
		if shared.IsInternalIP(conn.RemoteAddress) {
			internal[conn.RemoteAddress] = true
		} else {
			external[conn.RemoteAddress] = true
		}
	}
	e.ConnInternalRemotes = len(internal)
	e.ConnExternalRemotes = len(external)
	e.HasInternalConn = len(internal) > 0
}

func firstSignalMatch(have []string, want []string) string {
	set := make(map[string]bool, len(have))
	for _, s := range have {
		set[s] = true
	}
	for _, s := range want {
		if set[s] {
			return s
		}
	}
	return ""
}

// evaluateSuppression decides whether a vendor-FP rule *would* demote this
// candidate. Decisive behavioral signals always block suppression. This is
// the single place rule additions should touch so /fp-report stays truthful.
func evaluateSuppression(e *FPReportEntry) (bool, string) {
	if e.DecisiveSignal != "" {
		return false, "decisive-signal:" + e.DecisiveSignal
	}
	if len(e.FPShapeHardBlockers) > 0 {
		return false, "fp-shape-hard-blocker:" + e.FPShapeHardBlockers[0]
	}
	if len(e.FPShapeSoftBlockers) > 0 && !e.FPShapeSoftOverride {
		return false, "fp-shape-soft-blocker:" + e.FPShapeSoftBlockers[0]
	}
	if e.BenignOverridden {
		return false, "benign-overridden-by-behavior"
	}
	if e.FPShapeDemoted || e.FPShapeWouldDemote {
		return true, shared.VendorFPShapeReason
	}
	if e.VendorUpdateDemoted {
		return true, shared.VendorUpdateCadenceReason
	}
	if e.KnownUpdater {
		return true, "known-updater"
	}
	if e.KnownNetworkActive {
		return true, "known-network-active"
	}
	if e.Signed && e.SignatureTrust == shared.SignatureTrustTrusted && !e.StrongEvidence {
		return true, shared.SignatureTrustedReason
	}
	if e.KnownVendorPath && e.TrafficVerified && !e.StrongEvidence {
		return true, "known-vendor-path+traffic-verified"
	}
	if e.BenignControlClient && !e.StrongEvidence {
		return true, "benign-beacon-client"
	}
	return false, ""
}

func handleFPReport(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/fp-report")
	rest = strings.TrimPrefix(rest, "/")

	var (
		cands []shared.Candidate
		host  string
	)
	if rest == "" || rest == "local" {
		debugAPI.mu.RLock()
		cands = append([]shared.Candidate(nil), debugAPI.latestRaw...)
		host = debugAPI.hostScope
		debugAPI.mu.RUnlock()
	} else {
		store := currentAgentStore()
		if store == nil {
			writeNotServerMode(w)
			return
		}
		hostCands, _, ok := store.HostSnapshot(rest)
		if !ok {
			http.Error(w, "host not found", http.StatusNotFound)
			return
		}
		cands = hostCands
		host = rest
	}

	entries := BuildFPReport(cands)
	q := r.URL.Query()
	if only := strings.TrimSpace(q.Get("only")); only == "suppressed" {
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
	writeJSON(w, map[string]interface{}{
		"host":       host,
		"count":      len(entries),
		"suppressed": suppressed,
		"entries":    entries,
	})
}

// handleOnlineStatus surfaces the signature worker's posture + counters.
func handleOnlineStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"signature": shared.SnapshotOnlineStatus(),
		"dns":       shared.SnapshotDNSStats(),
	})
}

// handleOnlineVerdict returns the cached Authenticode verdict for a given
// PID (looked up against whichever snapshot — local or per-host — applies).
// Returns 404 when the PID is unknown or no verdict is cached.
func handleOnlineVerdict(w http.ResponseWriter, r *http.Request) {
	pidStr := strings.TrimPrefix(r.URL.Path, "/online/verdict/")
	pidStr = strings.TrimSpace(pidStr)
	if pidStr == "" {
		http.NotFound(w, r)
		return
	}

	// Walk local snapshot + any agent-store hosts to find the PID.
	var exePath string
	debugAPI.mu.RLock()
	for _, c := range debugAPI.latestRaw {
		if c.Proc != nil && fmt.Sprintf("%d", c.Proc.Pid) == pidStr {
			exePath = c.Proc.ExePath
			break
		}
	}
	debugAPI.mu.RUnlock()

	if exePath == "" {
		if store := currentAgentStore(); store != nil {
			for _, host := range store.HostList() {
				cands, _, ok := store.HostSnapshot(host.Host)
				if !ok {
					continue
				}
				for i := range cands {
					if cands[i].Proc != nil && fmt.Sprintf("%d", cands[i].Proc.Pid) == pidStr {
						exePath = cands[i].Proc.ExePath
						break
					}
				}
				if exePath != "" {
					break
				}
			}
		}
	}

	if exePath == "" {
		http.Error(w, "pid not found", http.StatusNotFound)
		return
	}
	verdict := shared.LookupVerdictForPath(exePath)
	if verdict == nil {
		writeJSON(w, map[string]interface{}{
			"pid":      pidStr,
			"exe_path": exePath,
			"verdict":  nil,
		})
		return
	}
	writeJSON(w, map[string]interface{}{
		"pid":      pidStr,
		"exe_path": exePath,
		"verdict":  verdict,
	})
}

// handleOperatorLabels — GET list of all labels.
func handleOperatorLabels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	labels := shared.ListOperatorLabels()
	writeJSON(w, map[string]interface{}{
		"count":  len(labels),
		"labels": labels,
	})
}

// handleOperatorLabel — POST set/update, GET on query-string lookup.
// POST body: {"sha256":"...", "verdict":"benign|malicious", "reason":"..."}
func handleOperatorLabel(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req struct {
			SHA256  string `json:"sha256"`
			Verdict string `json:"verdict"`
			Reason  string `json:"reason,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := shared.SetOperatorLabel(req.SHA256, req.Verdict, req.Reason); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		label := shared.LookupOperatorLabel(req.SHA256)
		writeJSON(w, map[string]interface{}{"ok": true, "label": label})
	default:
		http.Error(w, "use POST with {sha256, verdict, reason}", http.StatusMethodNotAllowed)
	}
}

// handleOperatorLabelByHash — GET single label, DELETE clears.
// Path: /operator/label/<sha256>
func handleOperatorLabelByHash(w http.ResponseWriter, r *http.Request) {
	hash := strings.TrimPrefix(r.URL.Path, "/operator/label/")
	hash = strings.TrimSpace(hash)
	if hash == "" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		label := shared.LookupOperatorLabel(hash)
		if label == nil {
			http.Error(w, "no label for hash", http.StatusNotFound)
			return
		}
		writeJSON(w, label)
	case http.MethodDelete:
		if err := shared.ClearOperatorLabel(hash); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]interface{}{"ok": true})
	default:
		http.Error(w, "GET or DELETE", http.StatusMethodNotAllowed)
	}
}

// handleFPReportSummary returns aggregate counts derived from BuildFPReport
// — per-role, per-suppression-reason, per-signal, per-FP-shape-blocker.
// Callers building dashboards or alerting on role mix don't have to pull
// the full entry list and aggregate client-side.
func handleFPReportSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	debugAPI.mu.RLock()
	cands := append([]shared.Candidate(nil), debugAPI.latestRaw...)
	host := debugAPI.hostScope
	cycle := debugAPI.cycle
	updated := debugAPI.updatedAt
	debugAPI.mu.RUnlock()

	entries := BuildFPReport(cands)

	roleCounts := make(map[string]int)
	stateCounts := make(map[string]int)
	signalCounts := make(map[string]int)
	blockerCounts := make(map[string]int)
	suppressReasonCounts := make(map[string]int)
	suppressed := 0
	wouldDemote := 0
	tier2Preserved := 0
	strongEvidence := 0
	activeProxying := 0
	tunnelingNow := 0

	for i := range entries {
		e := &entries[i]
		roleCounts[e.Role]++
		if e.TunnelingState {
			tunnelingNow++
		}
		if e.WouldSuppress {
			suppressed++
			if r := strings.TrimSpace(e.SuppressReason); r != "" {
				suppressReasonCounts[r]++
			}
		}
		if e.FPShapeWouldDemote {
			wouldDemote++
		}
		if e.Tier2Preserved {
			tier2Preserved++
		}
		if e.StrongEvidence {
			strongEvidence++
		}
		if e.ActiveProxying {
			activeProxying++
		}
		for _, s := range e.Signals {
			signalCounts[s]++
		}
		for _, b := range e.FPShapeBlockers {
			blockerCounts[b]++
		}
	}

	// State histogram over the current candidate set (reused from classifier
	// state rather than re-derived, so what the user sees on the dashboard
	// matches what this endpoint reports).
	shared.ClassifyMu.RLock()
	for i := range cands {
		s := shared.CandidateStateUnsafe(cands[i])
		stateCounts[s]++
	}
	shared.ClassifyMu.RUnlock()

	writeJSON(w, map[string]interface{}{
		"host":                  host,
		"cycle":                 cycle,
		"updated":               updated.Format(time.RFC3339),
		"total":                 len(entries),
		"suppressed":            suppressed,
		"fp_shape_would_demote": wouldDemote,
		"tier2_preserved":       tier2Preserved,
		"strong_evidence":       strongEvidence,
		"active_proxying":       activeProxying,
		"tunneling_now":         tunnelingNow,
		"role_counts":           roleCounts,
		"state_counts":          stateCounts,
		"signal_counts":         signalCounts,
		"fp_shape_blockers":     blockerCounts,
		"suppress_reasons":      suppressReasonCounts,
	})
}

// handleMLShadow returns the current shadow-comparison summary — rolling
// agreement rate, qualify / degrade thresholds, and the demoted flag.
// Useful for operators tracking ML health without opening the TUI.
func handleMLShadow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	agree, disagree := model.ShadowCounts()
	total := agree + disagree
	rate := 0.0
	if total > 0 {
		rate = float64(agree) / float64(total)
	}
	writeJSON(w, map[string]interface{}{
		"agree":               agree,
		"disagree":            disagree,
		"total":               total,
		"agreement_rate":      rate,
		"qualified":           model.MLQualified(),
		"demoted":             model.MLDemoted(),
		"qualify_threshold":   model.ShadowQualifyAgreement,
		"qualify_predictions": model.ShadowQualifyPredictions,
		"degrade_floor":       model.ShadowDegradeFloor,
	})
}

// handleMLDisagreements returns the last N ML-vs-rule disagreements
// captured by RecordShadowDisagreement, in chronological order (oldest
// first). Operators use this to tune the model by inspecting the
// actual disagreement population instead of tailing logs.
func handleMLDisagreements(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	entries := model.ShadowDisagreements()
	writeJSON(w, map[string]interface{}{
		"count":   len(entries),
		"entries": entries,
	})
}

func writeNotServerMode(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"error":"not server mode"}` + "\n"))
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
