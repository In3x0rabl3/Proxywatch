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
	SeenSeconds            int      `json:"seen_seconds"`
	ListenerCount          int      `json:"listener_count"`
	ConnCount              int      `json:"conn_count"`
	IOReadBps              uint64   `json:"io_read_bps"`
	IOWriteBps             uint64   `json:"io_write_bps"`
	MLRole                 string   `json:"ml_role,omitempty"`
	MLConfidence           float64  `json:"ml_confidence,omitempty"`
	SuggestedRole          string   `json:"suggested_role,omitempty"`
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
		State:                  shared.CandidateState(*c),
		Score:                  c.Score,
		Confidence:             c.Confidence,
		ActiveProxying:         c.ActiveProxying,
		StrongEvidence:         c.StrongEvidence,
		TrafficVerified:        c.TrafficVerified,
		Signals:                append([]string(nil), c.Signals...),
		Reasons:                append([]string(nil), c.Reasons...),
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
	mux.HandleFunc("/agents", handleAgents)
	mux.HandleFunc("/agent/", handleAgentScoped)
	mux.HandleFunc("/diff/", handleDiff)
	mux.HandleFunc("/fp-report", handleFPReport)
	mux.HandleFunc("/fp-report/", handleFPReport)
	mux.HandleFunc("/online/status", handleOnlineStatus)
	mux.HandleFunc("/online/verdict/", handleOnlineVerdict)
	mux.HandleFunc("/operator/labels", handleOperatorLabels)
	mux.HandleFunc("/operator/label", handleOperatorLabel)
	mux.HandleFunc("/operator/label/", handleOperatorLabelByHash)
	registerSIEMDebugRoutes(mux)

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
	snap := CandidatesToSnapshots(cands)

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
		signals := append([]string(nil), c.Signals...)
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
	writeJSON(w, BuildDiffMap(CandidatesToSnapshots(cands)))
}

// FPReportEntry is the per-PID verdict trace returned by /fp-report.
// It is intentionally derived from stateless heuristics so the same function
// can be re-run after a rule change to diff before/after — no hidden state.
type FPReportEntry struct {
	PID                 int      `json:"pid"`
	Host                string   `json:"host,omitempty"`
	Name                string   `json:"name"`
	ExePath             string   `json:"exe_path,omitempty"`
	Company             string   `json:"company,omitempty"`
	Role                string   `json:"role"`
	Score               int      `json:"score"`
	Signals             []string `json:"signals,omitempty"`
	Reasons             []string `json:"reasons,omitempty"`
	SHA256              string   `json:"sha256,omitempty"`
	OperatorLabel       string   `json:"operator_label,omitempty"`
	KnownVendorPath     bool     `json:"known_vendor_path"`
	KnownNetworkActive  bool     `json:"known_network_active"`
	KnownUpdater        bool     `json:"known_updater"`
	Signed                 bool   `json:"signed"`
	SignatureTrust         string `json:"signature_trust,omitempty"`
	AuthenticodeTrust      string `json:"authenticode_trust,omitempty"`
	AuthenticodePublisher  string `json:"authenticode_publisher,omitempty"`
	AuthenticodeOCSPChecked bool  `json:"authenticode_ocsp_checked"`
	OnlineKnownBenign      bool     `json:"online_known_benign"`
	OnlineKnownMalicious   bool     `json:"online_known_malicious"`
	PkgOwned               bool     `json:"pkg_owned"`
	PkgOwnerName           string   `json:"pkg_owner_name,omitempty"`
	PublisherDNSAligned    bool     `json:"publisher_dns_aligned"`
	OnlineEvidence         []string `json:"online_evidence,omitempty"`
	BenignControlClient bool     `json:"benign_control_client"`
	BenignOverridden    bool     `json:"benign_overridden_by_behavior"`
	TrafficVerified     bool     `json:"traffic_verified"`
	StrongEvidence      bool     `json:"strong_evidence"`
	ActiveProxying      bool     `json:"active_proxying"`
	DecisiveSignal      string   `json:"decisive_signal,omitempty"`
	VendorUpdateDemoted bool     `json:"vendor_update_demoted"`
	FPShapeScore              int      `json:"fp_shape_score"`
	FPShapeReasons            []string `json:"fp_shape_reasons,omitempty"`
	FPShapeBlockers           []string `json:"fp_shape_blockers,omitempty"`
	FPShapeHardBlockers       []string `json:"fp_shape_hard_blockers,omitempty"`
	FPShapeSoftBlockers       []string `json:"fp_shape_soft_blockers,omitempty"`
	FPShapeSoftOverride       bool     `json:"fp_shape_soft_override"`
	FPShapeOverrideReason     string   `json:"fp_shape_override_reason,omitempty"`
	FPShapeVendorSignalCount  int      `json:"fp_shape_vendor_signal_count"`
	FPShapeWouldDemote        bool     `json:"fp_shape_would_demote"`
	FPShapeDemoted            bool     `json:"fp_shape_demoted"`
	WouldSuppress       bool     `json:"would_suppress"`
	SuppressReason      string   `json:"suppress_reason,omitempty"`

	// Tier-2 hard-distinguisher trace. Populated from
	// shared.HasHardDistinguisher so operators can see, per candidate,
	// which Tier-2 signals fired (or why none did). Used to diagnose
	// cases where a control-channel candidate unexpectedly demotes to
	// outbound — if Tier2Hits is empty, DemoteShapeOnlyControlRole
	// fell through to the demote path.
	Tier2Hits               []string `json:"tier2_hits,omitempty"`
	Tier2Preserved          bool     `json:"tier2_preserved"`
	ShapeOnlyRole           bool     `json:"shape_only_role"`
	BeaconIntervalMs        int      `json:"beacon_interval_ms,omitempty"`
	BeaconJitter            float64  `json:"beacon_jitter,omitempty"`
	HasInternalConn         bool     `json:"has_internal_conn"`
	HasNonLoopbackListener  bool     `json:"has_non_loopback_listener"`
	ConnInternalRemotes     int      `json:"conn_internal_remotes"`
	ConnExternalRemotes     int      `json:"conn_external_remotes"`
	TunnelingState          bool     `json:"tunneling_state"`
}

// decisiveFPSignals are the signals that always defeat vendor-identity
// suppression (per roles.go:182). If any is present, WouldSuppress is false.
var decisiveFPSignals = []string{
	"pivot-ssh-tunnel-flags",
	"pivot-named-pipe-c2-pattern",
	"beacon-syn-cycle-cadence",
	"beacon-pattern-confirmed",
	"strong-control-session",
	"persistent-control",
	"tunnel",
	"tunneling",
	"control-pivot",
	"lateral-pivot-shape",
}

// BuildFPReport computes per-candidate FP verdict trace from stateless
// heuristics. Shape is stable so /fp-report output can be diffed across
// rule changes to see what a change would suppress (or stop suppressing).
func BuildFPReport(cands []shared.Candidate) []FPReportEntry {
	out := make([]FPReportEntry, 0, len(cands))
	for i := range cands {
		c := &cands[i]
		if c.Proc == nil {
			continue
		}
		entry := FPReportEntry{
			PID:                 c.Proc.Pid,
			Host:                c.Host,
			Name:                c.Proc.Name,
			ExePath:             c.Proc.ExePath,
			Company:             c.Proc.Company,
			Role:                c.Role,
			Score:               c.Score,
			Signals:             append([]string(nil), c.Signals...),
			Reasons:             append([]string(nil), c.Reasons...),
			SHA256:              c.Proc.SHA256,
			KnownVendorPath:     shared.IsKnownVendorProcess(c.Proc),
			KnownNetworkActive:  shared.IsKnownNetworkActiveProcess(c.Proc),
			KnownUpdater:        shared.IsKnownUpdaterProcess(c.Proc),
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
			BenignControlClient: shared.IsLikelyBenignControlClient(c.Proc),
			BenignOverridden:    shared.BenignOverriddenByBehavior(c),
			TrafficVerified:     c.TrafficVerified,
			StrongEvidence:      c.StrongEvidence,
			ActiveProxying:      c.ActiveProxying,
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
// so operators can curl /fp-report and see *why* a specific control-channel
// was or wasn't preserved. Read-only — never mutates the candidate.
func (e *FPReportEntry) populateTier2Trace(c *shared.Candidate) {
	preserved, hits := shared.HasHardDistinguisher(c)
	e.Tier2Hits = hits
	e.Tier2Preserved = preserved
	e.ShapeOnlyRole = shared.IsShapeOnlyCandidateRoleForReport(c.Role)
	e.BeaconIntervalMs = c.BeaconIntervalMs
	e.BeaconJitter = c.BeaconJitter
	e.HasNonLoopbackListener = shared.HasNonLoopbackListenerForReport(c)
	e.TunnelingState = shared.CandidateState(*c) == "tunneling"
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
		return true, "benign-control-client"
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
