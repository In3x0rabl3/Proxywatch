package output

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"proxywatch/internal/shared"
)

// ── shared export schema (used by TUI + HTTP) ───────────────────────────────

// SIEMExportSchema is the top-level version string emitted in export docs.
const SIEMExportSchema = "proxywatch-siem-export-v1"

// SIEMExport is the shape produced by both the TUI `e` handler and the
// POST /siem/export endpoint. Exported so keys/siem.go can call BuildSIEMExport
// without re-implementing the shape.
type SIEMExport struct {
	Schema     string          `json:"schema"`
	ExportedAt string          `json:"exported_at"`
	Host       string          `json:"host"`
	Formats    []string        `json:"formats"`
	Count      int             `json:"count"`
	Detections []SIEMDetection `json:"detections"`
}

type SIEMDetection struct {
	Candidate SIEMCandidateView `json:"candidate"`
	Rules     map[string]any    `json:"rules"`
}

type SIEMCandidateView struct {
	PID              int           `json:"pid"`
	Name             string        `json:"name"`
	Host             string        `json:"host"`
	Role             string        `json:"role"`
	ControlSubtype   string        `json:"control_subtype,omitempty"`
	Score            int           `json:"score"`
	Confidence       int           `json:"confidence"`
	SHA256           string        `json:"sha256,omitempty"`
	ExePath          string        `json:"exe_path,omitempty"`
	BeaconIntervalMs int           `json:"beacon_interval_ms,omitempty"`
	BeaconJitter     float64       `json:"beacon_jitter,omitempty"`
	ControlChannel   *SIEMConnView `json:"control_channel,omitempty"`
	Signals          []string      `json:"signals,omitempty"`
	Reasons          []string      `json:"reasons,omitempty"`
}

type SIEMConnView struct {
	RemoteAddress string `json:"remote_address"`
	RemotePort    int    `json:"remote_port"`
}

// BuildSIEMDetection composes the candidate view + per-format rule map for a
// single candidate. Formats with a false mask bit are omitted. Index order
// matches SIEMFormatNames: 0=splunk 1=kql 2=sigma 3=yara 4=suricata.
func BuildSIEMDetection(c *shared.Candidate, mask [5]bool) SIEMDetection {
	view := SIEMCandidateView{
		Host:             shared.DisplayHost(c.Host),
		Role:             c.Role,
		ControlSubtype:   c.ControlSubtype,
		Score:            c.Score,
		Confidence:       c.Confidence,
		BeaconIntervalMs: c.BeaconIntervalMs,
		BeaconJitter:     c.BeaconJitter,
		Signals:          append([]string(nil), c.Signals...),
		Reasons:          append([]string(nil), c.Reasons...),
	}
	if c.Proc != nil {
		view.PID = c.Proc.Pid
		view.Name = c.Proc.Name
		view.SHA256 = c.Proc.SHA256
		view.ExePath = c.Proc.ExePath
	}
	if c.ControlChannel != nil {
		view.ControlChannel = &SIEMConnView{
			RemoteAddress: c.ControlChannel.RemoteAddress,
			RemotePort:    c.ControlChannel.RemotePort,
		}
	}
	rules := map[string]any{}
	item := MakeDefenderCandidateItem(*c, c.Host)
	if mask[0] {
		rules["splunk"] = item.Queries.Splunk
	}
	if mask[1] {
		rules["kql"] = item.Queries.KQL
	}
	if mask[2] && item.Queries.SigmaLike != nil {
		rules["sigma"] = item.Queries.SigmaLike
	}
	if mask[3] {
		if r := BuildYARARule(c); r != "" {
			rules["yara"] = r
		}
	}
	if mask[4] {
		if r := BuildSuricataRule(c); r != "" {
			rules["suricata"] = r
		}
	}
	return SIEMDetection{Candidate: view, Rules: rules}
}

// BuildSIEMExport is the shared constructor used by both the TUI file writer
// and the HTTP endpoint so their documents are byte-for-byte equivalent.
func BuildSIEMExport(cands []shared.Candidate, mask [5]bool, host string, now time.Time) SIEMExport {
	detections := make([]SIEMDetection, 0, len(cands))
	for i := range cands {
		detections = append(detections, BuildSIEMDetection(&cands[i], mask))
	}
	return SIEMExport{
		Schema:     SIEMExportSchema,
		ExportedAt: now.UTC().Format(time.RFC3339),
		Host:       shared.DisplayHost(host),
		Formats:    SIEMFormatNames(mask),
		Count:      len(detections),
		Detections: detections,
	}
}

// SIEMFormatNames returns the string names of the true positions in mask.
func SIEMFormatNames(mask [5]bool) []string {
	names := []string{"splunk", "kql", "sigma", "yara", "suricata"}
	out := make([]string, 0, 5)
	for i, n := range names {
		if mask[i] {
			out = append(out, n)
		}
	}
	return out
}

// siemPlatforms maps URL platform values to rule-builder dispatch keys.
var siemPlatforms = map[string]string{
	"splunk":   "splunk",
	"kql":      "kql",
	"elastic":  "kql",
	"sigma":    "sigma",
	"yara":     "yara",
	"suricata": "suricata",
}

// RegisterSIEMDebugRoutes wires /siem/* routes onto an existing mux. Called
// from StartDebugAPIServer.
func registerSIEMDebugRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/siem/rules", handleSIEMRule)
	mux.HandleFunc("/siem/rules/", handleSIEMRule)
	mux.HandleFunc("/siem/bundle", handleSIEMBundle)
	mux.HandleFunc("/siem/bundle/", handleSIEMBundle)
	mux.HandleFunc("/siem/export", handleSIEMExport)
}

// handleSIEMExport — POST {pids:[…], formats:[…]} → SIEMExport JSON.
// Empty pids selects every current candidate; empty formats enables all.
// GET is rejected so operators don't accidentally trigger a large payload.
func handleSIEMExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "use POST with {pids, formats}", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		PIDs    []int    `json:"pids"`
		Formats []string `json:"formats"`
		Host    string   `json:"host,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err.Error() != "EOF" {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	mask := formatMaskFromNames(req.Formats)
	cands := collectExportCandidates(req.PIDs, req.Host)
	if len(cands) == 0 {
		http.Error(w, "no matching candidates", http.StatusNotFound)
		return
	}
	hostScope := strings.TrimSpace(req.Host)
	if hostScope == "" {
		debugAPI.mu.RLock()
		hostScope = debugAPI.hostScope
		debugAPI.mu.RUnlock()
	}
	doc := BuildSIEMExport(cands, mask, hostScope, nowFn())
	writeJSON(w, doc)
}

// formatMaskFromNames converts a list of format names to the 5-bool mask.
// Empty input → all-true (export everything).
func formatMaskFromNames(names []string) [5]bool {
	if len(names) == 0 {
		return [5]bool{true, true, true, true, true}
	}
	order := map[string]int{"splunk": 0, "kql": 1, "elastic": 1, "sigma": 2, "yara": 3, "suricata": 4}
	var mask [5]bool
	for _, n := range names {
		if idx, ok := order[strings.ToLower(strings.TrimSpace(n))]; ok {
			mask[idx] = true
		}
	}
	return mask
}

// collectExportCandidates matches by PID across the local snapshot and every
// agent-store host. Empty pids selects every current candidate from the local
// snapshot (or host scope when provided).
func collectExportCandidates(pids []int, host string) []shared.Candidate {
	want := map[int]bool{}
	for _, p := range pids {
		if p > 0 {
			want[p] = true
		}
	}

	hit := []shared.Candidate{}
	include := func(c shared.Candidate) {
		if c.Proc == nil {
			return
		}
		if len(want) == 0 || want[c.Proc.Pid] {
			hit = append(hit, c)
		}
	}

	host = strings.TrimSpace(host)
	if host == "" || host == "local" {
		debugAPI.mu.RLock()
		raw := append([]shared.Candidate(nil), debugAPI.latestRaw...)
		debugAPI.mu.RUnlock()
		for _, c := range raw {
			include(c)
		}
	}
	if store := currentAgentStore(); store != nil {
		for _, h := range store.HostList() {
			if host != "" && host != "local" && !strings.EqualFold(host, h.Host) {
				continue
			}
			cands, _, ok := store.HostSnapshot(h.Host)
			if !ok {
				continue
			}
			for _, c := range cands {
				include(c)
			}
		}
	}
	return hit
}

// nowFn is overridable for deterministic tests.
var nowFn = time.Now

// handleSIEMRule returns a single rule in the requested platform. Query:
//
//	?sha256=<hex>     — match candidate by exe SHA256
//	?pid=<int>        — match by PID in the local snapshot
//	?platform=<name>  — splunk | kql | sigma | yara | suricata
//
// Returns 404 when the candidate or platform is unknown.
func handleSIEMRule(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	platform := strings.ToLower(strings.TrimSpace(q.Get("platform")))
	if platform == "" {
		platform = "splunk"
	}
	key, ok := siemPlatforms[platform]
	if !ok {
		http.Error(w, "unknown platform; allowed: splunk kql elastic sigma yara suricata", http.StatusBadRequest)
		return
	}

	cand := lookupCandidateByQuery(q)
	if cand == nil {
		http.Error(w, "candidate not found (specify ?sha256= or ?pid=)", http.StatusNotFound)
		return
	}

	rule := buildSIEMRule(cand, key)
	if rule == "" {
		http.Error(w, "rule generation produced no output for this candidate", http.StatusUnprocessableEntity)
		return
	}
	writeJSON(w, map[string]interface{}{
		"pid":      cand.Proc.Pid,
		"host":     shared.DisplayHost(cand.Host),
		"platform": platform,
		"rule":     rule,
	})
}

// handleSIEMBundle returns all five platforms at once for a single candidate.
// Same selectors as /siem/rules.
func handleSIEMBundle(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	cand := lookupCandidateByQuery(q)
	if cand == nil {
		http.Error(w, "candidate not found (specify ?sha256= or ?pid=)", http.StatusNotFound)
		return
	}
	bundle := map[string]string{}
	for _, key := range []string{"splunk", "kql", "sigma", "yara", "suricata"} {
		bundle[key] = buildSIEMRule(cand, key)
	}
	writeJSON(w, map[string]interface{}{
		"pid":   cand.Proc.Pid,
		"host":  shared.DisplayHost(cand.Host),
		"rules": bundle,
	})
}

func lookupCandidateByQuery(q map[string][]string) *shared.Candidate {
	var sha, pid string
	if v := q["sha256"]; len(v) > 0 {
		sha = strings.ToLower(strings.TrimSpace(v[0]))
	}
	if v := q["pid"]; len(v) > 0 {
		pid = strings.TrimSpace(v[0])
	}
	debugAPI.mu.RLock()
	raw := append([]shared.Candidate(nil), debugAPI.latestRaw...)
	debugAPI.mu.RUnlock()
	for i := range raw {
		c := &raw[i]
		if c.Proc == nil {
			continue
		}
		if sha != "" && strings.EqualFold(c.Proc.SHA256, sha) {
			return c
		}
		if pid != "" && fmt.Sprintf("%d", c.Proc.Pid) == pid {
			return c
		}
	}
	if store := currentAgentStore(); store != nil {
		for _, host := range store.HostList() {
			cands, _, ok := store.HostSnapshot(host.Host)
			if !ok {
				continue
			}
			for i := range cands {
				c := &cands[i]
				if c.Proc == nil {
					continue
				}
				if sha != "" && strings.EqualFold(c.Proc.SHA256, sha) {
					return c
				}
				if pid != "" && fmt.Sprintf("%d", c.Proc.Pid) == pid {
					return c
				}
			}
		}
	}
	return nil
}

func buildSIEMRule(c *shared.Candidate, key string) string {
	if c == nil || c.Proc == nil {
		return ""
	}
	switch key {
	case "splunk":
		item := MakeDefenderCandidateItem(*c, c.Host)
		return item.Queries.Splunk
	case "kql":
		item := MakeDefenderCandidateItem(*c, c.Host)
		return item.Queries.KQL
	case "sigma":
		item := MakeDefenderCandidateItem(*c, c.Host)
		if item.Queries.SigmaLike == nil {
			return ""
		}
		b, err := json.MarshalIndent(item.Queries.SigmaLike, "", "  ")
		if err != nil {
			return ""
		}
		return string(b)
	case "yara":
		return BuildYARARule(c)
	case "suricata":
		return BuildSuricataRule(c)
	}
	return ""
}
