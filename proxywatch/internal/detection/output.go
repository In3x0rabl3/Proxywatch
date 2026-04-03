package classifier

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"proxywatch/internal/safeio"
	"proxywatch/internal/shared"
)

const (
	detectionOutputDirName     = "detections"
	defaultDebugOutputName     = "detection-debug.ndjson"
	defaultDefenderOutputName  = "defender-detections.json"
	detectionOutputDirFileMode = 0o700
	detectionOutputFileMode    = 0o600
)

type detectionOutputConfig struct {
	DebugLogPath string
	DefenderPath string
}

type debugDetectionSummary struct {
	Schema         string   `json:"schema"`
	Kind           string   `json:"kind"`
	GeneratedAt    string   `json:"generated_at"`
	Cycle          uint64   `json:"cycle"`
	HostScope      string   `json:"host_scope"`
	MinScore       int      `json:"min_score"`
	RoleFilter     []string `json:"role_filter,omitempty"`
	ScoredCount    int      `json:"scored_count"`
	FlaggedCount   int      `json:"flagged_count"`
	DisplayedCount int      `json:"displayed_count"`
}

type debugDetectionRecord struct {
	Schema      string                `json:"schema"`
	Kind        string                `json:"kind"`
	GeneratedAt string                `json:"generated_at"`
	Cycle       uint64                `json:"cycle"`
	HostScope   string                `json:"host_scope"`
	Displayed   bool                  `json:"displayed"`
	Flagged     bool                  `json:"flagged"`
	State       string                `json:"state"`
	RoleFamily  string                `json:"role_family"`
	Candidate   defenderCandidateItem `json:"candidate"`
}

type defenderExport struct {
	Schema         string                  `json:"schema"`
	GeneratedAt    string                  `json:"generated_at"`
	Cycle          uint64                  `json:"cycle"`
	HostScope      string                  `json:"host_scope"`
	MinScore       int                     `json:"min_score"`
	RoleFilter     []string                `json:"role_filter,omitempty"`
	ScoredCount    int                     `json:"scored_count"`
	FlaggedCount   int                     `json:"flagged_count"`
	DisplayedCount int                     `json:"displayed_count"`
	RoleCounts     map[string]int          `json:"role_counts"`
	StateCounts    map[string]int          `json:"state_counts"`
	SignalCounts   map[string]int          `json:"signal_counts"`
	ReasonCounts   map[string]int          `json:"reason_counts"`
	Detections     []defenderCandidateItem `json:"detections"`
	RoleRules      []defenderRoleRule      `json:"role_rules"`
}

type defenderCandidateItem struct {
	DetectionID      string                      `json:"detection_id"`
	Host             string                      `json:"host"`
	PID              int                         `json:"pid"`
	Process          string                      `json:"process"`
	ProcessPath      string                      `json:"process_path,omitempty"`
	User             string                      `json:"user,omitempty"`
	Role             string                      `json:"role"`
	RoleFamily       string                      `json:"role_family"`
	State            string                      `json:"state"`
	Score            int                         `json:"score"`
	Confidence       int                         `json:"confidence"`
	StrongEvidence   bool                        `json:"strong_evidence"`
	Active           bool                        `json:"active"`
	TrafficVerified  bool                        `json:"traffic_verified"`
	InboundTotal     int                         `json:"inbound_total"`
	TCPInOut         [2]int                      `json:"tcp_in_out"`
	UDPListenerCount int                         `json:"udp_listener_count"`
	ControlSeconds   int                         `json:"control_duration_seconds"`
	Signals          []string                    `json:"signals,omitempty"`
	Reasons          []string                    `json:"reasons,omitempty"`
	ControlChannel   *defenderConnIndicator      `json:"control_channel,omitempty"`
	Connections      []defenderConnIndicator     `json:"connections,omitempty"`
	TCPListeners     []defenderListenerIndicator `json:"tcp_listeners,omitempty"`
	UDPListeners     []defenderListenerIndicator `json:"udp_listeners,omitempty"`
	Queries          defenderQueries             `json:"queries"`
}

type defenderConnIndicator struct {
	Proto         string `json:"proto"`
	LocalAddress  string `json:"local_address,omitempty"`
	LocalPort     int    `json:"local_port,omitempty"`
	RemoteAddress string `json:"remote_address,omitempty"`
	RemotePort    int    `json:"remote_port,omitempty"`
	State         string `json:"state,omitempty"`
	Scope         string `json:"scope"`
}

type defenderListenerIndicator struct {
	Proto        string `json:"proto"`
	LocalAddress string `json:"local_address,omitempty"`
	LocalPort    int    `json:"local_port,omitempty"`
	State        string `json:"state,omitempty"`
}

type defenderQueries struct {
	Splunk    string         `json:"splunk"`
	KQL       string         `json:"kql"`
	SigmaLike map[string]any `json:"sigma_like"`
}

type defenderRoleRule struct {
	Role              string   `json:"role"`
	RoleFamily        string   `json:"role_family"`
	Count             int      `json:"count"`
	TopSignals        []string `json:"top_signals,omitempty"`
	TopReasons        []string `json:"top_reasons,omitempty"`
	SplunkTemplate    string   `json:"splunk_template"`
	KQLTemplate       string   `json:"kql_template"`
	DetectionStrategy string   `json:"detection_strategy"`
}

var (
	detectionOutputMu    sync.RWMutex
	detectionOutputCfg   detectionOutputConfig
	detectionOutputCycle uint64

	lastDetectionOutputErrMu sync.Mutex
	lastDetectionOutputErr   string
	lastDetectionOutputAt    time.Time
)

// ConfigureDetectionOutputs enables/disables debug and defender detection exports.
// Empty paths disable each output independently.
func ConfigureDetectionOutputs(debugPath, defenderPath string) error {
	normalizedDebug, err := normalizeDetectionOutputPath(debugPath, defaultDebugOutputName, ".ndjson")
	if err != nil {
		return fmt.Errorf("normalize debug path: %w", err)
	}
	normalizedDefender, err := normalizeDetectionOutputPath(defenderPath, defaultDefenderOutputName, ".json")
	if err != nil {
		return fmt.Errorf("normalize defender path: %w", err)
	}
	if err := ensureDetectionOutputDir(normalizedDebug); err != nil {
		return fmt.Errorf("prepare debug output: %w", err)
	}
	if err := ensureDetectionOutputDir(normalizedDefender); err != nil {
		return fmt.Errorf("prepare defender output: %w", err)
	}

	detectionOutputMu.Lock()
	detectionOutputCfg = detectionOutputConfig{
		DebugLogPath: normalizedDebug,
		DefenderPath: normalizedDefender,
	}
	detectionOutputMu.Unlock()
	return nil
}

func emitDetectionOutputs(
	now time.Time,
	hostScope string,
	scored []shared.Candidate,
	displayed []shared.Candidate,
	opts shared.ClassifyOptions,
) {
	cfg := currentDetectionOutputConfig()
	if cfg.DebugLogPath == "" && cfg.DefenderPath == "" {
		return
	}

	cycle := nextDetectionOutputCycle()
	flagged := flaggedCandidates(scored, opts.MinScore)

	if cfg.DebugLogPath != "" {
		if err := appendDebugDetectionLog(cfg.DebugLogPath, now, cycle, hostScope, scored, flagged, displayed, opts); err != nil {
			reportDetectionOutputError(err)
		}
	}
	if cfg.DefenderPath != "" {
		if err := writeDefenderDetectionJSON(cfg.DefenderPath, now, cycle, hostScope, scored, flagged, displayed, opts); err != nil {
			reportDetectionOutputError(err)
		}
	}
}

func appendDebugDetectionLog(
	path string,
	now time.Time,
	cycle uint64,
	hostScope string,
	scored []shared.Candidate,
	flagged []shared.Candidate,
	displayed []shared.Candidate,
	opts shared.ClassifyOptions,
) error {
	f, closeFile, err := safeio.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, detectionOutputFileMode)
	if err != nil {
		return err
	}
	defer func() { _ = closeFile() }()

	flaggedSet := candidateKeySet(flagged)
	displayedSet := candidateKeySet(displayed)
	roleFilter := sortedRoleFilter(opts.RoleFilter)

	enc := json.NewEncoder(f)
	if err := enc.Encode(debugDetectionSummary{
		Schema:         "proxywatch-detection-debug-v1",
		Kind:           "summary",
		GeneratedAt:    now.UTC().Format(time.RFC3339Nano),
		Cycle:          cycle,
		HostScope:      shared.DisplayHost(hostScope),
		MinScore:       opts.MinScore,
		RoleFilter:     roleFilter,
		ScoredCount:    len(scored),
		FlaggedCount:   len(flagged),
		DisplayedCount: len(displayed),
	}); err != nil {
		return err
	}

	for _, c := range scored {
		key := shared.CandidateKey(c)
		item := makeDefenderCandidateItem(c, hostScope)
		rec := debugDetectionRecord{
			Schema:      "proxywatch-detection-debug-v1",
			Kind:        "candidate",
			GeneratedAt: now.UTC().Format(time.RFC3339Nano),
			Cycle:       cycle,
			HostScope:   shared.DisplayHost(hostScope),
			Displayed:   displayedSet[key],
			Flagged:     flaggedSet[key],
			State:       shared.CandidateState(c),
			RoleFamily:  shared.RoleFamily(c.Role),
			Candidate:   item,
		}
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	return nil
}

func writeDefenderDetectionJSON(
	path string,
	now time.Time,
	cycle uint64,
	hostScope string,
	scored []shared.Candidate,
	flagged []shared.Candidate,
	displayed []shared.Candidate,
	opts shared.ClassifyOptions,
) error {
	roleCounts := make(map[string]int)
	stateCounts := make(map[string]int)
	signalCounts := make(map[string]int)
	reasonCounts := make(map[string]int)

	items := make([]defenderCandidateItem, 0, len(flagged))
	for _, c := range flagged {
		item := makeDefenderCandidateItem(c, hostScope)
		items = append(items, item)

		roleCounts[c.Role]++
		stateCounts[shared.CandidateState(c)]++
		for _, s := range item.Signals {
			signalCounts[s]++
		}
		for _, r := range item.Reasons {
			reasonCounts[r]++
		}
	}

	exp := defenderExport{
		Schema:         "proxywatch-defender-detections-v1",
		GeneratedAt:    now.UTC().Format(time.RFC3339Nano),
		Cycle:          cycle,
		HostScope:      shared.DisplayHost(hostScope),
		MinScore:       opts.MinScore,
		RoleFilter:     sortedRoleFilter(opts.RoleFilter),
		ScoredCount:    len(scored),
		FlaggedCount:   len(flagged),
		DisplayedCount: len(displayed),
		RoleCounts:     roleCounts,
		StateCounts:    stateCounts,
		SignalCounts:   signalCounts,
		ReasonCounts:   reasonCounts,
		Detections:     items,
		RoleRules:      buildRoleRules(items),
	}

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, detectionOutputDirFileMode); err != nil {
			return err
		}
	}
	f, closeFile, err := safeio.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, detectionOutputFileMode)
	if err != nil {
		return err
	}
	defer func() { _ = closeFile() }()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(exp)
}

func makeDefenderCandidateItem(c shared.Candidate, hostScope string) defenderCandidateItem {
	host := shared.DisplayHost(c.Host)
	if strings.TrimSpace(host) == "" {
		host = shared.DisplayHost(hostScope)
	}
	var procName, procPath, user string
	var pid int
	if c.Proc != nil {
		procName = strings.TrimSpace(c.Proc.Name)
		procPath = strings.TrimSpace(c.Proc.ExePath)
		user = strings.TrimSpace(c.Proc.UserName)
		pid = c.Proc.Pid
	}
	if procName == "" {
		procName = "(unknown)"
	}
	detectionID := buildDetectionID(host, procName, pid, c.Role)
	controlConn := convertControlConn(c.ControlChannel)
	connections := convertConnections(c.Conns)
	tcpListeners, udpListeners := convertListeners(c.Listeners, c.UDPListeners)
	primary := choosePrimaryConnection(controlConn, connections)

	item := defenderCandidateItem{
		DetectionID:      detectionID,
		Host:             host,
		PID:              pid,
		Process:          procName,
		ProcessPath:      procPath,
		User:             user,
		Role:             strings.TrimSpace(c.Role),
		RoleFamily:       shared.RoleFamily(c.Role),
		State:            shared.CandidateState(c),
		Score:            c.Score,
		Confidence:       c.Confidence,
		StrongEvidence:   c.StrongEvidence,
		Active:           c.ActiveProxying,
		TrafficVerified:  c.TrafficVerified,
		InboundTotal:     c.InboundTotal,
		TCPInOut:         [2]int{c.InboundTotal, c.OutTotal},
		UDPListenerCount: len(c.UDPListeners),
		ControlSeconds:   c.ControlDurationSeconds,
		Signals:          sortedUniqueStrings(c.Signals),
		Reasons:          sortedUniqueStrings(c.Reasons),
		ControlChannel:   controlConn,
		Connections:      connections,
		TCPListeners:     tcpListeners,
		UDPListeners:     udpListeners,
	}
	item.Queries = buildDefenderQueries(item, primary)
	return item
}

func buildRoleRules(items []defenderCandidateItem) []defenderRoleRule {
	type aggregate struct {
		count   int
		signals map[string]int
		reasons map[string]int
	}
	roleAgg := make(map[string]*aggregate)
	roleFamily := make(map[string]string)
	for _, item := range items {
		role := strings.TrimSpace(item.Role)
		if role == "" {
			continue
		}
		agg := roleAgg[role]
		if agg == nil {
			agg = &aggregate{
				signals: make(map[string]int),
				reasons: make(map[string]int),
			}
			roleAgg[role] = agg
		}
		agg.count++
		roleFamily[role] = item.RoleFamily
		for _, signal := range item.Signals {
			agg.signals[signal]++
		}
		for _, reason := range item.Reasons {
			agg.reasons[reason]++
		}
	}

	roles := make([]string, 0, len(roleAgg))
	for role := range roleAgg {
		roles = append(roles, role)
	}
	sort.Strings(roles)

	out := make([]defenderRoleRule, 0, len(roles))
	for _, role := range roles {
		agg := roleAgg[role]
		if agg == nil {
			continue
		}
		topSignals := topMapKeys(agg.signals, 8)
		topReasons := topMapKeys(agg.reasons, 6)
		out = append(out, defenderRoleRule{
			Role:              role,
			RoleFamily:        roleFamily[role],
			Count:             agg.count,
			TopSignals:        topSignals,
			TopReasons:        topReasons,
			SplunkTemplate:    roleSplunkTemplate(role, topSignals),
			KQLTemplate:       roleKQLTemplate(role, topSignals),
			DetectionStrategy: roleDetectionStrategy(role, topSignals),
		})
	}
	return out
}

func buildDefenderQueries(item defenderCandidateItem, primary *defenderConnIndicator) defenderQueries {
	splunk := buildSplunkQuery(item, primary)
	kql := buildKQLQuery(item, primary)
	sigma := buildSigmaLike(item, primary)
	return defenderQueries{
		Splunk:    splunk,
		KQL:       kql,
		SigmaLike: sigma,
	}
}

func buildSplunkQuery(item defenderCandidateItem, primary *defenderConnIndicator) string {
	var b strings.Builder
	b.WriteString("index=<endpoint_index> ")
	b.WriteString(`(process_name="`)
	b.WriteString(escapeQueryValue(item.Process))
	b.WriteString(`" OR process_path="`)
	b.WriteString(escapeQueryValue(item.ProcessPath))
	b.WriteString(`")`)
	if item.Host != "" {
		b.WriteString(` host="`)
		b.WriteString(escapeQueryValue(item.Host))
		b.WriteString(`"`)
	}
	if item.PID > 0 {
		b.WriteString(" pid=")
		b.WriteString(strconv.Itoa(item.PID))
	}
	if primary != nil {
		if strings.TrimSpace(primary.RemoteAddress) != "" {
			b.WriteString(` remote_ip="`)
			b.WriteString(escapeQueryValue(primary.RemoteAddress))
			b.WriteString(`"`)
		}
		if primary.RemotePort > 0 {
			b.WriteString(" remote_port=")
			b.WriteString(strconv.Itoa(primary.RemotePort))
		}
	}
	b.WriteString(` | stats count min(_time) as first_seen max(_time) as last_seen by host process_name pid remote_ip remote_port`)
	return b.String()
}

func buildKQLQuery(item defenderCandidateItem, primary *defenderConnIndicator) string {
	var lines []string
	lines = append(lines, "DeviceNetworkEvents")
	if item.Host != "" {
		lines = append(lines, "| where DeviceName =~ \""+escapeQueryValue(item.Host)+"\"")
	}
	if item.PID > 0 {
		lines = append(lines, "| where InitiatingProcessId == "+strconv.Itoa(item.PID))
	}
	if item.Process != "" {
		lines = append(lines, "| where InitiatingProcessFileName =~ \""+escapeQueryValue(item.Process)+"\"")
	}
	if primary != nil {
		if strings.TrimSpace(primary.RemoteAddress) != "" {
			lines = append(lines, "| where RemoteIP == \""+escapeQueryValue(primary.RemoteAddress)+"\"")
		}
		if primary.RemotePort > 0 {
			lines = append(lines, "| where RemotePort == "+strconv.Itoa(primary.RemotePort))
		}
	}
	lines = append(lines, "| summarize hits=count(), first_seen=min(Timestamp), last_seen=max(Timestamp) by DeviceName, InitiatingProcessFileName, InitiatingProcessId, RemoteIP, RemotePort")
	return strings.Join(lines, "\n")
}

func buildSigmaLike(item defenderCandidateItem, primary *defenderConnIndicator) map[string]any {
	selection := map[string]any{
		"ProcessName": item.Process,
		"ProcessId":   item.PID,
		"Role":        item.Role,
	}
	if item.ProcessPath != "" {
		selection["ProcessPath"] = item.ProcessPath
	}
	if item.Host != "" {
		selection["Host"] = item.Host
	}
	if primary != nil {
		if primary.RemoteAddress != "" {
			selection["RemoteIP"] = primary.RemoteAddress
		}
		if primary.RemotePort > 0 {
			selection["RemotePort"] = primary.RemotePort
		}
		if primary.Scope != "" {
			selection["Scope"] = primary.Scope
		}
	}
	return map[string]any{
		"title":     "ProxyWatch " + item.Role + " detection for " + item.Process,
		"logsource": map[string]any{"category": "network_connection"},
		"detection": map[string]any{
			"selection": selection,
			"condition": "selection",
		},
	}
}

func roleSplunkTemplate(role string, signals []string) string {
	if len(signals) == 0 {
		return `index=<endpoint_index> proxywatch_role="` + escapeQueryValue(role) + `"`
	}
	return `index=<endpoint_index> proxywatch_role="` + escapeQueryValue(role) + `" signal IN ("` + strings.Join(signals, `","`) + `")`
}

func roleKQLTemplate(role string, signals []string) string {
	lines := []string{
		"ProxywatchDetections",
		"| where Role == \"" + escapeQueryValue(role) + "\"",
	}
	if len(signals) > 0 {
		lines = append(lines, "| where Signal in~ (\""+strings.Join(signals, "\", \"")+"\")")
	}
	lines = append(lines, "| summarize hits=count() by Host, Process, Role")
	return strings.Join(lines, "\n")
}

func roleDetectionStrategy(role string, signals []string) string {
	if len(signals) == 0 {
		return "Alert when role " + role + " is observed."
	}
	return "Alert when role " + role + " is observed with one or more of: " + strings.Join(signals, ", ") + "."
}

func convertControlConn(cn *shared.ConnectionInfo) *defenderConnIndicator {
	if cn == nil {
		return nil
	}
	out := convertConn(*cn)
	return &out
}

func convertConnections(conns []shared.ConnectionInfo) []defenderConnIndicator {
	if len(conns) == 0 {
		return nil
	}
	out := make([]defenderConnIndicator, 0, len(conns))
	for _, cn := range conns {
		out = append(out, convertConn(cn))
	}
	return out
}

func convertConn(cn shared.ConnectionInfo) defenderConnIndicator {
	return defenderConnIndicator{
		Proto:         "tcp",
		LocalAddress:  strings.TrimSpace(cn.LocalAddress),
		LocalPort:     cn.LocalPort,
		RemoteAddress: strings.TrimSpace(cn.RemoteAddress),
		RemotePort:    cn.RemotePort,
		State:         strings.TrimSpace(cn.State),
		Scope:         connectionScope(cn),
	}
}

func convertListeners(tcp []shared.ListenerInfo, udp []shared.UDPListenerInfo) ([]defenderListenerIndicator, []defenderListenerIndicator) {
	var tcpOut []defenderListenerIndicator
	var udpOut []defenderListenerIndicator
	if len(tcp) > 0 {
		tcpOut = make([]defenderListenerIndicator, 0, len(tcp))
		for _, li := range tcp {
			tcpOut = append(tcpOut, defenderListenerIndicator{
				Proto:        "tcp",
				LocalAddress: strings.TrimSpace(li.LocalAddress),
				LocalPort:    li.LocalPort,
				State:        strings.TrimSpace(li.State),
			})
		}
	}
	if len(udp) > 0 {
		udpOut = make([]defenderListenerIndicator, 0, len(udp))
		for _, li := range udp {
			udpOut = append(udpOut, defenderListenerIndicator{
				Proto:        "udp",
				LocalAddress: strings.TrimSpace(li.LocalAddress),
				LocalPort:    li.LocalPort,
				State:        "LISTEN",
			})
		}
	}
	return tcpOut, udpOut
}

func choosePrimaryConnection(control *defenderConnIndicator, connections []defenderConnIndicator) *defenderConnIndicator {
	if control != nil {
		return control
	}
	for i := range connections {
		cn := connections[i]
		if strings.TrimSpace(cn.RemoteAddress) == "" || shared.IsWildcardIP(cn.RemoteAddress) {
			continue
		}
		return &connections[i]
	}
	return nil
}

func flaggedCandidates(scored []shared.Candidate, minScore int) []shared.Candidate {
	if len(scored) == 0 {
		return nil
	}
	out := make([]shared.Candidate, 0, len(scored))
	for _, c := range scored {
		if c.Score >= minScore || shared.IsControlRole(c.Role) {
			out = append(out, c)
		}
	}
	return out
}

func candidateKeySet(items []shared.Candidate) map[string]bool {
	out := make(map[string]bool, len(items))
	for _, c := range items {
		out[shared.CandidateKey(c)] = true
	}
	return out
}

func buildDetectionID(host, process string, pid int, role string) string {
	host = sanitizeIDPart(host)
	process = sanitizeIDPart(process)
	role = sanitizeIDPart(role)
	return host + "-" + process + "-" + strconv.Itoa(pid) + "-" + role
}

func sanitizeIDPart(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "unknown"
	}
	return out
}

func connectionScope(cn shared.ConnectionInfo) string {
	remote := strings.TrimSpace(cn.RemoteAddress)
	if remote == "" || shared.IsWildcardIP(remote) {
		return "unknown"
	}
	if shared.IsLoopbackIP(remote) {
		return "loopback"
	}
	if shared.IsInternalIP(remote) {
		return "internal"
	}
	return "external"
}

func topMapKeys(freq map[string]int, limit int) []string {
	if len(freq) == 0 || limit <= 0 {
		return nil
	}
	type pair struct {
		key   string
		count int
	}
	pairs := make([]pair, 0, len(freq))
	for key, count := range freq {
		pairs = append(pairs, pair{key: key, count: count})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count != pairs[j].count {
			return pairs[i].count > pairs[j].count
		}
		return pairs[i].key < pairs[j].key
	})
	if len(pairs) > limit {
		pairs = pairs[:limit]
	}
	out := make([]string, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, p.key)
	}
	return out
}

func sortedUniqueStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(in))
	for _, raw := range in {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		set[v] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func sortedRoleFilter(roleFilter map[string]bool) []string {
	if len(roleFilter) == 0 {
		return nil
	}
	out := make([]string, 0, len(roleFilter))
	for role, allowed := range roleFilter {
		if !allowed {
			continue
		}
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		out = append(out, role)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeDetectionOutputPath(path, fallback, requiredExt string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", nil
	}
	path = safeio.ExpandHomePath(path)
	if filepath.IsAbs(path) {
		clean := filepath.Clean(path)
		if clean == "" || clean == "." || clean == string(filepath.Separator) {
			return "", fmt.Errorf("invalid output path: %q", path)
		}
		if requiredExt != "" && !strings.HasSuffix(strings.ToLower(clean), requiredExt) {
			clean += requiredExt
		}
		return clean, nil
	}
	rel := safeio.SanitizeRelativePath(path, fallback)
	out := filepath.Join(detectionOutputRootDir(), rel)
	if requiredExt != "" && !strings.HasSuffix(strings.ToLower(out), requiredExt) {
		out += requiredExt
	}
	return out, nil
}

func ensureDetectionOutputDir(path string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if dir == "" || dir == "." {
		return nil
	}
	return os.MkdirAll(dir, detectionOutputDirFileMode)
}

func detectionOutputRootDir() string {
	home := safeio.UserHomeDir()
	if home == "" {
		return filepath.Join(".proxywatch", detectionOutputDirName)
	}
	return filepath.Join(home, ".proxywatch", detectionOutputDirName)
}

func currentDetectionOutputConfig() detectionOutputConfig {
	detectionOutputMu.RLock()
	cfg := detectionOutputCfg
	detectionOutputMu.RUnlock()
	return cfg
}

func nextDetectionOutputCycle() uint64 {
	detectionOutputMu.Lock()
	detectionOutputCycle++
	next := detectionOutputCycle
	detectionOutputMu.Unlock()
	return next
}

func reportDetectionOutputError(err error) {
	if err == nil {
		return
	}
	msg := strings.TrimSpace(err.Error())
	if msg == "" {
		return
	}

	lastDetectionOutputErrMu.Lock()
	defer lastDetectionOutputErrMu.Unlock()
	now := time.Now().UTC()
	if msg == lastDetectionOutputErr && now.Sub(lastDetectionOutputAt) < 30*time.Second {
		return
	}
	lastDetectionOutputErr = msg
	lastDetectionOutputAt = now
	fmt.Fprintln(os.Stderr, "proxywatch detection output error:", msg)
}

func escapeQueryValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	v = strings.ReplaceAll(v, "\\", "\\\\")
	v = strings.ReplaceAll(v, "\"", "\\\"")
	return v
}
