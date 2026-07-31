package output

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
	DetectionOutputDirName     = "detections"
	DefaultDebugOutputName     = "detection-debug.ndjson"
	DefaultDefenderOutputName  = "defender-detections.json"
	DetectionOutputDirFileMode = 0o700
	DetectionOutputFileMode    = 0o600
)

type DetectionOutputConfig struct {
	DebugLogPath string
	DefenderPath string
}

type DebugDetectionSummary struct {
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

type DebugDetectionRecord struct {
	Schema      string                `json:"schema"`
	Kind        string                `json:"kind"`
	GeneratedAt string                `json:"generated_at"`
	Cycle       uint64                `json:"cycle"`
	HostScope   string                `json:"host_scope"`
	Displayed   bool                  `json:"displayed"`
	Flagged     bool                  `json:"flagged"`
	State       string                `json:"state"`
	RoleFamily  string                `json:"role_family"`
	Candidate   DefenderCandidateItem `json:"candidate"`
}

type DefenderExport struct {
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
	Detections     []DefenderCandidateItem `json:"detections"`
	RoleRules      []DefenderRoleRule      `json:"role_rules"`
}

type DefenderCandidateItem struct {
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
	ControlChannel   *DefenderConnIndicator      `json:"control_channel,omitempty"`
	Connections      []DefenderConnIndicator     `json:"connections,omitempty"`
	TCPListeners     []DefenderListenerIndicator `json:"tcp_listeners,omitempty"`
	UDPListeners     []DefenderListenerIndicator `json:"udp_listeners,omitempty"`
	Queries          DefenderQueries             `json:"queries"`
}

type DefenderConnIndicator struct {
	Proto         string `json:"proto"`
	LocalAddress  string `json:"local_address,omitempty"`
	LocalPort     int    `json:"local_port,omitempty"`
	RemoteAddress string `json:"remote_address,omitempty"`
	RemotePort    int    `json:"remote_port,omitempty"`
	State         string `json:"state,omitempty"`
	Scope         string `json:"scope"`
}

type DefenderListenerIndicator struct {
	Proto        string `json:"proto"`
	LocalAddress string `json:"local_address,omitempty"`
	LocalPort    int    `json:"local_port,omitempty"`
	State        string `json:"state,omitempty"`
}

type DefenderQueries struct {
	Splunk    string         `json:"splunk"`
	KQL       string         `json:"kql"`
	SigmaLike map[string]any `json:"sigma_like"`
}

type DefenderRoleRule struct {
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
	DetectionOutputMu    sync.RWMutex
	DetectionOutputCfg   DetectionOutputConfig
	DetectionOutputCycle uint64

	LastDetectionOutputErrMu sync.Mutex
	LastDetectionOutputErr   string
	LastDetectionOutputAt    time.Time
)

// ConfigureDetectionOutputs enables/disables debug and defender detection exports.
// Empty paths disable each output independently.
func ConfigureDetectionOutputs(debugPath, defenderPath string) error {
	normalizedDebug, err := NormalizeDetectionOutputPath(debugPath, DefaultDebugOutputName, ".ndjson")
	if err != nil {
		return fmt.Errorf("normalize debug path: %w", err)
	}
	normalizedDefender, err := NormalizeDetectionOutputPath(defenderPath, DefaultDefenderOutputName, ".json")
	if err != nil {
		return fmt.Errorf("normalize defender path: %w", err)
	}
	if err := EnsureDetectionOutputDir(normalizedDebug); err != nil {
		return fmt.Errorf("prepare debug output: %w", err)
	}
	if err := EnsureDetectionOutputDir(normalizedDefender); err != nil {
		return fmt.Errorf("prepare defender output: %w", err)
	}

	DetectionOutputMu.Lock()
	DetectionOutputCfg = DetectionOutputConfig{
		DebugLogPath: normalizedDebug,
		DefenderPath: normalizedDefender,
	}
	DetectionOutputMu.Unlock()
	return nil
}

func EmitDetectionOutputs(
	now time.Time,
	hostScope string,
	scored []shared.Candidate,
	displayed []shared.Candidate,
	opts shared.ClassifyOptions,
) {
	cfg := CurrentDetectionOutputConfig()
	cycle := NextDetectionOutputCycle()

	// Update debug API snapshot every cycle regardless of file output config —
	// the API is always available if started via --debug-api flag.
	UpdateDebugAPISnapshot(cycle, hostScope, scored)

	if cfg.DebugLogPath == "" && cfg.DefenderPath == "" && !SentinelOutputConfigured() {
		return
	}

	flagged := FlaggedCandidates(scored, opts.MinScore)

	if cfg.DebugLogPath != "" {
		if err := AppendDebugDetectionLog(cfg.DebugLogPath, now, cycle, hostScope, scored, flagged, displayed, opts); err != nil {
			ReportDetectionOutputError(err)
		}
	}
	if cfg.DefenderPath != "" {
		if err := WriteDefenderDetectionJSON(cfg.DefenderPath, now, cycle, hostScope, scored, flagged, displayed, opts); err != nil {
			ReportDetectionOutputError(err)
		}
	}
	EmitSentinelDetections(now, cycle, hostScope, flagged)
}

func AppendDebugDetectionLog(
	path string,
	now time.Time,
	cycle uint64,
	hostScope string,
	scored []shared.Candidate,
	flagged []shared.Candidate,
	displayed []shared.Candidate,
	opts shared.ClassifyOptions,
) error {
	f, closeFile, err := safeio.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, DetectionOutputFileMode)
	if err != nil {
		return err
	}
	defer func() { _ = closeFile() }()

	flaggedSet := CandidateKeySet(flagged)
	displayedSet := CandidateKeySet(displayed)
	roleFilter := SortedRoleFilter(opts.RoleFilter)

	enc := json.NewEncoder(f)
	if err := enc.Encode(DebugDetectionSummary{
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
		item := MakeDefenderCandidateItem(c, hostScope)
		rec := DebugDetectionRecord{
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

func WriteDefenderDetectionJSON(
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

	items := make([]DefenderCandidateItem, 0, len(flagged))
	for _, c := range flagged {
		item := MakeDefenderCandidateItem(c, hostScope)
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

	exp := DefenderExport{
		Schema:         "proxywatch-defender-detections-v1",
		GeneratedAt:    now.UTC().Format(time.RFC3339Nano),
		Cycle:          cycle,
		HostScope:      shared.DisplayHost(hostScope),
		MinScore:       opts.MinScore,
		RoleFilter:     SortedRoleFilter(opts.RoleFilter),
		ScoredCount:    len(scored),
		FlaggedCount:   len(flagged),
		DisplayedCount: len(displayed),
		RoleCounts:     roleCounts,
		StateCounts:    stateCounts,
		SignalCounts:   signalCounts,
		ReasonCounts:   reasonCounts,
		Detections:     items,
		RoleRules:      BuildRoleRules(items),
	}

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, DetectionOutputDirFileMode); err != nil {
			return err
		}
	}
	f, closeFile, err := safeio.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, DetectionOutputFileMode)
	if err != nil {
		return err
	}
	defer func() { _ = closeFile() }()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(exp)
}

func MakeDefenderCandidateItem(c shared.Candidate, hostScope string) DefenderCandidateItem {
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
	detectionID := BuildDetectionID(host, procName, pid, c.Role)
	controlConn := ConvertControlConn(c.ControlChannel)
	connections := ConvertConnections(c.Conns)
	tcpListeners, udpListeners := ConvertListeners(c.Listeners, c.UDPListeners)
	primary := ChoosePrimaryConnection(controlConn, connections)

	item := DefenderCandidateItem{
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
		Signals:          SortedUniqueStrings(c.Signals),
		Reasons:          SortedUniqueStrings(c.Reasons),
		ControlChannel:   controlConn,
		Connections:      connections,
		TCPListeners:     tcpListeners,
		UDPListeners:     udpListeners,
	}
	item.Queries = BuildDefenderQueries(item, primary)
	return item
}

func BuildRoleRules(items []DefenderCandidateItem) []DefenderRoleRule {
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

	out := make([]DefenderRoleRule, 0, len(roles))
	for _, role := range roles {
		agg := roleAgg[role]
		if agg == nil {
			continue
		}
		topSignals := TopMapKeys(agg.signals, 8)
		topReasons := TopMapKeys(agg.reasons, 6)
		out = append(out, DefenderRoleRule{
			Role:              role,
			RoleFamily:        roleFamily[role],
			Count:             agg.count,
			TopSignals:        topSignals,
			TopReasons:        topReasons,
			SplunkTemplate:    RoleSplunkTemplate(role, topSignals),
			KQLTemplate:       RoleKQLTemplate(role, topSignals),
			DetectionStrategy: RoleDetectionStrategy(role, topSignals),
		})
	}
	return out
}

func BuildDefenderQueries(item DefenderCandidateItem, primary *DefenderConnIndicator) DefenderQueries {
	splunk := BuildSplunkQuery(item, primary)
	kql := BuildKQLQuery(item, primary)
	sigma := BuildSigmaLike(item, primary)
	return DefenderQueries{
		Splunk:    splunk,
		KQL:       kql,
		SigmaLike: sigma,
	}
}

func BuildSplunkQuery(item DefenderCandidateItem, primary *DefenderConnIndicator) string {
	var b strings.Builder
	b.WriteString("index=<endpoint_index> ")
	b.WriteString(`(process_name="`)
	b.WriteString(EscapeQueryValue(item.Process))
	b.WriteString(`" OR process_path="`)
	b.WriteString(EscapeQueryValue(item.ProcessPath))
	b.WriteString(`")`)
	if item.Host != "" {
		b.WriteString(` host="`)
		b.WriteString(EscapeQueryValue(item.Host))
		b.WriteString(`"`)
	}
	if item.PID > 0 {
		b.WriteString(" pid=")
		b.WriteString(strconv.Itoa(item.PID))
	}
	if primary != nil {
		if strings.TrimSpace(primary.RemoteAddress) != "" {
			b.WriteString(` remote_ip="`)
			b.WriteString(EscapeQueryValue(primary.RemoteAddress))
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

func BuildKQLQuery(item DefenderCandidateItem, primary *DefenderConnIndicator) string {
	var lines []string
	lines = append(lines, "DeviceNetworkEvents")
	if item.Host != "" {
		lines = append(lines, "| where DeviceName =~ \""+EscapeQueryValue(item.Host)+"\"")
	}
	if item.PID > 0 {
		lines = append(lines, "| where InitiatingProcessId == "+strconv.Itoa(item.PID))
	}
	if item.Process != "" {
		lines = append(lines, "| where InitiatingProcessFileName =~ \""+EscapeQueryValue(item.Process)+"\"")
	}
	if primary != nil {
		if strings.TrimSpace(primary.RemoteAddress) != "" {
			lines = append(lines, "| where RemoteIP == \""+EscapeQueryValue(primary.RemoteAddress)+"\"")
		}
		if primary.RemotePort > 0 {
			lines = append(lines, "| where RemotePort == "+strconv.Itoa(primary.RemotePort))
		}
	}
	lines = append(lines, "| summarize hits=count(), first_seen=min(Timestamp), last_seen=max(Timestamp) by DeviceName, InitiatingProcessFileName, InitiatingProcessId, RemoteIP, RemotePort")
	return strings.Join(lines, "\n")
}

func BuildSigmaLike(item DefenderCandidateItem, primary *DefenderConnIndicator) map[string]any {
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

func RoleSplunkTemplate(role string, signals []string) string {
	if len(signals) == 0 {
		return `index=<endpoint_index> proxywatch_role="` + EscapeQueryValue(role) + `"`
	}
	return `index=<endpoint_index> proxywatch_role="` + EscapeQueryValue(role) + `" signal IN ("` + strings.Join(signals, `","`) + `")`
}

func RoleKQLTemplate(role string, signals []string) string {
	lines := []string{
		"ProxywatchDetections",
		"| where Role == \"" + EscapeQueryValue(role) + "\"",
	}
	if len(signals) > 0 {
		lines = append(lines, "| where Signal in~ (\""+strings.Join(signals, "\", \"")+"\")")
	}
	lines = append(lines, "| summarize hits=count() by Host, Process, Role")
	return strings.Join(lines, "\n")
}

func RoleDetectionStrategy(role string, signals []string) string {
	if len(signals) == 0 {
		return "Alert when role " + role + " is observed."
	}
	return "Alert when role " + role + " is observed with one or more of: " + strings.Join(signals, ", ") + "."
}

func ConvertControlConn(cn *shared.ConnectionInfo) *DefenderConnIndicator {
	if cn == nil {
		return nil
	}
	out := ConvertConn(*cn)
	return &out
}

func ConvertConnections(conns []shared.ConnectionInfo) []DefenderConnIndicator {
	if len(conns) == 0 {
		return nil
	}
	out := make([]DefenderConnIndicator, 0, len(conns))
	for _, cn := range conns {
		out = append(out, ConvertConn(cn))
	}
	return out
}

func ConvertConn(cn shared.ConnectionInfo) DefenderConnIndicator {
	return DefenderConnIndicator{
		Proto:         "tcp",
		LocalAddress:  strings.TrimSpace(cn.LocalAddress),
		LocalPort:     cn.LocalPort,
		RemoteAddress: strings.TrimSpace(cn.RemoteAddress),
		RemotePort:    cn.RemotePort,
		State:         strings.TrimSpace(cn.State),
		Scope:         ConnectionScope(cn),
	}
}

func ConvertListeners(tcp []shared.ListenerInfo, udp []shared.UDPListenerInfo) ([]DefenderListenerIndicator, []DefenderListenerIndicator) {
	var tcpOut []DefenderListenerIndicator
	var udpOut []DefenderListenerIndicator
	if len(tcp) > 0 {
		tcpOut = make([]DefenderListenerIndicator, 0, len(tcp))
		for _, li := range tcp {
			tcpOut = append(tcpOut, DefenderListenerIndicator{
				Proto:        "tcp",
				LocalAddress: strings.TrimSpace(li.LocalAddress),
				LocalPort:    li.LocalPort,
				State:        strings.TrimSpace(li.State),
			})
		}
	}
	if len(udp) > 0 {
		udpOut = make([]DefenderListenerIndicator, 0, len(udp))
		for _, li := range udp {
			udpOut = append(udpOut, DefenderListenerIndicator{
				Proto:        "udp",
				LocalAddress: strings.TrimSpace(li.LocalAddress),
				LocalPort:    li.LocalPort,
				State:        "LISTEN",
			})
		}
	}
	return tcpOut, udpOut
}

func ChoosePrimaryConnection(control *DefenderConnIndicator, connections []DefenderConnIndicator) *DefenderConnIndicator {
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

func FlaggedCandidates(scored []shared.Candidate, minScore int) []shared.Candidate {
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

func CandidateKeySet(items []shared.Candidate) map[string]bool {
	out := make(map[string]bool, len(items))
	for _, c := range items {
		out[shared.CandidateKey(c)] = true
	}
	return out
}

func BuildDetectionID(host, process string, pid int, role string) string {
	host = SanitizeIDPart(host)
	process = SanitizeIDPart(process)
	role = SanitizeIDPart(role)
	return host + "-" + process + "-" + strconv.Itoa(pid) + "-" + role
}

func SanitizeIDPart(v string) string {
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

func ConnectionScope(cn shared.ConnectionInfo) string {
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

func TopMapKeys(freq map[string]int, limit int) []string {
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

func SortedUniqueStrings(in []string) []string {
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

func SortedRoleFilter(roleFilter map[string]bool) []string {
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

func NormalizeDetectionOutputPath(path, fallback, requiredExt string) (string, error) {
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
	out := filepath.Join(DetectionOutputRootDir(), rel)
	if requiredExt != "" && !strings.HasSuffix(strings.ToLower(out), requiredExt) {
		out += requiredExt
	}
	return out, nil
}

func EnsureDetectionOutputDir(path string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if dir == "" || dir == "." {
		return nil
	}
	return os.MkdirAll(dir, DetectionOutputDirFileMode)
}

func DetectionOutputRootDir() string {
	home := safeio.UserHomeDir()
	if home == "" {
		return filepath.Join(".proxywatch", DetectionOutputDirName)
	}
	return filepath.Join(home, ".proxywatch", DetectionOutputDirName)
}

func CurrentDetectionOutputConfig() DetectionOutputConfig {
	DetectionOutputMu.RLock()
	cfg := DetectionOutputCfg
	DetectionOutputMu.RUnlock()
	return cfg
}

func NextDetectionOutputCycle() uint64 {
	DetectionOutputMu.Lock()
	DetectionOutputCycle++
	next := DetectionOutputCycle
	DetectionOutputMu.Unlock()
	return next
}

func ReportDetectionOutputError(err error) {
	if err == nil {
		return
	}
	msg := strings.TrimSpace(err.Error())
	if msg == "" {
		return
	}

	LastDetectionOutputErrMu.Lock()
	defer LastDetectionOutputErrMu.Unlock()
	now := time.Now().UTC()
	if msg == LastDetectionOutputErr && now.Sub(LastDetectionOutputAt) < 30*time.Second {
		return
	}
	LastDetectionOutputErr = msg
	LastDetectionOutputAt = now
	shared.LogError("detection", "output error: %s", msg)
}

func EscapeQueryValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	v = strings.ReplaceAll(v, "\\", "\\\\")
	v = strings.ReplaceAll(v, "\"", "\\\"")
	return v
}
