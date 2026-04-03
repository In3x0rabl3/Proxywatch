package contour

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"proxywatch/internal/keystore"
	"proxywatch/internal/safeio"
	"proxywatch/internal/shared"
)

const (
	defaultOutputPath = "~/.proxywatch/contour/latest.json"
	defaultContourDir = "~/.proxywatch/contour"
)

var durationOptions = []string{"30s", "1m", "5m"}

type RunInput struct {
	Source      string
	Duration    time.Duration
	SampleEvery time.Duration
	Output      string
	ProbeRole   string
	ProbeTarget string
	ProbeMode   string
	Samples     []shared.Candidate
	OnProgress  func(lines []string) // called with cumulative progress lines during execution
	OnPartial   func(report Report)  // called with partial report as data becomes available
}

type RunResult struct {
	Report     Report
	ReportPath string
	Hints      []shared.ContourHint
}

// ServiceSummary captures classified egress services for a contour report.
type ServiceSummary struct {
	TotalClassified int                  `json:"total_classified"`
	HighRisk        int                  `json:"high_risk"`
	Services        []ServiceReportEntry `json:"services,omitempty"`
	Categories      map[string]int       `json:"categories,omitempty"`
}

// ServiceReportEntry is one classified service in the report.
type ServiceReportEntry struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Risk     string `json:"risk"`
	Conns    int    `json:"conns"`
	UniqueIP int    `json:"unique_ips"`
}

type Report struct {
	ID                 string               `json:"id"`
	GeneratedAt        time.Time            `json:"generated_at"`
	Source             string               `json:"source"`
	Duration           string               `json:"duration"`
	SampleEvery        string               `json:"sample_every"`
	OutputPath         string               `json:"output_path"`
	SampleCount        int                  `json:"sample_count"`
	CandidateCount     int                  `json:"candidate_count"`
	FindingCount       int                  `json:"finding_count"`
	FindingsBySeverity map[string]int       `json:"findings_by_severity"`
	Summary            string               `json:"summary"`
	Findings           []Finding            `json:"findings"`
	Hints              []shared.ContourHint `json:"hints"`
	Probe              *ProbeSummary        `json:"probe,omitempty"`
	EgressServices     *ServiceSummary      `json:"egress_services,omitempty"`
	ReportLines        []string             `json:"report_lines,omitempty"`
}

type Finding struct {
	CandidateKey string         `json:"candidate_key"`
	Host         string         `json:"host"`
	PID          int            `json:"pid"`
	Process      string         `json:"process"`
	Role         string         `json:"role"`
	Category     string         `json:"category"`
	Technique    string         `json:"technique"`
	Severity     string         `json:"severity"`
	Signal       string         `json:"signal"`
	Reason       string         `json:"reason"`
	Evidence     map[string]any `json:"evidence,omitempty"`
}

type candidateAggregate struct {
	key       string
	host      string
	pid       int
	process   string
	role      string
	samples   int
	active    bool
	strong    bool
	writeB    uint64
	writeBps  uint64
	readB     uint64
	outTotal  int
	outExt    int
	outInt    int
	outLoop   int
	controlS  int
	tgtExt    map[string]struct{}
	tgtInt    map[string]struct{}
	tgtLoop   map[string]struct{}
	portExt   map[int]int
	tcpListen map[int]struct{}
	udpListen map[int]struct{}

	// Service-aware tracking (populated after resolveExternalServices).
	services *serviceProfile

	// Port distribution for protocol-mismatch detection.
	portProtoHits map[int]int // external port -> connection count

	// DNS-port traffic tracking.
	dnsPortConns  int // connections to port 53 or 853
	httpsConns    int // connections to port 443
	sshConns      int // connections to port 22
	socksConns    int // connections to typical SOCKS ports (1080, etc.)
	longLivedExt  int // OutLongLived from candidate
	shortLivedExt int // OutShortLived from candidate
}

func DefaultOutputPath() string {
	return defaultOutputPath
}

func DurationOptions() []string {
	out := make([]string, len(durationOptions))
	copy(out, durationOptions)
	return out
}

func SuggestedSampleEvery(duration time.Duration) time.Duration {
	switch {
	case duration <= 15*time.Second:
		return 1 * time.Second
	case duration <= 45*time.Second:
		return 2 * time.Second
	case duration <= 2*time.Minute:
		return 5 * time.Second
	default:
		return 10 * time.Second
	}
}

func NewRunOutputPath() string {
	now := time.Now().UTC()
	day := now.Format("20060102")
	name := fmt.Sprintf("proxywatch-contour-%s-%06d.json", now.Format("20060102-150405"), now.UnixNano()%1_000_000)
	return filepath.Join(safeio.ExpandHomePath(defaultContourDir), day, name)
}

func Execute(input RunInput) (RunResult, error) {
	return ExecuteContext(context.Background(), input)
}

func ExecuteContext(ctx context.Context, input RunInput) (RunResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if input.Duration <= 0 {
		return RunResult{}, fmt.Errorf("duration must be greater than 0")
	}
	if err := ctx.Err(); err != nil {
		return RunResult{}, err
	}

	// Progress log — accumulated lines pushed to the UI during execution.
	progress := make([]string, 0, 32)
	emit := func(line string) {
		progress = append(progress, line)
		if input.OnProgress != nil {
			input.OnProgress(progress)
		}
	}

	source := strings.TrimSpace(input.Source)
	if source == "" {
		source = "all"
	}
	sampleEvery := input.SampleEvery
	if sampleEvery <= 0 {
		sampleEvery = SuggestedSampleEvery(input.Duration)
	}
	outPath := normalizeOutputPath(input.Output)
	now := time.Now().UTC()
	runID := fmt.Sprintf("%s-%06d", now.Format("20060102-150405"), now.UnixNano()%1_000_000)

	uniquePIDs := make(map[int]struct{}, len(input.Samples))
	for _, s := range input.Samples {
		if s.Proc != nil {
			uniquePIDs[s.Proc.Pid] = struct{}{}
		}
	}
	emit(fmt.Sprintf("[*] Analyzing %d samples from %d processes...", len(input.Samples), len(uniquePIDs)))
	scoped := filterBySource(input.Samples, source)
	if err := ctx.Err(); err != nil {
		return RunResult{}, err
	}
	aggs := aggregateCandidates(scoped)
	emit(fmt.Sprintf("[*] Aggregated %d candidate profiles", len(aggs)))

	// Resolve external IPs to known cloud/SaaS services via reverse DNS.
	emit("[*] Resolving external IPs to cloud services (reverse DNS)...")
	enrichAggregatesWithServices(ctx, aggs)
	svcCount := 0
	for _, agg := range aggs {
		if agg.services != nil {
			svcCount += agg.services.total
		}
	}
	if svcCount > 0 {
		emit(fmt.Sprintf("[+] Classified %d connections to known services", svcCount))
	}
	if err := ctx.Err(); err != nil {
		return RunResult{}, err
	}

	findings := buildFindings(aggs)
	if err := ctx.Err(); err != nil {
		return RunResult{}, err
	}

	egressServices := buildEgressServiceSummary(aggs)

	// Helper to push partial report to the UI as data becomes available.
	emitPartial := func(probeSummary *ProbeSummary) {
		if input.OnPartial == nil {
			return
		}
		sevCounts := map[string]int{"watch": 0, "strong": 0, "active": 0}
		for _, f := range findings {
			sevCounts[shared.NormalizeContourSeverity(f.Severity)]++
		}
		partial := Report{
			ID:                 runID,
			GeneratedAt:        now,
			Source:             source,
			SampleCount:        len(scoped),
			CandidateCount:     len(aggs),
			FindingCount:       len(findings),
			FindingsBySeverity: sevCounts,
			Summary:            buildSummary(len(scoped), len(aggs), len(findings), sevCounts),
			Findings:           findings,
			Probe:              probeSummary,
			EgressServices:     egressServices,
		}
		partial.ReportLines = RenderReportLines(partial)
		input.OnPartial(partial)
	}

	// Emit partial after behavioral findings.
	emitPartial(nil)

	var probeSummary *ProbeSummary
	if probeMode := NormalizeProbeMode(input.ProbeMode); probeMode != ProbeModeOff {
		depth := ProbeModeLabel(probeMode)
		target := strings.TrimSpace(input.ProbeTarget)
		emit(fmt.Sprintf("[*] Starting %s probe to %s...", depth, target))
		summary, probeFindings := runProbeSuiteWithProgress(ctx, probeMode, input.ProbeRole, input.ProbeTarget, input.Duration, scoped, emit, func(ps ProbeSummary) {
			emitPartial(&ps)
		})
		probeSummary = &summary
		if len(probeFindings) > 0 {
			findings = append(findings, probeFindings...)
		}
		if err := ctx.Err(); err != nil {
			return RunResult{}, err
		}
	}
	findings = normalizeFindings(findings)
	hints := buildHints(findings)
	severityCounts := map[string]int{"watch": 0, "strong": 0, "active": 0}
	for _, finding := range findings {
		sev := shared.NormalizeContourSeverity(finding.Severity)
		severityCounts[sev]++
	}

	summary := buildSummary(len(scoped), len(aggs), len(findings), severityCounts)
	report := Report{
		ID:                 runID,
		GeneratedAt:        now,
		Source:             source,
		Duration:           input.Duration.Round(time.Second).String(),
		SampleEvery:        sampleEvery.Round(time.Second).String(),
		OutputPath:         outPath,
		SampleCount:        len(scoped),
		CandidateCount:     len(aggs),
		FindingCount:       len(findings),
		FindingsBySeverity: severityCounts,
		Summary:            summary,
		Findings:           findings,
		Hints:              hints,
		Probe:              probeSummary,
		EgressServices:     egressServices,
	}
	report.ReportLines = RenderReportLines(report)
	if err := ctx.Err(); err != nil {
		return RunResult{}, err
	}
	if err := writeJSONFile(outPath, report); err != nil {
		return RunResult{}, err
	}
	return RunResult{
		Report:     report,
		ReportPath: outPath,
		Hints:      hints,
	}, nil
}

func LoadReport(path string) (Report, error) {
	path = normalizeOutputPath(path)
	raw, err := safeio.ReadFile(path)
	if err != nil {
		return Report{}, err
	}
	var report Report
	if err := json.Unmarshal(raw, &report); err != nil {
		return Report{}, err
	}
	if strings.TrimSpace(report.OutputPath) == "" {
		report.OutputPath = path
	}
	if len(report.FindingsBySeverity) == 0 {
		report.FindingsBySeverity = map[string]int{"watch": 0, "strong": 0, "active": 0}
		for _, finding := range report.Findings {
			report.FindingsBySeverity[shared.NormalizeContourSeverity(finding.Severity)]++
		}
	}
	report.ReportLines = RenderReportLines(report)
	return report, nil
}

func RenderReportLines(report Report) []string {
	if report.Probe != nil && report.Probe.Enabled && NormalizeProbeRole(report.Probe.Role) == ProbeRoleListen {
		return renderListenerReportLines(report)
	}

	lines := make([]string, 0, 64)

	// ── Findings ───────────────────────────────────────────────
	if len(report.Findings) > 0 {
		lines = append(lines, "")
		shown := 0
		for _, f := range report.Findings {
			if shown >= 6 {
				lines = append(lines, fmt.Sprintf("    +%d more", len(report.Findings)-shown))
				break
			}
			sev := strings.ToUpper(shared.NormalizeContourSeverity(f.Severity))
			lines = append(lines, fmt.Sprintf("  %s  %s", reportSevTag(sev), f.Reason))
			shown++
		}
	}

	if report.Probe == nil || !report.Probe.Enabled {
		if strings.TrimSpace(report.OutputPath) != "" {
			lines = append(lines, "")
			lines = append(lines, "  output  "+report.OutputPath)
		}
		return lines
	}

	probe := report.Probe

	// ── Probe overview ─────────────────────────────────────────
	lines = append(lines, "")
	target := nonEmpty(strings.TrimSpace(probe.Endpoint), "-")
	lines = append(lines, fmt.Sprintf("  target   %s", target))

	portsOpen := 0
	for _, pr := range probe.PortResults {
		if pr.TunnelSuccess > 0 {
			portsOpen++
		}
	}
	totalPorts := len(probe.Ports)
	if totalPorts == 0 {
		totalPorts = len(defaultProbePorts)
	}
	lines = append(lines, fmt.Sprintf("  ports    %d open / %d tested", portsOpen, totalPorts))

	if len(probe.InternalRoutes) > 0 || len(probe.InternetSubnets) > 0 {
		lines = append(lines, fmt.Sprintf("  routes   %d internal, %d internet", len(probe.InternalRoutes), len(probe.InternetSubnets)))
	}
	if probe.AvgLatencyMs > 0 {
		lines = append(lines, fmt.Sprintf("  latency  ~%dms", probe.AvgLatencyMs))
	}
	if probe.TLSIntercepted {
		lines = append(lines, fmt.Sprintf("  tls      intercepted (%s)", probe.TLSInterceptOrg))
	}

	// ── Tunnels ────────────────────────────────────────────────
	if probe.TunnelAttempts > 0 {
		var carriers []string
		for _, m := range probe.MethodResults {
			if m.TunnelAttempts <= 0 || !methodUsesSocksCarrierTunnel(strings.ToLower(strings.TrimSpace(m.Method))) {
				continue
			}
			switch probeStatusLabel(m.TunnelSuccess, m.TunnelAttempts) {
			case "PASS":
				carriers = append(carriers, m.Method)
			case "MIXED":
				carriers = append(carriers, fmt.Sprintf("%s %d/%d", m.Method, m.TunnelSuccess, m.TunnelAttempts))
			}
		}
		if len(carriers) > 0 {
			lines = append(lines, "")
			lines = append(lines, "  tunnels")
			for _, c := range carriers {
				lines = append(lines, "    - "+c)
			}
		}
		if probe.DomainFrontingPossible {
			lines = append(lines, fmt.Sprintf("    - domain fronting via %s", probe.DomainFrontingSNI))
		}
	}

	// ── Exfiltration ───────────────────────────────────────────
	if probe.ExfilAttempts > 0 {
		var exfilPass, exfilPartial []string
		exfilFail := 0
		for _, m := range probe.MethodResults {
			if m.ExfilAttempts <= 0 {
				continue
			}
			switch probeStatusLabel(m.ExfilSuccess, m.ExfilAttempts) {
			case "PASS":
				exfilPass = append(exfilPass, m.Method)
			case "MIXED":
				exfilPartial = append(exfilPartial, fmt.Sprintf("%s %d/%d", m.Method, m.ExfilSuccess, m.ExfilAttempts))
			default:
				exfilFail++
			}
		}
		if len(exfilPass) > 0 || len(exfilPartial) > 0 {
			lines = append(lines, "")
			lines = append(lines, "  exfil")
			if len(exfilPass) > 0 {
				lines = append(lines, wrapJoinLines("    pass  ", exfilPass, 72, "          ")...)
			}
			if len(exfilPartial) > 0 {
				lines = append(lines, wrapJoinLines("    part  ", exfilPartial, 72, "          ")...)
			}
			if exfilFail > 0 {
				lines = append(lines, fmt.Sprintf("    fail  %d protocol%s blocked", exfilFail, plural(exfilFail)))
			}
		}
	}

	// ── Proxies ────────────────────────────────────────────────
	if len(probe.Proxies) > 0 {
		lines = append(lines, "")
		lines = append(lines, fmt.Sprintf("  proxies  %d found, %d reachable", len(probe.Proxies), probe.ReachableProxyCount))
		for _, pline := range renderProxyCandidateLines(probe.Proxies) {
			lines = append(lines, "    "+pline)
		}
	}

	// ── Services ───────────────────────────────────────────────
	if len(probe.ServiceReachable) > 0 || len(probe.ServiceBlocked) > 0 {
		lines = append(lines, "")
		lines = append(lines, "  services")
		if len(probe.ServiceReachable) > 0 {
			lines = append(lines, wrapJoinLines("    reach  ", probe.ServiceReachable, 72, "           ")...)
		}
		if len(probe.ServiceBlocked) > 0 {
			lines = append(lines, wrapJoinLines("    block  ", probe.ServiceBlocked, 72, "           ")...)
		}
	}

	// ── Egress ─────────────────────────────────────────────────
	if report.EgressServices != nil && len(report.EgressServices.Services) > 0 {
		lines = append(lines, "")
		lines = append(lines, "  egress")
		shown := 0
		for _, svc := range report.EgressServices.Services {
			if shown >= 6 {
				lines = append(lines, fmt.Sprintf("    +%d more", len(report.EgressServices.Services)-shown))
				break
			}
			lines = append(lines, fmt.Sprintf("    %-18s %d conn  %d IP%s",
				clip(svc.Name, 18), svc.Conns, svc.UniqueIP, plural(svc.UniqueIP)))
			shown++
		}
	}

	if strings.TrimSpace(report.OutputPath) != "" {
		lines = append(lines, "")
		lines = append(lines, "  output  "+report.OutputPath)
	}
	return lines
}

// reportSevTag returns a fixed-width severity label for findings.
func reportSevTag(sev string) string {
	switch sev {
	case "ACTIVE":
		return "ACTIVE"
	case "STRONG":
		return "STRONG"
	default:
		return "WATCH "
	}
}

// wrapJoinLines joins items with ", " and wraps at maxWidth, returning
// multiple lines. The first line uses prefix, continuation lines use indent.
func wrapJoinLines(prefix string, items []string, maxWidth int, indent string) []string {
	if len(items) == 0 {
		return nil
	}
	var result []string
	line := prefix
	for i, item := range items {
		add := item
		if i < len(items)-1 {
			add += ", "
		}
		if len(line)+len(add) > maxWidth && line != prefix {
			result = append(result, line)
			line = indent
		}
		line += add
	}
	if line != "" {
		result = append(result, line)
	}
	return result
}

func renderListenerReportLines(report Report) []string {
	lines := make([]string, 0, 256)
	summary := strings.TrimSpace(report.Summary)
	if summary == "" {
		summary = "No listener activity was captured."
	}
	tunnelChecks := 0
	exfilChecks := 0
	for _, check := range report.Probe.SuccessfulChecks {
		if strings.EqualFold(strings.TrimSpace(check.Kind), "exfil") {
			exfilChecks++
			continue
		}
		tunnelChecks++
	}
	boundPorts := len(report.Probe.Ports) - len(report.Probe.PortsUnavailable)
	if boundPorts < 0 {
		boundPorts = 0
	}

	lines = append(lines, summary)
	lines = append(lines, "")
	lines = append(lines, fmt.Sprintf("  %d ports bound  |  %d exchanges  |  %d tunnel  %d exfil", boundPorts, report.Probe.ListenerExchanges, tunnelChecks, exfilChecks))
	if len(report.Probe.PortsUnavailable) > 0 {
		lines = append(lines, fmt.Sprintf("  %d port%s could not bind", len(report.Probe.PortsUnavailable), plural(len(report.Probe.PortsUnavailable))))
	}

	// ── Activity ────────────────────────────────────────────────
	lines = append(lines, "")
	lines = append(lines, "Activity")
	if len(report.Probe.SuccessfulChecks) == 0 {
		lines = append(lines, "  No probes received. Run proxywatch in Egress mode targeting this host.")
	} else {
		var tunnelLines, exfilLines []string
		for _, check := range report.Probe.SuccessfulChecks {
			method := nonEmpty(strings.TrimSpace(check.Method), "-")
			transport := strings.ToUpper(nonEmpty(strings.TrimSpace(check.Transport), "-"))
			peer := nonEmpty(strings.TrimSpace(check.Peer), "?")
			line := fmt.Sprintf("  [PASS] %s/%-8s port %-5d from %s", transport, method, check.Port, peer)
			if strings.EqualFold(strings.TrimSpace(check.Kind), "exfil") {
				exfilLines = append(exfilLines, line)
			} else {
				tunnelLines = append(tunnelLines, line)
			}
		}
		if len(tunnelLines) > 0 {
			lines = append(lines, fmt.Sprintf("  Tunnel (%d received)", len(tunnelLines)))
			lines = append(lines, tunnelLines...)
		}
		if len(exfilLines) > 0 {
			lines = append(lines, fmt.Sprintf("  Exfil (%d received)", len(exfilLines)))
			lines = append(lines, exfilLines...)
		}
	}

	// ── Findings ────────────────────────────────────────────────
	lines = append(lines, "")
	lines = append(lines, "Findings")
	if len(report.Findings) == 0 {
		lines = append(lines, "  No findings from listener activity.")
		return lines
	}
	for _, f := range report.Findings {
		sev := strings.ToUpper(shared.NormalizeContourSeverity(f.Severity))
		lines = append(lines, fmt.Sprintf("  [%s] %s", sev, f.Technique))
		lines = append(lines, "         "+f.Reason)
	}
	if strings.TrimSpace(report.OutputPath) != "" {
		lines = append(lines, "")
		lines = append(lines, "Report: "+report.OutputPath)
	}
	return lines
}

func filterBySource(samples []shared.Candidate, source string) []shared.Candidate {
	if len(samples) == 0 {
		return nil
	}
	source = strings.TrimSpace(source)
	if source == "" || strings.EqualFold(source, "all") {
		out := make([]shared.Candidate, 0, len(samples))
		out = append(out, samples...)
		return out
	}
	out := make([]shared.Candidate, 0, len(samples))
	for _, sample := range samples {
		if strings.EqualFold(shared.DisplayHost(sample.Host), source) {
			out = append(out, sample)
		}
	}
	return out
}

func aggregateCandidates(samples []shared.Candidate) map[string]*candidateAggregate {
	aggs := make(map[string]*candidateAggregate, len(samples))
	for _, sample := range samples {
		if sample.Proc == nil {
			continue
		}
		key := shared.CandidateKey(sample)
		agg, ok := aggs[key]
		if !ok {
			agg = &candidateAggregate{
				key:           key,
				host:          shared.DisplayHost(sample.Host),
				pid:           sample.Proc.Pid,
				process:       strings.TrimSpace(sample.Proc.Name),
				role:          shared.RoleFamily(sample.Role),
				tgtExt:        make(map[string]struct{}),
				tgtInt:        make(map[string]struct{}),
				tgtLoop:       make(map[string]struct{}),
				portExt:       make(map[int]int),
				tcpListen:     make(map[int]struct{}),
				udpListen:     make(map[int]struct{}),
				services:      newServiceProfile(),
				portProtoHits: make(map[int]int),
			}
			aggs[key] = agg
		}
		agg.samples++
		if rolePriority(sample.Role) > rolePriority(agg.role) {
			agg.role = shared.RoleFamily(sample.Role)
		}
		agg.active = agg.active || sample.ActiveProxying
		agg.strong = agg.strong || sample.StrongEvidence
		agg.writeB = maxUint64(agg.writeB, sample.Proc.IOWriteBytes)
		agg.writeBps = maxUint64(agg.writeBps, sample.Proc.IOWriteBps)
		agg.readB = maxUint64(agg.readB, sample.Proc.IOReadBytes)
		agg.outTotal = max(agg.outTotal, sample.OutTotal)
		agg.outExt = max(agg.outExt, sample.OutExternal)
		agg.outInt = max(agg.outInt, sample.OutInternal)
		agg.outLoop = max(agg.outLoop, sample.OutLoopback)
		agg.controlS = max(agg.controlS, sample.ControlDurationSeconds)
		agg.longLivedExt = max(agg.longLivedExt, sample.OutLongLived)
		agg.shortLivedExt = max(agg.shortLivedExt, sample.OutShortLived)
		for _, conn := range sample.Conns {
			remote := strings.TrimSpace(conn.RemoteAddress)
			if remote == "" {
				continue
			}
			target := remote + ":" + strconv.Itoa(conn.RemotePort)
			switch {
			case shared.IsLoopbackIP(remote):
				agg.tgtLoop[target] = struct{}{}
			case shared.IsInternalIP(remote):
				agg.tgtInt[target] = struct{}{}
			default:
				agg.tgtExt[target] = struct{}{}
				if conn.RemotePort > 0 {
					agg.portExt[conn.RemotePort]++
					agg.portProtoHits[conn.RemotePort]++
				}
				// Track protocol-specific port hits for service detection.
				switch conn.RemotePort {
				case 53, 853:
					agg.dnsPortConns++
				case 443:
					agg.httpsConns++
				case 22:
					agg.sshConns++
				case 1080, 1081, 9050, 9150:
					agg.socksConns++
				}
			}
		}
		for _, l := range sample.Listeners {
			if l.LocalPort > 0 {
				agg.tcpListen[l.LocalPort] = struct{}{}
			}
		}
		for _, l := range sample.UDPListeners {
			if l.LocalPort > 0 {
				agg.udpListen[l.LocalPort] = struct{}{}
			}
		}
	}
	return aggs
}

// enrichAggregatesWithServices collects all unique external IPs across
// aggregates, resolves them to known services via reverse DNS, and populates
// each aggregate's serviceProfile.
func enrichAggregatesWithServices(ctx context.Context, aggs map[string]*candidateAggregate) {
	if len(aggs) == 0 {
		return
	}

	// Collect unique external IPs and map them back to their aggregates.
	type ipOwner struct {
		agg  *candidateAggregate
		port int
	}
	ipAggs := make(map[string][]ipOwner, 64)
	allIPs := make([]string, 0, 128)

	for _, agg := range aggs {
		for target := range agg.tgtExt {
			host, portStr, err := net.SplitHostPort(target)
			if err != nil {
				continue
			}
			port, _ := strconv.Atoi(portStr)
			if _, seen := ipAggs[host]; !seen {
				allIPs = append(allIPs, host)
			}
			ipAggs[host] = append(ipAggs[host], ipOwner{agg: agg, port: port})
		}
	}

	if len(allIPs) == 0 {
		return
	}

	resolutions := resolveExternalServices(ctx, allIPs, 400*time.Millisecond, 80)
	for _, res := range resolutions {
		if !res.Matched {
			continue
		}
		owners := ipAggs[res.IP]
		for _, owner := range owners {
			owner.agg.services.add(res.IP, owner.port, res.Match)
		}
	}
}

func buildFindings(aggs map[string]*candidateAggregate) []Finding {
	if len(aggs) == 0 {
		return nil
	}
	findings := make([]Finding, 0, len(aggs)*2)
	for _, agg := range aggs {
		externalTargets := len(agg.tgtExt)
		internalTargets := len(agg.tgtInt)
		loopTargets := len(agg.tgtLoop)
		uncommonPorts := externalUncommonPorts(agg.portExt)
		hasListener := len(agg.tcpListen) > 0 || len(agg.udpListen) > 0

		if externalTargets > 0 && agg.writeB >= 256*1024*1024 {
			sev := "strong"
			if agg.writeB >= 1024*1024*1024 || agg.writeBps >= 4*1024*1024 {
				sev = "active"
			}
			findings = append(findings, makeFinding(agg, "exfiltration", "bulk-outbound-write", sev, "contour-exfil-bulk-write",
				fmt.Sprintf("High outbound write volume to external targets (%s write, %d external target%s)", formatBytes(agg.writeB), externalTargets, plural(externalTargets)),
				map[string]any{"write_bytes": agg.writeB, "write_bps": agg.writeBps, "external_targets": externalTargets}))
		}

		if externalTargets > 0 && agg.samples >= 2 && agg.writeBps >= 512*1024 {
			sev := "watch"
			if agg.writeBps >= 2*1024*1024 {
				sev = "strong"
			}
			findings = append(findings, makeFinding(agg, "exfiltration", "sustained-write-rate", sev, "contour-exfil-sustained-rate",
				fmt.Sprintf("Sustained external write rate observed (%s)", formatBytes(agg.writeBps)+"/s"),
				map[string]any{"write_bps": agg.writeBps, "external_targets": externalTargets}))
		}

		if externalTargets > 0 && len(uncommonPorts) > 0 {
			sev := "watch"
			if len(uncommonPorts) >= 3 {
				sev = "strong"
			}
			findings = append(findings, makeFinding(agg, "escape", "uncommon-egress-port", sev, "contour-escape-uncommon-port",
				fmt.Sprintf("External traffic uses uncommon egress port%s %s", plural(len(uncommonPorts)), joinInts(uncommonPorts)),
				map[string]any{"uncommon_ports": uncommonPorts, "external_targets": externalTargets}))
		}

		if externalTargets > 0 && internalTargets > 0 {
			sev := "strong"
			if agg.role == "control-tunnel" || agg.role == "control-pivot" || agg.active {
				sev = "active"
			}
			findings = append(findings, makeFinding(agg, "escape", "internal-external-bridge", sev, "contour-escape-bridge",
				fmt.Sprintf("Process bridges internal (%d) and external (%d) targets", internalTargets, externalTargets),
				map[string]any{"internal_targets": internalTargets, "external_targets": externalTargets}))
		}

		if externalTargets > 0 && loopTargets >= 2 {
			sev := "strong"
			if agg.active || agg.role == "control-tunnel" || agg.role == "control-pivot" {
				sev = "active"
			}
			findings = append(findings, makeFinding(agg, "escape", "loopback-egress-broker", sev, "contour-escape-loopback-broker",
				fmt.Sprintf("Loopback fanout (%d) combined with external egress (%d) suggests broker/tunnel escape", loopTargets, externalTargets),
				map[string]any{"loopback_targets": loopTargets, "external_targets": externalTargets}))
		}

		if hasListener && externalTargets > 0 {
			sev := "strong"
			if agg.role == "control-tunnel" || agg.role == "control-pivot" || agg.active {
				sev = "active"
			}
			findings = append(findings, makeFinding(agg, "escape", "listener-egress", sev, "contour-escape-listener-egress",
				"Listening process also maintained external egress, consistent with pivot/escape behavior",
				map[string]any{"tcp_listeners": len(agg.tcpListen), "udp_listeners": len(agg.udpListen), "external_targets": externalTargets}))
		}

		// --- Service-aware findings ---

		if agg.services != nil && agg.services.total > 0 {
			sp := agg.services

			// Cloud storage upload detection.
			storageConns := sp.categories[SvcCatCloudStorage]
			if storageConns > 0 && agg.writeB >= 10*1024*1024 {
				sev := "strong"
				if agg.writeB >= 256*1024*1024 || agg.writeBps >= 1*1024*1024 {
					sev = "active"
				}
				names := serviceNamesForCategory(sp, SvcCatCloudStorage)
				findings = append(findings, makeFinding(agg, "exfiltration", "cloud-storage-upload", sev, "contour-exfil-cloud-storage",
					fmt.Sprintf("Process writes %s to cloud storage service%s (%s)", formatBytes(agg.writeB), plural(len(names)), strings.Join(names, ", ")),
					map[string]any{"write_bytes": agg.writeB, "services": names, "storage_conns": storageConns}))
			}

			// Messaging exfil detection (webhooks, file uploads).
			msgConns := sp.categories[SvcCatMessaging]
			if msgConns > 0 && agg.writeB >= 1*1024*1024 {
				sev := "watch"
				if agg.writeB >= 50*1024*1024 {
					sev = "strong"
				}
				if agg.writeB >= 256*1024*1024 {
					sev = "active"
				}
				names := serviceNamesForCategory(sp, SvcCatMessaging)
				findings = append(findings, makeFinding(agg, "exfiltration", "messaging-channel", sev, "contour-exfil-messaging",
					fmt.Sprintf("Process sends %s via messaging service%s (%s)", formatBytes(agg.writeB), plural(len(names)), strings.Join(names, ", ")),
					map[string]any{"write_bytes": agg.writeB, "services": names, "messaging_conns": msgConns}))
			}

			// Code hosting exfil detection (gists, repos, releases, API).
			codeConns := sp.categories[SvcCatCodeHosting]
			if codeConns > 0 && agg.writeB >= 5*1024*1024 {
				sev := "watch"
				if agg.writeB >= 100*1024*1024 {
					sev = "strong"
				}
				names := serviceNamesForCategory(sp, SvcCatCodeHosting)
				findings = append(findings, makeFinding(agg, "exfiltration", "code-hosting-upload", sev, "contour-exfil-code-hosting",
					fmt.Sprintf("Process writes %s to code hosting service%s (%s)", formatBytes(agg.writeB), plural(len(names)), strings.Join(names, ", ")),
					map[string]any{"write_bytes": agg.writeB, "services": names, "code_conns": codeConns}))
			}

			// Paste/file share exfil detection.
			pasteConns := sp.categories[SvcCatPasteShare]
			if pasteConns > 0 {
				sev := "strong"
				if agg.writeB >= 10*1024*1024 {
					sev = "active"
				}
				names := serviceNamesForCategory(sp, SvcCatPasteShare)
				findings = append(findings, makeFinding(agg, "exfiltration", "paste-service-upload", sev, "contour-exfil-paste-service",
					fmt.Sprintf("Process connects to paste/file-share service%s (%s) with %s written", plural(len(names)), strings.Join(names, ", "), formatBytes(agg.writeB)),
					map[string]any{"write_bytes": agg.writeB, "services": names, "paste_conns": pasteConns}))
			}

			// Tunnel/VPN service detection.
			tunnelConns := sp.categories[SvcCatTunnelVPN]
			if tunnelConns > 0 {
				sev := "active"
				names := serviceNamesForCategory(sp, SvcCatTunnelVPN)
				findings = append(findings, makeFinding(agg, "escape", "tunnel-service-egress", sev, "contour-escape-tunnel-service",
					fmt.Sprintf("Process connects to tunnel/VPN service%s (%s)", plural(len(names)), strings.Join(names, ", ")),
					map[string]any{"services": names, "tunnel_conns": tunnelConns}))
			}

			// CDN domain-fronting risk.
			cdnConns := sp.categories[SvcCatCDN]
			if cdnConns > 0 && (agg.writeB >= 50*1024*1024 || agg.role == "control-tunnel" || agg.role == "control-pivot" || agg.active) {
				sev := "watch"
				if agg.writeB >= 256*1024*1024 || agg.role == "control-tunnel" || agg.role == "control-pivot" {
					sev = "strong"
				}
				names := serviceNamesForCategory(sp, SvcCatCDN)
				findings = append(findings, makeFinding(agg, "escape", "cdn-domain-fronting-risk", sev, "contour-escape-cdn-fronting",
					fmt.Sprintf("Process sends %s through CDN (%s), possible domain fronting", formatBytes(agg.writeB), strings.Join(names, ", ")),
					map[string]any{"write_bytes": agg.writeB, "services": names, "cdn_conns": cdnConns}))
			}

			// Multi-service fan-out: process talks to many different exfil-capable services.
			exfilCategories := 0
			for cat, count := range sp.categories {
				if count > 0 && exfilCapableCategory(cat) {
					exfilCategories++
				}
			}
			if exfilCategories >= 2 {
				sev := "strong"
				if exfilCategories >= 3 || sp.highRisk >= 3 {
					sev = "active"
				}
				allNames := make([]string, 0, len(sp.hits))
				for _, hit := range sp.sortedHits() {
					if exfilCapableCategory(hit.Category) {
						allNames = append(allNames, hit.Name)
					}
				}
				findings = append(findings, makeFinding(agg, "exfiltration", "multi-service-fan-out", sev, "contour-exfil-multi-service",
					fmt.Sprintf("Process fans out to %d exfil-capable service categories (%s)", exfilCategories, strings.Join(allNames, ", ")),
					map[string]any{"exfil_categories": exfilCategories, "services": allNames, "total_classified": sp.total}))
			}
		}

		// SOCKS port egress detection (external SOCKS proxies).
		if agg.socksConns > 0 && externalTargets > 0 {
			sev := "strong"
			if agg.socksConns >= 3 || agg.active {
				sev = "active"
			}
			findings = append(findings, makeFinding(agg, "escape", "socks-proxy-egress", sev, "contour-escape-socks-egress",
				fmt.Sprintf("Process connects to %d external SOCKS proxy port%s", agg.socksConns, plural(agg.socksConns)),
				map[string]any{"socks_conns": agg.socksConns, "external_targets": externalTargets}))
		}

		// DNS-port heavy traffic (potential DNS tunneling).
		if agg.dnsPortConns >= 3 && externalTargets > 0 {
			sev := "watch"
			if agg.dnsPortConns >= 8 || agg.writeB >= 10*1024*1024 {
				sev = "strong"
			}
			findings = append(findings, makeFinding(agg, "escape", "dns-tunnel-indicator", sev, "contour-escape-dns-tunnel",
				fmt.Sprintf("Process maintains %d DNS-port connections to external targets with %s written", agg.dnsPortConns, formatBytes(agg.writeB)),
				map[string]any{"dns_conns": agg.dnsPortConns, "write_bytes": agg.writeB, "external_targets": externalTargets}))
		}

		// Long-lived external session with high write (sustained exfil channel).
		if agg.controlS >= 120 && externalTargets > 0 && agg.writeB >= 50*1024*1024 {
			sev := "strong"
			if agg.controlS >= 300 && agg.writeB >= 256*1024*1024 {
				sev = "active"
			}
			findings = append(findings, makeFinding(agg, "exfiltration", "sustained-session-exfil", sev, "contour-exfil-sustained-session",
				fmt.Sprintf("Long-lived external session (%ds) with %s written across %d target%s", agg.controlS, formatBytes(agg.writeB), externalTargets, plural(externalTargets)),
				map[string]any{"control_seconds": agg.controlS, "write_bytes": agg.writeB, "external_targets": externalTargets}))
		}

		// SSH egress fan-out (potential SSH tunneling/pivoting).
		if agg.sshConns >= 2 && externalTargets > 0 {
			sev := "watch"
			if agg.sshConns >= 4 || agg.active {
				sev = "strong"
			}
			findings = append(findings, makeFinding(agg, "escape", "ssh-egress-fan-out", sev, "contour-escape-ssh-fanout",
				fmt.Sprintf("Process maintains %d SSH connections to external targets", agg.sshConns),
				map[string]any{"ssh_conns": agg.sshConns, "external_targets": externalTargets}))
		}
	}

	return normalizeFindings(findings)
}

func buildHints(findings []Finding) []shared.ContourHint {
	if len(findings) == 0 {
		return nil
	}
	out := make([]shared.ContourHint, 0, len(findings))
	seen := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		if strings.TrimSpace(finding.CandidateKey) == "" || finding.PID <= 0 {
			continue
		}
		key := finding.CandidateKey + "|" + finding.Signal
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, shared.ContourHint{
			CandidateKey: finding.CandidateKey,
			Host:         finding.Host,
			PID:          finding.PID,
			Process:      finding.Process,
			Category:     finding.Category,
			Signal:       finding.Signal,
			Reason:       finding.Reason,
			Severity:     shared.NormalizeContourSeverity(finding.Severity),
		})
	}
	return out
}

func buildSummary(sampleCount, candidateCount, findings int, bySeverity map[string]int) string {
	return fmt.Sprintf(
		"Contour analyzed %d samples across %d unique processes and found %d egress findings (active %d, strong %d, watch %d).",
		sampleCount,
		candidateCount,
		findings,
		bySeverity["active"],
		bySeverity["strong"],
		bySeverity["watch"],
	)
}

func dedupeFindings(findings []Finding) []Finding {
	if len(findings) <= 1 {
		return findings
	}
	out := make([]Finding, 0, len(findings))
	seen := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		key := finding.CandidateKey + "|" + finding.Signal
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, finding)
	}
	return out
}

func renderProxyCandidateLines(endpoints []ProbeEndpoint) []string {
	if len(endpoints) == 0 {
		return []string{"- none discovered"}
	}
	type row struct {
		status string
		scope  string
		label  string
	}
	rows := make([]row, 0, len(endpoints))
	for _, endpoint := range endpoints {
		hostPort := endpointDisplayTarget(endpoint)
		if hostPort == "" {
			continue
		}
		switch {
		case endpoint.PivotReachable:
			via := strings.TrimSpace(endpoint.PivotScheme)
			if via == "" {
				via = "proxy"
			}
			rows = append(rows, row{
				status: "PIVOT",
				scope:  endpoint.Scope,
				label:  hostPort + " -> " + nonEmpty(strings.TrimSpace(endpoint.PivotTarget), defaultProbePivotTarget) + " via " + via,
			})
		case endpoint.Reachable:
			label := hostPort
			if tried := strings.TrimSpace(endpoint.ProxyTried); tried != "" {
				label += " (tried " + tried + ")"
			}
			rows = append(rows, row{
				status: "UP",
				scope:  endpoint.Scope,
				label:  label,
			})
		}
	}
	if len(rows) == 0 {
		return []string{"- none reachable"}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		scopeI := endpointScopeRank(rows[i].scope)
		scopeJ := endpointScopeRank(rows[j].scope)
		if scopeI != scopeJ {
			return scopeI < scopeJ
		}
		if rows[i].status != rows[j].status {
			return rows[i].status > rows[j].status
		}
		return rows[i].label < rows[j].label
	})
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		if row.status == "PIVOT" {
			out = append(out, "[PIVOT] "+row.label)
		} else {
			out = append(out, "- "+row.label)
		}
	}
	return out
}

func endpointDisplayTarget(endpoint ProbeEndpoint) string {
	host := strings.TrimSpace(endpoint.Host)
	port := endpoint.Port
	if host != "" && port > 0 {
		return net.JoinHostPort(host, strconv.Itoa(port))
	}
	host, port, ok := endpointHostPort(endpoint.Endpoint)
	if !ok {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// ProbeStatusLabel returns "PASS", "MIXED", "FAIL", or "NONE" for the given
// success/attempts ratio.
func ProbeStatusLabel(success, attempts int) string {
	return probeStatusLabel(success, attempts)
}

func probeStatusLabel(success, attempts int) string {
	if attempts <= 0 {
		return "NONE"
	}
	if success <= 0 {
		return "FAIL"
	}
	if success >= attempts {
		return "PASS"
	}
	return "MIXED"
}

// buildEgressServiceSummary merges service profiles across all aggregates into
// a single report-level summary.
func buildEgressServiceSummary(aggs map[string]*candidateAggregate) *ServiceSummary {
	merged := make(map[string]*serviceHit, 32)
	categories := make(map[string]int, 12)
	total := 0
	highRisk := 0

	for _, agg := range aggs {
		if agg.services == nil {
			continue
		}
		for name, hit := range agg.services.hits {
			m, ok := merged[name]
			if !ok {
				m = &serviceHit{
					Name:     hit.Name,
					Category: hit.Category,
					Risk:     hit.Risk,
					IPs:      make(map[string]struct{}),
					Ports:    make(map[int]struct{}),
				}
				merged[name] = m
			}
			m.Count += hit.Count
			for ip := range hit.IPs {
				m.IPs[ip] = struct{}{}
			}
			for port := range hit.Ports {
				m.Ports[port] = struct{}{}
			}
		}
		for cat, count := range agg.services.categories {
			categories[cat] += count
		}
		total += agg.services.total
		highRisk += agg.services.highRisk
	}

	if total == 0 {
		return nil
	}

	entries := make([]ServiceReportEntry, 0, len(merged))
	for _, hit := range merged {
		entries = append(entries, ServiceReportEntry{
			Name:     hit.Name,
			Category: hit.Category,
			Risk:     hit.Risk,
			Conns:    hit.Count,
			UniqueIP: len(hit.IPs),
		})
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if riskRank(entries[i].Risk) != riskRank(entries[j].Risk) {
			return riskRank(entries[i].Risk) > riskRank(entries[j].Risk)
		}
		if entries[i].Conns != entries[j].Conns {
			return entries[i].Conns > entries[j].Conns
		}
		return entries[i].Name < entries[j].Name
	})

	return &ServiceSummary{
		TotalClassified: total,
		HighRisk:        highRisk,
		Services:        entries,
		Categories:      categories,
	}
}

// serviceNamesForCategory returns the names of services in a specific category.
func serviceNamesForCategory(sp *serviceProfile, category string) []string {
	if sp == nil {
		return nil
	}
	names := make([]string, 0, 4)
	for _, hit := range sp.sortedHits() {
		if hit.Category == category {
			names = append(names, hit.Name)
		}
	}
	return names
}

func makeFinding(agg *candidateAggregate, category, technique, severity, signal, reason string, evidence map[string]any) Finding {
	return Finding{
		CandidateKey: agg.key,
		Host:         agg.host,
		PID:          agg.pid,
		Process:      agg.process,
		Role:         agg.role,
		Category:     strings.TrimSpace(category),
		Technique:    strings.TrimSpace(technique),
		Severity:     shared.NormalizeContourSeverity(severity),
		Signal:       strings.TrimSpace(signal),
		Reason:       strings.TrimSpace(reason),
		Evidence:     evidence,
	}
}

func externalUncommonPorts(portHits map[int]int) []int {
	if len(portHits) == 0 {
		return nil
	}
	common := map[int]bool{
		53: true, 80: true, 123: true, 443: true, 465: true, 587: true, 853: true,
	}
	out := make([]int, 0, len(portHits))
	for port := range portHits {
		if port <= 0 {
			continue
		}
		if common[port] {
			continue
		}
		out = append(out, port)
	}
	sort.Ints(out)
	return out
}

func severityPriority(severity string) int {
	switch shared.NormalizeContourSeverity(severity) {
	case "active":
		return 3
	case "strong":
		return 2
	default:
		return 1
	}
}

func rolePriority(role string) int {
	switch role {
	case "control-session", "control-beacon":
		return 4
	case "control-tunnel", "control-pivot":
		return 3
	case "listen":
		return 2
	case "outbound":
		return 1
	default:
		return 0
	}
}

func formatBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div := uint64(unit)
	exp := 0
	for n >= div*unit && exp < 4 {
		div *= unit
		exp++
	}
	value := float64(n) / float64(div)
	suffix := []string{"KB", "MB", "GB", "TB", "PB"}[exp]
	return fmt.Sprintf("%.1f %s", value, suffix)
}

func joinInts(values []int) string {
	if len(values) == 0 {
		return "(none)"
	}
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, strconv.Itoa(v))
	}
	return strings.Join(parts, ",")
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func clip(v string, maxLen int) string {
	v = strings.TrimSpace(v)
	if len(v) <= maxLen {
		return v
	}
	if maxLen <= 3 {
		return v[:maxLen]
	}
	return v[:maxLen-3] + "..."
}

func normalizeOutputPath(path string) string {
	return safeio.NormalizeJSONOutputPath(path, defaultOutputPath, safeio.ExpandHomePath(defaultContourDir))
}

func writeJSONFile(path string, value any) error {
	path = normalizeOutputPath(path)
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	vaultKey := vaultKeyFromPath(path)
	return keystore.VaultWrite(vaultKey, data, path)
}

func vaultKeyFromPath(path string) string {
	if idx := strings.Index(path, ".proxywatch/"); idx >= 0 {
		return path[idx+len(".proxywatch/"):]
	}
	return filepath.Base(path)
}

func maxUint64(a, b uint64) uint64 {
	if a >= b {
		return a
	}
	return b
}

func nonEmpty(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
