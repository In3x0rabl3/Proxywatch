package contour

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"proxywatch/internal/safeio"
	"proxywatch/internal/shared"
)

const (
	defaultOutputPath = "~/.proxywatch/contour/latest.json"
	defaultContourDir = "~/.proxywatch/contour"
)

var durationOptions = []string{"10s", "30s", "1m", "2m", "5m", "10m", "15m"}

type RunInput struct {
	Source      string
	Duration    time.Duration
	SampleEvery time.Duration
	Output      string
	ProbeRole   string
	ProbeTarget string
	ProbeMode   string
	Samples     []shared.Candidate
}

type RunResult struct {
	Report     Report
	ReportPath string
	Hints      []shared.ContourHint
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
	return filepath.Join(expandHomePath(defaultContourDir), day, name)
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

	scoped := filterBySource(input.Samples, source)
	if err := ctx.Err(); err != nil {
		return RunResult{}, err
	}
	aggs := aggregateCandidates(scoped)
	findings := buildFindings(aggs)
	if err := ctx.Err(); err != nil {
		return RunResult{}, err
	}
	var probeSummary *ProbeSummary
	if probeMode := NormalizeProbeMode(input.ProbeMode); probeMode != ProbeModeOff {
		summary, probeFindings := runProbeSuite(ctx, probeMode, input.ProbeRole, input.ProbeTarget, input.Duration, scoped)
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

	lines := make([]string, 0, 256)
	summary := strings.TrimSpace(report.Summary)
	if summary == "" {
		summary = "No contour findings were generated."
	}
	lines = append(lines, "Overview")
	lines = append(lines, "Summary: "+summary)
	lines = append(lines, "Sample every: "+nonEmpty(strings.TrimSpace(report.SampleEvery), "10s"))
	lines = append(lines, fmt.Sprintf("Captured samples: %d", report.SampleCount))
	lines = append(lines, fmt.Sprintf("Unique processes: %d", report.CandidateCount))
	lines = append(lines, fmt.Sprintf("Findings: %d (active %d strong %d watch %d)", report.FindingCount, report.FindingsBySeverity["active"], report.FindingsBySeverity["strong"], report.FindingsBySeverity["watch"]))
	if report.Probe != nil && report.Probe.Enabled {
		role := NormalizeProbeRole(report.Probe.Role)
		lines = append(lines, "")
		lines = append(lines, "Probe Matrix")
		lines = append(lines, "Role: "+ProbeRoleLabel(report.Probe.Role))
		lines = append(lines, "Endpoint: "+nonEmpty(strings.TrimSpace(report.Probe.Endpoint), "-"))
		lines = append(lines, "Probe mode: "+ProbeModeLabel(report.Probe.Mode))
		if role == ProbeRoleScan {
			lines = append(lines, fmt.Sprintf("Probe matrix (connectivity): %d/%d", report.Probe.TunnelSuccess, report.Probe.TunnelAttempts))
		} else {
			lines = append(lines, fmt.Sprintf("Probe matrix (tunnel): %d/%d", report.Probe.TunnelSuccess, report.Probe.TunnelAttempts))
			if report.Probe.ExfilAttempts > 0 {
				lines = append(lines, fmt.Sprintf("Probe matrix (exfil): %d/%d", report.Probe.ExfilSuccess, report.Probe.ExfilAttempts))
			}
		}
		totalChecks := len(report.Probe.SuccessfulChecks) + len(report.Probe.FailedChecks)
		if totalChecks > 0 {
			lines = append(lines, fmt.Sprintf("Probe checks: %d total (%d pass, %d fail)", totalChecks, len(report.Probe.SuccessfulChecks), len(report.Probe.FailedChecks)))
		}
		lines = append(lines, fmt.Sprintf("Probe routes: %d internal, %d internet-routable", len(report.Probe.InternalRoutes), len(report.Probe.InternetSubnets)))
		lines = append(lines, fmt.Sprintf("Probe proxies: %d total (%d reachable, %d pivot-capable)", len(report.Probe.Proxies), report.Probe.ReachableProxyCount, report.Probe.PivotProxyCount))
		lines = append(lines, fmt.Sprintf("Probe config endpoints: %d total (%d reachable)", len(report.Probe.ConfigEndpoints), report.Probe.ReachableConfigCount))
		if strings.TrimSpace(report.Probe.ProxyPivotTarget) != "" {
			lines = append(lines, "Probe pivot target: "+report.Probe.ProxyPivotTarget)
		}
		if report.Probe.ListenerReady {
			lines = append(lines, fmt.Sprintf("Probe listener: ready on %d ports for %ds (exchanges %d)", len(report.Probe.Ports)-len(report.Probe.PortsUnavailable), report.Probe.ListenerSeconds, report.Probe.ListenerExchanges))
		}
	}
	lines = append(lines, fmt.Sprintf("Calibration hints exported: %d", len(report.Hints)))
	if strings.TrimSpace(report.OutputPath) != "" {
		lines = append(lines, "Report: "+report.OutputPath)
	}

	if report.Probe != nil && report.Probe.Enabled {
		role := NormalizeProbeRole(report.Probe.Role)
		if len(report.Probe.MethodResults) > 0 {
			if role == ProbeRoleScan {
				lines = append(lines, "")
				lines = append(lines, "Probe Methods")
				shown := 0
				for _, method := range report.Probe.MethodResults {
					status := probeStatusLabel(method.TunnelSuccess, method.TunnelAttempts)
					if status == "FAIL" {
						continue
					}
					transport := strings.ToUpper(strings.TrimSpace(method.Transport))
					methodName := clip(strings.TrimSpace(method.Method), 9)
					shown++
					lines = append(lines, fmt.Sprintf(
						"- [%s] %-4s/%-9s connectivity %d/%d",
						status,
						transport,
						methodName,
						method.TunnelSuccess,
						method.TunnelAttempts,
					))
				}
				if shown == 0 {
					lines = append(lines, "- [NONE] no verified methods")
				}
			} else {
				lines = append(lines, "")
				lines = append(lines, "Tunnel Methods")
				shownTunnel := 0
				for _, method := range report.Probe.MethodResults {
					if method.TunnelAttempts <= 0 || method.TunnelSuccess <= 0 {
						continue
					}
					status := probeStatusLabel(method.TunnelSuccess, method.TunnelAttempts)
					transport := strings.ToUpper(strings.TrimSpace(method.Transport))
					methodName := clip(strings.TrimSpace(method.Method), 9)
					shownTunnel++
					lines = append(lines, fmt.Sprintf(
						"- [%s] %-4s/%-9s tunnel %d/%d",
						status,
						transport,
						methodName,
						method.TunnelSuccess,
						method.TunnelAttempts,
					))
				}
				if shownTunnel == 0 {
					lines = append(lines, "- [NONE] no verified tunnel methods")
				}

				lines = append(lines, "")
				lines = append(lines, "Exfiltration Methods")
				shownExfil := 0
				for _, method := range report.Probe.MethodResults {
					if method.ExfilAttempts <= 0 || method.ExfilSuccess <= 0 {
						continue
					}
					status := probeStatusLabel(method.ExfilSuccess, method.ExfilAttempts)
					transport := strings.ToUpper(strings.TrimSpace(method.Transport))
					methodName := clip(strings.TrimSpace(method.Method), 9)
					shownExfil++
					lines = append(lines, fmt.Sprintf(
						"- [%s] %-4s/%-9s exfil %d/%d",
						status,
						transport,
						methodName,
						method.ExfilSuccess,
						method.ExfilAttempts,
					))
				}
				if shownExfil == 0 {
					lines = append(lines, "- [NONE] no verified exfiltration methods")
				}
			}
		}

		if role == ProbeRoleScan && len(report.Probe.PortResults) > 0 {
			lines = append(lines, "")
			lines = append(lines, "Probe Ports")
			shown := 0
			for _, port := range report.Probe.PortResults {
				status := probeStatusLabel(port.TunnelSuccess, port.TunnelAttempts)
				if status == "FAIL" {
					continue
				}
				shown++
				lines = append(lines, fmt.Sprintf(
					"- [%s] port %-5d connectivity %d/%d",
					status,
					port.Port,
					port.TunnelSuccess,
					port.TunnelAttempts,
				))
			}
			if shown == 0 {
				lines = append(lines, "- [NONE] no verified ports")
			}
		}

		if len(report.Probe.SuccessfulChecks) > 0 || len(report.Probe.FailedChecks) > 0 {
			lines = append(lines, "")
			lines = append(lines, "Probe Checks")
			lines = append(lines, renderProbeCheckSummary(report.Probe.SuccessfulChecks, report.Probe.FailedChecks)...)
		}

		lines = append(lines, "")
		lines = append(lines, "Probe Discoveries")
		if len(report.Probe.Ports) > 0 {
			allowedPorts := len(report.Probe.Ports) - len(report.Probe.PortsUnavailable)
			if allowedPorts < 0 {
				allowedPorts = 0
			}
			lines = append(lines, fmt.Sprintf("Probe ports: %d total (%d allowed)", len(report.Probe.Ports), allowedPorts))
		}
		if len(report.Probe.Protocols) > 0 {
			lines = append(lines, fmt.Sprintf("Probe protocols: %d (wire signatures validated)", len(report.Probe.Protocols)))
		}
		if len(report.Probe.InternetSubnets) > 0 {
			lines = append(lines, "Internet-routable subnets: "+clip(strings.Join(report.Probe.InternetSubnets, ","), 100))
		}
		lines = append(lines, fmt.Sprintf("Proxy candidates: %d discovered", len(report.Probe.Proxies)))
		lines = append(lines, renderProxyCandidateLines(report.Probe.Proxies)...)
		if len(report.Probe.ConfigEndpoints) > 0 {
			lines = append(lines, fmt.Sprintf("Config endpoints: %d discovered (%d reachable)", len(report.Probe.ConfigEndpoints), report.Probe.ReachableConfigCount))
		}
		if len(report.Probe.PortsUnavailable) > 0 {
			lines = append(lines, fmt.Sprintf("Ports unavailable: %d denied", len(report.Probe.PortsUnavailable)))
		}
	}

	lines = append(lines, "")
	lines = append(lines, "Findings")
	if len(report.Findings) == 0 {
		lines = append(lines, "- No tunnel or egress-escape patterns exceeded contour thresholds.")
		return lines
	}

	for _, finding := range report.Findings {
		lines = append(lines, fmt.Sprintf(
			"- [%s] %-8s pid=%-6d %-24s role=%-8s %s/%s :: %s",
			strings.ToUpper(shared.NormalizeContourSeverity(finding.Severity)),
			clip(shared.DisplayHost(finding.Host), 8),
			finding.PID,
			clip(finding.Process, 24),
			clip(finding.Role, 8),
			clip(finding.Category, 12),
			clip(finding.Technique, 22),
			finding.Reason,
		))
	}
	return lines
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
	lines = append(lines, "Overview")
	lines = append(lines, "Summary: "+summary)
	lines = append(lines, "Role: Listener")
	lines = append(lines, fmt.Sprintf("Listener exchanges: %d", report.Probe.ListenerExchanges))
	lines = append(lines, fmt.Sprintf("Listener checks: %d", len(report.Probe.SuccessfulChecks)))
	lines = append(lines, fmt.Sprintf("Tunnel checks: %d", tunnelChecks))
	lines = append(lines, fmt.Sprintf("Exfil checks: %d", exfilChecks))
	lines = append(lines, fmt.Sprintf("Ports bound: %d/%d", len(report.Probe.Ports)-len(report.Probe.PortsUnavailable), len(report.Probe.Ports)))
	if len(report.Probe.PortsUnavailable) > 0 {
		lines = append(lines, "Ports unavailable: "+joinInts(report.Probe.PortsUnavailable))
	}
	lines = append(lines, fmt.Sprintf("Calibration hints exported: %d", len(report.Hints)))
	if strings.TrimSpace(report.OutputPath) != "" {
		lines = append(lines, "Report: "+report.OutputPath)
	}

	if len(report.Probe.PortResults) > 0 {
		lines = append(lines, "")
		lines = append(lines, "Listener Ports")
		for _, port := range report.Probe.PortResults {
			status := "FAIL"
			if port.ListenerBound {
				status = "PASS"
			}
			lines = append(lines, fmt.Sprintf("- [%s] port %d listener %s", status, port.Port, ternaryBound(port.ListenerBound)))
		}
	}

	lines = append(lines, "")
	lines = append(lines, "Listener Checks")
	if len(report.Probe.SuccessfulChecks) == 0 {
		lines = append(lines, "- [NONE] no listener checks received")
	} else {
		for _, check := range report.Probe.SuccessfulChecks {
			lines = append(lines, formatListenerCheckLine(check))
		}
	}

	lines = append(lines, "")
	lines = append(lines, "Findings")
	if len(report.Findings) == 0 {
		lines = append(lines, "- No listener findings were generated.")
		return lines
	}
	for _, finding := range report.Findings {
		lines = append(lines, fmt.Sprintf(
			"- [%s] %-8s pid=%-6d %-24s role=%-8s %s/%s :: %s",
			strings.ToUpper(shared.NormalizeContourSeverity(finding.Severity)),
			clip(shared.DisplayHost(finding.Host), 8),
			finding.PID,
			clip(finding.Process, 24),
			clip(finding.Role, 8),
			clip(finding.Category, 12),
			clip(finding.Technique, 22),
			finding.Reason,
		))
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
		for _, sample := range samples {
			out = append(out, sample)
		}
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
				key:       key,
				host:      shared.DisplayHost(sample.Host),
				pid:       sample.Proc.Pid,
				process:   strings.TrimSpace(sample.Proc.Name),
				role:      shared.RoleFamily(sample.Role),
				tgtExt:    make(map[string]struct{}),
				tgtInt:    make(map[string]struct{}),
				tgtLoop:   make(map[string]struct{}),
				portExt:   make(map[int]int),
				tcpListen: make(map[int]struct{}),
				udpListen: make(map[int]struct{}),
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
			if agg.role == "tunnel" || agg.active {
				sev = "active"
			}
			findings = append(findings, makeFinding(agg, "escape", "internal-external-bridge", sev, "contour-escape-bridge",
				fmt.Sprintf("Process bridges internal (%d) and external (%d) targets", internalTargets, externalTargets),
				map[string]any{"internal_targets": internalTargets, "external_targets": externalTargets}))
		}

		if externalTargets > 0 && loopTargets >= 2 {
			sev := "strong"
			if agg.active || agg.role == "tunnel" {
				sev = "active"
			}
			findings = append(findings, makeFinding(agg, "escape", "loopback-egress-broker", sev, "contour-escape-loopback-broker",
				fmt.Sprintf("Loopback fanout (%d) combined with external egress (%d) suggests broker/tunnel escape", loopTargets, externalTargets),
				map[string]any{"loopback_targets": loopTargets, "external_targets": externalTargets}))
		}

		if hasListener && externalTargets > 0 {
			sev := "strong"
			if agg.role == "tunnel" || agg.active {
				sev = "active"
			}
			findings = append(findings, makeFinding(agg, "escape", "listener-egress", sev, "contour-escape-listener-egress",
				"Listening process also maintained external egress, consistent with pivot/escape behavior",
				map[string]any{"tcp_listeners": len(agg.tcpListen), "udp_listeners": len(agg.udpListen), "external_targets": externalTargets}))
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

func formatEndpointList(endpoints []ProbeEndpoint) string {
	if len(endpoints) == 0 {
		return "(none)"
	}
	parts := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		label := endpoint.Endpoint
		scope := strings.TrimSpace(endpoint.Scope)
		if scope != "" {
			label = scope + ":" + label
		}
		if endpoint.Reachable {
			label += "[up]"
		}
		if endpoint.PivotReachable {
			label += "[pivot]"
		}
		parts = append(parts, label)
		if len(parts) >= 6 {
			break
		}
	}
	if len(endpoints) > len(parts) {
		parts = append(parts, fmt.Sprintf("+%d more", len(endpoints)-len(parts)))
	}
	return strings.Join(parts, ", ")
}

func renderProxyCandidateLines(endpoints []ProbeEndpoint) []string {
	if len(endpoints) == 0 {
		return []string{"- [NONE] no proxy candidates discovered"}
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
		return []string{"- [NONE] no reachable proxy candidates"}
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
	lines := make([]string, 0, len(rows))
	for _, row := range rows {
		lines = append(lines, fmt.Sprintf("- [%s] %s", row.status, row.label))
	}
	return lines
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

func mergeProbeStatuses(a, b string) string {
	normalize := func(v string) string {
		switch strings.ToUpper(strings.TrimSpace(v)) {
		case "PASS":
			return "PASS"
		case "FAIL":
			return "FAIL"
		case "MIXED":
			return "MIXED"
		default:
			return "NONE"
		}
	}
	a = normalize(a)
	b = normalize(b)
	if a == "NONE" {
		return b
	}
	if b == "NONE" {
		return a
	}
	if a == b {
		return a
	}
	if a == "MIXED" || b == "MIXED" {
		return "MIXED"
	}
	return "MIXED"
}

func ternaryBound(bound bool) string {
	if bound {
		return "bound"
	}
	return "unavailable"
}

func formatListenerCheckLine(check ProbeCheck) string {
	status := "PASS"
	if !check.Success {
		status = "FAIL"
	}
	kind := strings.ToUpper(nonEmpty(strings.TrimSpace(check.Kind), "tunnel"))
	method := nonEmpty(strings.TrimSpace(check.Method), "-")
	transport := strings.ToUpper(nonEmpty(strings.TrimSpace(check.Transport), "-"))
	peer := nonEmpty(strings.TrimSpace(check.Peer), "-")
	return fmt.Sprintf("- [%s] %-6s %s/%s@%d <- %s", status, kind, transport, method, check.Port, peer)
}

func renderProbeCheckSummary(successful, failed []ProbeCheck) []string {
	total := len(successful) + len(failed)
	if total == 0 {
		return []string{"- [NONE] (none)"}
	}
	lines := make([]string, 0, 3)
	lines = append(lines, fmt.Sprintf("- [%s] coverage %d/%d (fail=%d)", probeStatusLabel(len(successful), total), len(successful), total, len(failed)))
	if len(successful) > 0 {
		lines = append(lines, "- [PASS] pass by method: "+summarizeProbeChecksByMethod(successful, 5))
	} else {
		lines = append(lines, "- [NONE] no successful checks")
	}
	return lines
}

func summarizeProbeChecksByMethod(checks []ProbeCheck, limit int) string {
	if len(checks) == 0 {
		return "(none)"
	}
	counts := make(map[string]int, len(checks))
	for _, check := range checks {
		kind := strings.ToUpper(strings.TrimSpace(check.Kind))
		method := nonEmpty(strings.TrimSpace(check.Method), "-")
		transport := strings.ToUpper(nonEmpty(strings.TrimSpace(check.Transport), "-"))
		label := transport + "/" + method
		if kind != "" && kind != "TUNNEL" {
			label = kind + ":" + label
		}
		counts[label]++
	}
	return summarizeProbeCheckCounts(counts, limit)
}

func summarizeProbeChecksByPort(checks []ProbeCheck, limit int) string {
	if len(checks) == 0 {
		return "(none)"
	}
	type portCount struct {
		Port  int
		Count int
	}
	counts := make(map[int]int, len(checks))
	for _, check := range checks {
		if check.Port <= 0 {
			continue
		}
		counts[check.Port]++
	}
	if len(counts) == 0 {
		return "(none)"
	}
	items := make([]portCount, 0, len(counts))
	for port, count := range counts {
		items = append(items, portCount{Port: port, Count: count})
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}
		return items[i].Port < items[j].Port
	})
	if limit <= 0 || limit > len(items) {
		limit = len(items)
	}
	parts := make([]string, 0, limit+1)
	for i := 0; i < limit; i++ {
		parts = append(parts, fmt.Sprintf("%d(x%d)", items[i].Port, items[i].Count))
	}
	if len(items) > limit {
		parts = append(parts, fmt.Sprintf("+%d more", len(items)-limit))
	}
	return strings.Join(parts, ", ")
}

func summarizeProbeCheckSamples(checks []ProbeCheck, limit int) string {
	if len(checks) == 0 {
		return "(none)"
	}
	if limit <= 0 {
		limit = 5
	}
	parts := make([]string, 0, min(limit, len(checks))+1)
	for i, check := range checks {
		if i >= limit {
			break
		}
		kind := strings.ToUpper(strings.TrimSpace(check.Kind))
		method := nonEmpty(strings.TrimSpace(check.Method), "-")
		transport := strings.ToUpper(nonEmpty(strings.TrimSpace(check.Transport), "-"))
		label := fmt.Sprintf("%s/%s@%d", transport, method, check.Port)
		if kind != "" && kind != "TUNNEL" {
			label = kind + ":" + label
		}
		parts = append(parts, label)
	}
	if len(checks) > limit {
		parts = append(parts, fmt.Sprintf("+%d more", len(checks)-limit))
	}
	return strings.Join(parts, ", ")
}

func summarizeProbeCheckCounts(counts map[string]int, limit int) string {
	if len(counts) == 0 {
		return "(none)"
	}
	type countItem struct {
		Label string
		Count int
	}
	items := make([]countItem, 0, len(counts))
	for label, count := range counts {
		items = append(items, countItem{Label: label, Count: count})
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}
		return items[i].Label < items[j].Label
	})
	if limit <= 0 || limit > len(items) {
		limit = len(items)
	}
	parts := make([]string, 0, limit+1)
	for i := 0; i < limit; i++ {
		parts = append(parts, fmt.Sprintf("%s(x%d)", items[i].Label, items[i].Count))
	}
	if len(items) > limit {
		parts = append(parts, fmt.Sprintf("+%d more", len(items)-limit))
	}
	return strings.Join(parts, ", ")
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
	family := strings.ToLower(strings.TrimSpace(role))
	switch family {
	case "tunnel", "session", "beacon", "listener", "outbound", "other":
	default:
		family = shared.RoleFamily(role)
	}
	switch family {
	case "tunnel":
		return 5
	case "session":
		return 4
	case "beacon":
		return 3
	case "listener":
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
	path = strings.TrimSpace(path)
	if path == "" {
		path = defaultOutputPath
	}
	path = expandHomePath(path)
	if filepath.IsAbs(path) {
		path = filepath.Clean(path)
	} else {
		path = filepath.Join(expandHomePath(defaultContourDir), sanitizeRelativeOutputPath(path, "latest.json"))
	}
	if !strings.HasSuffix(strings.ToLower(path), ".json") {
		path += ".json"
	}
	return path
}

func sanitizeRelativeOutputPath(path, fallback string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return fallback
	}
	path = filepath.Clean(path)
	if path == "." || path == "" {
		return fallback
	}
	for strings.HasPrefix(path, "."+string(filepath.Separator)) {
		path = strings.TrimPrefix(path, "."+string(filepath.Separator))
	}
	path = strings.TrimLeft(path, string(filepath.Separator))
	parentPrefix := ".." + string(filepath.Separator)
	for path == ".." || strings.HasPrefix(path, parentPrefix) {
		if path == ".." {
			return fallback
		}
		path = strings.TrimPrefix(path, parentPrefix)
	}
	if path == "" || path == "." {
		return fallback
	}
	return path
}

func expandHomePath(path string) string {
	if path == "" || path[0] != '~' {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return path
	}
	if path == "~" {
		return home
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(home, path[2:])
	}
	return path
}

func writeJSONFile(path string, value any) error {
	path = normalizeOutputPath(path)
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
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
