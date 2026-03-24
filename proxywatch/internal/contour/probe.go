package contour

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"proxywatch/internal/shared"
)

const (
	ProbeModeOff    = "off"
	ProbeModeSweep  = "sweep"
	ProbeModeChecks = "checks"

	probeMatrixModeTunnel = "tunnel"
	probeMatrixModeExfil  = "exfil"
	probeMatrixModeBoth   = "both"

	ProbeRoleClient = "client"
	ProbeRoleListen = "listen"
	ProbeRoleScan   = "scan"

	defaultProbePivotTarget = "ifconfig.me:443"
)

var (
	probeModeOptions  = []string{ProbeModeChecks, ProbeModeSweep, ProbeModeOff}
	probeRoleOptions  = []string{ProbeRoleClient, ProbeRoleListen, ProbeRoleScan}
	defaultProbePorts = []int{
		53, 80, 443, 22, 25, 110, 143, 445, 3389, 8080,
		21, 23, 26, 81, 88, 111, 135, 139, 389, 587,
		993, 995, 636, 1025, 1723, 3306, 1433, 1521, 5432, 5900,
		6379, 11211, 27017, 5000, 5001, 5060, 5061, 5222, 5228, 5353,
		123, 543, 548, 554, 631, 873, 902, 989, 990, 1194,
		1434, 1812, 1883, 1900, 1935, 2049, 2375, 2376, 2483, 2484,
		3000, 3128, 3268, 3269, 3478, 3690, 4443, 4500, 4567, 500,
		514, 515, 520, 1099, 1701, 2082, 2083, 2086, 2087, 2095,
		2096, 5671, 5672, 5985, 5986, 6443, 6514, 6667, 7001, 7070,
		7443, 7777, 8000, 8008, 8081, 8088, 8090, 8443, 8888, 9000,
	}
	defaultProtocols = []probeProtocol{
		{Name: "http", Transport: "tcp"},
		{Name: "https", Transport: "tcp"},
		{Name: "ws", Transport: "tcp"},
		{Name: "wss", Transport: "tcp"},
		{Name: "ssh", Transport: "tcp"},
		{Name: "smtp", Transport: "tcp"},
		{Name: "smtps", Transport: "tcp"},
		{Name: "imap", Transport: "tcp"},
		{Name: "imaps", Transport: "tcp"},
		{Name: "pop3", Transport: "tcp"},
		{Name: "pop3s", Transport: "tcp"},
		{Name: "ftp", Transport: "tcp"},
		{Name: "ftps", Transport: "tcp"},
		{Name: "smb", Transport: "tcp"},
		{Name: "rdp", Transport: "tcp"},
		{Name: "ldap", Transport: "tcp"},
		{Name: "ldaps", Transport: "tcp"},
		{Name: "socks4", Transport: "tcp"},
		{Name: "socks5", Transport: "tcp"},
		{Name: "mqtt", Transport: "tcp"},
		{Name: "amqp", Transport: "tcp"},
		{Name: "postgres", Transport: "tcp"},
		{Name: "dns", Transport: "udp"},
		{Name: "ntp", Transport: "udp"},
		{Name: "quic", Transport: "udp"},
		{Name: "webrtc", Transport: "udp"},
		{Name: "sip", Transport: "udp"},
		{Name: "rtsp", Transport: "tcp"},
		{Name: "snmp", Transport: "udp"},
		{Name: "coap", Transport: "udp"},
		{Name: "redis", Transport: "tcp"},
	}

	endpointURLRE        = regexp.MustCompile(`(?i)(?:https?|wss?|ssh|socks5?|socks4|ftp|ftps|smtp|smtps|imap|imaps|pop3s?|ldap|ldaps|amqp|mqtt|postgres|rtsp|sip|snmp|coap|redis|stun|turns?)://[^\s"'<>]+`)
	endpointIPRE         = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b`)
	endpointDomainPortRE = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+):\d{2,5}\b`)
	endpointHostPortRE   = regexp.MustCompile(`(?i)\b(?:localhost|[a-z0-9][a-z0-9-]{0,62}):\d{2,5}\b`)
	endpointIPv6RE       = regexp.MustCompile(`\[[0-9a-fA-F:]+\]:\d{2,5}\b`)
	windowsEnvVarRE      = regexp.MustCompile(`%([^%]+)%`)
	probeNonceCtr        uint64
)

const (
	probePacketVersion   = byte(1)
	probePacketHeaderLen = 20
	probePacketReqMagic  = "CP2Q"
	probePacketRespMagic = "CP2R"
	probeKindTunnel      = byte(1)
	probeKindExfil       = byte(2)
	probeFlagExfil       = byte(1 << 0)
)

var (
	probeMethodIDs = map[string]byte{
		"http": 1, "https": 2, "ws": 3, "wss": 4, "ssh": 5, "smtp": 6, "smtps": 7,
		"imap": 8, "imaps": 9, "pop3": 10, "pop3s": 11, "ftp": 12, "ftps": 13,
		"smb": 14, "rdp": 15, "ldap": 16, "ldaps": 17, "socks4": 18, "socks5": 19,
		"mqtt": 20, "amqp": 21, "postgres": 22, "dns": 23, "ntp": 24, "quic": 25,
		"webrtc": 26, "sip": 27, "rtsp": 28, "snmp": 29, "coap": 30, "redis": 31,
	}
	probeMethodNames = map[byte]string{
		1: "http", 2: "https", 3: "ws", 4: "wss", 5: "ssh", 6: "smtp", 7: "smtps",
		8: "imap", 9: "imaps", 10: "pop3", 11: "pop3s", 12: "ftp", 13: "ftps",
		14: "smb", 15: "rdp", 16: "ldap", 17: "ldaps", 18: "socks4", 19: "socks5",
		20: "mqtt", 21: "amqp", 22: "postgres", 23: "dns", 24: "ntp", 25: "quic",
		26: "webrtc", 27: "sip", 28: "rtsp", 29: "snmp", 30: "coap", 31: "redis",
	}
	probeTunnelMarker = []byte("\n--CONTOUR-TUNNEL--\n")
	probeExfilMarker  = []byte("\n--CONTOUR-EXFIL--\n")
	probeTLSMethods   = map[string]struct{}{
		"https": {}, "wss": {}, "smtps": {}, "imaps": {}, "pop3s": {}, "ftps": {}, "ldaps": {},
	}
	probeSocksCarrierMethods = map[string]struct{}{
		"http": {}, "https": {}, "ws": {}, "wss": {}, "ssh": {},
	}
)

type probeProtocol struct {
	Name      string
	Transport string
}

type ProbeEndpoint struct {
	Endpoint       string `json:"endpoint"`
	Source         string `json:"source"`
	Host           string `json:"host,omitempty"`
	Port           int    `json:"port,omitempty"`
	Scope          string `json:"scope,omitempty"`
	Reachable      bool   `json:"reachable"`
	PivotReachable bool   `json:"pivot_reachable,omitempty"`
	PivotTarget    string `json:"pivot_target,omitempty"`
	PivotScheme    string `json:"pivot_scheme,omitempty"`
	ProxyTried     string `json:"proxy_tried,omitempty"`
}

type ProbeMethodResult struct {
	Method         string `json:"method"`
	Transport      string `json:"transport"`
	TunnelAttempts int    `json:"tunnel_attempts,omitempty"`
	TunnelSuccess  int    `json:"tunnel_success,omitempty"`
	ExfilAttempts  int    `json:"exfil_attempts,omitempty"`
	ExfilSuccess   int    `json:"exfil_success,omitempty"`
}

type ProbePortResult struct {
	Port           int  `json:"port"`
	TunnelAttempts int  `json:"tunnel_attempts,omitempty"`
	TunnelSuccess  int  `json:"tunnel_success,omitempty"`
	ExfilAttempts  int  `json:"exfil_attempts,omitempty"`
	ExfilSuccess   int  `json:"exfil_success,omitempty"`
	ListenerBound  bool `json:"listener_bound,omitempty"`
}

type ProbeCheck struct {
	Kind      string `json:"kind"`
	Method    string `json:"method"`
	Transport string `json:"transport"`
	Port      int    `json:"port"`
	Success   bool   `json:"success"`
	Peer      string `json:"peer,omitempty"`
}

type ProbeSummary struct {
	Enabled              bool                `json:"enabled"`
	Mode                 string              `json:"mode"`
	Role                 string              `json:"role"`
	Endpoint             string              `json:"endpoint,omitempty"`
	Ports                []int               `json:"ports,omitempty"`
	Protocols            []string            `json:"protocols,omitempty"`
	TunnelAttempts       int                 `json:"tunnel_attempts,omitempty"`
	TunnelSuccess        int                 `json:"tunnel_success,omitempty"`
	ExfilAttempts        int                 `json:"exfil_attempts,omitempty"`
	ExfilSuccess         int                 `json:"exfil_success,omitempty"`
	PortsUnavailable     []int               `json:"ports_unavailable,omitempty"`
	ListenerReady        bool                `json:"listener_ready,omitempty"`
	ListenerSeconds      int                 `json:"listener_seconds,omitempty"`
	ListenerExchanges    int                 `json:"listener_exchanges,omitempty"`
	MethodResults        []ProbeMethodResult `json:"method_results,omitempty"`
	PortResults          []ProbePortResult   `json:"port_results,omitempty"`
	SuccessfulChecks     []ProbeCheck        `json:"successful_checks,omitempty"`
	FailedChecks         []ProbeCheck        `json:"failed_checks,omitempty"`
	InternalRoutes       []string            `json:"internal_routes,omitempty"`
	InternetSubnets      []string            `json:"internet_subnets,omitempty"`
	Proxies              []ProbeEndpoint     `json:"proxies,omitempty"`
	ConfigEndpoints      []ProbeEndpoint     `json:"config_endpoints,omitempty"`
	ReachableProxyCount  int                 `json:"reachable_proxy_count,omitempty"`
	PivotProxyCount      int                 `json:"pivot_proxy_count,omitempty"`
	ProxyPivotTarget     string              `json:"proxy_pivot_target,omitempty"`
	ReachableConfigCount int                 `json:"reachable_config_count,omitempty"`
}

func DefaultProbeMode() string { return ProbeModeChecks }

func ProbeModeOptions() []string {
	out := make([]string, len(probeModeOptions))
	copy(out, probeModeOptions)
	return out
}

func NormalizeProbeMode(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case ProbeModeChecks, "chacks", "check", "verify", "validation", "tunnel", "exfil", "both":
		return ProbeModeChecks
	case ProbeModeSweep, "scan", "discovery":
		return ProbeModeSweep
	case "", "disabled", "disable", "none", "false", "0", ProbeModeOff:
		return ProbeModeOff
	default:
		return DefaultProbeMode()
	}
}

func ProbeModeLabel(v string) string {
	switch NormalizeProbeMode(v) {
	case ProbeModeOff:
		return "Off"
	case ProbeModeSweep:
		return "Sweep"
	default:
		return "Checks"
	}
}

func DefaultProbeRole() string {
	return ProbeRoleClient
}

func ProbeRoleOptions() []string {
	out := make([]string, len(probeRoleOptions))
	copy(out, probeRoleOptions)
	return out
}

func NormalizeProbeRole(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case ProbeRoleListen, "listener", "server", "srv":
		return ProbeRoleListen
	case ProbeRoleScan, "scanner", "standalone":
		return ProbeRoleScan
	case "", ProbeRoleClient, "connect":
		return ProbeRoleClient
	default:
		return DefaultProbeRole()
	}
}

func ProbeRoleLabel(v string) string {
	switch NormalizeProbeRole(v) {
	case ProbeRoleListen:
		return "Listener"
	case ProbeRoleScan:
		return "Scan"
	default:
		return "Client"
	}
}

func defaultProbeProtocolNames() []string {
	out := make([]string, 0, len(defaultProtocols))
	for _, proto := range defaultProtocols {
		out = append(out, proto.Name)
	}
	return out
}

func defaultProbePortsCopy() []int {
	out := make([]int, len(defaultProbePorts))
	copy(out, defaultProbePorts)
	return out
}

func runProbeSuite(ctx context.Context, mode, role, endpoint string, duration time.Duration, samples []shared.Candidate) (ProbeSummary, []Finding) {
	if ctx == nil {
		ctx = context.Background()
	}
	mode = NormalizeProbeMode(mode)
	role = NormalizeProbeRole(role)
	if role == ProbeRoleListen {
		mode = ProbeModeChecks
	} else if role == ProbeRoleScan {
		if mode == ProbeModeChecks {
			mode = ProbeModeSweep
		}
	} else if mode == ProbeModeSweep {
		mode = ProbeModeChecks
	}
	endpoint = strings.TrimSpace(endpoint)

	summary := ProbeSummary{
		Enabled:   mode != ProbeModeOff,
		Mode:      mode,
		Role:      role,
		Endpoint:  endpoint,
		Ports:     defaultProbePortsCopy(),
		Protocols: defaultProbeProtocolNames(),
	}
	if mode == ProbeModeOff {
		return summary, nil
	}
	if err := ctx.Err(); err != nil {
		return summary, nil
	}

	findings := make([]Finding, 0, 12)
	if role == ProbeRoleListen {
		listenFor := duration
		if listenFor <= 0 {
			listenFor = 30 * time.Second
		}
		listenerStats := runListenerProbe(ctx, summary.Ports, listenFor)
		summary.PortsUnavailable = listenerStats.portsUnavailable
		summary.ListenerReady = listenerStats.ready
		summary.ListenerSeconds = int(listenerStats.duration.Round(time.Second).Seconds())
		summary.ListenerExchanges = listenerStats.exchanges
		summary.PortResults = listenerStats.portResults
		summary.SuccessfulChecks = listenerStats.checks
		for _, check := range listenerStats.checks {
			switch strings.ToLower(strings.TrimSpace(check.Kind)) {
			case "exfil":
				summary.ExfilAttempts++
				summary.ExfilSuccess++
			default:
				summary.TunnelAttempts++
				summary.TunnelSuccess++
			}
		}
		if err := ctx.Err(); err != nil {
			return summary, nil
		}
		findings = append(findings, buildProbeFindings(summary)...)
		return summary, normalizeFindings(findings)
	} else {
		host, normalizedEndpoint, ok := parseProbeTarget(endpoint)
		summary.Endpoint = normalizedEndpoint
		if !ok {
			findings = append(findings, makeProbeFinding(
				"escape",
				"invalid-endpoint",
				"watch",
				"contour-probe-endpoint-invalid",
				"Client/Scan roles require an endpoint host (example: 10.0.0.12 or 10.0.0.12:443).",
				map[string]any{"endpoint": endpoint},
			))
		} else {
			probeFn := probeProtocolRoundTrip
			if role == ProbeRoleScan {
				probeFn = probeEndpointScanRoundTrip
			}
			matrixMode := probeMatrixModeTunnel
			verificationRounds := 1
			if role == ProbeRoleScan || mode == ProbeModeSweep {
				// Sweep is a connectivity matrix only.
				matrixMode = probeMatrixModeTunnel
			} else {
				// Checks verify both tunnel establishment and exfil payload transfer.
				matrixMode = probeMatrixModeBoth
				verificationRounds = 3
			}
			probeTimeout := 900 * time.Millisecond
			if matrixMode == probeMatrixModeBoth {
				// Tunnel checks include multi-step carrier + SOCKS5 handshakes.
				probeTimeout = 4 * time.Second
			}
			matrix := runRemoteProbeMatrix(ctx, host, matrixMode, summary.Ports, defaultProtocols, probeTimeout, verificationRounds, probeFn)
			summary.TunnelAttempts = matrix.tunnelAttempts
			summary.TunnelSuccess = matrix.tunnelSuccess
			summary.ExfilAttempts = matrix.exfilAttempts
			summary.ExfilSuccess = matrix.exfilSuccess
			summary.PortsUnavailable = matrix.portsUnavailable
			summary.MethodResults = matrix.methodResults
			summary.PortResults = matrix.portResults
			summary.SuccessfulChecks = matrix.successChecks
			summary.FailedChecks = matrix.failedChecks
		}
	}
	if err := ctx.Err(); err != nil {
		return summary, nil
	}

	internalRoutes, internetSubnets := discoverRouteHints(ctx)
	summary.InternalRoutes = internalRoutes
	summary.InternetSubnets = internetSubnets

	proxies := mergeProbeEndpoints(discoverEnvProxyEndpoints(), discoverSampleProxyEndpoints(samples))
	configEndpoints := mergeProbeEndpoints(discoverConfigEndpoints(samples), discoverEnvConfigEndpoints())

	summary.Proxies, summary.ReachableProxyCount, summary.PivotProxyCount = testProxyEndpointReachability(ctx, proxies, 1200*time.Millisecond)
	if summary.PivotProxyCount > 0 {
		summary.ProxyPivotTarget = defaultProbePivotTarget
	}
	summary.ConfigEndpoints, summary.ReachableConfigCount, _ = testEndpointReachability(ctx, configEndpoints, 700*time.Millisecond)

	findings = append(findings, buildProbeFindings(summary)...)
	return summary, normalizeFindings(findings)
}

type probeMatrixStats struct {
	tunnelAttempts   int
	tunnelSuccess    int
	exfilAttempts    int
	exfilSuccess     int
	portsUnavailable []int
	methodResults    []ProbeMethodResult
	portResults      []ProbePortResult
	successChecks    []ProbeCheck
	failedChecks     []ProbeCheck
}

type probeMethodCounter struct {
	method    string
	transport string
	tunnelA   int
	tunnelS   int
	exfilA    int
	exfilS    int
}

type probePortCounter struct {
	port    int
	tunnelA int
	tunnelS int
	exfilA  int
	exfilS  int
}

type probeJob struct {
	kind  string
	proto probeProtocol
	port  int
}

type probeJobResult struct {
	job     probeJob
	success bool
}

func runRemoteProbeMatrix(
	ctx context.Context,
	host, mode string,
	ports []int,
	protocols []probeProtocol,
	timeout time.Duration,
	verificationRounds int,
	probeFn func(context.Context, string, int, string, probeProtocol, time.Duration) bool,
) probeMatrixStats {
	if ctx == nil {
		ctx = context.Background()
	}
	if probeFn == nil {
		probeFn = probeProtocolRoundTrip
	}
	if verificationRounds <= 0 {
		verificationRounds = 1
	}
	stats := probeMatrixStats{}
	includesTunnel := mode == probeMatrixModeTunnel || mode == probeMatrixModeBoth
	includesExfil := mode == probeMatrixModeExfil || mode == probeMatrixModeBoth
	methodCounters := make(map[string]*probeMethodCounter, len(protocols))
	portCounters := make(map[int]*probePortCounter, len(ports))
	jobs := make([]probeJob, 0, len(ports)*len(protocols)*2)
	for _, proto := range protocols {
		key := strings.ToLower(strings.TrimSpace(proto.Transport)) + "/" + strings.ToLower(strings.TrimSpace(proto.Name))
		methodCounters[key] = &probeMethodCounter{
			method:    strings.TrimSpace(proto.Name),
			transport: strings.ToLower(strings.TrimSpace(proto.Transport)),
		}
	}
	for _, port := range ports {
		portCounters[port] = &probePortCounter{port: port}
		for _, proto := range protocols {
			if includesTunnel {
				// Sweep (connectivity-only) probes all methods. Checks mode verifies
				// tunnel capability only on the explicit carrier methods.
				if mode == probeMatrixModeTunnel || methodUsesSocksCarrierTunnel(proto.Name) {
					jobs = append(jobs, probeJob{kind: "tunnel", proto: proto, port: port})
				}
			}
			if includesExfil {
				jobs = append(jobs, probeJob{kind: "exfil", proto: proto, port: port})
			}
		}
	}
	appendCheck := func(kind string, proto probeProtocol, port int, success bool) {
		kind = strings.ToLower(strings.TrimSpace(kind))
		transport := strings.ToLower(strings.TrimSpace(proto.Transport))
		method := strings.TrimSpace(proto.Name)
		key := transport + "/" + strings.ToLower(method)
		m := methodCounters[key]
		if m == nil {
			m = &probeMethodCounter{method: method, transport: transport}
			methodCounters[key] = m
		}
		p := portCounters[port]
		if p == nil {
			p = &probePortCounter{port: port}
			portCounters[port] = p
		}
		switch kind {
		case "tunnel":
			stats.tunnelAttempts++
			m.tunnelA++
			p.tunnelA++
			if success {
				stats.tunnelSuccess++
				m.tunnelS++
				p.tunnelS++
			}
		case "exfil":
			stats.exfilAttempts++
			m.exfilA++
			p.exfilA++
			if success {
				stats.exfilSuccess++
				m.exfilS++
				p.exfilS++
			}
		}
		check := ProbeCheck{
			Kind:      kind,
			Method:    method,
			Transport: transport,
			Port:      port,
			Success:   success,
		}
		if success {
			stats.successChecks = append(stats.successChecks, check)
			return
		}
		stats.failedChecks = append(stats.failedChecks, check)
	}

	if len(jobs) > 0 {
		workerCount := max(4, len(ports)*2)
		if workerCount > 32 {
			workerCount = 32
		}
		if mode == probeMatrixModeBoth && workerCount > 8 {
			// Checks mode performs multi-step verification on every probe and is
			// more reliable with lower in-flight concurrency.
			workerCount = 8
		}
		if workerCount > len(jobs) {
			workerCount = len(jobs)
		}
		jobsCh := make(chan probeJob)
		resultsCh := make(chan probeJobResult, workerCount*2)
		var wg sync.WaitGroup
		for i := 0; i < workerCount; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for job := range jobsCh {
					if err := ctx.Err(); err != nil {
						return
					}
					success := true
					for round := 0; round < verificationRounds; round++ {
						if err := ctx.Err(); err != nil {
							return
						}
						if !probeFn(ctx, host, job.port, job.kind, job.proto, timeout) {
							success = false
							break
						}
					}
					select {
					case resultsCh <- probeJobResult{job: job, success: success}:
					case <-ctx.Done():
						return
					}
				}
			}()
		}
		go func() {
			defer close(jobsCh)
			for _, job := range jobs {
				select {
				case jobsCh <- job:
				case <-ctx.Done():
					return
				}
			}
		}()
		go func() {
			wg.Wait()
			close(resultsCh)
		}()
		attemptsByPort := make(map[int]int, len(ports))
		successByPort := make(map[int]int, len(ports))
		for result := range resultsCh {
			appendCheck(result.job.kind, result.job.proto, result.job.port, result.success)
			attemptsByPort[result.job.port]++
			if result.success {
				successByPort[result.job.port]++
			}
		}
		for _, port := range ports {
			if attemptsByPort[port] > 0 && successByPort[port] == 0 {
				stats.portsUnavailable = append(stats.portsUnavailable, port)
			}
		}
	}
	stats.methodResults = flattenMethodCounters(methodCounters)
	stats.portResults = flattenPortCounters(portCounters)
	sortProbeChecks(stats.successChecks)
	sortProbeChecks(stats.failedChecks)
	sort.Ints(stats.portsUnavailable)
	return stats
}

func sortProbeChecks(checks []ProbeCheck) {
	sort.SliceStable(checks, func(i, j int) bool {
		if checks[i].Kind != checks[j].Kind {
			return checks[i].Kind < checks[j].Kind
		}
		if checks[i].Transport != checks[j].Transport {
			return checks[i].Transport < checks[j].Transport
		}
		if checks[i].Method != checks[j].Method {
			return checks[i].Method < checks[j].Method
		}
		return checks[i].Port < checks[j].Port
	})
}

func flattenMethodCounters(counters map[string]*probeMethodCounter) []ProbeMethodResult {
	if len(counters) == 0 {
		return nil
	}
	out := make([]ProbeMethodResult, 0, len(counters))
	for _, c := range counters {
		out = append(out, ProbeMethodResult{
			Method:         c.method,
			Transport:      c.transport,
			TunnelAttempts: c.tunnelA,
			TunnelSuccess:  c.tunnelS,
			ExfilAttempts:  c.exfilA,
			ExfilSuccess:   c.exfilS,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Transport != out[j].Transport {
			return out[i].Transport < out[j].Transport
		}
		return out[i].Method < out[j].Method
	})
	return out
}

func flattenPortCounters(counters map[int]*probePortCounter) []ProbePortResult {
	if len(counters) == 0 {
		return nil
	}
	out := make([]ProbePortResult, 0, len(counters))
	for _, c := range counters {
		out = append(out, ProbePortResult{
			Port:           c.port,
			TunnelAttempts: c.tunnelA,
			TunnelSuccess:  c.tunnelS,
			ExfilAttempts:  c.exfilA,
			ExfilSuccess:   c.exfilS,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Port < out[j].Port
	})
	return out
}

type listenerProbeStats struct {
	ready            bool
	duration         time.Duration
	portsUnavailable []int
	exchanges        int
	portResults      []ProbePortResult
	checks           []ProbeCheck
}

type probeListenerRecorder struct {
	mu     sync.Mutex
	checks []ProbeCheck
}

func newProbeListenerRecorder(capacity int) *probeListenerRecorder {
	if capacity < 0 {
		capacity = 0
	}
	return &probeListenerRecorder{checks: make([]ProbeCheck, 0, capacity)}
}

func (r *probeListenerRecorder) record(check ProbeCheck) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.checks = append(r.checks, check)
	r.mu.Unlock()
}

func (r *probeListenerRecorder) snapshot() []ProbeCheck {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	out := make([]ProbeCheck, len(r.checks))
	copy(out, r.checks)
	r.mu.Unlock()
	return out
}

func runListenerProbe(ctx context.Context, ports []int, duration time.Duration) listenerProbeStats {
	if ctx == nil {
		ctx = context.Background()
	}
	if duration <= 0 {
		duration = 30 * time.Second
	}
	startedAt := time.Now()
	stats := listenerProbeStats{duration: duration}
	var exchangeCounter uint64
	recorder := newProbeListenerRecorder(len(ports) * 4)
	closers := make([]func(), 0, len(ports)*2)
	readyPorts := 0
	portReady := make(map[int]bool, len(ports))

	for _, port := range ports {
		tcpLn, tcpErr := startTCPEchoServerOn("0.0.0.0", port, &exchangeCounter, recorder)
		udpSrv, udpErr := startUDPEchoServerOn("0.0.0.0", port, &exchangeCounter, recorder)
		if tcpErr != nil && udpErr != nil {
			stats.portsUnavailable = append(stats.portsUnavailable, port)
			continue
		}
		readyPorts++
		portReady[port] = true
		if tcpLn != nil {
			ln := tcpLn
			closers = append(closers, func() {
				_ = ln.Close()
			})
		}
		if udpSrv != nil {
			srv := udpSrv
			closers = append(closers, srv.Close)
		}
	}

	stats.ready = readyPorts > 0
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
	for _, closeFn := range closers {
		closeFn()
	}
	stats.duration = time.Since(startedAt)
	stats.exchanges = int(atomic.LoadUint64(&exchangeCounter))
	stats.checks = recorder.snapshot()
	stats.portResults = make([]ProbePortResult, 0, len(ports))
	for _, port := range ports {
		stats.portResults = append(stats.portResults, ProbePortResult{
			Port:          port,
			ListenerBound: portReady[port],
		})
	}
	sort.SliceStable(stats.portResults, func(i, j int) bool {
		return stats.portResults[i].Port < stats.portResults[j].Port
	})
	sort.Ints(stats.portsUnavailable)
	return stats
}

func buildProbeFindings(summary ProbeSummary) []Finding {
	if !summary.Enabled {
		return nil
	}
	findings := make([]Finding, 0, 10)
	if summary.Role == ProbeRoleListen {
		if summary.ListenerReady {
			severity := "strong"
			if summary.ListenerExchanges > 0 {
				severity = "active"
			}
			reason := fmt.Sprintf("Probe listener bound %d/%d target ports for %ds and processed %d exchange%s.", len(summary.Ports)-len(summary.PortsUnavailable), len(summary.Ports), summary.ListenerSeconds, summary.ListenerExchanges, plural(summary.ListenerExchanges))
			findings = append(findings, makeProbeFinding("tunnel", "listener-readiness", severity, "contour-probe-listener-ready", reason, map[string]any{
				"listener_seconds":   summary.ListenerSeconds,
				"listener_exchanges": summary.ListenerExchanges,
				"ports_total":        len(summary.Ports),
				"ports_unavailable":  summary.PortsUnavailable,
			}))
		} else {
			reason := "Probe listener could not bind any of the target ports."
			findings = append(findings, makeProbeFinding("escape", "listener-bind-failed", "watch", "contour-probe-listener-bind-failed", reason, map[string]any{
				"ports_unavailable": summary.PortsUnavailable,
			}))
		}
	}

	if summary.TunnelAttempts > 0 {
		ratio := float64(summary.TunnelSuccess) / float64(summary.TunnelAttempts)
		severity := "watch"
		switch {
		case ratio >= 0.80 && summary.TunnelSuccess >= 40:
			severity = "active"
		case ratio >= 0.40 && summary.TunnelSuccess >= 16:
			severity = "strong"
		}
		if summary.Role == ProbeRoleScan {
			reason := fmt.Sprintf("Scan connectivity matrix succeeded on %d/%d protocol-port checks.", summary.TunnelSuccess, summary.TunnelAttempts)
			findings = append(findings, makeProbeFinding("network", "connectivity-port-cycle", severity, "contour-probe-connectivity-matrix", reason, map[string]any{
				"mode":           summary.Mode,
				"endpoint":       summary.Endpoint,
				"ports":          summary.Ports,
				"protocol_count": len(summary.Protocols),
				"success":        summary.TunnelSuccess,
				"attempts":       summary.TunnelAttempts,
			}))
		} else {
			reason := fmt.Sprintf("Tunnel probe matrix succeeded on %d/%d protocol-port checks.", summary.TunnelSuccess, summary.TunnelAttempts)
			findings = append(findings, makeProbeFinding("tunnel", "multi-protocol-port-cycle", severity, "contour-probe-tunnel-matrix", reason, map[string]any{
				"mode":           summary.Mode,
				"endpoint":       summary.Endpoint,
				"ports":          summary.Ports,
				"protocol_count": len(summary.Protocols),
				"success":        summary.TunnelSuccess,
				"attempts":       summary.TunnelAttempts,
			}))
		}
	}

	if summary.Role != ProbeRoleScan && summary.ExfilAttempts > 0 {
		ratio := float64(summary.ExfilSuccess) / float64(summary.ExfilAttempts)
		severity := "watch"
		switch {
		case ratio >= 0.80 && summary.ExfilSuccess >= 40:
			severity = "active"
		case ratio >= 0.40 && summary.ExfilSuccess >= 16:
			severity = "strong"
		}
		reason := fmt.Sprintf("Exfil probe matrix succeeded on %d/%d protocol-port checks.", summary.ExfilSuccess, summary.ExfilAttempts)
		findings = append(findings, makeProbeFinding("exfiltration", "multi-protocol-port-exfil", severity, "contour-probe-exfil-matrix", reason, map[string]any{
			"mode":           summary.Mode,
			"endpoint":       summary.Endpoint,
			"ports":          summary.Ports,
			"protocol_count": len(summary.Protocols),
			"success":        summary.ExfilSuccess,
			"attempts":       summary.ExfilAttempts,
		}))
	}

	if len(summary.PortsUnavailable) > 0 {
		reason := fmt.Sprintf("%d top ports were unavailable or returned no successful probe exchanges.", len(summary.PortsUnavailable))
		findings = append(findings, makeProbeFinding("escape", "blocked-probe-port", "watch", "contour-probe-port-unavailable", reason, map[string]any{
			"ports_unavailable": summary.PortsUnavailable,
		}))
	}

	if len(summary.InternetSubnets) > 0 {
		severity := "watch"
		if len(summary.InternetSubnets) >= 2 {
			severity = "strong"
		}
		reason := fmt.Sprintf("Detected %d internet-routable local subnet%s.", len(summary.InternetSubnets), plural(len(summary.InternetSubnets)))
		findings = append(findings, makeProbeFinding("network", "internet-usable-subnet", severity, "contour-probe-internet-subnets", reason, map[string]any{
			"internet_subnets": summary.InternetSubnets,
		}))
	}

	if summary.ReachableProxyCount > 0 {
		severity := "strong"
		if summary.ReachableProxyCount >= 3 {
			severity = "active"
		}
		reason := fmt.Sprintf("Detected %d reachable proxy endpoint%s from env and traffic analysis.", summary.ReachableProxyCount, plural(summary.ReachableProxyCount))
		findings = append(findings, makeProbeFinding("escape", "proxy-egress-endpoint", severity, "contour-probe-proxy-endpoint", reason, map[string]any{
			"reachable_proxies": summary.ReachableProxyCount,
			"proxy_total":       len(summary.Proxies),
			"pivot_proxies":     summary.PivotProxyCount,
			"pivot_target":      summary.ProxyPivotTarget,
		}))
	} else if len(summary.Proxies) > 0 {
		reason := fmt.Sprintf("Detected %d proxy endpoint%s, but none were reachable during active tests.", len(summary.Proxies), plural(len(summary.Proxies)))
		findings = append(findings, makeProbeFinding("escape", "proxy-endpoint-discovered", "watch", "contour-probe-proxy-discovered", reason, map[string]any{
			"proxy_total": len(summary.Proxies),
		}))
	}
	if summary.PivotProxyCount > 0 {
		severity := "strong"
		if summary.PivotProxyCount >= 2 {
			severity = "active"
		}
		reason := fmt.Sprintf("Verified %d reachable proxy endpoint%s can pivot to %s.", summary.PivotProxyCount, plural(summary.PivotProxyCount), nonEmpty(strings.TrimSpace(summary.ProxyPivotTarget), defaultProbePivotTarget))
		findings = append(findings, makeProbeFinding("escape", "proxy-pivot-path", severity, "contour-probe-proxy-pivot", reason, map[string]any{
			"pivot_proxies": summary.PivotProxyCount,
			"pivot_target":  nonEmpty(strings.TrimSpace(summary.ProxyPivotTarget), defaultProbePivotTarget),
		}))
	}

	if len(summary.ConfigEndpoints) > 0 {
		severity := "watch"
		if summary.ReachableConfigCount >= 2 {
			severity = "strong"
		}
		reason := fmt.Sprintf("Discovered %d endpoint%s in config files and environment context (%d reachable).", len(summary.ConfigEndpoints), plural(len(summary.ConfigEndpoints)), summary.ReachableConfigCount)
		findings = append(findings, makeProbeFinding("exfiltration", "config-endpoint-discovery", severity, "contour-probe-config-endpoint", reason, map[string]any{
			"config_endpoint_total":     len(summary.ConfigEndpoints),
			"config_endpoint_reachable": summary.ReachableConfigCount,
		}))
	}

	return normalizeFindings(findings)
}

func makeProbeFinding(category, technique, severity, signal, reason string, evidence map[string]any) Finding {
	return Finding{
		CandidateKey: "",
		Host:         "local",
		PID:          0,
		Process:      "contour-probe",
		Role:         "other",
		Category:     strings.TrimSpace(category),
		Technique:    strings.TrimSpace(technique),
		Severity:     shared.NormalizeContourSeverity(severity),
		Signal:       strings.TrimSpace(signal),
		Reason:       strings.TrimSpace(reason),
		Evidence:     evidence,
	}
}

type probePacket struct {
	Kind   string
	Method string
	Port   int
	Exfil  bool
	Nonce  uint64
	Body   []byte
}

func probeProtocolRoundTrip(ctx context.Context, host string, port int, kind string, proto probeProtocol, timeout time.Duration) bool {
	method := strings.ToLower(strings.TrimSpace(proto.Name))
	transport := strings.ToLower(strings.TrimSpace(proto.Transport))
	isExfil := strings.EqualFold(strings.TrimSpace(kind), "exfil")
	if !isExfil && transport == "tcp" && methodUsesSocksCarrierTunnel(method) {
		return probeSocksCarrierTunnelRoundTrip(ctx, host, port, method, timeout)
	}
	request := buildProbeMethodRequestBody(method, port, isExfil)
	if len(request) == 0 {
		return false
	}
	if transport == "udp" {
		return probeUDPRoundTrip(ctx, host, port, method, request, timeout)
	}
	return probeTCPRoundTrip(ctx, host, port, method, request, timeout)
}

func probeEndpointScanRoundTrip(ctx context.Context, host string, port int, kind string, proto probeProtocol, timeout time.Duration) bool {
	transport := strings.ToLower(strings.TrimSpace(proto.Transport))
	method := strings.ToLower(strings.TrimSpace(proto.Name))
	_ = kind
	switch transport {
	case "udp":
		return probeEndpointUDPScan(ctx, host, port, method, timeout)
	default:
		if _, ok := probeTLSMethods[method]; ok {
			return probeEndpointTLSScan(ctx, host, port, method, timeout)
		}
		return probeEndpointTCPScan(ctx, host, port, method, timeout)
	}
}

func probeEndpointTCPScan(ctx context.Context, host string, port int, method string, timeout time.Duration) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return false
	}
	payload := buildProbeMethodBaseRequestBody(method, port)
	if len(payload) == 0 {
		return false
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	nw, err := conn.Write(payload)
	if err != nil || nw < len(payload) {
		return false
	}
	buf := make([]byte, 4096)
	nr, err := conn.Read(buf)
	if nr > 0 {
		// Match recognizable method-level responses when present.
		if validateEndpointScanResponse(method, buf[:nr]) {
			return true
		}
	}
	if err == nil {
		return nr > 0
	}
	// If write succeeded and peer simply closed/timeouted, keep as allowed for scan mode.
	if errors.Is(err, io.EOF) || isNetTimeout(err) {
		return true
	}
	return false
}

func probeEndpointTLSScan(ctx context.Context, host string, port int, method string, timeout time.Duration) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return false
	}
	serverName := host
	if net.ParseIP(serverName) != nil {
		serverName = ""
	}
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, strconv.Itoa(port)), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
	})
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	payload := buildProbeMethodBaseRequestBody(method, port)
	if len(payload) == 0 {
		return true
	}
	nw, err := conn.Write(payload)
	if err != nil || nw < len(payload) {
		return false
	}
	buf := make([]byte, 4096)
	nr, err := conn.Read(buf)
	if nr > 0 && validateEndpointScanResponse(method, buf[:nr]) {
		return true
	}
	if err == nil {
		return nr > 0
	}
	if errors.Is(err, io.EOF) || isNetTimeout(err) {
		return true
	}
	return false
}

func probeEndpointUDPScan(ctx context.Context, host string, port int, method string, timeout time.Duration) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return false
	}
	payload := buildProbeMethodBaseRequestBody(method, port)
	if len(payload) == 0 {
		return false
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if nw, err := conn.Write(payload); err != nil || nw < len(payload) {
		return false
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n <= 0 {
		return false
	}
	return validateEndpointScanResponse(method, buf[:n]) || n > 0
}

func validateEndpointScanResponse(method string, response []byte) bool {
	if len(response) == 0 {
		return false
	}
	lower := strings.ToLower(string(response))
	switch method {
	case "http", "https":
		return strings.HasPrefix(lower, "http/")
	case "ws", "wss":
		return strings.Contains(lower, "101 switching protocols") || strings.Contains(lower, "websocket")
	case "ssh":
		return strings.HasPrefix(lower, "ssh-")
	case "smtp", "smtps":
		return strings.HasPrefix(lower, "220") || strings.HasPrefix(lower, "250")
	case "imap", "imaps":
		return strings.HasPrefix(lower, "* ") || strings.Contains(lower, "capability")
	case "pop3", "pop3s":
		return strings.HasPrefix(lower, "+ok") || strings.HasPrefix(lower, "-err")
	case "ftp", "ftps":
		return strings.HasPrefix(lower, "220") || strings.HasPrefix(lower, "211")
	case "smb":
		return bytes.Contains(response, []byte("SMB"))
	case "rdp":
		return len(response) >= 2 && response[0] == 0x03 && response[1] == 0x00
	case "ldap", "ldaps":
		return response[0] == 0x30
	case "socks4":
		return len(response) >= 2 && response[1] >= 0x5a && response[1] <= 0x5d
	case "socks5":
		return len(response) >= 2 && response[0] == 0x05
	case "mqtt":
		return len(response) >= 2 && (response[0]&0xf0) == 0x20
	case "amqp":
		return bytes.HasPrefix(response, []byte("AMQP"))
	case "postgres":
		return len(response) >= 1 && bytes.Contains([]byte("ERNST"), []byte{response[0]})
	case "dns":
		return len(response) >= 12 && (response[2]&0x80) != 0
	case "ntp":
		return len(response) >= 48
	case "quic":
		return len(response) > 0
	case "webrtc":
		return len(response) >= 20 &&
			binary.BigEndian.Uint16(response[0:2]) == 0x0101 &&
			binary.BigEndian.Uint32(response[4:8]) == 0x2112a442
	case "sip":
		return strings.HasPrefix(lower, "sip/2.0")
	case "rtsp":
		return strings.HasPrefix(lower, "rtsp/1.0")
	case "snmp":
		return len(response) >= 16 &&
			response[0] == 0x30 &&
			bytes.Contains(response, []byte("public")) &&
			bytes.Contains(response, []byte{0xa2})
	case "coap":
		return len(response) >= 4 &&
			(response[0]&0xc0) == 0x40 &&
			response[1] == 0x45
	case "redis":
		return strings.HasPrefix(lower, "+pong")
	default:
		return true
	}
}

func isNetTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func parseProbeTarget(raw string) (host string, normalized string, ok bool) {
	raw = strings.TrimSpace(strings.Trim(raw, `"'`))
	if raw == "" {
		return "", "", false
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || u == nil {
			return "", raw, false
		}
		h := strings.TrimSpace(u.Hostname())
		if h == "" {
			return "", raw, false
		}
		return h, h, true
	}
	if h, p, err := net.SplitHostPort(raw); err == nil {
		h = strings.TrimSpace(strings.Trim(h, "[]"))
		if h == "" {
			return "", raw, false
		}
		if strings.TrimSpace(p) == "" {
			return "", raw, false
		}
		return h, h, true
	}
	if strings.Contains(raw, "/") {
		return "", raw, false
	}
	h := strings.TrimSpace(strings.Trim(raw, "[]"))
	if h == "" {
		return "", raw, false
	}
	return h, h, true
}

func normalizeFindings(findings []Finding) []Finding {
	if len(findings) <= 1 {
		return findings
	}
	sort.SliceStable(findings, func(i, j int) bool {
		si := severityPriority(findings[i].Severity)
		sj := severityPriority(findings[j].Severity)
		if si != sj {
			return si > sj
		}
		if findings[i].Host != findings[j].Host {
			return findings[i].Host < findings[j].Host
		}
		if findings[i].Process != findings[j].Process {
			return findings[i].Process < findings[j].Process
		}
		if findings[i].PID != findings[j].PID {
			return findings[i].PID < findings[j].PID
		}
		return findings[i].Signal < findings[j].Signal
	})
	return dedupeFindings(findings)
}
