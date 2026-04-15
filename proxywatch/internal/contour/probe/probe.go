package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
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
	ProbeModeSweep  = "sweep" // Deprecated: mapped to ProbeModeChecks.
	ProbeModeChecks = "checks"

	probeMatrixModeTunnel = "tunnel"
	probeMatrixModeExfil  = "exfil"
	probeMatrixModeBoth   = "both"

	ProbeRoleClient = "client"
	ProbeRoleListen = "listen"
	ProbeRoleScan   = "scan" // Deprecated: mapped to ProbeRoleClient.

	DefaultProbePivotTarget = "ifconfig.me:443"
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
	Enabled                  bool                 `json:"enabled"`
	Mode                     string               `json:"mode"`
	Role                     string               `json:"role"`
	Endpoint                 string               `json:"endpoint,omitempty"`
	Ports                    []int                `json:"ports,omitempty"`
	Protocols                []string             `json:"protocols,omitempty"`
	TunnelAttempts           int                  `json:"tunnel_attempts,omitempty"`
	TunnelSuccess            int                  `json:"tunnel_success,omitempty"`
	ExfilAttempts            int                  `json:"exfil_attempts,omitempty"`
	ExfilSuccess             int                  `json:"exfil_success,omitempty"`
	PortsUnavailable         []int                `json:"ports_unavailable,omitempty"`
	ListenerReady            bool                 `json:"listener_ready,omitempty"`
	ListenerSeconds          int                  `json:"listener_seconds,omitempty"`
	ListenerExchanges        int                  `json:"listener_exchanges,omitempty"`
	MethodResults            []ProbeMethodResult  `json:"method_results,omitempty"`
	PortResults              []ProbePortResult    `json:"port_results,omitempty"`
	SuccessfulChecks         []ProbeCheck         `json:"successful_checks,omitempty"`
	FailedChecks             []ProbeCheck         `json:"failed_checks,omitempty"`
	InternalRoutes           []string             `json:"internal_routes,omitempty"`
	InternetSubnets          []string             `json:"internet_subnets,omitempty"`
	Proxies                  []ProbeEndpoint      `json:"proxies,omitempty"`
	ConfigEndpoints          []ProbeEndpoint      `json:"config_endpoints,omitempty"`
	ReachableProxyCount      int                  `json:"reachable_proxy_count,omitempty"`
	PivotProxyCount          int                  `json:"pivot_proxy_count,omitempty"`
	ProxyPivotTarget         string               `json:"proxy_pivot_target,omitempty"`
	ReachableConfigCount     int                  `json:"reachable_config_count,omitempty"`
	ServiceReachable         []string             `json:"service_reachable,omitempty"`
	ServiceBlocked           []string             `json:"service_blocked,omitempty"`
	ServiceResults           []ServiceProbeResult `json:"service_results,omitempty"`
	HTTPMethodsAllowed       []string             `json:"http_methods_allowed,omitempty"`
	HTTPMethodsChecked       bool                 `json:"http_methods_checked,omitempty"`
	TLSChecked               bool                 `json:"tls_checked,omitempty"`
	TLSIntercepted           bool                 `json:"tls_intercepted,omitempty"`
	TLSInterceptOrg          string               `json:"tls_intercept_org,omitempty"`
	TLSInterceptIssuer       string               `json:"tls_intercept_issuer,omitempty"`       // full issuer CN
	TLSInterceptExpectedOrg  string               `json:"tls_intercept_expected_org,omitempty"` // what the cert SHOULD have been
	DomainFrontingPossible   bool                 `json:"domain_fronting_possible,omitempty"`
	DomainFrontingSNI        string               `json:"domain_fronting_sni,omitempty"`
	DomainFrontingCDN        string               `json:"domain_fronting_cdn,omitempty"`         // which CDN was vulnerable
	DomainFrontingCDNIP      string               `json:"domain_fronting_cdn_ip,omitempty"`      // CDN anycast IP used
	DomainFrontingCertIssuer string               `json:"domain_fronting_cert_issuer,omitempty"` // cert issuer returned
	DomainFrontingViableCDNs []string             `json:"domain_fronting_viable_cdns,omitempty"` // all CDNs that accept mismatched SNI
	AvgLatencyMs             int                  `json:"avg_latency_ms,omitempty"`
	MaxLatencyMs             int                  `json:"max_latency_ms,omitempty"`
}

// ServiceProbeResult records whether a well-known cloud/SaaS service is
// reachable from the host under test.
type ServiceProbeResult struct {
	Name      string `json:"name"`
	Category  string `json:"category"` // "exfil", "escape", "c2"
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Reachable bool   `json:"reachable"`
	Tested    bool   `json:"tested"`
}

// ListenerProbeResult contains the outcome of a listener probe.
type ListenerProbeResult struct {
	Checks           []ProbeCheck
	PortsUnavailable []int
	Exchanges        int
}

// RunListenerProbe starts protocol-aware listeners on the given ports and
// detects real protocol exchanges from a scanning peer. It blocks until ctx
// is cancelled. onUpdate is called periodically (~1s) with the current
// snapshot so the UI can populate methods incrementally.
func RunListenerProbe(ctx context.Context, ports []int, onUpdate func(ListenerProbeResult)) ListenerProbeResult {
	if ctx == nil {
		ctx = context.Background()
	}
	var exchangeCounter uint64
	recorder := newProbeListenerRecorder(len(ports) * 4)
	closers := make([]func(), 0, len(ports)*2)
	var portsUnavailable []int

	for _, port := range ports {
		tcpLn, tcpErr := startTCPEchoServerOn("0.0.0.0", port, &exchangeCounter, recorder)
		udpSrv, udpErr := startUDPEchoServerOn("0.0.0.0", port, &exchangeCounter, recorder)
		if tcpErr != nil && udpErr != nil {
			portsUnavailable = append(portsUnavailable, port)
			continue
		}
		if tcpLn != nil {
			ln := tcpLn
			closers = append(closers, func() { _ = ln.Close() })
		}
		if udpSrv != nil {
			srv := udpSrv
			closers = append(closers, srv.Close)
		}
	}

	// Periodic snapshot loop — update caller every second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			for _, closeFn := range closers {
				closeFn()
			}
			return ListenerProbeResult{
				Checks:           recorder.snapshot(),
				PortsUnavailable: portsUnavailable,
				Exchanges:        int(atomic.LoadUint64(&exchangeCounter)),
			}
		case <-ticker.C:
			if onUpdate != nil {
				onUpdate(ListenerProbeResult{
					Checks:           recorder.snapshot(),
					PortsUnavailable: portsUnavailable,
					Exchanges:        int(atomic.LoadUint64(&exchangeCounter)),
				})
			}
		}
	}
}

func RunProbeSuiteWithProgress(ctx context.Context, mode, role, endpoint string, duration time.Duration, samples []shared.Candidate, emit func(string), onPartial ...func(ProbeSummary)) (ProbeSummary, []Finding) {
	if emit == nil {
		emit = func(string) {}
	}
	emitSummary := func(s ProbeSummary) {
		if len(onPartial) > 0 && onPartial[0] != nil {
			onPartial[0](s)
		}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	mode = NormalizeProbeMode(mode)
	role = NormalizeProbeRole(role)
	// Listener mode is still supported internally for backwards compatibility
	// with saved reports, even though it is no longer exposed in the UI.
	if role == ProbeRoleListen {
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
		return summary, NormalizeFindings(findings)
	}

	// Pre-populate service results so the UI renders empty grids immediately.
	summary.ServiceResults = make([]ServiceProbeResult, len(serviceTargetNames))
	for i, name := range serviceTargetNames {
		summary.ServiceResults[i] = ServiceProbeResult{Name: name}
	}
	// Emit initial summary so matrices appear with all dots right away.
	emitSummary(summary)

	host, normalizedEndpoint, ok := parseProbeTarget(endpoint)
	summary.Endpoint = normalizedEndpoint
	if !ok {
		findings = append(findings, makeProbeFinding(
			"escape",
			"invalid-endpoint",
			"watch",
			"contour-probe-endpoint-invalid",
			"A target host is required (example: 10.0.0.12 or ifconfig.me).",
			map[string]any{"endpoint": endpoint},
		))
	} else {
		// ── Protocol matrix ──
		emit(fmt.Sprintf("[*] Verifying tunnels on %s (%d ports)...", host, len(summary.Ports)))
		applyMatrix := func(m probeMatrixStats) {
			summary.TunnelAttempts = m.tunnelAttempts
			summary.TunnelSuccess = m.tunnelSuccess
			summary.ExfilAttempts = m.exfilAttempts
			summary.ExfilSuccess = m.exfilSuccess
			summary.PortsUnavailable = m.portsUnavailable
			summary.MethodResults = m.methodResults
			summary.PortResults = m.portResults
			summary.SuccessfulChecks = m.successChecks
			summary.FailedChecks = m.failedChecks
		}
		matrix := runRemoteProbeMatrix(ctx, host, probeMatrixModeBoth, summary.Ports, defaultProtocols, 900*time.Millisecond, 1, probeEndpointScanRoundTrip, func(snap probeMatrixStats) {
			applyMatrix(snap)
			emitSummary(summary)
		})
		applyMatrix(matrix)
		emit(fmt.Sprintf("[+] Protocol matrix: %d/%d", matrix.tunnelSuccess+matrix.exfilSuccess, matrix.tunnelAttempts+matrix.exfilAttempts))
		emitSummary(summary)
	}
	if err := ctx.Err(); err != nil {
		return summary, nil
	}

	// ── Service reachability (runs immediately after matrix) ──
	if mode == ProbeModeChecks {
		if err := ctx.Err(); err == nil {
			emit("[*] Testing reachability of exfil-capable services...")
			serviceTargets := []struct {
				name, category, host string
				port                 int
			}{
				// Cloud storage — attacker uploads exfil data via API/web
				{"Dropbox", "exfil", "www.dropbox.com", 443},
				{"GDrive", "exfil", "drive.google.com", 443},
				{"OneDrive", "exfil", "onedrive.live.com", 443},
				{"S3", "exfil", "s3.amazonaws.com", 443},
				{"AzBlob", "exfil", "blob.core.windows.net", 443},
				{"GCS", "exfil", "storage.googleapis.com", 443},
				{"Box", "exfil", "app.box.com", 443},
				{"Mega", "exfil", "mega.nz", 443},
				{"WeTrans", "exfil", "wetransfer.com", 443},
				{"iCloud", "exfil", "www.icloud.com", 443},
				{"pCloud", "exfil", "api.pcloud.com", 443},
				{"Backblz", "exfil", "api.backblazeb2.com", 443},
				// Messaging — C2 via webhooks/bots/API
				{"Slack", "exfil", "hooks.slack.com", 443},
				{"Discord", "exfil", "discord.com", 443},
				{"Telegra", "exfil", "api.telegram.org", 443},
				{"Teams", "exfil", "teams.microsoft.com", 443},
				// Code hosting — C2 via repos/gists/issues/API
				{"GitHub", "exfil", "api.github.com", 443},
				{"GitLab", "exfil", "gitlab.com", 443},
				{"Bitbkt", "exfil", "bitbucket.org", 443},
				{"Pastbn", "exfil", "pastebin.com", 443},
				{"Gist", "exfil", "gist.github.com", 443},
				{"Codbrg", "exfil", "codeberg.org", 443},
				// Container registries — exfil hidden in container layers
				{"Docker", "exfil", "registry-1.docker.io", 443},
				{"GHCR", "exfil", "ghcr.io", 443},
				{"Quay", "exfil", "quay.io", 443},
				// CI/CD — C2 via build pipelines/artifacts
				{"GHAct", "exfil", "pipelines.actions.githubusercontent.com", 443},
				{"Circle", "exfil", "circleci.com", 443},
				{"Buildkt", "exfil", "agent.buildkite.com", 443},
				// Tunnels / VPN — direct escape from network
				{"ngrok", "escape", "tunnel.ngrok.com", 443},
				{"CFTunl", "escape", "trycloudflare.com", 443},
				{"Tailsc", "escape", "controlplane.tailscale.com", 443},
				{"ZeroTr", "escape", "my.zerotier.com", 443},
				{"Bore", "escape", "bore.pub", 443},
				{"lclrun", "escape", "localhost.run", 22},
				{"Serveo", "escape", "serveo.net", 22},
				{"Pagekt", "escape", "pagekite.net", 443},
				// CDN — domain fronting pivot
				{"CFlare", "escape", "www.cloudflare.com", 443},
				{"CFront", "escape", "cloudfront.net", 443},
				{"Fastly", "escape", "www.fastly.com", 443},
				{"Akamai", "escape", "www.akamai.com", 443},
				{"AzCDN", "escape", "www.azureedge.net", 443},
				{"GoogCDN", "escape", "www.gstatic.com", 443},
				// Serverless / hosting — C2 backend hosting
				{"Heroku", "c2", "herokuapp.com", 443},
				{"Vercel", "c2", "vercel.app", 443},
				{"Netlfy", "c2", "netlify.app", 443},
				{"Railwy", "c2", "railway.app", 443},
				{"Render", "c2", "onrender.com", 443},
				{"Fly.io", "c2", "fly.dev", 443},
				{"Deno", "c2", "deno.dev", 443},
				{"Supabs", "c2", "supabase.co", 443},
				{"Replit", "c2", "repl.co", 443},
				{"Glitch", "c2", "glitch.me", 443},
				{"Workers", "c2", "workers.dev", 443},
				// API / cloud — C2 via API calls
				{"OpenAI", "c2", "api.openai.com", 443},
				{"AWS", "c2", "sts.amazonaws.com", 443},
			}
			// Pre-populate all services as untested so the UI grid renders immediately.
			results := make([]ServiceProbeResult, len(serviceTargets))
			for i, svc := range serviceTargets {
				results[i] = ServiceProbeResult{
					Name:     svc.name,
					Category: svc.category,
					Host:     svc.host,
					Port:     svc.port,
				}
			}
			summary.ServiceResults = results
			emitSummary(summary)

			// Test service reachability with TLS verification.
			// CDNs have global anycast so bare TCP always succeeds — a TLS
			// handshake that validates the expected hostname proves the
			// connection isn't being intercepted or blocked by a proxy/firewall
			// returning a block page. For non-443 ports, fall back to TCP.
			var reachable, blocked []string
			for i, svc := range serviceTargets {
				if err := ctx.Err(); err != nil {
					break
				}
				ok := false
				if svc.port == 443 {
					ok = testServiceTLS(ctx, svc.host, 900*time.Millisecond)
				} else {
					dialer := net.Dialer{Timeout: 900 * time.Millisecond}
					conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(svc.host, strconv.Itoa(svc.port)))
					if err == nil {
						_ = conn.Close()
						ok = true
					}
				}
				if ok {
					reachable = append(reachable, svc.name)
				} else {
					blocked = append(blocked, svc.name)
				}
				results[i].Reachable = ok
				results[i].Tested = true
				summary.ServiceReachable = reachable
				summary.ServiceBlocked = blocked
				summary.ServiceResults = results
				emitSummary(summary)
			}
			summary.ServiceReachable = reachable
			summary.ServiceBlocked = blocked
			summary.ServiceResults = results
			if len(reachable) > 0 {
				emit(fmt.Sprintf("[+] %d services reachable: %s", len(reachable), strings.Join(reachable, ", ")))
			}
			if len(blocked) > 0 {
				emit(fmt.Sprintf("[-] %d services blocked: %s", len(blocked), strings.Join(blocked, ", ")))
			}
			emitSummary(summary)
		}
	}
	if err := ctx.Err(); err != nil {
		return summary, nil
	}

	emit("[*] Discovering network routes and interfaces...")
	internalRoutes, internetSubnets := discoverRouteHints(ctx)
	summary.InternalRoutes = internalRoutes
	summary.InternetSubnets = internetSubnets
	emit(fmt.Sprintf("[+] Routes: %d discovered", len(internalRoutes)+len(internetSubnets)))
	emitSummary(summary)

	emit("[*] Scanning environment for proxy endpoints...")
	proxies := mergeProbeEndpoints(
		mergeProbeEndpoints(discoverEnvProxyEndpoints(), discoverSampleProxyEndpoints(samples)),
		discoverLocalhostProxyEndpoints(ctx),
	)
	emit("[*] Scanning config files for endpoints...")
	configEndpoints := mergeProbeEndpoints(discoverConfigEndpoints(samples), discoverEnvConfigEndpoints())
	emit(fmt.Sprintf("[+] Found %d proxy candidates  %d config endpoints", len(proxies), len(configEndpoints)))
	emitSummary(summary)

	emit("[*] Testing proxy reachability and pivot capability...")
	pivotTarget := DefaultProbePivotTarget
	if strings.TrimSpace(endpoint) != "" {
		pt := strings.TrimSpace(endpoint)
		if !strings.Contains(pt, ":") {
			pt += ":443"
		}
		pivotTarget = pt
	}
	summary.Proxies, summary.ReachableProxyCount, summary.PivotProxyCount = testProxyEndpointReachabilityWithTarget(ctx, proxies, 1200*time.Millisecond, pivotTarget)
	if summary.PivotProxyCount > 0 {
		summary.ProxyPivotTarget = pivotTarget
	}
	emit(fmt.Sprintf("[+] Proxies: %d reachable  %d can pivot to %s", summary.ReachableProxyCount, summary.PivotProxyCount, pivotTarget))
	emit("[*] Testing config endpoint reachability...")
	summary.ConfigEndpoints, summary.ReachableConfigCount, _ = testEndpointReachability(ctx, configEndpoints, 700*time.Millisecond)
	emit(fmt.Sprintf("[+] Found endpoints: %d reachable of %d", summary.ReachableConfigCount, len(configEndpoints)))
	emitSummary(summary)

	// ── Deep Phase 3: Service reachability + config endpoint pivot ──
	// Test if discovered config endpoints can also pivot to the target,
	// and verify reachability of known cloud/SaaS services for exfil.
	if mode == ProbeModeChecks {
		if err := ctx.Err(); err == nil {
			emit("[*] Testing config endpoints for pivot capability...")
			lastNotify := time.Now()
			for i, ep := range summary.ConfigEndpoints {
				if !ep.Reachable || ep.PivotReachable {
					continue
				}
				if err := ctx.Err(); err != nil {
					break
				}
				schemes := proxySchemeCandidates(ep.Endpoint, ep.Port)
				if len(schemes) == 0 {
					continue
				}
				for _, scheme := range schemes {
					candidate := scheme + "://" + net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port))
					if testProxyPivot(ctx, candidate, pivotTarget, 2*time.Second) {
						summary.ConfigEndpoints[i].PivotReachable = true
						summary.ConfigEndpoints[i].PivotScheme = scheme
						summary.ConfigEndpoints[i].PivotTarget = pivotTarget
						summary.PivotProxyCount++
						break
					}
				}
				if time.Since(lastNotify) >= 2*time.Second {
					lastNotify = time.Now()
					emitSummary(summary)
				}
			}
			// Count config endpoints that can pivot.
			pivotCount := 0
			for _, ep := range summary.ConfigEndpoints {
				if ep.PivotReachable {
					pivotCount++
				}
			}
			emit(fmt.Sprintf("[+] Endpoint pivot: %d of %d reachable endpoints can pivot", pivotCount, summary.ReachableConfigCount))
		}

		emitSummary(summary)
	}

	// ── TLS Certificate Inspection ──
	if mode == ProbeModeChecks {
		if err := ctx.Err(); err == nil {
			emit("[*] Inspecting TLS certificates...")
			tlsTarget := host
			if strings.TrimSpace(endpoint) != "" {
				if h, _, ok := parseProbeTarget(endpoint); ok {
					tlsTarget = h
				}
			}
			tlsResult := probeTLSInterception(ctx, tlsTarget, 443, 2*time.Second)
			if tlsResult.Intercepted {
				summary.TLSIntercepted = true
				summary.TLSInterceptOrg = tlsResult.IssuerOrg
				summary.TLSInterceptIssuer = tlsResult.IssuerCN
				summary.TLSInterceptExpectedOrg = tlsResult.ExpectedOrg
				emit(fmt.Sprintf("[!] TLS interception detected: cert signed by %q (CN=%s), expected %s",
					tlsResult.IssuerOrg, tlsResult.IssuerCN, tlsResult.ExpectedOrg))
			} else {
				emit("[+] No TLS interception detected")
			}
			summary.TLSChecked = true
			emitSummary(summary)
		}
	}

	// ── Domain Fronting Detection ──
	// Real domain fronting: connect to a CDN's IP, set SNI to a high-reputation
	// domain (e.g. www.google.com), and verify the CDN accepts the TLS handshake.
	// If the CDN responds with a valid cert for the SNI domain (or any cert at all),
	// an attacker can route C2 traffic through that CDN by setting the HTTP Host
	// header to their real backend while the SNI shows the fronted domain.
	// We test against actual CDN endpoints, not the user's target.
	if mode == ProbeModeChecks {
		if err := ctx.Err(); err == nil {
			emit("[*] Testing domain fronting (SNI mismatch against CDNs)...")
			type frontTest struct {
				cdn     string // CDN endpoint to connect to
				sni     string // high-reputation SNI to front with
				display string // display label
			}
			frontTests := []frontTest{
				{"cloudfront.net", "www.amazon.com", "CloudFront"},
				{"cloudflare.com", "www.google.com", "Cloudflare"},
				{"fastly.com", "www.reddit.com", "Fastly"},
				{"azureedge.net", "www.microsoft.com", "Azure CDN"},
				{"cdn.googleapis.com", "www.google.com", "Google CDN"},
				{"edgecastcdn.net", "www.verizon.com", "Edgecast"},
			}
			for _, ft := range frontTests {
				if err := ctx.Err(); err != nil {
					break
				}
				// Resolve CDN first to get an anycast IP.
				ips, err := net.DefaultResolver.LookupHost(ctx, ft.cdn)
				if err != nil || len(ips) == 0 {
					continue
				}
				// Connect to CDN IP, present SNI of a completely different domain.
				dialer := net.Dialer{Timeout: 2 * time.Second}
				conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ips[0], "443"))
				if err != nil {
					continue
				}
				tlsConn := tls.Client(conn, &tls.Config{
					ServerName:         ft.sni,
					InsecureSkipVerify: true,
				})
				_ = tlsConn.SetDeadline(time.Now().Add(2 * time.Second))
				if err := tlsConn.Handshake(); err == nil {
					// Verify: the CDN accepted TLS with a mismatched SNI.
					// Check if the cert is NOT for the SNI domain (proving the CDN
					// didn't validate) or IS for the SNI (proving it served content).
					state := tlsConn.ConnectionState()
					certOrg := ""
					if len(state.PeerCertificates) > 0 {
						leaf := state.PeerCertificates[0]
						if len(leaf.Issuer.Organization) > 0 {
							certOrg = leaf.Issuer.Organization[0]
						}
					}
					summary.DomainFrontingViableCDNs = append(summary.DomainFrontingViableCDNs, ft.display)
					if !summary.DomainFrontingPossible {
						// Record first viable CDN as the primary.
						summary.DomainFrontingPossible = true
						summary.DomainFrontingSNI = ft.sni
						summary.DomainFrontingCDN = ft.display
						summary.DomainFrontingCDNIP = ips[0]
						summary.DomainFrontingCertIssuer = certOrg
					}
					emit(fmt.Sprintf("[+] Domain fronting viable: %s CDN (%s) accepted SNI %s", ft.display, ips[0], ft.sni))
					_ = tlsConn.Close()
				}
				_ = conn.Close()
			}
			if !summary.DomainFrontingPossible {
				emit("[-] Domain fronting not viable — CDNs rejected mismatched SNI")
			}
			emitSummary(summary)
		}
	}

	// ── HTTP Method Probing on reachable proxies ──
	if mode == ProbeModeChecks {
		if err := ctx.Err(); err == nil {
			allMethods := []string{"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "CONNECT"}
			if summary.ReachableProxyCount > 0 {
				emit("[*] Testing HTTP methods on reachable proxies...")
				methodSet := make(map[string]struct{})
				tested := 0
				for _, ep := range summary.Proxies {
					if !ep.Reachable || tested >= 3 {
						break
					}
					if err := ctx.Err(); err != nil {
						break
					}
					tested++
					addr := net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port))
					for _, method := range allMethods {
						if probeHTTPMethod(ctx, addr, method, 1500*time.Millisecond) {
							methodSet[method] = struct{}{}
						}
					}
				}
				if len(methodSet) > 0 {
					allowed := make([]string, 0, len(methodSet))
					for _, m := range allMethods {
						if _, ok := methodSet[m]; ok {
							allowed = append(allowed, m)
						}
					}
					summary.HTTPMethodsAllowed = allowed
					emit(fmt.Sprintf("[+] HTTP methods allowed: %s", strings.Join(allowed, ", ")))
				} else {
					emit("[-] No HTTP methods accepted by tested proxies")
				}
			} else {
				emit("[-] No HTTP methods accepted: no reachable proxies")
			}
			summary.HTTPMethodsChecked = true
			emitSummary(summary)
		}
	}

	emit("[*] Building report...")
	emit("[+] Report complete")
	findings = append(findings, buildProbeFindings(summary)...)
	return summary, NormalizeFindings(findings)
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
	onResult ...func(probeMatrixStats),
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
			if methodUsesSocksCarrierTunnel(proto.Name) {
				if includesTunnel {
					jobs = append(jobs, probeJob{kind: "tunnel", proto: proto, port: port})
				}
			} else if includesExfil {
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
			m.tunnelA++
			p.tunnelA++
			stats.tunnelAttempts++
			if success {
				m.tunnelS++
				p.tunnelS++
				stats.tunnelSuccess++
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
		hasCallback := len(onResult) > 0 && onResult[0] != nil
		lastNotify := time.Now()
		for result := range resultsCh {
			appendCheck(result.job.kind, result.job.proto, result.job.port, result.success)
			attemptsByPort[result.job.port]++
			if result.success {
				successByPort[result.job.port]++
			}
			if hasCallback && time.Since(lastNotify) >= 2*time.Second {
				lastNotify = time.Now()
				snap := stats
				snap.methodResults = flattenMethodCounters(methodCounters)
				snap.portResults = flattenPortCounters(portCounters)
				onResult[0](snap)
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

type probePacket struct {
	Kind   string
	Method string
	Port   int
	Exfil  bool
	Nonce  uint64
	Body   []byte
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

// testServiceTLS verifies a service is genuinely reachable by completing a TLS
// handshake that validates the server certificate against the expected hostname.
// This catches proxy/firewall block pages that accept TCP but serve a different
// certificate, and avoids false positives from CDN anycast IPs that always
// accept TCP connections even when the upstream service is blocked.
func testServiceTLS(ctx context.Context, host string, timeout time.Duration) bool {
	deadline, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config: &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
		},
	}
	conn, err := dialer.DialContext(deadline, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
