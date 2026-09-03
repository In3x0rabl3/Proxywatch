package pcap

import (
	"fmt"

	"proxywatch/internal/shared"
)

// StampBeaconAnalysisSignals applies beacon analysis results as signals to candidates.
func StampBeaconAnalysisSignals(candidates []shared.Candidate, analysisByPID map[int]*BeaconAnalysis) {
	if len(analysisByPID) == 0 {
		return
	}

	for i := range candidates {
		c := &candidates[i]
		if c.Proc == nil || !IsSyntheticPID(c.Proc.Pid) {
			continue
		}

		analysis, ok := analysisByPID[c.Proc.Pid]
		if !ok || analysis == nil {
			continue
		}

		// High total beacon score
		if analysis.TotalScore >= 0.7 {
			c.Signals = shared.AppendUniqueSignal(c.Signals, "beacon-rita-score-high")
			c.Reasons = shared.AppendUniqueSignal(c.Reasons,
				fmt.Sprintf("RITA beacon score %.2f (TS=%.2f, DS=%.2f) across %d connections",
					analysis.TotalScore, analysis.TSScore, analysis.DSScore, analysis.ConnectionCount))
		}

		// Strobe pattern (rapid regular connections)
		if analysis.IsStrobe {
			c.Signals = shared.AppendUniqueSignal(c.Signals, "beacon-strobe-pattern")
			c.Reasons = shared.AppendUniqueSignal(c.Reasons,
				fmt.Sprintf("Strobe pattern: %.1f connections/minute with low variance",
					analysis.StrobeDensity))
		}

		// Long connection (interactive session indicator)
		if analysis.IsLongConnection {
			c.Signals = shared.AppendUniqueSignal(c.Signals, "session-long-connection")
			c.Reasons = shared.AppendUniqueSignal(c.Reasons,
				fmt.Sprintf("Long-lived connection: %.0f seconds", analysis.LongConnDuration))
		}

		// Jitter detection (C2 with intentional randomization)
		if analysis.HasJitter && analysis.TSScore >= 0.5 {
			c.Signals = shared.AppendUniqueSignal(c.Signals, "beacon-jitter-detected")
			c.Reasons = shared.AppendUniqueSignal(c.Reasons,
				fmt.Sprintf("Beacon jitter detected: CV=%.2f (5-35%% variation)",
					analysis.JitterCoefficient))
		}

		// Single destination concentration
		if analysis.DestConcentration >= 0.9 && analysis.ConnectionCount >= 10 {
			c.Signals = shared.AppendUniqueSignal(c.Signals, "beacon-single-target")
			c.Reasons = shared.AppendUniqueSignal(c.Reasons,
				fmt.Sprintf("%.0f%% of %d connections to single destination %s:%d",
					analysis.DestConcentration*100, analysis.ConnectionCount,
					analysis.PrimaryDestIP, analysis.PrimaryDestPort))
		}

		// DNS tunnel indicators
		if analysis.IsDNSTunnel {
			c.Signals = shared.AppendUniqueSignal(c.Signals, "dns-tunnel-detected")
			c.Reasons = shared.AppendUniqueSignal(c.Reasons,
				fmt.Sprintf("DNS tunnel indicators: entropy=%.2f, rate=%.1f queries/min, regularity=%.2f",
					analysis.DNSQueryEntropy, analysis.DNSQueryPerMinute, analysis.TSScore))
		}

		// High DNS query entropy alone
		if analysis.DNSQueryEntropy >= 4.0 && analysis.DNSQueryPerMinute >= 2.0 {
			c.Signals = shared.AppendUniqueSignal(c.Signals, "dns-high-entropy-subdomain")
			c.Reasons = shared.AppendUniqueSignal(c.Reasons,
				fmt.Sprintf("High entropy DNS subdomains: %.2f bits/char at %.1f queries/min",
					analysis.DNSQueryEntropy, analysis.DNSQueryPerMinute))
		}

		// Low interval variance (perfect beacon)
		if analysis.IntervalMADScore >= 0.9 && analysis.ConnectionCount >= 20 {
			c.Signals = shared.AppendUniqueSignal(c.Signals, "beacon-perfect-interval")
			c.Reasons = shared.AppendUniqueSignal(c.Reasons,
				fmt.Sprintf("Nearly perfect interval uniformity (MAD score %.2f) across %d connections",
					analysis.IntervalMADScore, analysis.ConnectionCount))
		}

		// Uniform payload sizes
		if analysis.SizeMADScore >= 0.9 && analysis.ConnectionCount >= 20 {
			c.Signals = shared.AppendUniqueSignal(c.Signals, "beacon-uniform-payload")
			c.Reasons = shared.AppendUniqueSignal(c.Reasons,
				fmt.Sprintf("Uniform payload sizes (MAD score %.2f) across %d connections",
					analysis.SizeMADScore, analysis.ConnectionCount))
		}
	}
}

// StampPivotAnalysisSignals applies pivot analysis results as signals to candidates.
func StampPivotAnalysisSignals(candidates []shared.Candidate, analysisByPID map[int]*PivotAnalysis) {
	if len(analysisByPID) == 0 {
		return
	}

	for i := range candidates {
		c := &candidates[i]
		if c.Proc == nil || !IsSyntheticPID(c.Proc.Pid) {
			continue
		}

		analysis, ok := analysisByPID[c.Proc.Pid]
		if !ok || analysis == nil {
			continue
		}

		// High pivot score
		if analysis.PivotScore >= 0.6 {
			c.Signals = shared.AppendUniqueSignal(c.Signals, "pivot-behavior-detected")
			c.Reasons = shared.AppendUniqueSignal(c.Reasons,
				fmt.Sprintf("Pivot/relay behavior: score %.2f with %d inbound/%d outbound connections",
					analysis.PivotScore, analysis.InboundConnections, analysis.OutboundConnections))
		}

		// Throughput symmetry (relay indicator)
		if analysis.HasSymmetry {
			c.Signals = shared.AppendUniqueSignal(c.Signals, "pivot-throughput-symmetry")
			c.Reasons = shared.AppendUniqueSignal(c.Reasons,
				fmt.Sprintf("Throughput symmetry: ratio %.2f (in=%d KB, out=%d KB)",
					analysis.ThroughputRatio, analysis.TotalBytesIn/1024, analysis.TotalBytesOut/1024))
		}

		// Multiplexing (SOCKS/tunnel indicator)
		if analysis.HasMultiplexing {
			c.Signals = shared.AppendUniqueSignal(c.Signals, "pivot-multiplexing")
			c.Reasons = shared.AppendUniqueSignal(c.Reasons,
				fmt.Sprintf("Multiplexing: %d internal sources through %d external destinations (ratio %.1f)",
					analysis.UniqueInboundSrcs, analysis.UniqueOutboundDsts, analysis.MultiplexRatio))
		}

		// Timing correlation (relay indicator)
		if analysis.HasTimingCorrelation {
			c.Signals = shared.AppendUniqueSignal(c.Signals, "pivot-timing-correlation")
			c.Reasons = shared.AppendUniqueSignal(c.Reasons,
				fmt.Sprintf("Timing correlation: consistent %.2fs lag between inbound and outbound",
					analysis.CorrelationLag))
		}

		// Port forwarding
		if analysis.HasPortForwarding {
			c.Signals = shared.AppendUniqueSignal(c.Signals, "pivot-port-forwarding")
			c.Reasons = shared.AppendUniqueSignal(c.Reasons,
				fmt.Sprintf("Port forwarding: listening on %v, forwarding to ports %v",
					analysis.ListenerPorts, analysis.ForwardedDestPorts))
		}
	}
}

// StampTunnelAnalysisSignals applies tunnel analysis results as signals to candidates.
func StampTunnelAnalysisSignals(candidates []shared.Candidate, analysisByPID map[int]*TunnelAnalysis) {
	if len(analysisByPID) == 0 {
		return
	}

	for i := range candidates {
		c := &candidates[i]
		if c.Proc == nil || !IsSyntheticPID(c.Proc.Pid) {
			continue
		}

		analysis, ok := analysisByPID[c.Proc.Pid]
		if !ok || analysis == nil {
			continue
		}

		// High tunnel score
		if analysis.TunnelScore >= 0.5 {
			c.Signals = shared.AppendUniqueSignal(c.Signals, "tunnel-detected")
			c.Reasons = shared.AppendUniqueSignal(c.Reasons,
				fmt.Sprintf("Tunnel detected: type=%s, score=%.2f",
					analysis.TunnelType, analysis.TunnelScore))
		}

		// Persistent connection
		if analysis.IsPersistent {
			c.Signals = shared.AppendUniqueSignal(c.Signals, "tunnel-persistent-conn")
			c.Reasons = shared.AppendUniqueSignal(c.Reasons,
				fmt.Sprintf("Persistent connection: %.0f seconds", analysis.PersistDuration))
		}

		// Keep-alive pattern
		if analysis.HasKeepAlive {
			c.Signals = shared.AppendUniqueSignal(c.Signals, "tunnel-keepalive-pattern")
			c.Reasons = shared.AppendUniqueSignal(c.Reasons,
				fmt.Sprintf("Keep-alive pattern: %d intervals at ~%.1fs each",
					analysis.KeepAliveCount, analysis.KeepAliveIntv))
		}

		// HTTP CONNECT tunnel
		if analysis.HTTPConnectSeen {
			c.Signals = shared.AppendUniqueSignal(c.Signals, "tunnel-http-connect")
			c.Reasons = shared.AppendUniqueSignal(c.Reasons, "HTTP CONNECT method observed")
		}

		// WebSocket upgrade
		if analysis.HTTPWebSocketSeen {
			c.Signals = shared.AppendUniqueSignal(c.Signals, "tunnel-websocket")
			c.Reasons = shared.AppendUniqueSignal(c.Reasons, "WebSocket upgrade observed")
		}

		// SSH tunnel
		if analysis.IsSSHTunnel {
			c.Signals = shared.AppendUniqueSignal(c.Signals, "tunnel-ssh")
			c.Reasons = shared.AppendUniqueSignal(c.Reasons, "Long-lived SSH connection (likely tunnel)")
		}

		// DNS tunnel
		if analysis.IsDNSTunnel {
			c.Signals = shared.AppendUniqueSignal(c.Signals, "tunnel-dns")
			c.Reasons = shared.AppendUniqueSignal(c.Reasons, "DNS tunneling indicators present")
		}
	}
}

// RunEnhancedAnalysis performs all enhanced analyses on pcap/zeek data
// and stamps the resulting signals on candidates.
func RunEnhancedAnalysis(
	candidates []shared.Candidate,
	flowsByPID map[int][]FlowSummary,
	httpData []ZeekHTTP,
	sslData []ZeekSSL,
	dnsData []ZeekDNS,
	localIPs []string,
) {
	localIPSet := make(map[string]bool, len(localIPs))
	for _, ip := range localIPs {
		localIPSet[ip] = true
	}

	// Run beacon analysis for each endpoint
	beaconAnalysisByPID := make(map[int]*BeaconAnalysis)
	for pid, flows := range flowsByPID {
		if analysis := AnalyzeBeaconBehavior(flows); analysis != nil {
			beaconAnalysisByPID[pid] = analysis
		}
	}
	StampBeaconAnalysisSignals(candidates, beaconAnalysisByPID)

	// Run pivot analysis for each endpoint
	pivotAnalysisByPID := make(map[int]*PivotAnalysis)
	for pid, flows := range flowsByPID {
		if analysis := AnalyzePivotBehavior(flows, localIPSet); analysis != nil {
			pivotAnalysisByPID[pid] = analysis
		}
	}
	StampPivotAnalysisSignals(candidates, pivotAnalysisByPID)

	// Run tunnel analysis for each endpoint
	tunnelAnalysisByPID := make(map[int]*TunnelAnalysis)
	for pid, flows := range flowsByPID {
		if analysis := AnalyzeTunnelBehavior(flows, httpData, sslData); analysis != nil {
			tunnelAnalysisByPID[pid] = analysis
		}
	}
	StampTunnelAnalysisSignals(candidates, tunnelAnalysisByPID)

	// DNS beacon analysis (aggregate across all DNS data)
	if len(dnsData) > 0 {
		// Group DNS by originator IP
		dnsByOrigIP := make(map[string][]ZeekDNS)
		for _, d := range dnsData {
			dnsByOrigIP[d.OrigH] = append(dnsByOrigIP[d.OrigH], d)
		}

		// Analyze each source's DNS patterns
		for origIP, records := range dnsByOrigIP {
			// Find the candidate for this originator
			for i := range candidates {
				c := &candidates[i]
				if c.Proc == nil {
					continue
				}
				// Match by checking if any flow belongs to this IP
				flows, ok := flowsByPID[c.Proc.Pid]
				if !ok {
					continue
				}
				isMatch := false
				for _, f := range flows {
					if f.LocalIP == origIP {
						isMatch = true
						break
					}
				}
				if !isMatch {
					continue
				}

				// Analyze DNS beaconing
				if analysis := AnalyzeDNSBeacon(records, ""); analysis != nil {
					if analysis.IsDNSTunnel {
						c.Signals = shared.AppendUniqueSignal(c.Signals, "dns-tunnel-detected")
						c.Reasons = shared.AppendUniqueSignal(c.Reasons,
							fmt.Sprintf("DNS tunnel: entropy=%.2f, rate=%.1f/min, regularity=%.2f",
								analysis.DNSQueryEntropy, analysis.DNSQueryPerMinute, analysis.TSScore))
					}
					if analysis.DNSQueryEntropy >= 4.0 {
						c.Signals = shared.AppendUniqueSignal(c.Signals, "dns-high-entropy-subdomain")
						c.Reasons = shared.AppendUniqueSignal(c.Reasons,
							fmt.Sprintf("High entropy DNS: %.2f bits/char", analysis.DNSQueryEntropy))
					}
				}
			}
		}
	}
}

// CalculateEnhancedBeaconScores computes RITA-style beacon scores for all endpoints.
func CalculateEnhancedBeaconScores(flowsByPID map[int][]FlowSummary) map[int]BeaconShape {
	result := make(map[int]BeaconShape, len(flowsByPID))

	for pid, flows := range flowsByPID {
		analysis := AnalyzeBeaconBehavior(flows)
		if analysis == nil {
			continue
		}

		result[pid] = BeaconShape{
			TSScore:     analysis.TSScore,
			DSScore:     analysis.DSScore,
			SampleCount: analysis.ConnectionCount,
		}
	}

	return result
}
