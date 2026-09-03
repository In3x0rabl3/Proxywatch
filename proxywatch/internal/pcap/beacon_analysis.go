package pcap

import (
	"math"
	"sort"

	"proxywatch/internal/shared"
)

// BeaconAnalysis holds the results of beacon detection analysis.
type BeaconAnalysis struct {
	// Connection timing analysis
	ConnectionCount    int
	IntervalMean       float64
	IntervalStdDev     float64
	IntervalSkew       float64
	IntervalDispersion float64 // bowley skew
	IntervalMADScore   float64

	// Size analysis
	SizeMean       float64
	SizeStdDev     float64
	SizeSkew       float64
	SizeDispersion float64
	SizeMADScore   float64

	// Combined scores (RITA-style)
	TSScore    float64 // Timestamp score [0,1] - higher is more beacon-like
	DSScore    float64 // Data size score [0,1] - higher is more uniform
	TotalScore float64 // Combined beacon probability

	// Pattern detection
	IsStrobe          bool    // Very rapid, regular connections
	StrobeDensity     float64 // Connections per minute when strobing
	IsLongConnection  bool    // Single long-lived connection
	LongConnDuration  float64 // Duration in seconds
	HasJitter         bool    // Intentional randomization detected
	JitterCoefficient float64 // CV of intervals
	IsDNSTunnel       bool    // DNS tunneling indicators
	DNSQueryEntropy   float64 // Entropy of DNS query strings
	DNSQueryPerMinute float64 // DNS query rate

	// Destination analysis
	UniqueDestinations int
	UniqueDestPorts    int
	PrimaryDestIP      string
	PrimaryDestPort    int
	DestConcentration  float64 // % of traffic to primary dest
}

// AnalyzeBeaconBehavior performs comprehensive beacon analysis on a set of flows.
func AnalyzeBeaconBehavior(flows []FlowSummary) *BeaconAnalysis {
	if len(flows) < 3 {
		return nil
	}

	analysis := &BeaconAnalysis{
		ConnectionCount: len(flows),
	}

	// Sort flows by time
	sorted := make([]FlowSummary, len(flows))
	copy(sorted, flows)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].FirstPacket.Before(sorted[j].FirstPacket)
	})

	// Calculate intervals between connections
	intervals := make([]float64, 0, len(sorted)-1)
	for i := 1; i < len(sorted); i++ {
		d := sorted[i].FirstPacket.Sub(sorted[i-1].FirstPacket).Seconds()
		if d > 0 {
			intervals = append(intervals, d)
		}
	}

	if len(intervals) >= 2 {
		analysis.IntervalMean, analysis.IntervalStdDev = meanStdDev(intervals)
		analysis.IntervalSkew = skewness(intervals)
		analysis.IntervalDispersion = bowleySkew(intervals)
		analysis.IntervalMADScore = madScore(intervals)
		analysis.TSScore = shared.StatisticalScore(intervals, 1.0)

		// Jitter detection
		if analysis.IntervalMean > 0 {
			analysis.JitterCoefficient = analysis.IntervalStdDev / analysis.IntervalMean
			analysis.HasJitter = analysis.JitterCoefficient > 0.05 && analysis.JitterCoefficient < 0.35
		}
	}

	// Calculate payload sizes
	sizes := make([]float64, 0, len(sorted))
	for _, f := range sorted {
		totalBytes := float64(f.BytesInitToResp + f.BytesRespToInit)
		sizes = append(sizes, totalBytes)
	}

	if len(sizes) >= 2 {
		analysis.SizeMean, analysis.SizeStdDev = meanStdDev(sizes)
		analysis.SizeSkew = skewness(sizes)
		analysis.SizeDispersion = bowleySkew(sizes)
		analysis.SizeMADScore = madScore(sizes)
		analysis.DSScore = shared.StatisticalScore(sizes, 0.0)
	}

	// Combined score (RITA-style weighted average)
	if analysis.TSScore > 0 || analysis.DSScore > 0 {
		// Weight timing more heavily than size (70/30 split)
		analysis.TotalScore = (0.7 * analysis.TSScore) + (0.3 * analysis.DSScore)
	}

	// Strobe detection: very rapid connections with low interval variance
	if analysis.IntervalMean > 0 && analysis.IntervalMean < 10 && // < 10 sec average
		analysis.JitterCoefficient < 0.1 && // very consistent
		len(intervals) >= 10 {
		analysis.IsStrobe = true
		analysis.StrobeDensity = 60.0 / analysis.IntervalMean
	}

	// Long connection detection
	for _, f := range sorted {
		duration := f.LastPacket.Sub(f.FirstPacket).Seconds()
		if duration > analysis.LongConnDuration {
			analysis.LongConnDuration = duration
		}
	}
	analysis.IsLongConnection = analysis.LongConnDuration > 300 // > 5 minutes

	// Destination analysis
	destCounts := make(map[string]int)
	portCounts := make(map[int]int)
	for _, f := range sorted {
		destCounts[f.RemoteIP]++
		portCounts[f.RemotePort]++
	}

	analysis.UniqueDestinations = len(destCounts)
	analysis.UniqueDestPorts = len(portCounts)

	// Find primary destination
	maxCount := 0
	for ip, count := range destCounts {
		if count > maxCount {
			maxCount = count
			analysis.PrimaryDestIP = ip
		}
	}

	maxPortCount := 0
	for port, count := range portCounts {
		if count > maxPortCount {
			maxPortCount = count
			analysis.PrimaryDestPort = port
		}
	}

	if len(sorted) > 0 {
		analysis.DestConcentration = float64(maxCount) / float64(len(sorted))
	}

	return analysis
}

// AnalyzeDNSBeacon analyzes DNS records for tunneling/beaconing indicators.
func AnalyzeDNSBeacon(records []ZeekDNS, targetDomain string) *BeaconAnalysis {
	if len(records) < 3 {
		return nil
	}

	// Filter to target domain if specified
	var filtered []ZeekDNS
	for _, r := range records {
		if targetDomain == "" || r.Query == targetDomain || hasSuffix(r.Query, "."+targetDomain) {
			filtered = append(filtered, r)
		}
	}

	if len(filtered) < 3 {
		return nil
	}

	analysis := &BeaconAnalysis{
		ConnectionCount: len(filtered),
		IsDNSTunnel:     false,
	}

	// Sort by timestamp
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].TS.Before(filtered[j].TS)
	})

	// Calculate query intervals
	intervals := make([]float64, 0, len(filtered)-1)
	for i := 1; i < len(filtered); i++ {
		d := filtered[i].TS.Sub(filtered[i-1].TS).Seconds()
		if d > 0 {
			intervals = append(intervals, d)
		}
	}

	if len(intervals) >= 2 {
		analysis.IntervalMean, analysis.IntervalStdDev = meanStdDev(intervals)
		analysis.TSScore = shared.StatisticalScore(intervals, 1.0)

		// Jitter analysis
		if analysis.IntervalMean > 0 {
			analysis.JitterCoefficient = analysis.IntervalStdDev / analysis.IntervalMean
			analysis.HasJitter = analysis.JitterCoefficient > 0.05 && analysis.JitterCoefficient < 0.35
		}
	}

	// Calculate query rate
	if len(filtered) >= 2 {
		duration := filtered[len(filtered)-1].TS.Sub(filtered[0].TS).Minutes()
		if duration > 0 {
			analysis.DNSQueryPerMinute = float64(len(filtered)) / duration
		}
	}

	// Calculate subdomain entropy (DNS tunneling indicator)
	var totalEntropy float64
	entropyCount := 0
	for _, r := range filtered {
		// Get subdomain portion
		subdomain := getSubdomain(r.Query, targetDomain)
		if subdomain != "" {
			entropy := stringEntropy(subdomain)
			totalEntropy += entropy
			entropyCount++
		}
	}

	if entropyCount > 0 {
		analysis.DNSQueryEntropy = totalEntropy / float64(entropyCount)
	}

	// High entropy subdomains + regular intervals = DNS tunnel
	analysis.IsDNSTunnel = analysis.DNSQueryEntropy > 3.5 &&
		analysis.TSScore > 0.5 &&
		analysis.DNSQueryPerMinute > 1.0

	return analysis
}

// PivotAnalysis holds results of pivot/relay detection.
type PivotAnalysis struct {
	// Traffic pattern
	InboundConnections  int
	OutboundConnections int
	UniqueInboundSrcs   int
	UniqueOutboundDsts  int

	// Throughput symmetry
	TotalBytesIn      uint64
	TotalBytesOut     uint64
	ThroughputRatio   float64
	HasSymmetry       bool
	SymmetryThreshold float64

	// Timing correlation
	HasTimingCorrelation bool
	CorrelationLag       float64

	// Connection patterns
	HasMultiplexing    bool // Multiple internal through single external
	MultiplexRatio     float64
	HasPortForwarding  bool // Internal listeners with external connections
	ListenerPorts      []int
	ForwardedDestPorts []int

	// Confidence
	PivotScore float64 // Overall pivot probability [0,1]
}

// AnalyzePivotBehavior detects relay/pivot patterns in traffic.
func AnalyzePivotBehavior(flows []FlowSummary, localIPs map[string]bool) *PivotAnalysis {
	if len(flows) < 2 {
		return nil
	}

	analysis := &PivotAnalysis{
		SymmetryThreshold: 0.5,
	}

	// Categorize flows
	var inbound, outbound []FlowSummary
	inboundSrcs := make(map[string]bool)
	outboundDsts := make(map[string]bool)

	for _, f := range flows {
		localIsInit := localIPs[f.LocalIP]
		remoteIsLocal := localIPs[f.RemoteIP]

		if localIsInit && !remoteIsLocal {
			// Outbound: local initiated to external
			outbound = append(outbound, f)
			outboundDsts[f.RemoteIP] = true
			analysis.TotalBytesOut += f.BytesInitToResp
			analysis.TotalBytesIn += f.BytesRespToInit
		} else if !localIsInit || remoteIsLocal {
			// Inbound: external initiated to local, or local-to-local
			inbound = append(inbound, f)
			inboundSrcs[f.LocalIP] = true
			analysis.TotalBytesIn += f.BytesInitToResp
			analysis.TotalBytesOut += f.BytesRespToInit
		}
	}

	analysis.InboundConnections = len(inbound)
	analysis.OutboundConnections = len(outbound)
	analysis.UniqueInboundSrcs = len(inboundSrcs)
	analysis.UniqueOutboundDsts = len(outboundDsts)

	// Throughput symmetry analysis
	if analysis.TotalBytesIn > 0 && analysis.TotalBytesOut > 0 {
		analysis.ThroughputRatio = float64(analysis.TotalBytesIn) / float64(analysis.TotalBytesOut)
		// Symmetry: ratio between 0.5 and 2.0 (within factor of 2)
		analysis.HasSymmetry = analysis.ThroughputRatio >= analysis.SymmetryThreshold &&
			analysis.ThroughputRatio <= 1.0/analysis.SymmetryThreshold
	}

	// Multiplexing detection: many internal sources through few external dests
	if analysis.UniqueInboundSrcs > 2 && analysis.UniqueOutboundDsts > 0 {
		analysis.MultiplexRatio = float64(analysis.UniqueInboundSrcs) / float64(analysis.UniqueOutboundDsts)
		analysis.HasMultiplexing = analysis.MultiplexRatio >= 3.0
	}

	// Timing correlation analysis
	if len(inbound) >= 3 && len(outbound) >= 3 {
		analysis.HasTimingCorrelation, analysis.CorrelationLag = detectTimingCorrelation(inbound, outbound)
	}

	// Port forwarding detection
	listenerPorts := make(map[int]bool)
	forwardedPorts := make(map[int]bool)

	for _, f := range inbound {
		if f.RemotePort < 1024 || f.RemotePort == 8080 || f.RemotePort == 8443 {
			listenerPorts[f.RemotePort] = true
		}
	}

	for _, f := range outbound {
		if f.RemotePort < 1024 || f.RemotePort == 3389 || f.RemotePort == 22 || f.RemotePort == 445 {
			forwardedPorts[f.RemotePort] = true
		}
	}

	for port := range listenerPorts {
		analysis.ListenerPorts = append(analysis.ListenerPorts, port)
	}
	for port := range forwardedPorts {
		analysis.ForwardedDestPorts = append(analysis.ForwardedDestPorts, port)
	}

	analysis.HasPortForwarding = len(listenerPorts) > 0 && len(forwardedPorts) > 0

	// Calculate overall pivot score
	score := 0.0
	if analysis.HasSymmetry {
		score += 0.3
	}
	if analysis.HasMultiplexing {
		score += 0.3
	}
	if analysis.HasTimingCorrelation {
		score += 0.2
	}
	if analysis.HasPortForwarding {
		score += 0.2
	}
	analysis.PivotScore = score

	return analysis
}

// TunnelAnalysis holds results of tunnel detection.
type TunnelAnalysis struct {
	// Connection characteristics
	IsPersistent    bool
	PersistDuration float64
	HasKeepAlive    bool
	KeepAliveCount  int
	KeepAliveIntv   float64

	// Encapsulation indicators
	HasNestedProtocol bool
	InnerProtocol     string
	PayloadEntropy    float64

	// SSH tunnel indicators
	IsSSHTunnel     bool
	SSHBannerSeen   bool
	SSHChannelCount int

	// HTTP tunnel indicators
	IsHTTPTunnel      bool
	HTTPConnectSeen   bool
	HTTPWebSocketSeen bool

	// DNS tunnel indicators
	IsDNSTunnel    bool
	DNSEncodedData bool
	DNSTXTAbuse    bool

	// Overall confidence
	TunnelScore float64
	TunnelType  string
}

// AnalyzeTunnelBehavior detects tunneling patterns.
func AnalyzeTunnelBehavior(flows []FlowSummary, httpData []ZeekHTTP, sslData []ZeekSSL) *TunnelAnalysis {
	if len(flows) == 0 {
		return nil
	}

	analysis := &TunnelAnalysis{}

	// Sort by time
	sorted := make([]FlowSummary, len(flows))
	copy(sorted, flows)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].FirstPacket.Before(sorted[j].FirstPacket)
	})

	// Check for persistent connections
	for _, f := range sorted {
		duration := f.LastPacket.Sub(f.FirstPacket).Seconds()
		if duration > analysis.PersistDuration {
			analysis.PersistDuration = duration
		}
	}
	analysis.IsPersistent = analysis.PersistDuration > 300 // > 5 minutes

	// Detect keep-alive patterns
	if len(sorted) >= 5 {
		intervals := make([]float64, 0, len(sorted)-1)
		for i := 1; i < len(sorted); i++ {
			d := sorted[i].FirstPacket.Sub(sorted[i-1].FirstPacket).Seconds()
			if d > 0 && d < 300 { // Ignore gaps > 5 min
				intervals = append(intervals, d)
			}
		}

		if len(intervals) >= 3 {
			mean, stddev := meanStdDev(intervals)
			cv := 0.0
			if mean > 0 {
				cv = stddev / mean
			}
			// Low coefficient of variation = regular keep-alive
			if cv < 0.3 && mean > 0 {
				analysis.HasKeepAlive = true
				analysis.KeepAliveCount = len(intervals)
				analysis.KeepAliveIntv = mean
			}
		}
	}

	// HTTP tunnel detection
	for _, h := range httpData {
		if h.Method == "CONNECT" {
			analysis.HTTPConnectSeen = true
			analysis.IsHTTPTunnel = true
		}
		if hasPrefix(h.UserAgent, "websocket") ||
			h.StatusCode == 101 {
			analysis.HTTPWebSocketSeen = true
			analysis.IsHTTPTunnel = true
		}
	}

	// SSH tunnel indicators (port 22 with long connection)
	for _, f := range sorted {
		if f.RemotePort == 22 {
			duration := f.LastPacket.Sub(f.FirstPacket).Seconds()
			if duration > 60 {
				analysis.IsSSHTunnel = true
				analysis.SSHBannerSeen = true
			}
		}
	}

	// Calculate tunnel score
	score := 0.0
	if analysis.IsPersistent {
		score += 0.2
	}
	if analysis.HasKeepAlive {
		score += 0.2
	}
	if analysis.IsHTTPTunnel {
		score += 0.3
		analysis.TunnelType = "HTTP"
	}
	if analysis.IsSSHTunnel {
		score += 0.3
		analysis.TunnelType = "SSH"
	}
	if analysis.IsDNSTunnel {
		score += 0.3
		analysis.TunnelType = "DNS"
	}
	analysis.TunnelScore = score

	return analysis
}

// Helper functions

func meanStdDev(data []float64) (mean, stddev float64) {
	if len(data) == 0 {
		return 0, 0
	}

	sum := 0.0
	for _, v := range data {
		sum += v
	}
	mean = sum / float64(len(data))

	if len(data) < 2 {
		return mean, 0
	}

	sumSq := 0.0
	for _, v := range data {
		diff := v - mean
		sumSq += diff * diff
	}
	stddev = math.Sqrt(sumSq / float64(len(data)-1))

	return mean, stddev
}

func skewness(data []float64) float64 {
	if len(data) < 3 {
		return 0
	}

	mean, stddev := meanStdDev(data)
	if stddev == 0 {
		return 0
	}

	sum := 0.0
	for _, v := range data {
		sum += math.Pow((v-mean)/stddev, 3)
	}

	n := float64(len(data))
	return (n / ((n - 1) * (n - 2))) * sum
}

func bowleySkew(data []float64) float64 {
	if len(data) < 4 {
		return 0
	}

	sorted := make([]float64, len(data))
	copy(sorted, data)
	sort.Float64s(sorted)

	n := len(sorted)
	q1 := sorted[n/4]
	q2 := sorted[n/2]
	q3 := sorted[3*n/4]

	denom := q3 - q1
	if denom == 0 {
		return 0
	}

	return (q1 + q3 - 2*q2) / denom
}

func madScore(data []float64) float64 {
	if len(data) < 2 {
		return 0
	}

	// Calculate median
	sorted := make([]float64, len(data))
	copy(sorted, data)
	sort.Float64s(sorted)

	var median float64
	n := len(sorted)
	if n%2 == 0 {
		median = (sorted[n/2-1] + sorted[n/2]) / 2
	} else {
		median = sorted[n/2]
	}

	// Calculate MAD
	deviations := make([]float64, len(data))
	for i, v := range data {
		deviations[i] = math.Abs(v - median)
	}
	sort.Float64s(deviations)

	var mad float64
	if n%2 == 0 {
		mad = (deviations[n/2-1] + deviations[n/2]) / 2
	} else {
		mad = deviations[n/2]
	}

	// Normalize to [0,1] score
	if median == 0 {
		return 0
	}

	// Low MAD relative to median = high uniformity = high score
	relMAD := mad / median
	score := 1.0 / (1.0 + relMAD)
	return score
}

func detectTimingCorrelation(inbound, outbound []FlowSummary) (bool, float64) {
	if len(inbound) < 3 || len(outbound) < 3 {
		return false, 0
	}

	// Cross-correlate timestamps to detect relay patterns
	// Simplified: check if outbound follows inbound with consistent lag

	inTimes := make([]float64, len(inbound))
	for i, f := range inbound {
		inTimes[i] = float64(f.FirstPacket.UnixNano()) / 1e9
	}

	outTimes := make([]float64, len(outbound))
	for i, f := range outbound {
		outTimes[i] = float64(f.FirstPacket.UnixNano()) / 1e9
	}

	// Find average lag between paired in/out
	lags := make([]float64, 0)
	for _, it := range inTimes {
		// Find closest outbound after inbound
		minLag := math.MaxFloat64
		for _, ot := range outTimes {
			lag := ot - it
			if lag > 0 && lag < minLag && lag < 5.0 { // Within 5 seconds
				minLag = lag
			}
		}
		if minLag < math.MaxFloat64 {
			lags = append(lags, minLag)
		}
	}

	if len(lags) < 3 {
		return false, 0
	}

	// Check if lags are consistent
	mean, stddev := meanStdDev(lags)
	cv := 0.0
	if mean > 0 {
		cv = stddev / mean
	}

	// Low CV means consistent lag = relay correlation
	return cv < 0.5, mean
}

func stringEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}

	entropy := 0.0
	n := float64(len(s))
	for _, count := range freq {
		p := float64(count) / n
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

func getSubdomain(query, baseDomain string) string {
	if baseDomain == "" {
		// Return first label
		parts := splitDomain(query)
		if len(parts) > 1 {
			return parts[0]
		}
		return ""
	}

	if hasSuffix(query, "."+baseDomain) {
		return query[:len(query)-len(baseDomain)-1]
	}
	return ""
}

func splitDomain(domain string) []string {
	var parts []string
	current := ""
	for _, c := range domain {
		if c == '.' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

func hasSuffix(s, suffix string) bool {
	if len(s) < len(suffix) {
		return false
	}
	return s[len(s)-len(suffix):] == suffix
}

func hasPrefix(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return s[:len(prefix)] == prefix
}
