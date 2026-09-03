package features

import (
	"math"
	"strings"
	"time"

	"proxywatch/internal/detection/model"
	"proxywatch/internal/shared"
)

// Extract computes the 117-feature behavioral vector from a scored candidate.
// All data comes from the Candidate, ProcessBehavior, and ProcessProfile.
// No deep packet inspection — everything is metadata and behavior.
func Extract(c *shared.Candidate, behavior *shared.ProcessBehavior, profile *model.ProcessProfile) FeatureVector {
	var fv FeatureVector
	if c == nil {
		return fv
	}
	fv.Valid = true

	extractBeacon(c, behavior, profile, &fv)
	extractSession(c, behavior, profile, &fv)
	extractPivot(c, &fv)
	extractOutbound(c, behavior, &fv)
	extractListener(c, &fv)
	extractOnline(c, &fv)

	return fv
}

// extractOnline populates the Authenticode-derived features. Values stay 0
// when verdict is unavailable (platform without the verifier, cache miss
// with posture cache-only, or offline), so a model trained on a host with
// online verification enabled degrades predictably when the verifier is
// absent.
func extractOnline(c *shared.Candidate, fv *FeatureVector) {
	if c == nil || c.Proc == nil {
		return
	}
	if c.Proc.SignatureTrust == shared.SignatureTrustTrusted && c.Proc.AuthenticodeOCSPSeen {
		fv.Values[FOnlineKnownBenign] = 1
	}
	if c.Proc.SignatureTrust == shared.SignatureTrustUntrusted {
		fv.Values[FOnlineKnownMalicious] = 1
	}
}

// ── shared helpers ──────────────────────────────────────────────────────────

// boolFloat converts a bool to 0.0 or 1.0.
func boolFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// safeDiv returns a/b, or 0 when b is zero.
func safeDiv(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a / b
}

func countDistinctTargets(conns []shared.ConnectionInfo) int {
	set := make(map[string]struct{})
	for _, cn := range conns {
		if cn.RemoteAddress != "" && !shared.IsWildcardIP(cn.RemoteAddress) && !shared.IsLoopbackIP(cn.RemoteAddress) {
			set[cn.RemoteAddress] = struct{}{}
		}
	}
	return len(set)
}

func countDistinctOutboundPorts(conns []shared.ConnectionInfo) int {
	ports := make(map[int]struct{})
	for _, cn := range conns {
		if cn.RemotePort > 0 && cn.RemoteAddress != "" && !shared.IsLoopbackIP(cn.RemoteAddress) {
			ports[cn.RemotePort] = struct{}{}
		}
	}
	return len(ports)
}

func allListenersLoopback(listeners []shared.ListenerInfo) bool {
	for _, l := range listeners {
		if shared.IsWildcardIP(l.LocalAddress) {
			return false
		}
		if !shared.IsLoopbackIP(l.LocalAddress) {
			return false
		}
	}
	return true
}

func listenerPortRange(listeners []shared.ListenerInfo) (min, max int) {
	min = 99999
	for _, l := range listeners {
		if l.LocalPort < min {
			min = l.LocalPort
		}
		if l.LocalPort > max {
			max = l.LocalPort
		}
	}
	return
}

func countInboundByScope(conns []shared.ConnectionInfo, listeners []shared.ListenerInfo) (ext, internal, loopback int) {
	listenerPorts := make(map[int]struct{})
	for _, l := range listeners {
		listenerPorts[l.LocalPort] = struct{}{}
	}
	for _, cn := range conns {
		if _, ok := listenerPorts[cn.LocalPort]; !ok {
			continue
		}
		if cn.RemoteAddress == "" {
			continue
		}
		if shared.IsLoopbackIP(cn.RemoteAddress) {
			loopback++
		} else if shared.IsInternalIP(cn.RemoteAddress) {
			internal++
		} else {
			ext++
		}
	}
	return
}

func countDistinctSources(conns []shared.ConnectionInfo, listeners []shared.ListenerInfo) int {
	listenerPorts := make(map[int]struct{})
	for _, l := range listeners {
		listenerPorts[l.LocalPort] = struct{}{}
	}
	sources := make(map[string]struct{})
	for _, cn := range conns {
		if _, ok := listenerPorts[cn.LocalPort]; ok && cn.RemoteAddress != "" {
			sources[cn.RemoteAddress] = struct{}{}
		}
	}
	return len(sources)
}

func isInboundConn(cn shared.ConnectionInfo, listeners []shared.ListenerInfo) bool {
	for _, l := range listeners {
		if cn.LocalPort == l.LocalPort {
			return true
		}
	}
	return false
}

func hasPortInConns(conns []shared.ConnectionInfo, port int) bool {
	for _, cn := range conns {
		if cn.RemotePort == port {
			return true
		}
	}
	return false
}

func connectionLifetimes(c *shared.Candidate) []float64 {
	now := time.Now()
	var lifetimes []float64
	for _, cn := range c.Conns {
		if cn.State != "ESTABLISHED" {
			continue
		}
		key := makeConnKey(c, cn)
		if first, ok := shared.ConnFirstSeen[key]; ok {
			lifetimes = append(lifetimes, now.Sub(first).Seconds())
		}
	}
	return lifetimes
}

func makeConnKey(c *shared.Candidate, cn shared.ConnectionInfo) shared.ConnKey {
	pid := 0
	if c.Proc != nil {
		pid = c.Proc.Pid
	}
	return shared.ConnKey{
		Pid:        pid,
		LocalAddr:  cn.LocalAddress,
		LocalPort:  cn.LocalPort,
		RemoteAddr: cn.RemoteAddress,
		RemotePort: cn.RemotePort,
	}
}

func integrityToFloat(integrity string) float64 {
	switch strings.ToLower(integrity) {
	case "low":
		return 0
	case "medium":
		return 1
	case "high":
		return 2
	case "system":
		return 3
	default:
		return 1
	}
}

func sampleMeanStddev(samples []uint64) (mean, stddev float64) {
	if len(samples) == 0 {
		return
	}
	sum := 0.0
	for _, v := range samples {
		sum += float64(v)
	}
	mean = sum / float64(len(samples))
	if len(samples) > 1 {
		varSum := 0.0
		for _, v := range samples {
			d := float64(v) - mean
			varSum += d * d
		}
		stddev = math.Sqrt(varSum / float64(len(samples)))
	}
	return
}

func intervalMeanStddev(intervals []float64) (mean, stddev float64) {
	if len(intervals) == 0 {
		return
	}
	sum := 0.0
	for _, v := range intervals {
		sum += v
	}
	mean = sum / float64(len(intervals))
	if len(intervals) > 1 {
		varSum := 0.0
		for _, v := range intervals {
			d := v - mean
			varSum += d * d
		}
		stddev = math.Sqrt(varSum / float64(len(intervals)))
	}
	return
}

func intervalAutocorrelation(intervals []float64) float64 {
	if len(intervals) < 2 {
		return 0
	}
	mean, stddev := intervalMeanStddev(intervals)
	if stddev == 0 {
		return 1
	}
	var sum float64
	n := len(intervals)
	for i := 0; i < n-1; i++ {
		sum += (intervals[i] - mean) * (intervals[i+1] - mean)
	}
	return sum / (float64(n-1) * stddev * stddev)
}

func intervalEntropy(intervals []float64) float64 {
	if len(intervals) < 2 {
		return 0
	}
	diffs := make([]float64, 0, len(intervals)-1)
	for i := 1; i < len(intervals); i++ {
		diffs = append(diffs, math.Abs(intervals[i]-intervals[i-1]))
	}
	if len(diffs) == 0 {
		return 0
	}
	bins := make(map[int]int)
	for _, d := range diffs {
		bins[int(d)]++
	}
	entropy := 0.0
	n := float64(len(diffs))
	for _, count := range bins {
		p := float64(count) / n
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func shannonEntropy(s string) float64 {
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

func isSuspiciousPath(exePath string) bool {
	p := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(exePath), "\\", "/"))
	if p == "" {
		return false
	}
	return strings.HasPrefix(p, "c:/users/") ||
		strings.HasPrefix(p, "/home/") ||
		strings.Contains(p, "/downloads/") ||
		strings.Contains(p, "/desktop/") ||
		strings.Contains(p, "/appdata/local/temp/") ||
		strings.Contains(p, "/tmp/") ||
		strings.Contains(p, "/var/tmp/")
}

func isC2PipeName(name string) bool {
	suspiciousPatterns := []string{
		"msagent_", "MSSE-", "postex_", "postex_ssh",
		"status_", "mojo.", "chrome.", "gecko.",
	}
	for _, pattern := range suspiciousPatterns {
		if len(name) >= len(pattern) && name[:len(pattern)] == pattern {
			return true
		}
	}
	return false
}

func isWellKnownAdminPipe(name string) bool {
	adminPipes := []string{"srvsvc", "svcctl", "wkssvc", "lsarpc", "samr", "netlogon"}
	for _, ap := range adminPipes {
		if name == ap {
			return true
		}
	}
	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
