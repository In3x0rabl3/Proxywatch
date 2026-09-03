package views

import (
	"fmt"
	"sort"
	"strings"

	"proxywatch/internal/pcap"
	"proxywatch/internal/shared"
)

// metaKeyFunc returns the grouping key for a (host, FlowMeta) pair, plus
// a human-readable display name fragment for the projected row. Empty
// key means "skip this flow" (e.g. JA3 grouping skips non-TLS flows).
type metaKeyFunc func(host string, meta pcap.FlowMeta, conn shared.ConnectionInfo) (key, displayName string)

// ja3Key buckets flows by (host, JA3 hash). Skips non-TLS flows.
func ja3Key(host string, meta pcap.FlowMeta, conn shared.ConnectionInfo) (string, string) {
	if meta.JA3 == "" {
		return "", ""
	}
	short := meta.JA3
	if len(short) > 8 {
		short = short[:8]
	}
	return host + "|ja3|" + meta.JA3,
		fmt.Sprintf("pcap-ja3:%s [%s…]:%d", host, short, conn.RemotePort)
}

// asnKey buckets flows by (host, ASN org) using the warm ASN cache.
// Internal RFC1918/loopback fall back to a fixed "internal-rfc1918"
// bucket. Unknown / not-yet-resolved IPs bucket as "unresolved-asn".
func asnKey(host string, meta pcap.FlowMeta, conn shared.ConnectionInfo) (string, string) {
	if conn.RemoteAddress == "" {
		return "", ""
	}
	if shared.IsLoopbackIP(conn.RemoteAddress) {
		return "", ""
	}
	var org string
	if shared.IsInternalIP(conn.RemoteAddress) {
		org = "internal-rfc1918"
	} else if orgs := shared.LookupCachedASNOrgsForIP(conn.RemoteAddress); len(orgs) > 0 {
		org = strings.Join(orgs, "+")
	} else {
		org = "unresolved-asn"
	}
	return host + "|asn|" + org,
		fmt.Sprintf("pcap-asn:%s → %s:%d", host, org, conn.RemotePort)
}

// sessionKey buckets flows by (host, time-window) where the window is
// a fixed 60-second slot computed from FirstSeen. Cheerful's C2 +
// SOCKS-tunneled scan within the same minute → one session row.
func sessionKey(host string, meta pcap.FlowMeta, conn shared.ConnectionInfo) (string, string) {
	if meta.FirstSeen.IsZero() {
		return "", ""
	}
	const sessionWindowSeconds = 60
	bucket := meta.FirstSeen.Unix() / sessionWindowSeconds
	return fmt.Sprintf("%s|session|%d", host, bucket),
		fmt.Sprintf("pcap-session:%s @%s",
			host, meta.FirstSeen.UTC().Format("15:04:05"))
}

// projectByMeta walks the candidate set, expands per-flow rows from
// each cluster's Conns, then re-buckets by the keyfn. Each output row
// inherits the WORST role across all contributing flows' parent
// clusters. Display name is taken from the key function's hint, with
// the dominant-port + flow count appended.
func projectByMeta(res *pcap.IngestResult, keyfn metaKeyFunc) []shared.Candidate {
	if res == nil || len(res.Candidates) == 0 {
		return nil
	}
	type bucket struct {
		display string
		role    string
		signals map[string]struct{}
		reasons map[string]struct{}
		conns   []shared.ConnectionInfo
		bytes   uint64
	}
	buckets := make(map[string]*bucket)
	// Seed projected rows from cluster candidates' connection lists.
	var passthrough []shared.Candidate
	for _, c := range res.Candidates {
		if c.Proc == nil || !pcap.IsSyntheticPID(c.Proc.Pid) {
			passthrough = append(passthrough, c)
			continue
		}
		name := c.Proc.Name
		// Listeners + rollups don't bucket — they pass through unchanged.
		if isListenerOrRollupName(name) {
			passthrough = append(passthrough, c)
			continue
		}
		host := parentHost(name)
		if host == "" {
			passthrough = append(passthrough, c)
			continue
		}
		for _, conn := range c.Conns {
			if conn.RemoteAddress == "" || conn.RemotePort <= 0 {
				continue
			}
			fid := pcap.FlowID{
				LocalIP:    conn.LocalAddress,
				LocalPort:  conn.LocalPort,
				RemoteIP:   conn.RemoteAddress,
				RemotePort: conn.RemotePort,
			}
			meta := res.FlowsMeta[fid]
			key, display := keyfn(host, meta, conn)
			if key == "" {
				continue
			}
			b, ok := buckets[key]
			if !ok {
				b = &bucket{
					display: display,
					signals: make(map[string]struct{}),
					reasons: make(map[string]struct{}),
				}
				buckets[key] = b
			}
			// Worst-role-wins.
			if roleSeverityRank(c.Role) > roleSeverityRank(b.role) {
				b.role = c.Role
			}
			for _, s := range c.Signals {
				b.signals[s] = struct{}{}
			}
			for _, r := range c.Reasons {
				b.reasons[r] = struct{}{}
			}
			b.conns = append(b.conns, conn)
			b.bytes += meta.BytesSum
		}
	}
	if len(buckets) == 0 {
		return passthrough
	}
	// Synthesize display candidates per bucket. Use a separate display-
	// PID range so they don't collide with the classifier's synthetic
	// PIDs.
	const projDisplayPIDBase = 0x7fff_a000_0000
	pidCounter := uint64(projDisplayPIDBase)
	out := make([]shared.Candidate, 0, len(passthrough)+len(buckets))
	out = append(out, passthrough...)
	keys := make([]string, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b := buckets[k]
		signals := make([]string, 0, len(b.signals))
		for s := range b.signals {
			signals = append(signals, s)
		}
		sort.Strings(signals)
		reasons := make([]string, 0, len(b.reasons))
		for r := range b.reasons {
			reasons = append(reasons, r)
		}
		sort.Strings(reasons)
		row := shared.Candidate{
			Role:    b.role,
			Signals: signals,
			Reasons: reasons,
			Conns:   b.conns,
			Proc: &shared.ProcessInfo{
				Pid:         int(pidCounter & 0x7fff_ffff),
				Name:        fmt.Sprintf("%s [%d flows]", b.display, len(b.conns)),
				IOReadBytes: b.bytes,
			},
		}
		pidCounter++
		out = append(out, row)
	}
	return out
}

// roleSeverityRank ranks roles for worst-wins aggregation in projected
// rows. Higher rank = more severe.
func roleSeverityRank(role string) int {
	switch strings.ToLower(role) {
	case "pivot":
		return 5
	case "beacon":
		return 4
	case "tunnel":
		return 3
	case "smb-pipe":
		return 2
	case "outbound":
		return 1
	}
	return 0
}

// projectGroupBy returns a transformed candidate set that matches the
// requested grouping mode. Returns nil to indicate no projection (use
// the original candidates as-is).
//
// Each non-default grouping is a VIEW over the existing /16 cluster
// candidates — classification is unchanged, only the row identity
// differs. Each projected row inherits Role / Signals / Reasons from
// the parent cluster (worst-role-wins when multiple parents
// contribute to one projected row) so the existing role guard,
// demote pass, operator labels etc. continue to dictate promotion.
func projectGroupBy(res *pcap.IngestResult, groupBy string) []shared.Candidate {
	switch groupBy {
	case "", "cluster":
		return nil // no projection; use res.Candidates as-is
	case "flow":
		return projectFlowView(res)
	case "ja3":
		return projectByMeta(res, ja3Key)
	case "asn":
		return projectByMeta(res, asnKey)
	case "beacon":
		return projectByMeta(res, sessionKey)
	case "behavior":
		// Phase 5 — needs PSD / cipher fingerprint plumbing in
		// flowState. Falls back to default until that ships.
		return nil
	default:
		return nil
	}
}

// projectFlowView expands each /16 cluster candidate into per-flow
// candidates — one synthetic display PID per (LocalAddr:LocalPort,
// RemoteAddr:RemotePort) tuple drawn from the cluster's Conns slice.
// Each child row inherits the parent's role/signals/reasons and gets
// only its own connection in the Conns slice so the renderer's
// pcapTupleFor() reads the per-flow tuple.
//
// Listener candidates and rollup candidates without per-connection
// detail are passed through unchanged — the per-flow view doesn't
// add value for them.
//
// Synthetic display PIDs use a separate PID range (offset above the
// cluster PIDs) so they don't collide with the classifier's
// synthetic PIDs.
func projectFlowView(res *pcap.IngestResult) []shared.Candidate {
	const flowDisplayPIDBase = 0x7fff_8000_0000 // well above SyntheticPIDBase
	out := make([]shared.Candidate, 0, len(res.Candidates)*2)
	pidCounter := uint64(flowDisplayPIDBase)
	for _, c := range res.Candidates {
		// Pass listeners + rollups + non-synthetic candidates through.
		if c.Proc == nil || !pcap.IsSyntheticPID(c.Proc.Pid) {
			out = append(out, c)
			continue
		}
		// Cluster candidates with no per-connection data: keep as-is.
		if len(c.Conns) == 0 {
			out = append(out, c)
			continue
		}
		// Don't expand listener-style or rollup-style cluster names —
		// they're already host-context rows, not destination clusters.
		name := ""
		if c.Proc != nil {
			name = c.Proc.Name
		}
		if isListenerOrRollupName(name) {
			out = append(out, c)
			continue
		}
		// Expand each connection into its own display row.
		for _, conn := range c.Conns {
			if conn.RemoteAddress == "" || conn.RemotePort <= 0 {
				continue
			}
			child := c
			childProc := *c.Proc
			childProc.Pid = int(pidCounter & 0x7fff_ffff)
			pidCounter++
			localAddr := conn.LocalAddress
			if localAddr == "" {
				// Fall back to the parent's host portion of the cluster name.
				localAddr = parentHost(name)
			}
			childProc.Name = fmt.Sprintf("pcap-flow:%s:%d → %s:%d",
				localAddr, conn.LocalPort,
				conn.RemoteAddress, conn.RemotePort)
			child.Proc = &childProc
			child.Conns = []shared.ConnectionInfo{conn}
			out = append(out, child)
		}
	}
	return out
}

// isListenerOrRollupName returns true for cluster names that don't
// represent destination-keyed clusters (so projecting them per-flow
// adds no information).
func isListenerOrRollupName(name string) bool {
	if name == "" {
		return false
	}
	// "pcap:<ip> outbound-ext" / " outbound-int"
	for _, suffix := range []string{" outbound-ext", " outbound-int"} {
		if hasSuffix(name, suffix) {
			return true
		}
	}
	// "pcap:<ip>:<port>" — listener form, no arrow
	if !contains(name, "→") && !contains(name, "outbound-") {
		return true
	}
	return false
}

func parentHost(clusterName string) string {
	// "pcap:172.16.1.81 → 104.21.0.0/16:443" → "172.16.1.81"
	const prefix = "pcap:"
	if !hasPrefix(clusterName, prefix) {
		return ""
	}
	body := clusterName[len(prefix):]
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case ' ', ':':
			return body[:i]
		}
	}
	return body
}

func hasPrefix(s, p string) bool {
	return len(s) >= len(p) && s[:len(p)] == p
}

func hasSuffix(s, suf string) bool {
	return len(s) >= len(suf) && s[len(s)-len(suf):] == suf
}

func contains(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	if len(s) < len(sub) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
