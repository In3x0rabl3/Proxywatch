package output

import (
	"fmt"
	"hash/fnv"
	"net"
	"strings"

	"proxywatch/internal/shared"
)

// suricataSIDBase is the starting SID allocated to proxywatch-generated
// rules. Operators should adjust via their own ruleset manager if it
// collides with existing rules.
const suricataSIDBase = 9_000_000

// BuildSuricataRule emits a single Suricata alert rule that fires on the
// observed control channel's (or primary connection's) remote IP/port.
// When beacon timing is known, a threshold clause limits the alert to one
// fire per interval to mirror beacon cadence. Returns an empty string when
// there's no usable remote endpoint.
func BuildSuricataRule(c *shared.Candidate) string {
	if c == nil || c.Proc == nil {
		return ""
	}

	remoteIP, remotePort, proto := primaryRemote(c)
	if remoteIP == "" || remotePort <= 0 {
		return "# No remote endpoint observed for this candidate — Suricata needs a destination to match."
	}

	procName := strings.TrimSpace(c.Proc.Name)
	if procName == "" {
		procName = "proxywatch_candidate"
	}

	sid := suricataSID(c)
	msg := fmt.Sprintf("Proxywatch %s %s → %s:%d",
		strings.TrimSpace(c.Role), procName, remoteIP, remotePort)

	var b strings.Builder
	b.WriteString("alert ")
	b.WriteString(proto)
	b.WriteString(" $HOME_NET any -> ")
	if isIPv6(remoteIP) {
		b.WriteString("[")
		b.WriteString(remoteIP)
		b.WriteString("]")
	} else {
		b.WriteString(remoteIP)
	}
	b.WriteString(fmt.Sprintf(" %d ", remotePort))
	b.WriteString("(")
	b.WriteString(fmt.Sprintf("msg:%q; ", msg))
	b.WriteString("flow:established,to_server; ")
	if c.BeaconIntervalMs > 0 {
		secs := c.BeaconIntervalMs / 1000
		if secs < 1 {
			secs = 1
		}
		b.WriteString(fmt.Sprintf("threshold:type both, track by_src, count 1, seconds %d; ", secs))
	}
	b.WriteString(fmt.Sprintf("metadata:role %s", strings.TrimSpace(c.Role)))
	if c.ControlSubtype != "" {
		b.WriteString(", subtype ")
		b.WriteString(c.ControlSubtype)
	}
	if c.Proc.SHA256 != "" {
		b.WriteString(", sha256 ")
		b.WriteString(c.Proc.SHA256[:min(len(c.Proc.SHA256), 16)])
	}
	b.WriteString("; ")
	b.WriteString("classtype:trojan-activity; ")
	b.WriteString(fmt.Sprintf("sid:%d; rev:1;)", sid))
	b.WriteString("\n")
	return b.String()
}

func primaryRemote(c *shared.Candidate) (string, int, string) {
	if c.ControlChannel != nil {
		ip := strings.TrimSpace(c.ControlChannel.RemoteAddress)
		if ip != "" && c.ControlChannel.RemotePort > 0 {
			return ip, c.ControlChannel.RemotePort, "tcp"
		}
	}
	for _, conn := range c.Conns {
		ip := strings.TrimSpace(conn.RemoteAddress)
		if ip == "" || conn.RemotePort <= 0 {
			continue
		}
		if shared.IsLoopbackIP(ip) {
			continue
		}
		return ip, conn.RemotePort, "tcp"
	}
	for _, u := range c.UDPListeners {
		if u.LocalPort > 0 {
			return strings.TrimSpace(u.LocalAddress), u.LocalPort, "udp"
		}
	}
	return "", 0, "tcp"
}

func isIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() == nil
}

// suricataSID hashes host+pid+role into a stable SID above the base so
// multiple candidates don't collide. Operators should re-SID before
// deployment to match their own allocation scheme.
func suricataSID(c *shared.Candidate) int {
	h := fnv.New32a()
	if c.Proc != nil {
		_, _ = h.Write([]byte(c.Proc.Name))
		_, _ = h.Write([]byte(fmt.Sprintf("%d", c.Proc.Pid)))
	}
	_, _ = h.Write([]byte(c.Role))
	_, _ = h.Write([]byte(c.Host))
	return suricataSIDBase + int(h.Sum32()%999_999)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
