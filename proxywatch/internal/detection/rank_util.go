package classifier

import (
	"hash/fnv"
	"proxywatch/internal/shared"
	"strconv"
	"strings"
)

func historyHostScope(c *shared.Candidate) string {
	if c == nil {
		return "local"
	}
	host := strings.ToLower(strings.TrimSpace(c.Host))
	if host == "" {
		return "local"
	}
	return host
}

func historyPIDForCandidate(c *shared.Candidate) int {
	if c == nil || c.Proc == nil {
		return 0
	}
	return scopedRuntimePID(historyHostScope(c), c.Proc.Pid)
}

func scopedRuntimePID(host string, pid int) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(host))
	_, _ = h.Write([]byte("|"))
	_, _ = h.Write([]byte(strconv.Itoa(pid)))
	out := int(h.Sum32() & 0x7fffffff)
	if out == 0 {
		if pid < 0 {
			return -pid
		}
		if pid == 0 {
			return 1
		}
		return pid
	}
	return out
}

func ProcessBehaviorKey(c *shared.Candidate) string {
	if c == nil || c.Proc == nil {
		return historyHostScope(c) + "|(unknown)"
	}
	p := c.Proc
	exe := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(p.ExePath, "\\", "/")))
	name := strings.ToLower(strings.TrimSpace(p.Name))
	user := strings.ToLower(strings.TrimSpace(p.UserName))
	if exe == "" {
		exe = "(unknown)"
	}
	if name == "" {
		name = "(unknown)"
	}
	// Include PID so multiple instances of the same binary (e.g., two ssh
	// processes) get independent model profiles and training labels.
	pid := strconv.Itoa(p.Pid)
	return historyHostScope(c) + "|" + exe + "|" + name + "|" + user + "|" + pid
}

// hasProxyTunnelLibPattern returns true when a library base filename contains
// substrings that indicate proxy, SOCKS, or tunneling functionality. No
// specific library names are hardcoded — only protocol/technique keywords.
// isSuspiciousExePath returns true when the executable runs from a
// user-writable location that legitimate long-running software rarely uses.
// This is purely path-based — no process names are checked.
func isSuspiciousExePath(exePath string) bool {
	p := shared.NormalizeExePath(exePath)
	if p == "" {
		return false
	}
	// Common user-writable staging locations.
	markers := []string{
		"/downloads/",
		"/desktop/",
		"/tmp/",
		"/var/tmp/",
		"/appdata/local/temp/",
		"/public/",
	}
	for _, m := range markers {
		if strings.Contains(p, m) {
			return true
		}
	}
	return false
}

func hasProxyTunnelLibPattern(base string) bool {
	if base == "" {
		return false
	}
	// Match "lib" prefix combined with a proxy/tunnel keyword.
	if !strings.HasPrefix(base, "lib") {
		return false
	}
	keywords := []string{"socks", "proxy", "tunnel", "tun2"}
	for _, kw := range keywords {
		if strings.Contains(base, kw) {
			return true
		}
	}
	return false
}

func isPendingControlState(state string) bool {
	switch state {
	case "SYN_SENT", "SYN_RECEIVED":
		return true
	default:
		return false
	}
}

func isEstablishedState(state string) bool {
	return state == "ESTABLISHED"
}

func isActiveConnState(state string) bool {
	switch state {
	case "ESTABLISHED",
		"SYN_SENT",
		"SYN_RECEIVED",
		"FIN_WAIT_1",
		"FIN_WAIT_2",
		"CLOSE_WAIT",
		"CLOSING",
		"LAST_ACK",
		"TIME_WAIT":
		return true
	default:
		return false
	}
}
