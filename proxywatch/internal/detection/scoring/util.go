package scoring

import (
	"hash/fnv"
	"proxywatch/internal/shared"
	"strconv"
	"strings"
)

func HistoryHostScope(c *shared.Candidate) string {
	if c == nil {
		return "local"
	}
	host := strings.ToLower(strings.TrimSpace(c.Host))
	if host == "" {
		return "local"
	}
	return host
}

func HistoryPIDForCandidate(c *shared.Candidate) int {
	if c == nil || c.Proc == nil {
		return 0
	}
	return ScopedRuntimePID(HistoryHostScope(c), c.Proc.Pid)
}

func ScopedRuntimePID(host string, pid int) int {
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

// ProcessBehaviorKey delegates to shared.CandidateBehaviorKey — single source of truth.
func ProcessBehaviorKey(c *shared.Candidate) string {
	return shared.CandidateBehaviorKey(c)
}

// IsSuspiciousExePath returns true when the executable runs from a
// user-writable location that legitimate long-running software rarely uses.
// This is purely path-based — no process names are checked.
func IsSuspiciousExePath(exePath string) bool {
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

func IsPendingControlState(state string) bool {
	switch state {
	case "SYN_SENT", "SYN_RECEIVED":
		return true
	default:
		return false
	}
}

func IsEstablishedState(state string) bool {
	return state == "ESTABLISHED"
}

func IsActiveConnState(state string) bool {
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
