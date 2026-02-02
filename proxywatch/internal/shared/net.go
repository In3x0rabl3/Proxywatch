package shared

import (
	"net"
	"strconv"
	"strings"
)

type ListenerInfo struct {
	Pid          int
	LocalAddress string
	LocalPort    int
	State        string
}

type ConnectionInfo struct {
	Pid           int
	LocalAddress  string
	LocalPort     int
	RemoteAddress string
	RemotePort    int
	State         string
}

// TargetPrefix returns a coarse prefix for an IP to group related targets.
// IPv4: /24 (first three octets). IPv6: /48 (first four hextets). Empty on parse failure.
func TargetPrefix(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	if v4 := parsed.To4(); v4 != nil {
		return strings.Join([]string{
			strconv.Itoa(int(v4[0])),
			strconv.Itoa(int(v4[1])),
			strconv.Itoa(int(v4[2])),
		}, ".")
	}
	// IPv6: use first four hextets
	parts := strings.Split(parsed.String(), ":")
	if len(parts) < 4 {
		return ""
	}
	return strings.ToLower(strings.Join(parts[:4], ":"))
}
