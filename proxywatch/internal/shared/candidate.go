package shared

import (
	"net"
	"strconv"
	"strings"
	"time"
)

type Candidate struct {
	Host         string
	Proc         *ProcessInfo
	Listeners    []ListenerInfo
	Conns        []ConnectionInfo
	UDPListeners []UDPListenerInfo

	// Delegated egress: process likely initiated traffic socket-owned by another process.
	DelegatedEgress   bool
	DelegatedStrong   bool
	DelegatedOwnerPID int
	DelegatedOwner    string

	// classifier-owned fields
	Score          int
	Confidence     int
	Reasons        []string
	Signals        []string
	Role           string
	ActiveProxying bool

	ControlChannel         *ConnectionInfo
	ControlDurationSeconds int

	OutTotal      int
	OutExternal   int
	OutInternal   int
	OutLoopback   int
	OutLongLived  int
	OutShortLived int

	InboundTotal int

	TrafficVerified bool
	StrongEvidence  bool
}

type ProcessInfo struct {
	Pid         int
	ParentPid   int
	Name        string
	SessionID   uint32
	SessionName string

	MemUsage uint64 // bytes (WorkingSetSize)
	Status   string // e.g. "Running"

	UserName     string // DOMAIN\User
	ExePath      string
	Company      string // file publisher/company (if available)
	Integrity    string
	IOReadBytes  uint64
	IOWriteBytes uint64
	IOOtherBytes uint64
	IOReadBps    uint64
	IOWriteBps   uint64
	IOOtherBps   uint64
	CpuTime      time.Duration // user + kernel
	WindowTitle  string        // reserved
}

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

type UDPListenerInfo struct {
	Pid          int
	LocalAddress string
	LocalPort    int
}

type Snapshot struct {
	Timestamp    time.Time
	Processes    map[int]*ProcessInfo
	Listeners    []ListenerInfo
	Connections  []ConnectionInfo
	UDPListeners []UDPListenerInfo
}

type ListenerKey struct {
	Pid  int
	Addr string
	Port int
}

const (
	BurstSamplesMax = 10
	BurstSamplesMid = 4
	BurstSamplesMin = 1
	BurstSleep      = 10 * time.Millisecond

	BurstIdleConnThreshold     = 5
	BurstModerateConnThreshold = 25

	ProcessMetaCacheTTL = 60 * time.Second
	CandidateLingerTTL  = 20 * time.Second
)

func CandidateKey(c Candidate) string {
	host := DisplayHost(c.Host)
	if c.Proc == nil {
		return host + ":0"
	}
	return host + ":" + strconv.Itoa(c.Proc.Pid)
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
