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
	RawSocket         bool            // process has open raw sockets (nmap, ping, etc.)
	RawConns          []RawSocketConn // raw/packet socket connection entries
	NamedPipes        []string        // named pipe handles (pipe names)

	// classifier-owned fields
	Score          int
	Confidence     int
	Reasons        []string
	Signals        []string
	Role           string
	ControlSubtype string // subtype qualifier (e.g. "session", "beacon", "socks-tunnel", "tcp-pivot")
	ActiveProxying bool

	ControlChannel         *ConnectionInfo
	ControlDurationSeconds int
	SeenSeconds            int
	Exited                 bool // process no longer running (lingered entry)

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
	StartTime    time.Time     // process creation time from OS
	WindowTitle  string        // reserved
	CmdLine      string        // full command line
	LoadedLibs   []string      // notable shared libraries / DLLs
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

// RawSocketConn represents a raw or packet socket entry from /proc/net/raw,
// /proc/net/raw6, or /proc/net/packet.
type RawSocketConn struct {
	Pid    int
	Local  string
	Remote string
	State  string
	Proto  string // "raw", "raw6", "packet"
}

// NamedPipeInfo represents an open named pipe handle detected on a process.
type NamedPipeInfo struct {
	Pid      int    `json:"pid"`
	PipeName string `json:"pipe_name"`
}

type Snapshot struct {
	Timestamp     time.Time
	Processes     map[int]*ProcessInfo
	Listeners     []ListenerInfo
	Connections   []ConnectionInfo
	UDPListeners  []UDPListenerInfo
	RawSocketPIDs map[int]bool    // PIDs with open raw sockets
	RawConns      []RawSocketConn // raw/packet socket entries
	NamedPipes    []NamedPipeInfo // named pipe handles per process
}

type ListenerKey struct {
	Pid  int
	Addr string
	Port int
}

const (
	BurstSamplesMax = 10
	BurstSamplesMid = 4
	BurstSamplesMin = 3
	BurstSleep      = 10 * time.Millisecond

	BurstIdleConnThreshold     = 5
	BurstModerateConnThreshold = 25

	ProcessMetaCacheTTL = 60 * time.Second
	CandidateLingerTTL  = 30 * time.Second
	// Keep suspicious labels visible long enough to survive intermittent callbacks.
	CandidateSuspiciousLingerTTL = 2 * time.Minute
	// Keep strong findings visible longer than normal watch rows.
	CandidateStrongLingerTTL = 1 * time.Minute
)

func CandidateKey(c Candidate) string {
	host := DisplayHost(c.Host)
	if c.Proc == nil {
		return host + ":0"
	}
	return host + ":" + strconv.Itoa(c.Proc.Pid)
}

func CandidateState(c Candidate) string {
	if c.Exited {
		return "exited"
	}
	if c.ActiveProxying {
		return "active"
	}
	if c.StrongEvidence {
		return "strong"
	}
	return "watch"
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

// ContourHint is a contour-derived signal mapped to a process candidate.
// Calibration can consume these hints to bias tuning toward observed
// exfiltration and egress-escape patterns.
type ContourHint struct {
	CandidateKey string `json:"candidate_key,omitempty"`
	Host         string `json:"host,omitempty"`
	PID          int    `json:"pid,omitempty"`
	Process      string `json:"process,omitempty"`
	Category     string `json:"category,omitempty"`
	Signal       string `json:"signal,omitempty"`
	Reason       string `json:"reason,omitempty"`
	Severity     string `json:"severity,omitempty"`
}

func NormalizeContourSeverity(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "active", "critical", "high":
		return "active"
	case "strong", "medium":
		return "strong"
	default:
		return "watch"
	}
}
