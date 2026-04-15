package shared

import (
	"net"
	"strconv"
	"strings"
	"sync"
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
	SuggestedRole          string  // rank.go's suggestion before model override
	BeaconIntervalMs       int     // confirmed beacon interval (persisted even when role is blocked)
	BeaconJitter           float64 // beacon jitter coefficient

	// ML model prediction (populated when model is loaded).
	MLRole       string             // ML-predicted role
	MLConfidence float64            // confidence of top prediction
	MLTopN       []MLRolePrediction // top-3 role candidates
	MLActive     bool               // true when ML model made this prediction
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

// MLRolePrediction is a single role candidate from the ML model.
type MLRolePrediction struct {
	Role string
	Prob float64
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

	// Child process tracking — built from PPID map during snapshot.
	ChildCount int   // number of child processes
	ChildPids  []int // child PIDs (capped at 50)

	// Thread count — from /proc/[pid]/stat (Linux) or PROCESSENTRY32.cntThreads (Windows).
	ThreadCount int

	// Handle/FD count — Windows: GetProcessHandleCount; Linux: /proc/[pid]/fd count.
	HandleCount int // Windows kernel handle count
	FDCount     int // Linux file descriptor count

	// Memory regions — Linux: parsed from /proc/[pid]/maps; Windows: deferred.
	HasRWXMemory  bool // has any read-write-execute memory region
	AnonExecCount int  // anonymous executable regions (no file backing = injected code)

	// Token details — Windows only (from existing token handle).
	TokenType     string // "Primary" or "Impersonation"
	ElevationType string // "Full", "Limited", or ""

	// Linux capabilities — from /proc/[pid]/status CapEff line.
	CapEffective uint64 // effective capability bitmask
	Seccomp      int    // 0=disabled, 1=strict, 2=filter

	// Signature trust — best-effort OS-native trust verification.
	// SignatureTrust is one of: "trusted", "untrusted", "unsigned", "unknown".
	// Signed is true iff SignatureTrust == "trusted". Populated by the
	// shared.VerifyBinaryTrust helper called from per-OS telemetry readers.
	// On platforms where OS-native signature APIs are not yet wired,
	// falls back to a conservative path+ownership heuristic — see
	// shared/signature.go for exact semantics.
	Signed         bool
	SignatureTrust string

	// Authenticode details populated by the Windows signature verifier when
	// PROXYWATCH_ONLINE_VERIFY is enabled. Publisher is the signer CN
	// extracted from the signing cert. AuthenticodeOCSPSeen is true when
	// the verdict came from a full WinVerifyTrust + OCSP round-trip (not
	// just a cached verdict from a prior run). Used by the FP-shape
	// evaluator to distinguish "fully verified" from "presumed via cache".
	Publisher            string
	AuthenticodeOCSPSeen bool

	// SHA256 of the on-disk executable, computed asynchronously by the
	// exe_hash worker. Stable across renames and path spoofing — an
	// attacker can put the same bytes anywhere but the hash doesn't
	// change. Used as the key for operator labels (Phase 9), so the
	// same binary gets the same verdict no matter where or as what
	// name it shows up.
	//
	// Empty when the hash hasn't been computed yet (first cycle after
	// process observation) or when the executable can't be read.
	SHA256 string

	// Vendor-agnostic online-evidence fields populated by the multi-verifier
	// layer (Phase 6). PkgOwned is hydrated from the path-scoped verdict
	// cache when the binary is tracked by dpkg. PublisherDNSAligned is set
	// live per-classify by EvaluatePublisherDNSAlignment when the process's
	// outbound destinations share DNS with the Authenticode publisher.
	// OnlineEvidence is a compact flat tag list for operator-visible
	// evidence trace ("dns:ptr-aligned:drata.com", "pkg:dpkg-owned:openssh-client", ...).
	PkgOwned             bool
	PkgOwnerName         string
	PublisherDNSAligned  bool
	OnlineEvidence       []string
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
	// CandidateLingerTTL is the default retention for benign/non-malicious exited processes.
	CandidateLingerTTL = 30 * time.Second
	// CandidateSuspiciousLingerTTL keeps malicious roles (sessions, tunnels, beacons, pivots)
	// visible long enough to survive intermittent callbacks.
	CandidateSuspiciousLingerTTL = 5 * time.Minute
	// CandidateStrongLingerTTL keeps strong-evidence findings visible.
	CandidateStrongLingerTTL = 5 * time.Minute
)

func CandidateKey(c Candidate) string {
	host := DisplayHost(c.Host)
	if c.Proc == nil {
		return host + ":0"
	}
	return host + ":" + strconv.Itoa(c.Proc.Pid)
}

// AnalyzingStableRoleCycles is the number of consecutive scan cycles the
// committed role must remain the same for Analyzing to exit. At
// 250ms/cycle this is ~3s if the classifier commits quickly, longer if
// the role keeps flapping. It's the "dynamic, as long as needed"
// component — if role flaps, streak resets and Analyzing extends.
const AnalyzingStableRoleCycles = 12

// AnalyzingMinVisibleSeconds is the wall-clock minimum a process must be
// visible in the current run before Analyzing can exit. Prevents the
// "assigned-a-role-instantly" feel on hosts where rank.go + persisted
// baseline converges in <1s. Operators want to SEE the scanner
// deliberating, not present instant verdicts that look stale.
//
// Exit condition: (streak >= AnalyzingStableRoleCycles) AND
//                  (time since firstSeenInRun >= AnalyzingMinVisibleSeconds)
// so a flapping process never exits early, and a stable process still
// shows Analyzing for the minimum visible window.
const AnalyzingMinVisibleSeconds = 10

// pidFirstSeenInRun tracks when each PID was first observed in the current
// process lifetime. Session-scoped (map is fresh on every scanner start)
// independent of disk-persisted ProcHistory, so every restart gives
// operators a visible Analyzing ramp regardless of the candidate's
// historical data. Not persisted, not thread-hot-path — only read from
// CandidateState which is already display-scoped.
var (
	pidFirstSeenMu   sync.Mutex
	pidFirstSeenInRun = map[int]time.Time{}
)

// firstSeenInRunFor returns the first-observation timestamp for a PID
// in the current scanner run. Creates the entry on first call.
func firstSeenInRunFor(pid int) time.Time {
	pidFirstSeenMu.Lock()
	defer pidFirstSeenMu.Unlock()
	if t, ok := pidFirstSeenInRun[pid]; ok {
		return t
	}
	t := time.Now()
	pidFirstSeenInRun[pid] = t
	return t
}

// Legacy name retained for external callers that reference it; unused by
// the current Analyzing gate. Safe to remove in a follow-up refactor.
const AnalyzingMinSeconds = 0

// ReAnalyzeInterval is how often (in observation cycles) a process
// re-enters the analyzing state to catch behavior changes.
const ReAnalyzeInterval = 500

func CandidateState(c Candidate) string {
	if c.Exited {
		return "exited"
	}
	// Tunneling detection: check if the process has RECENTLY CREATED connections
	// to non-loopback internal targets. "Recently" = first seen within 30 seconds.
	// This detects traffic flowing through a SOCKS tunnel — new internal connections
	// appear when the operator proxies traffic through the compromised host.
	// Tunneling = recently created connections to non-loopback internal targets
	// that are NOT the process's own C2 control channel.
	// Check control-pivot, OR control-channel with ActiveProxying (tunnel shape
	// detected by rank.go — session/beacon actively relaying internal traffic
	// through its C2 channel, e.g. SOCKS proxy through a Cobalt Strike beacon).
	isPivotLike := RoleFamily(c.Role) == "control-pivot"
	isControlChannel := RoleFamily(c.Role) == "control-channel"
	// Tunnel-through-session detection for control-channel and control-pivot
	// (ML model may promote control-channel → control-pivot after rank.go
	// sets ActiveProxying). When ActiveProxying is set, rank.go confirmed
	// tunnel shape this cycle (external C2 + internal connections on multiple
	// ports). Check for RECENTLY CREATED internal connections — each SOCKS
	// proxy request opens a new TCP connection, so active tunneling produces
	// fresh ConnFirstSeen entries. No control-target exclusion: when the
	// session multiplexes tunnel traffic, internal connections ARE the tunnel.
	//
	// Tunneling state is gated strictly on control-* roles. Non-control
	// processes (outbound, listener) that look like they're relaying traffic
	// must first be promoted to a control-* role upstream in rank.go — that
	// way the UI state cleanly reflects the classifier's role taxonomy.
	confirmedTunnel := c.Proc != nil && c.ActiveProxying &&
		(isPivotLike || isControlChannel)
	if confirmedTunnel {
		// ActiveProxying (from rank.go) means the TOPOLOGY indicates a tunnel.
		// But topology alone can be stale — persistent C2 connections stay
		// ESTABLISHED even when no traffic is flowing. Show "tunneling" only
		// when DATA IS ACTUALLY FLOWING through the tunnel right now.
		//
		// "Actually flowing" = one of:
		//   (a) process IO rate > dataFlowThreshold bytes/sec (read OR write)
		//   (b) new internal connection opened within the last 30s (active
		//       relay: SOCKS proxy requests create new TCP connections per
		//       forwarded stream)
		//
		// This distinguishes:
		//   - Active tunnel: proxychains through SSH -D sending bytes, or
		//     beacon's SOCKS proxy relaying traffic → tunneling
		//   - Idle tunnel: SSH session open but no SOCKS requests, or beacon
		//     keeping connections warm but no lateral activity → watch
		const dataFlowThreshold = 512 // bytes/sec — filters TCP keepalives
		now := time.Now()
		pid := c.Proc.Pid

		// (a) active IO rate — bytes per second (read or write)
		ioActive := false
		if c.Proc != nil {
			if c.Proc.IOReadBps >= dataFlowThreshold || c.Proc.IOWriteBps >= dataFlowThreshold {
				ioActive = true
			}
		}

		// (b) recent new internal connection (within 30s)
		connActive := false
		hasInternalConn := false
		for _, cn := range c.Conns {
			if cn.RemoteAddress == "" || IsLoopbackIP(cn.RemoteAddress) || !IsInternalIP(cn.RemoteAddress) {
				continue
			}
			hasInternalConn = true
			key := ConnKey{
				Pid:        pid,
				LocalAddr:  cn.LocalAddress,
				LocalPort:  cn.LocalPort,
				RemoteAddr: cn.RemoteAddress,
				RemotePort: cn.RemotePort,
			}
			if firstSeen, ok := ConnFirstSeen[key]; ok {
				if now.Sub(firstSeen) <= 30*time.Second {
					connActive = true
					break
				}
			} else {
				// First time seeing this connection — new arrival counts as active.
				connActive = true
				break
			}
		}
		// Historical connection churn: ephemeral relay that already closed.
		if !connActive {
			if keys, ok := ConnKeysByPID[pid]; ok {
				for _, key := range keys {
					if IsLoopbackIP(key.RemoteAddr) || !IsInternalIP(key.RemoteAddr) {
						continue
					}
					if firstSeen, ok := ConnFirstSeen[key]; ok {
						if now.Sub(firstSeen) <= 30*time.Second {
							connActive = true
							break
						}
					}
				}
			}
		}

		// Tunnel is "flowing" if IO is active AND at least one internal
		// connection is still present (the relay endpoint), OR if a new
		// internal connection appeared recently (the SOCKS proxy case).
		// STRICT real-time check — no linger. A previously-observed
		// TunnelingSeen timestamp is NOT sufficient: rank.go stamps
		// TunnelingSeen every cycle based on topology alone (control-
		// channel + internal conn + external C2), which would keep
		// tunneling state pinned ON for long-lived control channels even
		// when zero bytes are flowing. tunneling state must reflect
		// "data is moving through the tunnel RIGHT NOW", not "this
		// process has tunnel shape".
		if (ioActive && hasInternalConn) || connActive {
			return "tunneling"
		}
	}
	// Fallback for control-pivot without ActiveProxying:
	// original 30s recency check with control-target exclusion.
	if isPivotLike && !confirmedTunnel && c.Proc != nil {
		now := time.Now()
		pid := c.Proc.Pid

		controlTarget := ""
		if c.ControlChannel != nil {
			controlTarget = c.ControlChannel.RemoteAddress
		}

		isTunneling := false
		for _, cn := range c.Conns {
			if cn.RemoteAddress == "" || IsLoopbackIP(cn.RemoteAddress) || !IsInternalIP(cn.RemoteAddress) {
				continue
			}
			if cn.RemoteAddress == controlTarget {
				continue
			}
			key := ConnKey{
				Pid:        pid,
				LocalAddr:  cn.LocalAddress,
				LocalPort:  cn.LocalPort,
				RemoteAddr: cn.RemoteAddress,
				RemotePort: cn.RemotePort,
			}
			if firstSeen, ok := ConnFirstSeen[key]; ok {
				if now.Sub(firstSeen) <= 30*time.Second {
					isTunneling = true
					break
				}
			} else {
				isTunneling = true
				break
			}
		}

		if !isTunneling {
			if keys, ok := ConnKeysByPID[pid]; ok {
				for _, key := range keys {
					if IsLoopbackIP(key.RemoteAddr) || !IsInternalIP(key.RemoteAddr) {
						continue
					}
					if key.RemoteAddr == controlTarget {
						continue
					}
					if firstSeen, ok := ConnFirstSeen[key]; ok {
						if now.Sub(firstSeen) <= 30*time.Second {
							isTunneling = true
							break
						}
					}
				}
			}
		}

		if isTunneling {
			return "tunneling"
		}
	}
	// Analyzing — dynamic: hold as long as the classifier's role is still
	// flapping (< AnalyzingStableRoleCycles consecutive same-role cycles),
	// AND/OR the wall-clock visibility is below the short ramp minimum.
	// Exits early for confirmed pivots/tunnels. Hard-capped at
	// AnalyzingMaxSeconds so we always commit eventually. The previous
	// "has persisted baseline → never analyze" shortcut is removed — that
	// hid Analyzing from standalone restarts entirely. Now EVERY restart
	// gives the scanner a short analyzing window during which operators
	// see "the classifier is thinking", matching the server-side agent
	// behavior for parity.
	// Analyzing: hold until the role has been stable across
	// AnalyzingStableRoleCycles. If we reached this point we have NOT
	// returned "tunneling" above — that path required observing fresh
	// relay traffic (ioActive + internal conn OR new internal conn).
	// Merely having ActiveProxying + listener topology (confirmedTunnel)
	// doesn't count; pia-daemon, sshd, ssh without active SOCKS
	// forwarding hit confirmedTunnel but fall through. Those must ramp
	// through Analyzing like everything else. The previous guard
	// checking !confirmedTunnel incorrectly skipped Analyzing for that
	// case.
	needsAnalyzing := false
	if c.Proc != nil {
		hist := ProcHistoryByPID[c.Proc.Pid]
		if hist == nil || hist.RoleStableStreak < AnalyzingStableRoleCycles {
			needsAnalyzing = true
		}
		if time.Since(firstSeenInRunFor(c.Proc.Pid)) < AnalyzingMinVisibleSeconds*time.Second {
			needsAnalyzing = true
		}
	}
	if needsAnalyzing {
		frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		frame := frames[int(time.Now().UnixMilli()/120)%len(frames)]
		return frame + " Analyzing..."
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
