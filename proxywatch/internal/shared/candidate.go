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
	SeenSeconds  int
	Exited       bool // process no longer running (lingered entry)

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

	// Authenticode details populated by the Windows signature verifier.
	// Publisher is the signer CN extracted from the signing cert.
	// AuthenticodeOCSPSeen is true when the verdict came from a full
	// WinVerifyTrust + OCSP round-trip (not just a cached verdict from a
	// prior run). Used by the FP-shape evaluator to distinguish "fully
	// verified" from "presumed via cache".
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
	PkgOwned            bool
	PkgOwnerName        string
	PublisherDNSAligned bool
	OnlineEvidence      []string
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

// AppendUniqueSignal appends s to slice only if it isn't already present.
// Used by every code path that stamps signals onto a candidate so the
// SignalStats denominator doesn't inflate from duplicate stamps across
// post-passes (rule-engine, linger, child-tunnel aggregation, etc.).
// Operator-confirmed 2026-05-04: the PCAP detail SIGNALS list was
// showing duplicates (e.g. session-exfil-write-heavy twice) because
// scoring/rank.go, scoring/child_tunnel.go, and shared/linger.go each
// did plain append without checking.
func AppendUniqueSignal(slice []string, s string) []string {
	for _, x := range slice {
		if x == s {
			return slice
		}
	}
	return append(slice, s)
}

// DedupStrings returns slice with duplicates removed, preserving the
// order of first occurrence. Defensive boundary helper for the JSON
// snapshot + TUI render paths: even if some upstream emitter forgets
// to use AppendUniqueSignal, the user-visible state still shows each
// signal/reason exactly once. Returns nil for nil input so callers can
// distinguish "absent" from "explicitly empty" if they care.
func DedupStrings(slice []string) []string {
	if len(slice) == 0 {
		return slice
	}
	seen := make(map[string]struct{}, len(slice))
	out := make([]string, 0, len(slice))
	for _, s := range slice {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
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
//
//	(time since firstSeenInRun >= AnalyzingMinVisibleSeconds)
//
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
	pidFirstSeenMu    sync.Mutex
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

// CandidateState returns the operator-facing per-candidate state
// ("tunneling" / "analyzing" / "watch" / "exited"). Reads several
// global classifier maps (PivotUntil, ConnFirstSeen, ConnKeysByPID,
// ProcHistoryByPID); takes ClassifyMu.RLock() so it never races the
// background refresh goroutine that writes those maps from inside
// detection.Classify.
//
// Callers that already hold ClassifyMu (e.g. detection/output's
// EmitDetectionOutputs path, which is invoked from inside Classify
// while the exclusive Lock is held) MUST use CandidateStateUnsafe
// instead — RWMutex is not reentrant, and re-entering RLock from a
// goroutine that holds Lock deadlocks.
func CandidateState(c Candidate) string {
	ClassifyMu.RLock()
	defer ClassifyMu.RUnlock()
	return candidateStateLocked(c)
}

// CandidateStateUnsafe is the lock-free body of CandidateState.
// Caller MUST hold ClassifyMu (Lock or RLock). Used by
// detection/output's emit path, which runs from inside Classify
// where the exclusive Lock is already held.
func CandidateStateUnsafe(c Candidate) string {
	return candidateStateLocked(c)
}

func candidateStateLocked(c Candidate) string {
	if c.Exited {
		return "exited"
	}
	// Tunneling detection: check if the process has RECENTLY CREATED connections
	// to non-loopback internal targets. "Recently" = first seen within 30 seconds.
	// This detects traffic flowing through a SOCKS tunnel — new internal connections
	// appear when the operator proxies traffic through the compromised host.
	// Tunneling = recently created connections to non-loopback internal targets
	// that are NOT the process's own C2 control channel.
	// Check pivot, OR beacon with ActiveProxying (tunnel shape
	// detected by rank.go — session/beacon actively relaying internal traffic
	// through its C2 channel, e.g. SOCKS proxy through a Cobalt Strike beacon).
	isPivotLike := RoleFamily(c.Role) == "pivot"
	isControlChannel := RoleFamily(c.Role) == "beacon"
	// Pcap-mode tunneling shortcut. Synthetic candidates don't have
	// Conns populated (the cluster aggregates raw flows, not per-PID
	// socket lists), so the live ConnFirstSeen / ActiveProxying gate
	// below never fires. Use byte-rate evidence directly: IOReadBps +
	// IOWriteBps ≥ 512 B/s means data is actively flowing through the
	// cluster in the current ingest window.
	//
	// We deliberately do NOT fall back to "cumulative bytes > 0" here.
	// That fallback (removed 2026-05-03) made any cluster that had EVER
	// moved a byte stay pinned to "tunneling" forever — cheerful_glove
	// stayed "tunneling" with 0 B/s rate and only a CLOSE_WAIT internal
	// connection. If tail-mode bps reads 0 between beacon arrivals, the
	// state correctly shows "watch"/"monitoring" until the next beacon
	// — that matches the user expectation "tunneling = relay active
	// right now", not "this cluster carried bytes at some point".
	if c.Proc != nil && IsPcapMode(&c) && (isPivotLike || isControlChannel) {
		const dataFlowThreshold uint64 = 512
		if c.Proc.IOReadBps+c.Proc.IOWriteBps >= dataFlowThreshold {
			return "tunneling"
		}
	}
	// Tunnel-through-session detection for beacon and pivot
	// (ML model may promote beacon → pivot after rank.go
	// sets ActiveProxying). When ActiveProxying is set, rank.go confirmed
	// tunnel shape this cycle (external C2 + internal connections on multiple
	// ports). Check for RECENTLY CREATED internal connections — each SOCKS
	// proxy request opens a new TCP connection, so active tunneling produces
	// fresh ConnFirstSeen entries. No beacon-target exclusion: when the
	// session multiplexes tunnel traffic, internal connections ARE the tunnel.
	//
	// Tunneling state is gated strictly on beacon-* roles. Non-control
	// processes (outbound, listener) that look like they're relaying traffic
	// must first be promoted to a beacon-* role upstream in rank.go — that
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

		// (b) recent new OUTBOUND internal connection (within 30s)
		//
		// Tunnel traffic flows FROM the beacon/pivot OUTBOUND to internal
		// targets — the proxied requests create outbound connections.
		// INBOUND connections (e.g., SMB/WMI to SYSTEM) do not indicate
		// active tunneling. Gate on OutInternal > 0 to exclude processes
		// that only RECEIVE internal connections from triggering ACTIVE.
		//
		// The connActive 30s recency check below catches truly-recent
		// relay even if it has just closed.
		connActive := false
		if c.OutInternal > 0 {
			for _, cn := range c.Conns {
				if cn.RemoteAddress == "" || IsLoopbackIP(cn.RemoteAddress) || !IsInternalIP(cn.RemoteAddress) {
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
						connActive = true
						break
					}
				}
				// Removed: "else → new arrival counts as active"
				// Unknown connections (not in ConnFirstSeen) are NOT treated as new.
				// This prevents idle persistent connections from triggering ACTIVE
				// just because tracking started recently or missed them earlier.
			}
		}
		// Historical connection churn: ephemeral relay that already closed.
		// Same OutInternal gate: only consider historical outbound connections.
		if !connActive && c.OutInternal > 0 {
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

		// Tunnel is "flowing" when EITHER of:
		//   (a) IO rate is above the keepalive threshold (data pumping)
		//   (b) a new internal connection appeared within 30s (active SOCKS relay)
		//
		// Removed: "(c) at least one established internal connection still exists"
		// — that condition was too broad. Persistent internal connections (e.g.
		// RPC, WMI, SMB shares) do NOT indicate active tunneling. ACTIVE status
		// should only appear when data is FLOWING through the tunnel (ioActive)
		// or when the tunnel is actively opening new relay connections (connActive).
		// Without ioActive or connActive, even an "established" internal conn is
		// just idle state, not "tunneling right now."
		//
		// PivotUntil linger (60s) keeps the ROLE as pivot but does NOT
		// keep the STATUS as "tunneling" — the intent documented in
		// child_tunnel.go is "tunneling state must drop to 'watch' the
		// moment data stops flowing." The linger window preserves the
		// pivot classification during transient gaps (between scan probes)
		// but actual tunneling status requires current data flow evidence.
		if ioActive || connActive {
			return "tunneling"
		}
	}
	// Fallback for pivot without ActiveProxying:
	// original 30s recency check with beacon-target exclusion.
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
		// Stable enum value. The TUI applies its spinner glyph at render
		// time via CandidateStateDisplay; the JSON API gets a clean
		// "analyzing" so consumers (operator scripts, dashboards,
		// downstream pipelines) can string-match without dealing with
		// rotating Unicode braille frames in the state field — that
		// leak was visible in /metrics output as e.g. "⠧ Analyzing..."
		// on 2026-04-28.
		return "analyzing"
	}
	return "watch"
}

// CandidateStateDisplay returns the operator-facing rendering of state,
// using military-style terminology. JSON / API / metrics MUST use
// CandidateState (the stable enum) instead.
func CandidateStateDisplay(c Candidate) string {
	state := CandidateState(c)
	role := RoleFamily(c.Role)

	switch state {
	case "analyzing":
		frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		frame := frames[int(time.Now().UnixMilli()/120)%len(frames)]
		return frame + " TRACKING"
	case "tunneling":
		return "◉ ACTIVE"
	case "exited":
		return "○ COLD"
	case "watch":
		// Role-based status for watch state
		switch role {
		case "beacon":
			return "◎ ALERT"
		case "pivot":
			return "◎ ALERT"
		case "tunnel":
			return "◎ ALERT"
		default:
			return "● NOMINAL"
		}
	default:
		return "● NOMINAL"
	}
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
