package shared

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ClassifyOptions struct {
	MinScore    int
	RoleFilter  map[string]bool
	Incremental bool
	HostScope   string
}

type CandidateSignature struct {
	ListenerHash uint64
	ConnHash     uint64
	ProcHash     uint64
}

type ClassifierCache struct {
	Candidates map[int]Candidate
	Signatures map[int]CandidateSignature
}

type ClassifyFunc func(*Snapshot, ClassifyOptions, *ClassifierCache) []Candidate

type ConnKey struct {
	Pid        int
	LocalAddr  string
	LocalPort  int
	RemoteAddr string
	RemotePort int
}

type ProcHistory struct {
	LastSeen        time.Time
	LastActive      time.Time
	LastSuspicious  time.Time
	LastScoreEval   time.Time
	SuspicionKind   int
	StickyScore     int
	DisplayStreak   int
	LastDisplayEval time.Time
	LastOutRatio    float64
	LastInRatio     float64
	LastRole        string
	LastRoleChange  time.Time
	LastLoopRatio   float64
	ShapeSamples    int
	MemSamples      []uint64 // rolling window of working set values (max 20)

	// RoleStableStreak: consecutive scan cycles the role has been the same.
	// Used by CandidateState to exit Analyzing dynamically — once the role
	// has stabilized across N cycles, the process is "known enough" to
	// commit a display role instead of showing Analyzing.
	//
	// NOT persisted (json:"-"): the streak is intentionally session-scoped
	// so every scanner restart gives operators a visible Analyzing ramp,
	// even for long-running processes with lots of historical data.
	RoleStableStreak int `json:"-"`
}

// ModelGeneration increments every time the model is reset.
// Processes with a stale generation re-enter analyzing state.
var ModelGeneration int

type ProcessBehavior struct {
	Generation             int            `json:"generation"` // model generation when observations started
	LastSeen               time.Time      `json:"last_seen"`
	Observations           int            `json:"observations"`
	SuspiciousObservations int            `json:"suspicious_observations"`
	StrongObservations     int            `json:"strong_observations"`
	ActiveObservations     int            `json:"active_observations"`
	AvgOutExternal         float64        `json:"avg_out_external"`
	AvgOutInternal         float64        `json:"avg_out_internal"`
	AvgDistinctTargets     float64        `json:"avg_distinct_targets"`
	AvgControlSeconds      float64        `json:"avg_control_seconds"`
	KnownPrefixes          map[string]int `json:"known_prefixes,omitempty"`
	LastRoles              map[string]int `json:"last_roles,omitempty"`
	LastUpdated            time.Time      `json:"last_updated"`
}

type PendingControlHistory struct {
	Target       string    `json:"target"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	Observations int       `json:"observations"`
}

// SYNCycleHistory tracks SYN_SENT appearance/disappearance cycles to detect
// beacon-like callback patterns even when the C2 server is down and
// connections never reach ESTABLISHED state.
type SYNCycleHistory struct {
	Target      string    `json:"target"`
	Cycles      int       `json:"cycles"`       // number of present→absent→present transitions
	LastPresent bool      `json:"last_present"` // was SYN_SENT present in previous sample
	LastSeen    time.Time `json:"last_seen"`
	FirstSeen   time.Time `json:"first_seen"`
	Intervals   []float64 `json:"intervals"` // seconds between cycle starts (rolling window)
}

const (
	SuspicionControl = 1
	SuspicionProxy   = 2
	SuspicionBeacon  = 3
)

// ClassifyMu protects all global classifier state maps from concurrent
// access. The background refresh goroutine writes these maps from inside
// detection.Classify; the UI render thread reads them via CandidateState
// to derive per-candidate display state. Without this lock the runtime
// panics with "fatal error: concurrent map writes" or "concurrent map
// iteration and map write" at unpredictable times — observed live as
// the random-timing crash on the Windows TUI.
//
// Writers (Classify and AggregateLingerChildEvidence) take the
// exclusive Lock(). UI readers take the shared RLock() so multiple
// render passes can run concurrently while the writer is idle.
var ClassifyMu sync.RWMutex

var (
	ConnFirstSeen               = make(map[ConnKey]time.Time)
	ConnLastSeen                = make(map[ConnKey]time.Time)
	ConnKeysByPID               = make(map[int][]ConnKey) // reverse index for fast cleanup
	ConnMissingGrace            = 45 * time.Second
	ReverseControlMinDuration   = 30 * time.Second
	SessionMinLabelDuration     = 60 * time.Second
	TunnelMinLabelDuration      = 45 * time.Second
	PivotMinLabelDuration       = 45 * time.Second
	SMBPipeMinLabelDuration     = 45 * time.Second
	BeaconMinLabelDuration      = 90 * time.Second
	LongLivedOutboundMinAge     = 90 * time.Second
	ShortLivedOutboundMaxAge    = 10 * time.Second
	ShortLivedBurstWindow       = 45 * time.Second
	SlowScanWindow              = 2 * time.Hour
	BeaconSleepThreshold        = 30 * time.Second
	BeaconMinIntervals          = 3
	LocalTransportWindow        = 30 * time.Second
	PendingControlMinDuration   = 15 * time.Second
	PendingControlGapReset      = 45 * time.Second
	PendingControlMinObs        = 3
	RecentClientSeen            = make(map[int]time.Time)
	RecentOutboundSeen          = make(map[int]time.Time)
	RecentInternalScanSeen      = make(map[int]time.Time)
	ShortLivedBurstLast         = make(map[int]time.Time)
	ShortLivedBurstFirst        = make(map[int]time.Time)
	ShortLivedBurstCount        = make(map[int]int)
	ShortLivedBurstInterval     = make(map[int]time.Duration)
	ShortLivedBurstHits         = make(map[int]int)
	ShortLivedIntervals         = make(map[int][]time.Duration)
	InboundBurstLast            = make(map[int]time.Time)
	InboundBurstCount           = make(map[int]int)
	BeaconSeen                  = make(map[int]time.Time)
	TunnelingSeen               = make(map[int]time.Time)
	TunnelActivitySeen          = make(map[int]time.Time) // short-lived: tracks recent tunnel IO for state display
	PivotInternalSeen           = make(map[int]time.Time) // tracks recent pivot-non-loopback-internal signal for temporal pivot escalation
	PivotUntil                  = make(map[int]time.Time) // PID → expiry; while now < expiry, role is forced to pivot (SOCKS-forwarding linger)
	SMBPipeSeen                 = make(map[int]time.Time)
	LocalTransportLast          = make(map[int]time.Time)
	ParentChildFreq             = make(map[string]int)
	RareTupleCount              = make(map[string]int)
	PendingControlByPID         = make(map[int]*PendingControlHistory)
	SYNCycleByPID               = make(map[int]*SYNCycleHistory)
	RoleChangeCooldown          = 10 * time.Second
	MaliciousRoleDemoteCooldown = 5 * time.Minute
	ActiveWindow                = 10 * time.Second
	SuspicionWindow             = 10 * time.Minute
	HistoryTTL                  = 2 * time.Hour
	CleanupInterval             = 5 * time.Minute
	ReverseStickyScore          = 100
	ForwardStickyScore          = 80
	ReverseControlBaseScore     = 45
	MinInternalTargetsForRev    = 2
	MinInternalPortsForRev      = 2
	OutboundOnlyExternalCap     = 30
	AnalyzingMinObservations    = 5    // hold malicious roles in "analyzing" until this many scan cycles
	ShapeDeltaThreshold         = 0.35 // 35% shift triggers shape anomaly
	BeaconJitterCoVMax          = 0.5  // beacon jitter tolerance (50% CoV — real beacons are periodic)
	// How far to demote traffic that matches verified destinations without strong evidence in the UI ranking.
	TrafficVerifiedPenalty = 80
	// Minimum external target prefix diversity to treat traffic as verified on benign ports.
	VerifiedExternalMinPrefixes      = 5
	ObservedExternalPortProcessCount = make(map[int]int)
	ObservedExternalPortPrefixCount  = make(map[int]int)
	ObservedExternalPortConnCount    = make(map[int]int)
	ProcHistoryByPID                 = make(map[int]*ProcHistory)
	ProcessBehaviorByKey             = make(map[string]*ProcessBehavior)
	LastHistoryCleanup               time.Time

	// Temporal tracking for advanced behavioral signals.
	// IOBurstHistory tracks recent IO rates per PID for sleep-then-burst detection.
	IOBurstHistory = make(map[int]*IOBurstTracker)
	// ConnCountHistory tracks recent connection counts per PID for oscillation detection.
	ConnCountHistory = make(map[int]*ConnCountTracker)

	// ProxywatchStartedAt is set when proxywatch initializes. Used to gate the
	// "process first observed with pre-existing connections" detection — when
	// proxywatch itself just started (e.g., after a state reset or service
	// restart), every existing process appears as "first observed", which
	// would otherwise trigger the pre-existing-tunnel boost on every running
	// process. The boost is only applied for processes that appear AFTER
	// proxywatch has been observing the system for at least StartupGracePeriod.
	ProxywatchStartedAt = time.Now()
	StartupGracePeriod  = 60 * time.Second
)

// IOBurstTracker records recent IO rates to detect sleep→burst patterns.
type IOBurstTracker struct {
	Samples    []uint64 // recent total BPS samples (ring buffer)
	WriteIdx   int
	LastUpdate time.Time
	ZeroRuns   int // consecutive samples with 0 IO
	BurstRuns  int // consecutive samples with high IO
}

// DestFirstSeen tracks the first time each (LocalIP|/24-prefix|port)
// destination cluster was observed in this proxywatch instance's
// history. Stable across restarts (persisted in classifier-memory.json
// alongside ConnFirstSeen) — unlike ConnFirstSeen which is keyed on
// the per-process PID and gets invalidated on every restart.
//
// Used by the first-seen scoring rule: a brand-new destination from a
// host (≤7d) is corroborating evidence for malice;
// an established destination (≥30d) is a suppression signal pointing
// toward benign vendor traffic.
//
// Key format: "<localIP>|<TargetPrefix(remoteIP)>|<remotePort>"
// (the TargetPrefix is /24 for IPv4, /48 for IPv6).
var DestFirstSeen = make(map[string]time.Time)

// DestFirstSeenKey builds the canonical key for a destination cluster.
func DestFirstSeenKey(localIP, remoteIP string, remotePort int) string {
	prefix := TargetPrefix(remoteIP)
	if prefix == "" {
		prefix = remoteIP
	}
	return localIP + "|" + prefix + "|" + strconv.Itoa(remotePort)
}

// RecordDestFirstSeen stamps `now` as the first-seen for the cluster
// IF no entry exists. Idempotent — once set, never advanced (we want
// the EARLIEST observation across the lifetime of the agent).
// Caller must hold ClassifyMu.
func RecordDestFirstSeen(localIP, remoteIP string, remotePort int, now time.Time) {
	key := DestFirstSeenKey(localIP, remoteIP, remotePort)
	if _, ok := DestFirstSeen[key]; !ok {
		DestFirstSeen[key] = now
	}
}

// LookupDestFirstSeen returns the first-seen time for a destination
// cluster, or zero time if not previously observed.
// Caller must hold ClassifyMu (read).
func LookupDestFirstSeen(localIP, remoteIP string, remotePort int) time.Time {
	return DestFirstSeen[DestFirstSeenKey(localIP, remoteIP, remotePort)]
}

// ConnCountTracker records recent outbound connection counts for oscillation detection.
type ConnCountTracker struct {
	Samples    []int // recent outTotal values (ring buffer)
	WriteIdx   int
	LastUpdate time.Time
}

// LongConnDurationScore returns a 0-1 score for a connection's
// duration in seconds. Bracketed scoring:
//
//	  < 1h        → 0   (not long enough to be a "long connection")
//	1h–4h         → 0.4 (low)
//	4h–8h         → 0.4–0.6 (linear interpolation, medium-low → medium)
//	8h–12h        → 0.6–0.8 (medium → high, capped at 12h)
//	≥ 12h         → 0.8 (high — sustained operator-class persistence)
//
// Expressed as a continuous score rather than four discrete impact
// bands. Above 0.4 emit `session-long-connection`; above 0.6 the
// signal is considered decisive in pcap mode.
func LongConnDurationScore(seconds float64) float64 {
	switch {
	case seconds < 3600: // < 1h
		return 0
	case seconds < 14400: // 1h–4h
		return 0.4
	case seconds < 28800: // 4h–8h
		return 0.4 + 0.2*(seconds-14400)/14400
	case seconds < 43200: // 8h–12h
		return 0.6 + 0.2*(seconds-28800)/14400
	default: // ≥ 12h
		return 0.8
	}
}

func RolePriority(role string) int {
	switch role {
	case "pivot", "tunnel", "smb-pipe":
		return 100
	case "beacon":
		return 90
	case "listener", "listen":
		return 60
	case "outbound", "analyzing":
		return 20
	default:
		return 0
	}
}

func RoleFamily(role string) string {
	switch role {
	case "beacon":
		return "beacon"
	case "pivot", "tunnel", "smb-pipe":
		return "pivot"
	case "listener", "listen":
		return "listener"
	case "outbound", "analyzing":
		return "outbound"
	default:
		return "other"
	}
}

func IsControlRole(role string) bool {
	switch RoleFamily(role) {
	case "beacon", "pivot":
		return true
	default:
		return false
	}
}

// CandidateLess defines a consistent ordering for candidates.
func CandidateLess(a, b Candidate) bool {
	// Exited processes always sort below live ones.
	if a.Exited != b.Exited {
		return !a.Exited && b.Exited
	}

	famA := roleFamilyPriority(a.Role)
	famB := roleFamilyPriority(b.Role)
	if famA != famB {
		return famA > famB
	}

	priA := candidatePriority(a)
	priB := candidatePriority(b)
	if priA != priB {
		return priA > priB
	}
	if a.ActiveProxying != b.ActiveProxying {
		return a.ActiveProxying && !b.ActiveProxying
	}
	if a.OutInternal != b.OutInternal {
		return a.OutInternal > b.OutInternal
	}
	if a.OutTotal != b.OutTotal {
		return a.OutTotal > b.OutTotal
	}
	if a.Score == b.Score && a.Proc != nil && b.Proc != nil {
		return a.Proc.Pid < b.Proc.Pid
	}
	return a.Score > b.Score
}

func roleFamilyPriority(role string) int {
	switch RoleFamily(role) {
	case "pivot":
		return 5
	case "beacon":
		return 4
	case "listener":
		return 2
	default:
		return 1
	}
}

func candidatePriority(c Candidate) int {
	pri := RolePriority(c.Role)
	if c.TrafficVerified && !c.StrongEvidence {
		pri -= TrafficVerifiedPenalty
	}
	return pri
}

// --- role filters (merged from role_filters.go) ---

func ParseRoleFilter(s string) map[string]bool {
	allRoles := []string{
		"beacon",
		"pivot",
		"listener",
		"outbound",
	}

	roleGroups := map[string][]string{
		"recommended": {"beacon", "pivot"},
		"all":         allRoles,
		"beacon":      {"beacon"},
		"pivot":       {"pivot"},
		"listener":    {"listener"},
		"outbound":    {"outbound"},
		// Legacy aliases.
		"session":   {"beacon"},
		"tunnel":    {"pivot"},
		"smb-pipe":  {"pivot"},
		"listen":    {"listener"},
		"analyzing": {"outbound"},
		"control":   {"beacon", "pivot"},
		"command":   {"beacon"},
		"network":   {"listener", "outbound"},
		"reverse":   {"beacon"},
	}

	out := make(map[string]bool)
	s = strings.TrimSpace(s)
	if s == "" {
		return out
	}
	for _, r := range strings.Split(s, ",") {
		r = strings.TrimSpace(r)
		if r != "" {
			if expanded, ok := roleGroups[strings.ToLower(r)]; ok {
				for _, er := range expanded {
					out[er] = true
				}
				continue
			}
			out[r] = true
		}
	}
	return out
}

func RoleMatchesFilter(role string, roleFilter map[string]bool) bool {
	if len(roleFilter) == 0 {
		return true
	}
	if roleFilter[role] {
		return true
	}
	return roleFilter[RoleFamily(role)]
}

// --- network scope (merged from network_scope.go) ---

func IsInternalIP(ip string) bool {
	netIP := parseIP(ip)
	if netIP == nil {
		return false
	}
	if netIP.IsLoopback() || netIP.IsPrivate() {
		return true
	}
	if netIP.IsLinkLocalUnicast() || netIP.IsLinkLocalMulticast() {
		return true
	}
	return netIP.IsInterfaceLocalMulticast()
}

func IsLoopbackIP(ip string) bool {
	parsed := parseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback()
}

func IsWildcardIP(ip string) bool {
	return ip == "0.0.0.0" || ip == "::"
}

func ScopeLabelForLocalAddress(addr string) string {
	switch {
	case IsWildcardIP(addr):
		return "any"
	case IsLoopbackIP(addr):
		return "loopback"
	case IsInternalIP(addr):
		return "internal"
	default:
		return "external"
	}
}

func parseIP(raw string) net.IP {
	ip := strings.TrimSpace(raw)
	if ip == "" {
		return nil
	}
	if zone := strings.IndexByte(ip, '%'); zone > 0 {
		ip = ip[:zone]
	}
	return net.ParseIP(ip)
}
