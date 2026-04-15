package shared

import (
	"net"
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
	Generation int `json:"generation"` // model generation when observations started
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

// ClassifyMu protects all global classifier state maps from concurrent access.
// The background refresh goroutine runs ScoreCandidate in parallel with the
// main UI loop, and both read/write these maps.
var ClassifyMu sync.Mutex

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
	PivotUntil                  = make(map[int]time.Time) // PID → expiry; while now < expiry, role is forced to control-pivot (SOCKS-forwarding linger)
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

// ConnCountTracker records recent outbound connection counts for oscillation detection.
type ConnCountTracker struct {
	Samples    []int // recent outTotal values (ring buffer)
	WriteIdx   int
	LastUpdate time.Time
}

func RolePriority(role string) int {
	switch role {
	case "control-pivot":
		return 100
	case "control-channel":
		return 90
	case "listener", "listen":
		return 60
	case "outbound":
		return 20
	// Legacy aliases — map to equivalent new role priority.
	case "control-tunnel", "tunnel":
		return 100 // → control-pivot
	case "control-session", "control-beacon", "smb-pipe":
		return 90
	case "analyzing":
		return 20 // → outbound (analyzing removed)
	default:
		return 0
	}
}

func RoleFamily(role string) string {
	switch role {
	case "control-channel", "control-pivot":
		return role
	case "listener", "listen":
		return "listener"
	case "outbound":
		return "outbound"
	// Legacy aliases — map old internal roles to new taxonomy.
	case "control-session", "control-beacon":
		return "control-channel"
	case "control-tunnel", "tunnel":
		return "control-pivot"
	case "smb-pipe":
		return "control-pivot"
	case "analyzing":
		return "outbound"
	default:
		return "other"
	}
}

func IsControlRole(role string) bool {
	switch RoleFamily(role) {
	case "control-channel", "control-pivot":
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
	case "control-pivot":
		return 5
	case "control-channel":
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
		"control-channel",
		"control-pivot",
		"listener",
		"outbound",
	}

	roleGroups := map[string][]string{
		"recommended":     {"control-channel", "control-pivot"},
		"all":             allRoles,
		"control-channel": {"control-channel"},
		"control-pivot":   {"control-pivot"},
		"listener":        {"listener"},
		"outbound":        {"outbound"},
		// Legacy aliases.
		"control-session": {"control-channel"},
		"control-beacon":  {"control-channel"},
		"control-tunnel":  {"control-pivot"},
		"session":         {"control-channel"},
		"beacon":          {"control-channel"},
		"tunnel":          {"control-pivot"},
		"smb-pipe":        {"control-pivot"},
		"listen":          {"listener"},
		"analyzing":       {"outbound"},
		"control":         {"control-channel", "control-pivot"},
		"command":         {"control-channel"},
		"network":         {"listener", "outbound"},
		"reverse":         {"control-channel"},
		"pivot":           {"control-pivot"},
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
