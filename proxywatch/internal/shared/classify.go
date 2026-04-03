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
}

type ProcessBehavior struct {
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
	case "control-tunnel":
		return 100
	case "control-pivot":
		return 95
	case "control-session", "control-beacon":
		return 90
	case "analyzing":
		return 70
	case "listen":
		return 60
	case "outbound":
		return 20
	default:
		return 0
	}
}

func RoleFamily(role string) string {
	switch role {
	case "control-session", "control-beacon", "control-pivot", "control-tunnel", "listen", "outbound", "analyzing":
		return role
	// Legacy aliases.
	case "control-channel":
		return "control-session"
	case "tunnel":
		return "control-tunnel"
	case "smb-pipe":
		return "control-pivot"
	default:
		return "other"
	}
}

// MITRETechniques returns the ATT&CK technique IDs associated with a role.
func MITRETechniques(role string) []string {
	switch role {
	case "control-session", "control-beacon":
		return []string{"T1071", "T1090", "T1573"}
	case "control-tunnel":
		return []string{"T1572", "T1090", "T1573"}
	case "control-pivot":
		return []string{"T1572", "T1021.002", "T1570", "T1090"}
	case "listen":
		return []string{"T1090", "T1571"}
	case "outbound":
		return []string{"T1071"}
	default:
		return nil
	}
}

// MITRETactics returns the ATT&CK tactic names associated with a role family.
func MITRETactics(role string) []string {
	switch role {
	case "control-tunnel", "control-pivot":
		return []string{"Command and Control", "Lateral Movement"}
	case "control-session", "control-beacon":
		return []string{"Command and Control"}
	case "listen":
		return []string{"Command and Control", "Persistence"}
	case "outbound":
		return []string{"Command and Control"}
	default:
		return nil
	}
}

func IsControlRole(role string) bool {
	switch role {
	case "control-session", "control-beacon", "control-channel", "control-tunnel", "control-pivot", "analyzing":
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
	switch role {
	case "control-tunnel", "control-pivot":
		return 5
	case "control-session", "control-beacon":
		return 4
	case "analyzing":
		return 3
	case "listen":
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
		"control-session",
		"control-beacon",
		"control-pivot",
		"control-tunnel",
		"analyzing",
		"listen",
		"outbound",
	}

	roleGroups := map[string][]string{
		"recommended":     {"control-session", "control-beacon", "control-pivot", "control-tunnel", "analyzing"},
		"all":             allRoles,
		"control-session": {"control-session"},
		"control-beacon":  {"control-beacon"},
		"control-pivot":   {"control-pivot"},
		"control-tunnel":  {"control-tunnel"},
		"listen":          {"listen"},
		"outbound":        {"outbound"},
		// Legacy aliases.
		"control-channel": {"control-session", "control-beacon"},
		"session":         {"control-session"},
		"beacon":          {"control-beacon"},
		"tunnel":          {"control-tunnel", "control-pivot"},
		"smb-pipe":        {"control-pivot"},
		"control":         {"control-session", "control-beacon", "control-tunnel", "control-pivot"},
		"command":         {"control-session", "control-beacon"},
		"network":         {"listen", "outbound"},
		"reverse":         {"control-session", "control-beacon", "control-tunnel"},
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
