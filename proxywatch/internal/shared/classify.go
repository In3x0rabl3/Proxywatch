package shared

import (
	"net"
	"strings"
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
	Target      string      `json:"target"`
	Cycles      int         `json:"cycles"`       // number of present→absent→present transitions
	LastPresent bool        `json:"last_present"`  // was SYN_SENT present in previous sample
	LastSeen    time.Time   `json:"last_seen"`
	FirstSeen   time.Time   `json:"first_seen"`
	Intervals   []float64   `json:"intervals"`     // seconds between cycle starts (rolling window)
}

const (
	SuspicionControl = 1
	SuspicionProxy   = 2
	SuspicionBeacon  = 3
)

var (
	ConnFirstSeen             = make(map[ConnKey]time.Time)
	ConnLastSeen              = make(map[ConnKey]time.Time)
	ConnMissingGrace          = 45 * time.Second
	ReverseControlMinDuration = 5 * time.Second
	SessionMinLabelDuration   = 1 * time.Minute
	TunnelMinLabelDuration    = 1 * time.Minute
	SMBPipeMinLabelDuration   = 1 * time.Minute
	BeaconMinLabelDuration    = 2 * time.Minute
	LongLivedOutboundMinAge   = 60 * time.Second
	ShortLivedOutboundMaxAge  = 10 * time.Second
	ShortLivedBurstWindow     = 30 * time.Second
	SlowScanWindow            = 3 * time.Minute
	BeaconSleepThreshold      = 30 * time.Second
	BeaconMinIntervals        = 2
	LocalTransportWindow      = 30 * time.Second
	PendingControlMinDuration = 15 * time.Second
	PendingControlGapReset    = 45 * time.Second
	PendingControlMinObs      = 3
	RecentClientSeen          = make(map[int]time.Time)
	RecentOutboundSeen        = make(map[int]time.Time)
	RecentInternalScanSeen    = make(map[int]time.Time)
	ShortLivedBurstLast       = make(map[int]time.Time)
	ShortLivedBurstFirst      = make(map[int]time.Time)
	ShortLivedBurstCount      = make(map[int]int)
	ShortLivedBurstInterval   = make(map[int]time.Duration)
	ShortLivedBurstHits       = make(map[int]int)
	ShortLivedIntervals       = make(map[int][]time.Duration)
	InboundBurstLast          = make(map[int]time.Time)
	InboundBurstCount         = make(map[int]int)
	BeaconSeen                = make(map[int]time.Time)
	LocalTransportLast        = make(map[int]time.Time)
	ParentChildFreq           = make(map[string]int)
	RareTupleCount            = make(map[string]int)
	PendingControlByPID       = make(map[int]*PendingControlHistory)
	SYNCycleByPID             = make(map[int]*SYNCycleHistory)
	ActiveWindow              = 10 * time.Second
	SuspicionWindow           = 5 * time.Minute
	HistoryTTL                = 5 * time.Minute
	CleanupInterval           = 30 * time.Second
	ReverseStickyScore        = 90
	ForwardStickyScore        = 70
	ReverseControlBaseScore   = 45
	MinInternalTargetsForRev  = 2
	MinInternalPortsForRev    = 2
	OutboundOnlyExternalCap   = 30
	ShapeDeltaThreshold       = 0.35 // 35% shift triggers shape anomaly
	BeaconJitterCoVMax        = 0.8  // tighter jitter tolerance for callback cadence
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
)

func RolePriority(role string) int {
	switch role {
	case "tunnel":
		return 100
	case "smb-pipe":
		return 95
	case "session":
		return 90
	case "beacon":
		return 86
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
	case "session", "beacon", "tunnel", "smb-pipe", "listen", "outbound":
		return role
	default:
		return "other"
	}
}

// MITRETechniques returns the ATT&CK technique IDs associated with a role.
func MITRETechniques(role string) []string {
	switch role {
	case "session":
		return []string{"T1071", "T1090", "T1573"}
	case "beacon":
		return []string{"T1071", "T1571", "T1008"}
	case "tunnel":
		return []string{"T1572", "T1090", "T1573"}
	case "smb-pipe":
		return []string{"T1572", "T1021.002", "T1570"}
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
	case "tunnel", "smb-pipe":
		return []string{"Command and Control", "Lateral Movement"}
	case "session":
		return []string{"Command and Control"}
	case "beacon":
		return []string{"Command and Control"}
	case "listen":
		return []string{"Command and Control", "Persistence"}
	case "outbound":
		return []string{"Command and Control"}
	default:
		return nil
	}
}

func IsControlChannelRole(role string) bool {
	switch role {
	case "session", "beacon", "tunnel", "smb-pipe":
		return true
	default:
		return false
	}
}

// CandidateLess defines a consistent ordering for candidates.
func CandidateLess(a, b Candidate) bool {
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
	case "tunnel", "smb-pipe":
		return 5
	case "session":
		return 4
	case "beacon":
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
		"session",
		"beacon",
		"tunnel",
		"smb-pipe",
		"listen",
		"outbound",
	}

	roleGroups := map[string][]string{
		"recommended": {"session", "beacon", "tunnel", "smb-pipe"},
		"all":         allRoles,
		"session":     {"session"},
		"beacon":      {"beacon"},
		"tunnel":      {"tunnel", "smb-pipe"},
		"listen":      {"listen"},
		"outbound":    {"outbound"},
		// Legacy aliases.
		"control":  {"session", "beacon", "tunnel", "smb-pipe"},
		"command":  {"session", "beacon"},
		"network":  {"listen", "outbound"},
		"listener": {"listen"},
		"reverse":  {"session", "tunnel"},
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

func UDPScopeCounts(list []UDPListenerInfo) (internal, external, loopback int) {
	for _, u := range list {
		switch {
		case IsLoopbackIP(u.LocalAddress):
			loopback++
		case IsInternalIP(u.LocalAddress):
			internal++
		default:
			external++
		}
	}
	return
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
