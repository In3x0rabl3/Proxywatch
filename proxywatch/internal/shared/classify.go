package shared

import "time"

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
	BeaconJitterCoVMax        = 1.5  // tolerate broad jitter for callback cadence
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
	case "reverse-transport":
		return 100
	case "reverse-proxy":
		return 96
	case "smb-pipe":
		return 95
	case "susp-tun":
		return 94
	case "reverse-tunnel":
		return 92
	case "reverse-control":
		return 90
	case "susp-session":
		return 88
	case "susp-beacon":
		return 86
	case "proxy-listener":
		return 60
	case "listener-with-clients":
		return 55
	case "listener-with-outbound":
		return 50
	case "listener-only":
		return 45
	case "outbound-only":
		return 20
	default:
		return 0
	}
}

func RoleFamily(role string) string {
	switch role {
	case "smb-pipe", "reverse-transport", "reverse-proxy", "reverse-tunnel", "susp-tun":
		return "tunnel"
	case "reverse-control", "susp-session":
		return "session"
	case "susp-beacon":
		return "beacon"
	case "proxy-listener", "listener-with-clients", "listener-with-outbound", "listener-only":
		return "listener"
	case "outbound-only":
		return "outbound"
	default:
		return "other"
	}
}

func IsControlChannelRole(role string) bool {
	switch role {
	case "reverse-control", "reverse-transport", "smb-pipe", "susp-tun", "susp-session", "susp-beacon":
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
	switch RoleFamily(role) {
	case "tunnel":
		return 4
	case "session":
		return 3
	case "beacon":
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
