package shared

import "time"

type ConnKey struct {
	Pid        int
	LocalAddr  string
	LocalPort  int
	RemoteAddr string
	RemotePort int
}

type ProcHistory struct {
	LastSeen       time.Time
	LastActive     time.Time
	LastSuspicious time.Time
	SuspicionKind  int
	StickyScore    int
	LastOutRatio   float64
	LastInRatio    float64
	LastLoopRatio  float64
	ShapeSamples   int
}

const (
	SuspicionNone = iota
	SuspicionControl
	SuspicionProxy
)

var (
	ConnFirstSeen             = make(map[ConnKey]time.Time)
	ReverseControlMinDuration = 10 * time.Second
	LongLivedOutboundMinAge   = 60 * time.Second
	ShortLivedOutboundMaxAge  = 10 * time.Second
	ShortLivedBurstWindow     = 30 * time.Second
	SlowScanWindow            = 3 * time.Minute
	BeaconSleepThreshold      = 60 * time.Second
	BeaconMinIntervals        = 2
	LocalTransportWindow      = 30 * time.Second
	RecentClientSeen          = make(map[int]time.Time)
	RecentOutboundSeen        = make(map[int]time.Time)
	RecentInternalScanSeen    = make(map[int]time.Time)
	ShortLivedBurstLast       = make(map[int]time.Time)
	ShortLivedBurstCount      = make(map[int]int)
	ShortLivedBurstInterval   = make(map[int]time.Duration)
	ShortLivedBurstHits       = make(map[int]int)
	ShortLivedBurstTarget     = make(map[int]string)
	ShortLivedIntervals       = make(map[int][]time.Duration)
	InboundBurstLast          = make(map[int]time.Time)
	InboundBurstCount         = make(map[int]int)
	BeaconSeen                = make(map[int]time.Time)
	LocalTransportLast        = make(map[int]time.Time)
	ParentChildFreq           = make(map[string]int)
	RareTupleCount            = make(map[string]int)
	ActiveWindow              = 10 * time.Second
	ActiveHoldWindow          = 30 * time.Second
	SuspicionWindow           = 5 * time.Minute
	HistoryTTL                = 5 * time.Minute
	CleanupInterval           = 30 * time.Second
	ReverseStickyScore        = 90
	ForwardStickyScore        = 70
	ReverseControlBaseScore   = 40
	MinInternalTargetsForRev  = 2
	MinInternalPortsForRev    = 2
	OutboundOnlyExternalCap   = 30
	ShapeDeltaThreshold       = 0.35 // 35% shift triggers shape anomaly
	ProcHistoryByPID          = make(map[int]*ProcHistory)
	LastHistoryCleanup        time.Time
	BenignControlPorts        = map[int]bool{
		53:   true,
		80:   true,
		443:  true,
		8080: true,
		8443: true,
		8000: true,
		8001: true,
		8008: true,
		8888: true,
	}
)
