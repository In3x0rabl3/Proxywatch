package shared

import "time"

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
)
