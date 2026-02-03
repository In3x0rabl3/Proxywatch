package shared

import "strconv"

type Candidate struct {
	Host         string
	Proc         *ProcessInfo
	Listeners    []ListenerInfo
	Conns        []ConnectionInfo
	UDPListeners []UDPListenerInfo

	// classifier-owned fields
	Score          int
	Confidence     int
	Reasons        []string
	Signals        []string
	Role           string
	ActiveProxying bool

	ControlChannel         *ConnectionInfo
	ControlDurationSeconds int

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

func CandidateKey(c Candidate) string {
	host := c.Host
	if host == "" {
		host = "local"
	}
	if c.Proc == nil {
		return host + ":0"
	}
	return host + ":" + strconv.Itoa(c.Proc.Pid)
}
