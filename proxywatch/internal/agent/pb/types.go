package pb

type ProcessInfo struct {
	Pid          int32  `json:"pid"`
	ParentPid    int32  `json:"parent_pid"`
	Name         string `json:"name"`
	SessionId    uint32 `json:"session_id"`
	SessionName  string `json:"session_name"`
	MemUsage     uint64 `json:"mem_usage"`
	Status       string `json:"status"`
	UserName     string `json:"user_name"`
	ExePath      string `json:"exe_path"`
	Company      string `json:"company"`
	Integrity    string `json:"integrity"`
	IOReadBytes  uint64 `json:"io_read_bytes"`
	IOWriteBytes uint64 `json:"io_write_bytes"`
	IOOtherBytes uint64 `json:"io_other_bytes"`
	IOReadBps    uint64 `json:"io_read_bps"`
	IOWriteBps   uint64 `json:"io_write_bps"`
	IOOtherBps   uint64 `json:"io_other_bps"`
	CpuTimeNanos int64    `json:"cpu_time_nanos"`
	WindowTitle  string   `json:"window_title"`
	CmdLine      string   `json:"cmd_line,omitempty"`
	LoadedLibs   []string `json:"loaded_libs,omitempty"`
}

type ListenerInfo struct {
	Pid          int32  `json:"pid"`
	LocalAddress string `json:"local_address"`
	LocalPort    int32  `json:"local_port"`
	State        string `json:"state"`
}

type ConnectionInfo struct {
	Pid           int32  `json:"pid"`
	LocalAddress  string `json:"local_address"`
	LocalPort     int32  `json:"local_port"`
	RemoteAddress string `json:"remote_address"`
	RemotePort    int32  `json:"remote_port"`
	State         string `json:"state"`
}

type UDPListenerInfo struct {
	Pid          int32  `json:"pid"`
	LocalAddress string `json:"local_address"`
	LocalPort    int32  `json:"local_port"`
}

type Candidate struct {
	Host                   string             `json:"host"`
	Proc                   *ProcessInfo       `json:"proc"`
	Listeners              []*ListenerInfo    `json:"listeners"`
	Conns                  []*ConnectionInfo  `json:"conns"`
	UDPListeners           []*UDPListenerInfo `json:"udp_listeners"`
	Score                  int32              `json:"score"`
	Confidence             int32              `json:"confidence"`
	Reasons                []string           `json:"reasons"`
	Signals                []string           `json:"signals"`
	Role                   string             `json:"role"`
	ActiveProxying         bool               `json:"active_proxying"`
	ControlChannel         *ConnectionInfo    `json:"control_channel"`
	ControlDurationSeconds int32              `json:"control_duration_seconds"`
	OutTotal               int32              `json:"out_total"`
	OutExternal            int32              `json:"out_external"`
	OutInternal            int32              `json:"out_internal"`
	OutLoopback            int32              `json:"out_loopback"`
	OutLongLived           int32              `json:"out_long_lived"`
	OutShortLived          int32              `json:"out_short_lived"`
	InboundTotal           int32              `json:"inbound_total"`
	TrafficVerified        bool               `json:"traffic_verified"`
	StrongEvidence         bool               `json:"strong_evidence"`
}

type CandidateEnvelope struct {
	HostId        string       `json:"host_id"`
	TimestampUnix int64        `json:"timestamp_unix"`
	Candidates    []*Candidate `json:"candidates"`
}

type ClientMessage struct {
	Envelope        *CandidateEnvelope `json:"envelope,omitempty"`
	CommandResponse *CommandResponse   `json:"command_response,omitempty"`
}

type ServerCommand struct {
	RequestId string `json:"request_id"`
	Type      string `json:"type"`
	Pid       int32  `json:"pid"`
}

type CommandResponse struct {
	RequestId string `json:"request_id"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
}

type EnrollRequest struct {
	ClientNonce string `json:"client_nonce"`
	ClientUnix  int64  `json:"client_unix"`
	ClientProof string `json:"client_proof"`
}

type EnrollResponse struct {
	ServerNonce       string `json:"server_nonce"`
	ServerUnix        int64  `json:"server_unix"`
	ServerFingerprint string `json:"server_fingerprint"`
	ServerProof       string `json:"server_proof"`
}
