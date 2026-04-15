package pb

type ProcessInfo struct {
	Pid           int32    `json:"pid"`
	ParentPid     int32    `json:"parent_pid"`
	Name          string   `json:"name"`
	SessionId     uint32   `json:"session_id"`
	SessionName   string   `json:"session_name"`
	MemUsage      uint64   `json:"mem_usage"`
	Status        string   `json:"status"`
	UserName      string   `json:"user_name"`
	ExePath       string   `json:"exe_path"`
	Company       string   `json:"company"`
	Integrity     string   `json:"integrity"`
	IOReadBytes   uint64   `json:"io_read_bytes"`
	IOWriteBytes  uint64   `json:"io_write_bytes"`
	IOOtherBytes  uint64   `json:"io_other_bytes"`
	IOReadBps     uint64   `json:"io_read_bps"`
	IOWriteBps    uint64   `json:"io_write_bps"`
	IOOtherBps    uint64   `json:"io_other_bps"`
	CpuTimeNanos  int64    `json:"cpu_time_nanos"`
	StartTimeUnix int64    `json:"start_time_unix,omitempty"`
	WindowTitle   string   `json:"window_title"`
	CmdLine       string   `json:"cmd_line,omitempty"`
	LoadedLibs    []string `json:"loaded_libs,omitempty"`

	// Signature trust — populated by the agent's local telemetry reader.
	// Omitted on platforms where the verifier returns Unknown, keeping the
	// wire format backward-compatible with pre-signature-trust builds.
	SignatureTrust       string   `json:"signature_trust,omitempty"`
	Signed               bool     `json:"signed,omitempty"`
	Publisher            string   `json:"publisher,omitempty"`
	AuthenticodeOCSPSeen bool     `json:"authenticode_ocsp_seen,omitempty"`
	SHA256               string   `json:"sha256,omitempty"`
	PkgOwned             bool     `json:"pkg_owned,omitempty"`
	PkgOwnerName         string   `json:"pkg_owner_name,omitempty"`
	PublisherDNSAligned  bool     `json:"publisher_dns_aligned,omitempty"`
	OnlineEvidence       []string `json:"online_evidence,omitempty"`
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

type RawSocketConn struct {
	Pid    int32  `json:"pid"`
	Local  string `json:"local"`
	Remote string `json:"remote"`
	State  string `json:"state"`
	Proto  string `json:"proto"`
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
	ControlSubtype         string             `json:"control_subtype,omitempty"`
	ActiveProxying         bool               `json:"active_proxying"`
	ControlChannel         *ConnectionInfo    `json:"control_channel"`
	ControlDurationSeconds int32              `json:"control_duration_seconds"`
	SeenSeconds            int32              `json:"seen_seconds,omitempty"`
	OutTotal               int32              `json:"out_total"`
	OutExternal            int32              `json:"out_external"`
	OutInternal            int32              `json:"out_internal"`
	OutLoopback            int32              `json:"out_loopback"`
	OutLongLived           int32              `json:"out_long_lived"`
	OutShortLived          int32              `json:"out_short_lived"`
	InboundTotal           int32              `json:"inbound_total"`
	TrafficVerified        bool               `json:"traffic_verified"`
	StrongEvidence         bool               `json:"strong_evidence"`
	DelegatedEgress        bool               `json:"delegated_egress,omitempty"`
	DelegatedStrong        bool               `json:"delegated_strong,omitempty"`
	DelegatedOwnerPID      int32              `json:"delegated_owner_pid,omitempty"`
	DelegatedOwner         string             `json:"delegated_owner,omitempty"`
	RawSocket              bool               `json:"raw_socket,omitempty"`
	RawConns               []*RawSocketConn   `json:"raw_conns,omitempty"`
	NamedPipes             []string           `json:"named_pipes,omitempty"`
	Exited                 bool               `json:"exited,omitempty"`
	BeaconIntervalMs       int32              `json:"beacon_interval_ms,omitempty"`
	BeaconJitter           float64            `json:"beacon_jitter,omitempty"`
}

type CandidateEnvelope struct {
	HostId        string       `json:"host_id"`
	TimestampUnix int64        `json:"timestamp_unix"`
	Candidates    []*Candidate `json:"candidates"`
}

type TrainingRecord struct {
	TimestampUnix          int64     `json:"timestamp_unix"`
	ProcessKey             string    `json:"process_key"`
	ProcessName            string    `json:"process_name"`
	Features               []float64 `json:"features"`
	Signals                []string  `json:"signals"`
	RuleRole               string    `json:"rule_role"`
	RuleScore              int32     `json:"rule_score"`
	OperatorLabel          string    `json:"operator_label,omitempty"`
	ExperienceRole         string    `json:"experience_role,omitempty"`
	ExperienceObservations int32     `json:"experience_observations"`
	ExperienceStability    float64   `json:"experience_stability"`
	StrongEvidence         bool      `json:"strong_evidence"`
	TrafficVerified        bool      `json:"traffic_verified"`
}

type TrainingBatch struct {
	HostId        string            `json:"host_id"`
	SchemaHash    string            `json:"schema_hash"`
	BatchSequence int64             `json:"batch_sequence"`
	Records       []*TrainingRecord `json:"records,omitempty"`
}

type ModelArtifact struct {
	Version         string `json:"version"`
	SchemaHash      string `json:"schema_hash"`
	ModelJson       []byte `json:"model_json,omitempty"`
	ManifestJson    []byte `json:"manifest_json,omitempty"`
	PromotionReason string `json:"promotion_reason,omitempty"`
	TrainedAtUnix   int64  `json:"trained_at_unix,omitempty"`
	DatasetSize     int64  `json:"dataset_size,omitempty"`
}

type ClientMessage struct {
	Envelope        *CandidateEnvelope `json:"envelope,omitempty"`
	CommandResponse *CommandResponse   `json:"command_response,omitempty"`
	TrainingBatch   *TrainingBatch     `json:"training_batch,omitempty"`
}

type ServerCommand struct {
	RequestId string         `json:"request_id"`
	Type      string         `json:"type"`
	Pid       int32          `json:"pid"`
	Model     *ModelArtifact `json:"model,omitempty"`
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
