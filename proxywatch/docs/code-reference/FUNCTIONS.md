# Function Reference

This document provides detailed documentation for all exported functions and types.

## internal/shared

### Event Logging (eventlog.go)
| Function | Purpose |
|----------|---------|
| SetCyclePhase(phase string) | Set current processing phase |
| GetCyclePhase() string | Get current processing phase |
| SetCycleError(err string) | Set current cycle error |
| GetCycleError() string | Get current cycle error |
| LogInfo(source, format, args...) | Log info-level message |
| LogWarn(source, format, args...) | Log warning-level message |
| LogError(source, format, args...) | Log error-level message |
| EventLogSnapshot() []LogEvent | Get snapshot of recent events |

### ASN Lookup (asn.go)
| Function | Purpose |
|----------|---------|
| ResolveExternalASNOrgs(conns) | Resolve ASN organizations for connections |
| LookupCachedASNOrgsForIP(ip) | Get cached ASN orgs for IP |
| IsLikelyBenignOfflineTarget(target) | Check if target is likely benign |
| ASNOrgAlignedWithProcess(p, orgs) | Check if ASN aligns with process |
| IsCDNOrg(org) | Check if organization is a CDN |

### Classification (classify.go)
| Function | Purpose |
|----------|---------|
| RolePriority(role) int | Get priority for detection role |
| RoleFamily(role) string | Get family for role (tunnel, beacon, etc) |
| IsControlRole(role) bool | Check if role indicates control/C2 |
| CandidateLess(a, b) bool | Compare candidates for sorting |
| ParseRoleFilter(s) map[string]bool | Parse role filter string |
| RoleMatchesFilter(role, filter) bool | Check if role matches filter |
| IsInternalIP(ip) bool | Check if IP is internal/private |
| IsLoopbackIP(ip) bool | Check if IP is loopback |
| IsWildcardIP(ip) bool | Check if IP is wildcard (0.0.0.0) |
| ScopeLabelForLocalAddress(addr) string | Get scope label for address |

### Signature Verification (signature.go)
| Function | Purpose |
|----------|---------|
| VerifyBinaryTrust(exePath) (trust, publisher) | Verify binary signature trust |
| StartSignatureWorker() | Start background signature worker |
| StopSignatureWorker() | Stop background signature worker |

### Distinguishing (distinguishing.go)
| Function | Purpose |
|----------|---------|
| HasHardDistinguisher(c) (bool, []string) | Check for hard distinguishing signals |
| DemoteShapeOnlyControlRole(c) bool | Demote shape-only control roles |
| IsShapeOnlyCandidateRoleForReport(role) bool | Check if role is shape-only |
| HasNonLoopbackListenerForReport(c) bool | Check for non-loopback listeners |
| UpgradeSleepingBeaconProfile(c) bool | Upgrade sleeping beacon profile |

### Operator Labels (operator_labels.go)
| Function | Purpose |
|----------|---------|
| LookupOperatorLabel(sha256) *OperatorLabel | Get operator label for hash |
| SetOperatorLabel(sha256, verdict, reason) error | Set operator label |
| ClearOperatorLabel(sha256) error | Clear operator label |
| ListOperatorLabels() []OperatorLabel | List all operator labels |
| LoadOperatorLabels() error | Load labels from disk |

### Executable Hash (exe_hash.go)
| Function | Purpose |
|----------|---------|
| LookupExeSHA256(exePath) string | Get cached or compute SHA256 |

### Package Verification (verifier_pkg_*.go)
| Function | Purpose |
|----------|---------|
| LookupPackageOwner(exePath) string | Get package owner for executable |

### Publisher Domains (publisher_domains.go)
| Function | Purpose |
|----------|---------|
| LookupPublisherDomains(publisher) []string | Get domains for publisher |

### Whitelist (whitelist.go)
| Function | Purpose |
|----------|---------|
| LoadWhitelist(path) (*Whitelist, error) | Load whitelist from file |
| SaveWhitelist(path) error | Save whitelist to file |
| IsWhitelisted(sha256) bool | Check if hash is whitelisted |
| AddToWhitelist(entry) | Add entry to whitelist |
| RemoveFromWhitelist(sha256) | Remove from whitelist |

### DNS Cache (dns_cache.go)
| Function | Purpose |
|----------|---------|
| LookupCachedDNS(domain) []string | Get cached DNS records |
| CacheDNSResult(domain, ips) | Cache DNS lookup result |

### Heuristics (heuristics.go)
| Function | Purpose |
|----------|---------|
| InferRoleFromSignals(signals, subtype, current) string | Infer role from signals |
| IsLikelyBenignControlClient(p) bool | Check if process is benign |

---

## internal/detection

### Classifier (classifier.go)
| Function | Purpose |
|----------|---------|
| Classify(snap, opts, cache) []Candidate | Main classification entry point |
| ProcessBehaviorKey(c) string | Generate behavior key for candidate |

### Orchestrator (orchestrator.go)
| Function | Purpose |
|----------|---------|
| NewOrchestrator() *Orchestrator | Create new orchestrator |
| TriggerRetrain(reason, buffer) | Trigger model retraining |

### Scoring (scoring/*.go)
| Function | Purpose |
|----------|---------|
| ScoreCandidate(c) | Score a candidate |
| IsMaliciousRole(role) bool | Check if role is malicious |
| AggregateChildTunnelEvidence(candidates) | Aggregate tunnel evidence |
| ApplyPivotLinger(candidates, procs) | Apply pivot lingering |
| HistoryPIDForCandidate(c) int | Get history PID for candidate |
| ProcessBehaviorKey(c) string | Get behavior key |
| GetOrCreateProcessBehavior(key, now) *ProcessBehavior | Get or create behavior |

### Feature Extraction (features/*.go)
| Function | Purpose |
|----------|---------|
| Extract(c, behavior, profile) FeatureVector | Extract features |
| FeatureNames() []string | Get feature names |

### ML (ml/*.go)
| Function | Purpose |
|----------|---------|
| NewContinuousLearner(pred) *ContinuousLearner | Create learner |
| LoadNative(path) (Predictor, error) | Load native model |
| PredictRole(fv) PredictionResult | Predict role from features |

### Model (model/*.go)
| Function | Purpose |
|----------|---------|
| Load() error | Load model from disk |
| Save() error | Save model to disk |
| ResolveProfile(key) *Profile | Get profile for key |
| RecordObservationForMaturity() | Record maturity observation |
| RecordMLPrediction(prob, correct) | Record ML prediction |
| RecordShadowComparison(agree) | Record shadow comparison |

### Output (output/*.go)
| Function | Purpose |
|----------|---------|
| StartDebugAPIServer(addr) (*Server, error) | Start debug API server |
| RegisterAgentStore(store) | Register agent store for server-mode endpoints |
| UpdateDebugAPISnapshot(cycle, host, scored) | Update in-memory snapshot each cycle |
| CandidatesToSnapshots(scored) []CandidateSnapshot | Project candidates to JSON shape |
| BuildFPReport(cands) []FPReportEntry | Build FP verdict trace |
| BuildDiffMap(snap) map[string]DiffEntry | Build compact diff map for parity |
| BuildSIEMExport(cands, mask, host, now) SIEMExport | Build SIEM export document |

#### Debug API Endpoints

**Core Endpoints (always available):**
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/` | GET | Health check: `{ok, cycle, host, updated, candidates, server}` |
| `/candidates` | GET | Local candidates. Query: `?name=`, `?role=`, `?state=`, `?pid=` |
| `/candidate/<pid>` | GET | Single candidate by PID |
| `/self` | GET | Same as `/candidates` with stable path for monitoring |
| `/metrics` | GET | JSON counts by role/state |
| `/metrics/prom` | GET | Prometheus text-format metrics |

**Server Mode Endpoints (when AgentStore registered):**
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/agents` | GET | Connected agents + per-host summary |
| `/agent/<host>/candidates` | GET | Candidates from remote agent |
| `/agent/<host>/candidate/<pid>` | GET | Single candidate from agent |

**Diff Endpoints (parity testing):**
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/diff/local` | GET | Compact `{pid: {name, role, signals}}` map |
| `/diff/<host>` | GET | Same shape for remote agent |

**FP Report Endpoints:**
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/fp-report` | GET | FP verdict trace for local candidates |
| `/fp-report/<host>` | GET | FP verdict trace for agent host |
| `/fp-report/summary` | GET | Aggregate FP counts: roles, signals, blockers |

**Online Verification Endpoints:**
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/online/status` | GET | Signature worker + DNS cache stats |
| `/online/verdict/<pid>` | GET | Cached Authenticode verdict for PID |

**Operator Label Endpoints:**
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/operator/labels` | GET | List all operator labels |
| `/operator/label` | POST | Set label: `{sha256, verdict, reason}` |
| `/operator/label/<sha256>` | GET | Get label by hash |
| `/operator/label/<sha256>` | DELETE | Clear label |

**ML Health Endpoints:**
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/ml/shadow` | GET | Shadow comparison: agreement rate, thresholds, qualified/demoted |
| `/ml/disagreements` | GET | Last N ML-vs-rule disagreements |

**Timeline Endpoints:**
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/timeline/<pid>` | GET | Role/signal evolution history for PID |

---

## internal/agent

### Client (client.go)
| Function | Purpose |
|----------|---------|
| RunClientLoop(ctx, opts) error | Run agent client loop with reconnect |

### Server (server.go)
| Function | Purpose |
|----------|---------|
| ListenAndServe(addr, store) (*Server, *grpc.Server, net.Listener, error) | Start gRPC server |
| (*Server) Kill(host, pid) error | Kill process on remote host |
| (*Server) HostConnected(host) bool | Check if host is connected |
| (*Server) ConnectedHosts() map[string]bool | Get map of connected hosts |

### Store (server.go)
| Function | Purpose |
|----------|---------|
| NewStore() *Store | Create new candidate store |
| (*Store) Update(host, ts, cands) | Update candidates for host |
| (*Store) Snapshot(staleAfter) []Candidate | Get all non-stale candidates |
| (*Store) SnapshotHost(host) ([]Candidate, time.Time, bool) | Get candidates for host |
| (*Store) HostKeys() []HostStat | Get all known hosts with stats |
| (*Store) RemoveHost(host) bool | Remove host from store |
| (*Store) HostSummaries(...) []HostSummary | Get filtered host summaries |
| (*Store) LastUpdate(host) (time.Time, bool) | Get last update time for host |

### Auth (auth/*.go)
| Function | Purpose |
|----------|---------|
| SetAgentToken(token) error | Set agent token |
| EnsureServerAgentToken() (string, error) | Ensure server has token |

---

## internal/contour

### Tunnel (tunnel/*.go)
| Function | Purpose |
|----------|---------|
| RunTunnel(ctx, input) TunnelResult | Run tunnel |

### Probe (probe/*.go)
| Function | Purpose |
|----------|---------|
| RunProbe(ctx, config) ProbeResult | Run protocol probe |

### API (api/*.go)
| Function | Purpose |
|----------|---------|
| Start(addr) (*Server, error) | Start Contour API server |
| (*Server) Close() error | Stop API server |
| (*Server) SetActiveTunnel(...) | Register external tunnel with API |
| (*Server) MarkStopped() | Clear running flag when tunnel exits |
| (*Server) AppendLog(line) | Add log line to ring buffer |

#### Contour API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/` | GET | Health: `{ok, service, running, proto, updated}` |
| `/protocols` | GET | List carrier, dead-drop, and verifiable protocols |
| `/status` | GET | Active tunnel config, elapsed time, log buffer |
| `/tunnel/start` | POST | Start tunnel: `{role, proto, direction, ports, target}` |
| `/tunnel/stop` | POST | Cancel active tunnel |
| `/verify/<proto>` | GET | In-process round-trip test for one protocol |
| `/verify/all` | GET | Run all verifiable protocols sequentially |

**Supported Protocols:**
- Carrier: socks5, socks4, http, https, ws, wss, ssh, dns, ntp, smtp, ftp, imap, pop3, redis, postgres, ldap, smb, mqtt, amqp, rdp, quic, webrtc, openai-api, domainfront
- Dead-drop: openai-deaddrop, github-deaddrop

---

## internal/keystore

### Keystore (keystore.go)
| Function | Purpose |
|----------|---------|
| DefaultPath() string | Get default keystore path |
| Load(path) (*Values, error) | Load keystore |
| Save(path, values) error | Save keystore |
| ApplyToRuntime(values) | Apply values to runtime |
| RuntimeValue(key) string | Get runtime value |

---

## internal/ui

### Main (loop.go, root.go)
| Function | Purpose |
|----------|---------|
| Run(app, scanner) error | Run UI |

---

## Key Types

### Candidate (shared/candidate.go)
```go
type Candidate struct {
    Host            string
    Proc            *ProcessInfo
    Listeners       []ListenerInfo
    Conns           []ConnectionInfo
    UDPListeners    []UDPListenerInfo

    DelegatedEgress   bool
    DelegatedStrong   bool
    DelegatedOwnerPID int
    DelegatedOwner    string
    RawSocket         bool
    RawConns          []RawSocketConn
    NamedPipes        []string

    Score             int
    Confidence        int
    Reasons           []string
    Signals           []string
    Role              string
    ControlSubtype    string
    ActiveProxying    bool

    ControlChannel         *ConnectionInfo
    ControlDurationSeconds int
    SuggestedRole          string
    BeaconIntervalMs       int
    BeaconJitter           float64

    MLRole       string
    MLConfidence float64
    MLTopN       []MLRolePrediction
    MLActive     bool
    SeenSeconds  int
    Exited       bool

    OutTotal      int
    OutExternal   int
    OutInternal   int
    OutLoopback   int
    OutLongLived  int
    OutShortLived int
    InboundTotal  int

    TrafficVerified bool
    StrongEvidence  bool
}
```

### ProcessInfo (shared/candidate.go)
```go
type ProcessInfo struct {
    Pid       int
    Ppid      int
    Name      string
    ExePath   string
    Cmdline   string
    UserName  string
    Company   string
    SHA256    string
    LoadedLibs []string
    StartTime time.Time
}
```

### ConnectionInfo (shared/candidate.go)
```go
type ConnectionInfo struct {
    LocalAddress  string
    LocalPort     int
    RemoteAddress string
    RemotePort    int
    State         string
    Protocol      string
}
```

### AppState (shared/app.go)
```go
type AppState struct {
    RefreshInt         time.Duration
    ConfirmKill        bool
    ConfirmKillTimeout time.Duration
    RolePreset         string
    SortPreset         string
    LocalHost          string
    Whitelist          *Whitelist
    KeystorePath       string
    KeystoreValues     *keystore.Values
    KeystoreUnlocked   bool
    LastError          string
}
```

### Snapshot (shared/state.go)
```go
type Snapshot struct {
    Timestamp   time.Time
    Processes   map[int]*ProcessInfo
    Connections []ConnectionInfo
    Listeners   []ListenerInfo
}
```
