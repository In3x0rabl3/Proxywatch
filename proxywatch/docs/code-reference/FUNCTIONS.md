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
| StartDebugAPIServer(addr) (*Server, error) | Start debug API |
| RegisterAgentStore(store) | Register agent store for API |
| ConfigureDetectionOutputs(debug, defender) error | Configure outputs |

---

## internal/agent

### Client (client.go)
| Function | Purpose |
|----------|---------|
| RunClientLoop(ctx, opts) error | Run agent client loop |

### Server (server.go)
| Function | Purpose |
|----------|---------|
| ListenAndServe(addr, store) (*Server, *grpc.Server, net.Listener, error) | Start server |
| Kill(host, pid) error | Kill process on remote host |
| HostConnected(host) bool | Check if host is connected |
| ConnectedHosts() []string | Get list of connected hosts |

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
| Start(addr) (*Server, error) | Start API server |

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
    Host            string       // Host identifier
    Proc            *ProcessInfo // Process info
    Conns           []ConnInfo   // Connections
    Listeners       []ListenerInfo
    UDPListeners    []UDPListenerInfo
    Role            string       // Assigned role
    SuggestedRole   string       // Topology suggested role
    Score           int          // Confidence score
    Signals         []string     // Detection signals
    Reasons         []string     // Score reasons
    MLRole          string       // ML predicted role
    MLConfidence    float64      // ML confidence
    MLActive        bool         // ML is active
    MLTopN          []MLRolePrediction
    StrongEvidence  bool         // Has strong evidence
    TrafficVerified bool         // Traffic verified
    ControlSubtype  string       // Control subtype
    OutExternal     int          // External connections
    OutInternal     int          // Internal connections
    ActiveProxying  bool         // Active proxying detected
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
    // ... many more fields for UI state
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
