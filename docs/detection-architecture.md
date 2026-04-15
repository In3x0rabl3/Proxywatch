# Proxywatch Detection Architecture: Role-Centric Classification

## A. Role Definitions Table

Each role is a **behavioral hypothesis** about what a process is doing on behalf of an adversary. The classifier's job is to determine which hypothesis best fits the observed telemetry.

### Beacon (control-beacon)

**Purpose:** Periodic callback to C2 server. Receives tasking, sends results. Designed for long-term persistence with minimal footprint.

**Network telemetry:**
- Outbound-initiated connections to 1-3 external endpoints
- Regular or jittered intervals between connections (seconds to months)
- Short-lived connections: connect → exchange → disconnect → sleep
- Small payload sizes per callback (commands are small)
- Read-dominant IO: fetches tasking, sends small results
- May rotate destination IPs (failover/redirector pools)
- Typically HTTP/HTTPS (443) or DNS for blending
- NO persistent ESTABLISHED connection during sleep — the socket closes or times out between callbacks

**Host telemetry:**
- Low CPU usage relative to lifetime
- Stable memory footprint (no interactive workload)
- Minimal or zero child processes (pure callback agent)
- Few threads (1-5, no thread pool needed)
- Crypto/TLS libraries loaded
- Runs from user-writable path (Downloads, Temp, AppData)
- Rare or suspicious parent process (explorer.exe → unknown.exe)

**Key differentiator from Session:** Connection is NOT persistent. The process sleeps between callbacks. `OutLongLived` should be 0 because connections are short-lived. If the underlying transport uses HTTP keep-alive and the TCP socket remains ESTABLISHED during sleep, the socket has zero IO throughput during the sleep period — this distinguishes it from an active session.

**Key differentiator from Outbound:** Outbound apps contact known vendors on standard ports with vendor-aligned ASN. Beacons contact unknown infrastructure, often with ASN mismatch, from suspicious paths.

---

### Session (control-session)

**Purpose:** Interactive, persistent control channel. Operator sends commands in real-time, sees output immediately. Used for hands-on-keyboard activity.

**Network telemetry:**
- Single persistent ESTABLISHED connection held for minutes to hours
- Bidirectional IO: operator sends commands (writes), receives output (reads)
- IO is bursty: command → pause → output → pause (interactive cadence)
- `OutLongLived >= 1` — the connection carries sustained traffic, not idle keep-alive
- Write ratio higher than beacons (operator sending commands + exfil)
- Typically to a single external target
- Connection survives across multiple command exchanges

**Host telemetry:**
- May spawn child processes (cmd.exe, powershell.exe, whoami.exe) for operator commands
- Higher CPU than beacons (executing tasking interactively)
- IO is bidirectional and interactive (read/write balance 0.3-3.0)
- Command line may contain encoded content
- May have elevated integrity (post-exploitation privilege escalation)
- Rare parent-child relationship

**Key differentiator from Beacon:** Session has a persistent connection with active bidirectional IO. Beacon connects briefly and disconnects. The critical signal is `OutLongLived >= 1` combined with `ControlDurationSeconds >= 30`. A TCP socket that is ESTABLISHED but carrying zero IO during sleep periods is NOT a session — it's a beacon with keep-alive.

**Key differentiator from Pivot:** Session connects to ONE external target. Pivot relays traffic between external and internal targets.

---

### SOCKS Tunnel (control-pivot, subtype socks-tunnel)

**Purpose:** Dynamic port forwarding proxy. Allows operator to route arbitrary traffic through the compromised host.

**Network telemetry:**
- Loopback listener (127.0.0.1:XXXXX) — C2 framework binds SOCKS on localhost
- Multiple outbound connections to diverse internal targets and ports
- Inbound from loopback → outbound to internal = relay pattern
- Throughput symmetry: bytes in ≈ bytes out (proxy doesn't generate/consume)
- Fan-out: single listener serving multiple concurrent tunneled connections
- Port diversity: connections to many different destination ports through one listener

**Host telemetry:**
- Has TCP listener on loopback
- High file descriptor or handle count (many concurrent tunneled connections)
- Proxy library loaded (libsocks, proxychains artifacts)
- SSH with `-D` flag
- Often runs alongside a session/beacon (same process or child)

**Key differentiator from TCP Pivot:** SOCKS is dynamic (any target, any port through one listener). TCP pivot is static (one listener → one target).

**Key differentiator from Listener:** SOCKS listener is on loopback only (not externally exposed) and has corresponding outbound connections. Pure listener has no outbound relay.

---

### TCP Pivot (control-pivot, subtype tcp-pivot)

**Purpose:** Static port forward. Maps a specific local port to a specific remote target:port.

**Network telemetry:**
- Listener on a specific port (may be loopback or wildcard)
- Outbound connections to a SINGLE internal target:port
- 1:1 or N:1 mapping: each inbound client → corresponding outbound to same target
- Throughput symmetry: relay behavior
- SSH with `-L` or `-R` flags
- Connection count correlation: inbound ≈ outbound

**Host telemetry:**
- Has TCP listener
- SSH/plink process with tunnel flags in command line
- Fewer handles than SOCKS (less concurrent connections)
- Often service-like (session 0, no console)

**Key differentiator from SOCKS:** Fixed target, not dynamic. Only connects to one destination.

**Key differentiator from Session:** Has a listener component + outbound to internal. Session has no listener.

---

### SMB Pivot (control-pivot, subtype smb-pipe)

**Purpose:** Lateral movement and C2 relay over named pipes via SMB (port 445).

**Network telemetry:**
- Outbound connections to internal targets on port 445 (SMB)
- May have connections to multiple internal SMB targets
- All SMB targets are internal (lateral, not external)
- Low throughput: command relay, not bulk data transfer

**Host telemetry:**
- Named pipes matching C2 patterns: `msagent_*`, `MSSE-*`, `postex_*`, `status_*`
- Also standard admin pipes: `srvsvc`, `svcctl`, `wkssvc` (if used for lateral)
- May have elevated integrity (requires SMB authentication)
- Service context possible (session 0)
- Often no TCP listener (pipe-based, not socket-based)

**Key differentiator from other pivots:** Uses named pipes + SMB port 445, not TCP listeners.

**Key differentiator from normal SMB:** Normal SMB is file sharing to servers. C2 SMB pipes have recognizable naming patterns and connect to workstations, not file servers.

---

### Listener (listener)

**Purpose:** Exposes a network service. May be legitimate (web server, SSH) or malicious (bind shell, staged listener).

**Network telemetry:**
- Has TCP/UDP listener on one or more ports
- Accepts inbound connections
- May serve multiple clients simultaneously
- Typically NO outbound connections (pure service)
- External-facing or internal-only

**Host telemetry:**
- Service context (session 0) common for legitimate services
- Long-running, stable
- May have many threads (serving concurrent clients)
- Known vendor for legitimate services

**Key differentiator from Pivot:** Listener does NOT relay traffic outbound. It only serves inbound clients. If a listener process ALSO has outbound connections, it's likely a pivot.

---

### Outbound Communication (outbound)

**Purpose:** Normal application network activity. Not adversary-controlled.

**Network telemetry:**
- Connects to known vendor infrastructure (CDN, update servers)
- Standard ports (80, 443)
- ASN matches vendor (Microsoft → Microsoft ASN)
- Multiple external targets (CDN multi-IP is normal)
- No internal connections (apps don't lateral-move)

**Host telemetry:**
- Known vendor metadata (verified company)
- System path (C:\Windows\, C:\Program Files, /usr/)
- Legitimate parent process chain
- Normal IO patterns for application type

**Key differentiator from everything else:** Known vendor + system path + standard ports + ASN alignment. Unknown processes from user-writable paths don't get this classification.

---

## B. Detection Design Architecture

```
Telemetry Snapshot
       |
       v
+-------------------+
| Build Candidates  |  (process + connections + listeners + pipes)
+-------------------+
       |
       v
+-------------------+
| Score Candidate   |  (rank.go: compute derived fields)
| - ControlChannel  |  (FindPersistentControl, connection tracking)
| - BeaconInterval  |  (burst tracker, SYN cycle detector)
| - OutLongLived    |  (connection lifetime classification)
| - DelegatedEgress |  (socket ownership correlation)
+-------------------+
       |
       v
+-------------------+
| Emit Signals      |  (behavior/*.go: 73 role-specific signals)
| - Beacon (15)     |
| - Session (16)    |
| - Pivot (17)      |
| - Outbound (12)   |
| - Listener (13)   |
+-------------------+
       |
       v
+-------------------+        +-------------------+
| Extract Features  |  --->  | ML Prediction     |
| (117 features)    |        | (GBDT 5-class)    |
+-------------------+        +-------------------+
       |                              |
       v                              v
+-------------------+        +-------------------+
| InferRoleFromSig  |        | Model Role        |
| (signal counting) |        | (probability)     |
+-------------------+        +-------------------+
       |                              |
       +--------- merge -------------+
       |
       v
+-------------------+
| Final Role        |  (operator overrides > ML > signals > default)
| ActiveProxying    |  (topology check for tunneling state)
| Training Export   |  (deferred record with final role for learning)
+-------------------+
       |
       v
+-------------------+
| Dashboard Display |  (role, state, SRC indicator)
+-------------------+
```

**Hybrid rule/ML architecture:**
- **Rules (signals)** capture strong, explainable indicators. Each signal maps to a specific role hypothesis.
- **ML (GBDT)** handles ambiguous cases where no single signal is decisive. Uses all 117 features to predict role probabilities.
- **Rules enrich ML:** Signals are included in training records. Feature extraction uses derived fields (ControlChannel, BeaconInterval) computed by the rule engine.
- **ML feeds back:** Model predictions override rule suggestions when confident. Training labels (including operator corrections) improve future models.
- **No circular logic:** Rules compute signals → signals + features → ML prediction → final role. Rules never read ML output; ML never modifies signal emission.

---

## C. Feature Matrix by Role

### Discriminative Features (what separates roles from each other)

| Feature | Beacon | Session | SOCKS Tunnel | TCP Pivot | SMB Pivot | Listener | Outbound |
|---------|--------|---------|--------------|-----------|-----------|----------|----------|
| OutLongLived | **0** | **>=1** | varies | varies | 0 | 0 | varies |
| BeaconIntervalMs | **>0** | 0 | 0 | 0 | 0 | 0 | 0 |
| ControlDurationSec | low-med | **high** | varies | varies | 0 | 0 | varies |
| OutShortLived | **high** | low | varies | varies | low | 0 | varies |
| IOReadRatio | **>0.55** | 0.3-0.7 | ~0.5 | ~0.5 | varies | varies | >0.9 |
| IOWriteRatio | <0.45 | **0.3-0.7** | ~0.5 | ~0.5 | varies | varies | <0.1 |
| ListenerCount | 0 | 0 | **>=1** | **>=1** | 0 | **>=1** | 0 |
| ListenerLoopback | n/a | n/a | **1** | 0 or 1 | n/a | 0 | n/a |
| InboundTotal | 0 | 0 | **>0** | **>0** | 0 | **>0** | 0 |
| OutInternal | 0 | 0 | **>0** | **>0** | **>0** | 0 | 0 |
| OutExternal | 1 | 1 | 0-1 | 0-1 | 0 | 0 | **>=1** |
| SMBConnCount | 0 | 0 | 0 | 0 | **>0** | 0 | 0 |
| NamedPipeC2 | 0 | 0 | 0 | 0 | **1** | 0 | 0 |
| ThroughputSymmetry | low | medium | **high** | **high** | low | n/a | low |
| ChildProcessCount | **0** | **>0** | 0 | 0 | 0 | varies | varies |
| KnownVendor | 0 | 0 | 0 | 0 | 0 | varies | **1** |
| SuspiciousPath | **1** | **1** | 0-1 | 0-1 | 0 | 0 | **0** |
| ConnChurnRate | **high** | low | medium | low | low | 0 | varies |
| SleepRegularity | **high** | 0 | 0 | 0 | 0 | 0 | 0 |
| BurstSilenceShape | **>0** | 0 | 0 | 0 | 0 | 0 | 0 |

### Critical Disambiguation Features

**Beacon vs Session:**
- `OutLongLived`: 0 for beacon (short connections), >=1 for session (persistent)
- `BeaconIntervalMs`: >0 for beacon (confirmed timing), 0 for session
- `IOReadRatio`: >0.55 for beacon (fetching commands), balanced for session
- `ConnChurnRate`: high for beacon (reconnecting), low for session (single persistent)
- `SleepRegularity`: >0 for beacon (regular silence periods), 0 for session
- `ChildProcessCount`: 0 for beacon (sleeping agent), >0 for session (executing commands)

**SOCKS Tunnel vs TCP Pivot:**
- `PortDiversityThruProcess`: high for SOCKS (any target), low for TCP pivot (fixed target)
- `SOCKSCandidate`: 1 for SOCKS (loopback + diverse ports), 0 for TCP pivot
- `DistinctTargets`: many for SOCKS, 1 for TCP pivot
- `CmdHasTunnelFlags`: 1 for TCP pivot with SSH -L/-R, 0 for SOCKS typically

**Listener vs Pivot:**
- `OutTotal`: 0 for pure listener (serves only), >0 for pivot (relays outbound)
- `FanOutFromListener`: 0 for listener, >0 for pivot
- `InboundOutboundRatio`: infinity for listener (no outbound), ~1.0 for pivot (balanced)

---

## D. Rule Audit Checklist

### Rules That Are Too Generic (cause FPs on known-vendor processes)

| Signal | Problem | Status |
|--------|---------|--------|
| ~~beacon-no-children~~ | Every lightweight service has 0 children | **FIXED**: gated on !IsKnownVendorProcess |
| ~~beacon-http-channel~~ | Every HTTPS client fires this | **FIXED**: gated on !IsKnownVendorProcess |
| ~~beacon-crypto-lib-loaded~~ | Every TLS process fires this | **FIXED**: gated on !IsKnownVendorProcess |
| ~~beacon-thread-minimal~~ | 1-3 threads is normal for services | **FIXED**: gated on !IsKnownVendorProcess |
| ~~pivot-high-handle-count~~ | Browsers/WebView2 have many handles | **FIXED**: gated on !IsKnownVendorProcess |
| ~~session-asn-mismatch~~ | CDN-hosted vendor apps always mismatch | **FIXED**: gated on !knownGood |

### Rules That Cause Role Confusion

| Signal/Logic | Confusion | Status |
|-------------|-----------|--------|
| ~~ControlDurationSeconds >= 60 forces session~~ | HTTPS beacon keep-alive looks persistent | **FIXED**: removed from rank.go |
| ~~session-control-channel-persistent fires on idle keep-alive~~ | Beacon TCP socket stays ESTABLISHED during sleep | **FIXED**: requires OutLongLived >= 1 |
| beacon-target-lock fires on transient CDN fetches | One-shot requests trigger single-target signal | **FIXED**: requires OutLongLived >= 1 |

### Rules That Are Missing

| Gap | Impact | Recommendation |
|-----|--------|---------------|
| No beacon-specific "short-lived reconnection" signal | Beacons that connect briefly and disconnect aren't captured distinctly from session reconnects | Add: `beacon-short-lived-callback` — OutShortLived > 0 AND OutLongLived == 0 AND OutExternal > 0 AND !knownGood |
| No internal-only session signal | C2 pivoting through internal hosts (no external) gets 0 session signals | Add: `session-internal-control` — OutExternal == 0 AND OutInternal == 1 AND OutLongLived >= 1 AND ControlDuration >= 30 AND !knownGood |
| No IO-idle detection for keep-alive distinction | Can't distinguish active session from idle keep-alive socket | Track IO rate per connection, not just process-level IO. Feature: `ControlChannelIORate` |
| No SOCKS-specific signal beyond socks-candidate | SOCKS proxy detection relies on library/flag presence only | Add: `pivot-socks-diverse-targets` — ListenerLoopbackOnly AND DistinctOutboundPorts >= 3 AND InboundTotal > 0 |

### Features That Are Not Discriminative Enough

| Feature | Problem | Recommendation |
|---------|---------|---------------|
| FBeaconTargetStability | Binary flag, same value for beacon and session with single target | Make continuous: track target changes over time |
| FSessionControlDurationSec | Grows for beacons with keep-alive sockets | Pair with per-connection IO rate to distinguish active vs idle |
| FPivotInboundOutboundRatio | Capped at 0.3-3.0, loses resolution | Use log scale for better separation |

---

## E. Updated Rule Logic

### Signal Emission Changes (already implemented)

```
beacon.go:
  beacon-http-channel:      + !IsKnownVendorProcess(p)
  beacon-no-children:       + !IsKnownVendorProcess(p)
  beacon-crypto-lib-loaded: + !IsKnownVendorProcess(p)
  beacon-thread-minimal:    + !IsKnownVendorProcess(p)
  beacon-target-lock:       + OutLongLived >= 1

session.go:
  session-control-channel-persistent: + OutLongLived >= 1
  session-asn-mismatch:              + !knownGood

pivot.go:
  pivot-high-handle-count:  + !IsKnownVendorProcess(p)
```

### InferRoleFromSignals Changes (already implemented)

```
1. Decisive signals checked FIRST (before outbound suppression)
2. hasSessionPersistence flag for tie-breaking
3. When beacon == session hits AND hasSessionPersistence → session wins
4. Otherwise beacon >= session → beacon wins (beacons are the default suspicious)
```

### rank.go Control Subtype Changes (already implemented)

```
REMOVED: if c.ControlDurationSeconds >= 60 || outLongLived > 0 { hasSessionSig = true }
NOW: subtype determined purely by which legacy signals fire (beacon-cadence vs persistent-control)
```

### Proposed New Signals (not yet implemented)

```go
// beacon-short-lived-callback: connects briefly then disconnects (beacon sleep pattern).
// Session holds connections; beacons don't.
if c.OutShortLived > 0 && c.OutLongLived == 0 && c.OutExternal > 0 && !shared.IsKnownVendorProcess(p) {
    addSignal("beacon-short-lived-callback")
}

// session-internal-control: persistent control to internal target (lateral session).
if c.OutExternal == 0 && c.OutInternal == 1 && c.OutLongLived >= 1 &&
   c.ControlDurationSeconds >= 30 && !knownGood {
    addSignal("session-internal-control")
}
```

These would be added to the beacon/session whitelists in `shared/roles.go`.

---

## F. ML Training Pipeline Design

### Current Pipeline (already implemented)

```
Observation Loop (every 250ms):
  ScoreCandidate → EmitSignals → ExtractFeatures → BufferRecord
                                                          |
                                                    TrainingBuffer
                                                    (NDJSON on disk)
                                                          |
                                         +----------------+
                                         |
Retrain Loop (every 10s):               v
  ShouldRetrain? ──yes──> IngestRecords → Validate → Train (GBDT)
       |                                                    |
       no                                          role_classifier.json
       |                                                    |
   CheckForNewModel ←──────────────────────────────────────+
       |
   Hot-swap predictor
```

### Label Resolution Priority Chain

```
1. Operator Label    (weight 5.0) — explicit human assignment
2. User Verdict      (weight 3.0) — kill/whitelist actions  
3. Experience        (weight 2.0) — stable behavioral consensus (>=10 obs, >=0.7 stability)
4. Rule Role         (weight 1.0) — InferRoleFromSignals output
5. Default           (weight 0.5) — fallback "outbound"
```

### Class Imbalance Handling

```
Per-class weight = total_samples / (5 × class_count), capped at 20.0
Per-sample weight = source_weight × class_weight
Ensures minority classes (pivots, beacons) get proportional influence
```

### Model Versioning

```
~/.proxywatch/models/
  retrain/role_classifier.json    — latest retrained model
  active/role_classifier.json     — currently loaded model
  baselines/                      — user-created baseline snapshots
```

### Retrain Triggers

```
1. New operator label (immediate)
2. Maturity-gated cooldown:
   - COLD/LEARNING: 2-minute cooldown
   - STABLE: 5-minute cooldown
   - CALIBRATED: 10-minute cooldown
3. Buffer gate: minimum 50 records
```

### Validation

```
Pre-training checks:
  - Minimum 50 samples
  - Feature count == 117
  - Outbound class must exist
  - Warn if any class < 5 samples
  - Warn if outbound > 99%
  - Check for NaN/Inf values

Post-training evaluation:
  - Per-class precision/recall/F1
  - Confusion matrix
  - Shadow agreement with rules
  - Confidence distribution
```

---

## G. Training Record Schema

```json
{
  "schema": "proxywatch-training-v1",
  "timestamp": "2026-04-09T12:00:00Z",
  "host": "DEMO",
  "cycle": 1234,
  
  "process_key": "demo|c:\\users\\ops\\downloads\\beacon.exe|beacon.exe|demo\\ops|452",
  "process_name": "beacon.exe",
  "process_path": "C:\\Users\\ops\\Downloads\\beacon.exe",
  "user": "DEMO\\ops",
  "company": "",
  
  "features": {
    "beacon_interval_ms_confirmed": 300000,
    "beacon_jitter_cov": 0.4,
    "beacon_syn_cycle_count": 3,
    "session_control_duration_sec": 0,
    "session_out_long_lived": 0,
    "pivot_listener_count": 0,
    "outbound_known_vendor": 0,
    "...": "... (117 total)"
  },
  
  "signals": ["beacon-non-standard-port", "beacon-no-children", "beacon-micro-payload"],
  
  "rule_role": "control-beacon",
  "rule_score": 65,
  
  "model_role": "control-beacon",
  "model_confidence": 0.87,
  
  "operator_label": "beacon",
  "user_verdict": "",
  "calibration_verdict": "suspicious",
  
  "experience_role": "control-beacon",
  "experience_observations": 500,
  "experience_stability": 0.92,
  
  "strong_evidence": true,
  "traffic_verified": false
}
```

---

## H. Evaluation Plan

### Per-Role Metrics (computed after each retrain)

```
For each role in {outbound, listener, control-beacon, control-session, control-pivot}:
  - Precision: TP / (TP + FP)
  - Recall:    TP / (TP + FN)
  - F1:        2 × P × R / (P + R)
  
  Target thresholds:
    outbound:        P >= 0.95, R >= 0.90
    listener:        P >= 0.90, R >= 0.85
    control-beacon:  P >= 0.85, R >= 0.80
    control-session: P >= 0.85, R >= 0.80
    control-pivot:   P >= 0.80, R >= 0.75
```

### Confusion Pairs to Monitor

```
beacon ↔ session:  Most critical. Track weekly.
  Root cause: keep-alive sockets, OutLongLived miscounting
  
beacon ↔ outbound: FP risk. Known-vendor gate should prevent.
  Root cause: generic beacon signals on legitimate apps
  
session ↔ outbound: FP risk on persistent connections.
  Root cause: CDN long-polls, WebSocket apps
  
pivot ↔ listener: Listener with outbound = pivot, not listener.
  Root cause: server processes that also make outbound calls
  
pivot ↔ session: Pivot has relay topology, session does not.
  Root cause: session with child processes making internal calls
```

### Shadow Agreement Tracking

```
Every observation: compare rule_role vs ml_role
Track agreement rate per role
Alert when agreement drops below 80% for any role
Root-cause by examining features where they diverge
```

---

## I. False-Positive Reduction Strategy

### Tier 1: Signal Emission Gates (implemented)

Known-vendor processes don't emit generic signals. This is the most effective FP reduction because it prevents suspicious signal accumulation at the source.

**Affected signals:** 4 beacon, 1 pivot, 1 session = 6 signals gated
**Impact:** Eliminates ~80% of FPs on system processes (svchost, Edge, OneDrive)

### Tier 2: Outbound Suppression (existing)

When outbound signals outnumber suspicious signals, classify as outbound. This catches processes that do emit some generic suspicious signals but have overwhelming benign indicators.

**Condition:** outboundHits >= suspTotal → "outbound"

### Tier 3: Experience Learning (existing)

After 10+ observations with 70%+ role stability, the experience system provides a reliable baseline. Processes that consistently classify as outbound get the experience label as ground truth for retraining.

### Tier 4: Operator Whitelist (existing)

Operator can whitelist specific processes. This persists as the highest-priority label and prevents future false positives.

### Tier 5: Baseline Verification (existing)

`outbound-baseline-verified` fires when a known-vendor process has 10+ observations with <25% suspicious ratio. This suppresses any residual suspicious signals.

---

## J. Implementation Roadmap

### Phase 1: Signal Architecture (DONE)

- [x] Gate generic beacon signals on !IsKnownVendorProcess
- [x] Gate pivot-high-handle-count on !IsKnownVendorProcess
- [x] Gate session-asn-mismatch on !knownGood
- [x] Add duration requirement to beacon-target-lock
- [x] Decisive signal overrides (SSH tunnel, confirmed beacon interval)
- [x] Remove duration-based session force from rank.go
- [x] Require OutLongLived >= 1 for session-control-channel-persistent
- [x] Session persistence tie-break in InferRoleFromSignals

### Phase 2: New Discriminative Signals (NEXT)

- [ ] Add `beacon-short-lived-callback` signal (OutShortLived > 0, OutLongLived == 0)
- [ ] Add `session-internal-control` signal (internal-only persistent connection)
- [ ] Add to signal whitelists in shared/roles.go
- [ ] Verify no FP regression on known-vendor processes

### Phase 3: Feature Engineering (NEXT)

- [ ] Add `FBeaconOutLongLivedCount` feature (critical beacon/session separator)
- [ ] Add `FSessionIOActiveRatio` feature (IO rate during connection lifetime vs idle)
- [ ] Add `FBeaconReconnectCount` feature (connection teardown/recreate cycles)
- [ ] Pair ControlDurationSec with per-connection IO rate feature

### Phase 4: Training Pipeline Improvements

- [ ] Add per-role confusion matrix to retrain evaluation output
- [ ] Add concept drift detection (alert when role distribution shifts >10%)
- [ ] Add feature importance tracking per retrain cycle
- [ ] Add holdout validation (80/20 time-split)

### Phase 5: Continuous Validation

- [ ] Shadow agreement monitoring with per-role breakdown
- [ ] Weekly confusion pair analysis
- [ ] Automated FP/FN flagging when operator overrides contradict model
- [ ] Feature staleness detection (features that stopped being discriminative)
