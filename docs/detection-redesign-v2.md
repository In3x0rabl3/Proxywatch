# Detection System Redesign v2: Unified Control-Channel + Collection Fix

## A. Revised Taxonomy

| Role | Class Index | Description |
|------|------------|-------------|
| **outbound** | 0 | Normal application traffic — known vendors, standard behavior |
| **listener** | 1 | Network service — accepts inbound, no outbound relay |
| **control-channel** | 2 | C2 communication — both polling and interactive patterns |
| **control-pivot** | 3 | Traffic relay — SOCKS, TCP forward, SMB pipe |

Sub-modes for control-channel (informational, not classification targets):
- **polling-like**: periodic short callbacks, sleep gaps, read-dominant IO
- **interactive-like**: persistent connection, bidirectional bursty IO, child spawning
- **mixed/adaptive**: switches between modes, hybrid behavior

---

## B. Formal Definition of Control-Channel

### Purpose
A control-channel is a process-level communication relationship where a remote operator or C2 server controls local process behavior. The process maintains outbound connectivity, receives instructions, executes them locally, and reports results.

### Host Telemetry
- Process from user-writable path (Downloads, Temp, AppData, Desktop)
- Unknown vendor (no verified company metadata)
- Rare or suspicious parent-child chain (explorer → unknown.exe)
- May spawn children on command receipt (cmd, powershell, whoami)
- Low-to-moderate CPU (polling: minimal; interactive: moderate)
- Stable memory footprint between commands
- Crypto/TLS libraries loaded
- Few threads (1-5 typical for agents)
- May have encoded content in command line
- May have RWX memory (reflective loading)

### Network Telemetry
- Outbound-initiated to 1-3 external endpoints
- May be persistent (session-like) or periodic (beacon-like) or mixed
- Uses HTTPS (443), HTTP (80), or non-standard ports
- ASN often mismatches process vendor
- Small payload sizes per exchange (commands are small)
- Connection to infrastructure not in known CDN/vendor ranges

### Cadence Patterns
- **Polling**: regular or jittered intervals, connect → exchange → disconnect → sleep
- **Interactive**: persistent connection, bursty IO (command → response → idle → command)
- **Adaptive**: starts polling, escalates to interactive when tasked
- **Long-lived low-volume**: keep-alive connection with micro-payloads

### Persistence/Reconnect
- Reconnects to same endpoint after connection loss
- May rotate endpoints (failover/redirector pools)
- SYN cycling visible between callbacks
- Connection churn pattern: short-lived outbound recurring to same target

### What Makes It Different From Other Roles

| vs Role | Control-Channel | Other |
|---------|----------------|-------|
| **Pivot** | No listener, no internal relay | Has listener + outbound to internal. Throughput symmetry. |
| **Listener** | Initiates outbound | Only accepts inbound. Zero outbound. |
| **Outbound** | Unknown vendor, suspicious path | Known vendor, system path, ASN-aligned |

---

## C. Old → New Mapping

| Old Role | New Role |
|----------|----------|
| control-session | control-channel |
| control-beacon | control-channel |
| control-channel (legacy) | control-channel |
| control-pivot | control-pivot |
| listener | listener |
| outbound | outbound |

---

## D. Rule Audit

### Current Signal Architecture (33 control signals)

All former beacon-* and session-* signals contribute to a single `controlSignals` map. This is already implemented.

### Signals That Are Working

| Signal | Why It Works |
|--------|-------------|
| beacon-interval-confirmed | Confirmed timing pattern — high specificity |
| beacon-syn-cycle-cadence | SYN cycling — direct behavioral evidence |
| session-control-channel-persistent | Persistent connection — structural evidence |
| session-shell-spawn | Child spawning + network — behavioral evidence |
| session-encoding-in-cmdline | Encoded commands — forensic evidence |
| pivot-ssh-tunnel-flags | SSH -R/-L/-D flags — decisive |
| pivot-named-pipe-c2-pattern | Known C2 pipe names — decisive |

### Signals With Near-Zero Effectiveness (and why)

| Signal | Effectiveness | Root Cause | Fix |
|--------|-------------|------------|-----|
| beacon-no-children | ~1% | Fires on every unknown-vendor lightweight process. Not discriminative — most processes have 0 children. | Gate on: must also have OutExternal > 0 AND non-standard behavior (rare parent OR non-standard port) |
| beacon-memory-stable | ~0% | Nearly all processes have stable memory. Not discriminative. | Remove from controlSignals — use as ML feature only |
| beacon-low-cpu-long-life | ~1% | Many legitimate background processes are long-lived with low CPU. | Gate on: must also have OutExternal > 0 AND !systemPath |
| beacon-sleep-wake-cycle | ~2% | 1800s threshold too strict for fast beacons, too loose for idle apps | Reduce to 300s AND require confirmed burst history |
| session-conn-churn | ~1% | OutShortLived > 3 fires on many apps (DNS, health checks) | Increase to > 5 AND require same-target churn (not diverse) |
| beacon-io-read-dominant | ~0% | Read ratio 0.55-0.90 is normal for most apps | Narrow to 0.60-0.85 AND require OutExternal == 1 (single target) |
| outbound-cert-validation | ~0% | Fires broadly on any short HTTPS connections | Remove from outbound signals — too noisy |
| outbound-push-notification | ~1% | Single long-lived external is extremely common | Remove — not discriminative |

### Signals to Demote (ML-only, remove from rule inference)

These signals provide weak evidence individually but may be useful as ML features in combination:
- `beacon-memory-stable`
- `beacon-low-cpu-long-life`
- `beacon-io-read-dominant`
- `outbound-cert-validation`
- `outbound-push-notification`
- `listener-no-children`
- `listener-low-thread-count`

**Action:** Remove from `controlSignals`/`outboundSignals`/`listenerSignals` maps in roles.go. Keep the signal emission in behavior/*.go for training record inclusion, but don't count them in `InferRoleFromSignals`.

---

## E. Control-Channel Feature Matrix

### 120 features currently extracted (indices 0-119)

Organized by measurement category, not role:

**Callback/Timing (0-23):** Interval, jitter, SYN cycles, burst patterns, sleep regularity
**Control Persistence (24-47):** Connection duration, lifetime, churn rate, IO balance, integrity
**Relay/Topology (48-72):** Inbound/outbound ratio, throughput symmetry, listener behavior, SMB, pipes
**Identity/Reputation (73-94):** Vendor, path, ASN, port diversity, process entropy
**Service/Exposure (95-116):** Listener ports, inbound clients, service context
**Cross-role (117-119):** OutLongLivedCount, ReconnectCount, IOActiveRatio

### Missing Features (recommended additions)

| Feature | What It Measures | Why It Matters |
|---------|-----------------|---------------|
| `control_same_target_churn` | Short-lived connections to SAME target (not diverse) | Distinguishes beacon reconnection from browser multi-fetch |
| `control_io_silence_ratio` | Fraction of observation time with zero IO | High for polling beacons, low for interactive sessions |
| `control_child_after_network` | Child process spawned within 5s of network IO | Strong indicator of command execution after task retrieval |
| `control_endpoint_rarity` | How rare the destination IP/prefix is across all monitored hosts | C2 infrastructure is rare; CDN is common |
| `control_connection_state_transitions` | Count of ESTABLISHED → closed → ESTABLISHED cycles | Direct measurement of reconnection behavior |

---

## F. Role Disambiguation Matrix

| Feature | control-channel | control-pivot | listener | outbound |
|---------|----------------|---------------|----------|----------|
| OutExternal > 0 | **yes** | maybe | no | **yes** |
| OutInternal > 0 | no | **yes** | no | no |
| Listener present | no | **yes** | **yes** | no |
| InboundTotal > 0 | no | **yes** | **yes** | no |
| Known vendor | no | no | varies | **yes** |
| Suspicious path | **yes** | varies | no | no |
| Throughput symmetry | low | **high** | n/a | low |
| Fan-out from listener | n/a | **>0** | 0 | n/a |
| Named pipe C2 | no | **possible** | no | no |
| SMB to internal | no | **possible** | no | no |

---

## G. Signal Effectiveness Repair Plan

### Root Cause: Signal Learning Is Starved

The signal effectiveness tracker requires **50 observations + 70% role stability** before a process contributes TP/FP data. This excludes ~90% of processes, starving the learning system.

### Fixes

**1. Lower signal learning gate**
- Current: 50 obs + 70% stability
- Proposed: **20 obs + 50% stability**
- Location: `experience.go:202`
- Impact: 3-5x more processes contribute signal data

**2. Use operator labels immediately for signal stats**
- When an operator labels a process, immediately update all signal TP/FP counts for that process's signals
- Current: operator labels only affect training, not signal stats
- Location: `experience.go:188` — add early return for operator-labeled processes

**3. Track per-signal role distribution (not just TP/FP)**
- For each signal, track: how often it fires on control-channel vs outbound vs listener vs pivot
- A signal that fires 50% on control-channel and 50% on outbound is useless
- A signal that fires 90% on control-channel and 10% on outbound is discriminative
- Location: `model.go` SignalStat struct — add per-role counters

**4. Demote signals below precision threshold**
- If a signal's precision drops below 20% over 1000+ samples, demote it from the controlSignals map
- Add to ML-only features instead (can still contribute in combination)
- Location: `roles.go` — dynamic signal demotion based on model.SignalStats

---

## H. Collection and Shadowing Redesign

### Current Problems

1. **5-minute dedup window** discards temporal dynamics — a process transitioning from benign to suspicious within 5 minutes becomes a single ambiguous record
2. **50-record buffer** triggers training too early — models train on tiny datasets
3. **50,000 observation baseline gate** is unreachable — most environments never get there
4. **Shadow agreement requires 80% match with rules** — creates circular logic where ML inherits rule errors
5. **200-500 observation analyzing hold** is far too long — processes sit in limbo

### Collection Redesign

**1. Reduce dedup window from 5 minutes to 1 minute**
- Preserves more temporal variation
- A 5m-interval beacon generates 1 record per 5 minutes instead of 1 per cycle — still deduped but retains transition points
- Location: `dataset.go:151` — change `/300` to `/60`

**2. Increase minimum buffer for training from 50 to 200**
- Ensures models train on meaningful dataset sizes
- Prevents early tiny-dataset training that produces unreliable models
- Location: `retrain.go:160`

**3. Lower baseline observation gate from 50,000 to 5,000**
- Reachable in hours instead of weeks
- Still requires significant observation before declaring stable
- Location: `maturity.go:356`

**4. Lower experience label gate from 10 obs + 70% stability to 10 obs + 50% stability**
- More processes contribute to training labels earlier
- Location: `dataset.go:132`

**5. Lower benign verdict from 500 obs to 100 obs**
- A process observed 100 times with <5% suspicious is reliably benign
- Location: `experience.go:146`

### Shadowing Redesign

**1. Shadow for at least 500 predictions before qualification**
- Current: 100 predictions
- Proposed: 500 predictions — ensures statistical significance
- Location: `maturity.go:283`

**2. Track per-role shadow agreement (not just global)**
- Current: single agreement rate across all roles
- Proposed: per-role agreement. ML must agree on control-channel specifically, not just outbound.
- Location: `maturity.go` — add per-class agreement counters

**3. Allow ML qualification at 70% agreement (not 80%)**
- 80% is too strict when rules are known to be imperfect
- ML should be allowed to IMPROVE on rules, not just match them
- Location: `maturity.go:283`

---

## I. ML Architecture

### Stage 1: Primary Role Classification (GBDT, 4 classes)

```
120 features → GBDT (300 rounds × 4 classes = 1200 trees) → softmax probabilities
→ [P(outbound), P(listener), P(control-channel), P(control-pivot)]
```

Assign top-probability role when confidence >= 0.40.

### Stage 2: Sub-Mode Scoring (rule-based, post-classification)

After assigning control-channel:

```
polling_score = sum of:
  +3 if beacon_interval_ms_confirmed > 0
  +2 if beacon_reconnect_count > 0
  +2 if beacon_out_long_lived_count == 0
  +2 if beacon_sleep_regularity > 0.5
  +1 if beacon_io_read_ratio > 0.55

interactive_score = sum of:
  +3 if session_control_duration_sec > 60
  +2 if beacon_out_long_lived_count >= 1
  +2 if session_io_active_ratio > 0.3
  +2 if session_child_process_count > 0
  +1 if session_io_burstiness > 1.0
```

Sub-mode: polling-like / interactive-like / mixed (informational only)

### Confidence and Rejection

- Top probability >= 0.40: accept prediction
- Top probability < 0.40: defer to rule-based inference
- Second-best probability within 0.15 of top: flag as uncertain

---

## J. Training Pipeline Design

### Dataset Schema

```json
{
  "schema": "proxywatch-training-v2",
  "features": { /* 120 values */ },
  "signals": ["..."],
  "rule_role": "control-channel",
  "operator_label": "control-channel",
  "experience_role": "control-channel",
  "experience_stability": 0.85,
  "label_source": "operator",
  "sub_mode": "polling-like"
}
```

### Label Priority

```
1. Operator (weight 5.0) — explicit assignment
2. User verdict (weight 3.0) — kill/whitelist
3. Experience (weight 2.0) — 10+ obs, 50%+ stability
4. Rule (weight 1.0) — InferRoleFromSignals
5. Default (weight 0.5) — outbound
```

### Quality Gates

| Gate | Current | Proposed |
|------|---------|----------|
| Min buffer for training | 50 | 200 |
| Dedup window | 5 min | 1 min |
| Experience label gate | 10 obs + 70% stability | 10 obs + 50% stability |
| Benign verdict | 500 obs + <5% suspicious | 100 obs + <5% suspicious |
| Signal learning gate | 50 obs + 70% stability | 20 obs + 50% stability |
| ML shadow predictions | 100 | 500 |
| ML agreement threshold | 80% | 70% |
| Baseline observations | 50,000 | 5,000 |

### Training Frequency

| State | Cooldown | Trigger |
|-------|----------|---------|
| COLD | 2 min | operator label OR buffer >= 200 |
| LEARNING | 3 min | buffer growth >= 100 since last train |
| STABLE | 5 min | buffer growth >= 200 since last train |
| CALIBRATED | 10 min | operator label OR significant drift |

### Evaluation Per Retrain

- Per-role precision, recall, F1
- Confusion matrix (4×4)
- Signal importance ranking (top 20 features)
- Shadow agreement rate (global + per-role)
- Confidence distribution histogram

---

## K. Example Scoring Outputs

### Sliver Beacon (5m interval)
```json
{
  "role": "control-channel",
  "confidence": 0.78,
  "sub_mode": "polling-like",
  "signals": ["beacon-non-standard-port", "beacon-no-children", "session-asn-mismatch", "session-rare-parent-network"],
  "evidence": "Unknown vendor from C:\\Users\\ops\\Downloads, HTTPS to non-vendor ASN, rare parent chain"
}
```

### Sliver Session (persistent)
```json
{
  "role": "control-channel",
  "confidence": 0.82,
  "sub_mode": "interactive-like",
  "signals": ["session-control-channel-persistent", "beacon-http-channel", "session-asn-mismatch", "session-rare-parent-network"],
  "evidence": "Persistent control to Cloudflare:443, unknown vendor, bidirectional IO"
}
```

### SSH SOCKS Proxy
```json
{
  "role": "control-pivot",
  "confidence": 0.95,
  "signals": ["pivot-ssh-tunnel-flags"],
  "evidence": "SSH with -D flag, loopback listener, forwarding to internal targets"
}
```

---

## L. Implementation Roadmap

### Phase 1: Already Done
- [x] Merged control-beacon + control-session → control-channel (4 classes)
- [x] Unified controlSignals map (33 signals)
- [x] Signal emission gates (!IsKnownVendorProcess, !knownGood)
- [x] Role stability in no-ML fallback (5-min demotion cooldown)
- [x] Tunneling restricted to control-channel + control-pivot
- [x] Listener → control-pivot promotion on child tunnel evidence
- [x] 3 new ML features (OutLongLivedCount, ReconnectCount, IOActiveRatio)
- [x] 2 new signals (beacon-short-lived-callback, session-internal-control)

### Phase 2: Signal Effectiveness Fix (NEXT)
- [ ] Lower signal learning gate: 50→20 obs, 70%→50% stability
- [ ] Demote low-effectiveness signals from rule inference to ML-only
- [ ] Track per-signal role distribution
- [ ] Operator labels immediately update signal stats

### Phase 3: Collection & Training Quality (NEXT)
- [ ] Reduce dedup window 5min→1min
- [ ] Increase min training buffer 50→200
- [ ] Lower baseline gate 50,000→5,000
- [ ] Lower experience stability gate 70%→50%
- [ ] Lower benign verdict 500→100 obs
- [ ] Shadow 500 predictions before qualification (was 100)
- [ ] ML qualification at 70% agreement (was 80%)

### Phase 4: Sub-Mode Scoring
- [ ] Compute polling_score / interactive_score from features
- [ ] Store in ControlSubtype
- [ ] Display in inspector ("control-channel: polling-like")

### Phase 5: New Features
- [ ] control_same_target_churn
- [ ] control_io_silence_ratio
- [ ] control_child_after_network
- [ ] control_endpoint_rarity
- [ ] control_connection_state_transitions

### Phase 6: Continuous Improvement
- [ ] Per-role confusion matrix in retrain evaluation
- [ ] Feature importance tracking
- [ ] Shadow agreement per role
- [ ] Automated signal demotion when precision < 20%
