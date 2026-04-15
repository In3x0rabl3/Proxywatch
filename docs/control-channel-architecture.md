# Control-Channel Detection Architecture v2

## A. Revised Taxonomy

| Role | Description | ML Class Index |
|------|-------------|---------------|
| **control-channel** | C2 communication — beaconing, interactive sessions, or hybrid | 2 |
| **control-pivot** | Traffic relay — SOCKS tunnels, TCP forwards, SMB pipes | 3 |
| **listener** | Network service — accepts inbound, no outbound relay | 1 |
| **outbound** | Normal application traffic — known vendors, standard behavior | 0 |

**4 classes.** No beacon/session split at the role level.

---

## B. Formal Definition of Control-Channel

### What it is

A control-channel is a process-level communication relationship where a remote operator (or automated C2 server) controls the behavior of a local process. The local process:

1. Maintains connectivity to one or a small number of external endpoints
2. Receives instructions (tasking) via that connectivity
3. Executes instructions locally (spawns processes, reads files, moves laterally)
4. Reports results back via the same or related connectivity

### What qualifies as control-channel activity

Any of these patterns, observed on an unknown-vendor process:
- Persistent outbound connection to external endpoint with bidirectional IO
- Periodic reconnection to the same external endpoint(s)
- Short-lived outbound connections with regular or jittered timing
- Long-lived connection with bursty IO (command-response cadence)
- Outbound connection with subsequent child process spawning
- Connection to non-vendor-aligned ASN from user-writable path
- Delegated egress (process has no direct sockets but another process brokers its traffic)

### How it differs from other roles

| Comparison | Control-Channel | Other Role |
|-----------|----------------|------------|
| vs **Pivot** | Connects to external C2, executes locally | Relays traffic between endpoints. Has listener + outbound to internal targets. Throughput symmetry (relay, not generate). |
| vs **Listener** | Initiates outbound connections | Only accepts inbound. No outbound relay. |
| vs **Outbound** | Unknown vendor, suspicious path, non-standard behavior | Known vendor, system path, ASN-aligned, standard ports |

### How beacon-like and session-like behavior fit

Both are sub-modes of the same role:

| Sub-mode | Network Pattern | IO Pattern | Process Pattern |
|----------|----------------|------------|-----------------|
| **Polling-like** | Short-lived reconnections, sleep gaps, jittered intervals | Read-dominant (fetching tasking), small payloads | No children, idle between callbacks |
| **Interactive-like** | Persistent connection, continuous | Bidirectional, bursty (command-response) | May spawn children, higher CPU |
| **Mixed/Adaptive** | Switches between persistent and polling | Varies | Varies — starts polling, becomes interactive on tasking |
| **Long-lived low-volume** | Single persistent connection, minimal IO | Micro-payload keepalives | Idle, waiting for tasking |

These sub-modes are **scored as attributes**, not assigned as roles.

---

## C. Old → New Role Mapping

| Old Role | New Role | Notes |
|----------|----------|-------|
| control-session | control-channel | Merged |
| control-beacon | control-channel | Merged |
| control-channel (legacy) | control-channel | Name reused |
| control-pivot | control-pivot | Unchanged |
| control-tunnel | control-pivot | Legacy alias |
| tunnel | control-pivot | Legacy alias |
| smb-pipe | control-pivot | Legacy alias |
| listener | listener | Unchanged |
| outbound | outbound | Unchanged |

---

## D. Rule Audit and Migration

### Signals that remain unchanged (33 control-channel signals)

All former beacon-* and session-* signals now contribute to a single `controlSignals` map. Each signal fires based on its behavioral condition and increments `controlHits`:

**Callback/timing signals (16):**
`beacon-interval-confirmed`, `beacon-syn-cycle-cadence`, `beacon-target-lock`, `beacon-http-channel`, `beacon-endpoint-rotation`, `beacon-non-standard-port`, `beacon-reconnecting-unknown-vendor`, `beacon-sleep-wake-cycle`, `beacon-micro-payload`, `beacon-low-cpu-long-life`, `beacon-io-read-dominant`, `beacon-no-children`, `beacon-crypto-lib-loaded`, `beacon-memory-stable`, `beacon-thread-minimal`, `beacon-short-lived-callback`

**Persistent control signals (17):**
`session-control-channel-persistent`, `session-single-target-persistence`, `session-pre-existing-control`, `session-interactive-io-balance`, `session-conn-churn`, `session-exfil-write-heavy`, `session-asn-mismatch`, `session-shell-spawn`, `session-lolbin-children`, `session-elevated-external`, `session-encoding-in-cmdline`, `session-bursty-io-pattern`, `session-rare-parent-network`, `session-covert-channel`, `session-impersonation-token`, `session-rwx-memory`, `session-internal-control`

### Signal emission gates (already implemented)

| Signal | Gate | Prevents FP on |
|--------|------|---------------|
| beacon-http-channel | !IsKnownVendorProcess | HTTPS apps |
| beacon-no-children | !IsKnownVendorProcess | svchost, WebView2 |
| beacon-crypto-lib-loaded | !IsKnownVendorProcess | every TLS process |
| beacon-thread-minimal | !IsKnownVendorProcess | lightweight services |
| beacon-target-lock | OutLongLived >= 1 | transient CDN fetches |
| pivot-high-handle-count | !IsKnownVendorProcess | browsers |
| session-asn-mismatch | !knownGood | CDN-hosted vendor apps |
| session-control-channel-persistent | ControlDuration >= 30s, !knownGood | vendor persistent connections |

### Rules removed

| Old Logic | Why Removed |
|-----------|-------------|
| `ControlDurationSeconds >= 60` forces session subtype | HTTPS keep-alive makes beacons look persistent |
| Beacon/session tie-break logic | No separate roles to tie-break |
| `decisiveBeacon` as separate role override | Returns "control-channel" now (same as any control) |

### Inference logic (current state)

```go
// InferRoleFromSignals — simplified after merge
controlHits, pivotHits, outboundHits, listenerHits := count signals

if decisivePivot → "control-pivot"
if outboundHits >= (controlHits + pivotHits) → "outbound"
if controlHits + pivotHits > 0:
    if pivotHits >= controlHits → "control-pivot"
    else → "control-channel"
if listenerHits > 0 → "listener"
default → "outbound"
```

---

## E. Control-Channel Feature Matrix (120 features, indices 0-119)

### Callback/Timing Features (indices 0-23)

These features capture polling-like behavior patterns. Extracted for ALL candidates, not just "beacons":

| Index | Name | What It Measures |
|-------|------|-----------------|
| 0 | beacon_interval_ms_confirmed | Confirmed callback interval (ms) |
| 1 | beacon_jitter_cov | Jitter coefficient of variation |
| 2 | beacon_syn_cycle_count | SYN cycling events |
| 3 | beacon_callback_success_rate | ESTABLISHED / SYN attempts |
| 4 | beacon_target_stability | Target IP consistency |
| 5 | beacon_port_consistency | Always same dest port |
| 6 | beacon_ssl_likely | Uses 443/8443 |
| 7 | beacon_multi_target | Failover across IPs |
| 8 | beacon_conn_per_burst | Connections per cycle |
| 9 | beacon_drift_rate | Interval trend |
| 10 | beacon_interval_autocorr | Periodicity strength |
| 11 | beacon_hits_count | Confirmed burst count |
| 12 | beacon_io_per_second_avg | Total IO / age |
| 13 | beacon_io_read_ratio | Read / total |
| 14 | beacon_payload_size_mean | Avg bytes per burst |
| 15 | beacon_sleep_regularity | Silence period consistency |
| 16 | beacon_burst_silence_shape | Burst-to-silence ratio |
| 17 | beacon_cpu_to_age_ratio | CPU seconds / age |
| 18 | beacon_memory_variance | Working set variance |
| 19 | beacon_child_count | Child processes |
| 20 | beacon_has_crypto_lib | Crypto library loaded |
| 21 | beacon_jitter_entropy | Interval difference entropy |
| 22 | beacon_long_interval | Interval >= 5min |
| 23 | beacon_io_zero_periods | Cycles with zero IO |

### Persistent Control Features (indices 24-47)

These features capture interactive-like behavior. Extracted for ALL candidates:

| Index | Name | What It Measures |
|-------|------|-----------------|
| 24 | session_control_duration_sec | Control channel hold time |
| 25 | session_conn_lifetime_max_sec | Longest ESTABLISHED connection |
| 26 | session_distinct_targets | Unique external targets |
| 27 | session_external_conn_count | External connections |
| 28 | session_conn_churn_rate | Connections per minute |
| 29 | session_io_write_ratio | Write / total |
| 30 | session_asn_mismatch | Vendor/ASN alignment |
| 31 | session_pre_existing | Connections on first observation |
| 32 | session_control_channel_age_sec | Oldest connection age |
| 33 | session_internal_conn_count | Internal connections |
| 34 | session_io_current_rate | Instantaneous IO rate |
| 35 | session_io_rw_balance | Read/write ratio |
| 36 | session_io_burstiness | IO rate variance |
| 37 | session_integrity_level | Privilege level |
| 38 | session_cmd_length | Command line length |
| 39 | session_cmd_has_encoded | Encoded content flag |
| 40 | session_child_process_count | Children spawned |
| 41 | session_child_is_lolbin | Children are system binaries |
| 42 | session_delegated_egress_strong | Delegated egress flag |
| 43 | session_parent_score | Parent detection score |
| 44 | session_rare_parent | Rare parent-child combo |
| 45 | session_cpu_to_io_ratio | CPU per MB IO |
| 46 | session_io_other_ratio | IOOther fraction |
| 47 | session_idle_active_ratio | Idle vs active cycles |

### Cross-Role Disambiguation Features (indices 117-119)

| Index | Name | What It Measures |
|-------|------|-----------------|
| 117 | beacon_out_long_lived_count | Long-lived outbound connections (0 = polling-like) |
| 118 | beacon_reconnect_count | Short-lived reconnections (high = polling-like) |
| 119 | session_io_active_ratio | Active IO fraction (high = interactive-like) |

### Sub-Mode Scoring (derived from features, not separate ML output)

After the ML assigns `control-channel`, these feature combinations indicate sub-mode:

**Polling-like indicators:**
- `beacon_interval_ms_confirmed > 0`
- `beacon_out_long_lived_count == 0`
- `beacon_reconnect_count > 0`
- `beacon_sleep_regularity > 0.5`
- `beacon_io_read_ratio > 0.55`
- `beacon_child_count == 0`

**Interactive-like indicators:**
- `session_control_duration_sec > 60`
- `beacon_out_long_lived_count >= 1`
- `session_io_active_ratio > 0.3`
- `session_io_rw_balance` between 0.3-3.0
- `session_child_process_count > 0`
- `session_io_burstiness > 1.0`

**Mixed/Adaptive:**
- Both polling and interactive indicators present
- Feature values between the two extremes

---

## F. Role Disambiguation Matrix

### Control-Channel vs Outbound

| Feature | Control-Channel | Outbound |
|---------|----------------|----------|
| IsKnownVendorProcess | false | true |
| SuspiciousPath | true (Downloads, Temp) | false (System, Program Files) |
| ASN alignment | mismatched | aligned |
| Signal count | controlHits > 0 | outboundHits >= suspTotal |
| Rare parent | true | false |

**Key rule:** If outbound signals >= suspicious signals, classify as outbound. Known-vendor gate prevents suspicious signals from firing on legitimate apps, so this rarely conflicts.

**FP trap:** CDN-hosted vendor apps with persistent connections. Prevented by !knownGood gate on session-asn-mismatch and !IsKnownVendorProcess on beacon signals.

### Control-Channel vs Control-Pivot

| Feature | Control-Channel | Pivot |
|---------|----------------|-------|
| Listener present | no | yes |
| Outbound to internal | no (or minimal) | yes (relay target) |
| InboundTotal | 0 | > 0 |
| Throughput symmetry | low (generates/consumes) | high (relays) |
| Fan-out from listener | n/a | > 0 |

**Key rule:** Presence of listener + outbound to internal = pivot. Control-channel has no listener component.

**FP trap:** Control-channel process that spawns children making internal connections. The children's connections are on the children's PIDs, not the control-channel's.

### Control-Channel vs Listener

| Feature | Control-Channel | Listener |
|---------|----------------|----------|
| Outbound connections | yes (to C2) | no |
| Listener present | no | yes |
| Connection direction | initiates outbound | accepts inbound |

**Key rule:** Listeners have zero outbound. If a listener also has outbound, it's a pivot.

### Control-Channel vs SOCKS Tunnel

| Feature | Control-Channel | SOCKS Tunnel |
|---------|----------------|--------------|
| Loopback listener | no | yes |
| Port diversity outbound | low (1-2 targets) | high (many ports/targets) |
| SOCKSCandidate signal | no | yes |
| SSH -D flag | no | possible |

### Control-Channel vs SMB Pivot

| Feature | Control-Channel | SMB Pivot |
|---------|----------------|-----------|
| Port 445 connections | no | yes (internal) |
| Named pipe C2 pattern | no | yes |
| Connection targets | external | internal only |

### Control-Channel vs Normal Applications

| Comparison | Discriminating Feature |
|-----------|----------------------|
| vs Browser | Browser has multi-external-cdn, known vendor, standard ports. Control-channel has suspicious path, single target, rare parent. |
| vs Software updater | Updater has known vendor, download-heavy IO (95%+ read), standard ports. Control-channel has bidirectional IO, non-standard timing. |
| vs Remote admin (RDP, TeamViewer) | Known vendor, system path, standard ports. Control-channel from user-writable path, unknown vendor. |
| vs Backup/sync | Known vendor, ASN-aligned, high-volume download. Control-channel has micro-payload, jittered timing. |
| vs Chat client | Known vendor, bidirectional but to vendor infrastructure. Control-channel to unknown infrastructure. |

---

## G. ML Architecture

### Stage 1: Primary Role Classification (GBDT, 4 classes)

**Input:** 120-feature vector extracted from candidate telemetry
**Output:** Probability distribution over 4 classes
**Algorithm:** Gradient-boosted decision trees (softmax cross-entropy)
**Classes:** outbound (0), listener (1), control-channel (2), control-pivot (3)

```
Features (120) → GBDT Ensemble (300 rounds × 4 classes = 1200 trees)
                                    ↓
                    Softmax → [P(outbound), P(listener), P(control-channel), P(control-pivot)]
                                    ↓
                    Top prediction + confidence
```

**Decision:** Assign top-probability role when confidence >= 0.40. Below threshold: defer to rule-based inference.

### Stage 2: Sub-Mode Scoring (rule-based, no separate model)

After ML assigns `control-channel`, compute sub-mode scores from features:

```
polling_score = weighted_sum(
    beacon_interval_ms_confirmed > 0:     +3
    beacon_reconnect_count > 0:           +2
    beacon_out_long_lived_count == 0:     +2
    beacon_sleep_regularity > 0.5:        +2
    beacon_io_read_ratio > 0.55:          +1
    beacon_child_count == 0:              +1
)

interactive_score = weighted_sum(
    session_control_duration_sec > 60:    +3
    beacon_out_long_lived_count >= 1:     +2
    session_io_active_ratio > 0.3:        +2
    session_child_process_count > 0:      +2
    session_io_burstiness > 1.0:          +1
    session_io_rw_balance in [0.3, 3.0]:  +1
)

sub_mode:
    if polling_score > interactive_score + 3: "polling-like"
    elif interactive_score > polling_score + 3: "interactive-like"
    else: "mixed/adaptive"
```

This is informational metadata stored in `ControlSubtype`, not a role decision.

### Confidence and Explainability

Each classification includes:
```json
{
    "role": "control-channel",
    "confidence": 0.82,
    "sub_mode": "polling-like",
    "top_signals": ["beacon-non-standard-port", "beacon-no-children", "session-rare-parent-network"],
    "signal_count": {"control": 5, "pivot": 0, "outbound": 0, "listener": 0},
    "alternatives_rejected": {
        "outbound": "0 outbound signals, 5 control signals",
        "control-pivot": "no listener, no internal targets"
    }
}
```

---

## H. Training Pipeline

### Dataset Schema

```json
{
    "schema": "proxywatch-training-v2",
    "timestamp": "2026-04-09T12:00:00Z",
    "host": "DEMO",
    "process_key": "...",
    "features": { /* 120 feature values */ },
    "signals": ["beacon-non-standard-port", "session-rare-parent-network"],
    "rule_role": "control-channel",
    "model_role": "control-channel",
    "model_confidence": 0.82,
    "operator_label": "control-channel",
    "sub_mode": "polling-like"
}
```

### Label Resolution Priority

```
1. Operator Label     (weight 5.0) — "control-channel", "control-pivot", "outbound", "listener"
2. User Verdict       (weight 3.0) — kill → "control-channel", whitelist → "outbound"
3. Experience         (weight 2.0) — stable behavioral consensus
4. Rule Role          (weight 1.0) — InferRoleFromSignals output
5. Default            (weight 0.5) — "outbound"
```

### Class Imbalance

```
Per-class weight = total_samples / (4 × class_count), capped at 20.0
Ensures control-channel and control-pivot (minority) get proportional influence
```

### Retrain Cycle

```
Trigger: operator label OR maturity-gated cooldown (2-10 min)
Buffer gate: minimum 50 records
Algorithm: GBDT, 300 rounds, max_depth=6, lr=0.1, subsample=0.8
Validation: per-role P/R/F1, confusion matrix
Hot-swap: new model replaces old atomically
```

### Per-Role Evaluation Targets

```
outbound:        P >= 0.95, R >= 0.90
listener:        P >= 0.90, R >= 0.85
control-channel: P >= 0.85, R >= 0.80
control-pivot:   P >= 0.80, R >= 0.75
```

### Confusion Pairs to Monitor

```
control-channel ↔ outbound: most common FP. Known-vendor gate is primary defense.
control-channel ↔ control-pivot: pivot has relay topology (listener + internal targets).
control-pivot ↔ listener: listener has no outbound relay.
```

---

## I. Example Scoring Outputs

### Sliver Beacon (LIQUID_MEZZANINE, 5m interval)

```
Role: control-channel
Confidence: 0.78
Sub-mode: polling-like (score: 8 polling, 2 interactive)
Signals: beacon-http-channel, beacon-no-children, beacon-non-standard-port,
         session-asn-mismatch, session-rare-parent-network
Evidence: Unknown vendor from C:\Users\ops\Downloads, HTTPS to Microsoft ASN,
          no children, rare parent chain
```

### Sliver Session (CHEERFUL_GLOVE, persistent connection)

```
Role: control-channel
Confidence: 0.81
Sub-mode: interactive-like (score: 3 polling, 7 interactive)
Signals: session-control-channel-persistent, beacon-http-channel,
         beacon-no-children, session-asn-mismatch, session-rare-parent-network
Evidence: Persistent control to Cloudflare:443 held 5m, unknown vendor from
          C:\Users\ops\Downloads, bidirectional IO, rare parent chain
```

### SSH Reverse Tunnel

```
Role: control-pivot
Confidence: 0.95
Signals: pivot-ssh-tunnel-flags (DECISIVE)
Evidence: SSH with -R flag, external connection established
```

### Microsoft Edge WebView2

```
Role: outbound
Confidence: 0.92
Signals: outbound-known-vendor, outbound-standard-ports-only,
         outbound-cdn-destination, outbound-system-path
Evidence: Known vendor (Microsoft Corporation), system path, HTTPS to CDN
          (no control signals fired due to IsKnownVendorProcess gate)
```

---

## J. Implementation Roadmap

### Done

- [x] Merged control-beacon + control-session → control-channel (4-class model)
- [x] Unified controlSignals map (33 signals)
- [x] Simplified InferRoleFromSignals (single controlHits counter)
- [x] Updated all 25+ files (scoring, UI, training, model, export)
- [x] Backward-compatibility for persisted data with old role names
- [x] Signal emission gates (!IsKnownVendorProcess, !knownGood)
- [x] Decisive signal overrides (SSH tunnel flags → pivot)
- [x] 3 new ML features (OutLongLivedCount, ReconnectCount, IOActiveRatio)
- [x] 2 new signals (beacon-short-lived-callback, session-internal-control)
- [x] 30-second analyzing phase (SeenSeconds-based)
- [x] Dashboard role display, ML status sync, baseline reset fixes

### Next

- [ ] Sub-mode scoring (polling_score / interactive_score) → stored in ControlSubtype
- [ ] Display sub-mode in inspector ("control-channel: polling-like")
- [ ] Per-role confusion matrix in retrain evaluation
- [ ] Feature importance tracking per retrain cycle
- [ ] Shadow agreement monitoring with per-role breakdown
