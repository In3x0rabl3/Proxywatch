# Detection Overview

How ProxyWatch classifies processes into control-centric roles.

## The role taxonomy

ProxyWatch assigns every process one of four roles based on observed behavior:

| Role | Hypothesis |
|---|---|
| **outbound** | Normal application traffic — known vendor, standard behavior. |
| **listener** | Network service — accepts inbound, no outbound relay. |
| **control-channel** | C2 communication — beaconing, interactive sessions, or hybrid. |
| **control-pivot** | Traffic relay — SOCKS tunnels, TCP port forwards, SMB named-pipe pivots. |

Sub-modes (`polling-like`, `interactive-like`, `mixed`) and pivot sub-types (`socks-tunnel`, `tcp-pivot`, `smb-pipe`) are recorded as metadata on the assigned role — they're *how* a process behaves, not *which* role it gets.

## What each role looks like

### Control-channel

The local process maintains connectivity to a small number of external endpoints, receives instructions via that connectivity, and reports results back. Two common sub-modes:

- **Polling-like** — connects, exchanges briefly, disconnects, sleeps. Small payloads. Read-dominant IO. No child processes. Jittered or regular intervals.
- **Interactive-like** — persistent connection held for minutes to hours. Bidirectional bursty IO. May spawn shell / LOLBin children as operator commands come in.

Distinguished from `outbound` by: unknown vendor, suspicious executable path (Downloads, Temp, AppData), ASN mismatch, rare parent process.

### Control-pivot

The process relays traffic between endpoints rather than generating or consuming it itself. Three sub-types:

- **SOCKS tunnel** — loopback listener + diverse outbound targets and ports. SSH `-D` is the canonical operator-side case.
- **TCP port forward** — listener mapped to a single internal target. SSH `-L` / `-R`.
- **SMB pipe** — outbound port 445 to internal targets, C2-pattern named pipes (`msagent_*`, `MSSE-*`, `postex_*`).

Distinguished from `control-channel` by: presence of listener + outbound to internal targets, throughput symmetry (bytes in ≈ bytes out), fan-out from listener.

### Listener

Pure service — accepts inbound, no outbound relay. May be legitimate (sshd, web servers, RPC) or malicious (bind shell, staged listener). If a listener also has outbound to internal targets it's reclassified as `control-pivot`.

### Outbound

Everything else. Known vendor, standard ports, ASN-aligned, system path. Most processes on a healthy host end up here.

## How roles are decided

Two classifiers run in parallel:

1. **Rule engine** (`internal/detection/scoring/rank.go`) — topology heuristics score the candidate and produce a suggested role. This is deterministic, explainable, and survives cold starts.
2. **ML predictor** (`internal/detection/gbdt/` + `internal/detection/ml/`) — an on-device LightGBM gradient-boosted tree model trained on a 122-feature behavioral vector. Runs in shadow mode until it qualifies via shadow-agreement and prediction volume, then becomes the primary role assigner. Retrains automatically from an observation buffer when the feature schema bumps.

When ML is primary, the rule engine's suggestion is retained as `SuggestedRole` for training data and fallback. Safety overrides: a high-confidence ML prediction (≥ 0.80) wins over single-heuristic topology flips; when ML is uncertain, topology wins.

### Time-lingered pivot promotion

SOCKS-forwarding processes are "pivots while traffic flows" — between scans they look like whatever they structurally are (sshd child → outbound, beacon → control-channel). When a relay-context process (own listener + inbound, ancestor listener + inbound, or already-a-control-role) emits the `pivot-non-loopback-internal` signal, its role is promoted to `control-pivot` for 60 seconds. After the window, role reverts naturally. The parent-chain walk handles Windows OpenSSH's privsep (`sshd_main → sshd_privsep → sshd_session`) where the intermediate helper is too short-lived to be classified on its own.

### Tunneling state

`state=tunneling` is shown only when bytes are *actively moving* through the tunnel:

- IO ≥ 512 B/s on an internal connection, OR
- A fresh internal connection within the 30s conn-recency window.

Topology alone (control-channel + internal target) is not enough. Stop the tool, state drops to `watch` the next poll.

## How roles are told apart

Headline discriminators:

| Question | Control-channel | Control-pivot | Listener | Outbound |
|---|---|---|---|---|
| Has listener? | No | Yes (often) | Yes | No |
| Has outbound? | Yes (to C2) | Yes (to internal relay) | No | Yes (to vendor) |
| Connects to internal? | No | Yes | No | No |
| Vendor aligned? | No | N/A | N/A | Yes |
| Path / ASN suspicious? | Often | Often | N/A | No |

Specific collisions the classifier handles:

- **Control-channel vs outbound.** Known-vendor / system-path / ASN-aligned gates suppress suspicious signals on legitimate apps. CDN-hosted vendor apps (Edge, Teams, Slack) stay `outbound`.
- **Control-channel vs control-pivot.** Presence of listener + outbound to internal = pivot. Control-channel has no listener.
- **Control-pivot vs listener.** A listener with outbound to internal is a pivot; a listener with zero outbound is just a service.
- **SOCKS tunnel vs TCP pivot.** SOCKS is dynamic (one listener, many destinations/ports); TCP pivot is static (one listener, one destination). Port diversity is the tell.
- **Malicious SMB pipe vs normal SMB.** Normal SMB is client → file server with predictable pipe names. C2 SMB uses recognizable naming patterns (`msagent_*`, `postex_*`) and targets workstations.

## False-positive suppression

Several layers, each a hard gate before a suspicious signal becomes a role:

1. **Signal emission gates** — most control-channel signals won't fire on processes that pass `IsKnownVendorProcess` or `IsKnownNetworkActive`. Example: `beacon-crypto-lib-loaded` is gated so it doesn't fire on every TLS app.
2. **Vendor FP-shape demotion** — specific vendor-behavior patterns (Edge telemetry, Chrome update, Microsoft telemetry) demote score before role assignment.
3. **Experience model** — processes with a stable benign history accumulate a committed role. The ML model holds that committed role unless behavior contradicts it (e.g. sudden inbound + internal relay).
4. **Operator labels** — persistent SHA-256-keyed verdicts (`benign`, `malicious`, `session`, `beacon`, `tunnel`, `pivot`) override classifier output and feed the next training cycle. Managed via `/operator/label` on the debug API.
5. **Whitelist** — on-disk list applied after classification to drop known-good processes from output entirely.

Tier-2 preserves (strong evidence states like `persistent-control`, `pivot-ssh-tunnel-flags`, `beacon-syn-cycle-cadence`) defeat the gates above so real C2 isn't suppressed.

## Worked examples

**Sliver beacon on a 5-minute jitter.**
Role: `control-channel` · sub-mode: polling-like · confidence: ~0.78. Evidence: unknown vendor from `C:\Users\ops\Downloads`, HTTPS to non-aligned ASN, no children, rare parent chain, periodic short-lived callbacks.

**Sliver session with persistent HTTPS to Cloudflare.**
Role: `control-channel` · sub-mode: interactive-like · confidence: ~0.81. Evidence: persistent control channel held > 5 min, unknown vendor from user-writable path, bidirectional IO, rare parent chain.

**SSH SOCKS tunnel (`ssh -D`).**
Role: `control-pivot` · sub-type: socks-tunnel · confidence: ~0.95. Decisive signal: `pivot-ssh-tunnel-flags` from the command line.

**Windows sshd child forwarding `nxc ssh` through a proxychains tunnel.**
Role: `control-pivot` (lingered) · state: `tunneling` while forwarded conn is alive, `watch` during inter-probe idle. Role held for 60 s after last forward. Evidence: `Pivot active (58s left): internal forwarding in relay context — TCP relay → 172.16.1.2:22`.

**Microsoft Edge WebView2.**
Role: `outbound` · confidence: ~0.92. Evidence: known vendor, system path, HTTPS to CDN. Control signals never fired because `IsKnownVendorProcess` gates short-circuited them.

## Where to look in code

| Concern | File |
|---|---|
| Role taxonomy and families | [`internal/shared/classify.go`](../proxywatch/internal/shared/classify.go), [`internal/detection/scoring/roles.go`](../proxywatch/internal/detection/scoring/roles.go) |
| Scoring + role assignment | [`internal/detection/scoring/rank.go`](../proxywatch/internal/detection/scoring/rank.go) |
| Behavior signal emitters | [`internal/detection/behavior/`](../proxywatch/internal/detection/behavior/) |
| Feature extraction | [`internal/detection/features/`](../proxywatch/internal/detection/features/) |
| ML predictor / trainer | [`internal/detection/gbdt/`](../proxywatch/internal/detection/gbdt/), [`internal/detection/ml/`](../proxywatch/internal/detection/ml/) |
| Pivot linger | [`internal/detection/scoring/child_tunnel.go`](../proxywatch/internal/detection/scoring/child_tunnel.go) |
| Tunneling state + candidate state | [`internal/shared/candidate.go`](../proxywatch/internal/shared/candidate.go) |
| Experience model / committed role | [`internal/detection/model/`](../proxywatch/internal/detection/model/) |

> ⚠️ Significant portions of this detection pipeline were authored with AI-pair-programming assistance. The live classifier is verified against a lab network, but internal specifics (signal names, feature indices, gate thresholds) drift between releases — treat this doc as conceptual and the code as authoritative.
