# ProxyWatch API Reference

ProxyWatch exposes three distinct HTTP APIs for introspection and control:

1. **Debug API** — live classifier state (candidates, roles, signals, FP-report traces). Enabled with `-debug-api ADDR`.
2. **Agent Debug API** — per-agent introspection when running in connect (agent) mode. Enabled with `-agent-debug-api ADDR`.
3. **Contour API** — tunnel status + protocol verification when running headless Contour. Enabled with `-contour-api ADDR`.

All APIs speak JSON. None are authenticated — bind them only to trusted interfaces (e.g. `127.0.0.1:PORT` or a management VLAN). Responses always set `Content-Type: application/json`.

---

## 1. Debug API (local / server mode)

Exposes the detection state of the host ProxyWatch is running on (local mode) or all connected agents (server mode). This is the primary API for operator tooling, regression testing, and CI diffing.

### Enabling

```bash
# Local monitoring with debug API
sudo ./proxywatch-linux-amd64 -debug-api 127.0.0.1:7890

# Server (ingest) mode with debug API
sudo ./proxywatch-linux-amd64 -listen 0.0.0.0:50051 -debug-api 127.0.0.1:7890
```

**Where it lives:** [`internal/detection/output/debug_api.go`](../proxywatch/internal/detection/output/debug_api.go).

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Health / cycle counter. |
| `GET` | `/candidates` | All classified candidates with filter support. |
| `GET` | `/candidate/<pid>` | Single candidate by PID. |
| `GET` | `/metrics` | Role + state histograms, classifier counters. |
| `GET` | `/agents` | Connected agents (server mode only). |
| `GET` | `/agent/<host>/...` | Per-agent sub-views (server mode only). |
| `GET` | `/diff/<baseline>` | Diff current state against a stored baseline. |
| `GET` | `/fp-report` | FP-verdict trace per candidate (signals, reasons, online evidence, tier-2 preserves). |
| `GET` | `/fp-report/<filter>` | Filtered FP report. |
| `GET` | `/online/status` | Online-verification (Authenticode OCSP) runtime status. |
| `GET` | `/online/verdict/<sha256>` | Online-verification verdict for a specific executable hash. |
| `GET` | `/operator/labels` | List all operator training labels. |
| `POST` | `/operator/label` | Create or update an operator label. |
| `GET` | `/operator/label/<sha256>` | Fetch a single operator label by hash. |
| `DELETE` | `/operator/label/<sha256>` | Clear an operator label. |

### `GET /`

Liveness + a classifier tick counter. Useful for CI to confirm the binary is up and classifying before running tests.

```json
{
  "ok": true,
  "cycle": 4143,
  "host": "DEMO",
  "updated": "2026-04-15T15:12:41Z",
  "candidates": 24,
  "server": false
}
```

### `GET /candidates`

Returns the current classified-candidate slice with optional filters.

**Query parameters:**

| Param | Meaning | Example |
|---|---|---|
| `name` | Substring match on process name (case-insensitive) | `?name=sshd` |
| `role` | Exact match on role or role family | `?role=control-pivot` |
| `state` | Substring match on state | `?state=tunneling` |
| `pid` | Exact PID | `?pid=9556` |

Combine filters with `&`. Example:

```bash
curl -s 'http://127.0.0.1:7890/candidates?role=control-pivot&state=tunneling' | jq
```

**Response schema (per item):**

Key fields on each candidate. See [`CandidateSnapshot`](../proxywatch/internal/detection/output/debug_api.go) for the full list.

```json
{
  "cycle": 4143,
  "host": "DEMO",
  "updated": "2026-04-15T15:12:41Z",
  "count": 1,
  "items": [
    {
      "pid": 9556,
      "name": "sshd.exe",
      "exe_path": "C:\\Windows\\System32\\OpenSSH\\sshd.exe",
      "cmd": "C:\\Windows\\System32\\OpenSSH\\sshd.exe -z",
      "user": "DEMO\\ops",
      "parent_pid": 7008,
      "role": "control-pivot",
      "role_family": "control-pivot",
      "state": "tunneling",
      "score": 72,
      "confidence": 88,
      "active_proxying": true,
      "strong_evidence": true,
      "traffic_verified": false,
      "signals": ["pivot-non-loopback-internal", "outbound-system-path"],
      "reasons": ["Pivot active (58s left): internal forwarding in relay context — TCP relay → 172.16.1.2:22"],
      "inbound_total": 0,
      "out_total": 1,
      "out_external": 0,
      "out_internal": 1,
      "out_loopback": 0,
      "seen_seconds": 173,
      "listener_count": 0,
      "conn_count": 1,
      "io_read_bps": 0,
      "io_write_bps": 1024,
      "ml_role": "outbound",
      "ml_confidence": 0.83,
      "suggested_role": "outbound"
    }
  ]
}
```

### `GET /candidate/<pid>`

Single candidate by PID. Returns `404` if not found.

```bash
curl -s http://127.0.0.1:7890/candidate/9556 | jq
```

### `GET /metrics`

Role histogram, state histogram, and top-level classifier counters. Suitable for scraping into a dashboard.

```json
{
  "cycle": 4143,
  "role_counts":  { "control-channel": 4, "control-pivot": 2, "outbound": 18, "listener": 1 },
  "state_counts": { "watch": 22, "tunneling": 2, "exited": 1 },
  "candidates":   25
}
```

### `GET /agents` / `GET /agent/<host>/...` (server mode only)

Lists connected agents and exposes their per-agent views. Returns `{"error":"not server mode"}` with HTTP 404 when running locally without `-listen`.

Sub-paths under `/agent/<host>/`:

- `/agent/<host>/candidates`
- `/agent/<host>/candidate/<pid>`
- `/agent/<host>/fp-report`

### `GET /diff/<baseline-name>`

Diff current state against a stored baseline. Used for regression checks during rule development — after making a classifier change, compare output against the previous baseline to see which candidates shifted role or score.

### `GET /fp-report` / `GET /fp-report/<filter>`

Per-candidate FP-verdict trace. Each entry carries the full rationale for the role/score assignment: signals, reasons, trust evidence, tier-2 preserves, FP-shape blockers, would-suppress flags. This is the authoritative endpoint for "why was this process classified as X?".

Key fields (see [`FPReportEntry`](../proxywatch/internal/detection/output/debug_api.go#L480)):

```json
{
  "pid": 1672,
  "name": "cheerful_glove.exe",
  "role": "control-channel",
  "score": 100,
  "signals": ["pivot-multiplex-relay", "pivot-reverse-tunnel-shape", "outbound-known-vendor"],
  "reasons": ["Persistent reverse control channel detected"],
  "sha256": "…",
  "known_vendor_path": false,
  "signed": false,
  "authenticode_trust": "untrusted",
  "authenticode_publisher": "",
  "authenticode_ocsp_checked": false,
  "online_known_benign": false,
  "online_known_malicious": false,
  "publisher_dns_aligned": false,
  "benign_control_client": false,
  "traffic_verified": true,
  "strong_evidence": true,
  "active_proxying": true,
  "fp_shape_score": 0,
  "fp_shape_blockers": ["state:strong-evidence"],
  "would_suppress": false,
  "tier2_preserved": false,
  "has_internal_conn": true,
  "has_non_loopback_listener": false,
  "conn_internal_remotes": 4,
  "conn_external_remotes": 1,
  "tunneling_state": true
}
```

### `GET /online/status`

Online-verification runtime state — current posture (`live` / `cache-only` / `off`), how many entries are in the reputation cache, last OCSP fetch time, OCSP error counter.

Live verification is the default posture on all platforms. On Windows, it runs full Authenticode + OCSP through the WinTrust API. On Linux/macOS, it falls back to path + ownership trust hints. Operators can override via `PROXYWATCH_ONLINE_VERIFY`:

- unset, `live`, `on`, `1`, `true` — default, run live verification.
- `cache-only`, `offline` — read the persisted reputation cache but make no outbound calls. Use in air-gapped environments.
- `off`, `0`, `false`, `disable` — fully disabled.

### `GET /online/verdict/<sha256>`

Returns the online-verification verdict for an executable hash. Returns `404` if the hash isn't in the cache.

### `GET /operator/labels`

Lists all operator training labels currently persisted.

```json
{
  "count": 3,
  "labels": [
    { "sha256": "abc…", "verdict": "malicious", "reason": "sliver beacon", "created_at": "2026-04-10T10:00:00Z" }
  ]
}
```

### `POST /operator/label`

Create or update an operator label by SHA-256 hash.

**Body:**

```json
{
  "sha256": "a1b2c3…",
  "verdict": "benign",
  "reason": "internal ops tool"
}
```

`verdict` must be one of `benign`, `malicious`, `session`, `beacon`, `tunnel`, `pivot`. Response:

```json
{ "ok": true, "label": { "sha256": "…", "verdict": "benign", "reason": "…" } }
```

Labels flow into the ML training pipeline on the next retrain cycle. Useful for suppressing an internal red-team binary that keeps tripping as `control-channel`.

### `GET /operator/label/<sha256>`

Fetch a single label by hash. `404` if not found.

### `DELETE /operator/label/<sha256>`

Clear an operator label. The next retrain will drop its contribution from the training data.

```bash
curl -XDELETE http://127.0.0.1:7890/operator/label/a1b2c3…
```

---

## 2. Agent Debug API (remote agents)

When ProxyWatch runs in connect (agent) mode — `-connect <server>:50051` — this API exposes the agent's local classification state on the agent host itself. The server's main `/debug-api` already aggregates all agents, so this is mainly for debugging what the *agent* sees before it streams to the server.

### Enabling

```bash
./proxywatch-windows-amd64.exe -connect 10.0.0.5:50051 -agent-debug-api 127.0.0.1:7891
```

**Where it lives:** [`internal/agent/debug.go`](../proxywatch/internal/agent/debug.go).

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Health + agent identity. |
| `GET` | `/candidates` | Agent's current classified candidates (same shape as debug-api). |
| `GET` | `/candidate/<pid>` | Single candidate by PID. |
| `GET` | `/diff` | Diff agent-local vs last-streamed-to-server. |
| `GET` | `/fp-report` | Agent's local FP-report. |

Schemas mirror the main debug API. Use this when you suspect the agent→server stream is lossy or transforming data.

---

## 3. Contour API (headless tunnel client / server)

Exposes Contour's tunnel state and protocol verification when running the tunnel headless — i.e. without the TUI. Relevant only if you're driving Contour programmatically.

### Enabling

```bash
# Headless contour server with API
./proxywatch-linux-amd64 -contour-server -contour-api 127.0.0.1:7892 -contour-ports 8080

# Headless contour client with API
./proxywatch-windows-amd64.exe -contour-client 10.0.0.5 -contour-api 127.0.0.1:7892 -contour-ports 8080
```

**Where it lives:** [`internal/contour/api/api.go`](../proxywatch/internal/contour/api/api.go).

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Health. |
| `GET` | `/protocols` | List supported tunnel protocols. |
| `GET` | `/status` | Active tunnel status (running, role, protocol, ports, direction, target, recent log lines). |
| `POST` | `/tunnel/start` | Start a tunnel. |
| `POST` | `/tunnel/stop` | Stop the active tunnel. |
| `GET` | `/verify/<protocol>` | Verify tunnel protocol behavior (wire signature checks). `GET /verify/all` runs the full matrix. |

### `GET /protocols`

```json
{
  "protocols": ["http", "https", "ws", "dns", "ssh", "smtp", "ftp", "redis", "postgres", "socks5"]
}
```

### `GET /status`

```json
{
  "running": true,
  "role": "server",
  "proto": "http",
  "direction": "Forward",
  "ports": [8080],
  "target": "",
  "log_tail": ["client connected 10.0.0.10", "frame 1 relayed 1.2 KB"]
}
```

### `POST /tunnel/start`

**Body:**

```json
{
  "role": "server",
  "proto": "http",
  "direction": "Forward",
  "ports": [8080, 8443],
  "target": "10.0.0.5"
}
```

Returns `409` if a tunnel is already running.

### `POST /tunnel/stop`

Cancels the active tunnel context. Returns `{"ok": true}` or `404` if nothing is running.

### `GET /verify/<protocol>`

Runs the wire-signature validation for a single protocol. `/verify/all` runs every protocol in `/protocols` and returns a matrix of pass/fail with per-check detail. Verification can take up to ~120s for the full matrix — the API uses a 120s write timeout accordingly.

---

## Common usage patterns

### Poll for tunneling during a scan

```bash
# Start a scan through a SOCKS tunnel in the background, poll for tunneling state
( for i in $(seq 1 20); do
    curl -s 'http://127.0.0.1:7890/candidates?name=sshd' | jq '.items[] | {pid, role, state, ap:.active_proxying}'
    sleep 1
  done ) &
proxychains4 -f /etc/proxychains4.conf nmap -sT -p 1-500 172.16.1.130
wait
```

### Capture a baseline for regression diffing

```bash
curl -s http://127.0.0.1:7890/fp-report > baseline-before.json
# … apply classifier changes …
curl -s http://127.0.0.1:7890/fp-report > baseline-after.json
diff <(jq -S . baseline-before.json) <(jq -S . baseline-after.json) | less
```

### Train an operator label from a trusted internal binary

```bash
HASH=$(sha256sum /path/to/internal-tool | awk '{print $1}')
curl -X POST http://127.0.0.1:7890/operator/label \
  -H 'Content-Type: application/json' \
  -d "{\"sha256\":\"$HASH\",\"verdict\":\"benign\",\"reason\":\"internal ops tool\"}"
```

---

## Security considerations

- **No built-in auth.** Bind the debug APIs only to `127.0.0.1` or a management interface.
- **Reverse-proxy for remote access.** If you need remote access (e.g. SOC tooling), put the API behind an authenticated reverse proxy (nginx + mTLS, Tailscale ACL, etc.).
- **Operator-label mutation is write-access to the ML training set.** Treat `POST /operator/label` and `DELETE /operator/label/<hash>` endpoints as administrative — an attacker that can write labels can teach the classifier to suppress their own tooling.
- **Don't expose the contour API publicly.** `POST /tunnel/start` lets callers open tunnels from the host; that's appropriate for operator driving but not for untrusted reachability.

---

## Changelog

| Version | Change |
|---|---|
| v1.0.6 | Added `/online/status`, `/online/verdict/<hash>`, `/operator/labels`, `/operator/label`, `/operator/label/<hash>`. `tunneling_state` in `/fp-report` now reflects strict real-time flow gate, not topology. |
| v1.0.5 | Added `/diff/<baseline>`, services reachability fields in contour API. |
| v1.0.4 | `/candidates` filter query parameters added. |

> ⚠️ Significant portions of this documentation were authored with AI assistance and may not cover every response field. Authoritative source is the code — see the linked files in each section.
