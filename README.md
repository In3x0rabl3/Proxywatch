# ProxyWatch

ProxyWatch is a Windows userland network inspection tool that labels processes by role (tunnels, proxies, beacons) using TCP/UDP state and process context. It does not require kernel drivers, ETW, or packet capture.

ProxyWatch is built to be tuned for your environment. See [Role triggers and tuning](#role-triggers-and-tuning) for the exact files and example edits.

ProxyWatch (Agent) is a service that runs on remote endpoints and streams the results into a central ProxyWatch UI. Each build generates a unique TLS/mTLS trust bundle so only agents built from the same build can connect. Security comes first.

## Demo

ProxyWatch ships with a Terminal User Interface (TUI) for process inspection and remote kill. Tune thresholds or whitelist software to reduce noise. BloodHound export is built in so you can map suspicious sessions, beacons, and tunnels to exact host, user, and binary paths.

![Demo](docs/media/Demo-latest.gif)

---

## Quick start (local)

Interactive TUI:
```bash
proxywatch.exe
```

Keys:
- `UP/DOWN` to select
- `ENTER` to inspect
- `ESC` to return to dashboard
- `w` to whitelist the selected process
- `W` to open the whitelist manager (remove entries)
- `k` to kill the inspected process
- `q` to quit

---

## Multi-endpoint mode (ProxyWatch Agent)

1) Start ProxyWatch in ingest mode:
```bash
proxywatch.exe -listen 0.0.0.0:50051
```

2) Run the agent on each endpoint:
```bash
pwa.exe -server 10.0.0.5:50051
```

Optional agent flags:
- `-id` Host identifier (default: hostname)

- `-interval` Refresh interval (default `250ms`)

- `-incremental` Reuse classification for unchanged PIDs

- `--install` Install the ProxyWatch Agent Windows service

- `--uninstall` Uninstall the service

- `--start` Start the service

- `--stop` Stop the service

- `--service` Run under SCM (service mode only)

Notes:
- The TUI dashboard FOR Proxywatch shows a HOST column for each endpoint.

- Kill is available for remote hosts when the agent is connected.

- Use `-stale 30s` to drop endpoints that stop reporting.

- Transport is gRPC over TCP with JSON framing and automatic TLS/mTLS (generated at build time).

- Agent and UI must be built together so they share the same trust bundle.

- In the TUI, you'll noticed a section called `Active` this field will only return true when traffic is actively passing.

---
## BloodHound collection

Collection is started from the TUI:
1) Press `c` to open the collection screen
2) Use `UP/DOWN` to select a field, `ENTER` to edit Output or Roles
3) Use `LEFT/RIGHT` to change Duration
4) Select `Start/Stop` and press `ENTER`
5) The JSON file is written when the timer ends (or press `ENTER` again to stop early)

Works for both local mode and ingest mode (`-listen`).

Cypher examples live in [queries.md](docs/queries.md).

### Automatic upload to BloodHound
- Set env vars (or build with ldflags):
  - `BLOODHOUND_API_URL` (e.g., `http://127.0.0.1:18080/api/v2`)
  - `BLOODHOUND_API_TOKEN` (API key or bearer token)
  - `BLOODHOUND_API_TOKEN_ID` (only for HMAC keys; leave empty for bearer)
- After a collection finishes, ProxyWatch uploads the JSON via `file-upload/start -> file-upload/{id} -> file-upload/{id}/end`.
- Content-Type is `application/json`; HMAC signing matches BloodHound docs (METHOD+URI → hour-truncated RequestDate → body).

Examples:

**Suspicious processes by user**

<img width="1517" height="487" alt="Screenshot from 2026-02-01 12-05-34" src="https://github.com/user-attachments/assets/cb593db7-214e-453a-9a15-a771599f2e37" />

---

**Suspicious internal connection with the information table**

<img width="1485" height="769" alt="Screenshot from 2026-02-01 12-08-27" src="https://github.com/user-attachments/assets/abe33759-1884-48a7-b575-4f16e61e6612" />

---

**Full connection chain for internal connections**

<img width="1577" height="602" alt="Screenshot from 2026-02-01 11-54-42" src="https://github.com/user-attachments/assets/fda21094-b2bc-46f3-990a-eefd767f1bea" />

---

## Features

- Behavior-based detection without signatures

- Role assignment for tunnels, proxies, and beacons

- Reverse-control and reverse-transport detection

- Listener and client mapping (TCP + UDP)

- Short-lived connection capture for fast scans

- TUI with per-process inspector and manual kill

- Multi-endpoint ingest with ProxyWatch Agent

- BloodHound collection output (JSON file)

---

## Roles

ProxyWatch assigns a best-fit role per process:

| Role                     | Meaning |
|--------------------------|---------|
| `susp-tun`               | Control channel with tunnel evidence (loopback transport or internal scan activity) |
| `susp-beacon`            | Periodic short-lived outbound beacons (for example ~60s callbacks) |
| `susp-session`           | Control channel without proxying evidence |
| `reverse-proxy`          | Control channel with proxied outbound activity |
| `reverse-transport`      | Control channel + active local forwarding (loopback) |
| `reverse-control`        | Persistent outbound control channel (idle) |
| `reverse-tunnel`         | Multiple outbound targets, no listener |
| `proxy-listener`         | Listener with clients + outbound forwarding |
| `listener-with-clients`  | Local clients without outbound |
| `listener-with-outbound` | Listener, no clients, outbound activity |
| `listener-only`          | Listener without traffic |
| `outbound-only`          | Outbound activity only |

### Role groups for `-roles`

Use short group names (case-insensitive) instead of long comma lists:

| Group       | Expands to |
|-------------|------------|
| `all`       | all roles |
| `reverse`   | reverse-control, reverse-transport, reverse-proxy, reverse-tunnel |
| `listeners` | proxy-listener, listener-with-clients, listener-with-outbound, listener-only |
| `susp`      | susp-beacon, susp-session, susp-tun |
| `control`   | reverse-control, reverse-transport, susp-session, susp-beacon, susp-tun |

Examples:
- `proxywatch.exe -roles susp`
- `proxywatch.exe -roles reverse,listeners`
- `proxywatch.exe -roles control,susp-beacon`

---

## Role triggers and tuning

### Telemetry inputs (what the classifier looks at)

| Signal | Details |
| --- | --- |
| TCP listeners | Local ports; loopback-only vs wildcard bindings |
| Inbound clients | Active inbound sessions to listeners |
| Outbound connections | Internal vs external; distinct targets/ports |
| Connection age | Short-lived vs long-lived; burst intervals |
| Loopback transport | Local-to-local forwarding activity |
| Internal scan hints | Internal targets/ports that suggest lateral movement |

### Role triggers (simplified)

| Role | Trigger |
| --- | --- |
| `reverse-control` | Persistent outbound control channel (oldest ESTABLISHED > `ReverseControlMinDuration`), single outbound target, not in `BenignControlPorts` |
| `reverse-transport` | `reverse-control` + loopback transport activity |
| `reverse-proxy` | Control channel + proxying to internal targets (lateral hints or internal target/port counts) |
| `susp-session` | Persistent control channel without proxying evidence (and not `susp-tun`) |
| `susp-tun` | Control channel + loopback transport or internal scan activity (with reverse-control/proxy evidence) |
| `susp-beacon` | Periodic short-lived outbound bursts at/above `BeaconSleepThreshold` for `BeaconMinIntervals`; no listener and no long-lived outbound |
| `proxy-listener` | Listener + inbound clients + outbound |
| `listener-with-clients` | Listener + inbound clients, no outbound |
| `listener-with-outbound` | Listener + outbound, no inbound clients |
| `listener-only` | Listener with no inbound or outbound activity |
| `reverse-tunnel` | No listener; outbound to multiple targets (`out >= 3`) with internal-lateral evidence |
| `outbound-only` | Outbound activity without listener (default non-suspicious) |

### Where to edit (tuning files)

- [proxywatch/internal/shared/classifier_state.go](proxywatch/internal/shared/classifier_state.go)  
  Time windows, control thresholds, beacon thresholds, scoring baselines, benign control ports, and caps.

- [proxywatch/internal/shared/telemetry_types.go](proxywatch/internal/shared/telemetry_types.go)  
  Burst sampling windows and thresholds for short‑lived activity.

- [proxywatch/internal/shared/constants.go](proxywatch/internal/shared/constants.go)  
  Internal CIDRs and lateral movement ports.

- [proxywatch/cmd/proxywatch/main.go](proxywatch/cmd/proxywatch/main.go)  
  UI default role filter and the minimum score gate (`minScore`).

### Example edits

Make beacon detection stricter (longer interval, more repeats):
```go
// proxywatch/internal/shared/classifier_state.go
BeaconSleepThreshold = 120 * time.Second
BeaconMinIntervals = 3
```

Reduce false positives on common control ports:
```go
// proxywatch/internal/shared/classifier_state.go
ReverseControlMinDuration = 20 * time.Second
BenignControlPorts = map[int]bool{
	53: true, 80: true, 443: true, 8080: true,
	8443: true, 8000: true, 8001: true, 8008: true, 8888: true,
	9443: true, // add your own common benign ports here
}
```

Match your internal network ranges:
```go
// proxywatch/internal/shared/constants.go
InternalCIDRs = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"100.64.0.0/10", // example: carrier-grade NAT
}
```

Raise or lower the UI score gate (what shows up as suspicious):
```go
// proxywatch/cmd/proxywatch/main.go
minScore := 25 // default is 15
```

After edits, rebuild to apply changes.

## Flags

- `-roles` Comma-separated list of roles to display (overrides the default UI filter)

- `-interval` Refresh interval (default `250ms`)

- `-incremental` Reuse classification for unchanged PIDs

- `-listen` Listen address for ProxyWatch Agent ingest (for example `0.0.0.0:50051`)

- `-stale` Drop remote hosts after this duration without updates (0 = keep)

---

## How it works (high level)

ProxyWatch uses:

- `GetExtendedTcpTable` (IPv4/IPv6) for TCP state and PID association

- `GetExtendedUdpTable` for UDP listeners

- Toolhelp process snapshots and Win32 APIs for process metadata

- Timestamped tracking of outbound connections for control-channel inference

- Heuristic scoring and role classification

- Burst sampling per refresh to capture short-lived connections

No packets are captured. No kernel components are required.

---

## Build

This repo is already a Go module (no `go mod init` needed).

Linux:
```bash
sudo apt-get update
sudo apt-get install -y git make golang-go
```

If Go is already installed:
```bash
git clone https://github.com/In3x0rabl3/proxywatch.git
cd proxywatch/proxywatch
go mod download
make
```

Artifacts are placed in `build/` by default.

## Windows service

Install and start the agent service (keeps running after the terminal closes):
```bash
pwa.exe --install --server 10.0.0.5:50051
pwa.exe --start
```

Stop and uninstall:
```bash
pwa.exe --stop
pwa.exe --uninstall
```

Notes:
- `--service` is intended for the Service Control Manager (SCM) only.
- Use the normal binary for debugging or ad‑hoc runs.

---

## Notes

- Terminating processes may require elevated privileges depending on target.

- Lateral ports are used as heuristic hints (SMB, RDP, WinRM, LDAP, MSSQL, SSH).

- The TUI defaults to showing only `susp-session`, `susp-beacon`, and `susp-tun`. Use `-roles` to override.

- Whitelisted processes are stored in the user config directory at `proxywatch/whitelist.json`.
