# ProxyWatch

ProxyWatch is a Windows userland network inspection tool that labels processes by role (tunnels, proxies, beacons) using TCP/UDP state and process context. It does not require kernel drivers, ETW, or packet capture.

ProxyWatch Agent is a companion service that runs on remote endpoints and streams the same classified results into a central ProxyWatch UI. Each build generates a unique TLS/mTLS trust bundle so only agents built from the same build can connect.

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
- The dashboard shows a HOST column for each endpoint.
- Kill is available for remote hosts when the agent is connected.
- Use `-stale 30s` to drop endpoints that stop reporting.
- Transport is gRPC over TCP with JSON framing and automatic TLS/mTLS (generated at build time).
- Agent and UI must be built together so they share the same trust bundle.

---

## BloodHound collection

Collection is started from the TUI:
1) Press `c` to open the collection screen
2) Use `UP/DOWN` to select a field
3) Press `ENTER` to edit Output or Roles (type to change)
4) Use `LEFT/RIGHT` to change Duration
5) Select `Start/Stop` and press `ENTER` to start
4) Return to the dashboard while it runs
5) The JSON file is written automatically when the timer ends (or press `ENTER` again to stop early)

Works for both local mode and ingest mode (`-listen`).

Saved Cypher queries are in `queries.md`.

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

---

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

Clone and build:
```bash
git clone https://github.com/In3x0rabl3/proxywatch.git
cd proxywatch
make
```
Artifacts are placed in `dist/` by default.

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
