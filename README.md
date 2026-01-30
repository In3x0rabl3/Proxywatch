# ProxyWatch

ProxyWatch is a Windows userland network inspection tool that labels processes by role (tunnels, proxies, beacons) using TCP/UDP state and process context. It does not require kernel drivers, ETW, or packet capture.

Beaconhunter is a companion agent that runs on remote endpoints and streams the same classified results into a central ProxyWatch UI.

---

## Quick start (local)

Interactive TUI:
```bash
proxywatch.exe
```

One-shot (scriptable):
```bash
proxywatch.exe -once
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

## Multi-endpoint mode (Beaconhunter)

1) Start ProxyWatch in ingest mode:
```bash
proxywatch.exe -listen 0.0.0.0:50051
```

2) Run the agent on each endpoint:
```bash
beaconhunter-agent.exe -server 10.0.0.5:50051
```

Optional agent flags:
- `-id` Host identifier (default: hostname)
- `-interval` Refresh interval (default `250ms`)
- `-incremental` Reuse classification for unchanged PIDs
- `--install` Install the BeaconHunter Windows service
- `--uninstall` Uninstall the service
- `--start` Start the service
- `--stop` Stop the service
- `--service` Run under SCM (service mode only)

Notes:
- The dashboard shows a HOST column for each endpoint.
- Kill is available for remote hosts when the agent is connected.
- Use `-stale 30s` to drop endpoints that stop reporting.
- Transport is gRPC over TCP with a JSON codec. No auth or mTLS yet.

---

## BloodHound collection

Collection is started from the TUI:
1) Press `c` to open the collection screen
2) Set output path, duration, and roles
3) Press `ENTER` to start
4) Return to the dashboard while it runs
5) The JSON file is written automatically when the timer ends (or press `ENTER` again to stop early)

Works for both local mode and ingest mode (`-listen`).

---

## Features

- Behavior-based detection without signatures
- Role assignment for tunnels, proxies, and beacons
- Reverse-control and reverse-transport detection
- Listener and client mapping (TCP + UDP)
- Short-lived connection capture for fast scans
- TUI with per-process inspector and manual kill
- Multi-endpoint ingest with Beaconhunter
- BloodHound collection output (.zip)

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

- `-once` Run one scan and exit
- `-roles` Comma-separated list of roles to display (overrides the default UI filter)
- `-interval` Refresh interval (default `250ms`)
- `-incremental` Reuse classification for unchanged PIDs
- `-listen` Listen address for Beaconhunter ingest (for example `0.0.0.0:50051`)
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
cd proxywatch/proxywatch
go mod download
GOOS=windows GOARCH=amd64 go build -o proxywatch.exe ./cmd/proxywatch
GOOS=windows GOARCH=amd64 go build -o beaconhunter-agent.exe ./cmd/beaconhunter-agent
```

## Windows service

Install and start the agent service (keeps running after the terminal closes):
```bash
beaconhunter-agent.exe --install --server 10.0.0.5:50051
beaconhunter-agent.exe --start
```

Stop and uninstall:
```bash
beaconhunter-agent.exe --stop
beaconhunter-agent.exe --uninstall
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
