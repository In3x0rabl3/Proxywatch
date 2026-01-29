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

JSON logging:
```bash
proxywatch.exe -json out.json
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
- `-interval` Refresh interval
- `-incremental` Reuse classification for unchanged PIDs

Notes:
- The dashboard shows a HOST column for each endpoint.
- Kill is disabled for remote hosts.
- Use `-stale 30s` to drop endpoints that stop reporting.
- Transport is gRPC over TCP with a JSON codec. No auth or mTLS yet.

---

## Features

- Behavior-based detection without signatures
- Role assignment for tunnels, proxies, and beacons
- Reverse-control and reverse-transport detection
- Listener and client mapping (TCP + UDP)
- Short-lived connection capture for fast scans
- TUI with per-process inspector and manual kill
- JSON logging (pretty) for offline review
- Multi-endpoint ingest with Beaconhunter

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
- `-interval` Refresh interval (for example `250ms`, `1s`)
- `-incremental` Reuse classification for unchanged PIDs
- `-json` Write pretty JSON snapshots to a file (use `-` for stdout)
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

---

## Notes

- Terminating processes may require elevated privileges depending on target.
- Lateral ports are used as heuristic hints (SMB, RDP, WinRM, LDAP, MSSQL, SSH).
- The TUI defaults to showing only `susp-session`, `susp-beacon`, and `susp-tun`. Use `-roles` to override.
- Whitelisted processes are stored in the user config directory at `proxywatch/whitelist.json`.
