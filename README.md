# ProxyWatch

ProxyWatch is a Windows behavioral network inspection tool that identifies potential tunneling, proxying, and control‑channel activity by correlating network state with running processes. It operates without kernel drivers, ETW, or packet inspection. Detection is based on TCP/UDP state, process context, and heuristic scoring.

ProxyWatch can run continuously in a TUI, classify roles (e.g., susp‑tun, reverse‑proxy), and let you manually terminate a process from the inspector.

---

## Features
| Feature                       | Meaning |
|------------------------------|---------|
| **Behavior-based detection** | identifies proxy/tunnel patterns without signatures |
| **Reverse-control detection** | persistent outbound channels tracked over time |
| **Reverse-transport detection** | detects local forwarding activity over loopback |
| **Role assignment**          | processes are labeled based on observed traffic patterns |
| **Outbound fan-out heuristics** | identifies multiplexing & multiple service targets |
| **Client listener detection** | detects loopback/bound SOCKS-like behavior |
| **Lateral movement hints**   | flags internal connections to common lateral ports |
| **Short-lived connection capture** | burst sampling improves visibility of fast scans |
| **TUI + inspector**          | interactive view with per-process details (TCP + UDP) |
| **Manual kill (inspector)**  | terminate the inspected process with one keypress |
| **Run once or continuous**   | suitable for terminal usage, scripting, or monitoring |
| **No admin installation required** | uses standard Win32 APIs |

---

## Roles

ProxyWatch assigns a best‑fit role per process:

| Role                     | Meaning |
|--------------------------|---------|
| `susp-tun`               | Control channel with tunnel evidence (loopback transport or internal scan activity) |
| `susp-beacon`            | Periodic short‑lived outbound beacons (e.g., ~60s callbacks) |
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
| `no-network-activity`    | Nothing interesting |

---

## Usage

### Interactive TUI
```bash
proxywatch.exe
```

Keys:
- `UP/DOWN` to select
- `ENTER` to inspect
- `ESC` to return to dashboard
- `k` to kill the inspected process
- `q` to quit

### One-shot (scriptable)
```bash
proxywatch.exe -once
```

### Useful flags
- `-roles`: comma-separated list of roles to display (e.g., `reverse-proxy,reverse-control`)
- `-interval`: refresh interval (e.g., `250ms`, `1s`)
- `-incremental`: reuse classification for unchanged PIDs (faster, slightly less accurate)
- `-json`: write pretty JSON snapshots to a file (use `-` for stdout)
---

## How It Works (High-Level)

ProxyWatch uses:

- `GetExtendedTcpTable` (IPv4/IPv6) for TCP state & PID association
- Toolhelp process snapshot + Win32 APIs for process metadata
- timestamped tracking of outbound connections for control-channel inference
- heuristic scoring + role classification
- burst sampling per refresh to capture short-lived connections
- `GetExtendedUdpTable` for UDP listeners

No packets are captured. No kernel components are required.  
All analysis is userland and stateful across scans.

---

## Installation

Clone & build:

```bash
git clone https://github.com/In3x0rabl3/proxywatch.git
cd proxywatch/proxywatch
go mod download
go get github.com/gdamore/tcell/v2
GOOS=windows GOARCH=amd64 go build -o proxywatch.exe ./cmd/proxywatch
```

---

## Notes

- Terminating processes may require elevated privileges depending on target.
- Lateral ports are used as heuristic hints (SMB, RDP, WinRM, LDAP, MSSQL, SSH).
