# PROXYWATCH

Host-based detection for proxy tunnels, C2 beacons, and lateral movement. Classifies processes by network behavior, not identity.

[![Go Version](https://img.shields.io/badge/go-1.21+-00ADD8.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)

---

## Capabilities

| Feature | Description |
|---------|-------------|
| **Live Process Monitoring** | Real-time classification of all processes. Roles update as behavior evolves. |
| **Beacon Detection** | Identifies periodic callbacks via interval timing, jitter analysis, and behavioral signals. |
| **Tunnel Detection** | Catches reverse tunnels, SOCKS proxies, port forwards as traffic flows through them. |
| **Lateral Movement** | Flags pivots via SMB, WinRM, named pipes. Shows relay destinations and share access. |
| **PCAP Analysis** | Offline analysis of PCAP/Zeek logs with JA3, SSH banner, HTTP signature matching. |
| **On-Device ML** | GBDT classifier trains continuously. Shadow mode validates before promotion. |

---

## Role Classification

| Role | Description |
|------|-------------|
| `beacon` | Periodic callbacks with interval patterns to external infrastructure |
| `pivot` | Lateral movement, reverse tunnels, SOCKS proxies, SMB pipes |
| `listener` | Bound ports accepting inbound connections |
| `outbound` | Normal egress, no suspicious patterns |

---

## Quick Start

### Build

```bash
git clone https://github.com/In3x0rabl3/Proxywatch.git
cd Proxywatch/proxywatch && make
```

### Run

```bash
# Linux
sudo ./build/proxywatch-linux-amd64

# Windows (Administrator)
.\build\proxywatch-windows-amd64.exe
```

---

## Deployment Modes

### Standalone
```bash
sudo ./proxywatch
```
Local monitoring with TUI dashboard.

### Server Mode
```bash
sudo ./proxywatch -listen 0.0.0.0:50051
```
Accept agent connections, aggregate detection.

### Agent Mode
```bash
./proxywatch -connect 10.0.0.5:50051 -id WS01
```
Stream telemetry to central server.

### Windows Service
```bash
proxywatch.exe -install -connect 10.0.0.5:50051
proxywatch.exe -start
```

---

## Network Analysis

| Capability | Details |
|------------|---------|
| Input | PCAP, PCAPNG, Zeek logs (conn/dns/ssl), live interface tailing |
| TLS | JA3/JA3S fingerprinting, known C2 signature database |
| SSH | Banner extraction, C2 framework detection |
| HTTP | Request/response parsing, malware signature matching |
| DNS | DGA detection, tunnel volume analysis, entropy scoring |
| Beacon | Interval stats, size uniformity, jitter coefficient, strobe detection |

---

## Contour Probe Suite

Network security probes for egress testing and tunnel verification.

| Probe | Function |
|-------|----------|
| Protocol Matrix | Tunnel/exfil protocol reachability across ports |
| Service Grid | Cloud/SaaS service accessibility |
| TLS Inspection | Certificate chain analysis, interception detection |
| Domain Fronting | CDN fronting viability testing |
| DNS Exfil | Covert channel testing via DNS |

### Tunnel Protocols

`http` `https` `ws` `wss` `dns` `ssh` `smtp` `ftp` `imap` `redis` `postgres` `ldap` `smb` `socks5` `ntp`

```bash
# Server
./proxywatch -contour-server -contour-proto https -contour-ports 443

# Client
./proxywatch -contour-client 10.0.0.5 -contour-proto https
```

---

## Command Reference

| Flag | Description |
|------|-------------|
| `-listen <addr>` | Server mode, accept agent connections |
| `-connect <addr>` | Agent mode, stream to server |
| `-id <name>` | Host identifier for agent mode |
| `-agent-token` | Shared auth token for agent connections |
| `-debug-api <addr>` | HTTP debug API endpoint |
| `-contour-server` | Headless tunnel server |
| `-contour-client` | Headless tunnel client |
| `-service` | Run as Windows service |
| `-install / -uninstall` | Windows service management |
| `-training-export` | Export ML training telemetry |

---

## Interface Views

| View | Function |
|------|----------|
| Dashboard | Live process list with roles, states, threat scores |
| Inspector | Deep dive: connections, evidence, kill option |
| Analysis | PCAP/Zeek analysis with beacon scoring |
| Training | ML model status, shadow metrics, retrain controls |
| Contour | Network probe suite for egress testing |
| ProxyHound | Graph collection, BloodHound export |
| Keystore | Encrypted credential management (AES-256-GCM) |

---

## HTTP APIs

| Endpoint | Description |
|----------|-------------|
| `GET /candidates` | Current classification state |
| `GET /fp-report` | False positive analysis |
| `POST /operator/label` | Apply operator labels |
| `GET /metrics` | Prometheus-format metrics |

Enable with `-debug-api 127.0.0.1:7890`

---

## Integrations

- **BloodHound** — Export process/network graphs via ProxyHound
- **Webhook Alerts** — HTTP POST on malicious role promotion
- **Vault** — HashiCorp Vault keystore backend
- **YubiKey** — HMAC challenge-response for keystore unlock

---

## Data Persistence

| Data | Path |
|------|------|
| Classifier memory | `~/.proxywatch/runtime/classifier-memory.json` |
| ML models | `~/.proxywatch/models/` |
| Training data | `~/.proxywatch/training/` |
| Keystores | `~/.proxywatch/keystores/` |
| Collections | `~/.proxywatch/collections/` |
| Contour reports | `~/.proxywatch/contour/` |

---

## Requirements

- Go 1.21+ (build)
- Root/Administrator (full visibility)
- libpcap (Linux) / Npcap (Windows) for PCAP analysis

---

## License

BSD-3-Clause — see [LICENSE](LICENSE)
