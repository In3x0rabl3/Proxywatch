# ProxyWatch

ProxyWatch is a real-time process and network behavior monitor for detecting proxy activity, tunnels, C2 sessions, beacons, and lateral movement. It classifies processes into threat-focused role families using live host telemetry, behavioral heuristics, and an on-device ML model.

> ⚠️ **Vibe-coded disclaimer:** Significant portions of ProxyWatch, including classification heuristics, UI views. Audit before production use. Contributions welcome, especially for hardening and test coverage.

**Current version: v1.0.6**

## Features

- **Real-time dashboard** with process classification into control-centric roles: `control-channel`, `control-pivot`, `outbound`, `listener`.
- **Time-lingered pivot detection** — processes doing SOCKS / port-forwarding (sshd children, beacon SOCKS sub-channels, session port-forwards) flip to `control-pivot` while traffic flows and hold the role for a 60s linger window before reverting to their structural role.
- **Strict real-time tunneling state** — `state=tunneling` is shown only when bytes are actively moving through the tunnel, not just when tunnel topology exists.
- **Enriched pivot evidence** — the Inspector's Evidence panel shows the actual TCP relay destinations (`ip:port`), SMB admin-share activity, and named pipe names for a pivoting process.
- **Raw socket detection** for tools that bypass the kernel TCP stack (nmap SYN scans, ping, tcpdump, custom packet tools).
- **Inspector** with detailed process identity, network, analysis, reasons, and connection views in organized panels.
- **Contour** network probe suite: tunnel/exfil matrix, service reachability, TLS inspection, domain fronting, DNS exfiltration, HTTP method detection.
- **ProxyHound** collection and graph export with optional BloodHound CE API upload.
- **SIEM export** — generate detection rule bundles (Suricata, YARA, Splunk, KQL, ESQL) from live classifier state.
- **Training dashboard** — live ML training telemetry, feature schema, role predictions, model maturity and retrain timing.
- **Encrypted keystore** with YubiKey HMAC support, multiple keystores, auto-relock after use.
- **Multi-host** ingest mode with gRPC agent streaming and remote process kill.
- **Whitelist** manager for suppressing known-good processes.
- **Learning persistence** — ML model and classifier memory are cumulative across runs.

## Quick Start

### Build

```bash
git clone https://github.com/In3x0rabl3/Proxywatch.git
cd Proxywatch/proxywatch
make
# binaries are written to ./build/
```

### Run

```bash
# Local monitoring (recommended: run as root for full visibility)
sudo ./build/proxywatch-linux-amd64

# Multi-host ingest server
sudo ./build/proxywatch-linux-amd64 -listen 0.0.0.0:50051

# Remote agent (connects to ingest server)
./build/proxywatch-windows-amd64.exe -connect <proxywatch-ip>:50051
```

## Navigation

Use Left/Right arrow keys or number keys to switch between dashboards:

**Dashboard** → **1 Training** → **2 Contour** → **3 ProxyHound** → **4 SIEM** → **5 Whitelist** → **6 Keystore** → (cycles back)

Press `?` in any dashboard for context-specific help.

## Dashboard

The main process monitoring view. Shows all classified processes with host, PID, name, role, age, and state.

| Key | Action |
|-----|--------|
| `Enter` | Inspect selected process |
| `f` | Role/sort filter menu |
| `r` | Refresh interval menu |
| `W` | Whitelist selected process |
| `x` | Remove disconnected host row |
| `q` | Quit |

## Inspector

Detailed view of a single process with sections for identity, metadata, network activity, analysis, detection reasons, and connections.

| Key | Action |
|-----|--------|
| `Left`/`Right` | Cycle through processes |
| `p` | Jump to parent process |
| `k` + `y` | Kill process |
| `Up`/`Down` | Scroll |
| `Tab`/`Shift+Tab` | Jump between sections |
| `Esc` | Return to dashboard |

## Training

Live view of the on-device ML classifier. Shows feature-schema layout, current role predictions and confidences, model maturity (observations, shadow agreement, qualification status), and retrain timing.

No operator input required — the predictor runs continuously in shadow mode until it qualifies, then becomes primary.

## Contour

Network security probe suite that tests egress paths, tunnel viability, and exfiltration channels.

- **Matrix**: tunnel and exfiltration protocol reachability across ports.
- **Services**: cloud/SaaS service reachability grid.
- **Routes**: discovered network interfaces and subnets.
- **Endpoints**: reachable proxies and config endpoints.
- **Misc**: TLS inspection, domain fronting, DNS exfiltration, HTTP methods.

## SIEM

Exports detection rule bundles generated from live classifier state. One click produces Suricata rules, YARA rules, Splunk SPL queries, KQL queries, and ESQL queries in a single JSON file at `~/.proxywatch/siem/siem-<host>.json`.

No calibration workflow — the bundle is generated directly from the current classifier signals and role assignments on the host. Re-run to regenerate after new detections mature.

## ProxyHound

Collects process/network graph data and exports to BloodHound-compatible JSON format.

Results displayed in panels: Graph (nodes, edges, candidates, hosts), Network (external/internal connections, listeners), Output (file path, upload status).

Optional API upload when BloodHound credentials are configured in keystore.

## Keystore

Manages API keys, tokens, and runtime settings with AES-256-GCM encryption.

- Supports multiple keystores (plain or YubiKey HMAC-encrypted).
- Secure keystores auto-relock after each operation — YubiKey touch required per use.
- Auto-locks when leaving the Keystore dashboard.
- API keys also accepted via environment variables as fallback.

| Key | Action |
|-----|--------|
| `Enter` | Open keystore to view/edit fields |
| `a` | Activate keystore (load to runtime without opening) |
| `n` | Create new keystore |
| `d` | Delete keystore (press twice to confirm) |
| `Tab` | Toggle between fields and keystores list |

### Managed Keys

| Category | Keys |
|----------|------|
| BloodHound | `BLOODHOUND_API_URL`, `BLOODHOUND_API_TOKEN`, `BLOODHOUND_API_TOKEN_ID` |
| Detection | `PROXYWATCH_DETECT_DEBUG_LOG`, `PROXYWATCH_DETECT_RULES_JSON` |
| Agent/TLS | `PROXYWATCH_TLS_DIR`, `PROXYWATCH_AGENT_TOKEN` |

## How Classification Works

ProxyWatch classifies every process into one of four roles — `outbound`, `listener`, `control-channel`, `control-pivot` — using a rule-engine scorer and an on-device LightGBM predictor running in parallel. SOCKS-forwarding processes get a 60-second `control-pivot` linger while traffic flows; tunneling state only shows when bytes are actually moving.

See [`docs/detection.md`](docs/detection.md) for the role taxonomy, disambiguation tables, FP-suppression tiers, and worked examples.

## Persistence

| Data | Path |
|------|------|
| Classifier memory | `~/.proxywatch/runtime/classifier-memory.json` |
| ML model + GBDT snapshots | `~/.proxywatch/model/` |
| Training telemetry | `~/.proxywatch/training/` |
| Operator labels (kill / whitelist / training) | `~/.proxywatch/operator_labels/` |
| Keystores | `~/.proxywatch/keystores/` |
| Keystore registry | `~/.proxywatch/keystores.json` |
| ProxyHound collections | `~/.proxywatch/collections/` |
| Contour reports | `~/.proxywatch/contour/` |
| SIEM exports | `~/.proxywatch/siem/` |
| Whitelist | `~/.proxywatch/whitelist.json` |

## BloodHound Examples

**Suspicious processes by user**

<img width="1517" height="487" alt="Suspicious processes by user" src="https://github.com/user-attachments/assets/cb593db7-214e-453a-9a15-a771599f2e37" />

**Suspicious internal connection with object details**

<img width="1485" height="769" alt="Suspicious internal connection details" src="https://github.com/user-attachments/assets/abe33759-1884-48a7-b575-4f16e61e6612" />

**Full internal connection chain**

<img width="1577" height="602" alt="Full internal connection chain" src="https://github.com/user-attachments/assets/fda21094-b2bc-46f3-990a-eefd767f1bea" />

Cypher query pack: [`docs/queries.md`](docs/queries.md).

## HTTP APIs

ProxyWatch exposes three HTTP APIs for introspection and control — a local/server-mode Debug API (`/candidates`, `/fp-report`, `/operator/label`, `/metrics`), a per-agent Debug API for connect-mode agents, and a Contour API for headless tunnel operation. See [`docs/api-reference.md`](docs/api-reference.md) for full endpoint documentation with schemas, query parameters, and usage examples.

## Notes

- Run as root (`sudo`) for full visibility including raw socket detection and process IO stats.
- Whitelist is stored on disk and applied after classification.
- Kill actions may require elevation.
- Classifier memory persists across runs; the ML model retrains from its observation buffer on feature-schema bumps.
