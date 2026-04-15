# ProxyWatch

ProxyWatch is a real-time process and network behavior monitor for detecting proxy activity, tunnels, C2 sessions, beacons, and lateral movement. It classifies processes into threat-focused role families using live host telemetry, behavioral heuristics, and persisted learning data.

**Current version: v1.0.6**

## Features

- **Real-time dashboard** with process classification into control roles: control-channel, control-pivot, outbound, listener.
- **Time-lingered pivot detection** — processes doing SOCKS / port-forwarding (sshd children, beacon SOCKS sub-channels, session port-forwards) flip to `control-pivot` while traffic is flowing and hold the role for a 60s linger window before reverting to their structural role.
- **Strict real-time tunneling state** — `state=tunneling` is shown only when bytes are actively moving through the tunnel, not just when tunnel topology exists.
- **Enriched pivot evidence** — the Inspector's Evidence panel shows the actual TCP relay destinations (`ip:port`), SMB admin-share activity, and named pipe names for a pivoting process.
- **Raw socket detection** for tools that bypass the kernel TCP stack (nmap SYN scans, ping, tcpdump, custom packet tools).
- **Inspector** with detailed process identity, network, analysis, reasons, and connection views in organized panels.
- **Contour** network probe suite: tunnel/exfil matrix, service reachability, TLS inspection, domain fronting, DNS exfiltration, HTTP method detection.
- **Calibration** with AI-driven threshold tuning via OpenAI, Anthropic, or local LLM providers.
- **SIEM** detection pack generation: Splunk, KQL, ESQL, Suricata, and YARA output from calibration data.
- **ProxyHound** collection and graph export with optional BloodHound CE API upload.
- **Encrypted keystore** with YubiKey HMAC support, multiple keystores, auto-relock after use.
- **Multi-host** ingest mode with gRPC agent streaming and remote process kill.
- **Whitelist** manager for suppressing known-good processes.
- **Learning persistence** — calibration, classifier memory, and environment models are cumulative across runs.

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

**Dashboard** → **1 Calibration** → **2 Contour** → **3 ProxyHound** → **4 SIEM** → **5 Whitelist** → **6 Keystore** → (cycles back)

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

## Calibration

AI-driven threshold tuning. Collects telemetry samples, sends to an AI provider, and generates tuning recommendations with confidence scoring.

| Key | Action |
|-----|--------|
| `Enter` on Action | Start calibration / stop |
| `Enter` on Apply | Apply saved profile |
| `Enter` on fields | Cycle options via menu |

Requires an active keystore with an API key (OpenAI, Anthropic, or Local LLM). If using an encrypted keystore, YubiKey touch is prompted automatically when starting.

Results displayed in panels: Confidence, Tuning, Recommendations, Learning, History, Reasoning.

## SIEM

Generates detection packs from calibration reports with queries for Splunk, KQL, ESQL, Suricata rules, and YARA rules.

Results displayed in panels: Summary, Detections (high-level with severity), Notes. Full query details are in the JSON output file.

## Contour

Network security probe suite that tests egress paths, tunnel viability, and exfiltration channels.

- **Matrix**: tunnel and exfiltration protocol reachability across ports.
- **Services**: cloud/SaaS service reachability grid.
- **Routes**: discovered network interfaces and subnets.
- **Endpoints**: reachable proxies and config endpoints.
- **Misc**: TLS inspection, domain fronting, DNS exfiltration, HTTP methods.

## BloodHound

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
| AI Providers | `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `LOCAL_LLM_URL`, `LOCAL_LLM_API_KEY` |
| BloodHound | `BLOODHOUND_API_URL`, `BLOODHOUND_API_TOKEN`, `BLOODHOUND_API_TOKEN_ID` |
| SIEM | `PROXYWATCH_SIEM_PROVIDER`, `PROXYWATCH_SIEM_MODEL`, `PROXYWATCH_SIEM_*` |
| Detection | `PROXYWATCH_DETECT_DEBUG_LOG`, `PROXYWATCH_DETECT_RULES_JSON` |
| Agent/TLS | `PROXYWATCH_TLS_DIR`, `PROXYWATCH_AGENT_TOKEN` |

## How Classification Works

Classification logic is in `proxywatch/internal/detection/rank.go`. Thresholds are in `proxywatch/internal/shared/classify.go`.

Core signals:

- Long-lived control-channel behavior
- Tunnel/forwarding patterns from listener + flow relationships
- Beacon cadence/jitter detection
- Raw socket detection (bypasses TCP stack)
- Delegated egress via proxy broker processes
- Internal/external scope and destination-prefix context
- ASN organization alignment with process publisher context
- Command-line proxy/tunnel flag detection
- Stability guards to reduce role thrash

## Persistence

| Data | Path |
|------|------|
| Classifier memory | `~/.proxywatch/runtime/classifier-memory.json` |
| Active tuning profile | `~/.proxywatch/calibration/tuning.json` |
| Historical profiles | `~/.proxywatch/calibration/profiles/*.json` |
| Learning model | `~/.proxywatch/calibration/training/environment-model.json` |
| Calibration history | `~/.proxywatch/calibration/training/validated-calibrations.jsonl` |
| Keystores | `~/.proxywatch/keystores/` |
| Keystore registry | `~/.proxywatch/keystores.json` |
| Collections | `~/.proxywatch/collections/` |
| Contour reports | `~/.proxywatch/contour/` |
| SIEM detections | `~/.proxywatch/siem/` |
| Whitelist | `~/.proxywatch/whitelist.json` |

## BloodHound Examples

**Suspicious processes by user**

<img width="1517" height="487" alt="Suspicious processes by user" src="https://github.com/user-attachments/assets/cb593db7-214e-453a-9a15-a771599f2e37" />

**Suspicious internal connection with object details**

<img width="1485" height="769" alt="Suspicious internal connection details" src="https://github.com/user-attachments/assets/abe33759-1884-48a7-b575-4f16e61e6612" />

**Full internal connection chain**

<img width="1577" height="602" alt="Full internal connection chain" src="https://github.com/user-attachments/assets/fda21094-b2bc-46f3-990a-eefd767f1bea" />

Cypher query pack: `docs/queries.md`

## Notes

- Run as root (`sudo`) for full visibility including raw socket detection and process IO stats.
- Whitelist is stored on disk and applied after classification.
- Kill actions may require elevation.
- Each dashboard displays results in styled, bordered panels.
- Learning is cumulative — calibration and classifier memory persist across runs.
