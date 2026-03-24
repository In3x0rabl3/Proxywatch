# ProxyWatch

ProxyWatch is a process/network behavior monitor that classifies process activity into role families (`tunnel`, `session`, `beacon`, `listener`, `outbound`, `other`) using host telemetry plus persisted learning data.

## Features

- Terminal UI for host/process monitoring and triage.
- Local mode or multi-host ingest mode (`-listen` + remote `-connect`).
- Contour workflow for probe checks and endpoint/proxy discovery.
- Calibration workflow for profile generation and apply.
- SIEM workflow for report/JSON detection packs.
- BloodHound collection/export with optional API upload.
- Keystore workflow for runtime secrets/settings.
- Per-menu help overlays (`?`) across dashboard and workflows.

## Demo

![Demo](docs/media/Demo-latest.gif)

## Quick Start

### Build

```bash
git clone https://github.com/In3x0rabl3/Proxywatch.git
cd Proxywatch/proxywatch
make
# binaries are written to ./build/
```

### Run Local UI

```bash
sudo ./build/proxywatch-linux-amd64
```

### Run Ingest Server (multi-host)

```bash
sudo ./build/proxywatch-linux-amd64 -listen 0.0.0.0:50051
```

### Run Agent (example)

```bash
./build/proxywatch-windows-amd64.exe -connect <proxywatch-ip>:50051
```

## Dashboard Shortcuts

- `?`: open dashboard help
- `Enter`: inspect selected process
- `f`: role/sort menu
- `r`: refresh interval menu
- `b`: BloodHound collection workflow
- `c`: calibration workflow
- `o`: contour workflow
- `m`: SIEM workflow
- `k`: keystore workflow
- `w`: whitelist manager
- `W`: whitelist selected process
- `x`: remove disconnected host row
- `q`: quit

## Menu Help

Press `?` in each mode for context help:

- Dashboard
- Inspect
- BloodHound
- Calibration
- Contour
- SIEM
- Keystore
- Whitelist

## Inspect

- `k` then confirm (`y`) to kill selected process (local/remote as applicable)
- `x`: toggle reason/signal explanation view
- Connection details include local/remote/state/scope
- ASN context is shown for external destinations

## Roles

Primary threat-focused role families:

- `tunnel`: process looks like a proxy/relay (inbound + outbound forwarding shape)
- `session`: persistent control channel without proxying evidence
- `beacon`: recurring callback/check-in pattern (cadence and jitter)

## How Classification Works

Classification logic is in `proxywatch/internal/detection/rank.go`.

Primary thresholds and windows are in `proxywatch/internal/shared/classify.go`.

Core signals include:

- Long-lived control-channel behavior.
- Tunnel/forwarding patterns from listener + flow relationships.
- Beacon cadence/jitter behavior.
- Internal/external scope and destination-prefix context.
- ASN organization context as a bounded signal.
- Stability guards to reduce role thrash.

Runtime classifier memory is persisted across runs at:

- `~/.proxywatch/runtime/classifier-memory.json`

## Calibration and Learning Persistence

Calibration stores reusable state under `~/.proxywatch/calibration`:

- Active applied profile: `tuning.json`
- Historical profiles: `profiles/*.json`
- Learning model: `training/environment-model.json`
- Calibration memory index: `training/validated-calibrations.jsonl`

This means learning is cumulative over time, not only per-report.

## Contour Workflow

Contour (`o`) supports role/mode-driven checks and report generation.

- Connectivity/protocol/port probe checks.
- Listener/client/scan behavior depending on selected role/mode.
- Endpoint/proxy/config discovery and summary.
- Contour hints exported for calibration context.

## SIEM Workflow

SIEM generation (`m`) builds SIEM-facing artifacts from calibration output:

- Markdown report output
- JSON detection bundle
- Query templates for Splunk/KQL/Elastic/Sigma-like mappings

Backend implementation lives in:

- `proxywatch/internal/siem/siem.go`

## Keystore

Keystore (`k`) is the primary way to manage runtime secrets/settings.

- Default encrypted store: `~/.proxywatch/keystore.enc`
- Local key file: `~/.proxywatch/keystore.key`
- Actions:
  - `Load`: read encrypted values from disk into UI/runtime
  - `Save`: encrypt current values to disk
  - `Apply`: apply current values to runtime without writing disk

Common values managed here:

- Provider/API config (`OPENAI_*`, `ANTHROPIC_*`, `LOCAL_LLM_*`)
- BloodHound upload config (`BLOODHOUND_API_*`)
- SIEM generation config (`PROXYWATCH_SIEM_*`)
- Detection export outputs (`PROXYWATCH_DETECT_*`)

## BloodHound Collection

Collection flow:

1. Press `b`
2. Set output and duration
3. Start collection
4. JSON is written or uploaded via API

Cypher query pack:

- `docs/queries.md`

Collector logic:

- `proxywatch/internal/bloodhound/collect.go`

### BloodHound Examples

**Suspicious processes by user**

<img width="1517" height="487" alt="Suspicious processes by user" src="https://github.com/user-attachments/assets/cb593db7-214e-453a-9a15-a771599f2e37" />
<br>
**Suspicious internal connection with object details**

<img width="1485" height="769" alt="Suspicious internal connection details" src="https://github.com/user-attachments/assets/abe33759-1884-48a7-b575-4f16e61e6612" />
<br>
**Full internal connection chain**

<img width="1577" height="602" alt="Full internal connection chain" src="https://github.com/user-attachments/assets/fda21094-b2bc-46f3-990a-eefd767f1bea" />
<br>
## Tuning Guide

Key edit points:

- `proxywatch/internal/shared/classify.go`
- `proxywatch/internal/detection/rank.go`
- `proxywatch/internal/shared/classify_memory.go`
- `proxywatch/cmd/proxywatch/main.go`
- `proxywatch/docs/architecture/CODEMAP.md`

## Notes

- Whitelist is stored on disk and applied after classification.
- Kill actions may require elevation.
- Use dashboard role filters and sort controls to tune operator views.
