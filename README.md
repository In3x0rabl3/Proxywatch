# ProxyWatch

ProxyWatch is a process network monitor that classifies processes into roles based on a number of signals. It's nothing complicated, we just simply are mapping and learning how legitimate processes act, while doing the same for malicious processes. We then take this data, train, learn and apply a role to each process.

## Features

- Proxywatch has a Terminal User Interface (TUI), giving operators a clean view of each process.

- Processes are assigned via roles (`Tunnel`, `session`, `beacon` pushed to the top of the TUI). Operator can also view roles such as (`outbound`, `listner`, `reverse proxy`)

- Run ProxyWatch locally or ingest multiple endpoints

- BloodHound collections via Json files or API

- Tuning the classification of roles in inspect moode.

## Demo

![Demo](docs/media/Demo-latest.gif)

## Quick Start

### Build
```bash
git clone https://github.com/In3x0rabl3/Proxywatch.git
cd Proxywatch/proxywatch
go mod download
make
```

### Run Ingest Mode (multi-host)
```bash
sudo ./proxywatch-linux-amd64 -listen 0.0.0.0:50051
```

### Run Agents:
```bash
./pwa-windows-amd64.exe server <proxywatch-ip>:50051
```

## TUI
- `UP/DOWN`: move selection
- `ENTER`: inspect selected process
- `w`: whitelist selected process
- `W`: manage whitelist entries
- `c`: open collection workflow
- `q`: quit


## Inspect
- `k`: Kill local and remote processes 
- `x`: Traffic reasons + signals
- Connections: local/remote/state/scope
- Autonomous System Number (ASN): Resolving ASNs to Organizations


## Roles

| Role | Meaning |
| --- | --- |
| `Tunnel` | Session/tunnel behavior with strong tunnel evidence |
| `Session` | Persistent control channel without tunnel proxy shape |
| `Beacon` | Recurring callback pattern (cadence-driven) |
| `listener-*` | Listener variants (`clients`, `outbound`, or `only`) |
| `outbound-only` | Outbound traffic with no suspicious control shape |

## How Classification Works

Classification logic is in `proxywatch/internal/classifier/rank.go`.

State/threshold values are in `proxywatch/internal/shared/classify.go`.

Core signals:
- Control channel: long lived `ESTABLISHED` outbound connection (age-based).

- Tunnel: listener + control + local/internal patterns.

- Beacon: recurring short lived callbacks with cadence/jitter checks.

- Destination verification: internal/external scope and prefix.

- ASN assist: resolved ASN org alignment/mismatch as a bounded secondary score adjustment.

- Stability guards: session/beacon precedence and display smoothing to reduce role thrash.

Current behavior notes:
- Active long lived control channels stay as sessions.

- Short lived suspicious processes are retained briefly in TUI so operators can inspect them before they disappear.

## BloodHound Collection

Collection:
1. Press `c`
2. Set output/duration/roles
3. Start collection
4. JSON is written or uploaded via API

Cypher query pack:
- `docs/queries.md`

### Upload Config
Set env vars in the same shell that launches ProxyWatch:
```bash
export BLOODHOUND_API_URL='http://<bh-host>:8282/api/v2'
export BLOODHOUND_API_TOKEN='<token-or-key>'
export BLOODHOUND_API_ID='<id-for-hmac-keys>'
```

### Collector Graph Behavior
Collector logic: `proxywatch/internal/bloodhound/collect.go`


### BloodHound Examples

**Suspicious processes by user**

<img width="1517" height="487" alt="Suspicious processes by user" src="https://github.com/user-attachments/assets/cb593db7-214e-453a-9a15-a771599f2e37" />

**Suspicious internal connection with object details**

<img width="1485" height="769" alt="Suspicious internal connection details" src="https://github.com/user-attachments/assets/abe33759-1884-48a7-b575-4f16e61e6612" />

**Full internal connection chain**

<img width="1577" height="602" alt="Full internal connection chain" src="https://github.com/user-attachments/assets/fda21094-b2bc-46f3-990a-eefd767f1bea" />

## Tuning Guide

Edit these files for tuning:
- `proxywatch/internal/shared/classify.go`
  - time windows, scoring caps, beacon thresholds, role family ordering.

- `proxywatch/internal/classifier/rank.go`
  - role promotion/demotion logic and evidence handling.

- `proxywatch/internal/shared/helper.go`
  - benign-context helpers (path/company/service context checks).

- `proxywatch/cmd/proxywatch/main.go`
  - startup defaults (`minScore`, refresh interval, role filter defaults).

## CLI Flags
- `-roles`: roles or role families to display
- `-interval`: refresh interval (default `250ms`)
- `-incremental`: reuse unchanged PID classification (faster)
- `-listen`: enable ingest server mode
- `-stale`: drop stale remote hosts after duration

## Notes
- Whitelist is stored on disk and applied after classification.
- Kill actions may require elevation.
