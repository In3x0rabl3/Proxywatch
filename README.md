# ProxyWatch

ProxyWatch is a process network monitor that classifies processes into relevant roles (`tunnel`, `session`, `beacon`, `listener`, `outbound`) using socket behavior and process context.

## Features
- Live Terminal User Interface (TUI) with per-process inspect view.

- Role based prioritization (`susp-tun`, `susp-session`, `susp-beacon` at top).

- Local and remote ingest modes.

- BloodHound collection via Json or API key.

- Tuning data in inspect mode for role debugging and enhancements.

## Demo

![Demo](docs/media/Demo-latest.gif)

## Quick Start

### Build
```bash
cd proxywatch
go mod download
make
```

Artifacts are written to `proxywatch/build`.

### Run Local TUI
```bash
cd build
sudo ./proxywatch-linux-amd64
```

### Run Ingest Mode (multi-host)
```bash
sudo ./proxywatch-linux-amd64 -listen 0.0.0.0:50051
```

Agent example:
```bash
./pwa-windows-amd64.exe server <proxywatch-ip>:50051
```

## TUI Keys
- `UP/DOWN`: move selection
- `ENTER`: inspect selected process
- `x`: toggle explain details in inspect mode
- `k`: kill process (with confirmation)
- `w`: whitelist selected process
- `W`: manage whitelist entries
- `c`: open collection workflow
- `q`: quit

## Roles (Operator View)

| Role | Meaning |
| --- | --- |
| `susp-tun` | Session/tunnel behavior with strong tunnel evidence |
| `susp-session` | Persistent control channel without tunnel proxy shape |
| `susp-beacon` | Recurring callback pattern (cadence-driven) |
| `listener-*` | Listener variants (`clients`, `outbound`, or `only`) |
| `outbound-only` | Outbound traffic with no suspicious control shape |

## How Classification Works (Low-Level)

Classification logic is in `proxywatch/internal/classifier/rank.go`.
State/threshold values are in `proxywatch/internal/shared/classify.go`.

Core signals:
- Control channel: long-lived `ESTABLISHED` outbound connection (age-based).
- Tunnel shape: listener + control + local/internal fanout patterns.
- Beacon shape: recurring short-lived callbacks with cadence/jitter checks.
- Destination verification: internal/external scope and prefix diversity.
- ASN assist: resolved ASN org alignment/mismatch as a bounded secondary score adjustment.
- Stability guards: session/beacon precedence and display smoothing to reduce role thrash.

Current behavior notes:
- Active long-lived control channels stay session-oriented (avoid random beacon flips).
- Short-lived suspicious processes are retained briefly in UI (linger window) so operators can inspect them.

## Inspect Mode

Inspect mode displays:
- Process identity: user, path, parent PID, integrity.
- Traffic summary: `Proto In/Out`, established, listeners.
- Connection list: local/remote/state/scope.
- ASN orgs: resolved external destination org context.
- Explain block (`x`): reasons + signals used for current role.

## BloodHound Collection

Collection is TUI-driven:
1. Press `c`
2. Set output/duration/roles
3. Start collection
4. JSON is written when timer ends (or stop early)

Cypher query pack:
- `docs/queries.md`

### Upload Config
Set env vars in the same shell that launches ProxyWatch:
```bash
export BLOODHOUND_API_URL='http://<bh-host>:8282/api/v2'
export BLOODHOUND_API_TOKEN='<token-or-key>'
export BLOODHOUND_API_ID='<id-for-hmac-keys>'
```

If running as root, preserve env:
```bash
sudo --preserve-env=BLOODHOUND_API_URL,BLOODHOUND_API_TOKEN,BLOODHOUND_API_ID ./proxywatch-linux-amd64
```

Accepted aliases:
- URL: `BLOODHOUND_API_URL`, `BLOODHOUND_URL`
- Token: `BLOODHOUND_API_TOKEN`, `BLOODHOUND_API_KEY`, `BLOODHOUND_TOKEN`
- Token ID: `BLOODHOUND_API_TOKEN_ID`, `BLOODHOUND_API_ID`, `BLOODHOUND_TOKEN_ID`

### Collector Graph Behavior
Collector logic: `proxywatch/internal/bloodhound/collect.go`

- Emits Host/User/Process/Endpoint nodes.
- If a remote IP maps to a known host, collection emits both:
  - host pivot edges (`SuspConnectsToHost*`), and
  - endpoint edges (`SuspConnectsTo*`) for endpoint-based queries.
- Endpoint labels include hostname context when known.

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
- For release notes, see `CHANGELOG.md`.
