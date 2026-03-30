# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.4] - 2026-03-30

### Added
- **Raw socket detection**: processes using raw/packet sockets (nmap SYN scans, ping, tcpdump) are now detected and displayed in the dashboard with "Raw socket open (bypasses TCP stack)" reason and a score of 20.
- Raw socket connections shown in inspector CONNECTIONS box as `RAW` protocol entries.
- `/proc/net/raw`, `/proc/net/raw6`, and `/proc/net/packet` parsed for raw socket PID resolution.
- Environment variable fallback for `keystore.RuntimeValue()` — API keys can be set via env vars without a keystore.
- `RuntimeSetValue()` and `ClearSensitiveRuntime()` functions in keystore package for fine-grained runtime key management.
- Keystore **activate** action (`a` key) to mark a keystore as active without opening fields.
- Keystore **auto-lock on dashboard exit** — leaving the Keystore view automatically locks the keystore.
- Keystore **auto-relock for secure keystores** — after YubiKey decrypt for calibration/SIEM, values are applied to runtime then immediately relocked; sensitive keys cleared after operation completes.
- Keystore creation wizard accessible from fields panel via "Create" row and `n` key in display list.
- `isActiveKeystoreSecure()` helper that checks the registry instead of stale `app.KeystoreSecure`.
- Calibration and SIEM **YubiKey decrypt-and-retry** — when API key is missing and a secure keystore is active, automatically prompts for YubiKey touch, decrypts, and retries the action (once per attempt).
- `calibrationError()` and `siemError()` helpers that truncate error messages to screen width to prevent word wrap.
- Error notifications across all dashboards when actions fail to start, with clear reasons.
- Status messages for locked fields during active collection ("cannot change source while collection is running").
- BloodHound collection results display with three orange boxes: GRAPH (nodes, edges, candidates, hosts), NETWORK (external/internal connections, listeners, duration), OUTPUT (file path, upload status).
- Inspector **process cycling** with Left/Right arrow keys.
- Inspector **orange-bordered section boxes** for IDENTITY, PROCESS, NETWORK, ANALYSIS, REASONS, CONNECTIONS.
- Calibration report **orange-bordered section boxes** for CONFIDENCE, TUNING, RECOMMENDATIONS, LEARNING, HISTORY, REASONING with spaced-out recommendations.
- SIEM report **orange-bordered section boxes** for SUMMARY, DETECTIONS (high-level only), NOTES. Query/rule details kept in JSON output only.
- Contour **MATRIX** and **SERVICES** titled boxes with purple borders; **ROUTES**, **ENDPOINTS**, **MISC** titled info panels.
- `renderAccentPanel()` for orange-bordered titled panels matching contour's style.

### Changed
- Keystore view redesigned: SETUP panel always visible below FIELDS; Tab toggles between fields and display list; DISPLAY panel replaces KEYSTORES panel name.
- Keystore security panel simplified: shows "YubiKey (N slots active)" instead of verbose per-slot details.
- Keystore fields panel: labels padded to 13 chars for aligned values; Lock and Apply labels cleaned up (removed emoji).
- All emoji removed from keystore UI (lock icons, etc.) to fix lipgloss width miscalculation causing misaligned panel borders.
- `renderPanel()` top and bottom border width calculation uses `lipgloss.Width()` instead of `len()` for correct multi-byte character handling.
- `renderSetupPanel()` label width increased from 10 to 15 for consistent alignment.
- All dashboard DISPLAY panels reserve 1 line for status bar to prevent bottom border clipping.
- Startup keystore auto-load no longer sets `KeystoreUnlocked=true` — values are in runtime but keystore view shows locked state.
- Startup skips secure keystores silently instead of showing decrypt error on dashboard.
- Mode switching clears sensitive runtime values when using a secure keystore, requiring fresh YubiKey touch per dashboard.
- SIEM `applySIEMGenerationSettings()` uses `RuntimeSetValue()` for individual keys instead of `ApplyToRuntime()` which was overwriting API keys.

### Fixed
- **Contour crash**: `ui_loop.go` copied entire `AppState` (including `sync.Mutex`) into a goroutine, causing undefined behavior. Now creates a fresh struct with only needed fields.
- `go vet` warning for mutex copy eliminated.
- Keystore panel border misalignment from emoji double-width characters.
- Keystore delete not resetting UI state (panel, field, editing flags).
- Keystore creation wizard not resetting `KeystorePanel` to 0 after creation, leaving key handlers stuck on list panel.
- Keystore `selectKeystoreEntry` now falls back to `Load()` when `LoadSecure()` returns "not a secure keystore" (old-format encrypted keystores).
- Calibration could start without API key when runtime had stale values from a previous plain keystore.
- SIEM generation showed "started" even when provider keys were missing; now validates upfront.
- SIEM display was empty after generation due to overly aggressive line filtering.
- Inspector IO display changed from "N/A (needs root)" to "N/A" when running as root.

### Security
- API error response bodies truncated to 500 chars to prevent leaking sensitive data.
- `CALIBRATION_HTTP_TIMEOUT` capped at 5 minutes maximum.
- Sensitive runtime values (API keys) cleared after calibration/SIEM operations complete when using secure keystores.
- Keystore auto-locks on dashboard exit to minimize plaintext exposure.

### Removed
- Dead functions: `indexOf`, `startEventPump`, `handleUIEvent`, `stepContourField`, `stepSIEMField`, `stepCalibrationField`, `stepDuration`, `detectFIDO2Slots`.
- Dead contour functions: `formatEndpointList`, `mergeProbeStatuses`, `ternaryBound`, `formatListenerCheckLine`, `renderProbeCheckSummary`, `summarizeProbeChecksByPort`, `summarizeProbeCheckSamples`, `probePercent`, `summarizeProbeChecksByMethod`, `summarizeProbeCheckCounts`, `buildProbeRequestPacket`, `validateProbeResponse`, `buildProbeAMQPFrame`, `readTCPOnce`.
- Dead code: `_ = contentW` assignment in `tea_shared.go`.

### Code Organization
- Consolidated `tea_keymapping.go` + `tea_legacy.go` + `vscreen.go` into single `legacy.go`.
- Merged `tea_styles.go` into `tea_shared.go`.
- Renamed `ui_loop.go` to `tea_loop.go`.
- UI directory reduced from 22 to 19 Go files.

## [1.0.3] - 2026-03-24

### Added
- New **Contour** subsystem (`internal/contour/*`) with probe matrix execution, endpoint/proxy discovery, packet-wire validation, and role/mode aware checks.
- New **Calibration** backend (`internal/calibration/*`) including AI-driven tuning, fallback tuning normalization, historical learning model, profile persistence, and report artifact generation.
- New **SIEM** backend (`internal/siem/siem.go`) for markdown/JSON detection bundle generation with Splunk/KQL/Elastic/Sigma-style query output.
- New encrypted **Keystore** backend (`internal/keystore/keystore.go`) with runtime-config mapping for provider, BloodHound, SIEM, and detection-export settings.
- New persistent classifier memory (`internal/shared/classify_memory.go`) to retain behavioral history across runs.
- New detection output pipeline (`internal/detection/output.go`) for runtime export targets.
- New `internal/safeio` package for safer file IO wrappers.
- New architecture docs and code map under `proxywatch/docs/architecture/`.
- Per-menu help overlays (`?`) across Dashboard, Inspect, BloodHound, Calibration, Contour, SIEM, Keystore, and Whitelist.

### Changed
- Large codebase refactor from legacy `internal/classifier/*` paths to modular `internal/detection/*`.
- Agent runtime architecture expanded and reorganized (`internal/agent/*`) with clearer auth/bootstrap/client/server separation.
- Service entry layout consolidated under `cmd/proxywatch/` (legacy `cmd/proxywatch-agent/main.go` removed).
- Telemetry pipeline reorganized to explicit cross-platform files (`network_linux.go`, `network_windows.go`, `process_linux.go`, `process_windows.go`) and shared capture logic.
- UI stack split into focused renderer and key/runtime modules (`render_*`, `ui_*`) replacing monolithic `tui.go`/`state.go`.
- SIEM generation implementation moved out of calibration into dedicated package (`internal/siem/siem.go`) with calibration bridge (`internal/calibration/siem_bridge.go`).
- README and architecture docs rewritten to match current keybindings, workflows, persistence paths, and module layout.
- Demo media refreshed (`docs/media/Demo.mp4`, `docs/media/Demo-latest.gif`).

### Fixed
- Keystore setup panel clipping that hid `Save`/`Apply` on smaller layouts.
- Reconnect host naming behavior that could leave stale disconnected host rows and create unnecessary host suffixes.
- Dashboard process-list jitter by stabilizing candidate ordering/dedup behavior.
- Calibration analysis now supports runtime cancellation during provider requests.
- BloodHound upload/runtime config path now aligns with keystore-first runtime configuration.
- ProxyWatch runtime binaries are hidden from inspector/process candidate views even when launched from non-standard paths (for example `~/Downloads` release binaries).

### Removed
- Go test files in repository (`internal/agent/server_test.go`, `internal/contour/probe_tunnel_test.go`).
- Legacy classifier package files (`internal/classifier/*`).
- Legacy UI monolith files (`internal/ui/tui.go`, `internal/ui/state.go`).
- Legacy telemetry files (`internal/telemetry/netstat.go`, old process/net file paths).
- Legacy helper/scripts no longer used in new architecture (`proxywatch/scripts/gen_tls.go`, obsolete shared helpers).

## [1.0.2] - 2026-02-08

### Added
- ASN organization resolution in inspect mode for external destinations.
- ASN-assisted scoring as a bounded secondary signal (alignment/mismatch with process context).
- Candidate linger window so short-lived suspicious processes remain visible briefly in the TUI.
- Collection upload configuration diagnostics in TUI status (explicit missing env feedback).

### Changed
- Beacon/session precedence: active long-lived control channels now stay session-oriented instead of flipping to beacon.
- BloodHound collector now emits endpoint edges consistently and includes known-host context in endpoint labels.
- Known host mappings now annotate endpoint relationships with remote host context when available.
- BloodHound upload env loading accepts common aliases for URL/token/token-id variables.
- Collector code path simplified to reduce repeated edge-property construction.

### Fixed
- Frequent mislabeling where persistent session channels were promoted to beacons.
- BloodHound collection troubleshooting visibility when env vars are missing in the running process (common with `sudo`).
- Graph readability in BloodHound by including hostname context on endpoint nodes when IP-to-host mapping exists.

### Removed
- Unused upload helper path in BloodHound auth code.
- Repository `*_test.go` files.

## [1.0.1] - 2026-02-01

### Added
- ProxyWatch Agent with gRPC streaming ingest and remote kill support.
- Windows service support for the agent (`--install/--start/--stop/--uninstall`).
- Host column in the TUI and per-endpoint remote kill handling.
- Whitelist UI (`w` to add, `W` to manage) with on-disk storage.
- TUI collection screen for BloodHound graph output (output path, duration, roles).
- BloodHound OpenGraph JSON export including Host/User/Process/Endpoint nodes and susp-* edges.
- Queries guide (`docs/queries.md`) with prebuilt Cypher examples.

### Changed
- Default refresh interval set to 250ms for both UI and agent.
- Default UI filter shows only `susp-session`, `susp-beacon`, and `susp-tun` unless `-roles` is set.
- Agent binary renamed to `pwa.exe` and service name updated to ProxyWatch Agent.
- Networking/inspect output consolidated to include TCP/UDP in/out, established, and listeners.
- Collection runs from the TUI instead of CLI flags.
- Build flow uses top-level `make` to output binaries into `build/`.
- Build now runs the TLS generator with host GOOS/GOARCH and uses an absolute GOCACHE for cross-compiles.
- README shortened with tables for telemetry inputs and role triggers; build steps simplified.
- BloodHound auto-upload from TUI collections via API token (HMAC or bearer) and configurable env/ldflags.
- Role group shortcuts for `-roles` flag (`all`, `reverse`, `listeners`, `susp`, `control`) with case-insensitive parsing.
- Cross-platform BloodHound upload: JSON upload (correct content-type), HMAC chain aligned to BloodHound docs.

### Removed
- One-shot `-once` mode.
- Allowlist/allow-publisher/allow-user/allow-path flags and related behavior.
- JSON logging flags and logger implementation.
- `no-network-activity` role.
- `likely-tunnel` role.
- Local build artifacts in `build/` (repo cleanup).

### Fixed
- Remote kill support now routes through the agent stream.
- Default UI no longer highlights allowlisted processes unless explicitly whitelisted.
- BloodHound export metadata to match ingest schema (removed unsupported fields).

### Security
- Automatic TLS/mTLS ingest with a per-build trust bundle.
