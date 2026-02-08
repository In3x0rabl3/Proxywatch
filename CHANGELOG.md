# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
