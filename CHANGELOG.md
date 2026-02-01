# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.1] - 2026-02-01

### Added
- ProxyWatch Agent with gRPC streaming ingest and remote kill support.
- Windows service support for the agent (`--install/--start/--stop/--uninstall`).
- Host column in the TUI and per-endpoint remote kill handling.
- Whitelist UI (`w` to add, `W` to manage) with on-disk storage.
- TUI collection screen for BloodHound graph output (output path, duration, roles).
- BloodHound OpenGraph JSON export including Host/User/Process/Endpoint nodes and susp-* edges.
- Queries guide (`queries.md`) with prebuilt Cypher examples.

### Changed
- Default refresh interval set to 250ms for both UI and agent.
- Default UI filter shows only `susp-session`, `susp-beacon`, and `susp-tun` unless `-roles` is set.
- Agent binary renamed to `pwa.exe` and service name updated to ProxyWatch Agent.
- Networking/inspect output consolidated to include TCP/UDP in/out, established, and listeners.
- Collection runs from the TUI instead of CLI flags.
- Build flow uses top-level `make` to output binaries into `dist/`.
- Build now runs the TLS generator with host GOOS/GOARCH and uses an absolute GOCACHE for cross-compiles.
- README shortened with tables for telemetry inputs and role triggers; build steps simplified.

### Removed
- One-shot `-once` mode.
- Allowlist/allow-publisher/allow-user/allow-path flags and related behavior.
- JSON logging flags and logger implementation.
- `no-network-activity` role.
- `likely-tunnel` role.
- Local build artifacts in `dist/` (repo cleanup).

### Fixed
- Remote kill support now routes through the agent stream.
- Default UI no longer highlights allowlisted processes unless explicitly whitelisted.
- BloodHound export metadata to match ingest schema (removed unsupported fields).

### Security
- Automatic TLS/mTLS ingest with a per-build trust bundle.
