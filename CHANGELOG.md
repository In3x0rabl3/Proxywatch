# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **`rich-local-ipc-shape` shadow signal.** Fires when a process owns ≥2 loopback-bound listener ports (TCP + UDP combined) AND has ≥2 established loopback flows. Captures the desktop / Electron-app IPC pattern (Zoom helpers mesh, Slack, CloudSync, Docker Desktop, IDE ↔ language-server). Shadow-only — not in `controlSignals` / `pivotSignals` / `outboundSignals`, so it does not vote in `InferRoleFromSignals`. Surfaces in `/candidates` + `/fp-report` for operator inspection. Intended for measurement across lab candidates before any promotion to a vendor-signal-count contributor in the FP-shape demotion path; a sophisticated implant could fake the pattern by spinning up dummy loopback listeners, so this signal is never the sole gate for any role decision in this release.
- **macOS signature + package-ownership verification.** Phase 2 of the darwin backend. `codesign -dv --verbose=4` runs as a bounded (3s) subprocess from the signature-verification worker, parsing the Authority chain + TeamIdentifier to populate `SignatureTrust` + `Publisher`. Third-party apps signed with a Developer ID (Zoom, Slack, VS Code) now register as `SignatureTrustTrusted` with Publisher = "Zoom Communications, Inc." etc. `pkgutil --file-info-plain` runs (2s bounded, 5-minute cache) to extract the pkg-id for binaries installed via .pkg, populating `PkgOwned` + `PkgOwnerName`. This unlocks the FP-shape + `ApplyVendorIPCRescue` demotion paths on darwin: Zoom/Slack/CloudSync now have the identity signals required to demote out of control-* labels when their helper-mesh IPC trips rank.go's ActiveProxying gate. Fallback path for unsigned / ad-hoc-signed binaries remains the trusted-prefix + uid heuristic in `signature_darwin.go`.
- **macOS telemetry collection.** Phase 1 pure-Go detection pipeline for darwin — no cgo, compiles cleanly under `CGO_ENABLED=0`. `Collect()` now returns a real snapshot on macOS instead of the "unsupported" stub. Process enumeration via `unix.SysctlKinfoProcSlice("kern.proc.all")` yields pid, ppid, command name, status, effective UID, and start time for every process; `KERN_PROCARGS2` fills in executable path + full command line. Network state comes from a bounded `lsof -nP -i -F pPcnT` shell-out (lsof ships with every macOS install) parsed into TCP listeners, TCP connections (with states), and UDP listeners. `KillProcess` uses `syscall.Kill(pid, SIGKILL)` like Linux. Deferred to Track 11c: codesign-based SignatureTrust/Publisher, `pkgutil --file-info` PkgOwned, Mach-O LoadedLibs, per-process IO counters, HasRWXMemory / AnonExecCount, named-pipe enumeration, raw-socket PIDs. Current Phase 1 coverage is enough for role assignment (rank.go only needs topology + metadata) and delivers Zoom/Slack/CloudSync-class classification out of the box; vendor-identity FP suppression on darwin remains conservative until codesign integration lands.
- **darwin/arm64 release target.** Apple Silicon builds now ship alongside darwin/amd64 in the release workflow, with CI coverage in the build matrix and a `darwin/arm64` entry in the Makefile `TARGETS`.
- **linux/arm64 release target.** ARM Linux builds (Graviton, Ampere Altra, Raspberry Pi 4/5 64-bit, etc.) ship alongside linux/amd64 in the release workflow, with CI coverage and a `linux/arm64` Makefile entry.
- `docs/api-reference.md` — complete HTTP API reference covering the local/server-mode Debug API, the per-agent Debug API for connect-mode agents, and the headless Contour API. Documents every endpoint with methods, query parameters, request/response schemas, and operator usage patterns (polling during scans, capturing baselines for regression diffing, training operator labels).
- `docs/detection.md` — single presentation-friendly detection overview. Covers the role taxonomy, how roles are decided (rule engine + on-device ML), pivot linger, tunneling state semantics, role disambiguation, FP suppression tiers, worked examples, and code pointers.
- **`beacon-static-crypto-likely` shadow signal.** Fires when a process has external HTTPS traffic with zero dynamic crypto libraries loaded, is not a known vendor, and is unsigned. Fingerprints statically-linked Go / Rust / Nim beacons (Sliver, Merlin, Poseidon, Thanatos, Nimplant, Freyja) whose `crypto/tls` is bundled, not linked to schannel/bcrypt. Shadow-only — not in role-vote maps.
- **`lots-saas-c2-endpoint` shadow signal.** Fires when an unknown-vendor unsigned process connects to a known SaaS C2 endpoint (Slack, Discord, GitHub, Telegram, HiveMQ, Dropbox, Notion, Trello) via reverse-DNS lookup. Catches Mythic's public-SaaS C2 profiles that bypass the ASN-alignment FP-shape gate. Shadow-only with suffix-match tests.
- **`/ml/shadow` debug endpoint.** Returns the current rolling shadow-agreement rate, qualify/degrade thresholds, qualified/demoted flags. One-shot ML health summary.
- **`/ml/disagreements` debug endpoint.** Ring buffer of the last 100 ML-vs-rule disagreements with per-PID context (host, name, exe path, SHA256, both roles, confidence). Chronological order. Populated from the existing shadow-comparison site in `classifier.go`.
- **`/fp-report/summary` debug endpoint.** Aggregate counts by role, state, signal, FP-shape blocker, suppression reason. Eliminates the need for clients to pull the full per-candidate entry list and aggregate.
- **`/metrics/prom` Prometheus text-format endpoint.** Emits `proxywatch_candidates_total`, `proxywatch_cycle`, `proxywatch_candidates_by_role`, `proxywatch_candidates_by_state`, `proxywatch_ml_shadow_agreement_rate`, `proxywatch_ml_qualified`, `proxywatch_ml_demoted`. Scrapable by any Prometheus-compatible collector.
- **`/self` debug endpoint.** Returns the same shape as `/candidates` at a stable path that works in both local and server mode. Monitoring configs can point at `/self` unconditionally.
- **`PROXYWATCH_LOG_JSON=1` structured NDJSON logging.** When set, each `LogInfo`/`LogWarn`/`LogError` event also emits a single-line JSON object to stderr for SIEM ingestion. Opt-in — TUI default stays quiet.
- **FP-shape override instrumentation.** Every soft-blocker override decision logs a structured event with the full vendor-signal set and soft-blocker set for threshold-tuning analysis.
- **Dashboard classifier-lifecycle label.** Header shows `Classifier: ML` (green) when qualified, `ML DEGRADED` (red) when demoted, `Rules` otherwise. Operators see model health without opening the Training tab.
- **CI pipeline.** `.github/workflows/ci.yml` with build matrix (linux/windows/darwin amd64), `go vet`, `gofmt`, and `go test` jobs. `.github/workflows/release.yml` for signed releases via cosign keyless OIDC on tag push.
- **Test coverage foundation.** `scoring/roles_test.go` (DeriveRole, IsMaliciousRole, IsRoleUpgrade, ConfidenceFor, IsReverseControlShape — 38 cases), `scoring/util_test.go` (IsSuspiciousExePath, conn-state classifiers — 23 cases), `behavior/saas_test.go` (SaaS suffix matching — 16 cases), `shared/heuristics_test.go` (IsLOLBinProcess, IsScriptingEngine, IsLikelyBenignControlClient, IsKnownVendorProcess, IsKnownUpdaterProcess — 64 cases), `shared/classify_test.go` (RoleFamily, IsControlRole, InferRoleFromSignals, RoleMatchesFilter — 30 cases). Total: 5 test suites, ~170 test cases.

### Fixed
- **Signed vendor desktop / Electron apps (Zoom, CloudSync, Slack) held at `control-channel` / `control-pivot`.** `rank.go` correctly sets `ActiveProxying=true` on these apps when their helper-mesh IPC matches a relay-shaped topology, but that flag is treated as a hard blocker in both `DemoteShapeOnlyControlRole` (via `HasHardDistinguisher`) and `ApplyVendorFPShape` (via `ClassifyVendorFPBlockers`), preventing either demotion path from firing. New `ApplyVendorIPCRescue` rule in `shared/vendor_fp_shape.go` demotes the role to `outbound` (or `listener` when the process binds listener ports) when `rich-local-ipc-shape` converges with: signed Authenticode-trusted binary, non-empty Publisher, Authenticode-OCSP-verified OR trusted install path, and at least one independent identity signal (PublisherDNSAligned / PkgOwned / publisher-company match / outbound-asn-org-aligned). Electron / JIT apps with `HasRWXMemory=true` require two independent identity signals to compensate for the lost RWX-memory check. Implant-decisive signals (`injection-rwx-external`, `beacon-static-crypto-likely`, `pivot-ssh-tunnel-flags`, `pivot-named-pipe-c2-pattern`, `beacon-syn-cycle-cadence`, `raw-socket`, `child-tunnel-relay`, `pivot-anon-exec-memory`) always block the rescue, as do operator label = malicious, LOLBin process name, and authenticode distrust. An implant masquerading as a signed vendor app still trips at least one of those implant-decisive signals and keeps its label.
- **UDP-only listener daemons misclassified as `outbound`.** NetworkManager (DHCP client on UDP :68), systemd-resolved, dnsmasq, mDNS, NTP, SNMP-trap listeners, and other UDP-only processes were all landing in the `outbound` role because the role-assignment gate in `scoring/rank.go` only counted TCP listeners (`SocksListenerPorts(c.Listeners)` — a TCP-specific SOCKS-detection helper). Extracted a protocol-agnostic `HasAnyListener(c)` into `scoring/network.go` that covers both `c.Listeners` and `c.UDPListeners`, and pointed rank.go at it. UDP daemons now correctly get `listen`. Side benefit: tightens the `hasListener` exclusion gate used by `CanPromoteBeaconRole` / `ShouldPromoteControlSession` / `IsReverseControlShape` / `IsLikelySingleControlNoProxy`, so UDP listener daemons can no longer trip those threat-role promotion paths.
- **darwin build unbroken.** The v1.0.6 CHANGELOG claimed `GOOS=darwin go build ./...` all-clean, but `internal/ui/platform/` only shipped `_linux.go` / `_windows.go` files (explicitly tagged) and `cmd/proxywatch/service_linux.go` defined service hooks used unconditionally from `main.go` — so any darwin build failed with "build constraints exclude all Go files in internal/ui/platform." CI matrix hit the failure silently. Fixed by retagging the UI-platform files as `//go:build linux || darwin` (renamed `_linux.go` → `_unix.go`) and adding `cmd/proxywatch/service_darwin.go` with stubs returning "service mode not yet supported on macOS; use -connect directly" for `installService` / `startService` / `stopService` / `removeService` / `runService`. Darwin binaries now link + run; real-time telemetry still goes through the existing unsupported-OS stub. Verified `Mach-O 64-bit x86_64` and `Mach-O 64-bit arm64` outputs.
- **Windows `beacon-crypto-lib-loaded` signal restored.** The module enumeration on Windows (`EnumProcessModules`) was disabled in v1.0.6 because a naive timeout-goroutine approach could hang when the main scan path closed the process handle while a goroutine was mid-syscall on it — leaving protected service hosts (svchost with PPL) capable of stalling the scanner indefinitely. Re-enabled via a handle-duplicating wrapper (`DuplicateHandle` + goroutine-owned handle + 400 ms timeout + per-PID 60 s cooldown) in `telemetry/process_windows_libs.go`. A hung goroutine leaks its own duplicate but cannot corrupt state or stall the main path. Also added `LoadedLibs` to `shared.ProcessMeta` so the enumeration survives the 60 s process-meta cache TTL; previously the signal fired only on first observation then vanished forever because `applyCachedMeta` zeroed it. Verified live on the lab agent: scanner stayed at ~250 ms per cycle, the signal fires on real crypto-linked processes (svchost, onedrive.sync.service, startmenuexperiencehost), no regressions on the known lab binary set. Go-compiled beacons (Sliver) still won't fire the signal because Go's `crypto/tls` is pure-Go and doesn't link schannel / bcrypt — separate gap.
- **Manual "trigger training cycle" now works below the 200-sample auto threshold.** The dashboard trigger was routing through the same `ValidateDataset` gate as the auto path, which hard-errored below 200 samples — so a user asking for a manual retrain with a partial buffer would see training flash, fail at validation, and clear the buffer with nothing learned. Split the trigger into two orchestrator methods: `TriggerRetrain` (auto, 200-sample floor) and `TriggerRetrainManual` (operator-initiated, 20-sample floor). Dashboard now calls the manual variant. Buffer still clears on both success and failure so collection restarts cleanly for the next cycle.
- **ML shadow-agreement UI vs code mismatch.** Training view claimed the model needed 60% agreement over 100 predictions to qualify; the actual gate was 70% / 200. View now reads the real thresholds from `model.ShadowQualifyAgreement` and `model.ShadowQualifyPredictions` so the displayed numbers match what the runtime enforces.
- **ML model silently degrading over time.** Shadow agree/disagree counters were lifetime atomics with no decay, so an early run of good agreement masked later degradation indefinitely — a qualified model could keep primary status even as its rolling agreement rotted. Two changes address this:
  - `RecordShadowComparison` now halves both counters when the running total exceeds 2000, giving a rolling-window rate that reflects *recent* agreement.
  - New hysteresis band in `ComputeMaturity`: qualified models stay qualified until rolling agreement falls below `ShadowDegradeFloor = 0.60` (vs the `ShadowQualifyAgreement = 0.70` bar to qualify). When that happens, the model is demoted back to shadow mode and an `mlDemoted` latch fires. Training view surfaces a red "DEGRADED" indicator until the next retrain swaps in a fresh predictor.
  - Retrain hot-swap now calls `model.ResetShadowForRetrain()` — zeros the shadow counters, clears the demoted latch, and unqualifies so the new predictor is judged on its own predictions rather than inheriting the prior model's reputation.

### Changed
- **Online verification is on by default.** The signature worker now starts in `live` posture without any environment variable. Windows runs full Authenticode + OCSP through WinTrust; Linux/macOS fall back to path + ownership trust hints. Operators in air-gapped environments can opt out with `PROXYWATCH_ONLINE_VERIFY=cache-only` (consult cache, no outbound calls) or `PROXYWATCH_ONLINE_VERIFY=off` (fully disabled). Previously defaulted to `cache-only` and required explicitly setting `PROXYWATCH_ONLINE_VERIFY=live` to enable OCSP checks — that was a bad default because the features that feed the classifier (`FOnlineKnownBenign`, `FOnlineKnownMalicious`) only populate under live verification.
- Docs scrubbed to match v1.0.6 layout: removed stale Calibration / SIEM dashboard sections from `README.md`, updated file-path references from `internal/detection/rank.go` to `internal/detection/scoring/rank.go`, dropped calibration/SIEM rows from the Managed Keys and Persistence tables, and rewrote `proxywatch/docs/architecture/CODEMAP.md` against the current tree.
- Added vibe-coded disclaimer to `README.md` noting significant portions of ProxyWatch were authored with AI-pair-programming assistance.
- Consolidated duplicate Cypher query docs: deleted `proxywatch/docs/queries.md` (old Session/Beacon/Tunnel role taxonomy). `docs/queries.md` (control-* taxonomy) is the single source.
- Simplified `PULL_REQUEST_TEMPLATE.md` — replaced `<TODO>` placeholders with a minimal Summary / Type / Testing / Checklist template.

### Removed
- Three detection-architecture docs (`docs/detection-architecture.md`, `docs/control-channel-architecture.md`, `docs/detection-redesign-v2.md`) consolidated into a single `docs/detection.md`. The old docs had heavy overlap, internal implementation detail (specific signal names, feature indices, retrain triggers), and historical migration notes that aren't useful for presentation or operator orientation.

## [1.0.6] - 2026-04-15

### Added
- **Time-lingered control-pivot role promotion**: new `PivotUntil` runtime map (in `shared/classify.go`) plus `ApplyPivotLinger` (in `detection/scoring/child_tunnel.go`). When a process emits `pivot-non-loopback-internal` in a relay context (C1: already a control role; C2: owns listener + has inbound; C3: ancestor in the process tree owns listener + has inbound), the process is stamped into `PivotUntil` for 60 seconds and held at `role=control-pivot` for the window — regardless of what the ML model's committed role would otherwise hold. After the window, the role reverts naturally.
- **Multi-level parent-chain walk** for the relay-context check: Windows OpenSSH's two-level privsep tree (`sshd_main → sshd_privsep → sshd_session`) now resolves correctly to the listener ancestor even when the intermediate privsep helper is filtered out of the candidate slice. The walker uses `snap.Processes` (from telemetry) up to 4 levels deep.
- **Enriched pivot evidence**: new `describePivotEvidence` composer. When a process is promoted via `PivotUntil`, the reason string now includes the exact TCP relay targets (`ip:port`, deduped, capped at 3 + `+N more`), named pipe names (prefix-stripped for legibility, same cap), and a dedicated `"SMB admin-share relay (port 445)"` flag when the `pivot-admin-share-smb` signal is present. Visible in the Inspector's Evidence panel.
- **Pre-existing tunnel/session detection** at process first-observation: a process seen for the first time with both external + internal ESTABLISHED connections gets a +25 score boost (and +20 more for long-lived externals on non-benign clients), gated on proxywatch uptime exceeding `StartupGracePeriod` so service restarts don't false-flag everything as pre-existing.
- **Online verification signals** (`FOnlineKnownBenign` / `FOnlineKnownMalicious`, features 120–121) — Authenticode OCSP trust hints populated when `PROXYWATCH_ONLINE_VERIFY=live` on Windows, with pre-populated cache support across all platforms. Schema bump from 120 → 122 features; existing trained models are invalidated and the continuous learner retrains from its buffer.
- **Training view** (Dashboard → Training): live ML training data, feature schema, role predictions, model maturity, and retrain timing.

### Changed
- **Tunneling state gate is strict real-time**: `CandidateState` returns `"tunneling"` only when the process is control-channel or control-pivot AND (IO ≥ 512 B/s on internal conn OR a fresh internal conn arrival within the 30s conn-recency window). Removed the 30s `TunnelingSeen` linger that was previously pinning tunneling state ON for any process with tunnel topology — rank.go stamps `TunnelingSeen` every cycle from topology alone, which made the linger stick indefinitely. State now reflects actual byte movement.
- **Restored pre-refactor behavior for sshd-like SOCKS forwarders**: the role-escalation path at `rank.go:1670` now accepts `role=outbound` in addition to `control-channel/listen/listener` when both `tunnelingRecent` (ActiveProxying now or `TunnelingSeen` within 60s) and `pivotRecent` (pivot-non-loopback-internal now or `PivotInternalSeen` within 60s) hold. Fixes the regression where sshd children stayed at `outbound` during active SOCKS forwarding because they couldn't reach `control-channel` on their own (no listener, single target/port below `reverseTunnelEligible` threshold).
- **Detection pipeline restructured into typed subpackages**: `internal/detection/` now contains `behavior/` (signal emitters per role), `features/` (ML feature extraction), `gbdt/` (LightGBM predictor), `ml/` (learner + training), `model/` (role commit + calibration + experience), `output/` (debug API + emission), `scoring/` (rank + classifier helpers), and `telemetry/` (process/network/raw-socket enumeration). The previous flat `internal/detection/*.go` layout is gone.
- **`internal/contour/` restructured** into `api/`, `probe/`, `tunnel/` subpackages with thin re-export shims in the top-level `contour.go` and `reexport.go` so external callers don't break.
- **`internal/agent/` split** into `auth/` (bootstrap + TLS + trust), `convert.go`, `debug.go`, and generated protobuf code. Removed stale enrollment and trust-runtime shims.
- **`internal/shared/` expanded** with dedicated files: `display.go`, `distinguishing.go`, `dns_cache.go`, `eventlog.go`, `exe_hash.go`, `heuristics.go`, `online_evidence.go`, `operator_labels.go`, `publisher_domains.go`, `roles.go`, `signature*.go`, `state.go`, `vendor_fp_shape.go`, `verifier_pkg_*.go`, `verifier_publisher_dns.go`. Replaces the previous omnibus files.
- **ML is the primary role classifier** when the predictor is loaded and qualified via shadow agreement + prediction volume. Before qualification, ML runs shadow-only and rank.go's topology decision stands. Signal-based overrides (Cases 1/2/3 in `classifier.go`) gate strictly on `mlLowConfidence < 0.80` — a high-confidence ML prediction outweighs single-heuristic topology flips, so `msedgewebview2`-style cases (ML 99% outbound, topology control-channel) stop flipping.

### Removed
- **Tier A-E dead code cleanup**: ~96 unreachable functions, helpers, and scaffolding verified dead via multi-platform `deadcode` + cross-reference grep + function-variable wiring audit + external-consumer check + reflective-usage check. Deletions span `internal/calibration/{ai_integration,core,learning,reporting,sampling,tuning_normalization}.go`, `internal/contour/` tunnel/probe/deaddrop subsystems, `internal/detection/{delegated,output,rank*}.go`, `internal/model/{analyze,decide,egress,experience,feedback,model,patterns,quality,runtime}.go`, `internal/agent/{auth,auth_bootstrap,enroll,pb_convert,tls_runtime,trust_runtime}.go`, `internal/telemetry/*` platform stubs consolidated under `detection/telemetry/`, `internal/ui/` orphaned SIEM and training helpers, `internal/siem/*` file-local leftovers, `internal/shared/` LOLBin/MITRE/HTTP helpers with no remaining callers. Build-tag platform shims preserved (Tier F).

### Fixed
- **sshd parent-child SOCKS detection regression**: the cleanup refactor had rewritten `CandidateState` to gate tunneling on role ∈ {control-channel, control-pivot}, which locked out sshd children (they stay at `role=outbound`). Restored via the `PivotUntil` promotion path.
- **Botched refactor artifact** at `rank.go:968-971`: orphaned `c.ActiveProxying = true` line immediately overwritten on the next line, a cleanup merge conflict remnant.
- **Role assignment after ML override**: the ML model's committed-role hold (kicks in at ≥30 observations with benign/benign suggested/committed) was silently reverting control-pivot promotions. The pivot linger enforcement now runs *after* `model.DecideRole` via `scoring.ApplyPivotLinger(candidates, snap.Processes)` in `classifier.go`, so held benign roles can't un-promote an active pivot.

### Code Quality
- `go build ./... && GOOS=windows go build ./... && GOOS=darwin go build ./...` all clean.
- `go vet ./...` clean.
- Live end-to-end verification on Windows agent 172.16.1.2 via `proxychains4 -f /etc/proxychains4.conf nxc ssh 172.16.1.2` (burst) and `nmap -sT -Pn -p 1-400 172.16.1.2 -T4` (sustained): sshd child correctly flips `outbound → control-pivot` + `state=tunneling` during flow, holds control-pivot through brief idle dips via the 60s linger, reverts naturally. cheerful_glove, beacon-j, session.exe, liquid_mezzanine, system pid 4 retained their existing classifications; svchost/lsass/wininit/spoolsv/explorer stayed `outbound/watch` with no false promotions.

## [1.0.5] - 2026-04-03

### Added
- **Dead drop tunnels via OpenAI Files API**: full SOCKS5 relay through OpenAI's `/v1/files` endpoint using `.jsonl` uploads with `purpose=fine-tune`. Both forward and reverse modes verified with E2E tests.
- **GitHub dead drop**: session management with creator/non-creator pattern, stale session cleanup, `since`-filtered comment polling for reduced API pressure.
- **Services mode**: new tab in Contour alongside Scan and Tunnel. Table display with columns for Service, Status, Method, and Key. Currently GitHub and OpenAI.
- **Dashboard number key jumping**: press `0-6` from any view to jump directly to Dashboard, Calibration, Contour, ProxyHound, SIEM, Whitelist, or Keystore.
- Crash recovery in background refresh goroutine — panics in detection pipeline no longer crash the application.
- Tunnel constants centralizing 21+ magic values (`tunnelDialTimeout`, `tunnelIOTimeout`, `tunnelFrameBuf`, `tunnelRelayBuf`).

### Changed
- **Model maturity formula hardened**: "experienced" threshold raised to 5,000 observations, population scale requires 200+ profiles, feedback requires 20+ actions. New signal diversity and training pattern components.
- **SIEM report overhauled**: wider 78-char box with double-line header, per-detection confidence/signal/query counts, analysis section, word-wrapped descriptions, query truncation raised to 100 chars. JSON output excludes `report_lines`.
- **Services box redesigned**: table format with status indicators (`✓ READY` / `✓ reach` / `✗ blocked` / `○ untested`) and key column.
- **Azure probe domain fixed**: `azure.microsoft.com` → `blob.core.windows.net`.
- **Dashboard cycling fixed**: removed `LocalHost` guard blocking workflow cycling, removed double Left/Right event processing. All views handle cycling directly.
- Deprecated `viewport.LineUp`/`LineDown` replaced with `ScrollUp`/`ScrollDown` across all views.

### Removed
- Dead drop services: Slack, Discord, Firebase, AWS, Azure Blob, GCS, Teams, Buildkite, GitLab and all SaaS/serverless tunnel transports. Kept GitHub and OpenAI only.
- Telegram: all tunnel and dead drop code removed.
- 70+ unused functions, types, variables, and constants across all packages.

### Code Quality
- 14 identifiers unexported to reduce public API surface.
- BloodHound → ProxyHound naming in comments, docs, and display labels.
- All `staticcheck`, `go vet`, and `gofmt` issues resolved (46 capitalized error strings, latent bug where model override reasons were silently dropped, and more).

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
