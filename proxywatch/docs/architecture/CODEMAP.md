# ProxyWatch Code Map

> Maintainer's note: portions of this code map were generated with AI assistance; verify against the current tree before relying on it for deep changes. Run `ls -la proxywatch/internal/**` to confirm paths if the layout has shifted.

Edit-point index grouped by subsystem. Reflects the v1.0.6 layout after the Tier A–E cleanup refactor.

## Entry Points

- `cmd/proxywatch/main.go` — CLI flag handling, service/agent/client/local dispatch, debug-API bring-up.
- `cmd/proxywatch/service_linux.go` — Linux service lifecycle helpers.
- `cmd/proxywatch/service_windows.go` — Windows service lifecycle helpers (SCM integration).

## Transport and Agent

- `internal/agent/server.go` — gRPC ingest server, host/session state, remote actions.
- `internal/agent/client.go` — remote agent loop and stream publishing.
- `internal/agent/convert.go` — protobuf / shared-model conversion helpers.
- `internal/agent/debug.go` — agent-side introspection HTTP endpoint.
- `internal/agent/auth/auth.go` — per-call auth checks (token / cert).
- `internal/agent/auth/bootstrap.go` — token bootstrap / persistence helpers.
- `internal/agent/auth/codec.go` — auth payload serialization.
- `internal/agent/auth/enroll.go` — host enrollment flows.
- `internal/agent/auth/tls.go` — TLS runtime loading and policy.
- `internal/agent/auth/trust.go` — trust-on-first-use (TOFU) pinning.
- `internal/agent/pb/proxywatch_agent.proto` — gRPC contract.
- `internal/agent/pb/service.go` — generated gRPC service stubs.
- `internal/agent/pb/types.go` — generated transport DTOs.

## Telemetry

- `internal/detection/telemetry/network_linux.go` — Linux TCP/UDP collection via `/proc`.
- `internal/detection/telemetry/network_windows.go` — Windows TCP/UDP collection via syscalls, named-pipe enumeration, raw-socket heuristic.
- `internal/detection/telemetry/network_capture_common.go` — shared capture merge / window logic.
- `internal/detection/telemetry/process_linux.go` — Linux process enumeration and metadata.
- `internal/detection/telemetry/process_windows.go` — Windows process enumeration and metadata.
- `internal/detection/telemetry/windows_syscalls.go` — Windows syscall structs / constants.
- `internal/detection/telemetry/telemetry_stub.go` — unsupported-platform stubs.

## Detection Engine

Top level:
- `internal/detection/classifier.go` — classification orchestration, ML dispatch, child-tunnel aggregation, pivot-linger application, experience recording.
- `internal/detection/orchestrator.go` — higher-level run orchestration and result fan-out.
- `internal/detection/incremental.go` — incremental snapshot/refresh helpers.
- `internal/detection/display.go` — display-focused role / state formatting.
- `internal/detection/wrappers.go` — package-external re-export wrappers.

### Scoring (rule engine)

- `internal/detection/scoring/rank.go` — core scoring + role assignment, reverse-control / forward-tunnel / SMB-pipe / pivot escalation blocks.
- `internal/detection/scoring/roles.go` — `DeriveRole`, role-family mappings, confidence computation, reverse-control shape predicate.
- `internal/detection/scoring/network.go` — outbound-target stats, SMB-pipe activity, persistent-control detection, connection-age helpers.
- `internal/detection/scoring/history.go` — per-process history (score, connection churn, role streak, parent-child frequency).
- `internal/detection/scoring/behavior.go` — emits behavior signals after scoring populates candidate fields.
- `internal/detection/scoring/child_tunnel.go` — `AggregateChildTunnelEvidence` (parent listener + short-lived child forwarders) and `ApplyPivotLinger` (time-lingered control-pivot promotion with multi-level parent walk + evidence enrichment).
- `internal/detection/scoring/delegated.go` — delegated-egress / owner-correlation helpers.
- `internal/detection/scoring/util.go` — small math / string helpers used by the scorer.

### Behavior signal emitters

- `internal/detection/behavior/beacon.go` — beacon-family signals.
- `internal/detection/behavior/session.go` — persistent-session signals.
- `internal/detection/behavior/pivot.go` — pivot signals (`pivot-non-loopback-internal`, `pivot-admin-share-smb`, `pivot-named-pipe-c2-pattern`, SOCKS candidates, etc.).
- `internal/detection/behavior/listener.go` — listener-shape signals (wildcard bind, multiplexing, named-pipe servers).
- `internal/detection/behavior/outbound.go` — outbound-shape signals (vendor alignment, path heuristics).
- `internal/detection/behavior/distinguish.go` — cross-role disambiguation (raw socket, proxy-lib, cmdline flags).
- `internal/detection/behavior/helpers.go` — shared predicates used by the emitters.

### ML model

- `internal/detection/features/schema.go` — 122-feature constant layout + names.
- `internal/detection/features/extract.go` — feature-vector extraction from candidate + behavior + profile.
- `internal/detection/features/{beacon,session,pivot,listener_features,outbound_features}.go` — per-role feature computations.
- `internal/detection/gbdt/tree.go`, `trainer.go`, `evaluate.go`, `dataset.go`, `export.go`, `validation.go`, `training_schema.go`, `errors.go` — LightGBM-compatible GBDT implementation and training pipeline.
- `internal/detection/ml/predictor.go` — online predictor wrapping the GBDT trees.
- `internal/detection/ml/buffer.go` — observation buffer used for retrain on schema bump.
- `internal/detection/ml/retrain.go` — continuous-learning retrain loop.
- `internal/detection/ml/metrics.go` — shadow-agreement and prediction volume tracking.
- `internal/detection/ml/native.go` — platform-specific bits.

### Experience model

- `internal/detection/model/decide.go` — role-commitment logic, operator-verdict application, behavior-contradiction override.
- `internal/detection/model/experience.go` — experience record, role history, dominant-role tracking.
- `internal/detection/model/patterns.go` — training-pattern extraction and matching.
- `internal/detection/model/feedback.go` — operator feedback integration.
- `internal/detection/model/quality.go` — model-quality metrics and maturity gating.
- `internal/detection/model/maturity.go` — maturity thresholds + gates for ML qualification.
- `internal/detection/model/runtime.go` — model runtime state, auto-labeling from long-observation profiles.
- `internal/detection/model/egress.go`, `analyze.go`, `model.go` — supporting helpers + type defs.

### Output

- `internal/detection/output/debug_api.go` — HTTP debug API (`/fp-report`, `/candidates`, `/candidate/<pid>`, etc.).
- `internal/detection/output/output.go` — emission pipeline for classified candidates.
- `internal/detection/output/siem_api.go` — JSON export for SIEM-style consumers (legacy name; the in-app SIEM UI was removed in v1.0.6 but the data export path remains).
- `internal/detection/output/suricata.go` — Suricata rule export.
- `internal/detection/output/yara.go` — YARA rule export.

## Contour Backend

- `internal/contour/contour.go` — top-level re-export and bootstrap.
- `internal/contour/reexport.go` — thin shims keeping external callers stable across the subpackage split.
- `internal/contour/api/api.go` — Contour HTTP API.
- `internal/contour/probe/probe.go` — probe/check matrix control and role/mode behavior.
- `internal/contour/probe/probe_config.go`, `probe_endpoints.go`, `probe_findings.go`, `probe_packet_wire.go`, `probe_roundtrip.go`, `probe_services.go`, `probe_transport.go`, `shared.go` — transport / endpoint / service probe families.
- `internal/contour/tunnel/tunnel.go` — tunnel session / relay orchestration.
- `internal/contour/tunnel/tunnel_deaddrop.go` — dead-drop (OpenAI Files / GitHub comments) transports.
- `internal/contour/tunnel/tunnel_protocols.go`, `tunnel_protocols_api.go`, `tunnel_protocols_ext.go`, `tunnel_services.go` — per-protocol tunnel implementations.

## UI Rendering and Interaction

- `internal/ui/root.go` — root model / update / view.
- `internal/ui/loop.go` — app loop, mode routing, async task channels.
- `internal/ui/platform/` — platform-specific helpers.
- `internal/ui/common/helpers.go`, `render.go`, `styles.go` — shared layout / style helpers shared across views.
- `internal/ui/keys/dashboard.go`, `contour.go`, `collect.go`, `keystore.go`, `siem.go`, `training.go`, `workflow.go`, `shared.go` — keymaps per view.
- `internal/ui/render/dashboard.go`, `contour.go`, `collect.go`, `keystore.go`, `whitelist.go`, `consts.go`, `helpers.go`, `common_bridge.go` — render helpers per view.
- `internal/ui/views/dashboard.go`, `inspector.go`, `contour.go`, `keystore.go`, `proxyhound.go`, `report.go`, `siem.go`, `training.go`, `whitelist.go`, `bridge.go`, `legacy.go`, `live.go` — view models.

## Shared State and Models

- `internal/shared/app.go` — global app / UI state model.
- `internal/shared/candidate.go` — candidate / process / flow model definitions, `CandidateState`.
- `internal/shared/classify.go` — classification constants, runtime maps (`TunnelingSeen`, `PivotInternalSeen`, `PivotUntil`, beacon/burst trackers), `RoleFamily`, shared thresholds.
- `internal/shared/state.go` — persistent classifier-memory load / save / pruning.
- `internal/shared/roles.go` — role-filter parsing, role-family matching, signal-to-role inference.
- `internal/shared/display.go` — host-identity / process-display / process-meta-cache helpers.
- `internal/shared/heuristics.go` — benign-process heuristics, LOLBin / suspicious-name detection.
- `internal/shared/distinguishing.go` — hard-distinguisher + combo-preserve logic for tier-2 role decisions.
- `internal/shared/linger.go` — candidate linger behavior for removed / exiting processes.
- `internal/shared/whitelist.go` — whitelist storage and filtering.
- `internal/shared/asn.go` — ASN range lookup tables.
- `internal/shared/dns_cache.go` — DNS reverse-lookup cache.
- `internal/shared/eventlog.go` — Windows event-log readers.
- `internal/shared/exe_hash.go` — async SHA-256 computation for executable paths.
- `internal/shared/online_evidence.go` — online-verification trust markers (`FOnlineKnownBenign`, `FOnlineKnownMalicious`).
- `internal/shared/operator_labels.go` — operator kill / whitelist / training-label persistence.
- `internal/shared/publisher_domains.go` — publisher-DNS alignment lookup.
- `internal/shared/signature.go`, `signature_windows.go`, `signature_unix.go`, `signature_other.go`, `signature_worker.go` — Authenticode / code-signing verification and background worker.
- `internal/shared/verifier_pkg_linux.go`, `verifier_pkg_other.go`, `verifier_publisher_dns.go` — package-manager and DNS verifier strategies.
- `internal/shared/vendor_fp_shape.go` — vendor-FP-shape demotion rules.
- `internal/shared/session_log.go` — session-level audit logging.

## External Integrations and Utilities

- `internal/proxyhound/collect.go` — ProxyHound collection build and export.
- `internal/proxyhound/upload.go` — ProxyHound upload client and runtime config.
- `internal/keystore/keystore.go` — encrypted keystore and runtime env mapping.
- `internal/keystore/keystore_crypto.go` — AES-256-GCM + YubiKey HMAC helpers.
- `internal/keystore/keystore_runtime.go` — runtime environment wiring.
- `internal/keystore/keystore_vault.go` — on-disk vault format.
- `internal/safeio/safeio.go` — safe open / read / write / atomic-replace wrappers.
