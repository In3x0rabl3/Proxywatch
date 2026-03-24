# Proxywatch Code Map

This map groups code by function so developers can quickly find edit points.

## Entry Points

- `cmd/proxywatch/main.go`: main CLI/UI entrypoint and listen/client runtime wiring.
- `cmd/proxywatch/service_linux.go`: Linux service lifecycle helpers.
- `cmd/proxywatch/service_windows.go`: Windows service lifecycle helpers.

## Transport and Agent

- `internal/agent/server.go`: gRPC ingest server, host/session state, remote actions.
- `internal/agent/client.go`: remote agent loop and stream publishing.
- `internal/agent/enroll.go`: host enrollment and bootstrap flows.
- `internal/agent/auth.go`: per-call auth checks (token/cert).
- `internal/agent/auth_bootstrap.go`: token bootstrap/persistence helpers.
- `internal/agent/tls_runtime.go`: TLS runtime loading and policy.
- `internal/agent/trust_runtime.go`: trust-on-first-use (TOFU) pinning/runtime trust.
- `internal/agent/pb_convert.go`: protobuf/shared model conversion helpers.
- `internal/agent/pb/proxywatch_agent.proto`: gRPC contract.
- `internal/agent/pb/service.go`: generated gRPC service stubs.
- `internal/agent/pb/types.go`: generated transport DTOs.

## Telemetry by Platform

- `internal/telemetry/network_linux.go`: Linux TCP/UDP collection via `/proc`.
- `internal/telemetry/network_windows.go`: Windows TCP/UDP collection via syscalls.
- `internal/telemetry/network_capture_common.go`: shared capture merge/window logic.
- `internal/telemetry/process_linux.go`: Linux process enumeration and metadata.
- `internal/telemetry/process_windows.go`: Windows process enumeration and metadata.
- `internal/telemetry/platform/windows_syscalls.go`: Windows syscall structs/constants.
- `internal/telemetry/telemetry_stub.go`: unsupported-platform stubs.

## Detection Engine

- `internal/detection/classifier.go`: classification orchestration from snapshots.
- `internal/detection/rank.go`: scoring, role/state decision, feature weighting.
- `internal/detection/delegated.go`: delegated/owner correlation helpers.
- `internal/detection/display.go`: display-focused role/state formatting.
- `internal/detection/incremental.go`: incremental update helpers.
- `internal/detection/calibration.go`: calibration-specific detection paths.
- `internal/detection/output.go`: detection output writers/emitters.

## Contour Backend

- `internal/contour/core.go`: contour run orchestration, report generation, hints export.
- `internal/contour/probe.go`: probe/check matrix control and role/mode behavior.
- `internal/contour/probe_transport.go`: transport-level probe checks.
- `internal/contour/probe_packet_wire.go`: packet/wire signature validation logic.
- `internal/contour/probe_endpoints.go`: endpoint/proxy/config discovery and probing.

## Calibration Backend

- `internal/calibration/core.go`: calibration workflow, profiles, active tuning config.
- `internal/calibration/sampling.go`: candidate sampling policy for calibration runs.
- `internal/calibration/learning.go`: persistent environment learning model.
- `internal/calibration/ai_integration.go`: AI prompt build + provider request pipeline.
- `internal/calibration/tuning_normalization.go`: AI output normalization/guardrails.
- `internal/calibration/reporting.go`: report rendering, validation, history memory.
- `internal/calibration/siem_bridge.go`: bridge exposing calibration AI pipeline to SIEM package.

## SIEM Backend

- `internal/siem/siem.go`: SIEM package generation from calibration reports/datasets.

## UI Rendering and Interaction

- `internal/ui/ui_loop.go`: app loop, mode routing, async task channels.
- `internal/ui/ui_refresh.go`: refresh pipeline and candidate/snapshot update application.
- `internal/ui/ui_dashboard_keys.go`: dashboard key handling and mode entry.
- `internal/ui/ui_submenu_keys.go`: key handling for non-dashboard modes.
- `internal/ui/ui_workflow_runtime.go`: runtime state transitions for collect/calibrate/contour.
- `internal/ui/render_common.go`: shared style/panel/render utility helpers.
- `internal/ui/render_dashboard.go`: dashboard rendering.
- `internal/ui/render_inspector.go`: inspector rendering.
- `internal/ui/render_workflow_views.go`: collect/calibrate/contour/siem/keystore rendering.
- `internal/ui/render_whitelist.go`: whitelist rendering.

## Shared State and Models

- `internal/shared/app.go`: global app/UI state model.
- `internal/shared/candidate.go`: candidate/process/flow model definitions.
- `internal/shared/classify.go`: classification constants/runtime maps/helpers.
- `internal/shared/classify_memory.go`: persistent classifier memory load/save/pruning.
- `internal/shared/contour.go`: contour hint model + severity normalization.
- `internal/shared/network_scope.go`: internal/external/loopback scope helpers.
- `internal/shared/role_filters.go`: role filter parsing and matching.
- `internal/shared/host_identity.go`: host identity/display normalization.
- `internal/shared/process_display.go`: process display formatting helpers.
- `internal/shared/process_meta_cache.go`: process metadata cache helpers.
- `internal/shared/benign_process_heuristics.go`: benign process heuristics.
- `internal/shared/linger.go`: candidate linger behavior.
- `internal/shared/whitelist.go`: whitelist storage/filtering.
- `internal/shared/asn.go`: ASN/range helper structures.

## External Integrations and Utilities

- `internal/bloodhound/collect.go`: BloodHound collection build/export.
- `internal/bloodhound/upload.go`: BloodHound upload client/runtime config.
- `internal/keystore/keystore.go`: encrypted keystore and runtime env mapping.
- `internal/safeio/safeio.go`: safe open/read/write wrappers.
