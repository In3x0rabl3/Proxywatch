# Proxywatch TODO

## Classification Tuning
- Further reduce false positives for common enterprise apps (`OneDrive`, browsers, IDE traffic) without hardcoded process names.
- Refine beacon/session separation for mixed traffic workloads (long-lived control + periodic bursts).
- Expand delegated-egress attribution confidence for proxy-brokered traffic on Windows.

## BloodHound Workflow
- Add a release validation checklist that verifies all queries in `docs/queries.md` against a fresh collection.
- Add operator-facing query presets in the TUI collection workflow (export/copy helper).
- Document troubleshooting flow for upload auth failures (`401`, missing env, HMAC vs bearer mismatch).

## Operator UX
- Add a compact status line for why a role changed since last refresh.
- Add optional operator control for candidate linger duration in the TUI.
- Improve inspect-mode readability for dense process connection sets (paging/filtering).

## Packaging
- Standardize artifact naming and release manifest across Linux and Windows builds.
