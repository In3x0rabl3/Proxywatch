# Proxywatch TODO

## Ranking & Telemetry
- Validate process traffic by destination (ASN/org, domain/SNI, cert, port fit) and weight score by mismatch.
- Add publisher/path trust signals (signed vendor + system path) as a soft demotion only when destinations are benign.
- Reduce false positives for developer tools (VS Code, browsers)

## BloodHound Export / Graph Quality
- Ensure host identity (e.g., HOST:LOK vs ENDPOINT:172.16.1.130 or just HOST).
- Prefer Host nodes when IPs map to known hosts; avoid creating duplicate endpoint nodes.
- Provide host → process → host query examples in `docs/queries.md`.
- Verify graph roots start at Host nodes in common queries.

## Collection / Endpoint Context
- Attach host IPs reliably to telemetry snapshots.
- Improve mapping of known hosts vs unknown endpoints in collection output.
- Track multi-hop / double-pivot flows and expose them in queries.

## Build / Packaging
- Windows binaries should include architecture in name (e.g., `proxywatch-windows-amd64`, `pwa-windows-amd64`).

## Codebase Hygiene
- Slim unused code paths, remove dead flags/config (e.g., unused policy JSON).
- Reorganize project structure for clarity (group telemetry, classifier, UI, BH export).
