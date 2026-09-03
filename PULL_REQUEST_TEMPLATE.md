## Summary

<one or two sentences on what this PR does and why>

## Type of change

- [ ] Bug fix
- [ ] New feature / enhancement
- [ ] Refactor / code quality
- [ ] Documentation

## Testing

<how you verified the change — e.g. unit tests added, live test against lab agent, manual reproduction steps>

## Checklist

- [ ] `go build ./... && GOOS=windows go build ./cmd/proxywatch && go vet ./...` all pass
- [ ] `CHANGELOG.md` updated under `[Unreleased]` (or the target version)
- [ ] Relevant docs updated (`README.md`, `docs/*`, `proxywatch/docs/*`)
- [ ] No references to removed subsystems reintroduced (calibration UI, top-level `detection/rank.go` before the `scoring/` split, etc.)
