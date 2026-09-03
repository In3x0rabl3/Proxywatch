# Contributing to Proxywatch

The following is a set of guidelines for contributing to Proxywatch. These are mostly guidelines, not rules. Use your best judgment, and feel free to propose changes to this document in a pull request.

## Code of Conduct

This project and everyone participating in it is governed by the Code of Conduct [documented here](/CODE_OF_CONDUCT.md)). By participating, you are expected to uphold this code. Please report unacceptable behavior.

## Basics of Contributing to the Project

The project team welcomes feedback, new ideas, and external contributions. Review the following sections based on what you are looking to contribute.

### Reporting an Issue/Bug

Before submitting an issue, please do the following:

* Check open and closed issues for any previous related discussion
* Make sure you are using the latest release (check the bottom of the left-hand sidebar for your version)
* Check the [CHANGELOG](/CHANGELOG.md) to see if your issue has already been addressed

### Suggesting a Change or New Feature

* Please create an issue with the "enhancement" tag.

### Building and testing locally

```bash
cd proxywatch
go build ./...                                    # linux
GOOS=windows go build ./cmd/proxywatch             # windows cross-compile
go vet ./...
go test ./...
gofmt -l .                                         # should be empty
```

CI enforces all four on every push to `main` and every PR —
`.github/workflows/ci.yml`. A failing gate blocks merge.

### Writing tests

Tests live alongside the code in `*_test.go` files. Table-driven
tests are preferred for pure functions — see
[`internal/detection/scoring/roles_test.go`](proxywatch/internal/detection/scoring/roles_test.go)
for the canonical style. Keep test fixtures inline; do not introduce
a test-data directory unless the fixture genuinely needs file I/O.

New detection signals ship as **shadow-only** (not in
`controlSignals` / `pivotSignals` / `outboundSignals` maps in
[`internal/shared/roles.go`](proxywatch/internal/shared/roles.go))
until the shadow-disagreement feed (`/ml/disagreements` endpoint)
shows enough real hits vs false positives to justify voting.

### Submitting a Pull Request

The process described here has several goals:

- Maintain code quality
- Fix problems that are important to users
- Engage the community in working toward the best possible Proxywatch

Please follow these steps to have your contribution considered by the maintainers:

1. Follow all instructions in [the template](/PULL_REQUEST_TEMPLATE.md)
2. After you submit your pull request, verify that all [status checks](https://help.github.com/articles/about-status-checks/) are passing <details><summary>What if the status checks are failing?</summary>If a status check is failing, and you believe that the failure is unrelated to your change, please leave a comment on the pull request explaining why you believe the failure is unrelated. A maintainer will re-run the status check for you. If we conclude that the failure was a false positive, then we will open an issue to track that problem with our status check suite.</details>

While the prerequisites above must be satisfied prior to having your pull request reviewed, the reviewer(s) may ask you to complete additional design work, tests, or other changes before your pull request can be ultimately accepted.
