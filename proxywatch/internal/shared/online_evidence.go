package shared

import "time"

// Evidence is one verifier's finding about a binary or candidate. Multiple
// verifiers contribute to one VerdictEntry; the FP-shape evaluator and
// /fp-report read the combined set.
//
// Verdict values are intentionally coarse — a scorer that wants nuance reads
// Confidence. The constants are also used as blocker prefixes so a negative
// evidence item becomes `online:verifier-distrust:<name>` in the blocker
// trace, matching the Phase 5 Authenticode pattern.
type Evidence struct {
	Verifier   string    `json:"verifier"`
	Verdict    string    `json:"verdict"`
	Confidence int       `json:"confidence"`
	Tags       []string  `json:"tags,omitempty"`
	Detail     string    `json:"detail,omitempty"`
	CheckedAt  time.Time `json:"checked_at"`
}

// Verdict constants for Evidence.
const (
	VerdictPositive = "positive"
	VerdictNeutral  = "neutral"
	VerdictNegative = "negative"
)

// Verifier names — kept as constants so /fp-report, tests, and operator
// filters agree on the spellings.
const (
	VerifierAuthenticode = "authenticode"
	VerifierPkgOwnership = "pkg-ownership"
	VerifierPublisherDNS = "publisher-dns"
)
