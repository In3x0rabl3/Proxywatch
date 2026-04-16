package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestBuildEnrollClientProof_DeterministicWithToken(t *testing.T) {
	token := "shared-token"
	nonce := "nonce-abc"
	ts := int64(1_700_000_000)

	p1 := BuildEnrollClientProof(token, nonce, ts)
	p2 := BuildEnrollClientProof(token, nonce, ts)
	if p1 != p2 {
		t.Errorf("same inputs should produce identical proofs")
	}
	// Changing any single input must flip the hash.
	if BuildEnrollClientProof("different", nonce, ts) == p1 {
		t.Errorf("different token should produce different proof")
	}
	if BuildEnrollClientProof(token, "different-nonce", ts) == p1 {
		t.Errorf("different nonce should produce different proof")
	}
	if BuildEnrollClientProof(token, nonce, ts+1) == p1 {
		t.Errorf("different timestamp should produce different proof")
	}
	// Output is hex-encoded SHA256 → 64 chars.
	if len(p1) != sha256.Size*2 {
		t.Errorf("proof length = %d, want %d", len(p1), sha256.Size*2)
	}
	if _, err := hex.DecodeString(p1); err != nil {
		t.Errorf("proof should be valid hex: %v", err)
	}
}

func TestBuildEnrollServerProof_IncludesFingerprintAndNonce(t *testing.T) {
	base := BuildEnrollServerProof("tok", "cn", 123, "sn", "aabb")
	// Upper-case fingerprint must produce the same proof as lower (the
	// builder lowercases before hashing).
	if got := BuildEnrollServerProof("tok", "cn", 123, "sn", "AABB"); got != base {
		t.Errorf("fingerprint case should be normalized; got %q vs %q", got, base)
	}
	// Different server nonce → different proof.
	if got := BuildEnrollServerProof("tok", "cn", 123, "sn-other", "aabb"); got == base {
		t.Errorf("server nonce change should alter proof")
	}
	// Client proof != server proof for same inputs.
	cli := BuildEnrollClientProof("tok", "cn", 123)
	if cli == base {
		t.Errorf("client and server proofs must not collide")
	}
}

func TestConstantTimeHexEqual(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"aabb", "aabb", true},
		{"AABB", "aabb", true}, // case-insensitive.
		{"  aabb ", "aabb", true},
		{"aabb", "aabc", false},
		{"", "", false}, // empty string rejected.
		{"aa", "aabb", false},
	}
	for _, tc := range cases {
		if got := ConstantTimeHexEqual(tc.a, tc.b); got != tc.want {
			t.Errorf("ConstantTimeHexEqual(%q, %q) = %v, want %v",
				tc.a, tc.b, got, tc.want)
		}
	}
}

func TestRandomNonceBase64(t *testing.T) {
	n1, err := RandomNonceBase64(16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	n2, err := RandomNonceBase64(16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n1 == n2 {
		t.Errorf("two nonces collided — suspiciously non-random")
	}
	// Zero size triggers default of 24 bytes (RawURLEncoding encodes to 32 chars).
	dflt, err := RandomNonceBase64(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 24 bytes → 32 base64url chars.
	if len(dflt) != 32 {
		t.Errorf("default nonce length = %d, want 32", len(dflt))
	}
}

func TestWithinEnrollmentSkew(t *testing.T) {
	now := time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)
	// Exactly on time → within skew.
	if !WithinEnrollmentSkew(now.Unix(), now) {
		t.Errorf("zero skew should be within bounds")
	}
	// +4 minutes → within skew (limit is 5 minutes).
	if !WithinEnrollmentSkew(now.Add(-4*time.Minute).Unix(), now) {
		t.Errorf("4-minute clock skew should be accepted")
	}
	// +6 minutes → outside skew.
	if WithinEnrollmentSkew(now.Add(6*time.Minute).Unix(), now) {
		t.Errorf("6-minute future skew should be rejected")
	}
	if WithinEnrollmentSkew(now.Add(-6*time.Minute).Unix(), now) {
		t.Errorf("6-minute past skew should be rejected")
	}
	// Non-positive timestamp rejected.
	if WithinEnrollmentSkew(0, now) {
		t.Errorf("zero timestamp should be rejected")
	}
	if WithinEnrollmentSkew(-1, now) {
		t.Errorf("negative timestamp should be rejected")
	}
}

func TestValidFingerprintHex(t *testing.T) {
	good := strings.Repeat("ab", sha256.Size) // 64 hex chars.
	cases := []struct {
		in   string
		want bool
	}{
		{good, true},
		{strings.ToUpper(good), true},
		{"  " + good + "  ", true},
		{"", false},
		{"not-hex", false},
		{good[:62], false},               // too short.
		{good + "ab", false},             // too long.
		{strings.Repeat("z", 64), false}, // not valid hex characters.
	}
	for _, tc := range cases {
		if got := ValidFingerprintHex(tc.in); got != tc.want {
			t.Errorf("ValidFingerprintHex(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestCertFingerprint_Deterministic(t *testing.T) {
	data := []byte("a raw cert DER blob")
	f1 := CertFingerprint(data)
	f2 := CertFingerprint(data)
	if f1 != f2 {
		t.Errorf("same input should produce same fingerprint")
	}
	if len(f1) != sha256.Size*2 {
		t.Errorf("fingerprint length = %d, want %d", len(f1), sha256.Size*2)
	}
	if _, err := hex.DecodeString(f1); err != nil {
		t.Errorf("fingerprint should be hex: %v", err)
	}
	// Empty input still returns a valid fingerprint (SHA256 of empty bytes).
	if f := CertFingerprint(nil); len(f) != sha256.Size*2 {
		t.Errorf("empty-input fingerprint length = %d, want %d", len(f), sha256.Size*2)
	}
}

func TestAgentTrustPath_EncodesAddressStably(t *testing.T) {
	p1 := AgentTrustPath("host.example:443")
	p2 := AgentTrustPath("  HOST.EXAMPLE:443  ") // case + whitespace normalized.
	if p1 != p2 {
		t.Errorf("case/whitespace should be normalized: %q vs %q", p1, p2)
	}
	// Empty address fallback name is used.
	pEmpty := AgentTrustPath("")
	pServer := AgentTrustPath("server")
	if pEmpty != pServer {
		t.Errorf("empty address should map to the 'server' name: %q vs %q", pEmpty, pServer)
	}
	if !strings.HasSuffix(p1, ".pin") {
		t.Errorf("AgentTrustPath should end in .pin: %q", p1)
	}
}
