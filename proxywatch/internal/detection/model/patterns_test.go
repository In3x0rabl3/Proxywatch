package model

import (
	"testing"
)

func TestSanitizePatternID(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"simple", "simple"},
		{"UPPER", "upper"},
		{"path/with/slashes", "path-with-slashes"},
		{`c:\windows\system32\`, "c-windows-system32-"},
		// Colons get stripped (empty replacement), not hyphenated.
		{"has spaces and colons:", "has-spaces-and-colons"},
		{"mixed/Path\\with:all these", "mixed-path-withall-these"},
		// Truncation at 40 characters.
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaBBBB", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := sanitizePatternID(tc.in); got != tc.want {
			t.Errorf("sanitizePatternID(%q) = %q, want %q", tc.in, got, tc.want)
		}
		// Result is never longer than 40 characters.
		if len(sanitizePatternID(tc.in)) > 40 {
			t.Errorf("sanitizePatternID(%q) exceeded 40 chars", tc.in)
		}
	}
}

func TestIsSuspiciousRole(t *testing.T) {
	positive := []string{
		"control-channel", "control-pivot",
		// Legacy names still suspicious.
		"control-session", "control-beacon", "control-tunnel",
		"tunnel", "smb-pipe",
	}
	negative := []string{
		"outbound", "listener", "listen", "analyzing", "", "unknown",
	}
	for _, r := range positive {
		if !isSuspiciousRole(r) {
			t.Errorf("isSuspiciousRole(%q) = false, want true", r)
		}
	}
	for _, r := range negative {
		if isSuspiciousRole(r) {
			t.Errorf("isSuspiciousRole(%q) = true, want false", r)
		}
	}
}

func TestPatternMatches(t *testing.T) {
	boolPtr := func(b bool) *bool { return &b }

	// All fields empty → matches anything.
	p0 := &TrainingPattern{}
	if !patternMatches(p0, "/any/path", "anycompany", "user", true, false) {
		t.Errorf("empty pattern should match everything")
	}

	// PathPrefix must be a prefix match.
	p1 := &TrainingPattern{PathPrefix: "/usr/bin/"}
	if !patternMatches(p1, "/usr/bin/ls", "", "user", false, false) {
		t.Errorf("path prefix should match")
	}
	if patternMatches(p1, "/home/ops/x", "", "user", false, false) {
		t.Errorf("path prefix mismatch should not match")
	}

	// UserContext exact.
	p2 := &TrainingPattern{UserContext: "system"}
	if !patternMatches(p2, "/", "", "system", false, false) {
		t.Errorf("user context match should pass")
	}
	if patternMatches(p2, "/", "", "user", false, false) {
		t.Errorf("user context mismatch should fail")
	}

	// Company substring match (pattern company is a needle).
	p3 := &TrainingPattern{Company: "microsoft"}
	if !patternMatches(p3, "/", "microsoft corporation", "user", false, false) {
		t.Errorf("company substring should match")
	}
	if patternMatches(p3, "/", "acme inc.", "user", false, false) {
		t.Errorf("company mismatch should fail")
	}

	// HasListener pointer — nil means "don't care"; set means exact match.
	p4 := &TrainingPattern{HasListener: boolPtr(true)}
	if !patternMatches(p4, "/", "", "user", true, false) {
		t.Errorf("HasListener=true should match hasListener=true")
	}
	if patternMatches(p4, "/", "", "user", false, false) {
		t.Errorf("HasListener=true should not match hasListener=false")
	}

	// ExternalOnly pointer.
	p5 := &TrainingPattern{ExternalOnly: boolPtr(true)}
	if !patternMatches(p5, "/", "", "user", false, true) {
		t.Errorf("ExternalOnly=true should match externalOnly=true")
	}
	if patternMatches(p5, "/", "", "user", false, false) {
		t.Errorf("ExternalOnly=true should not match externalOnly=false")
	}

	// Multiple fields combined — all must match.
	p6 := &TrainingPattern{
		PathPrefix:  "/usr/bin/",
		UserContext: "system",
		Company:     "microsoft",
	}
	if !patternMatches(p6, "/usr/bin/svchost.exe", "microsoft corporation", "system", false, false) {
		t.Errorf("all-match should pass")
	}
	// One field off → fail.
	if patternMatches(p6, "/usr/bin/svchost.exe", "microsoft corporation", "user", false, false) {
		t.Errorf("user context off → should fail")
	}
}
