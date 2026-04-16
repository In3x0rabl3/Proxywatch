package proxyhound

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestJoinHostPort(t *testing.T) {
	cases := []struct {
		host, port, want string
	}{
		{"", "", ""},
		{"h", "", "h"},
		{"", "443", "443"},
		{"h", "443", "h:443"},
	}
	for _, tc := range cases {
		if got := joinHostPort(tc.host, tc.port); got != tc.want {
			t.Errorf("joinHostPort(%q, %q) = %q, want %q",
				tc.host, tc.port, got, tc.want)
		}
	}
}

func TestHostOr(t *testing.T) {
	if got := hostOr("proc", "h"); got != "h" {
		t.Errorf("hostOr with host = %q, want h", got)
	}
	if got := hostOr("proc", ""); got != "proc" {
		t.Errorf("hostOr without host = %q, want proc", got)
	}
	if got := hostOr("", ""); got != "" {
		t.Errorf("hostOr both empty = %q, want empty", got)
	}
}

func TestRoleKindPrefix(t *testing.T) {
	cases := []struct {
		role, want string
	}{
		{"control-tunnel", "Tunnel"},
		{"control-pivot", "Pivot"},
		{"control-channel", "Channel"},
		{"listen", "Listener"},
		{"outbound", "Outbound"},
		{"unknown-role", "Process"},
		{"", "Process"},
	}
	for _, tc := range cases {
		if got := roleKindPrefix(tc.role); got != tc.want {
			t.Errorf("roleKindPrefix(%q) = %q, want %q", tc.role, got, tc.want)
		}
	}
}

func TestRoleLabelFromPrefix_RoundTrip(t *testing.T) {
	// roleKindPrefix + roleLabelFromPrefix should form an inverse for known roles.
	roles := []string{"control-tunnel", "control-pivot", "control-channel", "outbound"}
	for _, r := range roles {
		pref := roleKindPrefix(r)
		label := roleLabelFromPrefix(pref)
		if label != r {
			t.Errorf("round-trip role %q -> prefix %q -> label %q", r, pref, label)
		}
	}
	// "listen" canonicalizes to "listener" via the label mapping.
	if roleLabelFromPrefix(roleKindPrefix("listen")) != "listener" {
		t.Errorf("listen should map to listener label")
	}
	// Unknown prefix gets lowercased.
	if got := roleLabelFromPrefix("FooBar"); got != "foobar" {
		t.Errorf("unknown prefix lowercase fallback: got %q", got)
	}
	// Empty prefix defaults to "process".
	if got := roleLabelFromPrefix(""); got != "process" {
		t.Errorf("empty prefix should default to process, got %q", got)
	}
}

func TestRoleFromKindSuffix(t *testing.T) {
	if r, ok := roleFromKindSuffix("ChannelProcessOnHost", "ProcessOnHost"); !ok || r != "control-channel" {
		t.Errorf("expected control-channel, got %q ok=%v", r, ok)
	}
	if _, ok := roleFromKindSuffix("SomethingElse", "ProcessOnHost"); ok {
		t.Errorf("non-matching suffix should return ok=false")
	}
	// Suffix equal to full kind → empty prefix → not a role.
	if _, ok := roleFromKindSuffix("ProcessOnHost", "ProcessOnHost"); ok {
		t.Errorf("empty prefix should be rejected")
	}
}

func TestKindForScope(t *testing.T) {
	cases := []struct {
		scope, want string
	}{
		{"external", "ExtKind"},
		{"internal", "IntKind"},
		{"loopback", "LoopKind"},
		{"", "ExtKind"}, // default.
		{"other", "ExtKind"},
	}
	for _, tc := range cases {
		if got := kindForScope(tc.scope, "ExtKind", "IntKind", "LoopKind"); got != tc.want {
			t.Errorf("kindForScope(%q) = %q, want %q", tc.scope, got, tc.want)
		}
	}
}

func TestUserNodeID(t *testing.T) {
	if id, ok := userNodeID("ADMIN"); !ok || id != "user:admin" {
		t.Errorf("got id=%q ok=%v, want user:admin true", id, ok)
	}
	if id, ok := userNodeID("  admin  "); !ok || id != "user:admin" {
		t.Errorf("whitespace trim failed: got %q", id)
	}
	// Empty / unknown username → ok=false.
	if _, ok := userNodeID(""); ok {
		t.Errorf("empty username should yield ok=false")
	}
	if _, ok := userNodeID("(unknown)"); ok {
		t.Errorf("(unknown) should yield ok=false")
	}
}

func TestPropString(t *testing.T) {
	if propString(nil, "key") != "" {
		t.Errorf("nil props should return empty string")
	}
	m := map[string]any{
		"s": "a-string",
		"i": 42,
		"f": 3.14,
		"b": true,
	}
	if got := propString(m, "s"); got != "a-string" {
		t.Errorf("string got %q", got)
	}
	if got := propString(m, "i"); got != "42" {
		t.Errorf("int got %q", got)
	}
	// Key missing → empty.
	if got := propString(m, "missing"); got != "" {
		t.Errorf("missing key got %q", got)
	}
}

func TestVaultKeyFromPath(t *testing.T) {
	// Paths under .proxywatch/ return the subpath after that marker.
	if got := vaultKeyFromPath("/home/u/.proxywatch/collections/a.json"); got != "collections/a.json" {
		t.Errorf("got %q", got)
	}
	// Other paths return the basename.
	if got := vaultKeyFromPath("/tmp/foo.json"); got != "foo.json" {
		t.Errorf("basename fallback got %q", got)
	}
}

func TestNormalizeCollectionOutputPath(t *testing.T) {
	// Empty returns empty.
	if got := normalizeCollectionOutputPath(""); got != "" {
		t.Errorf("empty input should return empty, got %q", got)
	}
	// Absolute preserved (cleaned).
	abs := "/tmp/x/y.json"
	if got := normalizeCollectionOutputPath(abs); got != filepath.Clean(abs) {
		t.Errorf("absolute: got %q", got)
	}
	// Relative gets joined under collectionsRootDir + collections/ prefix stripped.
	got := normalizeCollectionOutputPath("collections/sub/a.json")
	want := filepath.Join(collectionsRootDir(), "sub", "a.json")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestLooksLikeJWT(t *testing.T) {
	if !looksLikeJWT("aaa.bbb.ccc") {
		t.Errorf("JWT-shaped 3-part token not detected")
	}
	// Other dot counts → not a JWT shape.
	if looksLikeJWT("aaa.bbb") {
		t.Errorf("2-part token incorrectly flagged as JWT")
	}
	if looksLikeJWT("no-dots") {
		t.Errorf("no-dots token incorrectly flagged")
	}
	if looksLikeJWT("aaa.bbb.ccc.ddd") {
		t.Errorf("4-part token incorrectly flagged")
	}
}

func TestLooksLikeTokenKey(t *testing.T) {
	// Base64-ish chars → true.
	if !looksLikeTokenKey("AbCd+EfGh/==") {
		t.Errorf("base64-like token should be detected as key")
	}
	// Plain alphanumeric → false.
	if looksLikeTokenKey("onlyalphanum12345") {
		t.Errorf("plain alnum should not look like a key")
	}
}

func TestValidateAPIURL(t *testing.T) {
	// HTTPS valid.
	out, err := validateapiURL("https://bh.example/api/v2")
	if err != nil {
		t.Errorf("https should validate: %v", err)
	}
	if !strings.HasSuffix(out, "/api/v2") {
		t.Errorf("should normalize to /api/v2 suffix, got %q", out)
	}
	// http://localhost allowed.
	if _, err := validateapiURL("http://localhost:8080"); err != nil {
		t.Errorf("http://localhost should be allowed: %v", err)
	}
	// http://127.0.0.1 allowed.
	if _, err := validateapiURL("http://127.0.0.1:8080"); err != nil {
		t.Errorf("http://127.0.0.1 should be allowed: %v", err)
	}
	// http://other hosts rejected.
	if _, err := validateapiURL("http://evil.example/x"); err == nil {
		t.Errorf("insecure http should be rejected")
	}
	// Non-http scheme rejected.
	if _, err := validateapiURL("ftp://x.example"); err == nil {
		t.Errorf("non-http scheme should be rejected")
	}
	// Missing scheme / host rejected.
	if _, err := validateapiURL(""); err == nil {
		t.Errorf("empty should be rejected")
	}
	// URL path without /api/v2 → gets it appended.
	out, err = validateapiURL("https://bh.example")
	if err != nil {
		t.Errorf("unexpected: %v", err)
	}
	if !strings.HasSuffix(out, "/api/v2") {
		t.Errorf("missing /api/v2 should be appended, got %q", out)
	}
	// URL with /api (no v2) → appends v2.
	out, err = validateapiURL("https://bh.example/api")
	if err != nil {
		t.Errorf("unexpected: %v", err)
	}
	if !strings.HasSuffix(out, "/api/v2") {
		t.Errorf("/api should become /api/v2, got %q", out)
	}
}

func TestIsLocalhost(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"localhost", true},
		{"LOCALHOST", true},
		{"  localhost  ", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"example.com", false},
		{"10.0.0.1", false}, // private but not loopback.
		{"", false},
	}
	for _, tc := range cases {
		if got := isLocalhost(tc.in); got != tc.want {
			t.Errorf("isLocalhost(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
