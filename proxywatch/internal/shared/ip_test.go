package shared

import "testing"

func TestIsLoopbackIP(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1":    true,
		"127.10.20.30": true,
		"::1":          true,
		"0.0.0.0":      false, // wildcard, not loopback
		"10.0.0.1":     false,
		"192.168.1.1":  false,
		"8.8.8.8":      false,
		"172.16.1.2":   false,
		"":             false,
		"not-an-ip":    false,
		"fe80::1":      false,
	}
	for input, want := range cases {
		if got := IsLoopbackIP(input); got != want {
			t.Errorf("IsLoopbackIP(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestIsInternalIP(t *testing.T) {
	cases := map[string]bool{
		// RFC1918.
		"10.0.0.1":       true,
		"10.255.255.254": true,
		"172.16.0.1":     true,
		"172.31.255.254": true,
		"172.16.1.2":     true, // lab agent
		"192.168.0.1":    true,
		"192.168.1.254":  true,
		// RFC1918 boundary negatives.
		"172.15.1.1": false,
		"172.32.1.1": false,
		// Link-local — treated as internal by design.
		"169.254.1.1": true,
		// Public IPs.
		"8.8.8.8": false,
		"1.1.1.1": false,
		// Loopback IS internal per the current impl (net.IP.IsLoopback
		// matches the IsPrivate test). Call sites that need to separate
		// loopback from RFC1918 call IsLoopbackIP explicitly first.
		"127.0.0.1": true,
		// Wildcard.
		"0.0.0.0": false,
		// Junk.
		"":          false,
		"not-an-ip": false,
	}
	for input, want := range cases {
		if got := IsInternalIP(input); got != want {
			t.Errorf("IsInternalIP(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestIsWildcardIP(t *testing.T) {
	cases := map[string]bool{
		"0.0.0.0":   true,
		"::":        true,
		"127.0.0.1": false,
		"10.0.0.1":  false,
		"":          false,
	}
	for input, want := range cases {
		if got := IsWildcardIP(input); got != want {
			t.Errorf("IsWildcardIP(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestTargetPrefix(t *testing.T) {
	cases := map[string]string{
		// IPv4 — /24 prefix (first three octets).
		"192.168.1.10": "192.168.1",
		"10.0.0.1":     "10.0.0",
		"172.16.1.2":   "172.16.1",
		// Invalid / empty → empty.
		"":          "",
		"not-an-ip": "",
	}
	for input, want := range cases {
		if got := TargetPrefix(input); got != want {
			t.Errorf("TargetPrefix(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNormalizeExePath(t *testing.T) {
	cases := map[string]string{
		// Backslash → forward slash, lowercased, trimmed.
		`C:\Windows\System32\svchost.exe`:  "c:/windows/system32/svchost.exe",
		`  C:\Users\Ops\Downloads\x.exe  `: "c:/users/ops/downloads/x.exe",
		`/usr/bin/curl`:                    "/usr/bin/curl",
		``:                                 "",
		`  `:                               "",
	}
	for input, want := range cases {
		if got := NormalizeExePath(input); got != want {
			t.Errorf("NormalizeExePath(%q) = %q, want %q", input, got, want)
		}
	}
}
