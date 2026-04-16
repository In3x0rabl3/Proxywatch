package shared

import "testing"

func TestRoleFamily(t *testing.T) {
	cases := map[string]string{
		// Current taxonomy.
		"control-channel": "control-channel",
		"control-pivot":   "control-pivot",
		"listener":        "listener",
		"listen":          "listener",
		"outbound":        "outbound",
		// Legacy aliases must map correctly so CandidateState
		// and display code still work during transition.
		"control-session": "control-channel",
		"control-beacon":  "control-channel",
		"control-tunnel":  "control-pivot",
		"tunnel":          "control-pivot",
		"smb-pipe":        "control-pivot",
		"analyzing":       "outbound",
		// Unknown.
		"":        "other",
		"unknown": "other",
	}
	for input, want := range cases {
		if got := RoleFamily(input); got != want {
			t.Errorf("RoleFamily(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestIsControlRole(t *testing.T) {
	positive := []string{
		"control-channel", "control-pivot",
		// Legacy.
		"control-session", "control-beacon", "control-tunnel",
		"tunnel", "smb-pipe",
	}
	negative := []string{
		"outbound", "listener", "listen", "analyzing", "", "unknown",
	}
	for _, r := range positive {
		if !IsControlRole(r) {
			t.Errorf("IsControlRole(%q) = false, want true", r)
		}
	}
	for _, r := range negative {
		if IsControlRole(r) {
			t.Errorf("IsControlRole(%q) = true, want false", r)
		}
	}
}

func TestInferRoleFromSignals(t *testing.T) {
	cases := []struct {
		name       string
		signals    []string
		subtype    string
		actualRole string
		want       string
	}{
		{
			"decisive pivot signal overrides everything",
			[]string{"pivot-ssh-tunnel-flags", "outbound-baseline-verified"},
			"", "outbound",
			"control-pivot",
		},
		{
			"control signals win when they outnumber outbound",
			[]string{"beacon-interval-confirmed", "beacon-target-lock", "session-control-channel-persistent"},
			"", "outbound",
			"control-channel",
		},
		{
			"outbound signals dominate → outbound",
			[]string{
				"outbound-multi-external-cdn", "outbound-standard-ports-only",
				"outbound-asn-org-aligned", "outbound-baseline-verified",
			},
			"", "outbound",
			"outbound",
		},
		{
			"pivot signals outnumber control → control-pivot",
			[]string{
				"pivot-throughput-symmetry", "pivot-socks-candidate",
				"pivot-named-pipe-c2-pattern", "pivot-admin-share-smb",
			},
			"", "outbound",
			"control-pivot",
		},
		{
			"listener only → listener",
			[]string{"listener-open-port-awaiting", "listener-wildcard-bind"},
			"", "outbound",
			"listener",
		},
		{
			"no signals → outbound",
			nil, "", "outbound",
			"outbound",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := InferRoleFromSignals(tc.signals, tc.subtype, tc.actualRole)
			if got != tc.want {
				t.Errorf("InferRoleFromSignals(%v, %q, %q) = %q, want %q",
					tc.signals, tc.subtype, tc.actualRole, got, tc.want)
			}
		})
	}
}

func TestRoleMatchesFilter(t *testing.T) {
	filter := map[string]bool{
		"control-channel": true,
		"control-pivot":   true,
	}
	cases := []struct {
		role string
		want bool
	}{
		{"control-channel", true},
		{"control-pivot", true},
		// Legacy names should match via RoleFamily mapping.
		{"control-session", true},
		{"tunnel", true},
		{"smb-pipe", true},
		// Non-matching.
		{"outbound", false},
		{"listener", false},
	}
	for _, tc := range cases {
		if got := RoleMatchesFilter(tc.role, filter); got != tc.want {
			t.Errorf("RoleMatchesFilter(%q, filter) = %v, want %v", tc.role, got, tc.want)
		}
	}
	// Empty filter matches everything.
	if !RoleMatchesFilter("outbound", nil) {
		t.Errorf("RoleMatchesFilter(outbound, nil) = false, want true")
	}
	if !RoleMatchesFilter("outbound", map[string]bool{}) {
		t.Errorf("RoleMatchesFilter(outbound, {}) = false, want true")
	}
}
