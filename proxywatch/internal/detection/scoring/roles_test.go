package scoring

import (
	"testing"

	"proxywatch/internal/shared"
)

func TestDeriveRole(t *testing.T) {
	cases := []struct {
		name                  string
		hasListener           bool
		clients               int
		out                   int
		reverseTunnelEligible bool
		want                  string
	}{
		{"listener wins over everything", true, 0, 10, true, "listen"},
		{"listener wins with no clients", true, 0, 0, false, "listen"},
		{"tunnel needs out>=3 and eligible", false, 0, 3, true, "tunnel"},
		{"tunnel not eligible, drops to outbound", false, 0, 10, false, "outbound"},
		{"tunnel eligible but out<3, drops to outbound", false, 0, 2, true, "outbound"},
		{"default outbound when nothing matches", false, 0, 0, false, "outbound"},
		{"sshd child shape — no listener, 1 out — outbound", false, 0, 1, false, "outbound"},
		{"beacon shape — no listener, few outs — outbound", false, 0, 2, false, "outbound"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DeriveRole(tc.hasListener, tc.clients, tc.out, tc.reverseTunnelEligible)
			if got != tc.want {
				t.Errorf("DeriveRole(%v,%d,%d,%v) = %q, want %q",
					tc.hasListener, tc.clients, tc.out, tc.reverseTunnelEligible, got, tc.want)
			}
		})
	}
}

func TestIsMaliciousRole(t *testing.T) {
	cases := []struct {
		role string
		want bool
	}{
		// Current taxonomy.
		{"control-channel", true},
		{"control-pivot", true},
		{"outbound", false},
		{"listener", false},
		{"listen", false},
		// Legacy role names still treated as malicious during transition.
		{"control-session", true},
		{"control-beacon", true},
		{"control-tunnel", true},
		{"tunnel", true},
		{"smb-pipe", true},
		// Non-matching.
		{"", false},
		{"unknown", false},
		{"analyzing", false},
	}
	for _, tc := range cases {
		if got := IsMaliciousRole(tc.role); got != tc.want {
			t.Errorf("IsMaliciousRole(%q) = %v, want %v", tc.role, got, tc.want)
		}
	}
}

func TestIsRoleUpgrade(t *testing.T) {
	cases := []struct {
		old, new string
		want     bool
	}{
		{"outbound", "control-channel", true},
		{"outbound", "control-pivot", true},
		{"listener", "control-channel", true},
		{"listen", "control-channel", true},
		{"control-channel", "control-pivot", true},
		// Not upgrades.
		{"control-channel", "outbound", false},
		{"control-pivot", "control-channel", false},
		{"outbound", "outbound", false},
		{"control-pivot", "control-pivot", false},
		// Legacy equivalences.
		{"outbound", "tunnel", true},
		{"outbound", "smb-pipe", true},
		{"tunnel", "smb-pipe", false}, // both level 4
		{"control-tunnel", "control-pivot", false},
	}
	for _, tc := range cases {
		if got := IsRoleUpgrade(tc.old, tc.new); got != tc.want {
			t.Errorf("IsRoleUpgrade(%q,%q) = %v, want %v", tc.old, tc.new, got, tc.want)
		}
	}
}

func TestConfidenceFor(t *testing.T) {
	cases := []struct {
		name   string
		role   string
		score  int
		active bool
		min    int // inclusive lower bound
		max    int // inclusive upper bound
	}{
		// Active proxying adds +5 to the base.
		{"tunnel active", "tunnel", 100, true, 95, 100},
		{"tunnel inactive", "tunnel", 0, false, 85, 85},
		{"outbound low score", "outbound", 0, false, 30, 30},
		{"outbound high score", "outbound", 100, false, 55, 55}, // 30 + 25
		{"listen mid score", "listen", 40, false, 65, 65},       // 55 + 10
		// Unknown role → base 10 + score/4
		{"unknown role", "something-else", 0, false, 10, 10},
		// Clamping: score >= 400 would overflow without the 100 cap.
		{"clamped at 100", "tunnel", 400, true, 100, 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ConfidenceFor(tc.role, tc.score, tc.active)
			if got < tc.min || got > tc.max {
				t.Errorf("ConfidenceFor(%q, %d, %v) = %d; want in [%d,%d]",
					tc.role, tc.score, tc.active, got, tc.min, tc.max)
			}
		})
	}
}

func TestIsReverseControlShape(t *testing.T) {
	conn := &shared.ConnectionInfo{RemoteAddress: "10.0.0.1", RemotePort: 443, State: "ESTABLISHED"}

	cases := []struct {
		name            string
		controlConn     *shared.ConnectionInfo
		hasListener     bool
		outTotal        int
		distinctTargets int
		controlSecs     int
		want            bool
	}{
		{"no control conn → false", nil, false, 2, 1, 120, false},
		{"listener present → false", conn, true, 1, 1, 120, false},
		{"long-held with focused profile → true", conn, false, 2, 1, 120, true},
		{"long-held but too many targets → false", conn, false, 2, 5, 120, false},
		{"long-held but too many conns → false", conn, false, 10, 1, 120, false},
		{"short-held but classic reverse shape → true at min duration",
			conn, false, 1, 1, int(shared.ReverseControlMinDuration.Seconds()), true},
		{"too-short controlSecs → false", conn, false, 1, 1, 5, false},
		// Gate 1 (long-held + focused) admits outTotal=0 because the bound
		// is `<= 3`; the control connection itself is the only evidence.
		// This matches the session-only / sshd shape intentionally.
		{"long-held with zero out total, single target → true", conn, false, 0, 1, 120, true},
		// Short-held + outTotal=0 fails both gates (gate 2 requires outTotal > 0).
		{"short-held with zero out total → false", conn, false, 0, 1, 35, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsReverseControlShape(tc.controlConn, tc.hasListener, tc.outTotal, tc.distinctTargets, tc.controlSecs)
			if got != tc.want {
				t.Errorf("IsReverseControlShape(%v,%v,%d,%d,%d) = %v, want %v",
					tc.controlConn != nil, tc.hasListener, tc.outTotal, tc.distinctTargets, tc.controlSecs, got, tc.want)
			}
		})
	}
}
