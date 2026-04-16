package shared

import "testing"

func TestCandidateKey(t *testing.T) {
	cases := []struct {
		name string
		cand Candidate
		want string
	}{
		{
			"nil proc → host:0",
			Candidate{Host: "DEMO"},
			"DEMO:0",
		},
		{
			"host + pid",
			Candidate{Host: "DEMO", Proc: &ProcessInfo{Pid: 1234}},
			"DEMO:1234",
		},
		{
			"empty host defaults via DisplayHost",
			Candidate{Proc: &ProcessInfo{Pid: 42}},
			"local:42",
		},
		{
			"host whitespace trimmed (case preserved)",
			Candidate{Host: "  PROD-01  ", Proc: &ProcessInfo{Pid: 1}},
			"PROD-01:1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CandidateKey(tc.cand); got != tc.want {
				t.Errorf("CandidateKey = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCandidateState_Exited(t *testing.T) {
	// Exited wins over every other condition.
	c := Candidate{
		Exited: true,
		Proc:   &ProcessInfo{Pid: 1},
		Role:   "control-channel",
	}
	if got := CandidateState(c); got != "exited" {
		t.Errorf("CandidateState = %q, want exited", got)
	}
}

func TestCandidateState_TunnelingRequiresActiveProxying(t *testing.T) {
	// Control-channel role alone (no ActiveProxying) must not show
	// "tunneling" — that was the v1.0.6 regression we explicitly fixed.
	c := Candidate{
		Proc:           &ProcessInfo{Pid: 1, Name: "cheerful_glove.exe"},
		Role:           "control-channel",
		ActiveProxying: false,
	}
	got := CandidateState(c)
	if got == "tunneling" {
		t.Errorf("control-channel without ActiveProxying should NOT show tunneling; got %q", got)
	}
}

func TestCandidateState_NonControlRoleNeverTunneling(t *testing.T) {
	// Outbound / listener never show tunneling even with ActiveProxying.
	// Role gate is strict — pivot-linger promotes role *first*, then
	// state becomes tunneling.
	for _, role := range []string{"outbound", "listener", "analyzing", ""} {
		c := Candidate{
			Proc:           &ProcessInfo{Pid: 1, Name: "x"},
			Role:           role,
			ActiveProxying: true,
		}
		got := CandidateState(c)
		if got == "tunneling" {
			t.Errorf("role=%q with ActiveProxying showed tunneling — should be role-gated", role)
		}
	}
}
