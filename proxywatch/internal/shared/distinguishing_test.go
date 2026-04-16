package shared

import "testing"

func candWithSignals(signals ...string) *Candidate {
	return &Candidate{
		Proc:    &ProcessInfo{Pid: 1, Name: "test.exe"},
		Signals: signals,
	}
}

func TestHasHardDistinguisher_Signals(t *testing.T) {
	cases := []struct {
		name    string
		signals []string
		want    bool
	}{
		{"no signals", []string{}, false},
		{"unrelated signal", []string{"outbound-known-vendor"}, false},
		{"pivot-ssh-tunnel-flags", []string{"pivot-ssh-tunnel-flags"}, true},
		{"pivot-named-pipe-c2-pattern", []string{"pivot-named-pipe-c2-pattern"}, true},
		{"beacon-syn-cycle-cadence", []string{"beacon-syn-cycle-cadence"}, true},
		{"raw-socket", []string{"raw-socket"}, true},
		{"child-tunnel-relay", []string{"child-tunnel-relay"}, true},
		// Weak indicators must NOT fire the hard gate.
		{"suspicious-exe-path alone", []string{"suspicious-exe-path"}, false},
		{"cmdline-proxy-flags alone", []string{"cmdline-proxy-flags"}, false},
		{"proxy-library-loaded alone", []string{"proxy-library-loaded"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := candWithSignals(tc.signals...)
			got, _ := HasHardDistinguisher(c)
			if got != tc.want {
				t.Errorf("HasHardDistinguisher(signals=%v) = %v, want %v", tc.signals, got, tc.want)
			}
		})
	}
}

func TestHasHardDistinguisher_Combo(t *testing.T) {
	// Persistent-control + pivot-non-loopback-internal combo is a hard
	// distinguisher only when BOTH fire (sleeping-beacon preserve).
	t.Run("only persistent-control → false", func(t *testing.T) {
		c := candWithSignals("session-control-channel-persistent")
		got, _ := HasHardDistinguisher(c)
		if got {
			t.Errorf("persistent-control alone should not preserve")
		}
	})
	t.Run("only pivot-non-loopback-internal → false", func(t *testing.T) {
		c := candWithSignals("pivot-non-loopback-internal")
		got, _ := HasHardDistinguisher(c)
		if got {
			t.Errorf("pivot-non-loopback-internal alone should not preserve")
		}
	})
	t.Run("both → true with combo tag", func(t *testing.T) {
		c := candWithSignals("session-control-channel-persistent", "pivot-non-loopback-internal")
		got, hits := HasHardDistinguisher(c)
		if !got {
			t.Errorf("both signals should preserve")
		}
		found := false
		for _, h := range hits {
			if h == "combo:persistent-control+internal-pivot" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected combo tag in hits %v", hits)
		}
	})
}

func TestHasHardDistinguisher_State(t *testing.T) {
	// ActiveProxying alone is a hard distinguisher.
	c := &Candidate{
		Proc:           &ProcessInfo{Pid: 1, Name: "sshd.exe"},
		ActiveProxying: true,
	}
	got, hits := HasHardDistinguisher(c)
	if !got {
		t.Errorf("ActiveProxying should preserve")
	}
	found := false
	for _, h := range hits {
		if h == "state:active-proxying" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected state:active-proxying in hits %v", hits)
	}
}

func TestHasHardDistinguisher_Role(t *testing.T) {
	cases := map[string]bool{
		"smb-pipe":        true,
		"tunnel":          true,
		"control-tunnel":  true,
		"outbound":        false,
		"listener":        false,
		"control-channel": false, // shape-only role — needs corroborating evidence
		"":                false,
	}
	for role, want := range cases {
		c := &Candidate{
			Proc: &ProcessInfo{Pid: 1, Name: "x.exe"},
			Role: role,
		}
		got, _ := HasHardDistinguisher(c)
		if got != want {
			t.Errorf("role=%q: HasHardDistinguisher = %v, want %v", role, got, want)
		}
	}
}

func TestHasHardDistinguisher_AuthenticodeDistrust(t *testing.T) {
	c := &Candidate{
		Proc: &ProcessInfo{
			Pid:            1,
			Name:           "x.exe",
			SignatureTrust: SignatureTrustUntrusted,
		},
	}
	got, hits := HasHardDistinguisher(c)
	if !got {
		t.Errorf("Authenticode distrust should preserve")
	}
	found := false
	for _, h := range hits {
		if h == "online:authenticode-distrust" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected online:authenticode-distrust in hits %v", hits)
	}
}

func TestHasHardDistinguisher_NamedPipes(t *testing.T) {
	c := &Candidate{
		Proc:       &ProcessInfo{Pid: 1, Name: "x.exe"},
		NamedPipes: []string{`\\.\pipe\msagent_abc`},
	}
	got, _ := HasHardDistinguisher(c)
	if !got {
		t.Errorf("non-empty NamedPipes should preserve")
	}
}

func TestHasHardDistinguisher_NilSafety(t *testing.T) {
	if got, _ := HasHardDistinguisher(nil); got {
		t.Errorf("nil candidate should not preserve")
	}
	if got, _ := HasHardDistinguisher(&Candidate{}); got {
		t.Errorf("candidate with nil Proc should not preserve")
	}
}
