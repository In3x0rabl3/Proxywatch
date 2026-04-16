package behavior

import (
	"testing"

	"proxywatch/internal/shared"
)

func TestEmitPivotSignals_NonLoopbackInternal(t *testing.T) {
	// Sshd-child forwarder case: OutExternal==0 + non-loopback-internal
	// connections. Must fire pivot-non-loopback-internal — this is the
	// single signal that drives pivot-linger promotion.
	c := &shared.Candidate{
		Proc:        &shared.ProcessInfo{Pid: 1, Name: "sshd"},
		OutExternal: 0,
	}
	cs := CommonState{NonLoopbackInternalCount: 2}
	sigs := collectSignals(func(add func(string)) {
		EmitPivotSignals(c, add, SignalContext{}, cs)
	})
	if !hasSig(sigs, "pivot-non-loopback-internal") {
		t.Errorf("expected pivot-non-loopback-internal, got %v", sigs)
	}
	// Adding external traffic suppresses the signal — session, not pivot.
	c.OutExternal = 1
	sigs2 := collectSignals(func(add func(string)) {
		EmitPivotSignals(c, add, SignalContext{}, cs)
	})
	if hasSig(sigs2, "pivot-non-loopback-internal") {
		t.Errorf("OutExternal>0 should suppress pivot-non-loopback-internal")
	}
}

func TestEmitPivotSignals_ListenerPlusOutbound(t *testing.T) {
	c := &shared.Candidate{
		Proc:      &shared.ProcessInfo{Pid: 1, Name: "relay"},
		Listeners: []shared.ListenerInfo{{LocalPort: 8080}},
		OutTotal:  5,
	}
	sigs := collectSignals(func(add func(string)) {
		EmitPivotSignals(c, add, SignalContext{}, CommonState{})
	})
	if !hasSig(sigs, "pivot-listener-plus-outbound") {
		t.Errorf("expected pivot-listener-plus-outbound, got %v", sigs)
	}
}

func TestEmitPivotSignals_LoopbackListenerExternalOut(t *testing.T) {
	c := &shared.Candidate{
		Proc: &shared.ProcessInfo{Pid: 1, Name: "ssh"},
		Listeners: []shared.ListenerInfo{
			{LocalAddress: "127.0.0.1", LocalPort: 1080}, // SOCKS bind
		},
		OutExternal: 1,
	}
	sigs := collectSignals(func(add func(string)) {
		EmitPivotSignals(c, add, SignalContext{}, CommonState{})
	})
	if !hasSig(sigs, "pivot-loopback-listener-external-out") {
		t.Errorf("expected pivot-loopback-listener-external-out, got %v", sigs)
	}
}

func TestEmitPivotSignals_MultiplexRelay(t *testing.T) {
	c := &shared.Candidate{
		Proc:        &shared.ProcessInfo{Pid: 1, Name: "beacon"},
		OutExternal: 1,
		OutInternal: 3,
	}
	sigs := collectSignals(func(add func(string)) {
		EmitPivotSignals(c, add, SignalContext{}, CommonState{})
	})
	if !hasSig(sigs, "pivot-multiplex-relay") {
		t.Errorf("expected pivot-multiplex-relay, got %v", sigs)
	}
}

func TestEmitPivotSignals_MixedProtocolInternal(t *testing.T) {
	c := &shared.Candidate{
		Proc: &shared.ProcessInfo{Pid: 1, Name: "relay"},
	}
	// 3+ distinct internal ports → mixed-protocol.
	cs := CommonState{
		InternalPorts: map[int]int{445: 1, 3389: 1, 22: 1},
	}
	sigs := collectSignals(func(add func(string)) {
		EmitPivotSignals(c, add, SignalContext{}, cs)
	})
	if !hasSig(sigs, "pivot-mixed-protocol-internal") {
		t.Errorf("3 internal ports → expected pivot-mixed-protocol-internal, got %v", sigs)
	}
	// 2 ports is below threshold.
	cs2 := CommonState{InternalPorts: map[int]int{445: 1, 3389: 1}}
	sigs2 := collectSignals(func(add func(string)) {
		EmitPivotSignals(c, add, SignalContext{}, cs2)
	})
	if hasSig(sigs2, "pivot-mixed-protocol-internal") {
		t.Errorf("2 internal ports is below threshold; should not fire")
	}
}

func TestEmitPivotSignals_NamedPipeC2Pattern(t *testing.T) {
	c := &shared.Candidate{
		Proc:       &shared.ProcessInfo{Pid: 4, Name: "system"},
		NamedPipes: []string{"msagent_abc123"},
	}
	sigs := collectSignals(func(add func(string)) {
		EmitPivotSignals(c, add, SignalContext{}, CommonState{})
	})
	if !hasSig(sigs, "pivot-named-pipe-c2-pattern") {
		t.Errorf("Sliver pipe name → expected pivot-named-pipe-c2-pattern, got %v", sigs)
	}
	// Benign pipe → no fire.
	c.NamedPipes = []string{"srvsvc"}
	sigs2 := collectSignals(func(add func(string)) {
		EmitPivotSignals(c, add, SignalContext{}, CommonState{})
	})
	if hasSig(sigs2, "pivot-named-pipe-c2-pattern") {
		t.Errorf("benign pipe name should not fire C2-pattern signal")
	}
}

func TestEmitPivotSignals_AdminShareSMB(t *testing.T) {
	c := &shared.Candidate{
		Proc: &shared.ProcessInfo{Pid: 1, Name: "x"},
	}
	cs := CommonState{InternalPorts: map[int]int{445: 2}}
	sigs := collectSignals(func(add func(string)) {
		EmitPivotSignals(c, add, SignalContext{}, cs)
	})
	if !hasSig(sigs, "pivot-admin-share-smb") {
		t.Errorf("internal port 445 → expected pivot-admin-share-smb, got %v", sigs)
	}
}

func TestEmitPivotSignals_SSHTunnelFlags(t *testing.T) {
	cases := []struct {
		name    string
		binName string
		cmdline string
		want    bool
	}{
		{"ssh -D dynamic socks", "ssh", "ssh ops@host -D 1076", true},
		{"ssh -L local forward", "ssh.exe", "ssh -L 8080:internal:80 ops@host", true},
		{"ssh -R reverse", "ssh", "ssh -R 0.0.0.0:4444:localhost:22 attacker", true},
		{"plink -D", "plink.exe", "plink -D 1080 -pw x user@host", true},
		{"regular ssh no flags", "ssh", "ssh user@host", false},
		{"scp", "scp", "scp file user@host:/tmp", false},
		{"non-ssh", "curl", "curl -D header.txt http://example", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &shared.Candidate{
				Proc: &shared.ProcessInfo{
					Pid:     1,
					Name:    tc.binName,
					CmdLine: tc.cmdline,
				},
			}
			cs := CommonState{NameLower: tc.binName}
			sigs := collectSignals(func(add func(string)) {
				EmitPivotSignals(c, add, SignalContext{}, cs)
			})
			got := hasSig(sigs, "pivot-ssh-tunnel-flags")
			if got != tc.want {
				t.Errorf("pivot-ssh-tunnel-flags = %v, want %v (sigs=%v)", got, tc.want, sigs)
			}
		})
	}
}

func TestEmitPivotSignals_ProxyLibLoaded(t *testing.T) {
	c := &shared.Candidate{Proc: &shared.ProcessInfo{Pid: 1, Name: "x"}}
	cs := CommonState{HasProxyLib: true}
	sigs := collectSignals(func(add func(string)) {
		EmitPivotSignals(c, add, SignalContext{}, cs)
	})
	if !hasSig(sigs, "pivot-proxy-lib-loaded") {
		t.Errorf("HasProxyLib → expected pivot-proxy-lib-loaded, got %v", sigs)
	}
}
