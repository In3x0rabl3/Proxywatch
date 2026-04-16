package behavior

import (
	"testing"

	"proxywatch/internal/shared"
)

func TestEmitSessionSignals_ControlChannelPersistent(t *testing.T) {
	c := &shared.Candidate{
		Proc:                   &shared.ProcessInfo{Pid: 1, Name: "beacon"},
		ControlChannel:         &shared.ConnectionInfo{RemoteAddress: "1.2.3.4", RemotePort: 443},
		ControlDurationSeconds: 120,
	}
	sigs := collectSignals(func(add func(string)) {
		EmitSessionSignals(c, add, SignalContext{}, CommonState{})
	})
	if !hasSig(sigs, "session-control-channel-persistent") {
		t.Errorf("expected session-control-channel-persistent, got %v", sigs)
	}
	// Under 30s → no fire.
	c.ControlDurationSeconds = 10
	sigs2 := collectSignals(func(add func(string)) {
		EmitSessionSignals(c, add, SignalContext{}, CommonState{})
	})
	if hasSig(sigs2, "session-control-channel-persistent") {
		t.Errorf("10s duration below 30s threshold; should not fire")
	}
	// No ControlChannel → no fire.
	c.ControlChannel = nil
	c.ControlDurationSeconds = 120
	sigs3 := collectSignals(func(add func(string)) {
		EmitSessionSignals(c, add, SignalContext{}, CommonState{})
	})
	if hasSig(sigs3, "session-control-channel-persistent") {
		t.Errorf("nil ControlChannel; should not fire")
	}
}

func TestEmitSessionSignals_SingleTargetPersistence(t *testing.T) {
	c := &shared.Candidate{
		Proc:         &shared.ProcessInfo{Pid: 1, Name: "beacon"},
		OutExternal:  1,
		OutLongLived: 1,
		OutInternal:  0,
	}
	sigs := collectSignals(func(add func(string)) {
		EmitSessionSignals(c, add, SignalContext{}, CommonState{})
	})
	if !hasSig(sigs, "session-single-target-persistence") {
		t.Errorf("expected session-single-target-persistence, got %v", sigs)
	}
	// Adding internal out suppresses.
	c.OutInternal = 1
	sigs2 := collectSignals(func(add func(string)) {
		EmitSessionSignals(c, add, SignalContext{}, CommonState{})
	})
	if hasSig(sigs2, "session-single-target-persistence") {
		t.Errorf("OutInternal>0 should suppress single-target-persistence (becomes pivot shape)")
	}
}

func TestEmitSessionSignals_InteractiveIOBalance(t *testing.T) {
	c := &shared.Candidate{
		Proc: &shared.ProcessInfo{
			Pid:          1,
			Name:         "shell-session",
			IOReadBytes:  10 * 1024,
			IOWriteBytes: 8 * 1024, // ratio 1.25 (inside 0.3-3.0)
		},
		OutTotal: 1,
	}
	sigs := collectSignals(func(add func(string)) {
		EmitSessionSignals(c, add, SignalContext{}, CommonState{})
	})
	if !hasSig(sigs, "session-interactive-io-balance") {
		t.Errorf("balanced IO → expected session-interactive-io-balance, got %v", sigs)
	}
	// Read-dominant → ratio 10 (outside range), no fire.
	c.Proc.IOWriteBytes = 1024
	sigs2 := collectSignals(func(add func(string)) {
		EmitSessionSignals(c, add, SignalContext{}, CommonState{})
	})
	if hasSig(sigs2, "session-interactive-io-balance") {
		t.Errorf("10x imbalance should not fire interactive-io-balance")
	}
}

func TestEmitSessionSignals_ExfilWriteHeavy(t *testing.T) {
	c := &shared.Candidate{
		Proc: &shared.ProcessInfo{
			Pid:          1,
			Name:         "exfil",
			IOReadBytes:  1024,
			IOWriteBytes: 80 * 1024, // writeRatio 80/81 ≈ 0.988 > 0.70
		},
		OutTotal: 1,
	}
	cs := CommonState{TotalIO: 81 * 1024}
	sigs := collectSignals(func(add func(string)) {
		EmitSessionSignals(c, add, SignalContext{}, cs)
	})
	if !hasSig(sigs, "session-exfil-write-heavy") {
		t.Errorf("write-heavy → expected session-exfil-write-heavy, got %v", sigs)
	}
}

func TestEmitSessionSignals_ASNMismatch(t *testing.T) {
	// Vendor claim + ASN mismatch → fires.
	c := &shared.Candidate{
		Proc: &shared.ProcessInfo{
			Pid:     1,
			Name:    "x",
			Company: "Some Vendor Inc.",
		},
		OutExternal: 1,
	}
	cs := CommonState{ASNOrgs: []string{"Cloudflare"}, ASNAligned: false}
	sigs := collectSignals(func(add func(string)) {
		EmitSessionSignals(c, add, SignalContext{}, cs)
	})
	if !hasSig(sigs, "session-asn-mismatch") {
		t.Errorf("vendor with mismatched ASN → expected session-asn-mismatch, got %v", sigs)
	}
	// No vendor claim (empty Company + Publisher) → no fire (can't mismatch against nothing).
	c.Proc.Company = ""
	c.Proc.Publisher = ""
	sigs2 := collectSignals(func(add func(string)) {
		EmitSessionSignals(c, add, SignalContext{}, cs)
	})
	if hasSig(sigs2, "session-asn-mismatch") {
		t.Errorf("no vendor claim should not fire asn-mismatch (FP on missing data)")
	}
}

func TestEmitSessionSignals_ShellSpawn(t *testing.T) {
	// Shell binary with network activity.
	c := &shared.Candidate{
		Proc:     &shared.ProcessInfo{Pid: 1, Name: "bash"},
		OutTotal: 1,
	}
	cs := CommonState{NameLower: "bash"}
	sigs := collectSignals(func(add func(string)) {
		EmitSessionSignals(c, add, SignalContext{}, cs)
	})
	if !hasSig(sigs, "session-shell-spawn") {
		t.Errorf("shell binary + network → expected session-shell-spawn, got %v", sigs)
	}
	// Non-shell with children + external out also fires.
	c2 := &shared.Candidate{
		Proc:        &shared.ProcessInfo{Pid: 1, Name: "beacon", ChildCount: 2},
		OutExternal: 1,
	}
	sigs2 := collectSignals(func(add func(string)) {
		EmitSessionSignals(c2, add, SignalContext{}, CommonState{NameLower: "beacon"})
	})
	if !hasSig(sigs2, "session-shell-spawn") {
		t.Errorf("children + external out → expected session-shell-spawn, got %v", sigs2)
	}
}

func TestEmitSessionSignals_ElevatedExternal(t *testing.T) {
	c := &shared.Candidate{
		Proc:        &shared.ProcessInfo{Pid: 1, Name: "x", Integrity: "System"},
		OutExternal: 1,
	}
	sigs := collectSignals(func(add func(string)) {
		EmitSessionSignals(c, add, SignalContext{}, CommonState{})
	})
	if !hasSig(sigs, "session-elevated-external") {
		t.Errorf("System integrity + external → expected session-elevated-external, got %v", sigs)
	}
	// Medium → no fire.
	c.Proc.Integrity = "Medium"
	sigs2 := collectSignals(func(add func(string)) {
		EmitSessionSignals(c, add, SignalContext{}, CommonState{})
	})
	if hasSig(sigs2, "session-elevated-external") {
		t.Errorf("Medium integrity should not fire elevated-external")
	}
}

func TestEmitSessionSignals_InternalControl(t *testing.T) {
	// Lateral session: internal-only + long-lived + control channel.
	c := &shared.Candidate{
		Proc:                   &shared.ProcessInfo{Pid: 1, Name: "lateral"},
		OutExternal:            0,
		OutInternal:            1,
		OutLongLived:           1,
		ControlChannel:         &shared.ConnectionInfo{RemoteAddress: "10.0.0.5", RemotePort: 445},
		ControlDurationSeconds: 120,
	}
	sigs := collectSignals(func(add func(string)) {
		EmitSessionSignals(c, add, SignalContext{}, CommonState{})
	})
	if !hasSig(sigs, "session-internal-control") {
		t.Errorf("expected session-internal-control, got %v", sigs)
	}
}

func TestEmitSessionSignals_ImpersonationToken(t *testing.T) {
	c := &shared.Candidate{
		Proc:        &shared.ProcessInfo{Pid: 1, Name: "x", TokenType: "Impersonation"},
		OutExternal: 1,
	}
	sigs := collectSignals(func(add func(string)) {
		EmitSessionSignals(c, add, SignalContext{}, CommonState{})
	})
	if !hasSig(sigs, "session-impersonation-token") {
		t.Errorf("expected session-impersonation-token, got %v", sigs)
	}
}

func TestEmitSessionSignals_RWXMemory(t *testing.T) {
	c := &shared.Candidate{
		Proc:     &shared.ProcessInfo{Pid: 1, Name: "x", HasRWXMemory: true},
		OutTotal: 1,
	}
	sigs := collectSignals(func(add func(string)) {
		EmitSessionSignals(c, add, SignalContext{}, CommonState{})
	})
	if !hasSig(sigs, "session-rwx-memory") {
		t.Errorf("expected session-rwx-memory, got %v", sigs)
	}
}
