package scoring

import (
	"testing"
	"time"

	"proxywatch/internal/shared"
)

// resetPivotState wipes the package-level pivot-linger state between
// tests so one test doesn't influence another via the PivotUntil /
// TunnelingSeen maps.
func resetPivotState(pids ...int) {
	for _, pid := range pids {
		delete(shared.PivotUntil, pid)
		delete(shared.TunnelingSeen, pid)
		delete(shared.PivotInternalSeen, pid)
	}
}

func TestApplyPivotLinger_C1_AlreadyControlRole(t *testing.T) {
	resetPivotState(1001)
	defer resetPivotState(1001)

	// Candidate already in control-channel with the pivot signal fires
	// the C1 branch — "already a control role doing internal forwarding".
	cands := []shared.Candidate{
		{
			Proc:    &shared.ProcessInfo{Pid: 1001, Name: "beacon-j.exe", ParentPid: 1000},
			Signals: []string{"pivot-non-loopback-internal"},
			Role:    "control-channel",
		},
	}
	ApplyPivotLinger(cands, nil)

	if cands[0].Role != "control-pivot" {
		t.Errorf("C1: role = %q, want control-pivot", cands[0].Role)
	}
	if !cands[0].ActiveProxying {
		t.Errorf("C1: ActiveProxying should be set true")
	}
	if _, ok := shared.PivotUntil[1001]; !ok {
		t.Errorf("C1: PivotUntil should be stamped")
	}
}

func TestApplyPivotLinger_C2_OwnListenerWithInbound(t *testing.T) {
	resetPivotState(1002)
	defer resetPivotState(1002)

	// Process owns a listener AND has inbound connections AND fires the
	// pivot signal. That's the direct-relay case (C2).
	cands := []shared.Candidate{
		{
			Proc:         &shared.ProcessInfo{Pid: 1002, Name: "relay.exe", ParentPid: 1000},
			Listeners:    []shared.ListenerInfo{{LocalPort: 8080, LocalAddress: "0.0.0.0"}},
			InboundTotal: 2,
			Signals:      []string{"pivot-non-loopback-internal"},
			Role:         "outbound",
		},
	}
	ApplyPivotLinger(cands, nil)

	if cands[0].Role != "control-pivot" {
		t.Errorf("C2: role = %q, want control-pivot", cands[0].Role)
	}
}

func TestApplyPivotLinger_C3_AncestorListenerWithInbound(t *testing.T) {
	resetPivotState(1003, 1004)
	defer resetPivotState(1003, 1004)

	// sshd-style: parent owns listener + inbound, child does forwarding.
	// Child should promote via C3 — parent-chain walk.
	cands := []shared.Candidate{
		{
			// Parent sshd — listener :22 + inbound.
			Proc:         &shared.ProcessInfo{Pid: 1003, Name: "sshd.exe", ParentPid: 1},
			Listeners:    []shared.ListenerInfo{{LocalPort: 22, LocalAddress: "0.0.0.0"}},
			InboundTotal: 1,
			Role:         "outbound",
		},
		{
			// Child doing the SOCKS forwarding.
			Proc:    &shared.ProcessInfo{Pid: 1004, Name: "sshd.exe", ParentPid: 1003},
			Signals: []string{"pivot-non-loopback-internal"},
			Role:    "outbound",
		},
	}
	ApplyPivotLinger(cands, nil)

	// Child got promoted via parent-lookup.
	if cands[1].Role != "control-pivot" {
		t.Errorf("C3: child role = %q, want control-pivot", cands[1].Role)
	}
	// Parent doesn't change — no pivot signal on parent itself.
	if cands[0].Role != "outbound" {
		t.Errorf("C3: parent role = %q, want outbound (no signal fired on parent)", cands[0].Role)
	}
}

func TestApplyPivotLinger_NoSignal_NoPromotion(t *testing.T) {
	resetPivotState(1005)
	defer resetPivotState(1005)

	// No pivot-non-loopback-internal signal → no promotion regardless of
	// listener/inbound shape. Pure topology must not promote on its own.
	cands := []shared.Candidate{
		{
			Proc:         &shared.ProcessInfo{Pid: 1005, Name: "web.exe", ParentPid: 1},
			Listeners:    []shared.ListenerInfo{{LocalPort: 443, LocalAddress: "0.0.0.0"}},
			InboundTotal: 5,
			Role:         "outbound",
		},
	}
	ApplyPivotLinger(cands, nil)

	if cands[0].Role != "outbound" {
		t.Errorf("no-signal: role = %q, want outbound (no signal = no promotion)", cands[0].Role)
	}
	if _, ok := shared.PivotUntil[1005]; ok {
		t.Errorf("no-signal: PivotUntil should NOT be stamped")
	}
}

func TestApplyPivotLinger_Linger_ExpiryRestoresRole(t *testing.T) {
	resetPivotState(1006)
	defer resetPivotState(1006)

	// Simulate an expired PivotUntil — the role override should no-op and
	// the entry gets deleted.
	shared.PivotUntil[1006] = time.Now().Add(-1 * time.Second) // already expired

	cands := []shared.Candidate{
		{
			Proc: &shared.ProcessInfo{Pid: 1006, Name: "sshd.exe"},
			Role: "outbound",
		},
	}
	ApplyPivotLinger(cands, nil)

	if cands[0].Role != "outbound" {
		t.Errorf("expired: role = %q, want outbound", cands[0].Role)
	}
	if _, ok := shared.PivotUntil[1006]; ok {
		t.Errorf("expired: PivotUntil entry should be deleted")
	}
}

func TestApplyPivotLinger_ActiveLinger_HoldsRole(t *testing.T) {
	resetPivotState(1007)
	defer resetPivotState(1007)

	// Active linger (expiry in the future) forces role to control-pivot
	// even without a signal firing THIS cycle — that's the point.
	shared.PivotUntil[1007] = time.Now().Add(30 * time.Second)

	cands := []shared.Candidate{
		{
			Proc: &shared.ProcessInfo{Pid: 1007, Name: "sshd.exe"},
			Role: "outbound",
		},
	}
	ApplyPivotLinger(cands, nil)

	if cands[0].Role != "control-pivot" {
		t.Errorf("active-linger: role = %q, want control-pivot", cands[0].Role)
	}
	if !cands[0].ActiveProxying {
		t.Errorf("active-linger: ActiveProxying should be set")
	}
}

func TestApplyPivotLinger_AncestorViaProcessMap(t *testing.T) {
	resetPivotState(1008, 1009)
	defer resetPivotState(1008, 1009)

	// Windows sshd privsep case: grandparent is in candidates, intermediate
	// parent is NOT a candidate but IS in the processes map. Walker should
	// still find the relay ancestor.
	cands := []shared.Candidate{
		{
			// Grandparent sshd_main — the real listener owner.
			Proc:         &shared.ProcessInfo{Pid: 1008, Name: "sshd.exe", ParentPid: 1},
			Listeners:    []shared.ListenerInfo{{LocalPort: 22, LocalAddress: "0.0.0.0"}},
			InboundTotal: 1,
			Role:         "outbound",
		},
		{
			// Grandchild — parent (1500) is intermediate privsep, not in
			// candidates slice but reachable through `processes` map.
			Proc:    &shared.ProcessInfo{Pid: 1009, Name: "sshd.exe", ParentPid: 1500},
			Signals: []string{"pivot-non-loopback-internal"},
			Role:    "outbound",
		},
	}
	// Intermediate privsep process exists in the process-info map but not
	// in candidates — simulates a short-lived helper filtered out of
	// scoring.
	processes := map[int]*shared.ProcessInfo{
		1500: {Pid: 1500, ParentPid: 1008, Name: "sshd.exe"},
	}
	ApplyPivotLinger(cands, processes)

	if cands[1].Role != "control-pivot" {
		t.Errorf("ancestor-walk: grandchild role = %q, want control-pivot", cands[1].Role)
	}
}
