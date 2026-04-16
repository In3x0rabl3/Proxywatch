package behavior

import (
	"sort"
	"testing"

	"proxywatch/internal/shared"
)

// collectSignals runs an emitter and returns the fired signal names sorted.
// Threads an addSignal callback the same way the production scoring loop does.
func collectSignals(emit func(func(string))) []string {
	var got []string
	seen := map[string]struct{}{}
	add := func(s string) {
		if _, dup := seen[s]; dup {
			return
		}
		seen[s] = struct{}{}
		got = append(got, s)
	}
	emit(add)
	sort.Strings(got)
	return got
}

func hasSig(sigs []string, want string) bool {
	for _, s := range sigs {
		if s == want {
			return true
		}
	}
	return false
}

func TestEmitListenerSignals_NoListener_NoSignals(t *testing.T) {
	c := &shared.Candidate{Proc: &shared.ProcessInfo{Pid: 1, Name: "x"}}
	sigs := collectSignals(func(add func(string)) {
		EmitListenerSignals(c, add, SignalContext{}, CommonState{})
	})
	if len(sigs) != 0 {
		t.Errorf("no listener → expected 0 signals, got %v", sigs)
	}
}

func TestEmitListenerSignals_WildcardBindFires(t *testing.T) {
	c := &shared.Candidate{
		Proc: &shared.ProcessInfo{Pid: 1, Name: "sshd"},
		Listeners: []shared.ListenerInfo{
			{LocalAddress: "0.0.0.0", LocalPort: 22},
		},
	}
	sigs := collectSignals(func(add func(string)) {
		EmitListenerSignals(c, add, SignalContext{}, CommonState{})
	})
	if !hasSig(sigs, "listener-open-port-awaiting") {
		t.Errorf("expected listener-open-port-awaiting in %v", sigs)
	}
	if !hasSig(sigs, "listener-wildcard-bind") {
		t.Errorf("expected listener-wildcard-bind in %v", sigs)
	}
	// Port 22 is common → listener-uncommon-port should NOT fire.
	if hasSig(sigs, "listener-uncommon-port") {
		t.Errorf("port 22 is common, listener-uncommon-port should not fire")
	}
}

func TestEmitListenerSignals_UncommonPort(t *testing.T) {
	c := &shared.Candidate{
		Proc: &shared.ProcessInfo{Pid: 1, Name: "custom"},
		Listeners: []shared.ListenerInfo{
			{LocalAddress: "127.0.0.1", LocalPort: 4444},
		},
	}
	sigs := collectSignals(func(add func(string)) {
		EmitListenerSignals(c, add, SignalContext{}, CommonState{})
	})
	if !hasSig(sigs, "listener-uncommon-port") {
		t.Errorf("expected listener-uncommon-port on :4444, got %v", sigs)
	}
	if hasSig(sigs, "listener-wildcard-bind") {
		t.Errorf("127.0.0.1 is not wildcard")
	}
}

func TestEmitListenerSignals_MultipleClients(t *testing.T) {
	c := &shared.Candidate{
		Proc:         &shared.ProcessInfo{Pid: 1, Name: "web"},
		Listeners:    []shared.ListenerInfo{{LocalPort: 443}},
		InboundTotal: 5,
	}
	sigs := collectSignals(func(add func(string)) {
		EmitListenerSignals(c, add, SignalContext{}, CommonState{})
	})
	if !hasSig(sigs, "listener-accepting-multiple-clients") {
		t.Errorf("5 inbound → expected listener-accepting-multiple-clients, got %v", sigs)
	}
}

func TestEmitListenerSignals_ServiceContext(t *testing.T) {
	c := &shared.Candidate{
		Proc:      &shared.ProcessInfo{Pid: 4, Name: "system", SessionID: 0},
		Listeners: []shared.ListenerInfo{{LocalPort: 445}},
	}
	sigs := collectSignals(func(add func(string)) {
		EmitListenerSignals(c, add, SignalContext{}, CommonState{})
	})
	if !hasSig(sigs, "listener-service-context") {
		t.Errorf("session 0 with listener → expected listener-service-context, got %v", sigs)
	}
	// session 1 should NOT fire.
	c.Proc.SessionID = 1
	sigs2 := collectSignals(func(add func(string)) {
		EmitListenerSignals(c, add, SignalContext{}, CommonState{})
	})
	if hasSig(sigs2, "listener-service-context") {
		t.Errorf("session 1 should not fire listener-service-context")
	}
}

func TestEmitListenerSignals_LocalServer(t *testing.T) {
	// listener-local-server: has listener AND inbound AND zero external out.
	c := &shared.Candidate{
		Proc:         &shared.ProcessInfo{Pid: 1, Name: "local-service"},
		Listeners:    []shared.ListenerInfo{{LocalPort: 8080}},
		InboundTotal: 2,
		OutExternal:  0,
	}
	sigs := collectSignals(func(add func(string)) {
		EmitListenerSignals(c, add, SignalContext{}, CommonState{})
	})
	if !hasSig(sigs, "listener-local-server") {
		t.Errorf("expected listener-local-server, got %v", sigs)
	}
	// Add external outbound → signal should not fire.
	c.OutExternal = 1
	sigs2 := collectSignals(func(add func(string)) {
		EmitListenerSignals(c, add, SignalContext{}, CommonState{})
	})
	if hasSig(sigs2, "listener-local-server") {
		t.Errorf("with OutExternal>0, local-server should not fire")
	}
}

func TestEmitListenerSignals_LongIdle(t *testing.T) {
	c := &shared.Candidate{
		Proc:         &shared.ProcessInfo{Pid: 1, Name: "idle-service"},
		Listeners:    []shared.ListenerInfo{{LocalPort: 8080}},
		InboundTotal: 0,
		OutTotal:     0,
		SeenSeconds:  180,
	}
	sigs := collectSignals(func(add func(string)) {
		EmitListenerSignals(c, add, SignalContext{}, CommonState{})
	})
	if !hasSig(sigs, "listener-long-idle") {
		t.Errorf("idle >120s with no traffic → expected listener-long-idle, got %v", sigs)
	}
	// Under threshold → should not fire.
	c.SeenSeconds = 60
	sigs2 := collectSignals(func(add func(string)) {
		EmitListenerSignals(c, add, SignalContext{}, CommonState{})
	})
	if hasSig(sigs2, "listener-long-idle") {
		t.Errorf("60s is under 120s threshold; long-idle should not fire")
	}
}

func TestEmitListenerSignals_NamedPipeServer(t *testing.T) {
	c := &shared.Candidate{
		Proc:       &shared.ProcessInfo{Pid: 4, Name: "system"},
		Listeners:  []shared.ListenerInfo{{LocalPort: 445}},
		NamedPipes: []string{`\\.\pipe\srvsvc`},
	}
	sigs := collectSignals(func(add func(string)) {
		EmitListenerSignals(c, add, SignalContext{}, CommonState{})
	})
	if !hasSig(sigs, "listener-named-pipe-server") {
		t.Errorf("expected listener-named-pipe-server, got %v", sigs)
	}
}

func TestEmitListenerSignals_MixedProtocol(t *testing.T) {
	// Multiple TCP listeners.
	c := &shared.Candidate{
		Proc: &shared.ProcessInfo{Pid: 1, Name: "multi"},
		Listeners: []shared.ListenerInfo{
			{LocalPort: 80},
			{LocalPort: 443},
		},
	}
	sigs := collectSignals(func(add func(string)) {
		EmitListenerSignals(c, add, SignalContext{}, CommonState{})
	})
	if !hasSig(sigs, "listener-mixed-protocol") {
		t.Errorf("multiple TCP listeners → expected listener-mixed-protocol, got %v", sigs)
	}
	// TCP + UDP also fires.
	c2 := &shared.Candidate{
		Proc:         &shared.ProcessInfo{Pid: 1, Name: "dns"},
		Listeners:    []shared.ListenerInfo{{LocalPort: 53}},
		UDPListeners: []shared.UDPListenerInfo{{LocalPort: 53}},
	}
	sigs2 := collectSignals(func(add func(string)) {
		EmitListenerSignals(c2, add, SignalContext{}, CommonState{})
	})
	if !hasSig(sigs2, "listener-mixed-protocol") {
		t.Errorf("TCP + UDP → expected listener-mixed-protocol, got %v", sigs2)
	}
}

func TestEmitListenerSignals_HighMemoryAndLowThreadCount(t *testing.T) {
	c := &shared.Candidate{
		Proc: &shared.ProcessInfo{
			Pid:         1,
			Name:        "daemon",
			MemUsage:    200 * 1024 * 1024, // 200 MB > 100 MB threshold
			ThreadCount: 3,
		},
		Listeners: []shared.ListenerInfo{{LocalPort: 8080}},
	}
	sigs := collectSignals(func(add func(string)) {
		EmitListenerSignals(c, add, SignalContext{}, CommonState{})
	})
	if !hasSig(sigs, "listener-high-memory") {
		t.Errorf("expected listener-high-memory, got %v", sigs)
	}
	if !hasSig(sigs, "listener-low-thread-count") {
		t.Errorf("expected listener-low-thread-count, got %v", sigs)
	}
}

func TestEmitListenerSignals_NoChildren(t *testing.T) {
	c := &shared.Candidate{
		Proc:      &shared.ProcessInfo{Pid: 1, Name: "solo", ChildCount: 0},
		Listeners: []shared.ListenerInfo{{LocalPort: 8080}},
	}
	sigs := collectSignals(func(add func(string)) {
		EmitListenerSignals(c, add, SignalContext{}, CommonState{})
	})
	if !hasSig(sigs, "listener-no-children") {
		t.Errorf("expected listener-no-children, got %v", sigs)
	}
}
