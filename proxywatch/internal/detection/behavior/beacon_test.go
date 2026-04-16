package behavior

import (
	"testing"
	"time"

	"proxywatch/internal/shared"
)

func TestEmitBeaconSignals_IntervalConfirmed(t *testing.T) {
	c := &shared.Candidate{
		Proc:             &shared.ProcessInfo{Pid: 1, Name: "beacon"},
		BeaconIntervalMs: 60_000,
	}
	sigs := collectSignals(func(add func(string)) {
		EmitBeaconSignals(c, add, SignalContext{}, CommonState{})
	})
	if !hasSig(sigs, "beacon-interval-confirmed") {
		t.Errorf("BeaconIntervalMs > 0 → expected beacon-interval-confirmed, got %v", sigs)
	}
	// Zero interval → should not fire.
	c.BeaconIntervalMs = 0
	sigs2 := collectSignals(func(add func(string)) {
		EmitBeaconSignals(c, add, SignalContext{}, CommonState{})
	})
	if hasSig(sigs2, "beacon-interval-confirmed") {
		t.Errorf("zero interval should not fire beacon-interval-confirmed")
	}
}

func TestEmitBeaconSignals_TargetLock(t *testing.T) {
	// Single external target, no internal or inbound, long-lived.
	c := &shared.Candidate{
		Proc:         &shared.ProcessInfo{Pid: 1, Name: "beacon"},
		OutExternal:  1,
		OutInternal:  0,
		InboundTotal: 0,
		OutLongLived: 1,
	}
	sigs := collectSignals(func(add func(string)) {
		EmitBeaconSignals(c, add, SignalContext{}, CommonState{})
	})
	if !hasSig(sigs, "beacon-target-lock") {
		t.Errorf("single persistent external → expected beacon-target-lock, got %v", sigs)
	}
	// Adding inbound → should not fire.
	c.InboundTotal = 1
	sigs2 := collectSignals(func(add func(string)) {
		EmitBeaconSignals(c, add, SignalContext{}, CommonState{})
	})
	if hasSig(sigs2, "beacon-target-lock") {
		t.Errorf("inbound traffic should suppress beacon-target-lock")
	}
}

func TestEmitBeaconSignals_HTTPChannel(t *testing.T) {
	c := &shared.Candidate{
		Proc:        &shared.ProcessInfo{Pid: 1, Name: "beacon"},
		OutTotal:    2,
		OutExternal: 2,
	}
	cs := CommonState{AllHTTPPorts: true}
	sigs := collectSignals(func(add func(string)) {
		EmitBeaconSignals(c, add, SignalContext{}, cs)
	})
	if !hasSig(sigs, "beacon-http-channel") {
		t.Errorf("all HTTP ports → expected beacon-http-channel, got %v", sigs)
	}
	// AllHTTPPorts=false → no fire.
	cs2 := CommonState{AllHTTPPorts: false}
	sigs2 := collectSignals(func(add func(string)) {
		EmitBeaconSignals(c, add, SignalContext{}, cs2)
	})
	if hasSig(sigs2, "beacon-http-channel") {
		t.Errorf("non-HTTP ports should not fire beacon-http-channel")
	}
}

func TestEmitBeaconSignals_NonStandardPort(t *testing.T) {
	c := &shared.Candidate{
		Proc:     &shared.ProcessInfo{Pid: 1, Name: "beacon"},
		OutTotal: 1,
	}
	cs := CommonState{HasNonStandardPort: true}
	sigs := collectSignals(func(add func(string)) {
		EmitBeaconSignals(c, add, SignalContext{}, cs)
	})
	if !hasSig(sigs, "beacon-non-standard-port") {
		t.Errorf("HasNonStandardPort + OutTotal>0 → expected beacon-non-standard-port, got %v", sigs)
	}
}

func TestEmitBeaconSignals_EndpointRotation(t *testing.T) {
	c := &shared.Candidate{
		Proc:        &shared.ProcessInfo{Pid: 1, Name: "beacon"},
		OutExternal: 3,
	}
	// Port 443 used by 3 distinct external IPs → rotation.
	cs := CommonState{ExtPortCounts: map[int]int{443: 3}}
	sigs := collectSignals(func(add func(string)) {
		EmitBeaconSignals(c, add, SignalContext{}, cs)
	})
	if !hasSig(sigs, "beacon-endpoint-rotation") {
		t.Errorf("multiple external IPs on same port → expected beacon-endpoint-rotation, got %v", sigs)
	}
}

func TestEmitBeaconSignals_NoChildren(t *testing.T) {
	c := &shared.Candidate{
		Proc:     &shared.ProcessInfo{Pid: 1, Name: "beacon", ChildCount: 0},
		OutTotal: 1,
	}
	sigs := collectSignals(func(add func(string)) {
		EmitBeaconSignals(c, add, SignalContext{}, CommonState{})
	})
	if !hasSig(sigs, "beacon-no-children") {
		t.Errorf("no children + outbound → expected beacon-no-children, got %v", sigs)
	}
	// ChildCount>0 should not fire.
	c.Proc.ChildCount = 5
	sigs2 := collectSignals(func(add func(string)) {
		EmitBeaconSignals(c, add, SignalContext{}, CommonState{})
	})
	if hasSig(sigs2, "beacon-no-children") {
		t.Errorf("ChildCount=5 should not fire beacon-no-children")
	}
}

func TestEmitBeaconSignals_CryptoLibLoaded(t *testing.T) {
	c := &shared.Candidate{
		Proc:     &shared.ProcessInfo{Pid: 1, Name: "beacon"},
		OutTotal: 1,
	}
	cs := CommonState{HasCryptoLib: true}
	sigs := collectSignals(func(add func(string)) {
		EmitBeaconSignals(c, add, SignalContext{}, cs)
	})
	if !hasSig(sigs, "beacon-crypto-lib-loaded") {
		t.Errorf("HasCryptoLib + outbound → expected beacon-crypto-lib-loaded, got %v", sigs)
	}
}

func TestEmitBeaconSignals_StaticCryptoLikely(t *testing.T) {
	// Sliver/Go beacon fingerprint: external HTTPS + no crypto lib +
	// unknown vendor + not OS-trusted.
	c := &shared.Candidate{
		Proc: &shared.ProcessInfo{
			Pid:            1,
			Name:           "cheerful_glove.exe",
			ExePath:        `C:\Users\ops\Downloads\cheerful_glove.exe`,
			SignatureTrust: shared.SignatureTrustUnsigned,
		},
		OutTotal:    1,
		OutExternal: 1,
	}
	cs := CommonState{HasCryptoLib: false}
	sigs := collectSignals(func(add func(string)) {
		EmitBeaconSignals(c, add, SignalContext{}, cs)
	})
	if !hasSig(sigs, "beacon-static-crypto-likely") {
		t.Errorf("Go beacon shape → expected beacon-static-crypto-likely, got %v", sigs)
	}
	// Known-vendor process should NOT fire the signal.
	c.Proc.ExePath = `C:\Program Files\Microsoft\Edge\msedge.exe`
	sigs2 := collectSignals(func(add func(string)) {
		EmitBeaconSignals(c, add, SignalContext{}, cs)
	})
	if hasSig(sigs2, "beacon-static-crypto-likely") {
		t.Errorf("known-vendor process should not fire beacon-static-crypto-likely")
	}
	// OS-trusted signed binary should not fire.
	c.Proc.ExePath = `C:\Users\ops\Downloads\cheerful_glove.exe`
	c.Proc.SignatureTrust = shared.SignatureTrustTrusted
	sigs3 := collectSignals(func(add func(string)) {
		EmitBeaconSignals(c, add, SignalContext{}, cs)
	})
	if hasSig(sigs3, "beacon-static-crypto-likely") {
		t.Errorf("trusted-signed binary should not fire beacon-static-crypto-likely")
	}
}

func TestEmitBeaconSignals_LongRunningShape(t *testing.T) {
	// Long-running, very small IO, almost no CPU → sleeping beacon.
	c := &shared.Candidate{
		Proc: &shared.ProcessInfo{
			Pid:          1,
			Name:         "beacon",
			IOReadBytes:  500,
			IOWriteBytes: 500,
			CpuTime:      1 * time.Second,
		},
		OutTotal:    1,
		OutExternal: 1,
		SeenSeconds: 3600,
	}
	cs := CommonState{TotalIO: 1000, IOPerSec: 10} // below 50/sec + total > 1024 needed for read-dominant
	sigs := collectSignals(func(add func(string)) {
		EmitBeaconSignals(c, add, SignalContext{}, cs)
	})
	if !hasSig(sigs, "beacon-sleep-wake-cycle") {
		t.Errorf("old process + <=1 conn → expected beacon-sleep-wake-cycle, got %v", sigs)
	}
	if !hasSig(sigs, "beacon-low-cpu-long-life") {
		t.Errorf("long-running + low CPU → expected beacon-low-cpu-long-life, got %v", sigs)
	}
}
