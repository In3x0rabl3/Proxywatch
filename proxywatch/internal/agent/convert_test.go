package agent

import (
	"math"
	"testing"
	"time"

	"proxywatch/internal/agent/pb"
	"proxywatch/internal/shared"
)

func TestClampInt32(t *testing.T) {
	cases := []struct {
		in   int
		want int32
	}{
		{0, 0},
		{42, 42},
		{-42, -42},
		{math.MaxInt32, math.MaxInt32},
		{math.MinInt32, math.MinInt32},
		// Over-max / under-min clamp to boundaries.
		{math.MaxInt32 + 1, math.MaxInt32},
		{math.MinInt32 - 1, math.MinInt32},
	}
	for _, tc := range cases {
		if got := clampInt32(tc.in); got != tc.want {
			t.Errorf("clampInt32(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestToFromPBProcess_RoundTrip(t *testing.T) {
	start := time.Date(2026, 4, 15, 12, 30, 0, 0, time.UTC)
	orig := &shared.ProcessInfo{
		Pid:                  1234,
		ParentPid:            5678,
		Name:                 "sshd",
		SessionID:            1,
		SessionName:          "Console",
		MemUsage:             1 << 20,
		Status:               "Running",
		UserName:             "root",
		ExePath:              "/usr/sbin/sshd",
		Company:              "OpenBSD",
		Integrity:            "system",
		IOReadBytes:          1000,
		IOWriteBytes:         2000,
		IOOtherBytes:         500,
		CpuTime:              2 * time.Second,
		StartTime:            start,
		WindowTitle:          "ssh session",
		CmdLine:              "/usr/sbin/sshd -D",
		LoadedLibs:           []string{"libc.so", "libcrypto.so"},
		SignatureTrust:       "trusted",
		Signed:               true,
		Publisher:            "OpenBSD Project",
		AuthenticodeOCSPSeen: false,
		SHA256:               "abc123",
		PkgOwned:             true,
		PkgOwnerName:         "openssh-server",
		PublisherDNSAligned:  true,
		OnlineEvidence:       []string{"ev1", "ev2"},
	}
	p := ToPBProcess(orig)
	if p == nil {
		t.Fatal("ToPBProcess returned nil")
	}
	// Basic invariants.
	if p.Pid != 1234 || p.Name != "sshd" {
		t.Errorf("ToPBProcess field mismatch: pid=%d name=%q", p.Pid, p.Name)
	}
	if p.StartTimeUnix != start.Unix() {
		t.Errorf("StartTimeUnix = %d, want %d", p.StartTimeUnix, start.Unix())
	}

	got := FromPBProcess(p)
	if got == nil {
		t.Fatal("FromPBProcess returned nil")
	}
	// Walk the fields that should survive round-trip.
	if got.Pid != orig.Pid ||
		got.ParentPid != orig.ParentPid ||
		got.Name != orig.Name ||
		got.SessionID != orig.SessionID ||
		got.ExePath != orig.ExePath ||
		got.Publisher != orig.Publisher ||
		got.SHA256 != orig.SHA256 ||
		got.PkgOwned != orig.PkgOwned ||
		got.PublisherDNSAligned != orig.PublisherDNSAligned {
		t.Errorf("round-trip fields differ: got %+v, orig %+v", got, orig)
	}
	if got.CpuTime != orig.CpuTime {
		t.Errorf("CpuTime round-trip: got %v, want %v", got.CpuTime, orig.CpuTime)
	}
	if !got.StartTime.Equal(start) {
		t.Errorf("StartTime round-trip: got %v, want %v", got.StartTime, start)
	}
	if len(got.LoadedLibs) != 2 || got.LoadedLibs[0] != "libc.so" {
		t.Errorf("LoadedLibs round-trip: got %v", got.LoadedLibs)
	}
	if len(got.OnlineEvidence) != 2 || got.OnlineEvidence[1] != "ev2" {
		t.Errorf("OnlineEvidence round-trip: got %v", got.OnlineEvidence)
	}
}

func TestToPBProcess_NilSafe(t *testing.T) {
	if ToPBProcess(nil) != nil {
		t.Errorf("ToPBProcess(nil) should return nil")
	}
	if FromPBProcess(nil) != nil {
		t.Errorf("FromPBProcess(nil) should return nil")
	}
}

func TestToPBProcess_ZeroStartTimeProducesZeroUnix(t *testing.T) {
	p := ToPBProcess(&shared.ProcessInfo{Pid: 1})
	if p.StartTimeUnix != 0 {
		t.Errorf("zero StartTime should produce StartTimeUnix=0, got %d", p.StartTimeUnix)
	}
	// FromPB with StartTimeUnix=0 should leave time.Time zero.
	back := FromPBProcess(p)
	if !back.StartTime.IsZero() {
		t.Errorf("StartTimeUnix=0 should round-trip to zero time, got %v", back.StartTime)
	}
}

func TestToFromPBCandidate_RoundTrip(t *testing.T) {
	orig := shared.Candidate{
		Host:                   "host-a",
		Proc:                   &shared.ProcessInfo{Pid: 42, Name: "proc"},
		Score:                  88,
		Confidence:             77,
		Reasons:                []string{"reason1", "reason2"},
		Signals:                []string{"sig1"},
		Role:                   "control-channel",
		ControlSubtype:         "session",
		ActiveProxying:         true,
		ControlChannel:         &shared.ConnectionInfo{Pid: 42, RemoteAddress: "10.0.0.1", RemotePort: 443},
		ControlDurationSeconds: 120,
		SeenSeconds:            200,
		OutTotal:               10,
		OutExternal:            3,
		OutInternal:            7,
		OutLoopback:            0,
		OutLongLived:           2,
		OutShortLived:          8,
		InboundTotal:           1,
		TrafficVerified:        true,
		StrongEvidence:         false,
		DelegatedEgress:        true,
		DelegatedStrong:        false,
		DelegatedOwnerPID:      1,
		DelegatedOwner:         "owner",
		RawSocket:              true,
		Listeners:              []shared.ListenerInfo{{Pid: 42, LocalAddress: "0.0.0.0", LocalPort: 22}},
		Conns:                  []shared.ConnectionInfo{{Pid: 42, LocalAddress: "127.0.0.1", LocalPort: 1234, RemoteAddress: "1.2.3.4", RemotePort: 443}},
		UDPListeners:           []shared.UDPListenerInfo{{Pid: 42, LocalAddress: "0.0.0.0", LocalPort: 53}},
		RawConns:               []shared.RawSocketConn{{Pid: 42, Local: "raw:l", Remote: "raw:r", Proto: "icmp"}},
		NamedPipes:             []string{"pipe-a", "pipe-b"},
		Exited:                 false,
		BeaconIntervalMs:       5000,
		BeaconJitter:           0.15,
	}

	pbc := ToPBCandidate(orig)
	if pbc == nil {
		t.Fatal("ToPBCandidate returned nil")
	}
	got := FromPBCandidate(pbc, "fallback-host")

	// Host preserved (not overridden by fallback).
	if got.Host != "host-a" {
		t.Errorf("Host = %q, want host-a", got.Host)
	}
	if got.Score != orig.Score || got.Confidence != orig.Confidence {
		t.Errorf("score/conf mismatch: got %d/%d, want %d/%d",
			got.Score, got.Confidence, orig.Score, orig.Confidence)
	}
	if got.Role != orig.Role || got.ControlSubtype != orig.ControlSubtype {
		t.Errorf("role/subtype mismatch: got %q/%q", got.Role, got.ControlSubtype)
	}
	if got.BeaconIntervalMs != orig.BeaconIntervalMs || got.BeaconJitter != orig.BeaconJitter {
		t.Errorf("beacon round-trip mismatch: got %dms/%v",
			got.BeaconIntervalMs, got.BeaconJitter)
	}
	if len(got.Reasons) != 2 || got.Reasons[0] != "reason1" {
		t.Errorf("Reasons round-trip: got %v", got.Reasons)
	}
	if len(got.NamedPipes) != 2 || got.NamedPipes[1] != "pipe-b" {
		t.Errorf("NamedPipes round-trip: got %v", got.NamedPipes)
	}
	if len(got.Listeners) != 1 || got.Listeners[0].LocalPort != 22 {
		t.Errorf("Listeners round-trip: got %+v", got.Listeners)
	}
	if len(got.Conns) != 1 || got.Conns[0].RemoteAddress != "1.2.3.4" {
		t.Errorf("Conns round-trip: got %+v", got.Conns)
	}
	if len(got.UDPListeners) != 1 || got.UDPListeners[0].LocalPort != 53 {
		t.Errorf("UDPListeners round-trip: got %+v", got.UDPListeners)
	}
	if len(got.RawConns) != 1 || got.RawConns[0].Proto != "icmp" {
		t.Errorf("RawConns round-trip: got %+v", got.RawConns)
	}
	if got.ControlChannel == nil || got.ControlChannel.RemotePort != 443 {
		t.Errorf("ControlChannel round-trip failed: got %+v", got.ControlChannel)
	}
	if got.Proc == nil || got.Proc.Pid != 42 || got.Proc.Name != "proc" {
		t.Errorf("Proc round-trip failed: got %+v", got.Proc)
	}
}

func TestFromPBCandidate_FallbackHostUsedWhenEmpty(t *testing.T) {
	pbc := &pb.Candidate{Host: ""} // empty envelope.
	got := FromPBCandidate(pbc, "fallback")
	if got.Host != "fallback" {
		t.Errorf("empty Host should use fallback: got %q", got.Host)
	}
}

func TestFromPBCandidate_NilReturnsZero(t *testing.T) {
	got := FromPBCandidate(nil, "fallback")
	if got.Host != "" || got.Proc != nil {
		t.Errorf("nil pb.Candidate should produce zero shared.Candidate, got %+v", got)
	}
}

func TestToEnvelope_PackagesHostAndTimestamp(t *testing.T) {
	ts := time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)
	cands := []shared.Candidate{
		{Host: "h1", Proc: &shared.ProcessInfo{Pid: 1}},
		{Host: "h1", Proc: &shared.ProcessInfo{Pid: 2}},
	}
	env := ToEnvelope("h1", ts, cands)
	if env.HostId != "h1" {
		t.Errorf("HostId = %q, want h1", env.HostId)
	}
	if env.TimestampUnix != ts.Unix() {
		t.Errorf("TimestampUnix = %d, want %d", env.TimestampUnix, ts.Unix())
	}
	if len(env.Candidates) != 2 {
		t.Errorf("envelope has %d candidates, want 2", len(env.Candidates))
	}
	if env.Candidates[0].Proc.Pid != 1 || env.Candidates[1].Proc.Pid != 2 {
		t.Errorf("candidate order not preserved in envelope")
	}
}

func TestToPBConn_NilSafe(t *testing.T) {
	if ToPBConn(nil) != nil {
		t.Errorf("ToPBConn(nil) should return nil")
	}
	if FromPBConn(nil) != nil {
		t.Errorf("FromPBConn(nil) should return nil")
	}
}
