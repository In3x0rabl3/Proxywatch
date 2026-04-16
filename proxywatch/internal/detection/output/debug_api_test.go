package output

import (
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"

	"proxywatch/internal/shared"
)

func mkCand(pid int, name, role string, signals []string) shared.Candidate {
	return shared.Candidate{
		Host: "h1",
		Proc: &shared.ProcessInfo{
			Pid:  pid,
			Name: name,
		},
		Role:    role,
		Signals: signals,
	}
}

func TestCandidatesToSnapshots_SkipsNilProc(t *testing.T) {
	cands := []shared.Candidate{
		mkCand(1, "a", "outbound", nil),
		{Host: "h1", Proc: nil, Role: "outbound"}, // nil Proc — must be dropped.
		mkCand(2, "b", "outbound", nil),
	}
	snap := CandidatesToSnapshots(cands)
	if len(snap) != 2 {
		t.Errorf("got %d snapshots, want 2 (nil Proc filtered)", len(snap))
	}
	if snap[0].PID != 1 || snap[1].PID != 2 {
		t.Errorf("order not preserved: got PIDs %d,%d", snap[0].PID, snap[1].PID)
	}
}

func TestCandidatesToSnapshots_ProjectsFields(t *testing.T) {
	c := shared.Candidate{
		Host: "h1",
		Proc: &shared.ProcessInfo{
			Pid: 99, Name: "proc", ExePath: "/bin/p", UserName: "u", ParentPid: 1,
			CmdLine: "cmd args", IOReadBps: 10, IOWriteBps: 20,
		},
		Role:           "control-channel",
		Score:          80,
		Confidence:     60,
		ActiveProxying: true,
		Signals:        []string{"sig-a"},
		Reasons:        []string{"reason-x"},
		Listeners:      []shared.ListenerInfo{{}, {}},
		Conns:          []shared.ConnectionInfo{{}},
		OutTotal:       9,
		ControlChannel: &shared.ConnectionInfo{RemoteAddress: "1.2.3.4", RemotePort: 443},
	}
	snap := CandidatesToSnapshots([]shared.Candidate{c})
	if len(snap) != 1 {
		t.Fatalf("got %d snapshots, want 1", len(snap))
	}
	s := snap[0]
	if s.PID != 99 || s.Name != "proc" || s.ExePath != "/bin/p" || s.User != "u" {
		t.Errorf("basic proc projection failed: %+v", s)
	}
	if s.Role != "control-channel" || s.RoleFamily == "" {
		t.Errorf("role/family not populated: %+v", s)
	}
	if s.ListenerCount != 2 || s.ConnCount != 1 {
		t.Errorf("listener/conn count projection failed: got L=%d C=%d", s.ListenerCount, s.ConnCount)
	}
	if s.ControlChannelRemote != "1.2.3.4:443" {
		t.Errorf("ControlChannelRemote = %q, want 1.2.3.4:443", s.ControlChannelRemote)
	}
	// Signals + Reasons copied (not shared — mutating original must not bleed).
	c.Signals[0] = "mutated"
	if s.Signals[0] == "mutated" {
		t.Errorf("Signals slice aliased the original")
	}
}

func TestBuildDiffMap_SignalsSortedAndKeyedByPID(t *testing.T) {
	snap := []CandidateSnapshot{
		{PID: 42, Name: "proc-a", Role: "outbound", Signals: []string{"z-sig", "a-sig", "m-sig"}},
		{PID: 7, Name: "proc-b", Role: "listener", Signals: []string{"one"}},
	}
	out := BuildDiffMap(snap)
	if len(out) != 2 {
		t.Errorf("got %d entries, want 2", len(out))
	}
	e := out["42"]
	if e.Name != "proc-a" || e.Role != "outbound" {
		t.Errorf("diff entry for PID 42 mismatch: %+v", e)
	}
	if !sort.StringsAreSorted(e.Signals) {
		t.Errorf("signals not sorted: %v", e.Signals)
	}
	if got := out["7"].Signals; !reflect.DeepEqual(got, []string{"one"}) {
		t.Errorf("single-signal entry got %v", got)
	}
}

func TestFirstSignalMatch(t *testing.T) {
	have := []string{"alpha", "beta", "gamma"}
	// First-from-want order wins.
	if got := firstSignalMatch(have, []string{"zeta", "beta", "gamma"}); got != "beta" {
		t.Errorf("got %q, want beta", got)
	}
	// No match → empty string.
	if got := firstSignalMatch(have, []string{"delta", "epsilon"}); got != "" {
		t.Errorf("no match should return empty, got %q", got)
	}
	// Empty have or want → empty.
	if got := firstSignalMatch(nil, []string{"alpha"}); got != "" {
		t.Errorf("nil have should return empty, got %q", got)
	}
	if got := firstSignalMatch(have, nil); got != "" {
		t.Errorf("nil want should return empty, got %q", got)
	}
}

func TestEvaluateSuppression(t *testing.T) {
	// Decisive signal wins over every other rule.
	e := &FPReportEntry{DecisiveSignal: "pivot-ssh-tunnel-flags"}
	if s, r := evaluateSuppression(e); s || r != "decisive-signal:pivot-ssh-tunnel-flags" {
		t.Errorf("decisive should block suppression: s=%v r=%q", s, r)
	}

	// Hard blocker blocks suppression even without decisive signal.
	e = &FPReportEntry{FPShapeHardBlockers: []string{"block-1", "block-2"}}
	if s, r := evaluateSuppression(e); s || r != "fp-shape-hard-blocker:block-1" {
		t.Errorf("hard blocker should block: s=%v r=%q", s, r)
	}

	// Soft blocker blocks unless override is set.
	e = &FPReportEntry{FPShapeSoftBlockers: []string{"soft-1"}}
	if s, r := evaluateSuppression(e); s || r != "fp-shape-soft-blocker:soft-1" {
		t.Errorf("soft blocker should block: s=%v r=%q", s, r)
	}
	// With override → soft blocker ignored → falls through to the rest.
	e = &FPReportEntry{FPShapeSoftBlockers: []string{"soft-1"}, FPShapeSoftOverride: true}
	if s, _ := evaluateSuppression(e); s {
		t.Errorf("soft override should allow suppression to proceed (default is no suppress)")
	}

	// FP-shape demote → suppresses.
	e = &FPReportEntry{FPShapeDemoted: true}
	if s, r := evaluateSuppression(e); !s || r != shared.VendorFPShapeReason {
		t.Errorf("FPShapeDemoted should suppress: s=%v r=%q", s, r)
	}

	// VendorUpdateDemoted → suppresses.
	e = &FPReportEntry{VendorUpdateDemoted: true}
	if s, r := evaluateSuppression(e); !s || r != shared.VendorUpdateCadenceReason {
		t.Errorf("VendorUpdateDemoted should suppress: s=%v r=%q", s, r)
	}

	// KnownUpdater → suppresses.
	e = &FPReportEntry{KnownUpdater: true}
	if s, r := evaluateSuppression(e); !s || r != "known-updater" {
		t.Errorf("KnownUpdater should suppress: s=%v r=%q", s, r)
	}

	// Signed+trusted + no strong-evidence → suppresses.
	e = &FPReportEntry{Signed: true, SignatureTrust: shared.SignatureTrustTrusted}
	if s, r := evaluateSuppression(e); !s || r != shared.SignatureTrustedReason {
		t.Errorf("signed+trusted should suppress: s=%v r=%q", s, r)
	}
	// StrongEvidence on signed+trusted → does NOT suppress.
	e = &FPReportEntry{Signed: true, SignatureTrust: shared.SignatureTrustTrusted, StrongEvidence: true}
	if s, _ := evaluateSuppression(e); s {
		t.Errorf("strong evidence should prevent signed suppression")
	}

	// Benign overridden by behavior → blocks suppression with explicit reason.
	e = &FPReportEntry{BenignOverridden: true}
	if s, r := evaluateSuppression(e); s || r != "benign-overridden-by-behavior" {
		t.Errorf("BenignOverridden should block suppression: s=%v r=%q", s, r)
	}

	// Default: no rules fired → no suppression.
	e = &FPReportEntry{}
	if s, r := evaluateSuppression(e); s || r != "" {
		t.Errorf("empty entry should not suppress: s=%v r=%q", s, r)
	}
}

func TestFilterSnapshots(t *testing.T) {
	snap := []CandidateSnapshot{
		{PID: 1, Name: "sshd", Role: "control-channel", RoleFamily: "control", State: "Promoted"},
		{PID: 2, Name: "cheerful_glove", Role: "outbound", RoleFamily: "outbound", State: "Analyzing"},
		{PID: 3, Name: "curl", Role: "outbound", RoleFamily: "outbound", State: "Promoted"},
	}

	// No filters → all.
	r := httptest.NewRequest("GET", "/candidates", nil)
	if got := filterSnapshots(snap, r); len(got) != 3 {
		t.Errorf("empty filter: got %d, want 3", len(got))
	}

	// Name substring (case-insensitive).
	r = httptest.NewRequest("GET", "/candidates?name=SSH", nil)
	out := filterSnapshots(snap, r)
	if len(out) != 1 || out[0].PID != 1 {
		t.Errorf("name filter got %+v", out)
	}

	// Role filter matches role OR role family.
	r = httptest.NewRequest("GET", "/candidates?role=outbound", nil)
	out = filterSnapshots(snap, r)
	if len(out) != 2 {
		t.Errorf("role filter got %d, want 2", len(out))
	}
	r = httptest.NewRequest("GET", "/candidates?role=control", nil) // family match
	out = filterSnapshots(snap, r)
	if len(out) != 1 || out[0].PID != 1 {
		t.Errorf("role-family filter got %+v", out)
	}

	// State substring match.
	r = httptest.NewRequest("GET", "/candidates?state=analy", nil)
	out = filterSnapshots(snap, r)
	if len(out) != 1 || out[0].PID != 2 {
		t.Errorf("state filter got %+v", out)
	}

	// PID exact match.
	r = httptest.NewRequest("GET", "/candidates?pid=3", nil)
	out = filterSnapshots(snap, r)
	if len(out) != 1 || out[0].Name != "curl" {
		t.Errorf("pid filter got %+v", out)
	}
	// Non-matching PID → empty.
	r = httptest.NewRequest("GET", "/candidates?pid=999", nil)
	out = filterSnapshots(snap, r)
	if len(out) != 0 {
		t.Errorf("non-matching pid should yield empty, got %d", len(out))
	}

	// Combined filters are AND-composed.
	r = httptest.NewRequest("GET", "/candidates?role=outbound&state=promoted", nil)
	out = filterSnapshots(snap, r)
	if len(out) != 1 || out[0].PID != 3 {
		t.Errorf("combined role+state filter got %+v", out)
	}
}
