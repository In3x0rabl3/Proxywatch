package behavior

import (
	"testing"

	"proxywatch/internal/shared"
)

func TestEmitOutboundSignals_MultiExternalCDN(t *testing.T) {
	// Multiple external destinations, no internal → CDN/content delivery shape.
	c := &shared.Candidate{
		Proc:        &shared.ProcessInfo{Pid: 1, Name: "browser"},
		OutExternal: 5,
		OutInternal: 0,
	}
	sigs := collectSignals(func(add func(string)) {
		EmitOutboundSignals(c, add, SignalContext{}, CommonState{})
	})
	if !hasSig(sigs, "outbound-multi-external-cdn") {
		t.Errorf("expected outbound-multi-external-cdn, got %v", sigs)
	}
	// Adding internal → not CDN shape.
	c.OutInternal = 1
	sigs2 := collectSignals(func(add func(string)) {
		EmitOutboundSignals(c, add, SignalContext{}, CommonState{})
	})
	if hasSig(sigs2, "outbound-multi-external-cdn") {
		t.Errorf("internal traffic should suppress CDN signal")
	}
}

func TestEmitOutboundSignals_PushNotification(t *testing.T) {
	// Single long-lived external, no churn, no inbound → push-notification shape.
	c := &shared.Candidate{
		Proc:          &shared.ProcessInfo{Pid: 1, Name: "notify"},
		OutExternal:   1,
		OutInternal:   0,
		OutLongLived:  1,
		OutShortLived: 0,
		InboundTotal:  0,
	}
	sigs := collectSignals(func(add func(string)) {
		EmitOutboundSignals(c, add, SignalContext{}, CommonState{})
	})
	if !hasSig(sigs, "outbound-push-notification") {
		t.Errorf("expected outbound-push-notification, got %v", sigs)
	}
	// Any churn breaks the signal.
	c.OutShortLived = 1
	sigs2 := collectSignals(func(add func(string)) {
		EmitOutboundSignals(c, add, SignalContext{}, CommonState{})
	})
	if hasSig(sigs2, "outbound-push-notification") {
		t.Errorf("short-lived churn should suppress push-notification")
	}
}

func TestEmitOutboundSignals_CertValidation(t *testing.T) {
	c := &shared.Candidate{
		Proc:          &shared.ProcessInfo{Pid: 1, Name: "cert"},
		OutShortLived: 3,
		OutExternal:   3,
	}
	cs := CommonState{TotalIO: 10 * 1024}
	sigs := collectSignals(func(add func(string)) {
		EmitOutboundSignals(c, add, SignalContext{}, cs)
	})
	if !hasSig(sigs, "outbound-cert-validation") {
		t.Errorf("short-lived + tiny IO → expected outbound-cert-validation, got %v", sigs)
	}
	// Large IO disqualifies (not a cert-check shape).
	cs2 := CommonState{TotalIO: 200 * 1024}
	sigs2 := collectSignals(func(add func(string)) {
		EmitOutboundSignals(c, add, SignalContext{}, cs2)
	})
	if hasSig(sigs2, "outbound-cert-validation") {
		t.Errorf("large IO should suppress cert-validation")
	}
}

func TestEmitOutboundSignals_ASNAligned(t *testing.T) {
	c := &shared.Candidate{Proc: &shared.ProcessInfo{Pid: 1, Name: "x"}}
	cs := CommonState{ASNAligned: true}
	sigs := collectSignals(func(add func(string)) {
		EmitOutboundSignals(c, add, SignalContext{}, cs)
	})
	if !hasSig(sigs, "outbound-asn-org-aligned") {
		t.Errorf("expected outbound-asn-org-aligned, got %v", sigs)
	}
}

func TestEmitOutboundSignals_KnownVendor(t *testing.T) {
	c := &shared.Candidate{
		Proc: &shared.ProcessInfo{
			Pid:     1,
			Name:    "msedge",
			ExePath: `C:\Program Files\Microsoft\Edge\msedge.exe`,
		},
	}
	sigs := collectSignals(func(add func(string)) {
		EmitOutboundSignals(c, add, SignalContext{}, CommonState{})
	})
	if !hasSig(sigs, "outbound-known-vendor") {
		t.Errorf("trusted path → expected outbound-known-vendor, got %v", sigs)
	}
	// Downloads path → not known-vendor.
	c.Proc.ExePath = `C:\Users\ops\Downloads\x.exe`
	sigs2 := collectSignals(func(add func(string)) {
		EmitOutboundSignals(c, add, SignalContext{}, CommonState{})
	})
	if hasSig(sigs2, "outbound-known-vendor") {
		t.Errorf("user-writable path should not fire known-vendor")
	}
}

func TestEmitOutboundSignals_SystemPath(t *testing.T) {
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"linux /usr", `/usr/bin/curl`, true},
		{"linux /bin", `/bin/bash`, true},
		{"windows system32", `C:\Windows\System32\svchost.exe`, true},
		{"Program Files", `C:\Program Files\Foo\bar.exe`, true},
		{"user home", `/home/ops/x`, false},
		{"Downloads", `C:\Users\ops\Downloads\x.exe`, false},
		{"empty", ``, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &shared.Candidate{Proc: &shared.ProcessInfo{Pid: 1, Name: "x", ExePath: tc.path}}
			sigs := collectSignals(func(add func(string)) {
				EmitOutboundSignals(c, add, SignalContext{}, CommonState{})
			})
			got := hasSig(sigs, "outbound-system-path")
			if got != tc.want {
				t.Errorf("path=%q outbound-system-path = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestEmitOutboundSignals_SignatureTrusted(t *testing.T) {
	c := &shared.Candidate{
		Proc: &shared.ProcessInfo{
			Pid:            1,
			Name:           "signed",
			Signed:         true,
			SignatureTrust: shared.SignatureTrustTrusted,
		},
	}
	sigs := collectSignals(func(add func(string)) {
		EmitOutboundSignals(c, add, SignalContext{}, CommonState{})
	})
	// Verify the trusted-reason signal fires — its name is in shared.SignatureTrustedReason.
	found := false
	for _, s := range sigs {
		if s == shared.SignatureTrustedReason {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("trusted signature → expected %q, got %v", shared.SignatureTrustedReason, sigs)
	}
	// Not signed → not emitted.
	c.Proc.Signed = false
	c.Proc.SignatureTrust = shared.SignatureTrustUnsigned
	sigs2 := collectSignals(func(add func(string)) {
		EmitOutboundSignals(c, add, SignalContext{}, CommonState{})
	})
	for _, s := range sigs2 {
		if s == shared.SignatureTrustedReason {
			t.Errorf("unsigned binary should not fire trusted-signature signal")
		}
	}
}
