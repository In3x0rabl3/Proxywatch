package scoring

import "testing"

func TestIsSuspiciousExePath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		// Classic user-writable staging locations.
		{`C:\Users\ops\Downloads\impl.exe`, true},
		{`C:\Users\admin\Desktop\beacon.exe`, true},
		{`/tmp/implant`, true},
		{`/var/tmp/stager`, true},
		{`C:\Users\Public\shared.exe`, true},
		{`C:\Users\ops\AppData\Local\Temp\dropper.exe`, true},
		// System / vendor paths — not suspicious.
		{`C:\Windows\System32\svchost.exe`, false},
		{`C:\Program Files\Microsoft\Edge\msedge.exe`, false},
		{`/usr/bin/curl`, false},
		{`/usr/sbin/sshd`, false},
		{`/opt/proxywatch/proxywatch`, false},
		// Empty / degenerate.
		{``, false},
	}
	for _, tc := range cases {
		if got := IsSuspiciousExePath(tc.path); got != tc.want {
			t.Errorf("IsSuspiciousExePath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestConnStateClassifiers(t *testing.T) {
	type triple struct {
		pending     bool
		established bool
		active      bool
	}
	cases := map[string]triple{
		"ESTABLISHED":  {false, true, true},
		"SYN_SENT":     {true, false, true},
		"SYN_RECEIVED": {true, false, true},
		"FIN_WAIT_1":   {false, false, true},
		"FIN_WAIT_2":   {false, false, true},
		"CLOSE_WAIT":   {false, false, true},
		"CLOSING":      {false, false, true},
		"LAST_ACK":     {false, false, true},
		"TIME_WAIT":    {false, false, true},
		"LISTEN":       {false, false, false},
		"CLOSED":       {false, false, false},
		"":             {false, false, false},
		"UNKNOWN":      {false, false, false},
	}
	for state, want := range cases {
		if got := IsPendingControlState(state); got != want.pending {
			t.Errorf("IsPendingControlState(%q) = %v, want %v", state, got, want.pending)
		}
		if got := IsEstablishedState(state); got != want.established {
			t.Errorf("IsEstablishedState(%q) = %v, want %v", state, got, want.established)
		}
		if got := IsActiveConnState(state); got != want.active {
			t.Errorf("IsActiveConnState(%q) = %v, want %v", state, got, want.active)
		}
	}
}
