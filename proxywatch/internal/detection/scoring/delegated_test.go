package scoring

import (
	"testing"

	"proxywatch/internal/shared"
)

func TestNormalizedUser(t *testing.T) {
	cases := map[string]string{
		"":                     "",
		"(unknown)":            "",
		"  (unknown)  ":        "",
		"DEMO\\ops":            "demo\\ops",
		"  demo\\ops  ":        "demo\\ops",
		"NT AUTHORITY\\SYSTEM": "nt authority\\system",
	}
	for input, want := range cases {
		if got := NormalizedUser(input); got != want {
			t.Errorf("NormalizedUser(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestIsServicePrincipal(t *testing.T) {
	cases := []struct {
		user string
		want bool
	}{
		// Windows system accounts (note: already lowercased in practice).
		{"nt authority\\system", true},
		{"nt authority\\local service", true},
		{"nt authority\\network service", true},
		{"local service", true},
		{"network service", true},
		{"demo\\system", true}, // ends with \system
		{"someother\\system", true},
		// Regular users.
		{"demo\\ops", false},
		{"demo\\administrator", false},
		{"", false},
		{"root", false},
	}
	for _, tc := range cases {
		if got := IsServicePrincipal(tc.user); got != tc.want {
			t.Errorf("IsServicePrincipal(%q) = %v, want %v", tc.user, got, tc.want)
		}
	}
}

func TestIsLikelyUserWritablePath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"c:/users/ops/downloads/x.exe", true},
		{"c:/users/anyone/desktop/y.exe", true},
		{"c:/users/z/appdata/local/temp/a.exe", true},
		{"/home/op/beacon", true},
		{"/tmp/impl", true},
		{"/var/tmp/stager", true},
		// Note: suspicious-path substring alone (downloads/desktop/etc.) in
		// any part of the path triggers — catches C:\Program Files\foo\downloads\ too.
		// That's intentional.
		// Trusted paths.
		{"c:/windows/system32/svchost.exe", false},
		{"c:/program files/microsoft/edge/msedge.exe", false},
		{"/usr/bin/curl", false},
		{"/usr/sbin/sshd", false},
		{"/opt/proxywatch/proxywatch", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := IsLikelyUserWritablePath(tc.path); got != tc.want {
			t.Errorf("IsLikelyUserWritablePath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestIsKernelThreadLike(t *testing.T) {
	cases := []struct {
		name string
		proc *shared.ProcessInfo
		want bool
	}{
		{"nil", nil, false},
		{"kthreadd itself", &shared.ProcessInfo{Pid: 2, ParentPid: 0, ExePath: ""}, true},
		{"kernel worker pid>2 ppid=2", &shared.ProcessInfo{Pid: 100, ParentPid: 2, ExePath: ""}, true},
		{"kernel worker ppid=1 no exe", &shared.ProcessInfo{Pid: 50, ParentPid: 1, ExePath: ""}, true},
		{"normal user process", &shared.ProcessInfo{Pid: 1234, ParentPid: 1000, ExePath: "/usr/bin/bash"}, false},
		{"no exe but ppid>2", &shared.ProcessInfo{Pid: 1234, ParentPid: 100, ExePath: ""}, false},
		{"exe present, ppid<=2", &shared.ProcessInfo{Pid: 100, ParentPid: 1, ExePath: "/sbin/init-child"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsKernelThreadLike(tc.proc); got != tc.want {
				t.Errorf("IsKernelThreadLike(%+v) = %v, want %v", tc.proc, got, tc.want)
			}
		})
	}
}
