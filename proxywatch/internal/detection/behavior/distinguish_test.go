package behavior

import (
	"testing"

	"proxywatch/internal/shared"
)

func TestEmitDistinguishingSignals_SuspiciousPath(t *testing.T) {
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"Downloads", `C:\Users\ops\Downloads\x.exe`, true},
		{"Desktop", `C:\Users\ops\Desktop\beacon.exe`, true},
		{"AppData Local Temp", `C:\Users\ops\AppData\Local\Temp\dropper.exe`, true},
		{"/tmp", `/tmp/implant`, true},
		{"/var/tmp", `/var/tmp/stager`, true},
		{"/dev/shm", `/dev/shm/payload`, true},
		{"bare home drop", `/home/ops/random.exe`, true},
		{"bare user drop", `C:\Users\ops\foo.exe`, true},
		// NOT suspicious — AppData\Local\Programs is vendor install path.
		{"AppData Programs", `C:\Users\ops\AppData\Local\Programs\Slack\slack.exe`, false},
		// NOT suspicious — user package-manager paths.
		{".local/bin", `/home/ops/.local/bin/tool`, false},
		{".cache", `/home/ops/.cache/x`, false},
		// NOT suspicious — System paths.
		{"System32", `C:\Windows\System32\svchost.exe`, false},
		{"/usr/bin", `/usr/bin/curl`, false},
		{"empty", ``, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &shared.Candidate{Proc: &shared.ProcessInfo{Pid: 1, Name: "x", ExePath: tc.path}}
			sigs := collectSignals(func(add func(string)) {
				EmitDistinguishingSignals(c, add, SignalContext{}, CommonState{})
			})
			got := hasSig(sigs, "suspicious-exe-path")
			if got != tc.want {
				t.Errorf("path=%q suspicious-exe-path = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestEmitDistinguishingSignals_RawSocket(t *testing.T) {
	c := &shared.Candidate{
		Proc:      &shared.ProcessInfo{Pid: 1, Name: "nmap"},
		RawSocket: true,
	}
	sigs := collectSignals(func(add func(string)) {
		EmitDistinguishingSignals(c, add, SignalContext{}, CommonState{})
	})
	if !hasSig(sigs, "raw-socket") {
		t.Errorf("RawSocket flag → expected raw-socket signal, got %v", sigs)
	}
	c.RawSocket = false
	sigs2 := collectSignals(func(add func(string)) {
		EmitDistinguishingSignals(c, add, SignalContext{}, CommonState{})
	})
	if hasSig(sigs2, "raw-socket") {
		t.Errorf("RawSocket=false should not fire")
	}
}

func TestEmitDistinguishingSignals_CmdlineProxyFlags(t *testing.T) {
	cases := []struct {
		name    string
		binName string
		cmdline string
		want    bool
	}{
		{"socat", "socat", "socat TCP-LISTEN:8080 TCP:internal:80", true},
		{"chisel", "chisel", "chisel client host:8080 R:0.0.0.0:22:internal:22", true},
		{"ngrok", "ngrok", "ngrok tcp 22", true},
		{"frpc", "frpc", "frpc -c frpc.ini", true},
		{"proxychains wrapper", "proxychains", "proxychains curl https://x", true},
		{"proxychains4 wrapper (proxychains-ng)", "proxychains4", "proxychains4 curl https://x", true},
		{"--socks flag", "custom", "custom-app --socks 127.0.0.1:1080", true},
		{"--proxy flag", "custom", "custom-app --proxy http://x", true},
		// SSH-specific — handled by pivot emitter, not here.
		{"ssh -D (handled elsewhere)", "ssh", "ssh -D 1076 user@host", false},
		// No proxy flags.
		{"plain curl", "curl", "curl https://example.com", false},
		{"empty", "any", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &shared.Candidate{
				Proc: &shared.ProcessInfo{Pid: 1, Name: tc.binName, CmdLine: tc.cmdline},
			}
			cs := CommonState{NameLower: tc.binName}
			sigs := collectSignals(func(add func(string)) {
				EmitDistinguishingSignals(c, add, SignalContext{}, cs)
			})
			got := hasSig(sigs, "cmdline-proxy-flags")
			if got != tc.want {
				t.Errorf("cmd=%q cmdline-proxy-flags = %v, want %v", tc.cmdline, got, tc.want)
			}
		})
	}
}

func TestEmitDistinguishingSignals_ProxyLibraryLoaded(t *testing.T) {
	cases := []struct {
		name string
		libs []string
		want bool
	}{
		{"libproxychains", []string{"libproxychains4.so.4"}, true},
		{"libsocks", []string{"libsocks.so.1"}, true},
		{"libtsocks", []string{"libtsocks.so"}, true},
		// Crypto libs — not proxy.
		{"libcrypto only", []string{"libcrypto.so.3", "libssl.so.3"}, false},
		{"libc only", []string{"libc.so.6"}, false},
		{"empty", nil, false},
		// Mixed — any match fires.
		{"mixed", []string{"libc.so.6", "libproxychains.so.4"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &shared.Candidate{
				Proc: &shared.ProcessInfo{Pid: 1, Name: "x", LoadedLibs: tc.libs},
			}
			sigs := collectSignals(func(add func(string)) {
				EmitDistinguishingSignals(c, add, SignalContext{}, CommonState{})
			})
			got := hasSig(sigs, "proxy-library-loaded")
			if got != tc.want {
				t.Errorf("libs=%v proxy-library-loaded = %v, want %v", tc.libs, got, tc.want)
			}
		})
	}
}

func TestEmitDistinguishingSignals_NilSafety(t *testing.T) {
	// Emitter must tolerate nil candidate + nil Proc without panicking.
	collectSignals(func(add func(string)) {
		EmitDistinguishingSignals(nil, add, SignalContext{}, CommonState{})
	})
	collectSignals(func(add func(string)) {
		EmitDistinguishingSignals(&shared.Candidate{}, add, SignalContext{}, CommonState{})
	})
}
