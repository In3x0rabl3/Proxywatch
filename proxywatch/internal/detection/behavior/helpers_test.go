package behavior

import "testing"

func TestIsLolbinProcess_Behavior(t *testing.T) {
	// Behavior-package variant takes a name string directly (not a
	// *ProcessInfo). Subset of the shared-package variant; needs its own
	// test because the list is maintained here separately.
	positive := []string{
		"certutil", "certutil.exe",
		"bitsadmin", "mshta.exe", "regsvr32", "rundll32.exe",
		"msiexec.exe", "wmic", "cmstp", "installutil.exe",
		"curl.exe", "wget",
	}
	negative := []string{"explorer.exe", "chrome.exe", "", "cmd.exe", "python.exe"}
	for _, n := range positive {
		if !IsLolbinProcess(n) {
			t.Errorf("IsLolbinProcess(%q) = false, want true", n)
		}
	}
	for _, n := range negative {
		if IsLolbinProcess(n) {
			t.Errorf("IsLolbinProcess(%q) = true, want false", n)
		}
	}
}

func TestIsScriptingEngine_Behavior(t *testing.T) {
	positive := []string{
		"powershell", "powershell.exe", "pwsh", "pwsh.exe",
		"python", "python3", "python.exe", "python3.exe",
		"node.exe", "ruby.exe", "perl",
		"cscript.exe", "wscript.exe",
		"java.exe", "javaw.exe",
	}
	negative := []string{"explorer.exe", "svchost.exe", "curl", ""}
	for _, n := range positive {
		if !IsScriptingEngine(n) {
			t.Errorf("IsScriptingEngine(%q) = false, want true", n)
		}
	}
	for _, n := range negative {
		if IsScriptingEngine(n) {
			t.Errorf("IsScriptingEngine(%q) = true, want false", n)
		}
	}
}

func TestIsShell(t *testing.T) {
	positive := []string{
		"bash", "zsh", "sh", "fish", "tcsh", "csh", "dash",
		"cmd.exe", "powershell.exe", "pwsh", "pwsh.exe",
	}
	negative := []string{"python", "explorer.exe", "curl", "", "sh.exe"}
	for _, n := range positive {
		if !IsShell(n) {
			t.Errorf("IsShell(%q) = false, want true", n)
		}
	}
	for _, n := range negative {
		if IsShell(n) {
			t.Errorf("IsShell(%q) = true, want false", n)
		}
	}
}

func TestHasProxyTunnelLibPattern(t *testing.T) {
	cases := []struct {
		base string
		want bool
	}{
		// Positive — must start with "lib" and contain one of the keywords.
		{"libsocks5.so", true},
		{"libsocks.so.1", true},
		{"libproxychains.so.4", true},
		{"libtunnel.so", true},
		{"libtun2socks.so", true},
		{"libtun2.so", true},
		// Negative — libproxy.* is explicitly excluded (system PAC lib).
		{"libproxy.so", false},
		{"libproxy.so.1", false},
		{"libproxy", false},
		// Must start with "lib".
		{"socks5.dll", false},
		{"proxychains.exe", false},
		{"tunnel.so", false},
		// Doesn't contain any keyword.
		{"libc.so.6", false},
		{"libcrypto.so.3", false},
		{"libssl.so", false},
		// Empty.
		{"", false},
	}
	for _, tc := range cases {
		if got := HasProxyTunnelLibPattern(tc.base); got != tc.want {
			t.Errorf("HasProxyTunnelLibPattern(%q) = %v, want %v", tc.base, got, tc.want)
		}
	}
}

func TestIsC2PipeName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		// Known C2 pipe patterns (Sliver / Cobalt Strike style).
		{"msagent_abc123", true},
		{"MSSE-42-server", true},
		{"postex_rundll32", true},
		{"postex_ssh_12345", true},
		{"status_42", true},
		{"mojo.core.8.0", true},
		{"chrome.internal.xyz", true},
		{"gecko.worker.42", true},
		// Legitimate pipes — not C2 patterns.
		{"srvsvc", false},
		{"lsass", false},
		{"wkssvc", false},
		{"spoolss", false},
		{"epmapper", false},
		{"", false},
		// Truncated — needs the full pattern prefix.
		{"msagent", false}, // missing underscore
		{"MSSE", false},    // missing dash
	}
	for _, tc := range cases {
		if got := IsC2PipeName(tc.name); got != tc.want {
			t.Errorf("IsC2PipeName(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
