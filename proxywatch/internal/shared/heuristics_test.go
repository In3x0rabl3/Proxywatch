package shared

import "testing"

func TestIsLOLBinProcess(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		// Canonical LOLBins (.exe optional — telemetry lowercases names).
		{"certutil.exe", true},
		{"certutil", true},
		{"bitsadmin", true},
		{"mshta.exe", true},
		{"regsvr32.exe", true},
		{"rundll32", true},
		{"wmic.exe", true},
		{"msiexec", true},
		{"csc.exe", true},
		{"vbc.exe", true},
		// Not LOLBins.
		{"explorer.exe", false},
		{"chrome.exe", false},
		{"cmd.exe", false}, // cmd itself isn't in the list; it's a shell
		{"", false},
		{"certutil.exe.tmp", false}, // exact match only
	}
	for _, tc := range cases {
		p := &ProcessInfo{Name: tc.name}
		if got := IsLOLBinProcess(p); got != tc.want {
			t.Errorf("IsLOLBinProcess(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
	if IsLOLBinProcess(nil) {
		t.Errorf("IsLOLBinProcess(nil) = true, want false")
	}
}

func TestIsScriptingEngine(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"python.exe", true},
		{"python3", true},
		{"python3.11", true},
		{"powershell.exe", true},
		{"pwsh.exe", true},
		{"pwsh", true},
		{"ruby.exe", true},
		{"node.exe", true},
		{"nodejs", true},
		{"php", true},
		{"lua.exe", true},
		{"cscript.exe", true},
		{"wscript.exe", true},
		{"java.exe", true},
		{"javaw.exe", true},
		// Not scripting engines.
		{"explorer.exe", false},
		{"svchost.exe", false},
		{"", false},
		{"python-custom", false}, // exact match required
	}
	for _, tc := range cases {
		p := &ProcessInfo{Name: tc.name}
		if got := IsScriptingEngine(p); got != tc.want {
			t.Errorf("IsScriptingEngine(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
	if IsScriptingEngine(nil) {
		t.Errorf("IsScriptingEngine(nil) = true, want false")
	}
}

func TestIsLikelyBenignControlClient(t *testing.T) {
	cases := []struct {
		name string
		path string
		want bool
	}{
		// Trusted Linux paths.
		{"usr/bin", "", false}, // empty path → false
		{"curl-like", "/usr/bin/curl", true},
		{"sshd-like", "/usr/sbin/sshd", true},
		{"system lib", "/lib/x86_64-linux-gnu/libc.so.6", true},
		{"snap bundle", "/snap/firefox/current/firefox", true},
		{"nix store", "/nix/store/abc-hello-0.1/bin/hello", true},
		{"linuxbrew", "/home/ops/.linuxbrew/bin/rg", true},
		// /opt is intentionally NOT trusted.
		{"/opt/ rejected", "/opt/attacker/c2", false},
		// Trusted Windows paths (note: NormalizeExePath lowercases + slashes).
		{"windows system32", `C:\Windows\System32\svchost.exe`, true},
		{"Program Files", `C:\Program Files\Microsoft\Edge\msedge.exe`, true},
		{"Program Files x86", `C:\Program Files (x86)\Foo\bar.exe`, true},
		{"AppData Local Programs", `C:\Users\ops\AppData\Local\Programs\Slack\slack.exe`, true},
		{"AppData Local Discord", `C:\Users\ops\AppData\Local\Discord\app.exe`, true},
		// User-writable / malware-staging paths.
		{"Downloads rejected", `C:\Users\ops\Downloads\impl.exe`, false},
		{"Desktop rejected", `C:\Users\ops\Desktop\beacon.exe`, false},
		{"Temp rejected", `/tmp/stager`, false},
		{"raw AppData not enough", `C:\Users\ops\AppData\Local\random.exe`, false},
	}
	for _, tc := range cases {
		p := &ProcessInfo{ExePath: tc.path}
		if got := IsLikelyBenignControlClient(p); got != tc.want {
			t.Errorf("%s: IsLikelyBenignControlClient(%q) = %v, want %v",
				tc.name, tc.path, got, tc.want)
		}
	}
	if IsLikelyBenignControlClient(nil) {
		t.Errorf("IsLikelyBenignControlClient(nil) = true, want false")
	}
}

func TestIsKnownVendorProcess(t *testing.T) {
	// IsKnownVendorProcess is currently `IsLikelyBenignControlClient` with a
	// nil-guard — a compatible alias. Test that the gate actually chains.
	cases := []struct {
		path string
		want bool
	}{
		{`C:\Program Files\Microsoft\Edge\msedge.exe`, true},
		{`/usr/bin/sshd`, true},
		{`C:\Users\ops\Downloads\malware.exe`, false},
		{``, false},
	}
	for _, tc := range cases {
		p := &ProcessInfo{ExePath: tc.path}
		if got := IsKnownVendorProcess(p); got != tc.want {
			t.Errorf("IsKnownVendorProcess(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
	if IsKnownVendorProcess(nil) {
		t.Errorf("IsKnownVendorProcess(nil) = true, want false")
	}
}

func TestIsKnownUpdaterProcess(t *testing.T) {
	// Must pass both the exact-name table AND IsLikelyBenignControlClient.
	cases := []struct {
		desc string
		name string
		path string
		want bool
	}{
		{"updater + trusted path", "GoogleUpdate.exe", `C:\Program Files\Google\Update\GoogleUpdate.exe`, true},
		{"updater + trusted path", "crashpad_handler.exe", `C:\Program Files\Google\Chrome\Application\chrome.exe`, true},
		{"updater + trusted path", "MsUpdate", `C:\Program Files\Microsoft\Update\MsUpdate.exe`, true},
		{"updater + trusted path", "squirrel", `C:\Users\ops\AppData\Local\Programs\foo\Squirrel.exe`, true},

		// Correct name but untrusted path → false (attacker rename).
		{"updater name + user path → false", "crashpad_handler.exe", `C:\Users\ops\Downloads\crashpad_handler.exe`, false},
		// Trusted path but non-updater name → false.
		{"non-updater in trusted path", "chrome.exe", `C:\Program Files\Google\Chrome\Application\chrome.exe`, false},
		// Nil safety.
		{"empty", "", "", false},
	}
	for _, tc := range cases {
		p := &ProcessInfo{Name: tc.name, ExePath: tc.path}
		if got := IsKnownUpdaterProcess(p); got != tc.want {
			t.Errorf("%s: IsKnownUpdaterProcess(name=%q, path=%q) = %v, want %v",
				tc.desc, tc.name, tc.path, got, tc.want)
		}
	}
	if IsKnownUpdaterProcess(nil) {
		t.Errorf("IsKnownUpdaterProcess(nil) = true, want false")
	}
}
