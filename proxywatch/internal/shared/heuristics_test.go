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

func TestIsKnownNetworkActiveProcess(t *testing.T) {
	cases := []struct {
		desc    string
		name    string
		path    string
		cmdline string
		want    bool
	}{
		// VPN daemons.
		{"openvpn", "openvpn", "", "", true},
		{"tailscaled", "tailscaled", "", "", true},
		{"cloudflared", "cloudflared", "", "", true},
		// VPN path pattern.
		{"pia path", "daemon", "/Applications/PIAVPN/bin/daemon", "", true},

		// IDE / editor network services.
		{"vscode by name", "code", "", "", true},
		{"cursor", "cursor", "", "", true},
		{"vscode path", "runtime-helper", "/usr/share/code/helpers/x", "", true},

		// Time/update/package services.
		{"systemd-timesyncd", "systemd-timesyncd", "", "", true},
		{"snapd", "snapd", "", "", true},

		// Container runtimes.
		{"dockerd", "dockerd", "", "", true},
		{"containerd", "containerd", "", "", true},

		// Monitoring / observability.
		{"datadog-agent", "datadog-agent", "", "", true},
		{"otelcol", "otelcol", "", "", true},

		// Backup / sync.
		{"restic", "restic", "", "", true},
		{"syncthing", "syncthing", "", "", true},

		// Updaters.
		{"crashpad prefix match", "crashpad_handler", "", "", true},
		{"googleupdate prefix", "googleupdate", "", "", true},
		{"generic autoupdate substring", "my-autoupdater", "", "", true},

		// Enterprise / EDR.
		{"falcon-sensor", "falcon-sensor", "", "", true},
		{"osqueryd", "osqueryd", "", "", true},

		// Desktop apps.
		{"slack", "slack", "", "", true},
		{"discord", "discord", "", "", true},

		// Browsers.
		{"chrome", "chrome", "", "", true},
		{"firefox", "firefox", "", "", true},
		{"msedgewebview prefix", "msedgewebview2", "", "", true},

		// Electron renderer detection via cmdline.
		{"electron renderer", "some-helper", "", "node --type=renderer", true},
		{"electron gpu-process", "some-helper", "", "chrome --type=gpu-process foo", true},

		// Dev server patterns in cmdline.
		{"python http.server", "python3", "", "python3 -m http.server 8000", true},
		{"webpack-dev-server", "node", "", "node webpack-dev-server", true},
		{"rails server", "ruby", "", "bin/ruby rails server", true},

		// Windows Store apps.
		{"windowsapps path", "someapp", `C:\Program Files\WindowsApps\foo\someapp.exe`, "", true},
		{"onedrive name", "onedrive", "", "", true},

		// Vendor path patterns.
		{"sentinelone path", "agent", `/opt/sentinelone/bin/agent`, "", true},

		// Negatives.
		{"unknown process", "totallyrandom", "/tmp/foo", "", false},
		{"empty everything", "", "", "", false},
	}
	for _, tc := range cases {
		p := &ProcessInfo{Name: tc.name, ExePath: tc.path, CmdLine: tc.cmdline}
		if got := IsKnownNetworkActiveProcess(p); got != tc.want {
			t.Errorf("%s: IsKnownNetworkActiveProcess(name=%q, path=%q, cmdline=%q) = %v, want %v",
				tc.desc, tc.name, tc.path, tc.cmdline, got, tc.want)
		}
	}
	if IsKnownNetworkActiveProcess(nil) {
		t.Errorf("IsKnownNetworkActiveProcess(nil) = true, want false")
	}
}

func TestIsInjectionTargetProcess(t *testing.T) {
	positive := []string{
		"explorer.exe", "explorer",
		"svchost.exe", "svchost",
		"rundll32", "dllhost.exe",
		"regsvr32", "msiexec.exe",
		"werfault", "searchindexer.exe",
		"spoolsv", "lsass.exe", "csrss", "winlogon.exe",
		"taskhost", "taskhostw.exe",
	}
	negative := []string{
		"chrome.exe", "notepad.exe", "powershell.exe", "", "randomprocess",
	}
	for _, n := range positive {
		if !IsInjectionTargetProcess(&ProcessInfo{Name: n}) {
			t.Errorf("IsInjectionTargetProcess(%q) = false, want true", n)
		}
	}
	for _, n := range negative {
		if IsInjectionTargetProcess(&ProcessInfo{Name: n}) {
			t.Errorf("IsInjectionTargetProcess(%q) = true, want false", n)
		}
	}
	if IsInjectionTargetProcess(nil) {
		t.Errorf("IsInjectionTargetProcess(nil) = true, want false")
	}
}

func TestIsLikelyBenignBeacon(t *testing.T) {
	// Must pass IsLikelyBenignControlClient AND not live in a staging dir.
	cases := []struct {
		desc string
		path string
		want bool
	}{
		{"usr/bin trusted", "/usr/bin/curl", true},
		{"Program Files trusted", `C:\Program Files\Microsoft\Edge\msedge.exe`, true},
		// Trust-path match but then rejected via the blacklist pattern.
		{"/tmp/ excluded", "/tmp/stager", false},
		{"/downloads/ excluded", `C:\Users\ops\Downloads\beacon.exe`, false},
		{"AppData\\Local\\Temp excluded", `C:\Users\ops\AppData\Local\Temp\agent.exe`, false},
		// Untrusted path → false via IsLikelyBenignControlClient.
		{"unknown path", "/opt/attacker/c2", false},
		// Empty path → false.
		{"empty", "", false},
	}
	for _, tc := range cases {
		p := &ProcessInfo{ExePath: tc.path}
		if got := IsLikelyBenignBeacon(p); got != tc.want {
			t.Errorf("%s: IsLikelyBenignBeacon(%q) = %v, want %v",
				tc.desc, tc.path, got, tc.want)
		}
	}
	if IsLikelyBenignBeacon(nil) {
		t.Errorf("IsLikelyBenignBeacon(nil) = true, want false")
	}
}

func TestHasProxyFlags(t *testing.T) {
	positive := []string{
		"some-tool --socks 1080",
		"chisel client --socks5 :1080 server:8080",
		"revsocks --proxy 10.0.0.1:8080",
		"foo --listen 0.0.0.0:8443",
		"agent --reverse --tunnel",
		"curl --socks5 127.0.0.1:1080 https://example.com",
		"x -d 1080",
		"connect socks5://127.0.0.1:1080",
		"y --pipe \\\\.\\pipe\\foo",
	}
	negative := []string{
		"",
		"curl https://example.com",
		"/usr/bin/python3 server.py",
		"some tool without such flags",
	}
	for _, cl := range positive {
		if !HasProxyFlags(cl) {
			t.Errorf("HasProxyFlags(%q) = false, want true", cl)
		}
	}
	for _, cl := range negative {
		if HasProxyFlags(cl) {
			t.Errorf("HasProxyFlags(%q) = true, want false", cl)
		}
	}
}
