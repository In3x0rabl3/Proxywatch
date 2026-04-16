package shared

import "strings"

// IsLikelyBenignBeacon heuristically skips known-legit updater/AV beacons.
func IsLikelyBenignBeacon(p *ProcessInfo) bool {
	if p == nil {
		return false
	}
	if !IsLikelyBenignControlClient(p) {
		return false
	}
	path := NormalizeExePath(p.ExePath)
	if path == "" {
		return false
	}
	if strings.Contains(path, "/tmp/") ||
		strings.Contains(path, "/var/tmp/") ||
		strings.Contains(path, "/downloads/") ||
		strings.Contains(path, "/appdata/local/temp/") {
		return false
	}
	return true
}

func IsLikelyBenignControlClient(p *ProcessInfo) bool {
	if p == nil {
		return false
	}
	path := NormalizeExePath(p.ExePath)
	if path == "" {
		return false
	}

	roots := []string{
		// Package-manager-controlled paths — only root/package manager writes here.
		"/usr/",
		"/bin/",
		"/sbin/",
		"/lib/",
		"/lib64/",
		"/snap/",
		"/nix/store/",
		"/var/lib/flatpak/",
		// /opt/ is NOT trusted — anyone with sudo can install C2 there.
		// Legitimate /opt/ apps rely on outbound signal suppression or whitelisting.
		"c:/windows/",
		"c:/program files/",
		"c:/program files (x86)/",
		"c:/program files/windowsapps/",
	}
	// Modern Electron/vendor apps install to AppData\Local\Programs\ (Slack, VS Code,
	// Discord, Drata, etc.). These are signed vendor installations, not user-writable
	// in the malware sense. Only the Programs subdirectory qualifies — raw AppData does not.
	userLocalPrograms := []string{
		"/appdata/local/programs/",
		"/appdata/local/slack/",
		"/appdata/local/discord/",
		"/appdata/local/microsoft/",
	}
	for _, root := range roots {
		if strings.HasPrefix(path, root) {
			return true
		}
	}
	for _, root := range userLocalPrograms {
		if strings.Contains(path, root) {
			return true
		}
	}

	// IDE extension binaries are user-installed via verified marketplaces and
	// maintain long-lived connections to their vendor servers (which look like
	// C2 sessions). Treat these as benign control clients.
	if isIDEExtensionBinary(path) {
		return true
	}

	// Homebrew on Linux installs to the user's home directory.
	if strings.Contains(path, "/linuxbrew/") || strings.Contains(path, "/.linuxbrew/") {
		return true
	}

	// Some trusted Windows services ship in ProgramData vendor paths.
	// Treat those as benign only when the vendor path segment aligns with
	// publisher metadata and the process runs in a service-like security context.
	if strings.HasPrefix(path, "c:/programdata/") &&
		IsServiceLikeContext(p) &&
		programDataVendorMatchesCompany(path, p.Company) {
		return true
	}

	// Some trusted user-scoped clients install under AppData vendor folders.
	// Treat those as benign only when the vendor folder aligns with publisher metadata.
	if userAppDataVendorMatchesCompany(path, p.Company) {
		return true
	}

	return false
}

// BenignOverriddenByBehavior returns true when a process classified as benign
// by path/vendor heuristics exhibits network behavior anomalous enough to
// warrant re-scoring. This prevents compromised legitimate processes from
// being fully suppressed by the benign filter.
func BenignOverriddenByBehavior(c *Candidate) bool {
	if c == nil || c.Proc == nil {
		return false
	}
	// Known network-active processes that naturally maintain external
	// connections (VPNs, IDEs, location services, package managers, etc.).
	// These should never have benign overridden just for having connections.
	if IsKnownNetworkActiveProcess(c.Proc) {
		return false
	}
	// Injection-target system processes (svchost, explorer, rundll32, etc.)
	// running as SYSTEM from system paths that connect to their vendor's
	// infrastructure are expected behavior — not injection.
	injectionTarget := IsInjectionTargetProcess(c.Proc)
	injectionTargetTrusted := injectionTarget &&
		IsServiceLikeContext(c.Proc) &&
		c.OutExternal <= 5 &&
		c.OutInternal <= 2
	// Injection target NOT running in a service context (e.g. svchost as
	// a regular user) is always suspicious — indicates process injection
	// or masquerading.
	if injectionTarget && !IsServiceLikeContext(c.Proc) {
		return true
	}
	// Injection target with internal connections is suspicious — these
	// processes should not be reaching out to other internal hosts.
	if injectionTarget && c.OutInternal > 0 && !injectionTargetTrusted {
		return true
	}
	// Trusted injection targets in service context with minimal connections
	// are expected (svchost SYSTEM → Microsoft, etc.). Skip all remaining checks.
	if injectionTargetTrusted {
		return false
	}
	// Listener with active clients AND outbound connections = proxy shape.
	if c.InboundTotal > 0 && c.OutExternal > 0 {
		return true
	}
	// High external fan-out for a benign process.
	if c.OutExternal >= 10 {
		return true
	}
	// Injection target with external connections outside trusted context.
	if c.OutExternal > 0 && injectionTarget {
		return true
	}
	// Delegated egress with strong evidence.
	if c.DelegatedEgress && c.DelegatedStrong {
		return true
	}
	// Proxy-like command-line flags in a benign binary.
	if HasProxyFlags(c.Proc.CmdLine) {
		return true
	}
	// Raw socket usage in a benign binary — indicates packet crafting.
	if c.RawSocket {
		return true
	}
	// Repeated short-lived connections to the same target — callback pattern.
	if c.OutShortLived >= 2 && c.OutExternal > 0 {
		return true
	}
	return false
}

// IsKnownNetworkActiveProcess returns true for processes that naturally
// maintain external connections as part of their normal operation.
// These should not have their benign status overridden.
func IsKnownNetworkActiveProcess(p *ProcessInfo) bool {
	if p == nil {
		return false
	}
	name := strings.ToLower(strings.TrimSpace(p.Name))
	path := NormalizeExePath(p.ExePath)

	// VPN daemons — maintain persistent tunnels to external servers.
	vpnNames := []string{
		"pia-daemon", "openvpn", "wireguard", "wireguard-go",
		"nordvpnd", "expressvpn", "mullvad-daemon", "tailscaled",
		"wg-quick", "openconnect", "vpnkit",
		"cloudflared", "warp-svc", "zerotier-one",
		"globalprotect", "anyconnect", "vpnagent", "forticlient",
	}
	for _, v := range vpnNames {
		if name == v {
			return true
		}
	}
	// VPN path patterns.
	vpnPaths := []string{"/piavpn/", "/nordvpn/", "/expressvpn/", "/mullvad/", "/tailscale/", "/cloudflare/", "/zerotier/"}
	for _, vp := range vpnPaths {
		if strings.Contains(path, vp) {
			return true
		}
	}

	// IDE/editor network services — talk to extension marketplaces, telemetry, AI.
	ideNames := []string{
		"code", "code-insiders", "codium", "vscodium",
		"cursor", "zed", "sublime_text", "atom",
	}
	for _, ide := range ideNames {
		if name == ide {
			return true
		}
	}
	if strings.Contains(path, "/code/") || strings.Contains(path, "/vscode/") {
		return true
	}

	// Location/time/update services — query external APIs.
	svcNames := []string{
		"geoclue", "geoip", "ntpd", "chronyd", "systemd-timesyncd",
		"packagekitd", "gnome-software", "snapd", "flatpak",
		"unattended-upgrade", "apt", "dnf", "yum", "pacman",
		"NetworkManager", "networkmanager", "wpa_supplicant",
		"ModemManager", "avahi-daemon",
	}
	for _, svc := range svcNames {
		if strings.EqualFold(name, svc) {
			return true
		}
	}

	// Container runtimes — maintain connections to registries and orchestrators.
	containerNames := []string{
		"dockerd", "docker", "containerd", "containerd-shim",
		"containerd-shim-runc-v2", "kubelet", "kube-proxy",
		"crio", "podman",
	}
	for _, c := range containerNames {
		if name == c {
			return true
		}
	}

	// Monitoring/observability agents — report telemetry to external collectors.
	monitorNames := []string{
		"datadog-agent", "dd-agent", "newrelic-infra", "newrelic-daemon",
		"splunkd", "splunkforwarder", "telegraf", "grafana-agent",
		"node_exporter", "otelcol", "filebeat", "metricbeat",
		"fluentd", "fluent-bit", "zabbix_agentd", "nagios-nrpe",
		"prometheus",
	}
	for _, m := range monitorNames {
		if name == m {
			return true
		}
	}

	// Backup agents — stream data to external storage.
	backupNames := []string{
		"bztransmit", "crashplanservice", "carboniteservice",
		"veeamagent", "duplicati", "restic", "borg", "borgbackup",
	}
	for _, b := range backupNames {
		if name == b {
			return true
		}
	}

	// Auto-updaters and crash reporters — cycle reconnects to vendor CDNs
	// and look beacon-like. Common FP source on desktop systems.
	updaterNames := []string{
		"crashpad_handler", "breakpad", "crashreporter",
		"squirrel", "squirrelupdate", "update", "updater",
		"googleupdate", "googleupdater", "googlesoftwareupdate", "googlesoftwareupdateagent",
		"googlesoftwareupdatedaemon",
		"msupdate", "msupdatesrv", "microsoftautoupdate", "microsoft autoupdate",
		"macupdater", "sparkle", "autoupdate", "autoupdater",
		"adobearm", "armsvc", "acrotray", "acrocef",
		"jucheck", "jusched", "javaupdater",
		"mozillamaintenance", "mozillaupdate",
		"edgeupdate", "microsoftedgeupdate", "microsoftedgeupdatecore",
		"brave_update", "brave-update",
		"zoomautoupdater",
		"dockerupdater", "com.docker.updater",
		"1passwordupdater",
	}
	for _, u := range updaterNames {
		if name == u {
			return true
		}
	}
	if strings.HasPrefix(name, "googleupdate") ||
		strings.HasPrefix(name, "msedgeupdate") ||
		strings.HasPrefix(name, "microsoftedgeupdate") ||
		strings.HasPrefix(name, "sparkle") ||
		strings.Contains(name, "crashpad") ||
		strings.Contains(name, "autoupdate") {
		return true
	}

	// Windows Defender and built-in security services.
	if strings.HasPrefix(name, "mpdefender") ||
		strings.HasPrefix(name, "msmpeng") ||
		name == "securityhealthservice" ||
		name == "securityhealthsystray" ||
		name == "windowsdefender" {
		return true
	}

	// Enterprise management/EDR — maintain persistent C&C to their own cloud.
	edrNames := []string{
		"intuneclient", "ccmexec",
		"falcon-sensor", "csfalconservice",
		"sentinelagent", "cybereason",
		"ossec-agentd", "osqueryd",
		"drata-agent", "kolide-agent", "vanta-agent",
		"jamf", "kandji", "mosyle",
	}
	for _, e := range edrNames {
		if name == e {
			return true
		}
	}

	// Desktop apps with persistent connections (Electron and native).
	desktopNames := []string{
		"discord", "slack", "teams", "msteams", "teams.exe",
		"spotify", "zoom", "zoomit", "signal-desktop", "telegram-desktop",
		"keybase", "element-desktop",
		"1password", "bitwarden",
	}
	for _, d := range desktopNames {
		if name == d {
			return true
		}
	}

	// Cloud sync/storage agents.
	syncNames := []string{
		"dropbox", "nextcloud", "syncthing", "rclone", "megasync",
	}
	for _, s := range syncNames {
		if name == s {
			return true
		}
	}

	// Developer tools — talk to registries, APIs, remote hosts.
	devNames := []string{
		"gh", "git-remote-https", "git-remote-http",
		"docker-compose", "kubectl", "helm", "terraform", "terragrunt", "pulumi", "ansible", "ansible-playbook",
		"copilot-agent", "claude",
		// Cloud/SaaS CLIs — sustained TLS to cloud control planes is normal.
		"aws", "aws-vault", "gcloud", "gsutil", "bq", "az", "doctl",
		"oci", "ibmcloud", "fly", "flyctl", "railway", "heroku", "vercel", "netlify",
		"s3cmd", "rclone",
		// Package managers / language toolchains — external registries.
		"apt-get", "apt", "dnf", "yum", "pacman", "zypper", "apk",
		"npm", "pnpm", "yarn", "bun", "pip", "pip3", "pipx", "poetry", "uv",
		"cargo", "rustup", "go", "gobuild", "mvn", "gradle", "sbt",
		"composer", "gem", "bundle", "bundler",
		"brew", "port",
		// Language server helpers — LSPs typically fetch symbol data externally.
		"rust-analyzer", "gopls", "pyright", "pylance", "pylance-language-server",
		"typescript-language-server", "tsserver", "vscode-json-languageserver",
		"vscode-html-languageserver", "vscode-css-languageserver",
		"clangd", "solargraph", "jdtls", "lua-language-server",
		"jetbrains-toolbox", "fleet",
	}
	for _, d := range devNames {
		if name == d {
			return true
		}
	}

	// Browser processes and embedded browser runtimes — naturally high
	// external connection count.
	browsers := []string{
		"chrome", "chromium", "firefox", "brave", "vivaldi",
		"opera", "edge", "msedge", "safari",
	}
	for _, b := range browsers {
		if name == b {
			return true
		}
	}
	// WebView and browser-embedded runtimes used by desktop apps.
	if strings.HasPrefix(name, "msedgewebview") ||
		strings.HasPrefix(name, "cefsharp") ||
		strings.Contains(name, "webview") {
		return true
	}

	// Electron helper processes — renderers, GPU, utility subprocesses.
	cmdline := strings.ToLower(p.CmdLine)
	if strings.Contains(cmdline, "--type=renderer") ||
		strings.Contains(cmdline, "--type=gpu-process") ||
		strings.Contains(cmdline, "--type=utility") {
		return true
	}

	// Windows system services that naturally make external connections.
	winSvcNames := []string{
		"svchost", "svchost.exe",
		"lsass", "lsass.exe",
		"services", "services.exe",
		"sppsvc", "sppsvc.exe",
		"smartscreen", "smartscreen.exe",
		"dashost", "dashost.exe",
		"sihost", "sihost.exe",
		"taskhostw", "taskhostw.exe",
		"runtimebroker", "runtimebroker.exe",
		"backgroundtaskhost", "backgroundtaskhost.exe",
		"lockapp", "lockapp.exe",
		"searchhost", "searchhost.exe",
		"textinputhost", "textinputhost.exe",
		"wuauclt", "wuauclt.exe",
		"usoclient", "usoclient.exe",
		"windowsupdate",
	}
	for _, ws := range winSvcNames {
		if name == ws {
			// Only trusted when running in service/system context.
			// User-context copies are suspicious (injection/masquerade).
			if IsServiceLikeContext(p) || !IsInjectionTargetProcess(p) {
				return true
			}
		}
	}

	// Windows Store apps and Microsoft start/feed/widget providers.
	if strings.Contains(path, "/windowsapps/") ||
		strings.Contains(name, "startfeedprovider") ||
		strings.Contains(name, "widgetservice") ||
		strings.Contains(name, "searchhost") {
		return true
	}

	// OneDrive and cloud sync services.
	if strings.Contains(name, "onedrive") ||
		strings.Contains(path, "/onedrive/") {
		return true
	}

	// Developer server commands — processes running known dev server modules
	// are listeners, not C2. Check cmdline for common patterns.
	devServerPatterns := []string{
		"http.server",      // python3 -m http.server
		"simplehttpserver", // python2 -m SimpleHTTPServer
		"serve",            // npx serve, python -m http.server alias
		"webpack-dev-server",
		"webpack serve",
		"vite",
		"next dev",
		"ng serve",     // Angular
		"flask run",    // Flask
		"uvicorn",      // ASGI server
		"gunicorn",     // WSGI server
		"rails server", // Ruby on Rails
		"php -s",       // PHP built-in server
		"live-server",
	}
	for _, pat := range devServerPatterns {
		if strings.Contains(cmdline, pat) {
			return true
		}
	}

	// Path-based patterns for vendor-specific installation directories.
	vendorPaths := []string{
		"/docker/", "/containerd/", "/kubernetes/",
		"/datadog/", "/newrelic/", "/splunk/",
		"/crowdstrike/", "/sentinelone/", "/falcon/",
		"/dropbox/", "/discord/", "/slack/", "/spotify/",
		"/1password/", "/bitwarden/", "/syncthing/",
		"/zoom/", "/drata/", "/vanta/", "/kolide/",
		"/jamf/", "/kandji/", "/zscaler/", "/netskope/",
		"/fortinet/", "/sophos/", "/trellix/",
	}
	for _, vp := range vendorPaths {
		if strings.Contains(path, vp) {
			return true
		}
	}

	return false
}

// IsKnownVendorProcess returns true for processes from recognized software
// vendors installed in trusted paths. These processes get accelerated warmup
// thresholds since their vendor identity provides additional confidence.
func IsKnownVendorProcess(p *ProcessInfo) bool {
	if p == nil {
		return false
	}
	if !IsLikelyBenignControlClient(p) {
		return false
	}
	// Trusted path alone is sufficient for vendor recognition. Installing to
	// Program Files, /usr/, /opt/ etc. requires admin/root privileges.
	// The company metadata check was too strict — many legitimate vendors
	// (FileCloud, Duo) don't populate the PE Company field.
	return true
}

// IsKnownUpdaterProcess returns true for processes that are auto-updaters or
// crash reporters. This is a strict subset of IsKnownNetworkActiveProcess —
// only names whose *sole* networking purpose is periodic check-in with a
// vendor CDN. Used by the vendor-update-cadence FP rule to demote beacon-like
// telemetry that lacks any pivot/tunnel corroboration.
//
// A process only qualifies if it ALSO passes IsLikelyBenignControlClient
// (i.e. runs from an admin-writable path). A process named "crashpad_handler"
// out of /tmp does NOT qualify — attackers can rename binaries.
func IsKnownUpdaterProcess(p *ProcessInfo) bool {
	if p == nil {
		return false
	}
	if !IsLikelyBenignControlClient(p) {
		return false
	}
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p.Name), ".exe"))
	if name == "" {
		return false
	}
	updaterExact := map[string]bool{
		"crashpad_handler": true, "breakpad": true, "crashreporter": true,
		"squirrel": true, "squirrelupdate": true,
		"googleupdate": true, "googleupdater": true, "googlesoftwareupdate": true,
		"googlesoftwareupdateagent": true, "googlesoftwareupdatedaemon": true,
		"msupdate": true, "msupdatesrv": true,
		"microsoftautoupdate": true, "microsoft autoupdate": true,
		"macupdater": true, "sparkle": true, "autoupdate": true, "autoupdater": true,
		"adobearm": true, "armsvc": true, "acrotray": true, "acrocef": true,
		"jucheck": true, "jusched": true, "javaupdater": true,
		"mozillamaintenance": true, "mozillaupdate": true,
		"edgeupdate": true, "microsoftedgeupdate": true, "microsoftedgeupdatecore": true,
		"brave_update": true, "brave-update": true,
		"zoomautoupdater": true,
		"dockerupdater":   true, "com.docker.updater": true,
		"1passwordupdater": true,
	}
	if updaterExact[name] {
		return true
	}
	if strings.HasPrefix(name, "googleupdate") ||
		strings.HasPrefix(name, "msedgeupdate") ||
		strings.HasPrefix(name, "microsoftedgeupdate") ||
		strings.HasPrefix(name, "sparkle") ||
		strings.Contains(name, "crashpad") ||
		strings.Contains(name, "autoupdate") {
		return true
	}
	return false
}

// VendorUpdateCadenceReason is the single reason string appended to
// c.Reasons when the vendor-update-cadence rule fires. Exported so the
// debug API and tests can match on it without string drift.
const VendorUpdateCadenceReason = "vendor-update-suppressed"

// vendorUpdateDecisiveSignals are signals whose presence always blocks the
// vendor-update-cadence demotion. Kept in sync with decisiveFPSignals in
// output/debug_api.go — the two lists must agree on what "decisive" means.
var vendorUpdateDecisiveSignals = map[string]bool{
	"pivot-ssh-tunnel-flags":      true,
	"pivot-named-pipe-c2-pattern": true,
	"beacon-pattern-confirmed":    true,
	"strong-control-session":      true,
	"persistent-control":          true,
	"tunnel":                      true,
	"tunneling":                   true,
	"control-pivot":               true,
	"lateral-pivot-shape":         true,
}

// vendorUpdateCorroborators are signals that, if any are present, block
// demotion because they indicate suspicious behavior beyond mere periodic
// check-in (internal fanout, lateral movement, live named pipes, etc.).
var vendorUpdateCorroborators = map[string]bool{
	"internal-fanout":      true,
	"internal-lateral":     true,
	"lateral-host-sweep":   true,
	"lateral-wide-recon":   true,
	"lateral-pivot-shape":  true,
	"child-tunnel":         true,
	"smb-pipe":             true,
	"raw-socket":           true,
	"cmdline-proxy-flags":  true,
	"suspicious-exe-path":  true,
	"proxy-library-loaded": true,
}

// ApplyVendorUpdateSuppression runs the vendor-update-cadence FP rule.
// Returns true if the candidate's role was demoted to "outbound".
//
// Rule: if the process matches IsKnownUpdaterProcess AND currently has a
// beacon-ish role AND has no decisive or corroborating signals, demote to
// "outbound" and append VendorUpdateCadenceReason. Decisive signals (SSH
// tunnel flags, named-pipe C2, confirmed-beacon-pattern, lateral-pivot)
// ALWAYS block demotion — this is the single concession point so we never
// silently suppress a real threat that happens to wear a vendor name.
//
// Named pipes and raw sockets on the live process also block demotion,
// regardless of signal set, since those cannot arise from update traffic.
func ApplyVendorUpdateSuppression(c *Candidate) bool {
	if c == nil || c.Proc == nil {
		return false
	}
	if !IsKnownUpdaterProcess(c.Proc) {
		return false
	}
	// Only act when the current role is control-ish. Leave listener/outbound
	// candidates untouched — nothing to demote.
	if !IsControlRole(c.Role) {
		return false
	}
	if len(c.NamedPipes) > 0 {
		return false
	}
	for _, s := range c.Signals {
		if vendorUpdateDecisiveSignals[s] || vendorUpdateCorroborators[s] {
			return false
		}
	}
	// Require that something beacon-ish actually fired — otherwise this rule
	// has nothing to suppress and we leave the candidate alone.
	sawBeacon := false
	for _, s := range c.Signals {
		if s == "beacon" || s == "beacon-cadence" || s == "beacon-syn-cycle-cadence" {
			sawBeacon = true
			break
		}
	}
	if !sawBeacon {
		return false
	}
	c.Role = "outbound"
	for _, r := range c.Reasons {
		if r == VendorUpdateCadenceReason {
			return true
		}
	}
	c.Reasons = append(c.Reasons, VendorUpdateCadenceReason)
	return true
}

// IsLOLBinProcess returns true for Windows/Linux binaries commonly abused
// for living-off-the-land attacks (download, execute, proxy).
func IsLOLBinProcess(p *ProcessInfo) bool {
	if p == nil {
		return false
	}
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p.Name), ".exe"))
	lolbins := []string{
		"certutil", "bitsadmin", "mshta", "regsvr32", "rundll32",
		"wmic", "msiexec", "forfiles", "pcalua", "cmstp",
		"esentutl", "expand", "extrac32", "hh", "ieexec",
		"installutil", "msbuild", "odbcconf", "replace", "xwizard",
		"csc", "vbc", "jsc", "ilasm",
	}
	for _, l := range lolbins {
		if name == l {
			return true
		}
	}
	return false
}

// IsScriptingEngine returns true for scripting interpreters that can act
// as C2 agents, proxies, or tunnel endpoints when given network access.
func IsScriptingEngine(p *ProcessInfo) bool {
	if p == nil {
		return false
	}
	name := strings.ToLower(strings.TrimSpace(p.Name))
	base := strings.TrimSuffix(name, ".exe")
	engines := []string{
		"python", "python3", "python3.12", "python3.11", "python3.10", "python3.9",
		"powershell", "pwsh",
		"ruby", "perl", "node", "nodejs",
		"php", "lua",
		"cscript", "wscript", "mshta",
		"java", "javaw",
	}
	for _, e := range engines {
		if base == e {
			return true
		}
	}
	return false
}

// isInjectionTargetProcess returns true for Windows system processes that
// are common targets for process injection (explorer, svchost, rundll32, etc.).
func IsInjectionTargetProcess(p *ProcessInfo) bool {
	if p == nil {
		return false
	}
	name := strings.ToLower(strings.TrimSpace(p.Name))
	targets := []string{
		"explorer", "explorer.exe",
		"svchost", "svchost.exe",
		"rundll32", "rundll32.exe",
		"dllhost", "dllhost.exe",
		"regsvr32", "regsvr32.exe",
		"msiexec", "msiexec.exe",
		"werfault", "werfault.exe",
		"searchindexer", "searchindexer.exe",
		"spoolsv", "spoolsv.exe",
		"lsass", "lsass.exe",
		"csrss", "csrss.exe",
		"winlogon", "winlogon.exe",
		"taskhost", "taskhost.exe",
		"taskhostw", "taskhostw.exe",
	}
	for _, t := range targets {
		if name == t {
			return true
		}
	}
	return false
}

// HasProxyFlags returns true if a command line contains proxy/tunnel behavioral
// flags. Only generic protocol and technique indicators are matched — no
// specific tool names are hardcoded.
func HasProxyFlags(cmdline string) bool {
	if cmdline == "" {
		return false
	}
	cmd := strings.ToLower(cmdline)
	flags := []string{
		"--socks", "--socks5", "--socks4",
		"--proxy", "--http-proxy", "--https-proxy",
		"--listen", "--forward", "--reverse",
		"--tunnel", "--relay", "--pipe",
		"-d 1080", "-d 8080", "-l 1080", "-l 8080",
		"socks5://", "socks4://", "socks://",
	}
	for _, f := range flags {
		if strings.Contains(cmd, f) {
			return true
		}
	}
	return false
}

// NormalizeExePath lowercases and normalizes backslashes in an executable path.
func NormalizeExePath(path string) string {
	path = strings.ToLower(strings.TrimSpace(path))
	return strings.ReplaceAll(path, "\\", "/")
}

func IsServiceLikeContext(p *ProcessInfo) bool {
	if p == nil {
		return false
	}
	user := strings.ToLower(strings.TrimSpace(p.UserName))
	integrity := strings.ToLower(strings.TrimSpace(p.Integrity))

	switch integrity {
	case "system", "protected":
		return true
	}

	if strings.Contains(user, "nt authority\\") {
		return true
	}
	if strings.Contains(user, "local service") || strings.Contains(user, "network service") {
		return true
	}
	if strings.HasSuffix(user, "\\system") {
		return true
	}
	return false
}

func programDataVendorMatchesCompany(path, company string) bool {
	const prefix = "c:/programdata/"
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	company = strings.ToLower(strings.TrimSpace(company))
	if company == "" {
		return false
	}

	rel := strings.TrimPrefix(path, prefix)
	slash := strings.IndexByte(rel, '/')
	if slash <= 0 {
		return false
	}
	vendor := strings.TrimSpace(rel[:slash])
	if len(vendor) < 3 {
		return false
	}

	return strings.Contains(company, vendor)
}

// isIDEExtensionBinary returns true if the path resides inside a known IDE
// extension directory. These extensions are installed from verified
// marketplaces and commonly maintain long-lived connections to vendor APIs
// (e.g. Claude Code to Anthropic, Copilot to GitHub) which look like C2
// sessions but are legitimate.
func isIDEExtensionBinary(path string) bool {
	extDirs := []string{
		"/.vscode/extensions/",
		"/.vscode-server/extensions/",
		"/.vscode-insiders/extensions/",
		"/.cursor/extensions/",
		"/.windsurf/extensions/",
		"/.positron/extensions/",
		"/appdata/local/programs/microsoft vs code/",
		"/appdata/local/programs/cursor/",
	}
	for _, dir := range extDirs {
		if strings.Contains(path, dir) {
			return true
		}
	}
	// JetBrains Gateway / remote dev helpers install under .cache/JetBrains
	// or .local/share/JetBrains and keep persistent connections.
	if strings.Contains(path, "/jetbrains/") && (strings.Contains(path, "/.cache/") || strings.Contains(path, "/.local/share/")) {
		return true
	}
	return false
}

func userAppDataVendorMatchesCompany(path, company string) bool {
	company = strings.ToLower(strings.TrimSpace(company))
	if company == "" {
		return false
	}
	if !strings.HasPrefix(path, "c:/users/") {
		return false
	}

	markers := []string{
		"/appdata/local/",
		"/appdata/locallow/",
		"/appdata/roaming/",
	}
	rel := ""
	for _, marker := range markers {
		if idx := strings.Index(path, marker); idx >= 0 {
			rel = path[idx+len(marker):]
			break
		}
	}
	if rel == "" {
		return false
	}

	slash := strings.IndexByte(rel, '/')
	if slash <= 0 {
		return false
	}
	vendor := strings.TrimSpace(rel[:slash])
	if len(vendor) < 3 {
		return false
	}
	switch vendor {
	case "temp", "tmp", "downloads":
		return false
	}
	return strings.Contains(company, vendor)
}
