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
		"/usr/",
		"/bin/",
		"/sbin/",
		"/lib/",
		"/lib64/",
		"/opt/",
		"/snap/",
		"/nix/store/",
		"/var/lib/flatpak/",
		"c:/windows/",
		"c:/program files/",
		"c:/program files (x86)/",
	}
	for _, root := range roots {
		if strings.HasPrefix(path, root) {
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
		isServiceLikeContext(p) &&
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
	// Listener with active clients AND outbound connections = proxy shape.
	if c.InboundTotal > 0 && c.OutExternal > 0 {
		return true
	}
	// Very high external fan-out for a benign process.
	if c.OutExternal >= 15 {
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

func isServiceLikeContext(p *ProcessInfo) bool {
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
