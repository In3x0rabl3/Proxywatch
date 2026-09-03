package behavior

import (
	"strings"

	"proxywatch/internal/shared"
)

// SignalContext holds precomputed values from the detection package that the
// behavior emitters need but cannot compute themselves (to avoid circular deps).
type SignalContext struct {
	ScopedPID   int
	BehaviorKey string
	HostScope   string
}

// IsLolbinProcess checks if a process name is a living-off-the-land binary.
func IsLolbinProcess(name string) bool {
	switch name {
	case "certutil", "certutil.exe",
		"bitsadmin", "bitsadmin.exe",
		"mshta", "mshta.exe",
		"regsvr32", "regsvr32.exe",
		"rundll32", "rundll32.exe",
		"msiexec", "msiexec.exe",
		"wmic", "wmic.exe",
		"cmstp", "cmstp.exe",
		"installutil", "installutil.exe",
		"curl", "curl.exe",
		"wget", "wget.exe":
		return true
	}
	return false
}

// IsScriptingEngine checks if a process is a scripting engine.
func IsScriptingEngine(name string) bool {
	switch name {
	case "powershell", "powershell.exe", "pwsh", "pwsh.exe",
		"python", "python3", "python.exe", "python3.exe",
		"node", "node.exe",
		"ruby", "ruby.exe",
		"perl", "perl.exe",
		"cscript", "cscript.exe",
		"wscript", "wscript.exe",
		"java", "java.exe",
		"javaw", "javaw.exe":
		return true
	}
	return false
}

// IsShell checks if a process name is a shell.
func IsShell(name string) bool {
	switch name {
	case "bash", "zsh", "sh", "fish", "tcsh", "csh", "dash",
		"cmd.exe", "powershell.exe", "pwsh", "pwsh.exe":
		return true
	}
	return false
}

// HasProxyTunnelLibPattern returns true when a library base filename contains
// substrings that indicate proxy, SOCKS, or tunneling functionality.
func HasProxyTunnelLibPattern(base string) bool {
	if base == "" {
		return false
	}
	if !strings.HasPrefix(base, "lib") {
		return false
	}
	// Exclude libproxy.so — it's a system PAC/WPAD library loaded by many
	// legitimate apps (geoclue, gnome-settings, etc.), not a SOCKS proxy.
	if strings.HasPrefix(base, "libproxy.") || base == "libproxy" {
		return false
	}
	keywords := []string{"socks", "proxychains", "tunnel", "tun2"}
	for _, kw := range keywords {
		if strings.Contains(base, kw) {
			return true
		}
	}
	return false
}

// IsC2PipeName checks if a named pipe name matches known C2 patterns.
func IsC2PipeName(name string) bool {
	suspiciousPatterns := []string{
		"msagent_", "MSSE-", "postex_", "postex_ssh",
		"status_", "mojo.", "chrome.", "gecko.",
	}
	for _, pattern := range suspiciousPatterns {
		if len(name) >= len(pattern) && name[:len(pattern)] == pattern {
			return true
		}
	}
	return false
}

// IsSuspiciousRandomPipeName returns true for named pipes that look
// randomly generated — short alphanumeric strings with no recognizable
// vendor prefix. Covers custom Mythic SMB profiles and any operator-
// renamed implant pipes the fixed IsC2PipeName list can't catch.
// Shadow-only: the positive set is broad, so it feeds a new signal
// that doesn't vote in role inference yet.
func IsSuspiciousRandomPipeName(name string) bool {
	base := name
	// Strip the windows \\.\pipe\ prefix if present.
	if i := strings.LastIndex(base, `\`); i >= 0 {
		base = base[i+1:]
	}
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	if base == "" {
		return false
	}
	// Already flagged by the hard pattern list — don't double-count.
	if IsC2PipeName(base) {
		return false
	}
	// Known vendor/system pipe prefixes that we want to whitelist.
	benignPrefixes := []string{
		"anonpipe", "lsass", "spoolss", "srvsvc", "wkssvc", "samr",
		"netlogon", "eventlog", "scerpc", "atsvc", "epmapper",
		"mojo.", "chrome_", "msedge_", "slack_", "teams_",
		"docker_engine", "pipewire", "openssh-ssh", "git-lfs-",
		"vs_", "vscode_", "cursor_", "jetbrains_",
	}
	low := strings.ToLower(base)
	for _, pfx := range benignPrefixes {
		if strings.HasPrefix(low, pfx) {
			return false
		}
	}
	// Short base names are the C2 shape: 6–16 chars, alphanumeric only,
	// mixed case or mixed with digits. Most legitimate pipes are longer
	// and use hyphens/underscores/periods or clear vendor prefixes.
	if len(base) < 6 || len(base) > 16 {
		return false
	}
	var hasDigit, hasAlpha, hasSep bool
	for _, r := range base {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			hasAlpha = true
		case r == '-' || r == '_' || r == '.':
			hasSep = true
		default:
			return false
		}
	}
	// Only flag strings that mix letters+digits and have no separators —
	// classic random-token shape. Pure-alpha names like "WellKnownPipe"
	// and separator-containing names like "mojo.1234" are spared.
	return hasAlpha && hasDigit && !hasSep
}

// PrepareCommonState computes shared intermediate values used across multiple
// role emitters. Called once per candidate to avoid redundant work.
type CommonState struct {
	HasNonStandardPort       bool
	AllHTTPPorts             bool
	InternalPorts            map[int]int
	InternalHosts            map[string]bool
	NonLoopbackInternalCount int
	ExtPortCounts            map[int]int
	ExtHosts                 map[string]bool
	HasEncodingInCmdLine     bool
	HasCryptoLib             bool
	HasProxyLib              bool
	NameLower                string
	IsLolbin                 bool
	IsScripting              bool
	RareParentNetwork        bool
	IOPerSec                 float64
	TotalIO                  uint64
	// ASN resolution — computed once, shared across signal emitters.
	ASNOrgs    []string
	ASNAligned bool // vendor company matches destination ASN
	ASNIsCDN   bool // destination is a CDN
}

// PrepareCommonState builds the shared intermediate values from a candidate.
func PrepareCommonState(c *shared.Candidate, ctx SignalContext) CommonState {
	p := c.Proc
	totalIO := p.IOReadBytes + p.IOWriteBytes

	hasNonStandardPort := false
	allHTTPPorts := true
	for _, conn := range c.Conns {
		if conn.RemotePort > 0 && !shared.IsInternalIP(conn.RemoteAddress) && !shared.IsLoopbackIP(conn.RemoteAddress) {
			if conn.RemotePort != 443 && conn.RemotePort != 80 && conn.RemotePort != 8080 && conn.RemotePort != 8443 {
				hasNonStandardPort = true
				allHTTPPorts = false
			}
		}
	}

	// Build listener port set for filtering inbound accepted connections.
	listenerPorts := make(map[int]bool)
	for _, l := range c.Listeners {
		listenerPorts[l.LocalPort] = true
	}

	internalPorts := make(map[int]int)
	internalHosts := make(map[string]bool)
	nonLoopbackInternal := 0
	for _, conn := range c.Conns {
		if shared.IsInternalIP(conn.RemoteAddress) && conn.RemotePort > 0 {
			internalPorts[conn.RemotePort]++
			internalHosts[conn.RemoteAddress] = true
			// Only count OUTBOUND non-loopback internal connections.
			// Exclude connections accepted on listener ports (inbound clients).
			if !shared.IsLoopbackIP(conn.RemoteAddress) && !listenerPorts[conn.LocalPort] {
				nonLoopbackInternal++
			}
		}
	}

	extPortCounts := make(map[int]int)
	extHosts := make(map[string]bool)
	for _, conn := range c.Conns {
		if !shared.IsInternalIP(conn.RemoteAddress) && !shared.IsLoopbackIP(conn.RemoteAddress) && conn.RemotePort > 0 {
			extPortCounts[conn.RemotePort]++
			extHosts[conn.RemoteAddress] = true
		}
	}

	hasEncodingInCmdLine := false
	if p.CmdLine != "" {
		cmdLower := strings.ToLower(p.CmdLine)
		hasEncodingInCmdLine = strings.Contains(cmdLower, "-enc") ||
			strings.Contains(cmdLower, "-encodedcommand") ||
			strings.Contains(cmdLower, "base64") ||
			strings.Contains(cmdLower, "frombase64")
	}

	hasCryptoLib := false
	hasProxyLib := false
	for _, lib := range p.LoadedLibs {
		base := strings.ToLower(lib)
		if idx := strings.LastIndexAny(base, "/\\"); idx >= 0 {
			base = base[idx+1:]
		}
		if strings.Contains(base, "crypto") || strings.Contains(base, "ssl") || strings.Contains(base, "tls") {
			hasCryptoLib = true
		}
		if HasProxyTunnelLibPattern(base) {
			hasProxyLib = true
		}
	}

	nameLower := strings.ToLower(p.Name)
	isLolbin := IsLolbinProcess(nameLower)
	isScripting := IsScriptingEngine(nameLower)

	parentKey := ""
	if p.ParentPid > 0 {
		parentKey = ctx.HostScope + "|" + strings.ToLower(p.ExePath)
	}
	rareParentNetwork := false
	if parentKey != "" {
		fullKey := parentKey + "|" + strings.ToLower(p.Name)
		rareParentNetwork = shared.ParentChildFreq[fullKey] <= 1
	}

	var ioPerSec float64
	if c.SeenSeconds > 0 {
		ioPerSec = float64(totalIO) / float64(c.SeenSeconds)
	}

	// ASN resolution — compute once for all signal emitters.
	var asnOrgs []string
	var asnAligned, asnIsCDN bool
	if c.OutExternal > 0 {
		asnOrgs, _, _ = shared.ResolveExternalASNOrgs(c.Conns)
		if len(asnOrgs) > 0 && strings.TrimSpace(p.Company) != "" {
			asnAligned = shared.ASNOrgAlignedWithProcess(p, asnOrgs)
		}
		for _, org := range asnOrgs {
			if shared.IsCDNOrg(org) {
				asnIsCDN = true
				break
			}
		}
	}

	return CommonState{
		HasNonStandardPort:       hasNonStandardPort,
		AllHTTPPorts:             allHTTPPorts,
		InternalPorts:            internalPorts,
		InternalHosts:            internalHosts,
		NonLoopbackInternalCount: nonLoopbackInternal,
		ExtPortCounts:            extPortCounts,
		ExtHosts:                 extHosts,
		HasEncodingInCmdLine:     hasEncodingInCmdLine,
		HasCryptoLib:             hasCryptoLib,
		HasProxyLib:              hasProxyLib,
		NameLower:                nameLower,
		IsLolbin:                 isLolbin,
		IsScripting:              isScripting,
		RareParentNetwork:        rareParentNetwork,
		IOPerSec:                 ioPerSec,
		TotalIO:                  totalIO,
		ASNOrgs:                  asnOrgs,
		ASNAligned:               asnAligned,
		ASNIsCDN:                 asnIsCDN,
	}
}
