package behavior

import (
	"strings"

	"proxywatch/internal/shared"
)

// EmitDistinguishingSignals fires the signals that separate actual tooling
// from legitimate vendor phone-home. These are consumed by rank.go for
// promotion decisions AND by shared/distinguishing.go for the shape-only
// demotion guard.
//
// Each signal here represents a pattern legitimate vendor software does
// not produce:
//
//   - suspicious-exe-path: binary running from Downloads/Desktop/Temp/
//     other user-writable paths. Vendor binaries are installed in
//     Program Files / /usr/bin / AppData\Local\Programs (admin- or
//     package-manager-controlled).
//   - raw-socket: process has raw-socket activity (heuristic detected).
//     Vendor apps use TCP/UDP sockets; raw sockets indicate scanners,
//     sniffers, or C2 implants bypassing normal networking.
//   - cmdline-proxy-flags: tunnel/proxy CLI flags in the command line
//     (-D/-L/-R for SSH, --socks, --proxy). Legitimate apps don't pass
//     these by default.
//   - proxy-library-loaded: libproxychains / libsocks / similar loaded
//     into process address space.
//
// The SSH-specific pivot-ssh-tunnel-flags (emitted by pivot.go) is a
// superset of cmdline-proxy-flags filtered to ssh; we keep both so
// rank.go can score SSH specifically.
func EmitDistinguishingSignals(c *shared.Candidate, addSignal func(string), ctx SignalContext, cs CommonState) {
	if c == nil || c.Proc == nil {
		return
	}

	// suspicious-exe-path: binary from a user-writable path that vendor
	// software should never land in. Pattern matches both Windows user
	// paths and Unix ephemeral/home paths.
	if isSuspiciousExePath(c.Proc.ExePath) {
		addSignal("suspicious-exe-path")
	}

	// raw-socket: classifier sets c.RawSocket from Snapshot.RawSocketPIDs
	// (populated by telemetry on Windows and Linux). Fire the signal
	// name so rank.go's consumer + our distinguishing check see it.
	if c.RawSocket {
		addSignal("raw-socket")
	}

	// cmdline-proxy-flags: tunnel/proxy CLI flags. Scoped to exclude SSH
	// (which has its own pivot-ssh-tunnel-flags emitter in pivot.go)
	// so we don't double-fire for the same cmdline.
	if cmd := strings.ToLower(strings.TrimSpace(c.Proc.CmdLine)); cmd != "" {
		if hasProxyFlagPattern(cmd) && !strings.Contains(cs.NameLower, "ssh") {
			addSignal("cmdline-proxy-flags")
		}
	}

	// proxy-library-loaded: well-known proxy/tunnel libraries loaded
	// into process memory. Linux reads /proc/[pid]/maps directly.
	// Windows uses EnumProcessModules behind a handle-duplicating
	// goroutine wrapper (see telemetry/process_windows_libs.go) so
	// protected service hosts that historically hung the syscall
	// can no longer stall the scanner.
	if hasProxyLibraryLoaded(c.Proc.LoadedLibs) {
		addSignal("proxy-library-loaded")
	}
}

// isSuspiciousExePath returns true when the executable lives in a
// user-writable / ephemeral location that's a classic malware drop
// target. Case-insensitive, normalized slashes. Paths under Program
// Files / /usr/bin / AppData\Local\Programs are NOT suspicious.
func isSuspiciousExePath(exePath string) bool {
	p := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(exePath), "\\", "/"))
	if p == "" {
		return false
	}
	// Program-installed paths: explicitly NOT suspicious even if nested
	// under a user-ish directory. Must check before the generic patterns.
	if strings.Contains(p, "/appdata/local/programs/") {
		return false
	}
	// Windows user-writable drop targets.
	if strings.Contains(p, "/downloads/") ||
		strings.Contains(p, "/desktop/") ||
		strings.Contains(p, "/appdata/local/temp/") ||
		strings.Contains(p, "/appdata/roaming/temp/") {
		return true
	}
	// Unix ephemeral/user.
	if strings.HasPrefix(p, "/tmp/") ||
		strings.HasPrefix(p, "/var/tmp/") ||
		strings.HasPrefix(p, "/dev/shm/") {
		return true
	}
	// Explicit user-home drops that aren't under a vendor-installed
	// subtree (most legit user binaries live under a program/install
	// subdir). Bare /home/<user>/random.exe or c:/users/<user>/foo.exe
	// qualifies, but /home/<user>/.local/bin does not (package-manager
	// controlled via pip-user etc).
	if strings.HasPrefix(p, "c:/users/") || strings.HasPrefix(p, "/home/") {
		if strings.Contains(p, "/.local/bin/") ||
			strings.Contains(p, "/.cache/") ||
			strings.Contains(p, "/snap/") {
			return false
		}
		// Top-level c:/users/<user>/<file>.exe or in downloads/desktop/etc.
		// Count path segments after the user directory. Exactly 4 segments
		// means a bare drop (c:/users/ops/foo.exe).
		segments := strings.Split(strings.Trim(p, "/"), "/")
		if len(segments) <= 4 {
			return true
		}
	}
	return false
}

// hasProxyFlagPattern checks lowercase cmdline for tunnel/proxy flags
// that aren't part of legitimate app invocation. Intentionally simple —
// false positives (a legit app taking "--proxy" as a config arg) are
// acceptable because a legit vendor app wouldn't trip our demotion path
// anyway (its install-path-trust indicator dominates).
func hasProxyFlagPattern(cmdLower string) bool {
	// Tunnel flags (generic, not SSH-specific).
	for _, flag := range []string{
		" --socks", " --proxy",
		" -socks", " -proxy",
		"socat ", "chisel ", "ngrok ", "frpc ", "stunnel ",
		"gost ", "proxychains ", "proxychains4 ",
	} {
		if strings.Contains(cmdLower, flag) {
			return true
		}
	}
	return false
}

// hasProxyLibraryLoaded returns true when a well-known proxy/tunneling
// library is loaded into the process. Match on basename substring —
// version suffixes vary.
func hasProxyLibraryLoaded(libs []string) bool {
	for _, lib := range libs {
		low := strings.ToLower(lib)
		for _, needle := range []string{
			"libproxychains",
			"libsocks",
			"libtsocks",
			"libdsocksify",
		} {
			if strings.Contains(low, needle) {
				return true
			}
		}
	}
	return false
}
