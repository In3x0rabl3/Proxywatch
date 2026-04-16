//go:build windows
// +build windows

package telemetry

import (
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"proxywatch/internal/shared"
)

// Module enumeration on Windows: re-enables the beacon-crypto-lib-loaded
// signal that was dropped in v1.0.6 because a naive EnumProcessModules
// timeout approach could hang when the main scan path closed the process
// handle while a separate goroutine was mid-syscall on it.
//
// The safe pattern here:
//  1. Duplicate the process handle so the enumeration goroutine owns a
//     handle the main path will not close. DUPLICATE_SAME_ACCESS gives
//     the duplicate PROCESS_QUERY_INFORMATION + PROCESS_VM_READ which is
//     what EnumProcessModules needs.
//  2. Run the enumeration in a goroutine; the goroutine closes its own
//     duplicate when it completes (or when the syscall eventually
//     returns, however late that may be).
//  3. Main path waits up to enumModulesTimeout then moves on. A hung
//     goroutine leaks until the kernel unblocks or the host process
//     exits, but it owns its own resources — no undefined behaviour.
//  4. To prevent unbounded goroutine growth from the same protected
//     svchost that hangs every scan, remember PIDs that recently timed
//     out and skip them for the cooldown window. The cost of skipping
//     for 60 s is losing one beacon-crypto-lib-loaded observation on a
//     protected service process; the cost of not skipping is a leaked
//     goroutine per scan cycle.

const (
	// Budget per-PID for EnumProcessModules to return. Most real
	// processes return in < 5 ms; this timeout exists entirely for
	// protected service hosts where the syscall blocks.
	enumModulesTimeout = 400 * time.Millisecond

	// How long to skip a PID after it hangs once. Long enough to stop
	// goroutine pileup, short enough that transient hangs recover.
	enumModulesCooldown = 60 * time.Second

	// Cap on module name collection per process, matching the Linux
	// readMaps cap at 20 entries.
	maxLoadedLibs = 20
)

var (
	enumHangMu       sync.Mutex
	enumHangCooldown = make(map[int]time.Time) // pid → earliest time to retry
)

// fillLoadedLibs enumerates loaded modules for a Windows process and
// populates pi.LoadedLibs with the basenames of notable libraries
// (crypto / SSL / proxy / tunnel patterns). Safe against the protected-
// service-host hang via handle duplication + timeout + PID cooldown.
func fillLoadedLibs(h windows.Handle, pi *shared.ProcessInfo) {
	if pi == nil || pi.Pid <= 0 {
		return
	}

	// Skip if this PID recently hung — avoids piling up goroutines stuck
	// on the same unreachable svchost.
	enumHangMu.Lock()
	if until, ok := enumHangCooldown[pi.Pid]; ok {
		if time.Now().Before(until) {
			enumHangMu.Unlock()
			return
		}
		delete(enumHangCooldown, pi.Pid)
	}
	enumHangMu.Unlock()

	// Duplicate the handle so the goroutine owns one the main path will
	// not close underneath it.
	var dup windows.Handle
	current := windows.CurrentProcess()
	if err := windows.DuplicateHandle(
		current, h,
		current, &dup,
		0, false, windows.DUPLICATE_SAME_ACCESS,
	); err != nil {
		return
	}

	// result channel is buffered so the goroutine never blocks even
	// when we've moved on past the timeout.
	resultCh := make(chan []string, 1)
	go func() {
		defer windows.CloseHandle(dup)
		libs := enumerateNotableModules(dup)
		resultCh <- libs
	}()

	select {
	case libs := <-resultCh:
		pi.LoadedLibs = libs
	case <-time.After(enumModulesTimeout):
		// Stamp the cooldown; the goroutine will eventually close its
		// own dup when/if the syscall returns.
		enumHangMu.Lock()
		enumHangCooldown[pi.Pid] = time.Now().Add(enumModulesCooldown)
		enumHangMu.Unlock()
	}
}

// enumerateNotableModules runs the actual EnumProcessModules syscall and
// returns basenames that match notableLibPatterns, capped at maxLoadedLibs.
// Deduplicated. Called only from a goroutine with an owned duplicate
// handle — never from the main scan path directly.
func enumerateNotableModules(h windows.Handle) []string {
	// First call with a moderate buffer; grow if needed. Typical process
	// has 30–100 modules. cbNeeded returns the byte count required.
	const handleSize = unsafe.Sizeof(windows.Handle(0))
	capSlots := uint32(512) // 512 modules covers everything reasonable.
	modules := make([]windows.Handle, capSlots)
	var cbNeeded uint32

	// EnumProcessModulesEx with LIST_MODULES_ALL enumerates both 32- and
	// 64-bit modules, giving visibility into WoW64 processes where
	// injected x86 shellcode loads x86 DLLs that EnumProcessModules
	// (the non-Ex variant) would miss.
	r, _, _ := ProcEnumProcessModulesEx.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&modules[0])),
		uintptr(capSlots)*uintptr(handleSize),
		uintptr(unsafe.Pointer(&cbNeeded)),
		uintptr(LIST_MODULES_ALL),
	)
	if r == 0 {
		return nil
	}

	count := int(cbNeeded / uint32(handleSize))
	if count > int(capSlots) {
		// Rare: process has > 512 modules. Grow once and retry.
		capSlots = uint32(count)
		modules = make([]windows.Handle, capSlots)
		r, _, _ = ProcEnumProcessModulesEx.Call(
			uintptr(h),
			uintptr(unsafe.Pointer(&modules[0])),
			uintptr(capSlots)*uintptr(handleSize),
			uintptr(unsafe.Pointer(&cbNeeded)),
			uintptr(LIST_MODULES_ALL),
		)
		if r == 0 {
			return nil
		}
		count = int(cbNeeded / uint32(handleSize))
	}
	if count <= 0 {
		return nil
	}

	seen := make(map[string]struct{}, count)
	var libs []string

	nameBuf := make([]uint16, windows.MAX_PATH)
	for i := 0; i < count && len(libs) < maxLoadedLibs; i++ {
		n, _, _ := ProcGetModuleFileNameExW.Call(
			uintptr(h),
			uintptr(modules[i]),
			uintptr(unsafe.Pointer(&nameBuf[0])),
			uintptr(len(nameBuf)),
		)
		if n == 0 {
			continue
		}
		full := windows.UTF16ToString(nameBuf[:n])
		if full == "" {
			continue
		}
		base := strings.ToLower(filepath.Base(full))
		if !isNotableLib(base) {
			continue
		}
		if _, dup := seen[base]; dup {
			continue
		}
		seen[base] = struct{}{}
		libs = append(libs, base)
	}
	return libs
}

// isNotableLib mirrors the Linux notableLibPatterns check: crypto/SSL/TLS
// + known proxy/tunnel libraries. Kept in sync so HasCryptoLib /
// HasProxyTunnelLibPattern in behavior/helpers.go work identically on
// both platforms.
func isNotableLib(base string) bool {
	for _, pat := range notableLibPatternsWindows {
		if strings.Contains(base, pat) {
			return true
		}
	}
	return false
}

// notableLibPatternsWindows is the Windows-side version of the Linux
// notableLibPatterns list, with the lib-prefix dropped (Windows modules
// are *.dll, not lib*.so).
var notableLibPatternsWindows = []string{
	// Crypto / TLS (feeds beacon-crypto-lib-loaded).
	"crypto", "ssl", "tls", "wolfssl", "gnutls",
	"bcrypt", "ncrypt", "schannel", "cng",
	"nss3", "nspr4",
	"cryptsp", "cryptdll",

	// HTTP client stacks — catches wininet-based + winhttp-based beacons
	// (Cobalt Strike HTTP profile, custom .NET implants, legacy
	// Authenticode-style downloaders). wininet and winhttp both count as
	// crypto-lib for the static-crypto-likely gate — a process using
	// either wraps TLS through schannel anyway, but having it visible
	// lets the beacon fingerprint show HTTP-client-present.
	"wininet", "winhttp", "urlmon",

	// Auth / SSPI — beacons doing NTLM/Kerberos impersonation commonly
	// load sspicli / secur32. Visibility helps the injection / pivot
	// signal family without flipping false on plain browsers.
	"sspicli", "secur32",

	// Proxy / tunnel / HTTP-client (feeds pivot-has-proxy-lib).
	"ssh", "proxy", "curl", "socks", "tun",
	"nghttp", "pcap", "winpcap", "npcap",
}
