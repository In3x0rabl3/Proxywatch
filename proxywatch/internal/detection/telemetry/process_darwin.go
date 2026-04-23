//go:build darwin

package telemetry

import (
	"bufio"
	"bytes"
	"context"
	"debug/macho"
	"encoding/binary"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"proxywatch/internal/shared"
)

// GetProcessInfoMap enumerates every process on the host via the
// kern.proc.all sysctl. Pure-Go — no cgo required, compiles cleanly
// under the release workflow's CGO_ENABLED=0 constraint.
//
// ProcessInfo is populated on a best-effort basis. macOS doesn't
// expose per-process IO counters, capability masks, or seccomp state
// the way Linux does via /proc; fields that can't be obtained cheaply
// remain zero. The classifier's scoring logic already tolerates zero
// fields — a darwin candidate carrying only pid/ppid/name/exepath is
// still useful for role assignment.
//
// Fields populated here:
//
//	Pid, ParentPid, Name, UserName, ExePath, CmdLine, StartTime
//
// Fields intentionally left zero (collected elsewhere or deferred):
//
//	IOReadBytes etc., ThreadCount, FDCount, HasRWXMemory,
//	AnonExecCount, CapEffective, Seccomp, Signed, SignatureTrust,
//	PkgOwned, PkgOwnerName, SHA256, Publisher, Company
func GetProcessInfoMap() (map[int]*shared.ProcessInfo, error) {
	out := make(map[int]*shared.ProcessInfo)

	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return out, err
	}

	// One-shot thread-count lookup across all PIDs — much cheaper
	// than forking per-PID. Best-effort; a failed `ps` call leaves
	// ThreadCount at zero, which the classifier treats as "unknown"
	// (the beacon-thread-minimal signal gates on > 0 && <= 3).
	threadCounts := readDarwinThreadCounts()

	userCache := make(map[uint32]string)
	lookupUser := func(uid uint32) string {
		if name, ok := userCache[uid]; ok {
			return name
		}
		u, err := user.LookupId(strconv.Itoa(int(uid)))
		name := ""
		if err == nil && u != nil {
			name = u.Username
		}
		userCache[uid] = name
		return name
	}

	for i := range procs {
		kp := &procs[i]
		pid := int(kp.Proc.P_pid)
		if pid <= 0 {
			continue
		}
		pi := &shared.ProcessInfo{
			Pid:       pid,
			ParentPid: int(kp.Eproc.Ppid),
			Name:      trimCStringBytes(kp.Proc.P_comm[:]),
			UserName:  lookupUser(kp.Eproc.Ucred.Uid),
			Status:    darwinProcStatus(kp.Proc.P_stat),
		}
		if sec := kp.Proc.P_starttime.Sec; sec > 0 {
			pi.StartTime = time.Unix(int64(sec), int64(kp.Proc.P_starttime.Usec)*1000).UTC()
		}
		if n, ok := threadCounts[pid]; ok {
			pi.ThreadCount = n
		}

		// ExePath + CmdLine come from KERN_PROCARGS2. Best-effort: a
		// failure here is common for processes we can't read (root-
		// owned, csrss equivalents) — swallow and continue with the
		// ProcessInfo we have.
		if exe, cmdline, err := readProcArgs2Darwin(pid); err == nil {
			pi.ExePath = exe
			pi.CmdLine = cmdline
		}

		// LoadedLibs — Mach-O LC_LOAD_DYLIB parse of the executable
		// image. Only observes static dependencies (runtime-loaded
		// frameworks via dlopen won't show up), but that's enough to
		// feed beacon-crypto-lib-loaded for the common case where a
		// vendor app links OpenSSL / libcurl / libssh directly. A
		// statically-linked Go beacon will emit an empty list here —
		// which the classifier's beacon-static-crypto-likely signal
		// uses as positive evidence.
		if pi.ExePath != "" {
			pi.LoadedLibs = readMachoDylibs(pi.ExePath)
		}

		// Signature trust + publisher via shared cache. The sync path
		// calls signature_darwin.go's verifyBinaryTrust (path + uid
		// heuristic); the async worker thread upgrades the verdict to
		// codesign-based Authority / TeamIdentifier via
		// performAuthenticodeVerify. First observation returns the
		// heuristic verdict; subsequent cycles pick up the richer
		// codesign data from the VerdictEntry cache.
		if pi.ExePath != "" {
			pi.SignatureTrust, pi.Publisher = shared.VerifyBinaryTrust(pi.ExePath)
			pi.Signed = pi.SignatureTrust == shared.SignatureTrustTrusted
			if pi.Signed {
				// Best-effort package-ownership lookup — empty string
				// for untracked binaries. Cache-first, bounded 2s
				// subprocess on miss.
				if owner := shared.LookupPackageOwner(pi.ExePath); owner != "" {
					pi.PkgOwned = true
					pi.PkgOwnerName = owner
					if pi.Company == "" {
						pi.Company = owner
					}
				}
			}
			// SHA256 — async-cached, same flow as linux. Feeds
			// operator-label lookup.
			pi.SHA256 = shared.LookupExeSHA256(pi.ExePath)
		}

		out[pid] = pi
	}

	// Build child-process map from PPIDs.
	childrenByPPID := make(map[int][]int, len(out))
	for pid, proc := range out {
		if proc.ParentPid > 0 {
			childrenByPPID[proc.ParentPid] = append(childrenByPPID[proc.ParentPid], pid)
		}
	}
	for pid, proc := range out {
		children := childrenByPPID[pid]
		proc.ChildCount = len(children)
		if len(children) > 50 {
			children = children[:50]
		}
		proc.ChildPids = children
	}

	return out, nil
}

// readProcArgs2Darwin queries the KERN_PROCARGS2 sysctl for a PID and
// returns (exePath, cmdLine). The buffer layout is documented in
// sys/sysctl.h: int argc, then null-terminated exe path, then
// null-terminated argv entries.
func readProcArgs2Darwin(pid int) (string, string, error) {
	// CTL_KERN (1) / KERN_PROCARGS2 (49) / pid
	mib := []int32{1, 49, int32(pid)}
	raw, err := sysctlRawMIB(mib)
	if err != nil {
		return "", "", err
	}
	if len(raw) < 4 {
		return "", "", nil
	}
	argc := int(binary.LittleEndian.Uint32(raw[:4]))
	// Sanity: real argc is typically 1-50. A value over 4096 is
	// corrupt sysctl data (stale / racy read during process exit).
	// Clamp to a sane ceiling so we don't pre-allocate gigabytes if
	// argc comes back as 0x7fffffff.
	if argc < 0 || argc > 4096 {
		return "", "", nil
	}
	rest := raw[4:]

	// First null-terminated string after argc is the exec path.
	// Cap the search window to avoid scanning pathologically large
	// buffers; POSIX PATH_MAX on darwin is 1024, so 4KB is plenty.
	searchLimit := len(rest)
	if searchLimit > 4096 {
		searchLimit = 4096
	}
	end := bytes.IndexByte(rest[:searchLimit], 0)
	if end < 0 {
		return "", "", nil
	}
	exe := string(rest[:end])
	rest = rest[end+1:]
	for len(rest) > 0 && rest[0] == 0 {
		rest = rest[1:]
	}

	// Next `argc` null-delimited strings are argv.
	cmdParts := make([]string, 0, argc)
	for i := 0; i < argc && len(rest) > 0; i++ {
		end := bytes.IndexByte(rest, 0)
		if end < 0 {
			cmdParts = append(cmdParts, string(rest))
			break
		}
		cmdParts = append(cmdParts, string(rest[:end]))
		rest = rest[end+1:]
	}
	cmdline := strings.Join(cmdParts, " ")
	if len(cmdline) > 1024 {
		cmdline = cmdline[:1024]
	}
	return exe, cmdline, nil
}

// sysctlRawMIB wraps unix.SysctlRaw's MIB-int form. The unix package
// exposes SysctlRaw(name string) which takes a dotted name like
// "kern.proc.all"; KERN_PROCARGS2 isn't exported by name, so we build
// the MIB array manually.
func sysctlRawMIB(mib []int32) ([]byte, error) {
	// unix.SysctlRaw takes a string name, but we need the numeric MIB
	// path. Fall back to unix.Sysctl with a constructed string when
	// possible, otherwise use the lower-level approach via a BUF-sized
	// probe. The cleanest pure-Go path on darwin is to just call
	// unix.Sysctl("kern.procargs2", pid) — it exists for darwin as a
	// dot-joined form.
	return unix.SysctlRaw("kern.procargs2", int(mib[2]))
}

// trimCStringBytes returns the string up to the first NUL byte, with
// trailing whitespace trimmed. Used for kinfo_proc fixed-size char
// arrays (P_comm is [17]byte).
func trimCStringBytes(b []byte) string {
	if idx := bytes.IndexByte(b, 0); idx >= 0 {
		b = b[:idx]
	}
	return strings.TrimSpace(string(b))
}

// darwinProcStatus maps the kinfo_proc P_stat enum to a human string.
// Values come from sys/proc.h: SIDL=1, SRUN=2, SSLEEP=3, SSTOP=4,
// SZOMB=5.
func darwinProcStatus(s int8) string {
	switch s {
	case 1:
		return "Idle"
	case 2:
		return "Running"
	case 3:
		return "Sleeping"
	case 4:
		return "Stopped"
	case 5:
		return "Zombie"
	}
	return ""
}

// readDarwinThreadCounts runs `ps -A -o pid=,thcount=` once and
// returns a pid → thread-count map. One subprocess for all PIDs
// beats forking per-PID. Bounded via context timeout so a hung ps
// (unusual but possible on I/O-saturated systems) can't stall the
// classifier. Empty or malformed lines are skipped silently.
func readDarwinThreadCounts() map[int]int {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ps", "-A", "-o", "pid=,thcount=")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return nil
	}
	return parseThreadCounts(string(out))
}

// parseThreadCounts splits `ps -A -o pid=,thcount=` output into a
// pid → threadcount map. Separated from the subprocess call for
// unit testability against fixed fixtures.
func parseThreadCounts(raw string) map[int]int {
	out := make(map[int]int)
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil || pid <= 0 {
			continue
		}
		tc, err := strconv.Atoi(fields[1])
		if err != nil || tc < 0 {
			continue
		}
		out[pid] = tc
	}
	return out
}

// notableLibPatternsDarwin mirrors notableLibPatternsWindows +
// notableLibPatterns (linux) for macOS dylib naming. Apple ships TLS
// primitives under LibreSSL (libssl / libcrypto variants), so we keep
// the cross-platform keywords plus macOS-specific framework names.
var notableLibPatternsDarwin = []string{
	// Crypto / TLS — feeds beacon-crypto-lib-loaded.
	"libssl", "libcrypto", "libssh", "libgnutls", "libwolfssl",
	"libnss3", "libnspr4",
	"security.framework", "securityfoundation",
	"commoncrypto",
	// HTTP client stacks.
	"libcurl", "libnghttp",
	// Proxy / tunnel / packet-capture — feeds pivot-proxy-lib-loaded.
	"libproxy", "libsocks", "libtun", "libpcap", "libnet",
}

// readMachoDylibs opens the executable and returns a deduplicated
// list of notable LC_LOAD_DYLIB entries. Pure-Go via debug/macho;
// handles both thin (single-arch) and fat (universal) binaries. A
// parse failure returns nil so callers can treat it as "no evidence"
// without surfacing errors up the classifier stack.
//
// Limitations: static deps only. A runtime dlopen("libsomething.dylib")
// won't show up. That's acceptable — the classifier's static-crypto-
// likely signal specifically targets beacons that avoid linking crypto
// DLLs/dylibs (Go's crypto/tls, Rust's rustls, Nim's stdlib) and fires
// positively when the dylib list is empty.
func readMachoDylibs(exePath string) []string {
	if exePath == "" {
		return nil
	}

	// Try thin first; fall back to fat (universal) binary.
	if libs := readMachoDylibsThin(exePath); libs != nil {
		return libs
	}
	return readMachoDylibsFat(exePath)
}

func readMachoDylibsThin(exePath string) []string {
	f, err := macho.Open(exePath)
	if err != nil {
		return nil
	}
	defer f.Close()
	libs, lerr := f.ImportedLibraries()
	if lerr != nil {
		return nil
	}
	return filterMachoDylibs(libs)
}

func readMachoDylibsFat(exePath string) []string {
	f, err := macho.OpenFat(exePath)
	if err != nil {
		return nil
	}
	defer f.Close()
	if len(f.Arches) == 0 {
		return nil
	}
	// All archs of a universal binary link the same libs in
	// practice — read from the first arch.
	libs, lerr := f.Arches[0].ImportedLibraries()
	if lerr != nil {
		return nil
	}
	return filterMachoDylibs(libs)
}

// filterMachoDylibs keeps only the notable-pattern matches (so the
// classifier's HasCryptoLib / HasProxyLib computations have a
// manageable slice to scan), de-duplicates, and caps at 20 entries
// to match Linux / Windows behavior.
func filterMachoDylibs(libs []string) []string {
	if len(libs) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(libs))
	out := make([]string, 0, 8)
	for _, full := range libs {
		if full == "" {
			continue
		}
		base := strings.ToLower(filepath.Base(full))
		for _, pat := range notableLibPatternsDarwin {
			if !strings.Contains(base, pat) {
				continue
			}
			if _, dup := seen[base]; dup {
				break
			}
			seen[base] = struct{}{}
			out = append(out, base)
			break
		}
		if len(out) >= 20 {
			break
		}
	}
	return out
}
