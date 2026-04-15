//go:build linux

package telemetry

import (
	"bufio"
	"math"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"proxywatch/internal/safeio"
	"proxywatch/internal/shared"
)

func GetProcessInfoMap() (map[int]*shared.ProcessInfo, error) {
	out := make(map[int]*shared.ProcessInfo)
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return out, err
	}
	for _, pe := range procEntries {
		if !pe.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(pe.Name())
		if err != nil {
			continue
		}
		pi := readProcess(pid)
		if pi != nil {
			out[pid] = pi
		}
	}

	// Build child process map from PPIDs.
	childrenByPPID := make(map[int][]int)
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

func readProcess(pid int) *shared.ProcessInfo {
	statPath := filepath.Join("/proc", strconv.Itoa(pid), "stat")
	statData, err := safeio.ReadFile(statPath)
	if err != nil {
		return nil
	}

	// /proc/[pid]/stat: pid (comm) state ppid ...
	fields := parseStat(string(statData))
	if len(fields) < 5 {
		return nil
	}
	name := fields[1]
	ppid, _ := strconv.Atoi(fields[3])

	exePath, _ := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	status := readStatus(pid)
	username := ""
	if u, err := user.LookupId(status.uid); err == nil {
		username = u.Username
	}

	ioRead, ioWrite, ioOther := readIO(pid)
	cpuTime := readCPUTime(fields)
	threadCount := readThreadCount(fields)
	fdCount := readFDCount(pid)
	hasRWX, anonExec, libs := readMaps(pid)

	sigTrust, _ := shared.VerifyBinaryTrust(exePath)

	// Dpkg ownership — local disk walk, no network. Returns "" when
	// either the binary isn't dpkg-tracked or dpkg isn't installed.
	pkgOwner := shared.LookupPackageOwner(exePath)

	// SHA256 — async-cached. Returns "" on first observation, real hash
	// on subsequent cycles. Feeds operator-label lookup which is the
	// primary anti-spoof discriminator.
	exeHash := shared.LookupExeSHA256(exePath)

	return &shared.ProcessInfo{
		Pid:            pid,
		ParentPid:      ppid,
		Name:           name,
		ExePath:        exePath,
		UserName:       username,
		IOReadBytes:    ioRead,
		IOWriteBytes:   ioWrite,
		IOOtherBytes:   ioOther,
		CpuTime:        cpuTime,
		StartTime:      readStartTime(fields),
		CmdLine:        readCmdLine(pid),
		LoadedLibs:     libs,
		ThreadCount:    threadCount,
		FDCount:        fdCount,
		HasRWXMemory:   hasRWX,
		AnonExecCount:  anonExec,
		CapEffective:   status.capEffective,
		Seccomp:        status.seccomp,
		SignatureTrust: sigTrust,
		Signed:         sigTrust == shared.SignatureTrustTrusted,
		PkgOwned:       pkgOwner != "",
		PkgOwnerName:   pkgOwner,
		SHA256:         exeHash,
		// Linux has no PE metadata, so Company stays empty unless we
		// populate it from the package name. This gives
		// EvaluatePublisherDNSAlignment a lookup key on Linux (it falls
		// back from Publisher → Company). Only set when the binary is
		// actually dpkg/rpm/pacman/apk-owned — otherwise an attacker
		// could influence Company via a drop-in binary.
		Company: pkgOwner,
	}
}

func parseStat(stat string) []string {
	// comm can contain spaces within parentheses.
	open := strings.IndexByte(stat, '(')
	close := strings.LastIndexByte(stat, ')')
	if open == -1 || close == -1 || close <= open {
		return strings.Fields(stat)
	}
	prefix := strings.Fields(stat[:open])
	comm := stat[open+1 : close]
	suffix := strings.Fields(stat[close+1:])
	return append(append(prefix, comm), suffix...)
}

type statusInfo struct {
	uid          string
	capEffective uint64
	seccomp      int
}

func readStatus(pid int) statusInfo {
	statusPath := filepath.Join("/proc", strconv.Itoa(pid), "status")
	raw, err := safeio.ReadFile(statusPath)
	if err != nil {
		return statusInfo{}
	}
	var info statusInfo
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				info.uid = fields[1]
			}
		}
		if strings.HasPrefix(line, "CapEff:") {
			hexStr := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
			val, _ := strconv.ParseUint(hexStr, 16, 64)
			info.capEffective = val
		}
		if strings.HasPrefix(line, "Seccomp:") {
			val, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Seccomp:")))
			info.seccomp = val
		}
	}
	return info
}

func readIO(pid int) (uint64, uint64, uint64) {
	path := filepath.Join("/proc", strconv.Itoa(pid), "io")
	raw, err := safeio.ReadFile(path)
	if err != nil {
		return 0, 0, 0
	}
	var r, w, o uint64
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 {
			continue
		}
		val, _ := strconv.ParseUint(fields[1], 10, 64)
		switch fields[0] {
		case "read_bytes:":
			r = val
		case "write_bytes:":
			w = val
		case "cancelled_write_bytes:":
			o = val
		}
	}
	return r, w, o
}

// readStartTime extracts the process creation time from /proc/[pid]/stat.
// Field 21 (0-indexed) is starttime in clock ticks since boot.
func readStartTime(statFields []string) time.Time {
	if len(statFields) < 22 {
		return time.Time{}
	}
	startTicks, err := strconv.ParseInt(statFields[21], 10, 64)
	if err != nil || startTicks <= 0 {
		return time.Time{}
	}
	const clk int64 = 100 // USER_HZ
	uptimeData, err := safeio.ReadFile("/proc/uptime")
	if err != nil {
		return time.Time{}
	}
	uptimeFields := strings.Fields(string(uptimeData))
	if len(uptimeFields) == 0 {
		return time.Time{}
	}
	uptimeSecs, err := strconv.ParseFloat(uptimeFields[0], 64)
	if err != nil || uptimeSecs <= 0 {
		return time.Time{}
	}
	bootTime := time.Now().Add(-time.Duration(uptimeSecs * float64(time.Second)))
	procStart := bootTime.Add(time.Duration(startTicks * int64(time.Second) / clk))
	return procStart
}

func readCPUTime(statFields []string) time.Duration {
	// utime=14, stime=15 (0-based indexing after pid/name/state)
	if len(statFields) < 17 {
		return 0
	}
	utime, err := strconv.ParseInt(statFields[13], 10, 64)
	if err != nil || utime < 0 {
		utime = 0
	}
	stime, err := strconv.ParseInt(statFields[14], 10, 64)
	if err != nil || stime < 0 {
		stime = 0
	}
	const clk int64 = 100 // default USER_HZ
	nsPerTick := int64(time.Second) / clk
	if nsPerTick <= 0 {
		return 0
	}
	if utime > math.MaxInt64-stime {
		return time.Duration(math.MaxInt64)
	}
	totalTicks := utime + stime
	if totalTicks > math.MaxInt64/nsPerTick {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(totalTicks * nsPerTick)
}

func readCmdLine(pid int) string {
	path := filepath.Join("/proc", strconv.Itoa(pid), "cmdline")
	raw, err := safeio.ReadFile(path)
	if err != nil || len(raw) == 0 {
		return ""
	}
	// /proc/pid/cmdline uses null bytes as arg separators.
	for i := range raw {
		if raw[i] == 0 {
			raw[i] = ' '
		}
	}
	cmd := strings.TrimSpace(string(raw))
	// Cap at 1024 chars to avoid storing huge argument lists.
	if len(cmd) > 1024 {
		cmd = cmd[:1024]
	}
	return cmd
}

// notableLibPatterns are substrings that indicate proxy/tunnel/crypto libraries
// worth surfacing in process metadata.
var notableLibPatterns = []string{
	"libssh", "libssl", "libcrypto", "libgnutls",
	"libproxy", "libcurl", "libsocks", "libtun",
	"libpcap", "libnet", "libnghttp", "libwolfssl",
	"libnss3", "libnspr4",
}

func readThreadCount(statFields []string) int {
	// Field 19 (0-indexed) is num_threads in /proc/[pid]/stat.
	if len(statFields) < 20 {
		return 0
	}
	n, _ := strconv.Atoi(statFields[19])
	return n
}

func readFDCount(pid int) int {
	fdDir := filepath.Join("/proc", strconv.Itoa(pid), "fd")
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return 0
	}
	return len(entries)
}

// readMaps parses /proc/[pid]/maps for notable libraries, RWX regions, and
// anonymous executable regions in a single pass.
func readMaps(pid int) (hasRWX bool, anonExecCount int, libs []string) {
	path := filepath.Join("/proc", strconv.Itoa(pid), "maps")
	raw, err := safeio.ReadFile(path)
	if err != nil || len(raw) == 0 {
		return false, 0, nil
	}
	seen := make(map[string]struct{})
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		perms := fields[1]

		// Check for RWX memory regions.
		if len(perms) >= 3 && perms[0] == 'r' && perms[1] == 'w' && perms[2] == 'x' {
			hasRWX = true
		}

		// Check for anonymous executable regions (executable, no file backing).
		if len(perms) >= 3 && perms[2] == 'x' {
			inode := ""
			if len(fields) >= 5 {
				inode = fields[4]
			}
			mappedPath := ""
			if len(fields) >= 6 {
				mappedPath = fields[5]
			}
			if (inode == "0" || inode == "") && mappedPath == "" {
				anonExecCount++
			}
		}

		// Notable library detection (same logic as before).
		if len(fields) < 6 {
			continue
		}
		mapped := fields[len(fields)-1]
		if mapped == "" || mapped[0] != '/' {
			continue
		}
		if len(libs) >= 20 {
			continue
		}
		base := strings.ToLower(filepath.Base(mapped))
		for _, pat := range notableLibPatterns {
			if strings.Contains(base, pat) {
				if _, dup := seen[base]; !dup {
					seen[base] = struct{}{}
					libs = append(libs, base)
				}
				break
			}
		}
	}
	return hasRWX, anonExecCount, libs
}
