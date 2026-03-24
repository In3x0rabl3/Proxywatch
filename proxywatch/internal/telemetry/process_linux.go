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
	uid := readUID(pid)
	username := ""
	if u, err := user.LookupId(uid); err == nil {
		username = u.Username
	}

	ioRead, ioWrite, ioOther := readIO(pid)
	cpuTime := readCPUTime(fields)

	return &shared.ProcessInfo{
		Pid:          pid,
		ParentPid:    ppid,
		Name:         name,
		ExePath:      exePath,
		UserName:     username,
		IOReadBytes:  ioRead,
		IOWriteBytes: ioWrite,
		IOOtherBytes: ioOther,
		CpuTime:      cpuTime,
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

func readUID(pid int) string {
	statusPath := filepath.Join("/proc", strconv.Itoa(pid), "status")
	raw, err := safeio.ReadFile(statusPath)
	if err != nil {
		return ""
	}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return fields[1]
			}
		}
	}
	return ""
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
