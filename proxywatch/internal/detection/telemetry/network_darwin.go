//go:build darwin

package telemetry

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"proxywatch/internal/shared"
)

// Collect gathers a snapshot of processes + TCP/UDP state on macOS.
// Pure-Go implementation: processes come from the sysctl-based
// GetProcessInfoMap; network state comes from parsing `lsof -nP -i`
// output (lsof ships by default with macOS).
//
// Fields left zero on darwin relative to Linux/Windows (deferred —
// Track 11c covers the codesign / pkgutil / Mach-O inspection work):
//   - Signed / SignatureTrust / Publisher / PublisherDNSAligned
//   - PkgOwned / PkgOwnerName
//   - LoadedLibs, HasRWXMemory, AnonExecCount, ThreadCount, FDCount
//   - IO counters
//   - NamedPipes (unix-domain-socket enumeration deferred)
//   - RawSocketPIDs (requires private APIs on modern macOS)
func Collect() (*shared.Snapshot, error) {
	preProcs, _ := GetProcessInfoMap()

	listeners, conns, udpListeners, err := collectLsofDarwin()
	if err != nil {
		// Parse failure is recoverable — return the process map with
		// empty network state so callers can still reason about PIDs.
		listeners, conns, udpListeners = nil, nil, nil
	}

	procs, err := GetProcessInfoMap()
	if err != nil {
		return nil, fmt.Errorf("process: %w", err)
	}
	procs = mergeProcessMaps(preProcs, procs)

	return &shared.Snapshot{
		Timestamp:     time.Now().UTC(),
		Processes:     procs,
		Listeners:     listeners,
		Connections:   conns,
		UDPListeners:  udpListeners,
		RawConns:      nil,
		RawSocketPIDs: map[int]bool{},
		NamedPipes:    nil,
	}, nil
}

// collectLsofDarwin runs `lsof -nP -i -F pPcnLTS` and parses the
// field-formatted output. The -F flag gives machine-readable output:
// one record per line, tagged by a single-letter field code. Per-PID
// process records carry 'p' (pid), 'c' (command); per-file records
// carry 'P' (protocol), 'n' (name — local->remote), 'T' (state).
//
// Output shape (simplified):
//
//	p1234
//	cZoom
//	P TCP
//	n 127.0.0.1:60745->127.0.0.1:60746
//	TST=ESTABLISHED
//	P UDP
//	n *:5353
//
// State codes follow `TST=STATE` form. The lsof timeout is bounded
// to 5 seconds so a stuck system dialog (keychain prompt, etc.)
// doesn't freeze the classifier.
func collectLsofDarwin() (listeners []shared.ListenerInfo, conns []shared.ConnectionInfo, udp []shared.UDPListenerInfo, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "lsof", "-nP", "-i", "-F", "pPcnT")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := cmd.Output()
	if err != nil {
		// lsof exits non-zero when some sockets can't be read — treat
		// partial output as success, only bail on a truly empty result.
		if len(out) == 0 {
			return nil, nil, nil, fmt.Errorf("lsof: %w", err)
		}
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	var (
		curPID   int
		curProc  string
		curProto string
		curName  string
		curState string
	)

	flush := func() {
		if curProto == "" || curName == "" {
			return
		}
		proto := strings.ToUpper(strings.TrimSpace(curProto))
		local, remote, hasRemote := splitLsofEndpoints(curName)
		localAddr, localPort := parseLsofEndpoint(local)

		switch proto {
		case "TCP", "TCP4", "TCP6":
			if !hasRemote {
				// Listener.
				listeners = append(listeners, shared.ListenerInfo{
					Pid:          curPID,
					LocalAddress: localAddr,
					LocalPort:    localPort,
					State:        "LISTEN",
				})
			} else {
				remoteAddr, remotePort := parseLsofEndpoint(remote)
				state := strings.TrimPrefix(curState, "ST=")
				if state == "" {
					state = "ESTABLISHED"
				}
				conns = append(conns, shared.ConnectionInfo{
					Pid:           curPID,
					LocalAddress:  localAddr,
					LocalPort:     localPort,
					RemoteAddress: remoteAddr,
					RemotePort:    remotePort,
					State:         state,
				})
			}
		case "UDP", "UDP4", "UDP6":
			// lsof reports UDP sockets with only a local bind (no
			// "->"); treat each entry as a UDP listener record.
			udp = append(udp, shared.UDPListenerInfo{
				Pid:          curPID,
				LocalAddress: localAddr,
				LocalPort:    localPort,
			})
		}
		curProto = ""
		curName = ""
		curState = ""
	}

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}
		tag := line[0]
		val := line[1:]
		switch tag {
		case 'p':
			// New process record — flush any pending file record.
			flush()
			if pid, perr := strconv.Atoi(strings.TrimSpace(val)); perr == nil {
				curPID = pid
			}
			curProc = ""
		case 'c':
			curProc = strings.TrimSpace(val)
			_ = curProc // metadata; ProcessInfo already populated.
		case 'f':
			// New file descriptor — flush previous and reset.
			flush()
		case 'P':
			curProto = val
		case 'n':
			curName = val
		case 'T':
			curState = val
		}
	}
	flush()
	return listeners, conns, udp, scanner.Err()
}

// splitLsofEndpoints breaks a lsof 'n' field into local and remote
// endpoints. Connected sockets use "local->remote" form; listeners
// carry only the local endpoint.
func splitLsofEndpoints(name string) (local, remote string, hasRemote bool) {
	if i := strings.Index(name, "->"); i >= 0 {
		return strings.TrimSpace(name[:i]), strings.TrimSpace(name[i+2:]), true
	}
	return strings.TrimSpace(name), "", false
}

// parseLsofEndpoint parses "addr:port" (IPv4/IPv6). IPv6 addresses
// from lsof are bracket-free — the separator is the last colon.
// Wildcards ("*") are returned as-is; callers compare via
// shared.IsWildcardIP which handles both "*" and "0.0.0.0".
func parseLsofEndpoint(s string) (string, int) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0
	}
	// Last colon splits host/port for both IPv4 ("1.2.3.4:443") and
	// IPv6 ("fe80::1:443").
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return s, 0
	}
	addr := s[:idx]
	port, _ := strconv.Atoi(s[idx+1:])
	// Normalize "*" wildcard to "0.0.0.0" so downstream IsWildcardIP
	// checks behave identically to the Linux/Windows paths.
	if addr == "*" {
		addr = "0.0.0.0"
	}
	return addr, port
}

// KillProcess terminates a PID on darwin. Mirrors the Linux
// implementation — macOS uses the POSIX kill(2) syscall.
func KillProcess(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("invalid pid: %d", pid)
	}
	return syscall.Kill(pid, syscall.SIGKILL)
}

// mergeProcessMaps merges two process-map snapshots taken moments
// apart. Darwin-local copy — network_capture_common.go is gated on
// windows || linux because it also defines burst-capture helpers that
// depend on GetTCPTable (windows/linux only). This small helper is
// the only cross-platform piece we actually need on darwin.
func mergeProcessMaps(base, extra map[int]*shared.ProcessInfo) map[int]*shared.ProcessInfo {
	if len(base) == 0 {
		return extra
	}
	if len(extra) == 0 {
		return base
	}
	out := make(map[int]*shared.ProcessInfo, len(base)+len(extra))
	for pid, proc := range base {
		if proc == nil {
			continue
		}
		out[pid] = proc
	}
	for pid, proc := range extra {
		if proc == nil {
			continue
		}
		out[pid] = proc
	}
	return out
}
