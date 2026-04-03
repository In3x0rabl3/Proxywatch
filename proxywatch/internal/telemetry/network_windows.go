//go:build windows
// +build windows

package telemetry

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
	"unsafe"

	"proxywatch/internal/shared"
	"proxywatch/internal/telemetry/platform"

	"golang.org/x/sys/windows"
)

func GetTCPTable() ([]shared.ListenerInfo, []shared.ConnectionInfo, error) {
	l4, c4, err := getTCPTableForFamily(platform.AF_INET)
	if err != nil {
		return nil, nil, err
	}
	l6, c6, err := getTCPTableForFamily(platform.AF_INET6)
	if err != nil {
		return l4, c4, nil
	}
	return append(l4, l6...), append(c4, c6...), nil
}

func getTCPTableForFamily(family uint32) ([]shared.ListenerInfo, []shared.ConnectionInfo, error) {
	var size uint32

	r0, _, _ := platform.ProcGetExtendedTcp.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(family),
		uintptr(platform.TCP_TABLE_OWNER_PID_ALL),
		0,
	)

	const ERROR_INSUFFICIENT_BUFFER = 122
	if r0 != uintptr(ERROR_INSUFFICIENT_BUFFER) && r0 != 0 {
		return nil, nil, fmt.Errorf("GetExtendedTcpTable size query failed: %d", r0)
	}

	buf := make([]byte, size)
	const headerSize = int(unsafe.Sizeof(uint32(0)))
	if len(buf) < headerSize {
		return nil, nil, nil
	}
	r0, _, e1 := platform.ProcGetExtendedTcp.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(family),
		uintptr(platform.TCP_TABLE_OWNER_PID_ALL),
		0,
	)
	if r0 != 0 {
		return nil, nil, fmt.Errorf("GetExtendedTcpTable failed: %v (code=%d)", e1, r0)
	}

	used := int(size)
	if used > len(buf) {
		used = len(buf)
	}
	if used < headerSize {
		return nil, nil, nil
	}
	num := binary.LittleEndian.Uint32(buf[:headerSize])
	rowStart := headerSize

	var listeners []shared.ListenerInfo
	var conns []shared.ConnectionInfo

	if family == platform.AF_INET {
		rowSize := int(unsafe.Sizeof(platform.MIBTCPRowOwnerPID{}))
		maxRows := 0
		if used > rowStart && rowSize > 0 {
			maxRows = (used - rowStart) / rowSize
		}
		rows := int(num)
		if rows > maxRows {
			rows = maxRows
		}
		for i := 0; i < rows; i++ {
			off := rowStart + i*rowSize
			if off+rowSize > used {
				break
			}
			row := (*platform.MIBTCPRowOwnerPID)(unsafe.Pointer(&buf[off]))
			parseV4(row, &listeners, &conns)
		}
	} else {
		rowSize := int(unsafe.Sizeof(platform.MIBTCP6RowOwnerPID{}))
		maxRows := 0
		if used > rowStart && rowSize > 0 {
			maxRows = (used - rowStart) / rowSize
		}
		rows := int(num)
		if rows > maxRows {
			rows = maxRows
		}
		for i := 0; i < rows; i++ {
			off := rowStart + i*rowSize
			if off+rowSize > used {
				break
			}
			row := (*platform.MIBTCP6RowOwnerPID)(unsafe.Pointer(&buf[off]))
			parseV6(row, &listeners, &conns)
		}
	}

	return listeners, conns, nil
}

func parseV4(r *platform.MIBTCPRowOwnerPID, l *[]shared.ListenerInfo, c *[]shared.ConnectionInfo) {
	if r == nil || l == nil || c == nil {
		return
	}
	state := tcpStateToString(r.State)
	lip := net.IPv4(byte(r.LocalAddr), byte(r.LocalAddr>>8), byte(r.LocalAddr>>16), byte(r.LocalAddr>>24)).String()
	rip := net.IPv4(byte(r.RemoteAddr), byte(r.RemoteAddr>>8), byte(r.RemoteAddr>>16), byte(r.RemoteAddr>>24)).String()

	lp := ntohs(r.LocalPort)
	rp := ntohs(r.RemotePort)

	if state == "LISTEN" {
		*l = append(*l, shared.ListenerInfo{
			Pid:          int(r.OwningPID),
			LocalAddress: lip,
			LocalPort:    lp,
			State:        state,
		})
	} else {
		*c = append(*c, shared.ConnectionInfo{
			Pid:           int(r.OwningPID),
			LocalAddress:  lip,
			LocalPort:     lp,
			RemoteAddress: rip,
			RemotePort:    rp,
			State:         state,
		})
	}
}

func parseV6(r *platform.MIBTCP6RowOwnerPID, l *[]shared.ListenerInfo, c *[]shared.ConnectionInfo) {
	if r == nil || l == nil || c == nil {
		return
	}
	lip := net.IP(r.LocalAddr[:]).String()
	rip := net.IP(r.RemoteAddr[:]).String()
	lp := ntohs(r.LocalPort)
	rp := ntohs(r.RemotePort)
	state := tcpStateToString(r.State)

	if state == "LISTEN" {
		*l = append(*l, shared.ListenerInfo{
			Pid:          int(r.OwningPID),
			LocalAddress: lip,
			LocalPort:    lp,
			State:        state,
		})
	} else {
		*c = append(*c, shared.ConnectionInfo{
			Pid:           int(r.OwningPID),
			LocalAddress:  lip,
			LocalPort:     lp,
			RemoteAddress: rip,
			RemotePort:    rp,
			State:         state,
		})
	}
}

func ntohs(p uint32) int {
	v := uint16(p)
	return int((v >> 8) | (v << 8))
}

func tcpStateToString(s uint32) string {
	switch s {
	case 1:
		return "CLOSED"
	case 2:
		return "LISTEN"
	case 3:
		return "SYN_SENT"
	case 4:
		return "SYN_RECEIVED"
	case 5:
		return "ESTABLISHED"
	case 6:
		return "FIN_WAIT_1"
	case 7:
		return "FIN_WAIT_2"
	case 8:
		return "CLOSE_WAIT"
	case 9:
		return "CLOSING"
	case 10:
		return "LAST_ACK"
	case 11:
		return "TIME_WAIT"
	case 12:
		return "DELETE_TCB"
	default:
		return "UNKNOWN"
	}
}

func GetUDPTable() ([]shared.UDPListenerInfo, error) {
	l4, err := getUDPTableForFamily(platform.AF_INET)
	if err != nil {
		return nil, err
	}
	l6, err := getUDPTableForFamily(platform.AF_INET6)
	if err != nil {
		return l4, nil
	}
	return append(l4, l6...), nil
}

func getUDPTableForFamily(family uint32) ([]shared.UDPListenerInfo, error) {
	var size uint32

	r0, _, _ := platform.ProcGetExtendedUdp.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(family),
		uintptr(platform.UDP_TABLE_OWNER_PID),
		0,
	)

	const ERROR_INSUFFICIENT_BUFFER = 122
	if r0 != uintptr(ERROR_INSUFFICIENT_BUFFER) && r0 != 0 {
		return nil, fmt.Errorf("GetExtendedUdpTable size query failed: %d", r0)
	}

	buf := make([]byte, size)
	const headerSize = int(unsafe.Sizeof(uint32(0)))
	if len(buf) < headerSize {
		return nil, nil
	}
	r0, _, e1 := platform.ProcGetExtendedUdp.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(family),
		uintptr(platform.UDP_TABLE_OWNER_PID),
		0,
	)
	if r0 != 0 {
		return nil, fmt.Errorf("GetExtendedUdpTable failed: %v (code=%d)", e1, r0)
	}

	used := int(size)
	if used > len(buf) {
		used = len(buf)
	}
	if used < headerSize {
		return nil, nil
	}
	num := binary.LittleEndian.Uint32(buf[:headerSize])
	rowStart := headerSize

	out := make([]shared.UDPListenerInfo, 0, num)

	if family == platform.AF_INET {
		rowSize := int(unsafe.Sizeof(platform.MIBUDPROwnerPID{}))
		maxRows := 0
		if used > rowStart && rowSize > 0 {
			maxRows = (used - rowStart) / rowSize
		}
		rows := int(num)
		if rows > maxRows {
			rows = maxRows
		}
		for i := 0; i < rows; i++ {
			off := rowStart + i*rowSize
			if off+rowSize > used {
				break
			}
			row := (*platform.MIBUDPROwnerPID)(unsafe.Pointer(&buf[off]))
			out = append(out, parseUDPv4(row))
		}
	} else {
		rowSize := int(unsafe.Sizeof(platform.MIBUDP6OwnerPID{}))
		maxRows := 0
		if used > rowStart && rowSize > 0 {
			maxRows = (used - rowStart) / rowSize
		}
		rows := int(num)
		if rows > maxRows {
			rows = maxRows
		}
		for i := 0; i < rows; i++ {
			off := rowStart + i*rowSize
			if off+rowSize > used {
				break
			}
			row := (*platform.MIBUDP6OwnerPID)(unsafe.Pointer(&buf[off]))
			out = append(out, parseUDPv6(row))
		}
	}

	return out, nil
}

func parseUDPv4(r *platform.MIBUDPROwnerPID) shared.UDPListenerInfo {
	if r == nil {
		return shared.UDPListenerInfo{}
	}
	lip := net.IPv4(byte(r.LocalAddr), byte(r.LocalAddr>>8), byte(r.LocalAddr>>16), byte(r.LocalAddr>>24)).String()
	lp := ntohs(r.LocalPort)
	return shared.UDPListenerInfo{
		Pid:          int(r.OwningPID),
		LocalAddress: lip,
		LocalPort:    lp,
	}
}

func parseUDPv6(r *platform.MIBUDP6OwnerPID) shared.UDPListenerInfo {
	if r == nil {
		return shared.UDPListenerInfo{}
	}
	lip := net.IP(r.LocalAddr[:]).String()
	lp := ntohs(r.LocalPort)
	return shared.UDPListenerInfo{
		Pid:          int(r.OwningPID),
		LocalAddress: lip,
		LocalPort:    lp,
	}
}

func Collect() (*shared.Snapshot, error) {
	preProcs, _ := GetProcessInfoMap()

	listeners, conns, err := GetTCPTable()
	if err != nil {
		return nil, fmt.Errorf("network collection: %w", err)
	}

	if len(listeners) > 0 {
		// Tight loop to capture very short-lived inbound hits (fast scans).
		listeners, conns = fastBurstCapture(listeners, conns, 100*time.Millisecond, 2*time.Millisecond)
	} else {
		samples := burstSampleCount(len(listeners), len(conns))
		if samples > 1 {
			listeners, conns = burstCapture(listeners, conns, samples, shared.BurstSleep)
		}
	}

	procs, err := GetProcessInfoMap()
	if err != nil {
		return nil, fmt.Errorf("process: %w", err)
	}
	procs = mergeProcessMaps(preProcs, procs)
	procs = burstProcessCapture(procs, 2, 5*time.Millisecond)

	udpListeners, _ := GetUDPTable()

	rawPIDs := GetRawSocketPIDs()
	rawConns := GetRawSocketConns()

	// Enumerate named pipes every 10 seconds (expensive).
	var pipes []shared.NamedPipeInfo
	now := time.Now()
	if now.Sub(lastPipeEnumTime) >= 10*time.Second {
		pipes = EnumerateNamedPipes()
		lastPipeEnumTime = now
		lastPipeResult = pipes
	} else {
		pipes = lastPipeResult
	}

	return &shared.Snapshot{
		Timestamp:     time.Now().UTC(),
		Processes:     procs,
		Listeners:     listeners,
		Connections:   conns,
		UDPListeners:  udpListeners,
		RawSocketPIDs: rawPIDs,
		RawConns:      rawConns,
		NamedPipes:    pipes,
	}, nil
}

// GetRawSocketPIDs detects processes with raw socket activity on Windows.
// Windows lacks /proc/net/raw so we use heuristics from the TCP table:
//   - 3+ SYN_SENT connections (scanning handshake flood)
//   - Connections to 10+ distinct remote ports (port scan pattern)
func GetRawSocketPIDs() map[int]bool {
	pids := make(map[int]bool)
	synSentByPID := make(map[int]int)
	type pidPortSet map[int]map[int]bool
	distinctPortsByPID := make(pidPortSet)

	for _, family := range []uint32{platform.AF_INET, platform.AF_INET6} {
		_, conns, err := getTCPTableForFamily(family)
		if err != nil {
			continue
		}
		for _, c := range conns {
			if c.State == "SYN_SENT" {
				synSentByPID[c.Pid]++
			}
			// Track distinct remote ports per PID for scan detection.
			if c.State == "SYN_SENT" || c.State == "ESTABLISHED" || c.State == "TIME_WAIT" {
				if distinctPortsByPID[c.Pid] == nil {
					distinctPortsByPID[c.Pid] = make(map[int]bool)
				}
				distinctPortsByPID[c.Pid][c.RemotePort] = true
			}
		}
	}
	for pid, count := range synSentByPID {
		if count >= 3 {
			pids[pid] = true
		}
	}
	// Flag processes connecting to many distinct remote ports as likely scanners.
	for pid, ports := range distinctPortsByPID {
		if len(ports) >= 10 && !pids[pid] {
			pids[pid] = true
		}
	}
	if len(pids) == 0 {
		return nil
	}
	return pids
}

// GetRawSocketConns returns synthetic connection entries for processes
// detected as using raw sockets on Windows.
func GetRawSocketConns() []shared.RawSocketConn {
	pids := GetRawSocketPIDs()
	if len(pids) == 0 {
		return nil
	}

	var out []shared.RawSocketConn

	// For PIDs with raw sockets, collect their SYN_SENT connections as
	// evidence of scanning activity.
	for _, family := range []uint32{platform.AF_INET, platform.AF_INET6} {
		_, conns, err := getTCPTableForFamily(family)
		if err != nil {
			continue
		}
		for _, c := range conns {
			if !pids[c.Pid] {
				continue
			}
			if c.State == "SYN_SENT" {
				out = append(out, shared.RawSocketConn{
					Pid:    c.Pid,
					Local:  fmt.Sprintf("%s:%d", c.LocalAddress, c.LocalPort),
					Remote: fmt.Sprintf("%s:%d", c.RemoteAddress, c.RemotePort),
					State:  "SYN_SENT",
					Proto:  "raw",
				})
			}
		}
	}

	return out
}

// KillProcess terminates the process with the given PID.
func KillProcess(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("invalid pid: %d", pid)
	}

	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("open process: %w", err)
	}
	defer windows.CloseHandle(h)

	if err := windows.TerminateProcess(h, 1); err != nil {
		return fmt.Errorf("terminate process: %w", err)
	}

	return nil
}

var (
	lastPipeEnumTime time.Time
	lastPipeResult   []shared.NamedPipeInfo
)

// EnumerateNamedPipes discovers named pipe handles across all processes using
// NtQuerySystemInformation. Returns pipe name → owning PID mappings.
// Expensive — only called every 10 seconds.
func EnumerateNamedPipes() []shared.NamedPipeInfo {
	const systemHandleInformation = 16
	const objectNameInformation = 1

	bufSize := uint32(1024 * 1024)
	for attempts := 0; attempts < 3; attempts++ {
		buf := make([]byte, bufSize)
		var retLen uint32
		status, _, _ := platform.ProcNtQuerySystemInformation.Call(
			uintptr(systemHandleInformation),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(bufSize),
			uintptr(unsafe.Pointer(&retLen)),
		)
		if status == 0xC0000004 { // STATUS_INFO_LENGTH_MISMATCH
			bufSize = retLen + 4096
			continue
		}
		if status != 0 {
			return nil
		}

		if len(buf) < 8 {
			return nil
		}
		count := *(*uint32)(unsafe.Pointer(&buf[0]))
		if count == 0 || count > 500000 {
			return nil
		}

		entrySize := unsafe.Sizeof(platform.SystemHandleEntry{})
		offset := uintptr(8) // skip count + padding

		var pipes []shared.NamedPipeInfo
		lookups := 0
		maxLookups := 200
		seen := make(map[string]bool)

		for i := uint32(0); i < count && lookups < maxLookups; i++ {
			entryOffset := offset + uintptr(i)*entrySize
			if entryOffset+entrySize > uintptr(len(buf)) {
				break
			}
			entry := (*platform.SystemHandleEntry)(unsafe.Pointer(&buf[entryOffset]))
			pid := int(entry.OwnerPID)
			if pid <= 4 {
				continue
			}

			procH, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, uint32(pid))
			if err != nil {
				continue
			}

			var dupH windows.Handle
			err = windows.DuplicateHandle(
				procH, windows.Handle(entry.Handle),
				windows.CurrentProcess(), &dupH,
				0, false, windows.DUPLICATE_SAME_ACCESS,
			)
			windows.CloseHandle(procH)
			if err != nil || dupH == 0 {
				continue
			}

			lookups++
			nameBuf := make([]byte, 1024)
			var nameRetLen uint32
			nameStatus, _, _ := platform.ProcNtQueryObject.Call(
				uintptr(dupH), uintptr(objectNameInformation),
				uintptr(unsafe.Pointer(&nameBuf[0])),
				uintptr(len(nameBuf)),
				uintptr(unsafe.Pointer(&nameRetLen)),
			)
			windows.CloseHandle(dupH)

			if nameStatus != 0 || nameRetLen < 8 {
				continue
			}

			nameLen := *(*uint16)(unsafe.Pointer(&nameBuf[0]))
			if nameLen == 0 || nameLen > 512 {
				continue
			}
			headerSize := uintptr(unsafe.Sizeof(uintptr(0))) + 4
			if headerSize > uintptr(len(nameBuf)) || uintptr(nameLen)+headerSize > uintptr(len(nameBuf)) {
				continue
			}
			name := windows.UTF16ToString((*[256]uint16)(unsafe.Pointer(&nameBuf[headerSize]))[:nameLen/2])

			if len(name) == 0 {
				continue
			}
			isNamedPipe := false
			if len(name) > 18 && (name[:19] == `\Device\NamedPipe\` || name[:18] == `\Device\NamedPipe`) {
				isNamedPipe = true
			}
			if !isNamedPipe {
				continue
			}

			key := fmt.Sprintf("%d|%s", pid, name)
			if seen[key] {
				continue
			}
			seen[key] = true
			pipes = append(pipes, shared.NamedPipeInfo{Pid: pid, PipeName: name})
		}
		return pipes
	}
	return nil
}
