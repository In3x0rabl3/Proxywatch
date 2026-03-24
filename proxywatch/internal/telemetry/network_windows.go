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

	return &shared.Snapshot{
		Timestamp:    time.Now().UTC(),
		Processes:    procs,
		Listeners:    listeners,
		Connections:  conns,
		UDPListeners: udpListeners,
	}, nil
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
