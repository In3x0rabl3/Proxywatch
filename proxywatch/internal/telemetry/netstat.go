//go:build windows
// +build windows

package telemetry

import (
	"fmt"
	"net"
	"time"
	"unsafe"

	"proxywatch/internal/shared"

	"golang.org/x/sys/windows"
)

func GetTCPTable() ([]shared.ListenerInfo, []shared.ConnectionInfo, error) {
	l4, c4, err := getTCPTableForFamily(shared.AF_INET)
	if err != nil {
		return nil, nil, err
	}
	l6, c6, err := getTCPTableForFamily(shared.AF_INET6)
	if err != nil {
		return l4, c4, nil
	}
	return append(l4, l6...), append(c4, c6...), nil
}

func getTCPTableForFamily(family uint32) ([]shared.ListenerInfo, []shared.ConnectionInfo, error) {
	var size uint32

	r0, _, _ := shared.ProcGetExtendedTcp.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(family),
		uintptr(shared.TCP_TABLE_OWNER_PID_ALL),
		0,
	)

	const ERROR_INSUFFICIENT_BUFFER = 122
	if r0 != uintptr(ERROR_INSUFFICIENT_BUFFER) && r0 != 0 {
		return nil, nil, fmt.Errorf("GetExtendedTcpTable size query failed: %d", r0)
	}

	buf := make([]byte, size)
	r0, _, e1 := shared.ProcGetExtendedTcp.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(family),
		uintptr(shared.TCP_TABLE_OWNER_PID_ALL),
		0,
	)
	if r0 != 0 {
		return nil, nil, fmt.Errorf("GetExtendedTcpTable failed: %v (code=%d)", e1, r0)
	}

	bufPtr := uintptr(unsafe.Pointer(&buf[0]))
	num := *(*uint32)(unsafe.Pointer(bufPtr))
	rowPtr := bufPtr + unsafe.Sizeof(num)

	var listeners []shared.ListenerInfo
	var conns []shared.ConnectionInfo

	if family == shared.AF_INET {
		rowSize := unsafe.Sizeof(shared.MIBTCPRowOwnerPID{})
		for i := uint32(0); i < num; i++ {
			row := (*shared.MIBTCPRowOwnerPID)(unsafe.Pointer(rowPtr + uintptr(i)*rowSize))
			parseV4(row, &listeners, &conns)
		}
	} else {
		rowSize := unsafe.Sizeof(shared.MIBTCP6RowOwnerPID{})
		for i := uint32(0); i < num; i++ {
			row := (*shared.MIBTCP6RowOwnerPID)(unsafe.Pointer(rowPtr + uintptr(i)*rowSize))
			parseV6(row, &listeners, &conns)
		}
	}

	return listeners, conns, nil
}

func parseV4(r *shared.MIBTCPRowOwnerPID, l *[]shared.ListenerInfo, c *[]shared.ConnectionInfo) {
	state := tcpStateToString(r.State)
	lip := net.IPv4(byte(r.LocalAddr), byte(r.LocalAddr>>8), byte(r.LocalAddr>>16), byte(r.LocalAddr>>24)).String()
	rip := net.IPv4(byte(r.RemoteAddr), byte(r.RemoteAddr>>8), byte(r.RemoteAddr>>16), byte(r.RemoteAddr>>24)).String()

	lp := ntohs(r.LocalPort)
	rp := ntohs(r.RemotePort)

	if state == "LISTENING" {
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

func parseV6(r *shared.MIBTCP6RowOwnerPID, l *[]shared.ListenerInfo, c *[]shared.ConnectionInfo) {
	lip := net.IP(r.LocalAddr[:]).String()
	rip := net.IP(r.RemoteAddr[:]).String()
	lp := ntohs(r.LocalPort)
	rp := ntohs(r.RemotePort)
	state := tcpStateToString(r.State)

	if state == "LISTENING" {
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
		return "LISTENING"
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
	l4, err := getUDPTableForFamily(shared.AF_INET)
	if err != nil {
		return nil, err
	}
	l6, err := getUDPTableForFamily(shared.AF_INET6)
	if err != nil {
		return l4, nil
	}
	return append(l4, l6...), nil
}

func getUDPTableForFamily(family uint32) ([]shared.UDPListenerInfo, error) {
	var size uint32

	r0, _, _ := shared.ProcGetExtendedUdp.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(family),
		uintptr(shared.UDP_TABLE_OWNER_PID),
		0,
	)

	const ERROR_INSUFFICIENT_BUFFER = 122
	if r0 != uintptr(ERROR_INSUFFICIENT_BUFFER) && r0 != 0 {
		return nil, fmt.Errorf("GetExtendedUdpTable size query failed: %d", r0)
	}

	buf := make([]byte, size)
	r0, _, e1 := shared.ProcGetExtendedUdp.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(family),
		uintptr(shared.UDP_TABLE_OWNER_PID),
		0,
	)
	if r0 != 0 {
		return nil, fmt.Errorf("GetExtendedUdpTable failed: %v (code=%d)", e1, r0)
	}

	bufPtr := uintptr(unsafe.Pointer(&buf[0]))
	num := *(*uint32)(unsafe.Pointer(bufPtr))
	rowPtr := bufPtr + unsafe.Sizeof(num)

	out := make([]shared.UDPListenerInfo, 0, num)

	if family == shared.AF_INET {
		rowSize := unsafe.Sizeof(shared.MIBUDPROwnerPID{})
		for i := uint32(0); i < num; i++ {
			row := (*shared.MIBUDPROwnerPID)(unsafe.Pointer(rowPtr + uintptr(i)*rowSize))
			out = append(out, parseUDPv4(row))
		}
	} else {
		rowSize := unsafe.Sizeof(shared.MIBUDP6OwnerPID{})
		for i := uint32(0); i < num; i++ {
			row := (*shared.MIBUDP6OwnerPID)(unsafe.Pointer(rowPtr + uintptr(i)*rowSize))
			out = append(out, parseUDPv6(row))
		}
	}

	return out, nil
}

func parseUDPv4(r *shared.MIBUDPROwnerPID) shared.UDPListenerInfo {
	lip := net.IPv4(byte(r.LocalAddr), byte(r.LocalAddr>>8), byte(r.LocalAddr>>16), byte(r.LocalAddr>>24)).String()
	lp := ntohs(r.LocalPort)
	return shared.UDPListenerInfo{
		Pid:          int(r.OwningPID),
		LocalAddress: lip,
		LocalPort:    lp,
	}
}

func parseUDPv6(r *shared.MIBUDP6OwnerPID) shared.UDPListenerInfo {
	lip := net.IP(r.LocalAddr[:]).String()
	lp := ntohs(r.LocalPort)
	return shared.UDPListenerInfo{
		Pid:          int(r.OwningPID),
		LocalAddress: lip,
		LocalPort:    lp,
	}
}

func Collect() (*shared.Snapshot, error) {
	listeners, conns, err := GetTCPTable()
	if err != nil {
		return nil, fmt.Errorf("netstat: %w", err)
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

	udpListeners, _ := GetUDPTable()

	return &shared.Snapshot{
		Timestamp:    time.Now().UTC(),
		Processes:    procs,
		Listeners:    listeners,
		Connections:  conns,
		UDPListeners: udpListeners,
	}, nil
}

func burstCapture(
	baseListeners []shared.ListenerInfo,
	baseConns []shared.ConnectionInfo,
	samples int,
	sleep time.Duration,
) ([]shared.ListenerInfo, []shared.ConnectionInfo) {

	listenerMap := make(map[shared.ListenerKey]shared.ListenerInfo, len(baseListeners))
	connMap := make(map[shared.ConnKey]shared.ConnectionInfo, len(baseConns))

	mergeListeners(listenerMap, baseListeners)
	mergeConns(connMap, baseConns)

	for i := 1; i < samples; i++ {
		time.Sleep(sleep)
		listeners, conns, err := GetTCPTable()
		if err != nil {
			continue
		}
		mergeListeners(listenerMap, listeners)
		mergeConns(connMap, conns)
	}

	return buildSnapshots(listenerMap, connMap)
}

// fastBurstCapture runs captures until duration elapses, with a tight sleep.
func fastBurstCapture(
	baseListeners []shared.ListenerInfo,
	baseConns []shared.ConnectionInfo,
	duration time.Duration,
	sleep time.Duration,
) ([]shared.ListenerInfo, []shared.ConnectionInfo) {

	listenerMap := make(map[shared.ListenerKey]shared.ListenerInfo, len(baseListeners))
	connMap := make(map[shared.ConnKey]shared.ConnectionInfo, len(baseConns))
	mergeListeners(listenerMap, baseListeners)
	mergeConns(connMap, baseConns)

	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		time.Sleep(sleep)
		listeners, conns, err := GetTCPTable()
		if err != nil {
			continue
		}
		mergeListeners(listenerMap, listeners)
		mergeConns(connMap, conns)
	}

	return buildSnapshots(listenerMap, connMap)
}

func burstSampleCount(listenerCount, connCount int) int {
	total := listenerCount + connCount
	switch {
	case total <= shared.BurstIdleConnThreshold:
		return shared.BurstSamplesMin
	case total <= shared.BurstModerateConnThreshold:
		return shared.BurstSamplesMid
	default:
		return shared.BurstSamplesMax
	}
}

func mergeListeners(dest map[shared.ListenerKey]shared.ListenerInfo, in []shared.ListenerInfo) {
	for _, l := range in {
		key := shared.ListenerKey{
			Pid:  l.Pid,
			Addr: l.LocalAddress,
			Port: l.LocalPort,
		}
		dest[key] = l
	}
}

func mergeConns(dest map[shared.ConnKey]shared.ConnectionInfo, in []shared.ConnectionInfo) {
	for _, c := range in {
		key := shared.ConnKey{
			Pid:        c.Pid,
			LocalAddr:  c.LocalAddress,
			LocalPort:  c.LocalPort,
			RemoteAddr: c.RemoteAddress,
			RemotePort: c.RemotePort,
		}

		existing, ok := dest[key]
		if !ok {
			dest[key] = c
			continue
		}
		if existing.State != "ESTABLISHED" && c.State == "ESTABLISHED" {
			dest[key] = c
		}
	}
}

func buildSnapshots(
	listenerMap map[shared.ListenerKey]shared.ListenerInfo,
	connMap map[shared.ConnKey]shared.ConnectionInfo,
) ([]shared.ListenerInfo, []shared.ConnectionInfo) {
	outListeners := make([]shared.ListenerInfo, 0, len(listenerMap))
	for _, l := range listenerMap {
		outListeners = append(outListeners, l)
	}

	outConns := make([]shared.ConnectionInfo, 0, len(connMap))
	for _, c := range connMap {
		outConns = append(outConns, c)
	}

	return outListeners, outConns
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
