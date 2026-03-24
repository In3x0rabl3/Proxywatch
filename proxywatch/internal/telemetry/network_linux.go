//go:build linux

package telemetry

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"proxywatch/internal/safeio"
	"proxywatch/internal/shared"
)

type tcpRow struct {
	localIP   string
	localPort int
	remIP     string
	remPort   int
	state     string
	inode     string
}

func GetTCPTable() ([]shared.ListenerInfo, []shared.ConnectionInfo, error) {
	rows, err := readTCP("/proc/net/tcp")
	if err != nil {
		return nil, nil, err
	}
	rows6, _ := readTCP("/proc/net/tcp6")
	rows = append(rows, rows6...)

	inodePIDs, err := buildInodePIDMap()
	if err != nil {
		return nil, nil, err
	}

	listeners := make([]shared.ListenerInfo, 0)
	conns := make([]shared.ConnectionInfo, 0)

	for _, r := range rows {
		pid := inodePIDs[r.inode]
		if r.remPort == 0 {
			listeners = append(listeners, shared.ListenerInfo{
				Pid:          pid,
				LocalAddress: r.localIP,
				LocalPort:    r.localPort,
				State:        r.state,
			})
		} else {
			conns = append(conns, shared.ConnectionInfo{
				Pid:           pid,
				LocalAddress:  r.localIP,
				LocalPort:     r.localPort,
				RemoteAddress: r.remIP,
				RemotePort:    r.remPort,
				State:         r.state,
			})
		}
	}

	return listeners, conns, nil
}

func readTCP(path string) ([]tcpRow, error) {
	raw, err := safeio.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var out []tcpRow
	sc := bufio.NewScanner(bytes.NewReader(raw))
	if sc.Scan() {
		// skip header
	}
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		lip, lport := parseHexAddr(fields[1])
		rip, rport := parseHexAddr(fields[2])
		state := tcpState(fields[3])
		inode := fields[9]
		out = append(out, tcpRow{
			localIP:   lip,
			localPort: lport,
			remIP:     rip,
			remPort:   rport,
			state:     state,
			inode:     inode,
		})
	}
	return out, nil
}

func parseHexAddr(hexaddr string) (string, int) {
	parts := strings.Split(hexaddr, ":")
	if len(parts) != 2 {
		return "", 0
	}
	ipHex, portHex := parts[0], parts[1]
	port, _ := strconv.ParseInt(portHex, 16, 32)

	var ip net.IP
	if len(ipHex) == 8 { // IPv4
		b, _ := strconv.ParseUint(ipHex, 16, 32)
		b32 := uint32(b)
		ip = net.IPv4(
			byte(b32&0xff),
			byte((b32>>8)&0xff),
			byte((b32>>16)&0xff),
			byte((b32>>24)&0xff),
		)
	} else { // IPv6
		ipBytes := make([]byte, 16)
		for i := 0; i < 16; i++ {
			byteHex := ipHex[2*i : 2*i+2]
			v, _ := strconv.ParseUint(byteHex, 16, 8)
			ipBytes[15-i] = byte(v) // little endian in /proc
		}
		ip = net.IP(ipBytes)
	}
	return ip.String(), int(port)
}

func tcpState(hexState string) string {
	switch hexState {
	case "01":
		return "ESTABLISHED"
	case "02":
		return "SYN_SENT"
	case "03":
		return "SYN_RECEIVED"
	case "04":
		return "FIN_WAIT_1"
	case "05":
		return "FIN_WAIT_2"
	case "06":
		return "TIME_WAIT"
	case "07":
		return "CLOSE"
	case "08":
		return "CLOSE_WAIT"
	case "09":
		return "LAST_ACK"
	case "0A":
		return "LISTEN"
	case "0B":
		return "CLOSING"
	default:
		return hexState
	}
}

// buildInodePIDMap maps socket inode -> PID by scanning /proc/*/fd symlinks.
func buildInodePIDMap() (map[string]int, error) {
	out := make(map[string]int)
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
		fdDir := filepath.Join("/proc", pe.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
				inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
				out[inode] = pid
			}
		}
	}
	return out, nil
}

func GetUDPTable() ([]shared.UDPListenerInfo, error) {
	rows, err := readUDP("/proc/net/udp")
	if err != nil {
		return nil, err
	}
	rows6, _ := readUDP("/proc/net/udp6")
	rows = append(rows, rows6...)

	inodePIDs, err := buildInodePIDMap()
	if err != nil {
		return nil, err
	}

	out := make([]shared.UDPListenerInfo, 0, len(rows))
	for _, r := range rows {
		pid := inodePIDs[r.inode]
		out = append(out, shared.UDPListenerInfo{
			Pid:          pid,
			LocalAddress: r.localIP,
			LocalPort:    r.localPort,
		})
	}
	return out, nil
}

type udpRow struct {
	localIP   string
	localPort int
	inode     string
}

func readUDP(path string) ([]udpRow, error) {
	raw, err := safeio.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var out []udpRow
	sc := bufio.NewScanner(bytes.NewReader(raw))
	if sc.Scan() {
		// skip header
	}
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		lip, lport := parseHexAddr(fields[1])
		inode := fields[9]
		out = append(out, udpRow{
			localIP:   lip,
			localPort: lport,
			inode:     inode,
		})
	}
	return out, nil
}

// Collect gathers a snapshot of processes, TCP/UDP state on Linux.
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

	udpListeners, err := GetUDPTable()
	if err != nil {
		udpListeners = nil
	}

	procs, err := GetProcessInfoMap()
	if err != nil {
		return nil, fmt.Errorf("process: %w", err)
	}
	procs = mergeProcessMaps(preProcs, procs)
	procs = burstProcessCapture(procs, 2, 5*time.Millisecond)

	return &shared.Snapshot{
		Timestamp:    time.Now().UTC(),
		Processes:    procs,
		Listeners:    listeners,
		Connections:  conns,
		UDPListeners: udpListeners,
	}, nil
}

// KillProcess terminates a PID on Linux.
func KillProcess(pid int) error {
	return syscall.Kill(pid, syscall.SIGKILL)
}
