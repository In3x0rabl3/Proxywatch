//go:build linux

package telemetry

import (
	"bufio"
	"os"
	"strings"

	"proxywatch/internal/shared"
)

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
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []udpRow
	sc := bufio.NewScanner(f)
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
