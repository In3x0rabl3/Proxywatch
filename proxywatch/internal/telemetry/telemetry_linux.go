//go:build linux

package telemetry

import (
	"fmt"
	"time"

	"proxywatch/internal/shared"
)

// Collect gathers a snapshot of processes, TCP/UDP state on Linux.
func Collect() (*shared.Snapshot, error) {
	listeners, conns, err := GetTCPTable()
	if err != nil {
		return nil, fmt.Errorf("netstat: %w", err)
	}

	udpListeners, err := GetUDPTable()
	if err != nil {
		udpListeners = nil
	}

	procs, err := GetProcessInfoMap()
	if err != nil {
		return nil, fmt.Errorf("process: %w", err)
	}

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
	return killPID(pid)
}
