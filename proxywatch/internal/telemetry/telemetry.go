//go:build windows
// +build windows

package telemetry

import (
	"fmt"
	"time"

	"proxywatch/internal/shared"
)

func Collect() (*shared.Snapshot, error) {
	listeners, conns, err := GetTCPTable()
	if err != nil {
		return nil, fmt.Errorf("netstat: %w", err)
	}

	samples := burstSampleCount(len(listeners), len(conns))
	// If any listeners exist, force maximum burst samples to capture short-lived inbound hits.
	if len(listeners) > 0 {
		samples = shared.BurstSamplesMax
	}
	if samples > 1 {
		listeners, conns = burstCapture(listeners, conns, samples)
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
) ([]shared.ListenerInfo, []shared.ConnectionInfo) {

	listenerMap := make(map[shared.ListenerKey]shared.ListenerInfo, len(baseListeners))
	connMap := make(map[shared.ConnKey]shared.ConnectionInfo, len(baseConns))

	mergeListeners(listenerMap, baseListeners)
	mergeConns(connMap, baseConns)

	for i := 1; i < samples; i++ {
		time.Sleep(shared.BurstSleep)
		listeners, conns, err := GetTCPTable()
		if err != nil {
			continue
		}
		mergeListeners(listenerMap, listeners)
		mergeConns(connMap, conns)
	}

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
