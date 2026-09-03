//go:build windows || linux

package telemetry

import (
	"time"

	"proxywatch/internal/shared"
)

func mergeProcessMaps(base map[int]*shared.ProcessInfo, extra map[int]*shared.ProcessInfo) map[int]*shared.ProcessInfo {
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

func burstProcessCapture(base map[int]*shared.ProcessInfo, samples int, sleep time.Duration) map[int]*shared.ProcessInfo {
	if samples <= 1 {
		return base
	}

	out := make(map[int]*shared.ProcessInfo, len(base))
	for pid, proc := range base {
		if proc == nil {
			continue
		}
		out[pid] = proc
	}

	for i := 1; i < samples; i++ {
		time.Sleep(sleep)
		procs, err := GetProcessInfoMap()
		if err != nil {
			continue
		}
		for pid, proc := range procs {
			if proc == nil {
				continue
			}
			out[pid] = proc
		}
	}

	return out
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
