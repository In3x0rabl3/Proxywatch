package model

import (
	"fmt"
	"time"

	"proxywatch/internal/shared"
)

// IngestContourEgressPaths merges contour probe results into the model.
// Each port/protocol pair that succeeded as a tunnel or exfil channel
// is recorded with a confidence score.
func IngestContourEgressPaths(paths []EgressPath) {
	if len(paths) == 0 {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	if current == nil {
		return
	}
	now := time.Now().UTC()
	for _, path := range paths {
		existing, ok := current.EgressPaths[path.Port]
		if ok {
			// Merge: refresh confidence and confirmation time.
			existing.LastConfirmed = now
			if path.Confidence > existing.Confidence {
				existing.Confidence = path.Confidence
			}
			if path.TunnelCapable {
				existing.TunnelCapable = true
			}
			if path.ExfilCapable {
				existing.ExfilCapable = true
			}
			// Merge protocols.
			seen := make(map[string]struct{}, len(existing.Protocols))
			for _, p := range existing.Protocols {
				seen[p] = struct{}{}
			}
			for _, p := range path.Protocols {
				if _, ok := seen[p]; !ok {
					existing.Protocols = append(existing.Protocols, p)
				}
			}
		} else {
			ep := path
			if ep.DiscoveredAt.IsZero() {
				ep.DiscoveredAt = now
			}
			if ep.LastConfirmed.IsZero() {
				ep.LastConfirmed = now
			}
			current.EgressPaths[path.Port] = &ep
		}
	}
	markDirty()
}

// EgressSignals checks candidate connections against known egress paths
// and returns signal names and reason strings to add.
func EgressSignals(conns []shared.ConnectionInfo) (signals []string, reasons []string, tunnelBoost int) {
	mu.RLock()
	defer mu.RUnlock()
	if current == nil || len(current.EgressPaths) == 0 {
		return
	}

	tunnelSeen := false
	exfilSeen := false
	for _, cn := range conns {
		ep, ok := current.EgressPaths[cn.RemotePort]
		if !ok || ep.Confidence < 0.3 {
			continue
		}
		if ep.TunnelCapable && !tunnelSeen {
			signals = append(signals, "contour-egress-tunnel-port")
			reasons = append(reasons, fmt.Sprintf("Port %d confirmed tunnel-capable by contour (%.0f%% confidence)", cn.RemotePort, ep.Confidence*100))
			tunnelBoost += 2
			tunnelSeen = true
		}
		if ep.ExfilCapable && !exfilSeen {
			signals = append(signals, "contour-egress-exfil-port")
			reasons = append(reasons, fmt.Sprintf("Port %d confirmed exfil-capable by contour (%.0f%% confidence)", cn.RemotePort, ep.Confidence*100))
			exfilSeen = true
		}
	}
	return
}
