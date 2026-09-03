package pcap

import (
	"strings"

	"proxywatch/internal/shared"
)

// enrichPcapWithRareSignatures stamps `tls-rare-signature` and
// `http-rare-signature` on cluster candidates whose flow uses a TLS
// fingerprint (JA3 or SNI) or HTTP User-Agent that, from the local
// host's perspective, has only ever been observed talking to ONE
// distinct external destination IP across the whole capture.
//
// Rationale: a real browser's JA3 / Edge's UA reaches dozens of
// distinct destinations from any one host. An implant's WinHTTP JA3
// with one hardcoded C2 server reaches ONE. The "1 distinct dest"
// rule is self-filtering for legitimate apps because they fan out
// by design.
//
// Skips:
//   - empty fingerprints (no TLS / non-HTTP flows)
//   - destinations on internal RFC1918 / loopback (rare-internal is
//     the wrong axis — we care about external-facing C2)
//
// Only fires when the cluster's destination matches the
// rare-signature's destination, so an unrelated cluster from the
// same host doesn't get noise.
func enrichPcapWithRareSignatures(flows []*flowState, attr *pcapAttribution, candidates []shared.Candidate) {
	if len(flows) == 0 || attr == nil || len(candidates) == 0 {
		return
	}

	// Build distinct-destination sets keyed on (LocalIP, signature).
	// Each map's value is the set of distinct external RemoteIPs the
	// signature has been observed talking to.
	type sigKey struct {
		localIP string
		sig     string
	}
	addDest := func(m map[sigKey]map[string]struct{}, k sigKey, dest string) {
		if k.sig == "" || dest == "" {
			return
		}
		set, ok := m[k]
		if !ok {
			set = make(map[string]struct{})
			m[k] = set
		}
		set[dest] = struct{}{}
	}

	ja3Dests := make(map[sigKey]map[string]struct{})
	sniDests := make(map[sigKey]map[string]struct{})
	uaDests := make(map[sigKey]map[string]struct{})

	for _, st := range flows {
		if st == nil {
			continue
		}
		// Only consider external destinations — implants normally
		// reach for the internet, not LAN peers, on a unique
		// fingerprint. Rare-signature on internal traffic produces
		// noise from one-off SMB / RDP /WMI tools that legitimately
		// hit a single share.
		if shared.IsInternalIP(st.key.RespIP) || shared.IsLoopbackIP(st.key.RespIP) {
			continue
		}
		dest := st.key.RespIP
		if st.tlsJA3 != "" {
			addDest(ja3Dests, sigKey{st.key.InitIP, st.tlsJA3}, dest)
		}
		if st.tlsSNI != "" {
			addDest(sniDests, sigKey{st.key.InitIP, strings.ToLower(st.tlsSNI)}, dest)
		}
		if ua := strings.TrimSpace(st.httpUserAgent); ua != "" {
			addDest(uaDests, sigKey{st.key.InitIP, ua}, dest)
		}
	}

	// Second pass: identify which flows match a rare signature
	// (1 distinct destination from the local host) and aggregate per
	// cluster PID.
	type rareHit struct {
		ja3 string
		sni string
		ua  string
	}
	hits := make(map[int]*rareHit)
	addHit := func(pid int, build func(*rareHit)) {
		h, ok := hits[pid]
		if !ok {
			h = &rareHit{}
			hits[pid] = h
		}
		build(h)
	}

	for _, st := range flows {
		if st == nil {
			continue
		}
		if shared.IsInternalIP(st.key.RespIP) || shared.IsLoopbackIP(st.key.RespIP) {
			continue
		}
		var pids []int
		if rollupPID, ok := attr.outboundPIDFor(st.key.InitIP, st.key.RespIP); ok {
			pids = append(pids, rollupPID)
		}
		if flowPID, ok := attr.outboundFlowPIDFor(st.key.InitIP, st.key.RespIP, st.key.RespPort); ok {
			pids = append(pids, flowPID)
		}
		if len(pids) == 0 {
			continue
		}

		if st.tlsJA3 != "" {
			if set, ok := ja3Dests[sigKey{st.key.InitIP, st.tlsJA3}]; ok && len(set) == 1 {
				ja3 := st.tlsJA3
				for _, pid := range pids {
					addHit(pid, func(h *rareHit) {
						if h.ja3 == "" {
							h.ja3 = ja3
						}
					})
				}
			}
		}
		if st.tlsSNI != "" {
			sniLower := strings.ToLower(st.tlsSNI)
			if set, ok := sniDests[sigKey{st.key.InitIP, sniLower}]; ok && len(set) == 1 {
				sni := st.tlsSNI
				for _, pid := range pids {
					addHit(pid, func(h *rareHit) {
						if h.sni == "" {
							h.sni = sni
						}
					})
				}
			}
		}
		if ua := strings.TrimSpace(st.httpUserAgent); ua != "" {
			if set, ok := uaDests[sigKey{st.key.InitIP, ua}]; ok && len(set) == 1 {
				for _, pid := range pids {
					addHit(pid, func(h *rareHit) {
						if h.ua == "" {
							h.ua = ua
						}
					})
				}
			}
		}
	}

	if len(hits) == 0 {
		return
	}
	for i := range candidates {
		c := &candidates[i]
		if c.Proc == nil {
			continue
		}
		h := hits[c.Proc.Pid]
		if h == nil {
			continue
		}
		if h.ja3 != "" || h.sni != "" {
			c.Signals = shared.AppendUniqueSignal(c.Signals, "tls-rare-signature")
			reason := "TLS fingerprint reaches only one external destination from this host"
			if h.ja3 != "" {
				short := h.ja3
				if len(short) > 8 {
					short = short[:8]
				}
				reason += " (JA3 " + short + "…"
				if h.sni != "" {
					reason += " · SNI " + h.sni
				}
				reason += ")"
			} else if h.sni != "" {
				reason += " (SNI " + h.sni + ")"
			}
			c.Reasons = shared.AppendUniqueSignal(c.Reasons, reason)
		}
		if h.ua != "" {
			c.Signals = shared.AppendUniqueSignal(c.Signals, "http-rare-signature")
			short := h.ua
			if len(short) > 60 {
				short = short[:60] + "…"
			}
			c.Reasons = shared.AppendUniqueSignal(c.Reasons,
				"HTTP User-Agent reaches only one external destination from this host ("+short+")")
		}
	}
}
