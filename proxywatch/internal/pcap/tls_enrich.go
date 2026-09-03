package pcap

import (
	"fmt"
	"strings"

	"proxywatch/internal/shared"
)

// enrichPcapWithTLSSignals scans flow-level TLS fingerprints populated
// by parseTLSClientHello and stamps signals on the matching cluster
// candidates. Mirrors enrichPcapWithHTTPSignals.
//
// Signals emitted:
//   - tls-ja3-known-c2     — DECISIVE; JA3 hash matches embedded C2 DB.
//     Cluster candidate is force-promoted via the
//     pcapDecisiveSignals role-guard path.
//   - tls-ja3-known-benign — soft suppressor; cluster carries a known-good
//     fingerprint (Chrome, Firefox, Edge, etc.).
//   - tls-ja3-observed     — soft context only; an unknown JA3 was observed.
//
// SNI is stamped on Reasons for operator visibility. The pass also seeds
// the candidate's TLSJA3 + TLSSNI fields so downstream UI / labeling /
// future TLS operator-label code can read them without re-parsing.
//
// FP-safety: tls-ja3-known-c2 only fires on positive match against the
// curated DB (curated for multi-source attribution, see tls_database.go).
// tls-ja3-known-benign and tls-ja3-observed are non-promoting.
func enrichPcapWithTLSSignals(flows []*flowState, attr *pcapAttribution, candidates []shared.Candidate) {
	if len(flows) == 0 || attr == nil || len(candidates) == 0 {
		return
	}

	// Cross-flow JA3 clustering — index per-(client-host, JA3) → set of
	// EXTERNAL destination IPs. Same JA3 across 2-10 distinct external
	// destinations from one host is the signature of a single client
	// process talking to a small failover list — implants do this
	// (Sliver / Cobalt / Mythic ship with a multi-server config), and
	// browsers do NOT (Chrome/Firefox hit hundreds of endpoints, all
	// with the same JA3, which DOES land in this bucket but is filtered
	// by the upper bound). Browser fingerprints in the known-benign DB
	// are excluded outright. Internal-only destinations are excluded
	// because admin tools (SSH/RDP/file shares) trip the same shape.
	type ja3Key struct {
		host string
		ja3  string
	}
	ja3Dests := make(map[ja3Key]map[string]struct{})
	for _, st := range flows {
		if st == nil || st.tlsJA3 == "" {
			continue
		}
		// Skip known-benign JA3s — Chrome/Edge/Firefox hit hundreds of
		// destinations, no value in flagging multi-destination on them.
		if _, verdict := LookupJA3(st.tlsJA3); verdict == "benign" {
			continue
		}
		// External destinations only — admin SSH / RDP / file shares
		// to internal IPs would otherwise pollute this bucket.
		if shared.IsLoopbackIP(st.key.RespIP) || shared.IsInternalIP(st.key.RespIP) {
			continue
		}
		k := ja3Key{host: st.key.InitIP, ja3: st.tlsJA3}
		set, ok := ja3Dests[k]
		if !ok {
			set = make(map[string]struct{})
			ja3Dests[k] = set
		}
		set[st.key.RespIP] = struct{}{}
	}
	multiDestJA3 := make(map[ja3Key]int)     // key → distinct dest count (2-10 = implant failover)
	browserFanoutJA3 := make(map[ja3Key]int) // key → distinct dest count (>10 = browser fanout)
	for k, dests := range ja3Dests {
		switch {
		case len(dests) >= 2 && len(dests) <= 10:
			// 2-10 destinations: implant failover list pattern.
			multiDestJA3[k] = len(dests)
		case len(dests) > 10:
			// >10 destinations: browser-like fan-out. Stamp a benign
			// suppressor so the role-guard's beacon-shape conjunction
			// rescue ignores this cluster. PURELY DATA-DRIVEN — no
			// hardcoded JA3 lists, the benign verdict comes from the
			// observed multi-destination shape of the JA3 in THIS pcap.
			browserFanoutJA3[k] = len(dests)
		}
	}

	type matchSet struct {
		hasKnownC2       bool
		hasKnownBenign   bool
		hasObserved      bool
		hasKnownC2Server bool
		hasMultiDest     bool
		hasFanout        bool
		fanoutCount      int
		multiDestCount   int
		c2Label          string
		benignLabel      string
		c2ServerLabel    string
		ja3Hash          string
		ja3sHash         string
		sniSeen          map[string]struct{}
	}
	pidMatches := make(map[int]*matchSet)
	get := func(pid int) *matchSet {
		ms, ok := pidMatches[pid]
		if !ok {
			ms = &matchSet{sniSeen: make(map[string]struct{})}
			pidMatches[pid] = ms
		}
		return ms
	}

	for _, st := range flows {
		if st == nil {
			continue
		}
		hasClientFP := st.tlsParseAttempted && (st.tlsJA3 != "" || st.tlsSNI != "")
		hasServerFP := st.tlsServerParseAttempted && st.tlsJA3S != ""
		if !hasClientFP && !hasServerFP {
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

		label, verdict := LookupJA3(st.tlsJA3)
		serverLabel, serverVerdict := LookupJA3S(st.tlsJA3S)
		multiCount := 0
		fanoutCount := 0
		if st.tlsJA3 != "" {
			k := ja3Key{host: st.key.InitIP, ja3: st.tlsJA3}
			multiCount = multiDestJA3[k]
			fanoutCount = browserFanoutJA3[k]
		}
		for _, pid := range pids {
			ms := get(pid)
			if st.tlsJA3 != "" {
				ms.ja3Hash = st.tlsJA3
			}
			if st.tlsJA3S != "" {
				ms.ja3sHash = st.tlsJA3S
			}
			switch verdict {
			case "c2":
				ms.hasKnownC2 = true
				ms.c2Label = label
			case "benign":
				ms.hasKnownBenign = true
				ms.benignLabel = label
			default:
				if st.tlsJA3 != "" {
					ms.hasObserved = true
				}
			}
			if serverVerdict == "c2" {
				ms.hasKnownC2Server = true
				ms.c2ServerLabel = serverLabel
			}
			if multiCount > 0 {
				ms.hasMultiDest = true
				if multiCount > ms.multiDestCount {
					ms.multiDestCount = multiCount
				}
			}
			if fanoutCount > 0 {
				ms.hasFanout = true
				if fanoutCount > ms.fanoutCount {
					ms.fanoutCount = fanoutCount
				}
			}
			if st.tlsSNI != "" {
				ms.sniSeen[strings.TrimSpace(st.tlsSNI)] = struct{}{}
			}
		}
	}

	if len(pidMatches) == 0 {
		return
	}

	for i := range candidates {
		c := &candidates[i]
		if c.Proc == nil {
			continue
		}
		ms := pidMatches[c.Proc.Pid]
		if ms == nil {
			continue
		}
		switch {
		case ms.hasKnownC2:
			// Operator-confirmed FP 2026-05-04: tls-ja3-known-c2 was
			// firing on legitimate Microsoft Azure / Edge / Akamai
			// CDN traffic when the same JA3 was ALSO observed
			// browser-fanning across many destinations. A REAL C2
			// JA3 only contacts the C2 server (≤2 dests). A
			// JA3-DB collision with a generic client (Go's
			// crypto/tls default, Edge's WinHTTP) hits dozens
			// of unrelated services. The fanout shape veto
			// resolves the collision — without this gate, every
			// legit Azure SDK client trips known-c2 and gets
			// rescued via pcapDecisiveSignals.
			if ms.hasFanout {
				// Demote to soft observation so the fingerprint
				// still appears in the SIGNALS panel but doesn't
				// drive promotion via HasPacketDecisiveSignal.
				c.Signals = appendUniqueSignal(c.Signals, "tls-ja3-observed")
				c.Reasons = appendUniqueSignal(c.Reasons,
					"TLS JA3 ("+ms.ja3Hash+") matched "+ms.c2Label+" but fans out across many destinations — likely JA3-collision with legit client, not an implant fingerprint")
			} else {
				c.Signals = appendUniqueSignal(c.Signals, "tls-ja3-known-c2")
				c.Reasons = appendUniqueSignal(c.Reasons,
					"TLS JA3 matches "+ms.c2Label+" ("+ms.ja3Hash+")")
			}
		case ms.hasKnownBenign:
			c.Signals = appendUniqueSignal(c.Signals, "tls-ja3-known-benign")
			c.Reasons = appendUniqueSignal(c.Reasons,
				"TLS JA3 matches benign client "+ms.benignLabel+" ("+ms.ja3Hash+")")
		case ms.hasObserved:
			c.Signals = appendUniqueSignal(c.Signals, "tls-ja3-observed")
		}
		if ms.hasKnownC2Server {
			c.Signals = appendUniqueSignal(c.Signals, "tls-ja3s-known-c2")
			c.Reasons = appendUniqueSignal(c.Reasons,
				"TLS JA3S (server) matches "+ms.c2ServerLabel+" ("+ms.ja3sHash+")")
		}
		if ms.hasMultiDest {
			c.Signals = appendUniqueSignal(c.Signals, "tls-ja3-multi-destination")
			c.Reasons = appendUniqueSignal(c.Reasons,
				fmt.Sprintf("TLS JA3 %s seen across %d external destinations from one client",
					ms.ja3Hash, ms.multiDestCount))
		}
		if ms.hasFanout {
			// Dynamic benign suppressor: this JA3 fan-out across
			// >10 distinct external destinations from one client is
			// browser-shape, not implant-shape. The role-guard's
			// beacon-conjunction rescue checks this signal to skip
			// promotion of CDN+HTTP+beacon-shape clusters that are
			// actually browser/SaaS traffic.
			c.Signals = appendUniqueSignal(c.Signals, "tls-ja3-browser-fanout")
			c.Reasons = appendUniqueSignal(c.Reasons,
				fmt.Sprintf("TLS JA3 %s seen across %d destinations (browser fan-out, benign)",
					ms.ja3Hash, ms.fanoutCount))
		}
		if len(ms.sniSeen) > 0 {
			snis := make([]string, 0, len(ms.sniSeen))
			for s := range ms.sniSeen {
				if s == "" {
					continue
				}
				snis = append(snis, s)
			}
			if len(snis) > 0 {
				c.Reasons = appendUniqueSignal(c.Reasons, "TLS SNI: "+strings.Join(snis, ", "))
			}
		}
	}
}
