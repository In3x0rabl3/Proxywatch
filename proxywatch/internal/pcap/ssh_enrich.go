package pcap

import (
	"strings"

	"proxywatch/internal/shared"
)

// enrichPcapWithSSHBannerSignals scans flow-level SSH banners populated
// by parseSSHBanner and stamps signals on the matching cluster
// candidates. Mirrors enrichPcapWithHTTPSignals / enrichPcapWithTLSSignals.
//
// Signals emitted:
//   - ssh-banner-known-c2     — DECISIVE; client OR server banner
//     matches an embedded C2-framework name
//     (Sliver, Cobalt Strike, Mythic, etc.).
//   - ssh-banner-known-benign — soft suppressor; banner matches stock
//     OS / vendor SSH (OpenSSH, libssh,
//     PuTTY, WinSCP, ...). Used by FP scrub
//     to demote.
//   - ssh-banner-observed     — soft context only; an unknown SSH
//     banner was observed on the flow.
//
// The raw banner string + software token go on the candidate's
// Reasons slice for operator visibility, alongside SNI / JA3 entries.
//
// FP-safety: ssh-banner-known-c2 only fires on positive match against
// the curated framework table (single-source false positives are rare
// because frameworks ship distinctive default banners — Sliver's Go
// banner, Cobalt Strike's SSH listener, etc. don't accidentally appear
// on stock systems).
func enrichPcapWithSSHBannerSignals(flows []*flowState, attr *pcapAttribution, candidates []shared.Candidate) {
	if len(flows) == 0 || attr == nil || len(candidates) == 0 {
		return
	}

	type matchSet struct {
		hasKnownC2     bool
		hasKnownBenign bool
		hasObserved    bool
		c2Label        string
		benignLabel    string
		clientBanner   string
		serverBanner   string
	}
	pidMatches := make(map[int]*matchSet)
	get := func(pid int) *matchSet {
		ms, ok := pidMatches[pid]
		if !ok {
			ms = &matchSet{}
			pidMatches[pid] = ms
		}
		return ms
	}

	for _, st := range flows {
		if st == nil {
			continue
		}
		hasClient := st.sshClientBannerAttempted && st.sshClientBanner != ""
		hasServer := st.sshServerBannerAttempted && st.sshServerBanner != ""
		if !hasClient && !hasServer {
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

		clientLabel, clientVerdict := LookupSSHBanner(st.sshClientSoftware)
		serverLabel, serverVerdict := LookupSSHBanner(st.sshServerSoftware)

		for _, pid := range pids {
			ms := get(pid)
			if hasClient {
				ms.clientBanner = st.sshClientBanner
			}
			if hasServer {
				ms.serverBanner = st.sshServerBanner
			}
			switch {
			case clientVerdict == "c2":
				ms.hasKnownC2 = true
				ms.c2Label = clientLabel + " (client banner)"
			case serverVerdict == "c2":
				ms.hasKnownC2 = true
				ms.c2Label = serverLabel + " (server banner)"
			case clientVerdict == "benign" || serverVerdict == "benign":
				ms.hasKnownBenign = true
				if clientVerdict == "benign" {
					ms.benignLabel = clientLabel
				} else {
					ms.benignLabel = serverLabel
				}
			case hasClient || hasServer:
				ms.hasObserved = true
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
			c.Signals = appendUniqueSignal(c.Signals, "ssh-banner-known-c2")
			c.Reasons = appendUniqueSignal(c.Reasons,
				"SSH banner matches "+ms.c2Label)
		case ms.hasKnownBenign:
			c.Signals = appendUniqueSignal(c.Signals, "ssh-banner-known-benign")
			c.Reasons = appendUniqueSignal(c.Reasons,
				"SSH banner matches benign client/server "+ms.benignLabel)
		case ms.hasObserved:
			c.Signals = appendUniqueSignal(c.Signals, "ssh-banner-observed")
		}
		if ms.clientBanner != "" || ms.serverBanner != "" {
			parts := []string{}
			if ms.clientBanner != "" {
				parts = append(parts, "client="+ms.clientBanner)
			}
			if ms.serverBanner != "" {
				parts = append(parts, "server="+ms.serverBanner)
			}
			c.Reasons = appendUniqueSignal(c.Reasons, "SSH: "+strings.Join(parts, ", "))
		}
	}
}
