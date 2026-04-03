package contour

import (
	"fmt"
	"sort"
	"strings"

	"proxywatch/internal/shared"
)

func buildProbeFindings(summary ProbeSummary) []Finding {
	if !summary.Enabled {
		return nil
	}
	findings := make([]Finding, 0, 10)
	if summary.Role == ProbeRoleListen {
		if summary.ListenerReady {
			severity := "strong"
			if summary.ListenerExchanges > 0 {
				severity = "active"
			}
			reason := fmt.Sprintf("Probe listener bound %d/%d target ports for %ds and processed %d exchange%s.", len(summary.Ports)-len(summary.PortsUnavailable), len(summary.Ports), summary.ListenerSeconds, summary.ListenerExchanges, plural(summary.ListenerExchanges))
			findings = append(findings, makeProbeFinding("tunnel", "listener-readiness", severity, "contour-probe-listener-ready", reason, map[string]any{
				"listener_seconds":   summary.ListenerSeconds,
				"listener_exchanges": summary.ListenerExchanges,
				"ports_total":        len(summary.Ports),
				"ports_unavailable":  summary.PortsUnavailable,
			}))
		} else {
			reason := "Probe listener could not bind any of the target ports."
			findings = append(findings, makeProbeFinding("escape", "listener-bind-failed", "watch", "contour-probe-listener-bind-failed", reason, map[string]any{
				"ports_unavailable": summary.PortsUnavailable,
			}))
		}
	}

	if summary.TunnelAttempts > 0 {
		ratio := float64(summary.TunnelSuccess) / float64(summary.TunnelAttempts)
		severity := "watch"
		switch {
		case ratio >= 0.80 && summary.TunnelSuccess >= 40:
			severity = "active"
		case ratio >= 0.40 && summary.TunnelSuccess >= 16:
			severity = "strong"
		}
		reason := fmt.Sprintf("Tunnel probe matrix succeeded on %d/%d protocol-port checks.", summary.TunnelSuccess, summary.TunnelAttempts)
		findings = append(findings, makeProbeFinding("tunnel", "multi-protocol-port-cycle", severity, "contour-probe-tunnel-matrix", reason, map[string]any{
			"mode":           summary.Mode,
			"endpoint":       summary.Endpoint,
			"ports":          summary.Ports,
			"protocol_count": len(summary.Protocols),
			"success":        summary.TunnelSuccess,
			"attempts":       summary.TunnelAttempts,
		}))
	}

	if summary.ExfilAttempts > 0 {
		ratio := float64(summary.ExfilSuccess) / float64(summary.ExfilAttempts)
		severity := "watch"
		switch {
		case ratio >= 0.80 && summary.ExfilSuccess >= 40:
			severity = "active"
		case ratio >= 0.40 && summary.ExfilSuccess >= 16:
			severity = "strong"
		}
		reason := fmt.Sprintf("Exfil probe matrix succeeded on %d/%d protocol-port checks.", summary.ExfilSuccess, summary.ExfilAttempts)
		findings = append(findings, makeProbeFinding("exfiltration", "multi-protocol-port-exfil", severity, "contour-probe-exfil-matrix", reason, map[string]any{
			"mode":           summary.Mode,
			"endpoint":       summary.Endpoint,
			"ports":          summary.Ports,
			"protocol_count": len(summary.Protocols),
			"success":        summary.ExfilSuccess,
			"attempts":       summary.ExfilAttempts,
		}))
	}

	if len(summary.PortsUnavailable) > 0 {
		reason := fmt.Sprintf("%d top ports were unavailable or returned no successful probe exchanges.", len(summary.PortsUnavailable))
		findings = append(findings, makeProbeFinding("escape", "blocked-probe-port", "watch", "contour-probe-port-unavailable", reason, map[string]any{
			"ports_unavailable": summary.PortsUnavailable,
		}))
	}

	if len(summary.InternetSubnets) > 0 {
		severity := "watch"
		if len(summary.InternetSubnets) >= 2 {
			severity = "strong"
		}
		reason := fmt.Sprintf("Detected %d internet-routable local subnet%s.", len(summary.InternetSubnets), plural(len(summary.InternetSubnets)))
		findings = append(findings, makeProbeFinding("network", "internet-usable-subnet", severity, "contour-probe-internet-subnets", reason, map[string]any{
			"internet_subnets": summary.InternetSubnets,
		}))
	}

	if summary.ReachableProxyCount > 0 {
		severity := "strong"
		if summary.ReachableProxyCount >= 3 {
			severity = "active"
		}
		reason := fmt.Sprintf("Detected %d reachable proxy endpoint%s from env and traffic analysis.", summary.ReachableProxyCount, plural(summary.ReachableProxyCount))
		findings = append(findings, makeProbeFinding("escape", "proxy-egress-endpoint", severity, "contour-probe-proxy-endpoint", reason, map[string]any{
			"reachable_proxies": summary.ReachableProxyCount,
			"proxy_total":       len(summary.Proxies),
			"pivot_proxies":     summary.PivotProxyCount,
			"pivot_target":      summary.ProxyPivotTarget,
		}))
	} else if len(summary.Proxies) > 0 {
		reason := fmt.Sprintf("Detected %d proxy endpoint%s, but none were reachable during active tests.", len(summary.Proxies), plural(len(summary.Proxies)))
		findings = append(findings, makeProbeFinding("escape", "proxy-endpoint-discovered", "watch", "contour-probe-proxy-discovered", reason, map[string]any{
			"proxy_total": len(summary.Proxies),
		}))
	}
	if summary.PivotProxyCount > 0 {
		severity := "strong"
		if summary.PivotProxyCount >= 2 {
			severity = "active"
		}
		reason := fmt.Sprintf("Verified %d reachable proxy endpoint%s can pivot to %s.", summary.PivotProxyCount, plural(summary.PivotProxyCount), nonEmpty(strings.TrimSpace(summary.ProxyPivotTarget), defaultProbePivotTarget))
		findings = append(findings, makeProbeFinding("escape", "proxy-pivot-path", severity, "contour-probe-proxy-pivot", reason, map[string]any{
			"pivot_proxies": summary.PivotProxyCount,
			"pivot_target":  nonEmpty(strings.TrimSpace(summary.ProxyPivotTarget), defaultProbePivotTarget),
		}))
	}

	if len(summary.ConfigEndpoints) > 0 {
		severity := "watch"
		if summary.ReachableConfigCount >= 2 {
			severity = "strong"
		}
		reason := fmt.Sprintf("Discovered %d endpoint%s in config files and environment context (%d reachable).", len(summary.ConfigEndpoints), plural(len(summary.ConfigEndpoints)), summary.ReachableConfigCount)
		findings = append(findings, makeProbeFinding("exfiltration", "config-endpoint-discovery", severity, "contour-probe-config-endpoint", reason, map[string]any{
			"config_endpoint_total":     len(summary.ConfigEndpoints),
			"config_endpoint_reachable": summary.ReachableConfigCount,
		}))
	}

	if len(summary.ServiceReachable) > 0 {
		severity := "strong"
		if len(summary.ServiceReachable) >= 5 {
			severity = "active"
		}
		reason := fmt.Sprintf("%d exfil-capable service%s reachable from this host: %s",
			len(summary.ServiceReachable), plural(len(summary.ServiceReachable)),
			strings.Join(summary.ServiceReachable, ", "))
		findings = append(findings, makeProbeFinding("exfiltration", "service-reachability", severity, "contour-probe-service-reachable", reason, map[string]any{
			"reachable_services": summary.ServiceReachable,
			"blocked_services":   summary.ServiceBlocked,
		}))
	}

	if summary.TLSIntercepted {
		reason := fmt.Sprintf("TLS interception detected — certificate issuer org: %s", summary.TLSInterceptOrg)
		findings = append(findings, makeProbeFinding("network", "tls-interception", "strong", "contour-probe-tls-intercept", reason, map[string]any{
			"tls_intercept_org": summary.TLSInterceptOrg,
		}))
	}

	if summary.DomainFrontingPossible {
		findings = append(findings, makeProbeFinding("escape", "domain-fronting", "active", "contour-probe-domain-fronting",
			fmt.Sprintf("Domain fronting possible: TLS handshake succeeded with SNI %s on target %s", summary.DomainFrontingSNI, summary.Endpoint),
			map[string]any{"sni": summary.DomainFrontingSNI}))
	}

	return normalizeFindings(findings)
}

func makeProbeFinding(category, technique, severity, signal, reason string, evidence map[string]any) Finding {
	return Finding{
		CandidateKey: "",
		Host:         "local",
		PID:          0,
		Process:      "contour-probe",
		Role:         "other",
		Category:     strings.TrimSpace(category),
		Technique:    strings.TrimSpace(technique),
		Severity:     shared.NormalizeContourSeverity(severity),
		Signal:       strings.TrimSpace(signal),
		Reason:       strings.TrimSpace(reason),
		Evidence:     evidence,
	}
}

func normalizeFindings(findings []Finding) []Finding {
	if len(findings) <= 1 {
		return findings
	}
	sort.SliceStable(findings, func(i, j int) bool {
		si := severityPriority(findings[i].Severity)
		sj := severityPriority(findings[j].Severity)
		if si != sj {
			return si > sj
		}
		if findings[i].Host != findings[j].Host {
			return findings[i].Host < findings[j].Host
		}
		if findings[i].Process != findings[j].Process {
			return findings[i].Process < findings[j].Process
		}
		if findings[i].PID != findings[j].PID {
			return findings[i].PID < findings[j].PID
		}
		return findings[i].Signal < findings[j].Signal
	})
	return dedupeFindings(findings)
}
