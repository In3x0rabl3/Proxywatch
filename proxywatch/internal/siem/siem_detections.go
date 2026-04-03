package siem

import (
	"fmt"
	"strings"

	"proxywatch/internal/calibration"
	"proxywatch/internal/shared"
)

func buildSIEMDetections(report calibration.Report, roleStats map[string]*siemRoleStats, aiDetections []aiSIEMDetection) []SIEMDetection {
	out := make([]SIEMDetection, 0, 12)
	if len(aiDetections) > 0 {
		for _, det := range aiDetections {
			role := normalizeSIEMRole(det.Role)
			st := roleStats[role]
			procNames := sanitizeAndFallbackList(det.Processes, st, "process")
			signals := sanitizeAndFallbackSignals(det.Signals, st)
			reasons := sanitizeAndFallbackReasons(det.Reasons, st)
			severity := normalizeSeverity(det.Severity, role)
			title := strings.TrimSpace(det.Title)
			if title == "" {
				title = defaultSIEMDetectionTitle(role)
			}
			desc := strings.TrimSpace(det.Description)
			if desc == "" {
				desc = fallbackSIEMDescription(role, st, procNames)
			}
			out = append(out, makeSIEMDetection(role, severity, title, desc, procNames, signals, reasons))
		}
	}

	if len(out) == 0 {
		roles := orderedRoleFamiliesFromReport(report, roleStats)
		for _, role := range roles {
			st := roleStats[role]
			procNames := topMapKeys(st.Processes, 5)
			signals := topMapKeys(st.Signals, 8)
			reasons := topMapKeys(st.Reasons, 5)
			out = append(out, makeSIEMDetection(
				role,
				normalizeSeverity("", role),
				defaultSIEMDetectionTitle(role),
				fallbackSIEMDescription(role, st, procNames),
				procNames,
				signals,
				reasons,
			))
		}
	}

	if len(out) == 0 {
		out = append(out, makeSIEMDetection(
			"other",
			"low",
			"Proxywatch behavioral outlier",
			"Alert on process network behavior that deviates from calibrated baseline.",
			nil,
			nil,
			nil,
		))
	}

	// Attach calibrated thresholds from the report so downstream SIEM
	// consumers can reference the tuned values in alert logic.
	ctx := calibrationContextFromReport(report)

	seen := make(map[string]bool, len(out))
	filtered := make([]SIEMDetection, 0, len(out))
	for _, det := range out {
		if seen[det.ID] {
			continue
		}
		seen[det.ID] = true
		det.CalibrationContext = ctx
		filtered = append(filtered, det)
	}
	return filtered
}

func calibrationContextFromReport(report calibration.Report) *SIEMCalibrationCtx {
	s := report.Settings
	if s.BeaconSleepThreshold == "" && s.BeaconJitterCoVMax == 0 && s.ShapeDeltaThreshold == 0 && s.ReverseStickyScore == 0 {
		return nil
	}
	return &SIEMCalibrationCtx{
		BeaconSleepThreshold: s.BeaconSleepThreshold,
		BeaconJitterCoVMax:   fmt.Sprintf("%.2f", s.BeaconJitterCoVMax),
		ShapeDeltaThreshold:  fmt.Sprintf("%.2f", s.ShapeDeltaThreshold),
		ReverseStickyScore:   s.ReverseStickyScore,
		Confidence:           report.Confidence,
	}
}

func makeSIEMDetection(role, severity, title, description string, processes, signals, reasons []string) SIEMDetection {
	role = normalizeSIEMRole(role)
	if role == "" {
		role = "other"
	}
	processes = sanitizeStringList(processes, 6)
	signals = sanitizeStringList(signals, 10)
	reasons = sanitizeStringList(reasons, 8)
	id := strings.ToLower(strings.ReplaceAll(role+"-"+title, " ", "-"))
	id = sanitizeDetectionID(id)
	det := SIEMDetection{
		ID:          id,
		Title:       strings.TrimSpace(title),
		Role:        role,
		Severity:    normalizeSeverity(severity, role),
		Description: strings.TrimSpace(description),
		Processes:   processes,
		Signals:     signals,
		Reasons:     reasons,
		Techniques:  shared.MITRETechniques(role),
		Tactics:     shared.MITRETactics(role),
	}
	det.Queries = SIEMQueries{
		Splunk:   buildSIEMSplunkQuery(det),
		KQL:      buildSIEMKQLQuery(det),
		Elastic:  buildSIEMElasticQuery(det),
		Sigma:    buildSIEMSigma(det),
		YARA:     buildSIEMYARA(det),
		Suricata: buildSIEMSuricata(det),
	}
	return det
}

func sanitizeDetectionID(id string) string {
	id = strings.TrimSpace(strings.ToLower(id))
	if id == "" {
		return "proxywatch-detection"
	}
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "proxywatch-detection"
	}
	return out
}

func normalizeSIEMRole(role string) string {
	s := strings.ToLower(strings.TrimSpace(role))
	switch s {
	case "control-session", "control-channel":
		return "control-session"
	case "control-beacon":
		return "control-beacon"
	case "control-pivot", "smb-pipe":
		return "control-pivot"
	case "control-tunnel", "tunnel":
		return "control-tunnel"
	case "analyzing":
		return "analyzing"
	case "listen", "listener":
		return "listener"
	case "outbound":
		return "outbound"
	default:
		return "other"
	}
}

func normalizeSeverity(raw, role string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch s {
	case "low", "medium", "high", "critical":
		return s
	}
	switch normalizeSIEMRole(role) {
	case "control-session", "control-beacon", "control-tunnel", "control-pivot":
		return "high"
	case "analyzing":
		return "medium"
	case "listener":
		return "medium"
	case "outbound":
		return "low"
	default:
		return "low"
	}
}

func defaultSIEMDetectionTitle(role string) string {
	switch normalizeSIEMRole(role) {
	case "control-session":
		return "Persistent control-session behavior"
	case "control-beacon":
		return "Periodic beacon callback behavior"
	case "control-pivot":
		return "Pivot or lateral movement pattern"
	case "control-tunnel":
		return "Tunnel traffic pattern"
	case "analyzing":
		return "Process under behavioral analysis"
	case "listener":
		return "Unexpected listener exposure"
	case "outbound":
		return "Anomalous outbound pattern"
	default:
		return "Behavioral outlier"
	}
}

func fallbackSIEMDescription(role string, st *siemRoleStats, processes []string) string {
	count := 0
	if st != nil {
		count = st.Count
	}
	procText := ""
	if len(processes) > 0 {
		procText = " Top processes: " + strings.Join(processes, ", ") + "."
	}
	switch normalizeSIEMRole(role) {
	case "control-session":
		return fmt.Sprintf("Detected %d calibration samples with stable control-session characteristics.%s", count, procText)
	case "control-beacon":
		return fmt.Sprintf("Detected %d calibration samples with periodic beacon callback characteristics.%s", count, procText)
	case "control-pivot":
		return fmt.Sprintf("Detected %d calibration samples consistent with pivot/lateral movement traffic.%s", count, procText)
	case "control-tunnel":
		return fmt.Sprintf("Detected %d calibration samples consistent with tunnel traffic.%s", count, procText)
	case "analyzing":
		return fmt.Sprintf("Detected %d calibration samples still under behavioral analysis.%s", count, procText)
	case "listener":
		return fmt.Sprintf("Detected %d calibration samples with listener behavior.%s", count, procText)
	case "outbound":
		return fmt.Sprintf("Detected %d calibration samples with sustained outbound traffic.%s", count, procText)
	default:
		return fmt.Sprintf("Detected %d calibration samples with behavior deviations.%s", count, procText)
	}
}

func sanitizeAndFallbackList(values []string, st *siemRoleStats, kind string) []string {
	clean := sanitizeStringList(values, 6)
	if len(clean) > 0 {
		return clean
	}
	if st == nil {
		return nil
	}
	switch kind {
	case "process":
		return topMapKeys(st.Processes, 6)
	default:
		return nil
	}
}

func sanitizeAndFallbackSignals(values []string, st *siemRoleStats) []string {
	clean := sanitizeStringList(values, 10)
	if len(clean) > 0 {
		return clean
	}
	if st == nil {
		return nil
	}
	return topMapKeys(st.Signals, 10)
}

func sanitizeAndFallbackReasons(values []string, st *siemRoleStats) []string {
	clean := sanitizeStringList(values, 8)
	if len(clean) > 0 {
		return clean
	}
	if st == nil {
		return nil
	}
	return topMapKeys(st.Reasons, 8)
}
