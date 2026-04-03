package siem

import (
	"fmt"
	"strings"
)

func buildSIEMSplunkQuery(det SIEMDetection) string {
	parts := []string{`index=<endpoint_index>`, `sourcetype=<endpoint_network_or_edr>`}
	clauses := make([]string, 0, 3)
	clauses = append(clauses, `proxywatch_role="`+escapeSIEMQuery(det.Role)+`"`)
	if len(det.Processes) > 0 {
		procVals := make([]string, 0, len(det.Processes))
		for _, p := range det.Processes {
			procVals = append(procVals, `"`+escapeSIEMQuery(p)+`"`)
		}
		clauses = append(clauses, "process_name IN ("+strings.Join(procVals, ",")+")")
	}
	if len(det.Signals) > 0 {
		sigVals := make([]string, 0, len(det.Signals))
		for _, s := range det.Signals {
			sigVals = append(sigVals, `"`+escapeSIEMQuery(s)+`"`)
		}
		clauses = append(clauses, "signal IN ("+strings.Join(sigVals, ",")+")")
	}
	parts = append(parts, "("+strings.Join(clauses, " OR ")+")")
	parts = append(parts, `| stats count min(_time) as first_seen max(_time) as last_seen by host process_name dest_ip dest_port signal`)
	return strings.Join(parts, " ")
}

func buildSIEMKQLQuery(det SIEMDetection) string {
	lines := []string{
		"DeviceNetworkEvents",
		`| where tostring(AdditionalFields.ProxywatchRole) =~ "` + escapeSIEMQuery(det.Role) + `"`,
	}
	if len(det.Processes) > 0 {
		vals := make([]string, 0, len(det.Processes))
		for _, p := range det.Processes {
			vals = append(vals, `"`+escapeSIEMQuery(p)+`"`)
		}
		lines = append(lines, "| where InitiatingProcessFileName in~ ("+strings.Join(vals, ", ")+")")
	}
	if len(det.Signals) > 0 {
		vals := make([]string, 0, len(det.Signals))
		for _, s := range det.Signals {
			vals = append(vals, `"`+escapeSIEMQuery(s)+`"`)
		}
		lines = append(lines, "| where tostring(AdditionalFields.ProxywatchSignal) in~ ("+strings.Join(vals, ", ")+")")
	}
	lines = append(lines, "| summarize hits=count(), first_seen=min(Timestamp), last_seen=max(Timestamp) by DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort")
	return strings.Join(lines, "\n")
}

func buildSIEMElasticQuery(det SIEMDetection) string {
	lines := []string{"from logs-endpoint.events.network*"}
	lines = append(lines, `| where proxywatch.role == "`+escapeSIEMQuery(det.Role)+`"`)
	if len(det.Processes) > 0 {
		vals := make([]string, 0, len(det.Processes))
		for _, p := range det.Processes {
			vals = append(vals, `"`+escapeSIEMQuery(p)+`"`)
		}
		lines = append(lines, "| where process.name in ("+strings.Join(vals, ", ")+")")
	}
	if len(det.Signals) > 0 {
		vals := make([]string, 0, len(det.Signals))
		for _, s := range det.Signals {
			vals = append(vals, `"`+escapeSIEMQuery(s)+`"`)
		}
		lines = append(lines, "| where proxywatch.signal in ("+strings.Join(vals, ", ")+")")
	}
	lines = append(lines, "| stats hits = count(*) by host.name, process.name, destination.ip, destination.port")
	return strings.Join(lines, "\n")
}

func buildSIEMSigma(det SIEMDetection) map[string]any {
	selection := map[string]any{
		"ProxywatchRole": det.Role,
	}
	if len(det.Processes) > 0 {
		selection["ProcessName|contains"] = det.Processes
	}
	if len(det.Signals) > 0 {
		selection["ProxywatchSignal|contains"] = det.Signals
	}
	return map[string]any{
		"title":       det.Title,
		"id":          det.ID,
		"status":      "experimental",
		"description": det.Description,
		"logsource": map[string]any{
			"category": "network_connection",
			"product":  "windows",
		},
		"detection": map[string]any{
			"selection": selection,
			"condition": "selection",
		},
		"level": det.Severity,
	}
}

func buildSIEMYARA(det SIEMDetection) string {
	if len(det.Processes) == 0 {
		return ""
	}
	var b strings.Builder
	ruleName := strings.ReplaceAll(det.ID, "-", "_")
	b.WriteString(fmt.Sprintf("rule %s {\n", ruleName))
	b.WriteString("    meta:\n")
	b.WriteString(fmt.Sprintf("        description = \"%s\"\n", escapeSIEMQuery(det.Title)))
	b.WriteString(fmt.Sprintf("        severity = \"%s\"\n", det.Severity))
	if len(det.Techniques) > 0 {
		b.WriteString(fmt.Sprintf("        mitre = \"%s\"\n", strings.Join(det.Techniques, ",")))
	}
	b.WriteString(fmt.Sprintf("        role = \"%s\"\n", det.Role))
	b.WriteString("    strings:\n")
	for i, proc := range det.Processes {
		if i >= 10 {
			break
		}
		escaped := strings.ReplaceAll(proc, "\\", "\\\\")
		b.WriteString(fmt.Sprintf("        $proc%d = \"%s\" ascii nocase\n", i, escaped))
	}
	for i, sig := range det.Signals {
		if i >= 5 {
			break
		}
		b.WriteString(fmt.Sprintf("        $sig%d = \"%s\" ascii nocase\n", i, sig))
	}
	b.WriteString("    condition:\n")
	b.WriteString("        any of ($proc*) or any of ($sig*)\n")
	b.WriteString("}\n")
	return b.String()
}

func buildSIEMSuricata(det SIEMDetection) string {
	if len(det.Processes) == 0 {
		return ""
	}
	var rules []string
	sid := 3000000 // base SID for proxywatch-generated rules
	for i, proc := range det.Processes {
		if i >= 5 {
			break
		}
		rule := fmt.Sprintf(
			"alert tcp $HOME_NET any -> $EXTERNAL_NET any "+
				"(msg:\"PROXYWATCH %s - %s\"; "+
				"content:\"%s\"; nocase; "+
				"classtype:trojan-activity; "+
				"sid:%d; rev:1;"+
				")",
			det.Role, escapeSIEMQuery(proc),
			escapeSIEMQuery(proc),
			sid+i,
		)
		if len(det.Techniques) > 0 {
			rule = strings.TrimSuffix(rule, ")")
			rule += fmt.Sprintf(" metadata:mitre_technique %s;)", strings.Join(det.Techniques, ","))
		}
		rules = append(rules, rule)
	}
	return strings.Join(rules, "\n")
}

func escapeSIEMQuery(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	v = strings.ReplaceAll(v, "\\", "\\\\")
	v = strings.ReplaceAll(v, `"`, `\\"`)
	return v
}
