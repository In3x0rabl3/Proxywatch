package shared

import "strings"

// DisplayProcessName returns a UI-friendly process label.
func DisplayProcessName(p *ProcessInfo) string {
	if p == nil {
		return "(unknown)"
	}
	name := strings.TrimSpace(p.Name)
	if name == "" {
		name = "(unknown)"
	}
	if apt := aptMethodDisplayName(p.ExePath); apt != "" {
		return apt
	}
	return name
}

// IsProxywatchProcess identifies Proxywatch runtime binaries so they can be
// hidden from operator-facing candidate views.
func IsProxywatchProcess(p *ProcessInfo) bool {
	if p == nil {
		return false
	}
	path := strings.ToLower(strings.TrimSpace(p.ExePath))
	if path == "" {
		return false
	}
	path = strings.ReplaceAll(path, "\\", "/")
	base := path
	if idx := strings.LastIndexByte(base, '/'); idx >= 0 && idx+1 < len(base) {
		base = base[idx+1:]
	}
	name := strings.ToLower(strings.TrimSpace(p.Name))
	if !hasProxywatchBinaryName(base) && !hasProxywatchBinaryName(name) {
		return false
	}
	// Hide proxywatch runtime binaries regardless of where they are launched
	// from (for example release binaries run from Downloads).
	return true
}

// FilterProxywatchCandidates removes Proxywatch runtime processes from candidate lists.
func FilterProxywatchCandidates(cands []Candidate) []Candidate {
	if len(cands) == 0 {
		return cands
	}
	out := make([]Candidate, 0, len(cands))
	for _, c := range cands {
		if IsProxywatchProcess(c.Proc) {
			continue
		}
		out = append(out, c)
	}
	return out
}

func hasProxywatchBinaryName(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return false
	}
	if name == "pwa" || name == "pwa.exe" {
		return true
	}
	if name == "proxywatch" || name == "proxywatch.exe" {
		return true
	}
	// Keep support for versioned build names like proxywatch17(.exe).
	if strings.HasPrefix(name, "proxywatch") {
		return true
	}
	return false
}

func isTrustedProxywatchPath(path string) bool {
	path = strings.ToLower(strings.TrimSpace(path))
	if path == "" {
		return false
	}
	path = strings.ReplaceAll(path, "\\", "/")
	if strings.Contains(path, "/opt/proxywatch/") ||
		strings.Contains(path, "/.proxywatch/") ||
		strings.Contains(path, "/program files/proxywatch/") ||
		strings.Contains(path, "/programdata/proxywatch/") {
		return true
	}
	// Match common source/build locations to hide local proxywatch runtime binaries.
	return strings.Contains(path, "/proxywatch/build/") || strings.Contains(path, "/proxywatch/cmd/")
}

func aptMethodDisplayName(exePath string) string {
	path := strings.ToLower(strings.TrimSpace(exePath))
	if path == "" {
		return ""
	}
	path = strings.ReplaceAll(path, "\\", "/")
	const prefix = "/usr/lib/apt/methods/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	method := strings.TrimPrefix(path, prefix)
	if method == "" {
		return ""
	}
	if slash := strings.IndexByte(method, '/'); slash >= 0 {
		method = method[:slash]
	}
	method = strings.TrimSpace(method)
	if method == "" {
		return ""
	}
	return "apt-" + method
}
