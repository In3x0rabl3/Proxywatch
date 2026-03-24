package shared

import "strings"

// IsLikelyBenignBeacon heuristically skips known-legit updater/AV beacons.
func IsLikelyBenignBeacon(p *ProcessInfo) bool {
	if p == nil {
		return false
	}
	if !IsLikelyBenignControlClient(p) {
		return false
	}
	path := normalizeExePath(p.ExePath)
	if path == "" {
		return false
	}
	if strings.Contains(path, "/tmp/") ||
		strings.Contains(path, "/var/tmp/") ||
		strings.Contains(path, "/downloads/") ||
		strings.Contains(path, "/appdata/local/temp/") {
		return false
	}
	return true
}

func IsLikelyBenignControlClient(p *ProcessInfo) bool {
	if p == nil {
		return false
	}
	path := normalizeExePath(p.ExePath)
	if path == "" {
		return false
	}

	roots := []string{
		"/usr/",
		"/bin/",
		"/sbin/",
		"/lib/",
		"/lib64/",
		"/opt/",
		"/snap/",
		"/nix/store/",
		"c:/windows/",
		"c:/program files/",
		"c:/program files (x86)/",
	}
	for _, root := range roots {
		if strings.HasPrefix(path, root) {
			return true
		}
	}

	// Some trusted Windows services ship in ProgramData vendor paths.
	// Treat those as benign only when the vendor path segment aligns with
	// publisher metadata and the process runs in a service-like security context.
	if strings.HasPrefix(path, "c:/programdata/") &&
		isServiceLikeContext(p) &&
		programDataVendorMatchesCompany(path, p.Company) {
		return true
	}

	// Some trusted user-scoped clients install under AppData vendor folders.
	// Treat those as benign only when the vendor folder aligns with publisher metadata.
	if userAppDataVendorMatchesCompany(path, p.Company) {
		return true
	}

	return false
}

func normalizeExePath(path string) string {
	path = strings.ToLower(strings.TrimSpace(path))
	return strings.ReplaceAll(path, "\\", "/")
}

func isServiceLikeContext(p *ProcessInfo) bool {
	if p == nil {
		return false
	}
	user := strings.ToLower(strings.TrimSpace(p.UserName))
	integrity := strings.ToLower(strings.TrimSpace(p.Integrity))

	switch integrity {
	case "system", "protected":
		return true
	}

	if strings.Contains(user, "nt authority\\") {
		return true
	}
	if strings.Contains(user, "local service") || strings.Contains(user, "network service") {
		return true
	}
	if strings.HasSuffix(user, "\\system") {
		return true
	}
	return false
}

func programDataVendorMatchesCompany(path, company string) bool {
	const prefix = "c:/programdata/"
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	company = strings.ToLower(strings.TrimSpace(company))
	if company == "" {
		return false
	}

	rel := strings.TrimPrefix(path, prefix)
	slash := strings.IndexByte(rel, '/')
	if slash <= 0 {
		return false
	}
	vendor := strings.TrimSpace(rel[:slash])
	if len(vendor) < 3 {
		return false
	}

	return strings.Contains(company, vendor)
}

func userAppDataVendorMatchesCompany(path, company string) bool {
	company = strings.ToLower(strings.TrimSpace(company))
	if company == "" {
		return false
	}
	if !strings.HasPrefix(path, "c:/users/") {
		return false
	}

	markers := []string{
		"/appdata/local/",
		"/appdata/locallow/",
		"/appdata/roaming/",
	}
	rel := ""
	for _, marker := range markers {
		if idx := strings.Index(path, marker); idx >= 0 {
			rel = path[idx+len(marker):]
			break
		}
	}
	if rel == "" {
		return false
	}

	slash := strings.IndexByte(rel, '/')
	if slash <= 0 {
		return false
	}
	vendor := strings.TrimSpace(rel[:slash])
	if len(vendor) < 3 {
		return false
	}
	switch vendor {
	case "temp", "tmp", "downloads":
		return false
	}
	return strings.Contains(company, vendor)
}
