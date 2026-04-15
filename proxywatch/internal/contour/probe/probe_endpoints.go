package probe

import (
	"context"
	"crypto/tls"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"proxywatch/internal/safeio"
	"proxywatch/internal/shared"
)

var (
	endpointHostLabelRE     = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	endpointTimestampHostRE = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}t\d{2}$`)
)

func discoverRouteHints(ctx context.Context) ([]string, []string) {
	if ctx == nil {
		ctx = context.Background()
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil
	}
	routes := make([]string, 0, 12)
	internet := make([]string, 0, 4)
	seenRoute := make(map[string]struct{})
	seenInternet := make(map[string]struct{})
	for _, iface := range ifaces {
		if err := ctx.Err(); err != nil {
			break
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if err := ctx.Err(); err != nil {
				break
			}
			netCIDR := strings.TrimSpace(addr.String())
			if netCIDR == "" {
				continue
			}
			ip, _, err := net.ParseCIDR(netCIDR)
			if err != nil || ip == nil || ip.IsLoopback() {
				continue
			}
			if shared.IsInternalIP(ip.String()) {
				route := iface.Name + " " + netCIDR
				if _, ok := seenRoute[route]; !ok {
					seenRoute[route] = struct{}{}
					routes = append(routes, route)
				}
				continue
			}
			if _, ok := seenInternet[netCIDR]; !ok {
				seenInternet[netCIDR] = struct{}{}
				internet = append(internet, netCIDR)
			}
		}
	}
	sort.Strings(routes)
	sort.Strings(internet)
	return routes, internet
}

func discoverEnvProxyEndpoints() []ProbeEndpoint {
	endpoints := make([]ProbeEndpoint, 0, 8)
	seen := make(map[string]struct{})
	for _, kv := range os.Environ() {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		if key == "" {
			continue
		}
		keyLower := strings.ToLower(key)
		if !strings.Contains(keyLower, "proxy") {
			continue
		}
		for _, candidate := range splitEndpointCandidates(parts[1]) {
			normalized, ok := normalizeEndpoint(candidate)
			if !ok {
				continue
			}
			if _, ok := seen[normalized]; ok {
				continue
			}
			seen[normalized] = struct{}{}
			endpoints = append(endpoints, ProbeEndpoint{Endpoint: normalized, Source: "env:" + key})
		}
	}
	sort.SliceStable(endpoints, func(i, j int) bool {
		if endpoints[i].Source != endpoints[j].Source {
			return endpoints[i].Source < endpoints[j].Source
		}
		return endpoints[i].Endpoint < endpoints[j].Endpoint
	})
	return endpoints
}

func discoverEnvConfigEndpoints() []ProbeEndpoint {
	endpoints := make([]ProbeEndpoint, 0, 24)
	seen := make(map[string]struct{})
	for _, kv := range os.Environ() {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" || value == "" {
			continue
		}
		if !isLikelyEndpointEnvKey(key, value) {
			continue
		}
		candidates := splitEndpointCandidates(value)
		candidates = append(candidates, endpointURLRE.FindAllString(value, -1)...)
		candidates = append(candidates, endpointIPRE.FindAllString(value, -1)...)
		candidates = append(candidates, endpointDomainPortRE.FindAllString(value, -1)...)
		candidates = append(candidates, endpointHostPortRE.FindAllString(value, -1)...)
		candidates = append(candidates, endpointIPv6RE.FindAllString(value, -1)...)
		for _, candidate := range candidates {
			normalized, ok := normalizeEndpoint(candidate)
			if !ok {
				continue
			}
			entry := normalized + "|env:" + key
			if _, ok := seen[entry]; ok {
				continue
			}
			seen[entry] = struct{}{}
			endpoints = append(endpoints, ProbeEndpoint{Endpoint: normalized, Source: "env:" + key})
			if len(endpoints) >= 256 {
				return endpoints
			}
		}
	}
	sort.SliceStable(endpoints, func(i, j int) bool {
		if endpoints[i].Source != endpoints[j].Source {
			return endpoints[i].Source < endpoints[j].Source
		}
		return endpoints[i].Endpoint < endpoints[j].Endpoint
	})
	return endpoints
}

func discoverSampleProxyEndpoints(samples []shared.Candidate) []ProbeEndpoint {
	const maxEndpoints = 32
	proxyPorts := map[int]bool{80: true, 443: true, 1080: true, 3128: true, 8080: true, 8118: true, 8888: true}
	endpoints := make([]ProbeEndpoint, 0, 16)
	seen := make(map[string]struct{})
	for _, sample := range samples {
		for _, conn := range sample.Conns {
			if !proxyPorts[conn.RemotePort] {
				continue
			}
			ip := strings.TrimSpace(conn.RemoteAddress)
			if ip == "" || conn.RemotePort <= 0 {
				continue
			}
			scope := classifyEndpointHost(ip)
			if scope != "loopback" && scope != "internal-ip" && scope != "internal-domain" {
				// Sample connection endpoints on public networks are usually just destinations,
				// not local pivot proxies.
				continue
			}
			endpoint := "tcp://" + net.JoinHostPort(ip, strconv.Itoa(conn.RemotePort))
			if _, ok := seen[endpoint]; ok {
				continue
			}
			seen[endpoint] = struct{}{}
			endpoints = append(endpoints, ProbeEndpoint{Endpoint: endpoint, Source: "sample-conn:" + shared.CandidateKey(sample)})
			if len(endpoints) >= maxEndpoints {
				return endpoints
			}
		}
		for _, l := range sample.Listeners {
			if !proxyPorts[l.LocalPort] {
				continue
			}
			if l.LocalPort <= 0 {
				continue
			}
			endpoint := "tcp://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(l.LocalPort))
			if _, ok := seen[endpoint]; ok {
				continue
			}
			seen[endpoint] = struct{}{}
			endpoints = append(endpoints, ProbeEndpoint{Endpoint: endpoint, Source: "sample-listener:" + shared.CandidateKey(sample)})
			if len(endpoints) >= maxEndpoints {
				return endpoints
			}
		}
	}
	return endpoints
}

func discoverConfigEndpoints(samples []shared.Candidate) []ProbeEndpoint {
	paths := collectEndpointConfigPaths(samples)
	if len(paths) == 0 {
		return nil
	}
	endpoints := make([]ProbeEndpoint, 0, 24)
	seen := make(map[string]struct{})
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil || len(raw) == 0 || len(raw) > 1024*1024 {
			continue
		}
		text := compactEndpointCandidateText(path, string(raw))
		if text == "" {
			continue
		}
		pathLower := strings.ToLower(path)
		matches := endpointURLRE.FindAllString(text, -1)
		matches = append(matches, endpointIPRE.FindAllString(text, -1)...)
		matches = append(matches, endpointDomainPortRE.FindAllString(text, -1)...)
		if !isStructuredEndpointDataPath(pathLower) {
			matches = append(matches, endpointHostPortRE.FindAllString(text, -1)...)
		}
		matches = append(matches, endpointIPv6RE.FindAllString(text, -1)...)
		for _, candidate := range matches {
			normalized, ok := normalizeEndpoint(candidate)
			if !ok {
				continue
			}
			key := normalized + "|" + path
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			endpoints = append(endpoints, ProbeEndpoint{Endpoint: normalized, Source: "config:" + path})
			if len(endpoints) >= 256 {
				return endpoints
			}
		}
	}
	sort.SliceStable(endpoints, func(i, j int) bool {
		if endpoints[i].Source != endpoints[j].Source {
			return endpoints[i].Source < endpoints[j].Source
		}
		return endpoints[i].Endpoint < endpoints[j].Endpoint
	})
	return endpoints
}

func collectEndpointConfigPaths(samples []shared.Candidate) []string {
	const (
		maxConfigPaths = 512
		maxWalkFileMB  = 2
	)
	paths := make([]string, 0, 128)
	seen := make(map[string]struct{})
	addPath := func(path string) {
		normalized := normalizeEndpointConfigPath(path)
		if normalized == "" {
			return
		}
		if _, ok := seen[normalized]; ok {
			return
		}
		info, err := os.Stat(normalized)
		if err != nil || info.IsDir() {
			return
		}
		if !isLikelyEndpointConfigFile(normalized, maxWalkFileMB*1024*1024) {
			return
		}
		seen[normalized] = struct{}{}
		paths = append(paths, normalized)
	}

	addTree := func(root string, maxDepth, maxFiles int) {
		root = normalizeEndpointConfigPath(root)
		if root == "" {
			return
		}
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			return
		}
		filesSeen := 0
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if filesSeen >= maxFiles || len(paths) >= maxConfigPaths {
				return fs.SkipAll
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = ""
			}
			depth := 0
			if rel != "" && rel != "." {
				depth = strings.Count(rel, string(os.PathSeparator)) + 1
			}
			if d.IsDir() {
				name := strings.ToLower(strings.TrimSpace(d.Name()))
				if depth > maxDepth || shouldSkipEndpointConfigDir(name) {
					return fs.SkipDir
				}
				return nil
			}
			filesSeen++
			if depth > maxDepth {
				return nil
			}
			if !isLikelyEndpointConfigFile(path, maxWalkFileMB*1024*1024) {
				return nil
			}
			addPath(path)
			return nil
		})
	}

	for _, path := range defaultEndpointConfigFiles() {
		addPath(path)
	}

	configNames := []string{
		".env",
		"config.yml",
		"config.yaml",
		"config.json",
		"config.toml",
		"config.ini",
		"appsettings.json",
		"web.config",
		"applicationhost.config",
		"docker-compose.yml",
		"httpd.conf",
		"nginx.conf",
		"server.xml",
		"my.cnf",
		"my.ini",
	}
	if runtime.GOOS == "windows" {
		configNames = append(configNames, "unattend.xml", "unattended.xml", "sysprep.inf", "sysprep.xml")
	}
	exeDirs := make([]string, 0, len(samples))
	exeSeen := make(map[string]struct{}, len(samples))
	for _, sample := range samples {
		if sample.Proc == nil {
			continue
		}
		exePath := strings.TrimSpace(sample.Proc.ExePath)
		if exePath == "" {
			continue
		}
		dir := normalizeEndpointConfigPath(filepath.Dir(exePath))
		if dir != "" {
			if _, ok := exeSeen[dir]; !ok {
				exeSeen[dir] = struct{}{}
				exeDirs = append(exeDirs, dir)
			}
		}
		for _, name := range configNames {
			addPath(filepath.Join(dir, name))
		}
	}

	rootSeen := make(map[string]struct{}, 24)
	roots := make([]string, 0, 24+len(exeDirs))
	addRoot := func(root string) {
		normalized := normalizeEndpointConfigPath(root)
		if normalized == "" {
			return
		}
		if _, ok := rootSeen[normalized]; ok {
			return
		}
		info, err := os.Stat(normalized)
		if err != nil || !info.IsDir() {
			return
		}
		rootSeen[normalized] = struct{}{}
		roots = append(roots, normalized)
	}
	for _, root := range defaultEndpointConfigRoots() {
		addRoot(root)
	}
	if wd, err := os.Getwd(); err == nil {
		addRoot(wd)
	}
	for _, dir := range exeDirs {
		addRoot(dir)
	}
	home := normalizeEndpointConfigPath("~")
	if home != "" {
		addRoot(home)
	}
	for _, root := range roots {
		maxDepth, maxFiles := endpointConfigWalkLimits(root, home)
		addTree(root, maxDepth, maxFiles)
		if len(paths) >= maxConfigPaths {
			break
		}
	}

	sort.Strings(paths)
	if len(paths) > maxConfigPaths {
		return paths[:maxConfigPaths]
	}
	return paths
}

func normalizeEndpointConfigPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	path = expandPathPlaceholders(path)
	if path == "" {
		return ""
	}
	return filepath.Clean(path)
}

func expandPathPlaceholders(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	path = safeio.ExpandHomePath(path)
	path = os.ExpandEnv(path)
	return expandWindowsEnvPath(path)
}

func expandWindowsEnvPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || !strings.Contains(path, "%") {
		return path
	}
	return windowsEnvVarRE.ReplaceAllStringFunc(path, func(token string) string {
		if len(token) < 3 {
			return token
		}
		key := token[1 : len(token)-1]
		if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
			return v
		}
		if v, ok := os.LookupEnv(strings.ToUpper(key)); ok && strings.TrimSpace(v) != "" {
			return v
		}
		if v, ok := os.LookupEnv(strings.ToLower(key)); ok && strings.TrimSpace(v) != "" {
			return v
		}
		return token
	})
}

func defaultEndpointConfigFiles() []string {
	files := []string{
		"/etc/environment",
		"/etc/proxychains.conf",
		"~/.proxychains/proxychains.conf",
		"~/.ssh/config",
		"~/.gitconfig",
		"~/.npmrc",
		"~/.curlrc",
		"~/.config/proxywatch/config.env",
	}
	if runtime.GOOS == "windows" {
		files = append(files,
			"%USERPROFILE%\\.ssh\\config",
			"%USERPROFILE%\\.gitconfig",
			"%USERPROFILE%\\.npmrc",
			"%PROGRAMDATA%\\ssh\\sshd_config",
			"%WINDIR%\\System32\\drivers\\etc\\hosts",
			"%WINDIR%\\Panther\\Unattend.xml",
			"%WINDIR%\\Panther\\Unattended.xml",
			"%WINDIR%\\Panther\\Unattend\\Unattend.xml",
			"%WINDIR%\\System32\\Sysprep\\unattend.xml",
			"%WINDIR%\\System32\\Sysprep\\unattended.xml",
		)
	}
	return files
}

func defaultEndpointConfigRoots() []string {
	roots := []string{
		"/etc",
		"/usr/local/etc",
		"/opt",
		"/srv",
		"/home",
		"/root",
		"/Users",
		"/var/lib",
		"/var/www",
		"~/.config",
		"~/.ssh",
	}
	if runtime.GOOS == "windows" {
		roots = append(roots,
			"%PROGRAMDATA%",
			"%APPDATA%",
			"%LOCALAPPDATA%",
			"%USERPROFILE%",
			"%PUBLIC%",
			"%PROGRAMFILES%",
			"%PROGRAMFILES(X86)%",
			"%SYSTEMDRIVE%\\inetpub",
			"%SYSTEMDRIVE%\\tools",
		)
	}
	return roots
}

func endpointConfigWalkLimits(root, home string) (int, int) {
	normalizedRoot := strings.ToLower(strings.TrimSpace(filepath.Clean(root)))
	normalizedHome := strings.ToLower(strings.TrimSpace(filepath.Clean(home)))
	switch {
	case normalizedRoot == "":
		return 4, 900
	case runtime.GOOS == "windows" && strings.Contains(normalizedRoot, "program files"):
		return 4, 700
	case runtime.GOOS == "windows" && strings.Contains(normalizedRoot, "appdata"):
		return 5, 1400
	case runtime.GOOS == "windows" && strings.Contains(normalizedRoot, "windows"):
		return 3, 600
	case strings.HasPrefix(normalizedRoot, "/etc"):
		return 4, 1000
	case normalizedRoot == "/home" || normalizedRoot == "/users":
		return 3, 1200
	case strings.Contains(normalizedRoot, ".ssh"):
		return 4, 1000
	case strings.Contains(normalizedRoot, ".config"):
		return 5, 1200
	case normalizedHome != "" && normalizedRoot == normalizedHome:
		return 4, 1500
	default:
		return 4, 900
	}
}

func shouldSkipEndpointConfigDir(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", ".", "..":
		return false
	case ".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", "target", ".cache", "__pycache__", ".venv", "venv", ".proxywatch", ".codex", ".vscode", ".idea", "history", "logs", "log":
		return true
	default:
		return false
	}
}

func isLikelyEndpointConfigFile(path string, maxBytes int64) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	if info.Size() <= 0 || info.Size() > maxBytes {
		return false
	}
	name := strings.ToLower(strings.TrimSpace(filepath.Base(path)))
	if name == "" {
		return false
	}
	if isNoisyEndpointConfigPath(path) {
		return false
	}
	exact := map[string]struct{}{
		".env": {}, "env": {}, "config": {}, "config.env": {}, "config.ini": {}, "config.toml": {}, "config.json": {}, "config.yaml": {}, "config.yml": {},
		"settings.json": {}, "settings.yaml": {}, "settings.yml": {}, "appsettings.json": {}, "proxychains.conf": {}, "ssh_config": {},
		".gitconfig": {}, ".npmrc": {}, ".curlrc": {}, "web.config": {}, "app.config": {}, "applicationhost.config": {},
		"unattend.xml": {}, "unattended.xml": {}, "sysprep.inf": {}, "sysprep.xml": {}, "server.xml": {},
		"httpd.conf": {}, "https.conf": {}, "nginx.conf": {}, "my.ini": {}, "my.cnf": {}, "docker-compose.yml": {},
		"docker-compose.yaml": {}, "dockerfile": {}, "hosts": {},
	}
	if _, ok := exact[name]; ok {
		return true
	}
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".conf", ".cfg", ".cnf", ".ini", ".properties", ".service":
		return true
	}
	if ext == ".yaml" || ext == ".yml" || ext == ".json" || ext == ".toml" || ext == ".env" || ext == ".xml" || ext == ".config" || ext == ".ps1" || ext == ".cmd" || ext == ".bat" {
		for _, kw := range []string{"config", "settings", "proxy", "endpoint", "connection", "appsettings", "ssh", "unattend", "sysprep", "compose", "docker"} {
			if strings.Contains(name, kw) {
				return true
			}
		}
		return false
	}
	for _, kw := range []string{"config", "settings", "proxy", "endpoint", "connection", "appsettings", "ssh", "unattend", "sysprep", "compose", "docker"} {
		if strings.Contains(name, kw) {
			return true
		}
	}
	return false
}

func isNoisyEndpointConfigPath(path string) bool {
	p := strings.ToLower(strings.ReplaceAll(filepath.Clean(path), "\\", "/"))
	noise := []string{
		"/.proxywatch/",
		"/.proxywatch/contour/",
		"/.proxywatch/calibration/",
		"/.codex/",
		"/.config/code/user/history/",
		"/.config/code/network persistent state",
		"/.cache/",
		"/logs/",
	}
	for _, marker := range noise {
		if strings.Contains(p, marker) {
			return true
		}
	}
	return false
}

func mergeProbeEndpoints(a, b []ProbeEndpoint) []ProbeEndpoint {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	out := make([]ProbeEndpoint, 0, len(a)+len(b))
	seen := make(map[string]struct{}, len(a)+len(b))
	for _, item := range append(a, b...) {
		key := item.Endpoint
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].Endpoint < out[j].Endpoint
	})
	return out
}

func testEndpointReachability(ctx context.Context, endpoints []ProbeEndpoint, timeout time.Duration) ([]ProbeEndpoint, int, int) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(endpoints) == 0 {
		return nil, 0, 0
	}
	if timeout <= 0 {
		timeout = 700 * time.Millisecond
	}
	out := make([]ProbeEndpoint, len(endpoints))
	copy(out, endpoints)
	reachable := 0
	pivotable := 0
	for i := range out {
		if err := ctx.Err(); err != nil {
			break
		}
		host, port, ok := EndpointHostPort(out[i].Endpoint)
		if !ok {
			continue
		}
		out[i].Host = host
		out[i].Port = port
		out[i].Scope = classifyEndpointHost(host)
		dialer := net.Dialer{Timeout: timeout}
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			continue
		}
		out[i].Reachable = true
		reachable++
		_ = conn.Close()
	}
	return out, reachable, pivotable
}

func testProxyEndpointReachabilityWithTarget(ctx context.Context, endpoints []ProbeEndpoint, timeout time.Duration, pivotTarget string) ([]ProbeEndpoint, int, int) {
	if strings.TrimSpace(pivotTarget) == "" {
		pivotTarget = DefaultProbePivotTarget
	}
	return testProxyEndpointReachabilityTo(ctx, endpoints, timeout, pivotTarget)
}

func testProxyEndpointReachabilityTo(ctx context.Context, endpoints []ProbeEndpoint, timeout time.Duration, pivotTarget string) ([]ProbeEndpoint, int, int) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(endpoints) == 0 {
		return nil, 0, 0
	}
	if timeout <= 0 {
		timeout = 1200 * time.Millisecond
	}
	out := make([]ProbeEndpoint, len(endpoints))
	copy(out, endpoints)
	reachable := 0
	pivotable := 0
	pivotTimeout := timeout * 2
	if pivotTimeout < 2*time.Second {
		pivotTimeout = 2 * time.Second
	}
	for _, i := range prioritizeEndpointIndices(out) {
		if err := ctx.Err(); err != nil {
			break
		}
		host, port, ok := EndpointHostPort(out[i].Endpoint)
		if !ok {
			continue
		}
		out[i].Host = host
		out[i].Port = port
		out[i].Scope = classifyEndpointHost(host)
		dialer := net.Dialer{Timeout: timeout}
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			continue
		}
		out[i].Reachable = true
		reachable++
		_ = conn.Close()

		schemes := proxySchemeCandidates(out[i].Endpoint, port)
		if len(schemes) == 0 {
			continue
		}
		out[i].ProxyTried = strings.Join(schemes, ",")
		out[i].PivotTarget = pivotTarget
		for _, scheme := range schemes {
			candidate := scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port))
			if !testProxyPivot(ctx, candidate, pivotTarget, pivotTimeout) {
				continue
			}
			out[i].PivotReachable = true
			out[i].PivotScheme = scheme
			pivotable++
			break
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri := EndpointScopeRank(out[i].Scope)
		rj := EndpointScopeRank(out[j].Scope)
		if ri != rj {
			return ri < rj
		}
		if out[i].PivotReachable != out[j].PivotReachable {
			return out[i].PivotReachable
		}
		if out[i].Reachable != out[j].Reachable {
			return out[i].Reachable
		}
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Port < out[j].Port
	})
	return out, reachable, pivotable
}

func prioritizeEndpointIndices(endpoints []ProbeEndpoint) []int {
	indices := make([]int, len(endpoints))
	for i := range endpoints {
		indices[i] = i
	}
	sort.SliceStable(indices, func(a, b int) bool {
		ia := indices[a]
		ib := indices[b]
		ha, pa, oka := EndpointHostPort(endpoints[ia].Endpoint)
		hb, pb, okb := EndpointHostPort(endpoints[ib].Endpoint)
		if !oka {
			return false
		}
		if !okb {
			return true
		}
		ra := EndpointScopeRank(classifyEndpointHost(ha))
		rb := EndpointScopeRank(classifyEndpointHost(hb))
		if ra != rb {
			return ra < rb
		}
		if ha != hb {
			return ha < hb
		}
		return pa < pb
	})
	return indices
}

func proxySchemeCandidates(endpoint string, port int) []string {
	explicit := endpointScheme(endpoint)
	normalize := func(s string) string {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "socks":
			return "socks5"
		default:
			return strings.ToLower(strings.TrimSpace(s))
		}
	}
	dedupe := func(items []string) []string {
		if len(items) == 0 {
			return nil
		}
		out := make([]string, 0, len(items))
		seen := make(map[string]struct{}, len(items))
		for _, item := range items {
			item = normalize(item)
			if !isPivotProxyScheme(item) {
				continue
			}
			if _, ok := seen[item]; ok {
				continue
			}
			seen[item] = struct{}{}
			out = append(out, item)
		}
		return out
	}
	if isPivotProxyScheme(explicit) {
		return dedupe([]string{explicit})
	}
	switch port {
	case 1080:
		return dedupe([]string{"socks5", "socks4", "http", "https"})
	case 443, 4443, 7443, 8443, 9443:
		return dedupe([]string{"https", "http", "socks5", "socks4"})
	case 80, 81, 3128, 8000, 8008, 8080, 8081, 8088, 8118, 8888, 9000:
		return dedupe([]string{"http", "https", "socks5", "socks4"})
	default:
		return dedupe([]string{"http", "https", "socks5", "socks4"})
	}
}

func EndpointScopeRank(scope string) int {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "loopback":
		return 0
	case "internal-ip", "internal-domain":
		return 1
	case "domain":
		return 2
	case "external-ip":
		return 3
	default:
		return 4
	}
}

func classifyEndpointHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return "unknown"
	}
	if strings.EqualFold(host, "localhost") {
		return "loopback"
	}
	ip := net.ParseIP(host)
	if ip == nil {
		lower := strings.ToLower(host)
		if !strings.Contains(lower, ".") {
			return "internal-domain"
		}
		if strings.HasSuffix(lower, ".local") || strings.HasSuffix(lower, ".lan") || strings.HasSuffix(lower, ".internal") || strings.HasSuffix(lower, ".corp") || strings.HasSuffix(lower, ".home") || strings.HasSuffix(lower, ".localdomain") {
			return "internal-domain"
		}
		return "domain"
	}
	if ip.IsLoopback() {
		return "loopback"
	}
	if shared.IsInternalIP(ip.String()) {
		return "internal-ip"
	}
	return "external-ip"
}

func endpointScheme(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return ""
	}
	if strings.Contains(endpoint, "://") {
		u, err := url.Parse(endpoint)
		if err != nil || u == nil {
			return ""
		}
		return strings.ToLower(strings.TrimSpace(u.Scheme))
	}
	return "tcp"
}

func isPivotProxyScheme(scheme string) bool {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "http", "https", "socks", "socks4", "socks5":
		return true
	default:
		return false
	}
}

func testProxyPivot(ctx context.Context, endpoint, target string, timeout time.Duration) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = 700 * time.Millisecond
	}
	host, port, ok := EndpointHostPort(endpoint)
	if !ok {
		return false
	}
	targetHost, targetPort, ok := EndpointHostPort("tcp://" + strings.TrimSpace(target))
	if !ok {
		return false
	}
	scheme := endpointScheme(endpoint)
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	defer conn.Close()

	if strings.EqualFold(scheme, "https") {
		serverName := host
		if net.ParseIP(serverName) != nil {
			serverName = ""
		}
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         serverName,
		})
		_ = tlsConn.SetDeadline(time.Now().Add(timeout))
		if err := tlsConn.Handshake(); err != nil {
			return false
		}
		conn = tlsConn
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "http", "https":
		req := "CONNECT " + net.JoinHostPort(targetHost, strconv.Itoa(targetPort)) + " HTTP/1.1\r\nHost: " + net.JoinHostPort(targetHost, strconv.Itoa(targetPort)) + "\r\nProxy-Connection: Keep-Alive\r\n\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			return false
		}
		resp, err := readTCPWithIdleTimeout(conn, 4096, min(timeout/2, 500*time.Millisecond))
		if err != nil || len(resp) == 0 {
			return false
		}
		firstLine := strings.TrimSpace(strings.SplitN(string(resp), "\n", 2)[0])
		return strings.Contains(firstLine, " 200 ")
	case "socks", "socks5":
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			return false
		}
		methodSel, err := readTCPExact(conn, 2, timeout)
		if err != nil || len(methodSel) != 2 || methodSel[0] != 0x05 || methodSel[1] != 0x00 {
			return false
		}
		if len(targetHost) == 0 || len(targetHost) > 255 {
			return false
		}
		req := make([]byte, 0, 7+len(targetHost))
		req = append(req, 0x05, 0x01, 0x00, 0x03, byte(len(targetHost)))
		req = append(req, []byte(targetHost)...)
		req = append(req, byte(targetPort>>8), byte(targetPort))
		if _, err := conn.Write(req); err != nil {
			return false
		}
		reply, err := readSocks5ConnectMessage(conn, timeout)
		if err != nil || len(reply) == 0 {
			return false
		}
		return validateSocks5ConnectReply(reply)
	case "socks4":
		if len(targetHost) == 0 || len(targetHost) > 255 {
			return false
		}
		req := make([]byte, 0, 10+len(targetHost))
		req = append(req, 0x04, 0x01, byte(targetPort>>8), byte(targetPort))
		req = append(req, 0x00, 0x00, 0x00, 0x01) // SOCKS4a domain marker
		req = append(req, 0x00)                   // empty userid
		req = append(req, []byte(targetHost)...)
		req = append(req, 0x00)
		if _, err := conn.Write(req); err != nil {
			return false
		}
		reply, err := readTCPExact(conn, 8, timeout)
		if err != nil || len(reply) != 8 {
			return false
		}
		return reply[1] == 0x5a
	default:
		return false
	}
}

func isLikelyEndpointEnvKey(key, value string) bool {
	keyLower := strings.ToLower(strings.TrimSpace(key))
	value = strings.TrimSpace(value)
	if keyLower == "" || value == "" {
		return false
	}
	for _, bad := range []string{
		"ls_colors",
		"path",
		"display",
		"gtk",
		"xmodifiers",
		"term",
		"color",
		"prompt",
		"shell",
	} {
		if strings.Contains(keyLower, bad) {
			return false
		}
	}
	for _, good := range []string{
		"proxy",
		"url",
		"uri",
		"endpoint",
		"host",
		"server",
		"addr",
		"address",
		"port",
		"api",
		"webhook",
		"db",
		"database",
		"redis",
		"mongo",
		"postgres",
		"mysql",
		"amqp",
		"mqtt",
		"socks",
		"http",
		"https",
		"ftp",
		"ldap",
		"dns",
		"ntp",
		"webrtc",
		"stun",
		"turn",
		"sip",
		"rtsp",
		"snmp",
		"coap",
		"kafka",
		"elastic",
		"vault",
	} {
		if strings.Contains(keyLower, good) {
			return true
		}
	}
	return strings.Contains(value, "://")
}

func compactEndpointCandidateText(path, text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	pathLower := strings.ToLower(path)
	// JSON and YAML files often contain timestamps and code references that look like host:port.
	// Keep URL extraction for those formats but avoid broad host:port parsing noise.
	if strings.HasSuffix(pathLower, ".json") || strings.HasSuffix(pathLower, ".yaml") || strings.HasSuffix(pathLower, ".yml") {
		return text
	}
	lines := strings.Split(text, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "#"),
			strings.HasPrefix(line, ";"),
			strings.HasPrefix(line, "//"),
			strings.HasPrefix(line, "-- "),
			strings.HasPrefix(line, "<!--"),
			strings.HasPrefix(line, "/*"),
			strings.HasPrefix(line, "* "),
			strings.HasPrefix(line, "*/"):
			continue
		}
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if idx := strings.Index(line, " //"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func isStructuredEndpointDataPath(path string) bool {
	path = strings.ToLower(strings.TrimSpace(path))
	return strings.HasSuffix(path, ".json") || strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")
}

func splitEndpointCandidates(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	replacer := strings.NewReplacer(",", " ", ";", " ", "\n", " ", "\t", " ")
	raw = replacer.Replace(raw)
	parts := strings.Fields(raw)
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		candidate := strings.Trim(part, `"'`)
		if candidate != "" {
			out = append(out, candidate)
		}
	}
	return out
}

func normalizeEndpoint(raw string) (string, bool) {
	raw = strings.TrimSpace(strings.Trim(raw, `"'`))
	if raw == "" {
		return "", false
	}
	if !strings.Contains(raw, "://") {
		host, port, ok := parseCandidateHostPort(raw)
		if ok {
			return "tcp://" + net.JoinHostPort(host, strconv.Itoa(port)), true
		}
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return "", false
	}
	host := strings.TrimSpace(u.Hostname())
	if !isValidEndpointHost(host) {
		return "", false
	}
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	if scheme == "unix" || scheme == "file" || scheme == "npipe" {
		return "", false
	}
	portValue := strings.TrimSpace(u.Port())
	if portValue == "" {
		defaultPort, ok := defaultEndpointPortForScheme(scheme)
		if !ok {
			return "", false
		}
		portValue = strconv.Itoa(defaultPort)
	}
	port, err := strconv.Atoi(portValue)
	if err != nil || port <= 0 || port > 65535 {
		return "", false
	}
	return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port)), true
}

func EndpointHostPort(endpoint string) (string, int, bool) {
	raw := strings.TrimSpace(endpoint)
	if raw == "" {
		return "", 0, false
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || u == nil {
			return "", 0, false
		}
		host := strings.TrimSpace(u.Hostname())
		if !isValidEndpointHost(host) {
			return "", 0, false
		}
		portValue := strings.TrimSpace(u.Port())
		if portValue == "" {
			defaultPort, ok := defaultEndpointPortForScheme(u.Scheme)
			if !ok {
				return "", 0, false
			}
			return host, defaultPort, true
		}
		port, err := strconv.Atoi(portValue)
		if err != nil || port <= 0 || port > 65535 {
			return "", 0, false
		}
		return host, port, true
	}
	return parseCandidateHostPort(raw)
}

func parseCandidateHostPort(raw string) (string, int, bool) {
	host, portValue, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil {
		return "", 0, false
	}
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if !isValidEndpointHost(host) {
		return "", 0, false
	}
	port, err := strconv.Atoi(strings.TrimSpace(portValue))
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, false
	}
	if port < 20 {
		return "", 0, false
	}
	if looksLikeCodeReferenceHost(host) {
		return "", 0, false
	}
	return host, port, true
}

func isValidEndpointHost(host string) bool {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" {
		return false
	}
	if strings.ContainsAny(host, `/\ "'<>|=*%`) {
		return false
	}
	if strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") || strings.HasPrefix(host, "-") || strings.HasSuffix(host, "-") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	lower := strings.ToLower(host)
	if endpointTimestampHostRE.MatchString(lower) {
		return false
	}
	if strings.EqualFold(lower, "localhost") {
		return true
	}
	if isReservedExampleDomain(lower) {
		return false
	}
	parts := strings.Split(lower, ".")
	if len(parts) == 1 {
		part := parts[0]
		if len(part) < 2 || isAllDigits(part) {
			return false
		}
		return endpointHostLabelRE.MatchString(part)
	}
	if len(host) > 253 {
		return false
	}
	for _, part := range parts {
		if !endpointHostLabelRE.MatchString(part) {
			return false
		}
	}
	last := parts[len(parts)-1]
	return len(last) >= 2 && !isAllDigits(last)
}

func isReservedExampleDomain(host string) bool {
	host = strings.TrimSpace(strings.TrimSuffix(strings.ToLower(host), "."))
	if host == "" {
		return false
	}
	for _, suffix := range []string{"example.com", "example.net", "example.org", "example.edu"} {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

func looksLikeCodeReferenceHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || strings.Count(host, ".") != 1 {
		return false
	}
	parts := strings.Split(host, ".")
	if len(parts) != 2 {
		return false
	}
	switch parts[1] {
	case "ts", "js", "jsx", "tsx", "rs", "go", "py", "java", "cs", "cpp", "c", "h", "hpp", "md", "txt", "yaml", "yml", "json", "toml", "ini", "conf", "xml", "html", "css", "scss", "sql", "sh", "bat", "ps1":
		return true
	default:
		return false
	}
}

func isAllDigits(v string) bool {
	if strings.TrimSpace(v) == "" {
		return false
	}
	for _, r := range v {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func defaultEndpointPortForScheme(scheme string) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "http":
		return 80, true
	case "https":
		return 443, true
	case "ws":
		return 80, true
	case "wss":
		return 443, true
	case "ssh":
		return 22, true
	case "socks", "socks5", "socks4":
		return 1080, true
	case "ftp":
		return 21, true
	case "ftps":
		return 990, true
	case "smtp":
		return 25, true
	case "smtps":
		return 465, true
	case "imap":
		return 143, true
	case "imaps":
		return 993, true
	case "pop3":
		return 110, true
	case "pop3s":
		return 995, true
	case "ldap":
		return 389, true
	case "ldaps":
		return 636, true
	case "mqtt":
		return 1883, true
	case "amqp":
		return 5672, true
	case "postgres":
		return 5432, true
	case "tcp":
		return 0, false
	default:
		return 0, false
	}
}

// discoverLocalhostProxyEndpoints actively probes common proxy ports on
// localhost to find running proxies that might not be in the candidate list.
func discoverLocalhostProxyEndpoints(ctx context.Context) []ProbeEndpoint {
	proxyPorts := []int{1080, 3128, 8080, 8118, 8443, 8888, 9050, 9080, 9090, 9443}
	var endpoints []ProbeEndpoint
	for _, port := range proxyPorts {
		select {
		case <-ctx.Done():
			return endpoints
		default:
		}
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err != nil {
			continue
		}
		conn.Close()
		endpoints = append(endpoints, ProbeEndpoint{
			Endpoint:  "tcp://" + addr,
			Source:    "localhost-scan",
			Reachable: true,
		})
	}
	return endpoints
}
