package probe

import (
	"regexp"
	"strings"
)

var (
	defaultProbePorts = []int{
		21, 22, 25, 53, 80, 110, 123, 143, 389, 443,
		445, 993, 1433, 1883, 3306, 3389, 3478, 5432, 5672, 6379,
		8080, 8443, 8888, 9090,
	}
	defaultProtocols = []probeProtocol{
		// Tunnel / egress carriers
		{Name: "http", Transport: "tcp"},
		{Name: "https", Transport: "tcp"},
		{Name: "ws", Transport: "tcp"},
		{Name: "wss", Transport: "tcp"},
		{Name: "ssh", Transport: "tcp"},
		// Exfil channels
		{Name: "dns", Transport: "udp"},
		{Name: "smtp", Transport: "tcp"},
		{Name: "ftp", Transport: "tcp"},
		{Name: "smb", Transport: "tcp"},
		{Name: "imap", Transport: "tcp"},
		{Name: "pop3", Transport: "tcp"},
		// Escape / lateral
		{Name: "rdp", Transport: "tcp"},
		{Name: "ldap", Transport: "tcp"},
		{Name: "mqtt", Transport: "tcp"},
		{Name: "amqp", Transport: "tcp"},
		{Name: "redis", Transport: "tcp"},
		{Name: "postgres", Transport: "tcp"},
		{Name: "quic", Transport: "udp"},
		{Name: "webrtc", Transport: "udp"},
		{Name: "ntp", Transport: "udp"},
	}

	endpointURLRE        = regexp.MustCompile(`(?i)(?:https?|wss?|ssh|socks5?|socks4|ftp|ftps|smtp|smtps|imap|imaps|pop3s?|ldap|ldaps|amqp|mqtt|postgres|rtsp|sip|snmp|coap|redis|stun|turns?)://[^\s"'<>]+`)
	endpointIPRE         = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b`)
	endpointDomainPortRE = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+):\d{2,5}\b`)
	endpointHostPortRE   = regexp.MustCompile(`(?i)\b(?:localhost|[a-z0-9][a-z0-9-]{0,62}):\d{2,5}\b`)
	endpointIPv6RE       = regexp.MustCompile(`\[[0-9a-fA-F:]+\]:\d{2,5}\b`)
	windowsEnvVarRE      = regexp.MustCompile(`%([^%]+)%`)
)

var serviceTargetNames = []string{
	"Dropbox", "GDrive", "OneDrive", "S3", "AzBlob", "GCS", "Box", "Mega",
	"WeTrans", "iCloud", "pCloud", "Backblz", "Slack", "Discord", "Telegra",
	"Teams", "GitHub", "GitLab", "Bitbkt", "Pastbn",
	"Gist", "Codbrg", "Docker", "GHCR", "Quay", "GHAct", "Circle", "Buildkt",
	"ngrok", "CFTunl", "Tailsc", "ZeroTr", "Bore", "lclrun", "Serveo", "Pagekt",
	"CFlare", "CFront", "Fastly", "Akamai", "AzCDN", "GoogCDN",
	"Heroku", "Vercel",
	"Netlfy", "Railwy", "Render", "Fly.io", "Deno", "Supabs", "Replit",
	"Glitch", "Workers", "OpenAI", "AWS",
}

func DefaultProbeMode() string { return ProbeModeChecks }

func NormalizeProbeMode(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case ProbeModeChecks, "chacks", "check", "verify", "validation", "tunnel", "exfil", "both",
		ProbeModeSweep, "scan", "discovery":
		return ProbeModeChecks
	case "", "disabled", "disable", "none", "false", "0", ProbeModeOff:
		return ProbeModeOff
	default:
		return DefaultProbeMode()
	}
}

func ProbeModeLabel(v string) string {
	switch NormalizeProbeMode(v) {
	case ProbeModeOff:
		return "Off"
	default:
		return "Deep"
	}
}

func DefaultProbeRole() string {
	return ProbeRoleClient
}

func NormalizeProbeRole(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case ProbeRoleListen, "listener", "server", "srv":
		return ProbeRoleListen
	case ProbeRoleScan, "scanner", "standalone":
		return ProbeRoleClient // Scan role removed; map to client.
	case "", ProbeRoleClient, "connect":
		return ProbeRoleClient
	default:
		return DefaultProbeRole()
	}
}

func defaultProbeProtocolNames() []string {
	out := make([]string, 0, len(defaultProtocols))
	for _, proto := range defaultProtocols {
		out = append(out, proto.Name)
	}
	return out
}

func defaultProbePortsCopy() []int {
	out := make([]int, len(defaultProbePorts))
	copy(out, defaultProbePorts)
	return out
}

// DefaultProbePorts returns a copy of the default probe port list.
func DefaultProbePorts() []int {
	return defaultProbePortsCopy()
}

// DefaultProtocolNames returns the names of all default probe protocols.
func DefaultProtocolNames() []string {
	return defaultProbeProtocolNames()
}

// ClassifyProtoKind returns "tunnel" for tunnel-capable protocols and "exfil" for others.
func ClassifyProtoKind(proto string) string {
	if methodUsesSocksCarrierTunnel(proto) {
		return "tunnel"
	}
	p := strings.ToLower(strings.TrimSpace(proto))
	if p == "socks4" || p == "socks5" {
		return "tunnel"
	}
	return "exfil"
}
