package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

func probeProtocolRoundTrip(ctx context.Context, host string, port int, kind string, proto probeProtocol, timeout time.Duration) bool {
	method := strings.ToLower(strings.TrimSpace(proto.Name))
	transport := strings.ToLower(strings.TrimSpace(proto.Transport))
	isExfil := strings.EqualFold(strings.TrimSpace(kind), "exfil")
	if !isExfil && transport == "tcp" && methodUsesSocksCarrierTunnel(method) {
		return probeSocksCarrierTunnelRoundTrip(ctx, host, port, method, timeout)
	}
	request := buildProbeMethodRequestBody(method, port, isExfil)
	if len(request) == 0 {
		return false
	}
	if transport == "udp" {
		return probeUDPRoundTrip(ctx, host, port, method, request, timeout)
	}
	return probeTCPRoundTrip(ctx, host, port, method, request, timeout)
}

func probeEndpointScanRoundTrip(ctx context.Context, host string, port int, kind string, proto probeProtocol, timeout time.Duration) bool {
	transport := strings.ToLower(strings.TrimSpace(proto.Transport))
	method := strings.ToLower(strings.TrimSpace(proto.Name))
	_ = kind
	switch transport {
	case "udp":
		return probeEndpointUDPScan(ctx, host, port, method, timeout)
	default:
		if _, ok := probeTLSMethods[method]; ok {
			return probeEndpointTLSScan(ctx, host, port, method, timeout)
		}
		return probeEndpointTCPScan(ctx, host, port, method, timeout)
	}
}

func probeEndpointTCPScan(ctx context.Context, host string, port int, method string, timeout time.Duration) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return false
	}
	payload := buildProbeMethodBaseRequestBody(method, port)
	if len(payload) == 0 {
		return false
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	nw, err := conn.Write(payload)
	if err != nil || nw < len(payload) {
		return false
	}
	buf := make([]byte, 4096)
	nr, _ := conn.Read(buf)
	if nr > 0 {
		return validateEndpointScanResponse(method, buf[:nr])
	}
	return false
}

func probeEndpointTLSScan(ctx context.Context, host string, port int, method string, timeout time.Duration) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return false
	}
	serverName := host
	if net.ParseIP(serverName) != nil {
		serverName = ""
	}
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, strconv.Itoa(port)), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
	})
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	payload := buildProbeMethodBaseRequestBody(method, port)
	if len(payload) == 0 {
		return true
	}
	nw, err := conn.Write(payload)
	if err != nil || nw < len(payload) {
		return false
	}
	buf := make([]byte, 4096)
	nr, err := conn.Read(buf)
	if nr > 0 && validateEndpointScanResponse(method, buf[:nr]) {
		return true
	}
	if err == nil {
		return nr > 0
	}
	if errors.Is(err, io.EOF) || isNetTimeout(err) {
		return true
	}
	return false
}

// probeTLSInterception dials the given host:port with TLS and inspects the
// certificate issuer for signs of a TLS-intercepting proxy or firewall.
// Returns the issuer organisation and true if interception keywords are found.
// tlsInterceptionResult holds proof of TLS interception.
type tlsInterceptionResult struct {
	Intercepted bool
	IssuerOrg   string // org that signed the intercepting cert
	IssuerCN    string // full issuer common name
	ExpectedOrg string // what a real cert would show
	LeafSubject string // subject of the leaf cert
	LeafSerial  string // serial number of the leaf cert
}

func probeTLSInterception(ctx context.Context, host string, port int, timeout time.Duration) tlsInterceptionResult {
	result := tlsInterceptionResult{}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return result
	}
	serverName := host
	if net.ParseIP(serverName) != nil {
		serverName = ""
	}
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, strconv.Itoa(port)), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
	})
	if err != nil {
		return result
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return result
	}

	leaf := state.PeerCertificates[0]
	result.LeafSubject = leaf.Subject.CommonName
	if leaf.SerialNumber != nil {
		result.LeafSerial = leaf.SerialNumber.Text(16)
	}

	// Well-known CAs that sign legitimate certificates for major sites.
	// If the issuer is NOT one of these, the cert was likely re-signed by
	// a MITM proxy/firewall.
	legitimateIssuers := []string{
		"let's encrypt", "digicert", "comodo", "globalsign", "entrust",
		"godaddy", "amazon", "google trust", "microsoft", "apple",
		"baltimore", "verisign", "geotrust", "thawte", "sectigo",
		"isrg", "buypass", "certum", "starfield",
	}

	// Check the leaf certificate's issuer for interception keywords.
	interceptKeywords := []string{
		"proxy", "firewall", "inspect", "zscaler", "bluecoat",
		"fortinet", "fortigate", "paloalto", "palo alto", "checkpoint",
		"mcafee", "symantec", "websense", "sophos", "barracuda",
		"watchguard", "untangle", "squid", "netskope", "crowdstrike",
		"carbon black", "cisco umbrella", "umbrella",
	}

	for _, cert := range state.PeerCertificates {
		for _, org := range cert.Issuer.Organization {
			orgLower := strings.ToLower(org)

			// Direct interception keyword match.
			for _, kw := range interceptKeywords {
				if strings.Contains(orgLower, kw) {
					result.Intercepted = true
					result.IssuerOrg = org
					result.IssuerCN = cert.Issuer.CommonName
					result.ExpectedOrg = "a public CA (e.g., Let's Encrypt, DigiCert)"
					return result
				}
			}

			// If connecting to a well-known site and the issuer isn't a known
			// public CA, it's likely intercepted by a corporate CA.
			if serverName != "" {
				isLegit := false
				for _, ca := range legitimateIssuers {
					if strings.Contains(orgLower, ca) {
						isLegit = true
						break
					}
				}
				cnLower := strings.ToLower(cert.Issuer.CommonName)
				if !isLegit {
					for _, ca := range legitimateIssuers {
						if strings.Contains(cnLower, ca) {
							isLegit = true
							break
						}
					}
				}
				if !isLegit && org != "" {
					result.Intercepted = true
					result.IssuerOrg = org
					result.IssuerCN = cert.Issuer.CommonName
					result.ExpectedOrg = "a public CA (e.g., Let's Encrypt, DigiCert)"
					return result
				}
			}
		}
	}
	return result
}

// probeHTTPMethod sends a raw HTTP request with the given method to addr
// (host:port) and returns true if the response indicates the method is
// accepted (any 2xx, 3xx, or 407 status).
func probeHTTPMethod(ctx context.Context, addr, method string, timeout time.Duration) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return false
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	var req string
	switch method {
	case "CONNECT":
		req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
	case "POST":
		body := "probe=1"
		req = fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n%s", addr, len(body), body)
	case "PUT":
		body := "probe=1"
		req = fmt.Sprintf("PUT / HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n%s", addr, len(body), body)
	default:
		req = fmt.Sprintf("%s / HTTP/1.1\r\nHost: %s\r\n\r\n", method, addr)
	}

	if _, err := conn.Write([]byte(req)); err != nil {
		return false
	}
	buf := make([]byte, 1024)
	nr, _ := conn.Read(buf)
	if nr == 0 {
		return false
	}
	line := string(buf[:nr])
	// Look for an HTTP status line; accepted = 2xx, 3xx, or 407 (proxy auth required).
	if !strings.HasPrefix(line, "HTTP/") {
		return false
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return false
	}
	code, cerr := strconv.Atoi(parts[1])
	if cerr != nil {
		return false
	}
	return (code >= 200 && code < 400) || code == 407
}

func probeEndpointUDPScan(ctx context.Context, host string, port int, method string, timeout time.Duration) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return false
	}
	payload := buildProbeMethodBaseRequestBody(method, port)
	if len(payload) == 0 {
		return false
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if nw, err := conn.Write(payload); err != nil || nw < len(payload) {
		return false
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n <= 0 {
		return false
	}
	return validateEndpointScanResponse(method, buf[:n])
}

func validateEndpointScanResponse(method string, response []byte) bool {
	if len(response) == 0 {
		return false
	}
	lower := strings.ToLower(string(response))
	switch method {
	case "http", "https":
		return strings.HasPrefix(lower, "http/")
	case "ws", "wss":
		return strings.Contains(lower, "101 switching protocols") || strings.Contains(lower, "websocket")
	case "ssh":
		return strings.HasPrefix(lower, "ssh-")
	case "smtp", "smtps":
		return strings.HasPrefix(lower, "220") || strings.HasPrefix(lower, "250")
	case "imap", "imaps":
		return strings.HasPrefix(lower, "* ") || strings.Contains(lower, "capability")
	case "pop3", "pop3s":
		return strings.HasPrefix(lower, "+ok") || strings.HasPrefix(lower, "-err")
	case "ftp", "ftps":
		return strings.HasPrefix(lower, "220") || strings.HasPrefix(lower, "211")
	case "smb":
		return bytes.Contains(response, []byte("SMB"))
	case "rdp":
		return len(response) >= 2 && response[0] == 0x03 && response[1] == 0x00
	case "ldap", "ldaps":
		return response[0] == 0x30
	case "socks4":
		return len(response) >= 2 && response[1] >= 0x5a && response[1] <= 0x5d
	case "socks5":
		return len(response) >= 2 && response[0] == 0x05
	case "mqtt":
		return len(response) >= 2 && (response[0]&0xf0) == 0x20
	case "amqp":
		return bytes.HasPrefix(response, []byte("AMQP"))
	case "postgres":
		return len(response) >= 1 && bytes.Contains([]byte("ERNST"), []byte{response[0]})
	case "dns":
		return len(response) >= 12 && (response[2]&0x80) != 0
	case "ntp":
		return len(response) >= 48 && (response[0]&0x7) == 4 // server mode
	case "quic":
		return len(response) >= 8 && (response[0]&0x80) != 0 // long header form bit
	case "webrtc":
		return len(response) >= 20 &&
			binary.BigEndian.Uint16(response[0:2]) == 0x0101 &&
			binary.BigEndian.Uint32(response[4:8]) == 0x2112a442
	case "sip":
		return strings.HasPrefix(lower, "sip/2.0")
	case "rtsp":
		return strings.HasPrefix(lower, "rtsp/1.0")
	case "snmp":
		return len(response) >= 16 &&
			response[0] == 0x30 &&
			bytes.Contains(response, []byte("public")) &&
			bytes.Contains(response, []byte{0xa2})
	case "coap":
		return len(response) >= 4 &&
			(response[0]&0xc0) == 0x40 &&
			response[1] == 0x45
	case "redis":
		return strings.HasPrefix(lower, "+pong")
	default:
		return true
	}
}
