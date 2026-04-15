package tunnel

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	// tunnelDialTimeout is the standard TCP dial timeout for tunnel connections.
	tunnelDialTimeout = 5 * time.Second

	// tunnelIOTimeout is the default read/write deadline for tunnel I/O.
	tunnelIOTimeout = 5 * time.Second

	// tunnelFrameBuf is the standard buffer size for reading framed tunnel messages.
	tunnelFrameBuf = 256

	// tunnelRelayBuf is the buffer size for relay copy loops.
	tunnelRelayBuf = 32 * 1024
)

func extractProtoName(label string) string {
	parts := strings.Fields(label)
	if len(parts) > 0 {
		return strings.ToLower(parts[0])
	}
	return label
}

// shufflePorts returns a randomly ordered copy of the port list.
func shufflePorts(ports []int) []int {
	out := make([]int, len(ports))
	copy(out, ports)
	mrand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// generateSelfSignedCert creates an ephemeral TLS certificate.
func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "proxywatch"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

// TunnelInput describes a tunnel operation.
type TunnelInput struct {
	Role      string // "Server" or "Client"
	Method    string // protocol label
	Ports     []int  // available ports
	Target    string // client: server to connect through; server: ignored
	Direction string // "Forward" or "Reverse"
	Service   string // service name for domain-fronting (e.g., "slack.com")
	Emit      func(string)
}

// TunnelResult contains the outcome.
type TunnelResult struct {
	Error error
}

// RunTunnel starts a protocol-specific tunnel.
//
// The connection direction is always Client → Server (Server binds, Client
// connects). The Direction field controls where the SOCKS forwarder appears:
//
//	Forward: SOCKS forwarder on Client's localhost. Server is exit node.
//	         Client app → Client SOCKS → Server → destination.
//	Reverse: SOCKS forwarder on Server's localhost. Client is exit node.
//	         Server app → Server SOCKS → Client → destination.
func RunTunnel(ctx context.Context, input TunnelInput) TunnelResult {
	if input.Emit == nil {
		input.Emit = func(string) {}
	}
	proto := extractProtoName(input.Method)

	// Dead drop tunnels bypass port scanning entirely — no direct TCP.
	// Forward: Server = exit node (dials destinations), Client = SOCKS forwarder.
	// Reverse: Server = SOCKS forwarder, Client = exit node (dials destinations).
	if isDeadDropProto(proto) {
		ddRole := input.Role
		if input.Direction == "Reverse" {
			// Swap roles: Server acts as Client (SOCKS), Client acts as Server (exit).
			if ddRole == "Server" {
				ddRole = "Client"
			} else {
				ddRole = "Server"
			}
		}
		return runDeadDropTunnel(ctx, proto, ddRole, input.Emit)
	}

	if len(input.Ports) == 0 {
		return TunnelResult{Error: fmt.Errorf("no ports for %s", proto)}
	}
	direction := input.Direction
	if direction == "" {
		direction = "Forward"
	}

	switch input.Role {
	case "Server":
		// Server always binds the tunnel port.
		for _, port := range shufflePorts(input.Ports) {
			var result TunnelResult
			if direction == "Reverse" {
				// Reverse=true: Server has SOCKS, client is exit node.
				// Server's apps exit through client.
				result = runTunnelServerReverse(ctx, proto, port, input.Emit)
			} else {
				// Forward (default): Server is exit node, client has SOCKS.
				// Client's apps exit through server.
				result = runTunnelServer(ctx, proto, port, input.Emit)
			}
			if result.Error == nil || ctx.Err() != nil {
				return result
			}
			input.Emit(fmt.Sprintf("[*] Port %d unavailable, trying next...", port))
		}
		return TunnelResult{Error: fmt.Errorf("no available port for %s", proto)}
	case "Client":
		// Client always connects to Server.
		input.Emit(fmt.Sprintf("[*] Scanning %d port(s) for %s tunnel on %s...", len(input.Ports), proto, input.Target))
		for i, port := range input.Ports {
			if ctx.Err() != nil {
				return TunnelResult{Error: ctx.Err()}
			}
			input.Emit(fmt.Sprintf("[*] Trying %s:%d (%d/%d)...", input.Target, port, i+1, len(input.Ports)))
			var result TunnelResult
			if direction == "Reverse" {
				// Reverse: client is exit node, server has SOCKS.
				result = runTunnelClientReverse(ctx, proto, port, input.Target, input.Emit)
			} else {
				// Forward (default): client has SOCKS, server is exit node.
				result = runTunnelClient(ctx, proto, port, input.Target, input.Service, input.Emit)
			}
			if result.Error == nil {
				return result
			}
			input.Emit(fmt.Sprintf("[-] Port %d: %s", port, result.Error))
		}
		return TunnelResult{Error: fmt.Errorf("could not find %s tunnel on any port", proto)}
	default:
		return TunnelResult{Error: fmt.Errorf("unknown role: %s", input.Role)}
	}
}

// ── Reverse tunnel server: accept connection, open local SOCKS forwarder ──

func runTunnelServerReverse(ctx context.Context, proto string, port int, emit func(string)) TunnelResult {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return TunnelResult{Error: err}
	}
	defer ln.Close()
	emit(fmt.Sprintf("[+] Reverse %s tunnel bound on %s", proto, addr))
	emit(fmt.Sprintf("[+] Listening on port %d — waiting for client exit node...", port))
	go func() { <-ctx.Done(); ln.Close() }()

	// Accept the tunnel connection from the Client (exit node).
	conn, err := ln.Accept()
	if err != nil {
		if ctx.Err() != nil {
			return TunnelResult{}
		}
		return TunnelResult{Error: err}
	}
	defer conn.Close()
	emit(fmt.Sprintf("[+] Exit node connected from %s", conn.RemoteAddr()))

	// Open a local SOCKS5 forwarder on this server machine.
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return TunnelResult{Error: fmt.Errorf("local SOCKS listener: %w", err)}
	}
	defer socksLn.Close()
	localAddr := socksLn.Addr().String()
	emit(fmt.Sprintf("[+] Local SOCKS5 forwarder on %s", localAddr))
	emit(fmt.Sprintf("[+] Reverse tunnel active — socks5://%s → exit via client", localAddr))
	emit(fmt.Sprintf("[*] Point applications at socks5://%s", localAddr))

	go func() { <-ctx.Done(); socksLn.Close() }()

	// Each SOCKS5 connection: read target, send to exit node over tunnel,
	// relay bidirectionally. Serialized: the single tunnel connection can
	// only carry one relay at a time. Queued requests wait their turn.
	for {
		local, err := socksLn.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return TunnelResult{}
			}
			continue
		}
		// Serialized — one connection at a time through the tunnel.
		handleReverseTunnelSOCKS(local, conn, emit)
	}
}

// handleReverseTunnelSOCKS accepts a SOCKS5 request from a local app,
// sends the target to the exit node, and relays traffic.
func handleReverseTunnelSOCKS(local, tunnel net.Conn, emit func(string)) {
	defer local.Close()
	local.SetDeadline(time.Now().Add(5 * time.Minute))

	buf := make([]byte, tunnelFrameBuf)

	// SOCKS5 greeting.
	n, err := local.Read(buf)
	if err != nil || n < 3 || buf[0] != 0x05 {
		return
	}
	local.Write([]byte{0x05, 0x00})

	// CONNECT request.
	n, err = local.Read(buf)
	if err != nil || n < 7 || buf[0] != 0x05 || buf[1] != 0x01 {
		local.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	target := parseSOCKS5Target(buf[:n])
	if target == "" {
		local.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Send target to exit node via length-prefixed message over tunnel.
	targetBytes := []byte(target)
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(targetBytes)))
	tunnel.Write(header)
	tunnel.Write(targetBytes)

	// Read response from exit node.
	respBuf := make([]byte, 4)
	if _, err := io.ReadFull(tunnel, respBuf); err != nil {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	respLen := binary.BigEndian.Uint32(respBuf)
	if respLen > 256 {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	resp := make([]byte, respLen)
	io.ReadFull(tunnel, resp)
	if string(resp) != "ok" {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Success — relay traffic through tunnel.
	local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	emit(fmt.Sprintf("[+] Reverse SOCKS5: proxying → %s", target))

	// Bidirectional relay using length-prefixed frames over the shared tunnel.
	// Can't use raw io.Copy on the shared tunnel — it would consume bytes
	// from the next SOCKS request. Instead, frame each direction's data.
	done := make(chan struct{}, 2)

	// local → tunnel: read from SOCKS client, send as length-prefixed frames.
	go func() {
		buf := make([]byte, tunnelRelayBuf)
		for {
			n, err := local.Read(buf)
			if n > 0 {
				frame := make([]byte, 4+n)
				binary.BigEndian.PutUint32(frame[:4], uint32(n))
				if _, werr := tunnel.Write(frame[:4]); werr != nil {
					done <- struct{}{}
					return
				}
				if _, werr := tunnel.Write(buf[:n]); werr != nil {
					done <- struct{}{}
					return
				}
			}
			if err != nil {
				// Signal end of stream to exit node with zero-length frame.
				eof := make([]byte, 4)
				tunnel.Write(eof)
				done <- struct{}{}
				return
			}
		}
	}()

	// tunnel → local: read length-prefixed frames from exit node, write to SOCKS client.
	go func() {
		for {
			var lenBuf [4]byte
			if _, err := io.ReadFull(tunnel, lenBuf[:]); err != nil {
				done <- struct{}{}
				return
			}
			frameLen := binary.BigEndian.Uint32(lenBuf[:])
			if frameLen == 0 {
				// End of stream signal from exit node.
				done <- struct{}{}
				return
			}
			if frameLen > tunnelRelayBuf {
				done <- struct{}{}
				return
			}
			data := make([]byte, frameLen)
			if _, err := io.ReadFull(tunnel, data); err != nil {
				done <- struct{}{}
				return
			}
			if _, err := local.Write(data); err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	<-done
	local.Close()
}

// ── Reverse tunnel client: connect to server, act as exit node ────────────

func runTunnelClientReverse(ctx context.Context, proto string, port int, target string, emit func(string)) TunnelResult {
	proxyAddr := net.JoinHostPort(target, fmt.Sprintf("%d", port))

	conn, err := net.DialTimeout("tcp", proxyAddr, tunnelDialTimeout)
	if err != nil {
		return TunnelResult{Error: fmt.Errorf("cannot reach %s: %w", proxyAddr, err)}
	}
	defer conn.Close()

	emit(fmt.Sprintf("[+] Connected to server at %s as exit node", proxyAddr))
	emit("[+] Reverse tunnel active — proxying server's traffic to destinations")
	emit("[*] Waiting for proxy requests from server...")

	// Exit node loop: read target requests, connect, relay.
	for {
		if ctx.Err() != nil {
			return TunnelResult{}
		}
		conn.SetDeadline(time.Now().Add(5 * time.Minute))

		// Read length-prefixed target from server.
		header := make([]byte, 4)
		if _, err := io.ReadFull(conn, header); err != nil {
			if ctx.Err() != nil {
				return TunnelResult{}
			}
			return TunnelResult{Error: fmt.Errorf("tunnel closed: %w", err)}
		}
		targetLen := binary.BigEndian.Uint32(header)
		if targetLen == 0 || targetLen > 256 {
			continue
		}
		targetBuf := make([]byte, targetLen)
		if _, err := io.ReadFull(conn, targetBuf); err != nil {
			return TunnelResult{Error: err}
		}
		destAddr := string(targetBuf)

		// Connect to destination.
		remote, err := net.DialTimeout("tcp", destAddr, 10*time.Second)
		if err != nil {
			// Send failure.
			fail := []byte("fail")
			resp := make([]byte, 4)
			binary.BigEndian.PutUint32(resp, uint32(len(fail)))
			conn.Write(resp)
			conn.Write(fail)
			emit(fmt.Sprintf("[-] Cannot reach %s: %s", destAddr, err))
			continue
		}

		// Send success.
		ok := []byte("ok")
		resp := make([]byte, 4)
		binary.BigEndian.PutUint32(resp, uint32(len(ok)))
		conn.Write(resp)
		conn.Write(ok)
		emit(fmt.Sprintf("[+] Exit: proxying → %s", destAddr))

		// Framed relay — tunnel is shared, can't use raw io.Copy.
		// Each direction uses 4-byte length-prefixed frames. Zero-length = EOF.
		relayDone := make(chan struct{}, 2)

		// tunnel → remote: read framed data from server, write raw to destination.
		go func() {
			for {
				var lenBuf [4]byte
				if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
					relayDone <- struct{}{}
					return
				}
				frameLen := binary.BigEndian.Uint32(lenBuf[:])
				if frameLen == 0 {
					relayDone <- struct{}{}
					return
				}
				if frameLen > tunnelRelayBuf {
					relayDone <- struct{}{}
					return
				}
				data := make([]byte, frameLen)
				if _, err := io.ReadFull(conn, data); err != nil {
					relayDone <- struct{}{}
					return
				}
				if _, err := remote.Write(data); err != nil {
					relayDone <- struct{}{}
					return
				}
			}
		}()

		// remote → tunnel: read raw from destination, send as framed data to server.
		go func() {
			buf := make([]byte, tunnelRelayBuf)
			for {
				n, err := remote.Read(buf)
				if n > 0 {
					frame := make([]byte, 4)
					binary.BigEndian.PutUint32(frame, uint32(n))
					if _, werr := conn.Write(frame); werr != nil {
						relayDone <- struct{}{}
						return
					}
					if _, werr := conn.Write(buf[:n]); werr != nil {
						relayDone <- struct{}{}
						return
					}
				}
				if err != nil {
					eof := make([]byte, 4)
					conn.Write(eof)
					relayDone <- struct{}{}
					return
				}
			}
		}()
		<-relayDone
		remote.Close()
		emit(fmt.Sprintf("[+] Exit: relay to %s completed, waiting for next request...", destAddr))
		// Continue loop — wait for next target request from server.
	}
}

// ── Dead drop dispatch ──────────────────────────────────────────────────────

// isDeadDropProto returns true for protocol labels that use the dead drop
// relay system (API-only, no direct TCP between client and server).
func isDeadDropProto(proto string) bool {
	switch proto {
	case "github-deaddrop", "openai-deaddrop":
		return true
	}
	return false
}

// runDeadDropTunnel dispatches to the correct dead drop transport for the
// given protocol and role. Dead drop tunnels need no ports or target address.
func runDeadDropTunnel(ctx context.Context, proto, role string, emit func(string)) TunnelResult {
	if role == "" {
		role = "Client"
	}
	switch role {
	case "Server":
		switch proto {
		case "github-deaddrop":
			return serveGithubDeadDrop(ctx, emit)
		case "openai-deaddrop":
			return serveOpenAIDeadDrop(ctx, emit)
		}
	case "Client":
		switch proto {
		case "github-deaddrop":
			return connectGithubDeadDropClient(ctx, emit)
		case "openai-deaddrop":
			return connectOpenAIDeadDropClient(ctx, emit)
		}
	default:
		return TunnelResult{Error: fmt.Errorf("unknown role: %s", role)}
	}
	return TunnelResult{Error: fmt.Errorf("unknown dead drop protocol: %s", proto)}
}

// ── Server dispatch ─────────────────────────────────────────────────────────

func runTunnelServer(ctx context.Context, proto string, port int, emit func(string)) TunnelResult {
	switch proto {
	case "socks5":
		return serveSocks5(ctx, port, emit)
	case "socks4":
		return serveSocks4(ctx, port, emit)
	case "http", "http-proxy", "http-alt":
		return serveHTTPTunnel(ctx, false, port, emit)
	case "https", "https-alt":
		return serveHTTPTunnel(ctx, true, port, emit)
	case "ws":
		return serveWSTunnel(ctx, false, port, emit)
	case "wss":
		return serveWSTunnel(ctx, true, port, emit)
	case "dns":
		return serveDNSTunnel(ctx, port, emit)
	case "ntp":
		return serveNTPTunnel(ctx, port, emit)
	case "smtp":
		return serveSMTPTunnel(ctx, port, emit)
	case "ftp":
		return serveFTPTunnel(ctx, port, emit)
	case "imap":
		return serveIMAPTunnel(ctx, port, emit)
	case "pop3":
		return servePOP3Tunnel(ctx, port, emit)
	case "redis":
		return serveRedisTunnel(ctx, port, emit)
	case "postgres":
		return servePostgresTunnel(ctx, port, emit)
	case "ldap":
		return serveLDAPTunnel(ctx, port, emit)
	case "smb":
		return serveSMBTunnel(ctx, port, emit)
	case "mqtt":
		return serveMQTTTunnel(ctx, port, emit)
	case "amqp":
		return serveAMQPTunnel(ctx, port, emit)
	case "ssh":
		return serveSSHTunnel(ctx, port, emit)
	case "rdp":
		return serveRDPTunnel(ctx, port, emit)
	case "quic":
		return serveQUICTunnel(ctx, port, emit)
	case "webrtc":
		return serveWebRTCTunnel(ctx, port, emit)
	case "openai-api", "openai-service":
		return serveOpenAITunnel(ctx, port, emit)
	case "domainfront":
		return serveDomainFrontTunnel(ctx, port, emit)
	default:
		return serveSocks5(ctx, port, emit)
	}
}

// ── Client dispatch ─────────────────────────────────────────────────────────

func runTunnelClient(ctx context.Context, proto string, port int, target, service string, emit func(string)) TunnelResult {
	if target == "" {
		return TunnelResult{Error: fmt.Errorf("no target specified")}
	}
	proxyAddr := net.JoinHostPort(target, fmt.Sprintf("%d", port))

	switch proto {
	case "socks5":
		return connectSocks5Client(ctx, proxyAddr, emit)
	case "socks4":
		return connectSocks4Client(ctx, proxyAddr, emit)
	case "http", "http-proxy", "http-alt":
		return connectHTTPTunnelClient(ctx, false, proxyAddr, emit)
	case "https", "https-alt":
		return connectHTTPTunnelClient(ctx, true, proxyAddr, emit)
	case "ws":
		return connectWSTunnelClient(ctx, false, proxyAddr, emit)
	case "wss":
		return connectWSTunnelClient(ctx, true, proxyAddr, emit)
	case "dns":
		return connectDNSTunnelClient(ctx, proxyAddr, emit)
	case "ntp":
		return connectNTPTunnelClient(ctx, proxyAddr, emit)
	case "smtp":
		return connectSMTPTunnelClient(ctx, proxyAddr, emit)
	case "ftp":
		return connectFTPTunnelClient(ctx, proxyAddr, emit)
	case "imap":
		return connectIMAPTunnelClient(ctx, proxyAddr, emit)
	case "pop3":
		return connectPOP3TunnelClient(ctx, proxyAddr, emit)
	case "redis":
		return connectRedisTunnelClient(ctx, proxyAddr, emit)
	case "postgres":
		return connectPostgresTunnelClient(ctx, proxyAddr, emit)
	case "ldap":
		return connectLDAPTunnelClient(ctx, proxyAddr, emit)
	case "smb":
		return connectSMBTunnelClient(ctx, proxyAddr, emit)
	case "mqtt":
		return connectMQTTTunnelClient(ctx, proxyAddr, emit)
	case "amqp":
		return connectAMQPTunnelClient(ctx, proxyAddr, emit)
	case "ssh":
		return connectSSHTunnelClient(ctx, proxyAddr, emit)
	case "rdp":
		return connectRDPTunnelClient(ctx, proxyAddr, emit)
	case "quic":
		return connectQUICTunnelClient(ctx, proxyAddr, emit)
	case "webrtc":
		return connectWebRTCTunnelClient(ctx, proxyAddr, emit)
	case "openai-api", "openai-service":
		return connectOpenAITunnelClient(ctx, proxyAddr, emit)
	case "domainfront":
		return connectDomainFrontTunnelClient(ctx, proxyAddr, emit)
	default:
		return connectSocks5Client(ctx, proxyAddr, emit)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// SOCKS5 — standard SOCKS5 binary protocol (RFC 1928)
// Wire: 0x05 version, auth negotiation, CONNECT request, bidirectional relay
// ═══════════════════════════════════════════════════════════════════════════

func serveSocks5(ctx context.Context, port int, emit func(string)) TunnelResult {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return TunnelResult{Error: err}
	}
	defer ln.Close()
	emit(fmt.Sprintf("[+] SOCKS5 tunnel bound on %s", addr))
	emit(fmt.Sprintf("[+] Listening on port %d — waiting for client...", port))
	go func() { <-ctx.Done(); ln.Close() }()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return TunnelResult{}
			}
			continue
		}
		emit(fmt.Sprintf("[+] Client connected from %s", conn.RemoteAddr()))
		go handleSocks5(conn, emit)
	}
}

func handleSocks5(conn net.Conn, emit func(string)) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Minute))

	buf := make([]byte, tunnelFrameBuf)

	// Auth negotiation: version 5, methods.
	n, err := conn.Read(buf)
	if err != nil || n < 3 || buf[0] != 0x05 {
		return
	}
	conn.Write([]byte{0x05, 0x00}) // no auth

	// CONNECT request.
	n, err = conn.Read(buf)
	if err != nil || n < 7 || buf[0] != 0x05 || buf[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	targetAddr := parseSOCKS5Target(buf[:n])
	if targetAddr == "" {
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	remote, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	emit(fmt.Sprintf("[+] SOCKS5: proxying → %s", targetAddr))
	relay(conn, remote)
}

func connectSocks5Client(ctx context.Context, proxyAddr string, emit func(string)) TunnelResult {
	// Verify with real SOCKS5 handshake.
	conn, err := net.DialTimeout("tcp", proxyAddr, tunnelDialTimeout)
	if err != nil {
		return TunnelResult{Error: fmt.Errorf("cannot reach %s: %w", proxyAddr, err)}
	}
	conn.SetDeadline(time.Now().Add(tunnelIOTimeout))
	conn.Write([]byte{0x05, 0x01, 0x00})
	buf := make([]byte, 2)
	_, err = io.ReadFull(conn, buf)
	conn.Close()
	if err != nil || buf[0] != 0x05 {
		return TunnelResult{Error: fmt.Errorf("SOCKS5 handshake failed on %s", proxyAddr)}
	}

	return startLocalForwarder(ctx, proxyAddr, "socks5", emit, func(local net.Conn) {
		forwardSocks5(local, proxyAddr, emit)
	})
}

func forwardSocks5(local net.Conn, proxyAddr string, emit func(string)) {
	defer local.Close()
	local.SetDeadline(time.Now().Add(5 * time.Minute))

	buf := make([]byte, tunnelFrameBuf)

	// Read local SOCKS5 greeting, respond.
	n, err := local.Read(buf)
	if err != nil || n < 3 || buf[0] != 0x05 {
		return
	}
	local.Write([]byte{0x05, 0x00})

	// Read CONNECT request.
	n, err = local.Read(buf)
	if err != nil || n < 7 || buf[0] != 0x05 || buf[1] != 0x01 {
		local.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	connectReq := make([]byte, n)
	copy(connectReq, buf[:n])

	// Dial remote SOCKS5 proxy.
	remote, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()
	remote.SetDeadline(time.Now().Add(5 * time.Minute))

	// Forward to remote SOCKS5 proxy.
	remote.Write([]byte{0x05, 0x01, 0x00})
	rbuf := make([]byte, 2)
	if _, err := io.ReadFull(remote, rbuf); err != nil || rbuf[0] != 0x05 {
		local.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	remote.Write(connectReq)
	resp := make([]byte, tunnelFrameBuf)
	rn, err := remote.Read(resp)
	if err != nil || rn < 2 || resp[1] != 0x00 {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	local.Write(resp[:rn])

	target := parseSOCKS5Target(connectReq)
	if target != "" {
		emit(fmt.Sprintf("[+] SOCKS5 forwarding → %s", target))
	}
	relay(local, remote)
}

// ═══════════════════════════════════════════════════════════════════════════
// SOCKS4 — SOCKS4 binary protocol (no auth negotiation, 8-byte header)
// Wire: 0x04 version, 0x01 CONNECT, port(2), ip(4), userid, null
// ═══════════════════════════════════════════════════════════════════════════

func serveSocks4(ctx context.Context, port int, emit func(string)) TunnelResult {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return TunnelResult{Error: err}
	}
	defer ln.Close()
	emit(fmt.Sprintf("[+] SOCKS4 tunnel bound on %s", addr))
	emit(fmt.Sprintf("[+] Listening on port %d — waiting for client...", port))
	go func() { <-ctx.Done(); ln.Close() }()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return TunnelResult{}
			}
			continue
		}
		emit(fmt.Sprintf("[+] Client connected from %s", conn.RemoteAddr()))
		go handleSocks4(conn, emit)
	}
}

func handleSocks4(conn net.Conn, emit func(string)) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Minute))

	buf := make([]byte, tunnelFrameBuf)
	n, err := conn.Read(buf)
	if err != nil || n < 8 || buf[0] != 0x04 || buf[1] != 0x01 {
		return
	}

	dstPort := int(buf[2])<<8 | int(buf[3])
	dstIP := fmt.Sprintf("%d.%d.%d.%d", buf[4], buf[5], buf[6], buf[7])
	targetAddr := net.JoinHostPort(dstIP, fmt.Sprintf("%d", dstPort))

	// SOCKS4a: if IP is 0.0.0.x with x != 0, domain follows after userid null.
	if buf[4] == 0 && buf[5] == 0 && buf[6] == 0 && buf[7] != 0 {
		// Skip userid (find first null after byte 8).
		i := 8
		for i < n && buf[i] != 0 {
			i++
		}
		i++ // skip null
		// Read domain.
		j := i
		for j < n && buf[j] != 0 {
			j++
		}
		if j > i {
			targetAddr = fmt.Sprintf("%s:%d", string(buf[i:j]), dstPort)
		}
	}

	remote, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		// SOCKS4 reply: 0x00, 0x5B (rejected), port, ip
		conn.Write([]byte{0x00, 0x5B, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()

	// SOCKS4 reply: 0x00, 0x5A (granted), port, ip
	conn.Write([]byte{0x00, 0x5A, buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]})
	emit(fmt.Sprintf("[+] SOCKS4: proxying → %s", targetAddr))
	relay(conn, remote)
}

func connectSocks4Client(ctx context.Context, proxyAddr string, emit func(string)) TunnelResult {
	// Verify with real SOCKS4 handshake.
	conn, err := net.DialTimeout("tcp", proxyAddr, tunnelDialTimeout)
	if err != nil {
		return TunnelResult{Error: fmt.Errorf("cannot reach %s: %w", proxyAddr, err)}
	}
	conn.SetDeadline(time.Now().Add(tunnelIOTimeout))
	// SOCKS4 CONNECT to 0.0.0.1:80 (dummy) with SOCKS4a domain.
	req := []byte{0x04, 0x01, 0x00, 0x50, 0, 0, 0, 1, 0}
	req = append(req, []byte("proxywatch.verify")...)
	req = append(req, 0)
	conn.Write(req)
	buf := make([]byte, 8)
	_, err = io.ReadFull(conn, buf)
	conn.Close()
	// Accept 0x5A (granted) or 0x5B (rejected) — both prove it's SOCKS4.
	if err != nil || buf[0] != 0x00 || (buf[1] != 0x5A && buf[1] != 0x5B) {
		return TunnelResult{Error: fmt.Errorf("SOCKS4 handshake failed on %s", proxyAddr)}
	}

	return startLocalForwarder(ctx, proxyAddr, "socks4", emit, func(local net.Conn) {
		forwardSocks4(local, proxyAddr, emit)
	})
}

func forwardSocks4(local net.Conn, proxyAddr string, emit func(string)) {
	defer local.Close()
	local.SetDeadline(time.Now().Add(5 * time.Minute))

	buf := make([]byte, tunnelFrameBuf)

	// Local apps speak SOCKS5 to us. Accept SOCKS5, extract target,
	// then translate to SOCKS4 for the remote proxy.
	n, err := local.Read(buf)
	if err != nil || n < 3 || buf[0] != 0x05 {
		return
	}
	local.Write([]byte{0x05, 0x00}) // no auth

	n, err = local.Read(buf)
	if err != nil || n < 7 || buf[0] != 0x05 || buf[1] != 0x01 {
		local.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	target := parseSOCKS5Target(buf[:n])
	if target == "" {
		local.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Parse target into IP and port for SOCKS4 request.
	host, portStr, _ := net.SplitHostPort(target)
	var dstPort int
	fmt.Sscanf(portStr, "%d", &dstPort)

	// Dial remote SOCKS4 proxy.
	remote, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()
	remote.SetDeadline(time.Now().Add(5 * time.Minute))

	// Build SOCKS4a CONNECT request: VN=4, CD=1, port, IP=0.0.0.1, userid\0, domain\0
	s4req := []byte{0x04, 0x01, byte(dstPort >> 8), byte(dstPort), 0, 0, 0, 1, 0}
	s4req = append(s4req, []byte(host)...)
	s4req = append(s4req, 0)
	remote.Write(s4req)

	resp := make([]byte, 8)
	if _, err := io.ReadFull(remote, resp); err != nil || resp[1] != 0x5A {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// SOCKS5 success back to local app.
	local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	emit(fmt.Sprintf("[+] SOCKS4 forwarding → %s", target))
	relay(local, remote)
}

// ═══════════════════════════════════════════════════════════════════════════
// HTTP/HTTPS — tunnel data hidden inside normal HTTP POST/response streams
// Wire: looks like regular HTTP traffic (POST /api/stream with chunked body)
// Server responds with chunked 200 OK. Bidirectional data in HTTP bodies.
// ═══════════════════════════════════════════════════════════════════════════

const httpTunnelPath = "/api/stream"

func serveHTTPTunnel(ctx context.Context, useTLS bool, port int, emit func(string)) TunnelResult {
	addr := fmt.Sprintf("0.0.0.0:%d", port)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == httpTunnelPath {
			handleHTTPTunnelSession(w, r, emit)
			return
		}
		// Serve a plausible default page so it looks like a normal web server.
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><p>OK</p></body></html>\n")
	})

	srv := &http.Server{Addr: addr, Handler: handler}
	if useTLS {
		cert, err := generateSelfSignedCert()
		if err != nil {
			return TunnelResult{Error: err}
		}
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return TunnelResult{Error: err}
	}
	if useTLS {
		ln = tls.NewListener(ln, srv.TLSConfig)
	}

	proto := "HTTP"
	if useTLS {
		proto = "HTTPS"
	}
	emit(fmt.Sprintf("[+] %s tunnel bound on %s", proto, addr))
	emit(fmt.Sprintf("[+] Listening on port %d — waiting for client...", port))
	go func() { <-ctx.Done(); srv.Close() }()

	err = srv.Serve(ln)
	if err != nil && err != http.ErrServerClosed {
		return TunnelResult{Error: err}
	}
	return TunnelResult{}
}

func handleHTTPTunnelSession(w http.ResponseWriter, r *http.Request, emit func(string)) {
	emit(fmt.Sprintf("[+] Client connected from %s", r.RemoteAddr))

	// First line of the POST body is the target address.
	reader := bufio.NewReader(r.Body)
	targetLine, err := reader.ReadString('\n')
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	targetAddr := strings.TrimSpace(targetLine)
	if targetAddr == "" {
		http.Error(w, "no target", http.StatusBadRequest)
		return
	}

	remote, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		http.Error(w, "connection refused", http.StatusBadGateway)
		return
	}
	defer remote.Close()

	// Hijack to get a raw connection for bidirectional streaming.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}

	// Send HTTP 200 response with chunked encoding header.
	raw := "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n"
	conn, bufrw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	bufrw.WriteString(raw)
	bufrw.Flush()

	emit(fmt.Sprintf("[+] HTTP tunnel: proxying → %s", targetAddr))

	// Relay: remote → conn, and remaining POST body (via reader) + conn → remote.
	done := make(chan struct{}, 2)
	go func() { io.Copy(conn, remote); done <- struct{}{} }()
	go func() {
		// First drain any buffered POST body data.
		io.Copy(remote, reader)
		io.Copy(remote, conn)
		done <- struct{}{}
	}()
	<-done
}

func connectHTTPTunnelClient(ctx context.Context, useTLS bool, proxyAddr string, emit func(string)) TunnelResult {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}

	// Verify it's our HTTP tunnel by checking the default page.
	verifyConn, err := dialProxy(proxyAddr, useTLS)
	if err != nil {
		return TunnelResult{Error: fmt.Errorf("cannot reach %s: %w", proxyAddr, err)}
	}
	verifyConn.SetDeadline(time.Now().Add(tunnelIOTimeout))
	fmt.Fprintf(verifyConn, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", proxyAddr)
	buf := make([]byte, 512)
	n, _ := verifyConn.Read(buf)
	verifyConn.Close()
	if !strings.HasPrefix(string(buf[:n]), "HTTP/") {
		return TunnelResult{Error: fmt.Errorf("not an HTTP server on %s", proxyAddr)}
	}

	return startLocalForwarder(ctx, proxyAddr, scheme, emit, func(local net.Conn) {
		forwardHTTPTunnel(local, proxyAddr, useTLS, emit)
	})
}

// forwardHTTPTunnel sends a SOCKS5-accepted target over HTTP POST to the remote tunnel server.
func forwardHTTPTunnel(local net.Conn, proxyAddr string, useTLS bool, emit func(string)) {
	defer local.Close()
	local.SetDeadline(time.Now().Add(5 * time.Minute))

	// Accept SOCKS5 from local app, extract target.
	buf := make([]byte, tunnelFrameBuf)
	n, err := local.Read(buf)
	if err != nil || n < 3 || buf[0] != 0x05 {
		return
	}
	local.Write([]byte{0x05, 0x00})

	n, err = local.Read(buf)
	if err != nil || n < 7 || buf[0] != 0x05 || buf[1] != 0x01 {
		local.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	target := parseSOCKS5Target(buf[:n])
	if target == "" {
		local.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Connect to remote HTTP tunnel — POST with target as first line.
	remote, err := dialProxy(proxyAddr, useTLS)
	if err != nil {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()
	remote.SetDeadline(time.Now().Add(5 * time.Minute))

	// Send HTTP POST with target in body. Use large Content-Length
	// so the server's r.Body stays open for streaming.
	header := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/octet-stream\r\nContent-Length: 999999999\r\n\r\n",
		httpTunnelPath, proxyAddr)
	remote.Write([]byte(header))
	// First line: target address.
	remote.Write([]byte(target + "\n"))

	// Read HTTP 200 response.
	respBuf := make([]byte, 512)
	rn, err := remote.Read(respBuf)
	if err != nil || !strings.Contains(string(respBuf[:rn]), "200") {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// SOCKS5 success to local app.
	local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	emit(fmt.Sprintf("[+] HTTP tunnel forwarding → %s", target))
	relay(local, remote)
}

// ═══════════════════════════════════════════════════════════════════════════
// WS/WSS — WebSocket upgrade then binary frames carry tunnel data
// Wire: HTTP upgrade handshake, then WebSocket binary frames
// ═══════════════════════════════════════════════════════════════════════════

const wsMagicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func serveWSTunnel(ctx context.Context, useTLS bool, port int, emit func(string)) TunnelResult {
	addr := fmt.Sprintf("0.0.0.0:%d", port)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			handleWSSession(w, r, emit)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><p>OK</p></body></html>\n")
	})

	srv := &http.Server{Addr: addr, Handler: handler}
	if useTLS {
		cert, err := generateSelfSignedCert()
		if err != nil {
			return TunnelResult{Error: err}
		}
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return TunnelResult{Error: err}
	}
	if useTLS {
		ln = tls.NewListener(ln, srv.TLSConfig)
	}

	proto := "WS"
	if useTLS {
		proto = "WSS"
	}
	emit(fmt.Sprintf("[+] %s tunnel bound on %s", proto, addr))
	emit(fmt.Sprintf("[+] Listening on port %d — waiting for client...", port))
	go func() { <-ctx.Done(); srv.Close() }()

	err = srv.Serve(ln)
	if err != nil && err != http.ErrServerClosed {
		return TunnelResult{Error: err}
	}
	return TunnelResult{}
}

func handleWSSession(w http.ResponseWriter, r *http.Request, emit func(string)) {
	emit(fmt.Sprintf("[+] WebSocket client from %s", r.RemoteAddr))

	// Complete WebSocket handshake.
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "missing key", http.StatusBadRequest)
		return
	}
	acceptKey := wsAcceptKey(key)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	conn, bufrw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	// Send upgrade response.
	bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	bufrw.WriteString("Upgrade: websocket\r\n")
	bufrw.WriteString("Connection: Upgrade\r\n")
	bufrw.WriteString("Sec-WebSocket-Accept: " + acceptKey + "\r\n\r\n")
	bufrw.Flush()

	// First binary frame contains the target address.
	target, err := wsReadText(conn)
	if err != nil || target == "" {
		return
	}

	remote, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		wsWriteText(conn, "error:"+err.Error())
		return
	}
	defer remote.Close()
	wsWriteText(conn, "ok")

	emit(fmt.Sprintf("[+] WS tunnel: proxying → %s", target))

	// Relay using WebSocket binary frames.
	done := make(chan struct{}, 2)
	go func() { wsRelayToConn(conn, remote); done <- struct{}{} }()
	go func() { wsRelayFromConn(remote, conn); done <- struct{}{} }()
	<-done
}

func connectWSTunnelClient(ctx context.Context, useTLS bool, proxyAddr string, emit func(string)) TunnelResult {
	scheme := "ws"
	if useTLS {
		scheme = "wss"
	}

	// Verify by attempting WebSocket upgrade.
	conn, err := dialProxy(proxyAddr, useTLS)
	if err != nil {
		return TunnelResult{Error: fmt.Errorf("cannot reach %s: %w", proxyAddr, err)}
	}
	conn.SetDeadline(time.Now().Add(tunnelIOTimeout))
	wsKey := base64.StdEncoding.EncodeToString([]byte("proxywatch-verify"))
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		proxyAddr, wsKey)
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	conn.Close()
	if !strings.Contains(string(buf[:n]), "101") {
		return TunnelResult{Error: fmt.Errorf("WebSocket upgrade failed on %s", proxyAddr)}
	}

	return startLocalForwarder(ctx, proxyAddr, scheme, emit, func(local net.Conn) {
		forwardWSTunnel(local, proxyAddr, useTLS, emit)
	})
}

func forwardWSTunnel(local net.Conn, proxyAddr string, useTLS bool, emit func(string)) {
	defer local.Close()
	local.SetDeadline(time.Now().Add(5 * time.Minute))

	// Accept SOCKS5 from local app.
	buf := make([]byte, tunnelFrameBuf)
	n, err := local.Read(buf)
	if err != nil || n < 3 || buf[0] != 0x05 {
		return
	}
	local.Write([]byte{0x05, 0x00})

	n, err = local.Read(buf)
	if err != nil || n < 7 || buf[0] != 0x05 || buf[1] != 0x01 {
		local.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	target := parseSOCKS5Target(buf[:n])
	if target == "" {
		local.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// WebSocket upgrade to remote server.
	remote, err := dialProxy(proxyAddr, useTLS)
	if err != nil {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()
	remote.SetDeadline(time.Now().Add(5 * time.Minute))

	wsKey := base64.StdEncoding.EncodeToString([]byte("proxywatch-tunnel"))
	fmt.Fprintf(remote, "GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		proxyAddr, wsKey)

	respBuf := make([]byte, 512)
	rn, err := remote.Read(respBuf)
	if err != nil || !strings.Contains(string(respBuf[:rn]), "101") {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Send target via WebSocket text frame, wait for "ok".
	wsWriteText(remote, target)
	resp, err := wsReadText(remote)
	if err != nil || resp != "ok" {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	emit(fmt.Sprintf("[+] WS tunnel forwarding → %s", target))

	// Relay using WebSocket binary frames.
	done := make(chan struct{}, 2)
	go func() { wsRelayToConn(remote, local); done <- struct{}{} }()
	go func() { wsRelayFromConn(local, remote); done <- struct{}{} }()
	<-done
}

// ═══════════════════════════════════════════════════════════════════════════
// Shared helpers
// ═══════════════════════════════════════════════════════════════════════════

func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(b, a); done <- struct{}{} }()
	go func() { io.Copy(a, b); done <- struct{}{} }()
	<-done // wait for first direction to finish
	// Close both sides to unblock the other direction's io.Copy.
	a.Close()
	b.Close()
	<-done // wait for second direction to clean up
}

func dialProxy(addr string, useTLS bool) (net.Conn, error) {
	if useTLS {
		return tls.DialWithDialer(&net.Dialer{Timeout: tunnelDialTimeout}, "tcp", addr,
			&tls.Config{InsecureSkipVerify: true})
	}
	return net.DialTimeout("tcp", addr, tunnelDialTimeout)
}

// startLocalForwarder opens a local SOCKS5 listener and relays each
// accepted connection through the remote proxy via the provided handler.
func startLocalForwarder(ctx context.Context, proxyAddr, scheme string, emit func(string),
	handler func(local net.Conn)) TunnelResult {

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return TunnelResult{Error: fmt.Errorf("local listener: %w", err)}
	}
	defer ln.Close()
	localAddr := ln.Addr().String()

	emit(fmt.Sprintf("[+] Remote %s tunnel verified at %s", strings.ToUpper(scheme), proxyAddr))
	emit(fmt.Sprintf("[+] Local SOCKS5 forwarder on %s", localAddr))
	emit(fmt.Sprintf("[+] Tunnel active — socks5://%s → %s://%s", localAddr, scheme, proxyAddr))
	emit(fmt.Sprintf("[*] Point applications at socks5://%s", localAddr))

	go func() { <-ctx.Done(); ln.Close() }()

	for {
		local, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return TunnelResult{}
			}
			continue
		}
		go handler(local)
	}
}

func parseSOCKS5Target(req []byte) string {
	if len(req) < 7 {
		return ""
	}
	switch req[3] {
	case 0x01: // IPv4
		if len(req) < 10 {
			return ""
		}
		return fmt.Sprintf("%d.%d.%d.%d:%d", req[4], req[5], req[6], req[7],
			int(req[8])<<8|int(req[9]))
	case 0x03: // Domain
		dlen := int(req[4])
		if len(req) < 5+dlen+2 {
			return ""
		}
		return fmt.Sprintf("%s:%d", string(req[5:5+dlen]),
			int(req[5+dlen])<<8|int(req[5+dlen+1]))
	case 0x04: // IPv6
		if len(req) < 22 {
			return ""
		}
		return fmt.Sprintf("[%s]:%d", net.IP(req[4:20]).String(),
			int(req[20])<<8|int(req[21]))
	}
	return ""
}

// ── Minimal WebSocket frame helpers (no external dependency) ────────────

func wsAcceptKey(clientKey string) string {
	h := sha1.New()
	h.Write([]byte(clientKey + wsMagicGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func wsWriteText(conn net.Conn, msg string) {
	wsWriteFrame(conn, 0x01, []byte(msg))
}

func wsWriteFrame(conn net.Conn, opcode byte, payload []byte) {
	// Server frames are NOT masked.
	frame := []byte{0x80 | opcode}
	plen := len(payload)
	if plen < 126 {
		frame = append(frame, byte(plen))
	} else if plen < 65536 {
		frame = append(frame, 126)
		frame = append(frame, byte(plen>>8), byte(plen))
	} else {
		frame = append(frame, 127)
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(plen))
		frame = append(frame, b...)
	}
	frame = append(frame, payload...)
	conn.Write(frame)
}

func wsReadText(conn net.Conn) (string, error) {
	data, err := wsReadFrame(conn)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func wsReadFrame(conn net.Conn) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	masked := header[1]&0x80 != 0
	plen := int(header[1] & 0x7F)

	if plen == 126 {
		ext := make([]byte, 2)
		if _, err := io.ReadFull(conn, ext); err != nil {
			return nil, err
		}
		plen = int(binary.BigEndian.Uint16(ext))
	} else if plen == 127 {
		ext := make([]byte, 8)
		if _, err := io.ReadFull(conn, ext); err != nil {
			return nil, err
		}
		plen = int(binary.BigEndian.Uint64(ext))
	}

	var maskKey []byte
	if masked {
		maskKey = make([]byte, 4)
		if _, err := io.ReadFull(conn, maskKey); err != nil {
			return nil, err
		}
	}

	payload := make([]byte, plen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	return payload, nil
}

// wsRelayToConn reads WebSocket frames from ws and writes raw data to conn.
func wsRelayToConn(ws, conn net.Conn) {
	for {
		data, err := wsReadFrame(ws)
		if err != nil {
			return
		}
		if _, err := conn.Write(data); err != nil {
			return
		}
	}
}

// wsRelayFromConn reads raw data from conn and sends as WebSocket binary frames.
func wsRelayFromConn(conn, ws net.Conn) {
	buf := make([]byte, tunnelRelayBuf)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		wsWriteFrame(ws, 0x02, buf[:n]) // binary frame
	}
}
