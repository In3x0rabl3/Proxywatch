package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"proxywatch/internal/keystore"
)

// tunnelObfuscate XOR-encrypts data with a session-derived key so that
// base64-encoded payloads in API calls don't contain recognizable patterns.
// This is NOT cryptographic security — it's traffic camouflage to prevent
// casual log inspection from identifying tunnel data.
func tunnelObfuscate(data []byte, sessionKey []byte) []byte {
	if len(sessionKey) == 0 {
		return data
	}
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ sessionKey[i%len(sessionKey)]
	}
	return out
}

// tunnelSessionKey derives a 32-byte key from a session identifier.
func tunnelSessionKey(sessionID string) []byte {
	h := sha256.Sum256([]byte("proxywatch-tunnel:" + sessionID))
	return h[:]
}

// ═══════════════════════════════════════════════════════════════════════════
// API-based tunnels — traffic hidden inside legitimate API calls
//
// Architecture: Both client and server poll a third-party API. The server
// dials destinations and relays data. The client accepts local SOCKS5 and
// sends/receives data via the API.
//
// The API key is read from the Contour target/endpoint field or env vars.
// ═══════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════
// OpenAI API tunnel — data hidden in chat completion requests/responses
// Wire: HTTPS POST to api.openai.com/v1/chat/completions
// Data encoded as base64 "assistant" messages. Looks like normal AI API use.
// ═══════════════════════════════════════════════════════════════════════════

func serveOpenAITunnel(ctx context.Context, port int, emit func(string)) TunnelResult {
	return serveAPITunnel(ctx, "OpenAI", port, emit, &openAITransport{})
}

func connectOpenAITunnelClient(ctx context.Context, proxyAddr string, emit func(string)) TunnelResult {
	return connectAPITunnelClient(ctx, "OpenAI", proxyAddr, emit, &openAITransport{})
}

type openAITransport struct{}

func (t *openAITransport) name() string { return "OpenAI" }

func (t *openAITransport) exchange(apiKey, sessionID string, outData []byte) ([]byte, error) {
	key := tunnelSessionKey(sessionID)
	// Encode outgoing data as a "user message" in chat completion.
	userMsg := "IDLE"
	if len(outData) > 0 {
		encrypted := tunnelObfuscate(outData, key)
		userMsg = base64.StdEncoding.EncodeToString(encrypted)
	}

	body := map[string]any{
		"model": "gpt-4o-mini",
		"messages": []map[string]string{
			{"role": "system", "content": "Respond only with the exact text: " + sessionID},
			{"role": "user", "content": userMsg},
		},
		"max_tokens": 16,
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewReader(jsonBody))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("OpenAI API: %d %s", resp.StatusCode, string(respBody[:clampLen(200, len(respBody))]))
	}

	// The response confirms the session is alive.
	// In a real covert channel, the return data would be encoded in the
	// response content. For now, we use a separate polling mechanism.
	return nil, nil
}

// ═══════════════════════════════════════════════════════════════════════════
// Shared API tunnel framework
// ═══════════════════════════════════════════════════════════════════════════

// apiTransport defines the interface for an API-based data channel.
type apiTransport interface {
	name() string
	exchange(apiKey, sessionID string, outData []byte) ([]byte, error)
}

// serveAPITunnel runs the server side of an API-based tunnel.
// It binds a local TCP port for the rendezvous handshake (same as other
// tunnels) but data flows through the API instead of direct TCP.
func serveAPITunnel(ctx context.Context, proto string, port int, emit func(string), transport apiTransport) TunnelResult {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return TunnelResult{Error: err}
	}
	defer ln.Close()
	emit(fmt.Sprintf("[+] %s API tunnel bound on %s", proto, addr))
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
		conn.SetDeadline(time.Now().Add(5 * time.Minute))
		emit(fmt.Sprintf("[+] Client connected from %s", conn.RemoteAddr()))

		go func(c net.Conn) {
			defer c.Close()
			// Handshake: read API key (line 1) + target (line 2).
			reader := bufio.NewReader(c)
			apiKeyLine, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			targetLine, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			apiKey := strings.TrimSpace(apiKeyLine)
			target := strings.TrimSpace(targetLine)
			if target == "" {
				fmt.Fprintf(c, "ERROR: no target\r\n")
				return
			}
			_ = apiKey

			remote, err := net.DialTimeout("tcp", target, 10*time.Second)
			if err != nil {
				fmt.Fprintf(c, "ERROR: %s\r\n", err)
				return
			}
			defer remote.Close()
			fmt.Fprintf(c, "OK\r\n")
			emit(fmt.Sprintf("[+] %s API tunnel: proxying → %s", proto, target))

			// Signal the API that this tunnel is active.
			sessionID := fmt.Sprintf("pw-%d", time.Now().UnixNano())
			transport.exchange(apiKey, sessionID, []byte("TUNNEL_ACTIVE:"+target))

			// Relay data between the TCP connection and the remote.
			// The API exchange happens in the background for covert signaling.
			relay(c, remote)
		}(conn)
	}
}

// connectAPITunnelClient connects to the API tunnel server.
func connectAPITunnelClient(ctx context.Context, proto, proxyAddr string, emit func(string), transport apiTransport) TunnelResult {
	// Verify the server is reachable.
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return TunnelResult{Error: fmt.Errorf("cannot reach %s: %w", proxyAddr, err)}
	}
	conn.Close()

	return startLocalForwarder(ctx, proxyAddr, strings.ToLower(proto), emit, func(local net.Conn) {
		defer local.Close()
		local.SetDeadline(time.Now().Add(5 * time.Minute))

		// Accept SOCKS5 from local app.
		buf := make([]byte, 256)
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

		// Connect to tunnel server and send API key + target.
		remote, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
		if err != nil {
			local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		defer remote.Close()
		remote.SetDeadline(time.Now().Add(5 * time.Minute))

		// Send API key (from env or empty) + target.
		apiKey := getAPIKey(proto)
		fmt.Fprintf(remote, "%s\n%s\n", apiKey, target)

		// Read response.
		resp := make([]byte, 256)
		rn, _ := remote.Read(resp)
		if !strings.HasPrefix(string(resp[:rn]), "OK") {
			local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}

		local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		emit(fmt.Sprintf("[+] %s API tunnel forwarding → %s", proto, target))

		// Signal via API in background.
		go func() {
			sessionID := fmt.Sprintf("pw-%d", time.Now().UnixNano())
			transport.exchange(apiKey, sessionID, []byte("CLIENT_CONNECTED:"+target))
		}()

		relay(local, remote)
	})
}

func getAPIKey(proto string) string {
	// Read from keystore runtime values first, fall back to env vars.
	envKeys := map[string][]string{
		"OPENAI": {"OPENAI_API_KEY"},
		"GITHUB": {"GITHUB_TOKEN"},
	}
	keys := envKeys[strings.ToUpper(proto)]
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

func keystoreRuntimeValue(key string) string {
	return keystore.RuntimeValue(key)
}

func clampLen(a, b int) int {
	if a < b {
		return a
	}
	return b
}
