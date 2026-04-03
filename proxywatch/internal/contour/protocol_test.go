package contour

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestAllTunnelProtocols exercises every tunnel protocol on localhost (forward mode).
func TestAllTunnelProtocols(t *testing.T) {
	tunnelProtos := []string{
		"socks5", "socks4", "http", "https", "ws", "wss",
		"dns", "ntp", "smtp",
		"ftp", "imap", "pop3", "redis", "postgres",
		"ldap", "smb", "mqtt", "amqp",
		"ssh", "rdp", "quic", "webrtc",
		"openai-api", "github-api", "buildkite-api",
		"aws-api", "azure-api", "gcp-api",
	}

	basePort := 37200
	for i, proto := range tunnelProtos {
		proto := proto
		port := basePort + i
		t.Run("forward/"+proto, func(t *testing.T) {
			testTunnelProto(t, proto, port, "Forward")
		})
	}
}

// TestAllTunnelProtocolsReverse exercises every tunnel protocol in reverse mode.
func TestAllTunnelProtocolsReverse(t *testing.T) {
	tunnelProtos := []string{
		"socks5", "socks4", "http", "https", "ws", "wss",
		"dns", "ntp", "smtp",
		"ftp", "imap", "pop3", "redis", "postgres",
		"ldap", "smb", "mqtt", "amqp",
		"ssh", "rdp", "quic", "webrtc",
		"openai-api", "github-api", "buildkite-api",
		"aws-api", "azure-api", "gcp-api",
	}

	basePort := 38200
	for i, proto := range tunnelProtos {
		proto := proto
		port := basePort + i
		t.Run("reverse/"+proto, func(t *testing.T) {
			testTunnelProto(t, proto, port, "Reverse")
		})
	}
}

func testTunnelProto(t *testing.T, proto string, port int, direction string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverEmit := func(s string) { t.Logf("  [S] %s", s) }
	clientEmit := func(s string) { t.Logf("  [C] %s", s) }

	// Start echo server for tunnel to connect to.
	echoPort := port + 500
	echoLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", echoPort))
	if err != nil {
		t.Fatalf("echo server: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c)
		}
	}()

	// Start tunnel server.
	serverCtx, serverCancel := context.WithCancel(ctx)
	defer serverCancel()

	var localProxy string
	var proxyMu sync.Mutex

	// Forward (default): SOCKS binds on CLIENT side (chisel model).
	// Reverse=true: SOCKS binds on SERVER side.
	socksEmitSide := "Client"
	if direction == "Reverse" {
		socksEmitSide = "Server"
	}

	captureSOCKS := func(side, s string) {
		if side == socksEmitSide && strings.Contains(s, "Local SOCKS5 forwarder on ") {
			proxyMu.Lock()
			parts := strings.Split(s, "Local SOCKS5 forwarder on ")
			if len(parts) > 1 {
				localProxy = strings.TrimSpace(parts[1])
			}
			proxyMu.Unlock()
		}
	}

	serverWrappedEmit := func(s string) {
		serverEmit(s)
		captureSOCKS("Server", s)
	}
	clientWrappedEmit := func(s string) {
		clientEmit(s)
		captureSOCKS("Client", s)
	}

	go func() {
		RunTunnel(serverCtx, TunnelInput{
			Role: "Server", Method: proto, Ports: []int{port},
			Direction: direction, Emit: serverWrappedEmit,
		})
	}()
	if direction == "Forward" {
		// Forward: server handles multiple connections, safe to probe.
		waitForPort(t, port, 5*time.Second)
	} else {
		// Reverse: server accepts ONE tunnel connection as the tunnel.
		// Don't probe — it would consume the slot.
		time.Sleep(300 * time.Millisecond)
	}

	// Start tunnel client.
	clientCtx, clientCancel := context.WithCancel(ctx)
	defer clientCancel()

	go func() {
		RunTunnel(clientCtx, TunnelInput{
			Role: "Client", Method: proto, Ports: []int{port},
			Target: "127.0.0.1", Direction: direction, Emit: clientWrappedEmit,
		})
	}()

	// Wait for local forwarder.
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		proxyMu.Lock()
		addr := localProxy
		proxyMu.Unlock()
		if addr != "" {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	proxyMu.Lock()
	proxyAddr := localProxy
	proxyMu.Unlock()

	if proxyAddr == "" {
		t.Fatalf("FAIL %s: local SOCKS forwarder never started", proto)
	}

	// Send data through SOCKS5 tunnel to echo server.
	testData := []byte("PROXYWATCH-TUNNEL-TEST-" + strings.ToUpper(proto))
	echoed := sendThroughSOCKS5(t, proxyAddr, fmt.Sprintf("127.0.0.1:%d", echoPort), testData)

	clientCancel()
	serverCancel()

	if echoed == nil {
		t.Fatalf("FAIL %s: no echo response", proto)
	}
	if string(echoed) != string(testData) {
		t.Fatalf("FAIL %s: echo mismatch sent=%q got=%q", proto, testData, echoed)
	}
	t.Logf("  ✓ %s: tunnel echo verified (%d bytes)", proto, len(testData))
}

func waitForPort(t *testing.T, port int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("  ⚠ port %d not ready after %s", port, timeout)
}

func sendThroughSOCKS5(t *testing.T, proxyAddr, target string, data []byte) []byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Logf("  ⚠ SOCKS5 connect failed: %v", err)
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	conn.Write([]byte{0x05, 0x01, 0x00})
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil || buf[0] != 0x05 {
		t.Logf("  ⚠ SOCKS5 greeting failed: %v", err)
		return nil
	}

	host, portStr, _ := net.SplitHostPort(target)
	var portNum int
	fmt.Sscanf(portStr, "%d", &portNum)
	ip := net.ParseIP(host).To4()
	if ip == nil {
		t.Log("  ⚠ IPv4 only")
		return nil
	}
	req := []byte{0x05, 0x01, 0x00, 0x01,
		ip[0], ip[1], ip[2], ip[3],
		byte(portNum >> 8), byte(portNum)}
	conn.Write(req)

	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil || resp[1] != 0x00 {
		t.Logf("  ⚠ SOCKS5 CONNECT failed: err=%v resp=%v", err, resp)
		return nil
	}

	conn.Write(data)
	result := make([]byte, len(data))
	n, err := io.ReadFull(conn, result)
	if err != nil {
		t.Logf("  ⚠ echo read: %v (got %d bytes)", err, n)
		return result[:n]
	}
	return result
}
