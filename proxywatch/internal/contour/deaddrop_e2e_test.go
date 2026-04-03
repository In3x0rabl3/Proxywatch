package contour

import (
	"context"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGitHubDeadDropFullSOCKS(t *testing.T) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		t.Skip("No GITHUB_TOKEN")
	}
	os.Setenv("GITHUB_TOKEN", token)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Echo server.
	echoLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer echoLn.Close()
	echoAddr := echoLn.Addr().String()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				n, _ := c.Read(buf)
				if n > 0 {
					c.Write(buf[:n])
				}
			}(c)
		}
	}()

	// Server.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		serveDeadDropTunnelWithAuth(ctx, &githubDeadDrop{creator: true}, token, func(s string) {
			t.Logf("[S] %s", s)
		})
	}()

	// Wait for server to create the gist.
	t.Log("Waiting for server to create gist...")
	time.Sleep(8 * time.Second)

	// Client — capture SOCKS port.
	var socksAddr string
	var socksMu sync.Mutex
	wg.Add(1)
	go func() {
		defer wg.Done()
		connectDeadDropClientWithAuth(ctx, &githubDeadDrop{creator: false}, token, func(s string) {
			t.Logf("[C] %s", s)
			if strings.Contains(s, "Local SOCKS5 forwarder on ") {
				socksMu.Lock()
				parts := strings.Split(s, "Local SOCKS5 forwarder on ")
				if len(parts) > 1 {
					socksAddr = strings.TrimSpace(parts[1])
				}
				socksMu.Unlock()
			}
		})
	}()

	// Wait for SOCKS forwarder.
	t.Log("Waiting for client SOCKS forwarder...")
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		socksMu.Lock()
		addr := socksAddr
		socksMu.Unlock()
		if addr != "" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	socksMu.Lock()
	addr := socksAddr
	socksMu.Unlock()
	if addr == "" {
		t.Fatal("SOCKS forwarder never started")
	}
	t.Logf("SOCKS forwarder at %s", addr)

	// Connect through SOCKS to echo server.
	t.Log("Connecting through SOCKS5 to echo server...")
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("SOCKS connect: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(60 * time.Second))

	// SOCKS5 handshake.
	conn.Write([]byte{0x05, 0x01, 0x00})
	buf := make([]byte, 2)
	io.ReadFull(conn, buf)
	if buf[0] != 0x05 {
		t.Fatalf("SOCKS greeting failed: %v", buf)
	}

	// CONNECT to echo server.
	host, portStr, _ := net.SplitHostPort(echoAddr)
	ip := net.ParseIP(host).To4()
	var portNum int
	for _, c := range portStr {
		portNum = portNum*10 + int(c-'0')
	}
	req := []byte{0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], byte(portNum >> 8), byte(portNum)}
	conn.Write(req)
	resp := make([]byte, 10)
	io.ReadFull(conn, resp)
	if resp[1] != 0x00 {
		t.Fatalf("SOCKS CONNECT failed: resp[1]=%d", resp[1])
	}
	t.Log("SOCKS5 CONNECT succeeded")

	// Send test data.
	testData := []byte("DEAD-DROP-E2E-TEST-12345")
	t.Logf("Sending %d bytes through dead drop relay...", len(testData))
	conn.Write(testData)

	// Read echo.
	t.Log("Waiting for echo response...")
	result := make([]byte, len(testData))
	conn.SetDeadline(time.Now().Add(45 * time.Second))
	n, err := io.ReadFull(conn, result)
	if err != nil {
		t.Fatalf("Echo read: got %d bytes, err=%v, data=%q", n, err, result[:n])
	}
	if string(result) != string(testData) {
		t.Fatalf("Echo mismatch: got %q, want %q", result, testData)
	}
	t.Logf("SUCCESS: Dead drop E2E verified! Echo: %q", string(result))

	cancel()
	wg.Wait()
}
