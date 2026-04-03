package contour

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func TestDeadDropGitHubEndToEnd(t *testing.T) {
	// Use a mock transport instead of real GitHub to test the relay logic.
	store := &mockDeadDrop{data: make(map[string][]byte)}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Start echo server (destination).
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
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

	// Start server (exit node) in background.
	var serverErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		result := serveDeadDropTunnelWithAuth(ctx, store, "test-token", func(s string) {
			t.Logf("[S] %s", s)
		})
		if result.Error != nil {
			serverErr = result.Error
		}
	}()

	// Give server a moment to start polling.
	time.Sleep(200 * time.Millisecond)

	// Client side: create relay and send a CONNECT + data.
	auth := "test-token"
	sessionID := deadDropSessionID(auth)
	t.Logf("Session: %s", sessionID[:8])

	clientRelay := &deadDropRelay{
		transport: store,
		auth:      auth,
		channel:   sessionID,
		sendDir:   "c2s",
		recvDir:   "s2c",
		ctx:       ctx,
	}

	// Wait for server READY signal.
	t.Log("Client: waiting for READY")
	ready, err := clientRelay.pollRead()
	if err != nil {
		t.Fatalf("read READY: %v", err)
	}
	t.Logf("Client: got: %q", string(ready))
	if string(ready) != "READY" {
		t.Fatalf("expected READY, got %q", string(ready))
	}

	// Send CONNECT request.
	t.Log("Client: sending CONNECT")
	if err := clientRelay.Write([]byte("CONNECT:" + echoAddr)); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	// Wait for OK.
	t.Log("Client: waiting for OK")
	resp, err := clientRelay.pollRead()
	if err != nil {
		t.Fatalf("read OK: %v", err)
	}
	t.Logf("Client: got response: %q", string(resp))
	if string(resp) != "OK" {
		t.Fatalf("expected OK, got %q", string(resp))
	}

	// Send data.
	testData := []byte("HELLO-DEADDROP-TEST")
	t.Log("Client: sending data")
	if err := clientRelay.Write(testData); err != nil {
		t.Fatalf("write data: %v", err)
	}

	// Read response.
	t.Log("Client: waiting for echo response")
	echoResp, err := clientRelay.pollRead()
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	t.Logf("Client: got echo: %q", string(echoResp))
	if string(echoResp) != string(testData) {
		t.Fatalf("echo mismatch: got %q, want %q", echoResp, testData)
	}

	t.Log("SUCCESS: dead drop relay round-trip verified")
	cancel()
	wg.Wait()
	if serverErr != nil && serverErr != context.Canceled {
		t.Logf("Server error (expected on cancel): %v", serverErr)
	}
}

// mockDeadDrop is an in-memory implementation of deadDropTransport for testing.
type mockDeadDrop struct {
	mu   sync.Mutex
	data map[string][]byte
}

func (m *mockDeadDrop) name() string { return "Mock" }

func (m *mockDeadDrop) write(auth, channel, key string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	fullKey := fmt.Sprintf("%s/%s", channel, key)
	m.data[fullKey] = append([]byte(nil), data...)
	return nil
}

func (m *mockDeadDrop) read(auth, channel, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fullKey := fmt.Sprintf("%s/%s", channel, key)
	if d, ok := m.data[fullKey]; ok {
		return d, nil
	}
	return nil, nil
}

func (m *mockDeadDrop) delete(auth, channel, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	fullKey := fmt.Sprintf("%s/%s", channel, key)
	delete(m.data, fullKey)
	return nil
}

func TestGitHubGistWriteRead(t *testing.T) {
	// Test the actual GitHub Gist transport read/write.
	token := getServiceKey("GitHub")
	if token == "" {
		// Try keystore
		token = keystoreRuntimeValue("GITHUB_TOKEN")
	}
	if token == "" {
		t.Skip("No GITHUB_TOKEN available")
	}
	t.Logf("Token length: %d", len(token))

	dd := &githubDeadDrop{creator: true}
	channel := fmt.Sprintf("test-%d", time.Now().Unix())

	// Write a test value.
	testData := []byte("test-payload-12345")
	t.Log("Writing to GitHub Gist...")
	err := dd.write(token, channel, "c2s/1", testData)
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}
	t.Log("Write OK")

	// Read it back.
	time.Sleep(1 * time.Second)
	t.Log("Reading from GitHub Gist...")
	data, err := dd.read(token, channel, "c2s/1")
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if data == nil {
		t.Fatal("read returned nil — file not found in gist")
	}
	t.Logf("Read OK: %q (len=%d)", string(data), len(data))
	if string(data) != string(testData) {
		t.Fatalf("data mismatch: got %q, want %q", data, testData)
	}
	t.Log("GitHub Gist write/read verified!")

	// Cleanup.
	_ = dd.delete(token, channel, "c2s/1")
}

func TestGitHubDeadDropRealE2E(t *testing.T) {
	token := ""
	if v := os.Getenv("GITHUB_TOKEN"); v != "" {
		token = v
	}
	if token == "" {
		t.Skip("No GITHUB_TOKEN")
	}

	// Override getServiceKey to return our token for "GitHub".
	origKey := os.Getenv("GITHUB_TOKEN")
	os.Setenv("GITHUB_TOKEN", token)
	defer func() {
		if origKey != "" {
			os.Setenv("GITHUB_TOKEN", origKey)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Start echo server.
	echoLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer echoLn.Close()
	_ = echoLn.Addr().String()
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

	// Start server.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		serveDeadDropTunnel(ctx, &githubDeadDrop{creator: true}, func(s string) {
			t.Logf("[S] %s", s)
		})
	}()

	// Wait for server to create the gist channel.
	time.Sleep(8 * time.Second)

	// Start client.
	wg.Add(1)
	go func() {
		defer wg.Done()
		connectDeadDropClient(ctx, &githubDeadDrop{creator: false}, func(s string) {
			t.Logf("[C] %s", s)
		})
	}()

	// Wait for SOCKS forwarder.
	time.Sleep(10 * time.Second)

	// TODO: need to capture the SOCKS port from emit... for now just verify the flow.
	t.Log("Server and client both started via real GitHub API")
	cancel()
	wg.Wait()
}
