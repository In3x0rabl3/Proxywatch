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

func TestOpenAIDeadDropWriteRead(t *testing.T) {
	token := os.Getenv("OPENAI_API_KEY")
	if token == "" {
		t.Skip("No OPENAI_API_KEY")
	}

	dd := &openaiDeadDrop{creator: true}
	channel := "test-" + time.Now().UTC().Format("20060102-150405")
	t.Logf("Channel: %s, filename: %s", channel, dd.filename(channel, "c2s/1"))

	// Write
	testData := []byte("openai-deaddrop-test-payload")
	t.Log("Writing...")
	if err := dd.write(token, channel, "c2s/1", testData); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	t.Log("Write OK")

	time.Sleep(2 * time.Second)

	// Read
	t.Log("Reading...")
	data, err := dd.read(token, channel, "c2s/1")
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if data == nil {
		t.Fatal("read returned nil")
	}
	t.Logf("Read OK: %q", string(data))
	if string(data) != string(testData) {
		t.Fatalf("mismatch: got %q want %q", data, testData)
	}
	t.Log("Write/Read roundtrip verified!")

	// Delete
	if err := dd.delete(token, channel, "c2s/1"); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	t.Log("Delete OK — OpenAI dead drop verified!")
}

func TestOpenAIDeadDropFullSOCKS(t *testing.T) {
	token := os.Getenv("OPENAI_API_KEY")
	if token == "" {
		t.Skip("No OPENAI_API_KEY")
	}
	os.Setenv("OPENAI_API_KEY", token)

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
		serveDeadDropTunnelWithAuth(ctx, &openaiDeadDrop{creator: true}, token, func(s string) {
			t.Logf("[S] %s", s)
		})
	}()

	// Wait for server to upload READY signal.
	t.Log("Waiting for server to create dead drop channel...")
	time.Sleep(5 * time.Second)

	// Client — capture SOCKS port.
	var socksAddr string
	var socksMu sync.Mutex
	wg.Add(1)
	go func() {
		defer wg.Done()
		connectDeadDropClientWithAuth(ctx, &openaiDeadDrop{creator: false}, token, func(s string) {
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
	testData := []byte("OPENAI-DEAD-DROP-E2E-TEST-12345")
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
	t.Logf("SUCCESS: OpenAI dead drop E2E verified! Echo: %q", string(result))

	cancel()
	wg.Wait()
}

// TestOpenAIDeadDropReverse tests reverse mode: the roles are swapped so the
// "Client" side creates the channel and dials destinations (exit node),
// while the "Server" side runs the SOCKS forwarder.
func TestOpenAIDeadDropReverse(t *testing.T) {
	token := os.Getenv("OPENAI_API_KEY")
	if token == "" {
		t.Skip("No OPENAI_API_KEY")
	}
	os.Setenv("OPENAI_API_KEY", token)

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

	// Reverse: "Client" creates channel and acts as exit node (Server relay role).
	// "Server" connects and runs SOCKS forwarder (Client relay role).
	var wg sync.WaitGroup

	// Start the exit node (creator=true, runs serveDeadDropTunnel which dials destinations).
	wg.Add(1)
	go func() {
		defer wg.Done()
		t.Log("[Exit] Starting exit node (creator=true)...")
		serveDeadDropTunnelWithAuth(ctx, &openaiDeadDrop{creator: true}, token, func(s string) {
			t.Logf("[Exit] %s", s)
		})
	}()

	t.Log("Waiting for exit node to create dead drop channel...")
	time.Sleep(5 * time.Second)

	// Start the SOCKS forwarder (creator=false, runs connectDeadDropClient).
	var socksAddr string
	var socksMu sync.Mutex
	wg.Add(1)
	go func() {
		defer wg.Done()
		t.Log("[SOCKS] Starting SOCKS forwarder (creator=false)...")
		connectDeadDropClientWithAuth(ctx, &openaiDeadDrop{creator: false}, token, func(s string) {
			t.Logf("[SOCKS] %s", s)
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
	t.Log("SOCKS5 CONNECT succeeded (reverse mode)")

	// Send test data.
	testData := []byte("OPENAI-REVERSE-DEAD-DROP-E2E")
	t.Logf("Sending %d bytes through reverse dead drop relay...", len(testData))
	conn.Write(testData)

	// Read echo.
	result := make([]byte, len(testData))
	conn.SetDeadline(time.Now().Add(45 * time.Second))
	n, err := io.ReadFull(conn, result)
	if err != nil {
		t.Fatalf("Echo read: got %d bytes, err=%v, data=%q", n, err, result[:n])
	}
	if string(result) != string(testData) {
		t.Fatalf("Echo mismatch: got %q, want %q", result, testData)
	}
	t.Logf("SUCCESS: OpenAI REVERSE dead drop E2E verified! Echo: %q", string(result))

	cancel()
	wg.Wait()
}
