package api

// ContourAPIServer exposes contour tunnel operations over HTTP for testing and
// verification. Serves localhost only by default.
//
// Endpoints:
//
//	GET  /                 — health + running status
//	GET  /protocols        — all carrier and dead-drop protocol names
//	GET  /status           — active tunnel config, elapsed time, log ring buffer
//	POST /tunnel/start     — start a tunnel (JSON body with role/proto/ports/target)
//	POST /tunnel/stop      — cancel the active tunnel
//	GET  /verify/<proto>   — in-process round-trip test for one protocol
//	GET  /verify/all       — run all verifiable carrier protocols sequentially

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"proxywatch/internal/contour/tunnel"
)

const (
	maxLogLines    = 200
	verifyTimeout  = 12 * time.Second
	serverBindWait = 200 * time.Millisecond
	socksWaitMax   = 4 * time.Second
)

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

type tunnelState struct {
	mu        sync.RWMutex
	running   bool
	role      string
	proto     string
	direction string
	ports     []int
	target    string
	startedAt time.Time
	logs      []string
	cancel    context.CancelFunc
}

// Server is the contour HTTP API server.
type Server struct {
	state  *tunnelState
	server *http.Server
}

// ─────────────────────────────────────────────────────────────────────────────
// Protocol registry
// ─────────────────────────────────────────────────────────────────────────────

// carrierProtocols is the full list of tunnel carrier protocols supported by
// the contour tunnel dispatcher.
var carrierProtocols = []string{
	"socks5", "socks4",
	"http", "https",
	"ws", "wss",
	"ssh",
	"dns", "ntp",
	"smtp", "ftp", "imap", "pop3",
	"redis", "postgres",
	"ldap", "smb",
	"mqtt", "amqp",
	"rdp",
	"quic", "webrtc",
	"openai-api", "domainfront",
}

// deadDropProtocols require external API credentials and cannot be tested
// in-process.
var deadDropProtocols = []string{"openai-deaddrop", "github-deaddrop"}

// verifiableProtocols are carrier protocols that work on TCP loopback without
// external services. Excluded: quic/webrtc (non-TCP transport), openai-api
// (requires auth), domainfront (CDN-dependent in practice).
var verifiableProtocols = []string{
	"socks5", "socks4",
	"http", "https",
	"ws", "wss",
	"ssh",
	"dns", "ntp",
	"smtp", "ftp", "imap", "pop3",
	"redis", "postgres",
	"ldap", "smb",
	"mqtt", "amqp",
	"rdp",
}

func isDeadDrop(proto string) bool {
	for _, dd := range deadDropProtocols {
		if proto == dd {
			return true
		}
	}
	return false
}

// ─────────────────────────────────────────────────────────────────────────────
// Constructor
// ─────────────────────────────────────────────────────────────────────────────

// Start launches the contour HTTP API on addr and returns the server.
func Start(addr string) (*Server, error) {
	s := &Server{state: &tunnelState{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleHealth)
	mux.HandleFunc("/protocols", s.handleProtocols)
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/tunnel/start", s.handleTunnelStart)
	mux.HandleFunc("/tunnel/stop", s.handleTunnelStop)
	mux.HandleFunc("/verify/", s.handleVerify)

	s.server = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 120 * time.Second, // verify/all can take a while
	}
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "[contour-api] server error: %v\n", err)
		}
	}()
	return s, nil
}

// Close stops the API HTTP server.
func (s *Server) Close() error { return s.server.Close() }

// SetActiveTunnel registers an externally-started tunnel with the API so that
// /status returns live data. Call this before the tunnel goroutine starts and
// pass s.AppendLog as the Emit callback.
func (s *Server) SetActiveTunnel(role, proto, direction string, ports []int, target string, cancel context.CancelFunc) {
	s.state.mu.Lock()
	s.state.running = true
	s.state.role = role
	s.state.proto = proto
	s.state.direction = direction
	s.state.ports = ports
	s.state.target = target
	s.state.startedAt = time.Now()
	s.state.logs = nil
	s.state.cancel = cancel
	s.state.mu.Unlock()
}

// MarkStopped clears the running flag when the external tunnel goroutine exits.
func (s *Server) MarkStopped() {
	s.state.mu.Lock()
	s.state.running = false
	s.state.mu.Unlock()
}

// AppendLog adds a log line to the tunnel state ring buffer (thread-safe).
func (s *Server) AppendLog(line string) {
	s.state.mu.Lock()
	s.state.logs = append(s.state.logs, line)
	if len(s.state.logs) > maxLogLines {
		s.state.logs = s.state.logs[len(s.state.logs)-maxLogLines:]
	}
	s.state.mu.Unlock()
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP handlers
// ─────────────────────────────────────────────────────────────────────────────

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.state.mu.RLock()
	resp := map[string]interface{}{
		"ok":      true,
		"service": "contour-api",
		"running": s.state.running,
		"proto":   s.state.proto,
		"updated": time.Now().UTC().Format(time.RFC3339),
	}
	s.state.mu.RUnlock()
	writeJSON(w, resp)
}

func (s *Server) handleProtocols(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"carrier":     carrierProtocols,
		"deaddrop":    deadDropProtocols,
		"verifiable":  verifiableProtocols,
		"total":       len(carrierProtocols) + len(deadDropProtocols),
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.state.mu.RLock()
	defer s.state.mu.RUnlock()
	elapsed := 0.0
	started := ""
	if !s.state.startedAt.IsZero() {
		started = s.state.startedAt.UTC().Format(time.RFC3339)
		if s.state.running {
			elapsed = time.Since(s.state.startedAt).Seconds()
		}
	}
	logs := append([]string(nil), s.state.logs...)
	writeJSON(w, map[string]interface{}{
		"running":   s.state.running,
		"role":      s.state.role,
		"proto":     s.state.proto,
		"direction": s.state.direction,
		"ports":     s.state.ports,
		"target":    s.state.target,
		"started":   started,
		"elapsed_s": int(elapsed),
		"log_count": len(logs),
		"logs":      logs,
	})
}

type startRequest struct {
	Role      string `json:"role"`
	Proto     string `json:"proto"`
	Direction string `json:"direction"`
	Ports     []int  `json:"ports"`
	Target    string `json:"target"`
}

func (s *Server) handleTunnelStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req startRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Role == "" {
		req.Role = "Server"
	}
	if req.Proto == "" {
		req.Proto = "http"
	}
	if req.Direction == "" {
		req.Direction = "Forward"
	}
	if len(req.Ports) == 0 {
		req.Ports = []int{8080}
	}

	s.state.mu.Lock()
	if s.state.running && s.state.cancel != nil {
		s.state.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.state.running = true
	s.state.role = req.Role
	s.state.proto = req.Proto
	s.state.direction = req.Direction
	s.state.ports = req.Ports
	s.state.target = req.Target
	s.state.startedAt = time.Now()
	s.state.logs = nil
	s.state.cancel = cancel
	s.state.mu.Unlock()

	go func() {
		result := tunnel.RunTunnel(ctx, tunnel.TunnelInput{
			Role:      req.Role,
			Method:    req.Proto,
			Ports:     req.Ports,
			Target:    req.Target,
			Direction: req.Direction,
			Emit:      s.AppendLog,
		})
		s.state.mu.Lock()
		s.state.running = false
		if result.Error != nil {
			s.state.logs = append(s.state.logs, "[-] error: "+result.Error.Error())
		}
		s.state.mu.Unlock()
	}()

	writeJSON(w, map[string]interface{}{
		"ok":        true,
		"role":      req.Role,
		"proto":     req.Proto,
		"direction": req.Direction,
		"ports":     req.Ports,
		"target":    req.Target,
	})
}

func (s *Server) handleTunnelStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	s.state.mu.Lock()
	wasRunning := s.state.running
	if wasRunning && s.state.cancel != nil {
		s.state.cancel()
		s.state.running = false
	}
	s.state.mu.Unlock()
	writeJSON(w, map[string]interface{}{"ok": true, "was_running": wasRunning})
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	proto := strings.TrimPrefix(r.URL.Path, "/verify/")
	proto = strings.ToLower(strings.TrimSpace(proto))

	if proto == "all" {
		s.handleVerifyAll(w, r)
		return
	}
	if proto == "" {
		http.Error(w, "specify /verify/<proto> or /verify/all", http.StatusBadRequest)
		return
	}

	if isDeadDrop(proto) {
		writeJSON(w, VerifyResult{
			Proto:      proto,
			Skipped:    true,
			SkipReason: "dead drop requires external API credentials",
		})
		return
	}

	result := verifyProto(proto)
	writeJSON(w, result)
}

func (s *Server) handleVerifyAll(w http.ResponseWriter, r *http.Request) {
	results := make([]VerifyResult, 0, len(verifiableProtocols))
	passed := 0
	for _, proto := range verifiableProtocols {
		res := verifyProto(proto)
		results = append(results, res)
		if res.OK {
			passed++
		}
	}
	writeJSON(w, map[string]interface{}{
		"total":   len(results),
		"passed":  passed,
		"failed":  len(results) - passed,
		"results": results,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Verification harness
// ─────────────────────────────────────────────────────────────────────────────

// VerifyResult is the JSON-serialisable result of one protocol verification.
type VerifyResult struct {
	Proto       string   `json:"proto"`
	OK          bool     `json:"ok"`
	Skipped     bool     `json:"skipped,omitempty"`
	SkipReason  string   `json:"reason,omitempty"`
	SocksOK     bool     `json:"socks_ok"`
	RoundtripOK bool     `json:"roundtrip_ok"`
	ElapsedMS   int64    `json:"elapsed_ms"`
	SocksAddr   string   `json:"socks_addr,omitempty"`
	Error       string   `json:"error,omitempty"`
	Logs        []string `json:"logs"`
}

// verifyProto spins up an ephemeral server+client pair for proto, verifies
// the SOCKS5 forwarder appears, then does a full echo round-trip through it.
func verifyProto(proto string) VerifyResult {
	start := time.Now()
	res := VerifyResult{Proto: proto}

	ctx, cancel := context.WithTimeout(context.Background(), verifyTimeout)
	defer cancel()

	// 1. Local echo server.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		res.Error = "echo listen: " + err.Error()
		res.ElapsedMS = time.Since(start).Milliseconds()
		return res
	}
	defer echoLn.Close()
	go serveEcho(echoLn)
	echoAddr := echoLn.Addr().String()

	// 2. Free port for the protocol tunnel.
	tunnelPort, err := findFreePort()
	if err != nil {
		res.Error = "no free port: " + err.Error()
		res.ElapsedMS = time.Since(start).Milliseconds()
		return res
	}

	// Shared log collector.
	var logMu sync.Mutex
	var logs []string
	addLog := func(line string) {
		logMu.Lock()
		logs = append(logs, line)
		logMu.Unlock()
	}

	// 3. Start server (exit node).
	serverCtx, cancelServer := context.WithCancel(ctx)
	defer cancelServer()
	go tunnel.RunTunnel(serverCtx, tunnel.TunnelInput{
		Role:      "Server",
		Method:    proto,
		Ports:     []int{tunnelPort},
		Direction: "Forward",
		Emit:      func(s string) { addLog("[server] " + s) },
	})

	// 4. Give server time to bind.
	time.Sleep(serverBindWait)

	// 5. Start client (SOCKS forwarder), capture SOCKS addr from emit.
	socksAddrCh := make(chan string, 1)
	var socksOnce sync.Once

	clientCtx, cancelClient := context.WithCancel(ctx)
	defer cancelClient()
	go tunnel.RunTunnel(clientCtx, tunnel.TunnelInput{
		Role:      "Client",
		Method:    proto,
		Ports:     []int{tunnelPort},
		Target:    "127.0.0.1",
		Direction: "Forward",
		Emit: func(s string) {
			addLog("[client] " + s)
			// startLocalForwarder always emits:
			// "[+] Local SOCKS5 forwarder on 127.0.0.1:<PORT>"
			if idx := strings.Index(s, "Local SOCKS5 forwarder on "); idx >= 0 {
				addr := strings.TrimSpace(s[idx+len("Local SOCKS5 forwarder on "):])
				socksOnce.Do(func() { socksAddrCh <- addr })
			}
		},
	})

	// 6. Wait for SOCKS addr or timeout.
	select {
	case socksAddr := <-socksAddrCh:
		res.SocksOK = true
		res.SocksAddr = socksAddr
		// 7. SOCKS5 echo round-trip.
		rtErr := socks5RoundTrip(socksAddr, echoAddr)
		if rtErr == nil {
			res.RoundtripOK = true
			res.OK = true
		} else {
			res.Error = "roundtrip: " + rtErr.Error()
		}
	case <-time.After(socksWaitMax):
		res.Error = fmt.Sprintf("socks forwarder did not appear within %s", socksWaitMax)
	case <-ctx.Done():
		res.Error = "timeout waiting for socks forwarder"
	}

	// Tear down tunnel pair.
	cancelServer()
	cancelClient()

	logMu.Lock()
	res.Logs = logs
	logMu.Unlock()
	res.ElapsedMS = time.Since(start).Milliseconds()
	return res
}

// socks5RoundTrip connects to the SOCKS5 forwarder at socksAddr, issues a
// CONNECT to destAddr, sends a test payload, and verifies the echo.
func socks5RoundTrip(socksAddr, destAddr string) error {
	conn, err := net.DialTimeout("tcp", socksAddr, 3*time.Second)
	if err != nil {
		return fmt.Errorf("dial socks5: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(8 * time.Second))

	// SOCKS5 greeting: version 5, 1 method, no-auth.
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fmt.Errorf("greeting write: %w", err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("greeting read: %w", err)
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		return fmt.Errorf("unexpected greeting response: %02x %02x", buf[0], buf[1])
	}

	// Build CONNECT request for destAddr.
	host, portStr, err := net.SplitHostPort(destAddr)
	if err != nil {
		return fmt.Errorf("parse dest: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("parse port: %w", err)
	}

	var req []byte
	if ip := net.ParseIP(host).To4(); ip != nil {
		// IPv4 CONNECT
		req = []byte{0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], byte(port >> 8), byte(port & 0xff)}
	} else {
		// Domain name CONNECT
		req = append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}, []byte(host)...)
		req = append(req, byte(port>>8), byte(port&0xff))
	}
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("connect write: %w", err)
	}

	// Read CONNECT response — always 10 bytes (server emits IPv4 0.0.0.0).
	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("connect response: %w", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		return fmt.Errorf("connect rejected: REP=0x%02x", resp[1])
	}

	// Echo round-trip.
	const payload = "proxywatch-contour-verify"
	if _, err := conn.Write([]byte(payload)); err != nil {
		return fmt.Errorf("payload write: %w", err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, echo); err != nil {
		return fmt.Errorf("echo read: %w", err)
	}
	if string(echo) != payload {
		return fmt.Errorf("echo mismatch: got %q", echo)
	}
	return nil
}

// serveEcho runs a simple TCP echo server until the listener is closed.
func serveEcho(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			c.SetDeadline(time.Now().Add(15 * time.Second))
			io.Copy(c, c)
		}(c)
	}
}

// findFreePort returns a free TCP port on loopback by briefly binding and
// releasing it. There is a small TOCTOU window, but it is acceptable here.
func findFreePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port, nil
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
