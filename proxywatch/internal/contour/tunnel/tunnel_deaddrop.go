package tunnel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// deadDropHTTPClient is a shared HTTP client for all dead drop transports.
// Using http.DefaultClient (which has no timeout) risks goroutine leaks when
// remote services stall. This client enforces reasonable timeouts and reuses
// connections across requests.
var deadDropHTTPClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        20,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     30 * time.Second,
	},
}

// ═══════════════════════════════════════════════════════════════════════════
// Dead drop relay — true API-only relay system
//
// Architecture: Client and Server NEVER connect directly. All data flows
// through a third-party service API used as a dead drop.
//
//	Client App → SOCKS5 → Client → writes data to service API
//	                                    ↓ (polling 100-500ms)
//	Server reads from service API → dials destination → writes response
//	                                    ↓ (polling 100-500ms)
//	Client reads response from service API → SOCKS5 → Client App
//
// Both sides authenticate to the service independently with the same
// credentials. Session identity is derived deterministically from the
// auth token so no handshake is needed.
// ═══════════════════════════════════════════════════════════════════════════

// deadDropTransport is the interface for a service that can act as a dead drop.
// Both sides read and write through the service — never directly to each other.
type deadDropTransport interface {
	name() string
	// write stores a chunk of data under a key. Returns error if fails.
	write(auth, channel, key string, data []byte) error
	// read retrieves data for a key. Returns nil,nil if no data yet.
	read(auth, channel, key string) ([]byte, error)
	// delete removes a key after reading (cleanup).
	delete(auth, channel, key string) error
}

// deadDropSessionID derives a deterministic session ID so both sides
// compute the same channel without communicating. Based on auth token +
// hour (rotates hourly to avoid stale data from previous sessions).
func deadDropSessionID(auth string) string {
	h := sha256.Sum256([]byte("proxywatch-deaddrop:" + auth + ":" + time.Now().UTC().Format("2006-01-02-15")))
	return hex.EncodeToString(h[:16])
}

// deadDropRelay manages bidirectional data streaming over a polling API
// using numbered chunks.
type deadDropRelay struct {
	transport deadDropTransport
	auth      string
	channel   string // session ID
	sendDir   string // "c2s" or "s2c"
	recvDir   string // "s2c" or "c2s"
	sendSeq   int64
	recvSeq   int64
	ctx       context.Context
}

// Write encrypts and stores a data chunk in the dead drop.
// Retries once after a short delay on transient network errors.
func (r *deadDropRelay) Write(data []byte) error {
	seq := atomic.AddInt64(&r.sendSeq, 1)
	key := fmt.Sprintf("%s/%d", r.sendDir, seq)
	encrypted := tunnelObfuscate(data, tunnelSessionKey(r.channel))
	encoded := base64.StdEncoding.EncodeToString(encrypted)
	err := r.transport.write(r.auth, r.channel, key, []byte(encoded))
	if err != nil {
		// Retry once after a short delay for transient network glitches.
		select {
		case <-r.ctx.Done():
			return r.ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
		err = r.transport.write(r.auth, r.channel, key, []byte(encoded))
	}
	return err
}

// Read polls for the next data chunk from the dead drop. Returns nil,nil
// if no data is available yet (caller should poll again).
// Retries once on error before propagating the failure.
func (r *deadDropRelay) Read() ([]byte, error) {
	nextSeq := atomic.LoadInt64(&r.recvSeq) + 1
	key := fmt.Sprintf("%s/%d", r.recvDir, nextSeq)
	data, err := r.transport.read(r.auth, r.channel, key)
	if err != nil {
		// Retry once after a short delay for transient network glitches.
		select {
		case <-r.ctx.Done():
			return nil, r.ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
		data, err = r.transport.read(r.auth, r.channel, key)
		if err != nil {
			return nil, err
		}
	}
	if data == nil {
		return nil, nil // no data yet
	}
	atomic.AddInt64(&r.recvSeq, 1)
	// Cleanup after reading.
	go func() { _ = r.transport.delete(r.auth, r.channel, key) }()
	// Decode base64 then decrypt.
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("dead drop decode: %w", err)
	}
	return tunnelObfuscate(decoded, tunnelSessionKey(r.channel)), nil
}

// pollRead polls for the next chunk with adaptive backoff (100ms to 500ms).
// Returns the data or an error. Blocks until data arrives or context is done.
func (r *deadDropRelay) pollRead() ([]byte, error) {
	interval := 100 * time.Millisecond
	maxInterval := 500 * time.Millisecond
	for {
		if r.ctx.Err() != nil {
			return nil, r.ctx.Err()
		}
		data, err := r.Read()
		if err != nil {
			return nil, err
		}
		if data != nil {
			return data, nil
		}
		// Back off: increase interval up to max when idle.
		select {
		case <-r.ctx.Done():
			return nil, r.ctx.Err()
		case <-time.After(interval):
		}
		if interval < maxInterval {
			interval = interval * 3 / 2
			if interval > maxInterval {
				interval = maxInterval
			}
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Server side — polls dead drop for client data, dials destinations,
// writes responses back to dead drop
// ═══════════════════════════════════════════════════════════════════════════

func serveDeadDropTunnel(ctx context.Context, transport deadDropTransport, emit func(string)) TunnelResult {
	return serveDeadDropTunnelWithAuth(ctx, transport, "", emit)
}

func serveDeadDropTunnelWithAuth(ctx context.Context, transport deadDropTransport, authOverride string, emit func(string)) TunnelResult {
	auth := authOverride
	if auth == "" {
		auth = getServiceKey(transport.name())
	}
	if auth == "" {
		return TunnelResult{Error: fmt.Errorf("no credentials for %s dead drop", transport.name())}
	}

	sessionID := deadDropSessionID(auth)
	emit(fmt.Sprintf("[+] Dead drop relay via %s (session: %s)", transport.name(), sessionID[:8]))
	emit("[*] Polling for client data...")

	relay := &deadDropRelay{
		transport: transport,
		auth:      auth,
		channel:   sessionID,
		sendDir:   "s2c",
		recvDir:   "c2s",
		ctx:       ctx,
	}

	// Write a ready signal to force gist/channel creation before client connects.
	if err := relay.Write([]byte("READY")); err != nil {
		return TunnelResult{Error: fmt.Errorf("dead drop init: %w", err)}
	}
	emit("[+] Dead drop channel created, waiting for client...")

	// Server loop: read requests from dead drop, dial destinations, relay.
	for {
		if ctx.Err() != nil {
			return TunnelResult{}
		}

		// Wait for a target address from the client (first message of a session).
		data, err := relay.pollRead()
		if err != nil {
			if ctx.Err() != nil {
				return TunnelResult{}
			}
			return TunnelResult{Error: fmt.Errorf("dead drop read: %w", err)}
		}

		// Parse: "CONNECT:<target>" for new connection requests.
		msg := string(data)
		if !strings.HasPrefix(msg, "CONNECT:") {
			// Protocol control messages or keep-alives.
			if msg == "PING" {
				_ = relay.Write([]byte("PONG"))
			}
			continue
		}
		target := strings.TrimPrefix(msg, "CONNECT:")
		emit(fmt.Sprintf("[+] Dead drop: client requests → %s", target))

		// Dial the destination.
		remote, err := net.DialTimeout("tcp", target, 10*time.Second)
		if err != nil {
			emit(fmt.Sprintf("[-] Cannot reach %s: %s", target, err))
			_ = relay.Write([]byte("ERROR:" + err.Error()))
			continue
		}
		_ = relay.Write([]byte("OK"))
		emit(fmt.Sprintf("[+] Dead drop: relaying → %s", target))

		// Bidirectional relay through dead drop.
		deadDropRelayConn(ctx, relay, remote, emit)
		remote.Close()
		emit(fmt.Sprintf("[+] Dead drop: connection to %s closed, waiting for next...", target))
	}
}

// deadDropRelayConn relays data between a dead drop relay and a TCP connection.
func deadDropRelayConn(ctx context.Context, relay *deadDropRelay, conn net.Conn, emit func(string)) {
	var wg sync.WaitGroup
	relayCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// dead drop → conn: poll for data from peer, write to TCP.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		for {
			if relayCtx.Err() != nil {
				return
			}
			data, err := relay.pollRead()
			if err != nil {
				return
			}
			if string(data) == "EOF" {
				return
			}
			if _, err := conn.Write(data); err != nil {
				return
			}
		}
	}()

	// conn → dead drop: read from TCP, write to dead drop.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		buf := make([]byte, 32*1024)
		for {
			if relayCtx.Err() != nil {
				return
			}
			conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			n, err := conn.Read(buf)
			if n > 0 {
				emit(fmt.Sprintf("[*] Dead drop relay: writing %d bytes to %s/%d", n, relay.sendDir, relay.sendSeq+1))
				if werr := relay.Write(buf[:n]); werr != nil {
					emit(fmt.Sprintf("[-] Dead drop relay write error: %v", werr))
					return
				}
			}
			if err != nil {
				_ = relay.Write([]byte("EOF"))
				return
			}
		}
	}()

	wg.Wait()
}

// ═══════════════════════════════════════════════════════════════════════════
// Client side — opens local SOCKS5 forwarder, sends data through dead drop
// ═══════════════════════════════════════════════════════════════════════════

func connectDeadDropClient(ctx context.Context, transport deadDropTransport, emit func(string)) TunnelResult {
	return connectDeadDropClientWithAuth(ctx, transport, "", emit)
}

func connectDeadDropClientWithAuth(ctx context.Context, transport deadDropTransport, authOverride string, emit func(string)) TunnelResult {
	auth := authOverride
	if auth == "" {
		auth = getServiceKey(transport.name())
	}
	if auth == "" {
		return TunnelResult{Error: fmt.Errorf("no credentials for %s dead drop", transport.name())}
	}

	sessionID := deadDropSessionID(auth)
	emit(fmt.Sprintf("[+] Dead drop relay via %s (session: %s)", transport.name(), sessionID[:8]))

	// Start local SOCKS5 forwarder.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return TunnelResult{Error: fmt.Errorf("local SOCKS listener: %w", err)}
	}
	defer ln.Close()
	localAddr := ln.Addr().String()

	emit(fmt.Sprintf("[+] Local SOCKS5 forwarder on %s", localAddr))
	emit(fmt.Sprintf("[+] Dead drop tunnel active — socks5://%s → %s API", localAddr, transport.name()))
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
		go handleDeadDropSOCKS(ctx, local, transport, auth, sessionID, emit)
	}
}

// handleDeadDropSOCKS accepts a SOCKS5 request, sends the target and data
// through the dead drop, and relays responses back.
func handleDeadDropSOCKS(ctx context.Context, local net.Conn, transport deadDropTransport, auth, sessionID string, emit func(string)) {
	defer local.Close()
	local.SetDeadline(time.Now().Add(5 * time.Minute))

	buf := make([]byte, 256)

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

	relay := &deadDropRelay{
		transport: transport,
		auth:      auth,
		channel:   sessionID,
		sendDir:   "c2s",
		recvDir:   "s2c",
		ctx:       ctx,
	}

	// Wait for server READY signal (confirms the dead drop channel exists).
	ready, err := relay.pollRead()
	if err != nil || string(ready) != "READY" {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Send CONNECT request through dead drop.
	if err := relay.Write([]byte("CONNECT:" + target)); err != nil {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Wait for server response.
	resp, err := relay.pollRead()
	if err != nil {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	if !strings.HasPrefix(string(resp), "OK") {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		emit(fmt.Sprintf("[-] Dead drop: server error — %s", string(resp)))
		return
	}

	// SOCKS5 success.
	local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	emit(fmt.Sprintf("[+] Dead drop: forwarding → %s", target))

	// Bidirectional relay through dead drop.
	deadDropRelayConn(ctx, relay, local, emit)
}

// ═══════════════════════════════════════════════════════════════════════════
// Transport 1: GitHub Issues + Comments dead drop (inspired by gitC2 / MythicC2)
//
// write: POST comment to Issue with [key] prefix
// read:  GET comments on Issue, find matching [key]
// delete: Comments are left (private repo, ephemeral)
// Auth: GITHUB_TOKEN (both sides use same token)
//
// Creator side creates repo + issue, non-creator waits for issue to appear.
// ═══════════════════════════════════════════════════════════════════════════

type githubDeadDrop struct {
	mu       sync.Mutex
	issueNum int    // Issue number for this session
	repo     string // "owner/repo" — derived from token's user + a fixed repo name
	creator  bool

	lastPoll time.Time // tracks the last successful poll time for `since` filtering
}

func (t *githubDeadDrop) name() string { return "GitHub" }

// ensureRepo returns the repo path. We use the authenticated user's "proxywatch-relay"
// repo. If it doesn't exist, we create it (private).
func (t *githubDeadDrop) ensureRepo(auth string) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.repo != "" {
		return t.repo, nil
	}
	// Get authenticated user.
	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "Bearer "+auth)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := deadDropHTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var user map[string]any
	json.NewDecoder(resp.Body).Decode(&user)
	login, _ := user["login"].(string)
	if login == "" {
		return "", fmt.Errorf("gitHub: cannot get user login")
	}
	t.repo = login + "/proxywatch-relay"

	// Check if repo exists.
	req2, _ := http.NewRequest("GET", "https://api.github.com/repos/"+t.repo, nil)
	req2.Header.Set("Authorization", "Bearer "+auth)
	resp2, err := deadDropHTTPClient.Do(req2)
	if err == nil {
		resp2.Body.Close()
		if resp2.StatusCode == 200 {
			return t.repo, nil
		}
	}

	// Create private repo.
	body, _ := json.Marshal(map[string]any{
		"name":      "proxywatch-relay",
		"private":   true,
		"auto_init": true,
	})
	req3, _ := http.NewRequest("POST", "https://api.github.com/user/repos", bytes.NewReader(body))
	req3.Header.Set("Authorization", "Bearer "+auth)
	req3.Header.Set("Content-Type", "application/json")
	resp3, err := deadDropHTTPClient.Do(req3)
	if err != nil {
		return "", err
	}
	resp3.Body.Close()
	return t.repo, nil
}

func (t *githubDeadDrop) ensureIssue(auth, channel string) (string, int, error) {
	repo, err := t.ensureRepo(auth)
	if err != nil {
		return "", 0, err
	}
	t.mu.Lock()
	if t.issueNum > 0 {
		num := t.issueNum
		t.mu.Unlock()
		return repo, num, nil
	}
	t.mu.Unlock()

	// Search for existing session issue.
	title := "pw-" + channel[:12]
	searchURL := fmt.Sprintf("https://api.github.com/repos/%s/issues?state=open&per_page=20", repo)

	if t.creator {
		// Creator: close any stale issues with same title prefix before creating fresh.
		req, _ := http.NewRequest("GET", searchURL, nil)
		req.Header.Set("Authorization", "Bearer "+auth)
		req.Header.Set("Accept", "application/vnd.github+json")
		resp, err := deadDropHTTPClient.Do(req)
		if err == nil {
			var issues []map[string]any
			json.NewDecoder(resp.Body).Decode(&issues)
			resp.Body.Close()
			for _, iss := range issues {
				if issTitle, ok := iss["title"].(string); ok && strings.HasPrefix(issTitle, "pw-") {
					if num, ok := iss["number"].(float64); ok {
						closeBody, _ := json.Marshal(map[string]string{"state": "closed"})
						closeReq, _ := http.NewRequest("PATCH",
							fmt.Sprintf("https://api.github.com/repos/%s/issues/%d", repo, int(num)),
							bytes.NewReader(closeBody))
						closeReq.Header.Set("Authorization", "Bearer "+auth)
						closeReq.Header.Set("Content-Type", "application/json")
						closeResp, err := deadDropHTTPClient.Do(closeReq)
						if err == nil {
							closeResp.Body.Close()
						}
					}
				}
			}
		}
	} else {
		// Non-creator: search for the issue the creator made.
		req, _ := http.NewRequest("GET", searchURL, nil)
		req.Header.Set("Authorization", "Bearer "+auth)
		req.Header.Set("Accept", "application/vnd.github+json")
		resp, err := deadDropHTTPClient.Do(req)
		if err == nil {
			var issues []map[string]any
			json.NewDecoder(resp.Body).Decode(&issues)
			resp.Body.Close()
			for _, iss := range issues {
				if issTitle, ok := iss["title"].(string); ok && issTitle == title {
					if num, ok := iss["number"].(float64); ok {
						issNum := int(num)
						t.mu.Lock()
						t.issueNum = issNum
						t.mu.Unlock()
						return repo, issNum, nil
					}
				}
			}
		}
	}

	if !t.creator {
		// Non-creator: wait for the issue to appear.
		for i := 0; i < 30; i++ {
			time.Sleep(time.Second)
			req, _ := http.NewRequest("GET", searchURL, nil)
			req.Header.Set("Authorization", "Bearer "+auth)
			req.Header.Set("Accept", "application/vnd.github+json")
			resp, err := deadDropHTTPClient.Do(req)
			if err != nil {
				continue
			}
			var issues []map[string]any
			json.NewDecoder(resp.Body).Decode(&issues)
			resp.Body.Close()
			for _, iss := range issues {
				if tit, ok := iss["title"].(string); ok && tit == title {
					if num, ok := iss["number"].(float64); ok {
						issNum := int(num)
						t.mu.Lock()
						t.issueNum = issNum
						t.mu.Unlock()
						return repo, issNum, nil
					}
				}
			}
		}
		return "", 0, fmt.Errorf("gitHub: session issue not found")
	}

	// Creator: create the issue.
	body, _ := json.Marshal(map[string]string{"title": title, "body": "proxywatch relay session"})
	req2, _ := http.NewRequest("POST", fmt.Sprintf("https://api.github.com/repos/%s/issues", repo), bytes.NewReader(body))
	req2.Header.Set("Authorization", "Bearer "+auth)
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Accept", "application/vnd.github+json")
	resp2, err := deadDropHTTPClient.Do(req2)
	if err != nil {
		return "", 0, err
	}
	defer resp2.Body.Close()
	var result map[string]any
	json.NewDecoder(resp2.Body).Decode(&result)
	if num, ok := result["number"].(float64); ok {
		issNum := int(num)
		t.mu.Lock()
		t.issueNum = issNum
		t.mu.Unlock()
		return repo, issNum, nil
	}
	return "", 0, fmt.Errorf("gitHub: failed to create issue")
}

func (t *githubDeadDrop) write(auth, channel, key string, data []byte) error {
	repo, issNum, err := t.ensureIssue(auth, channel)
	if err != nil {
		return err
	}
	// Comment body: first line is the key tag, rest is data.
	comment := fmt.Sprintf("[%s]\n%s", key, string(data))
	body, _ := json.Marshal(map[string]string{"body": comment})
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/issues/%d/comments", repo, issNum)
	req, _ := http.NewRequest("POST", apiURL, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+auth)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := deadDropHTTPClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("gitHub issue comment: status %d", resp.StatusCode)
	}
	return nil
}

func (t *githubDeadDrop) read(auth, channel, key string) ([]byte, error) {
	repo, issNum, err := t.ensureIssue(auth, channel)
	if err != nil {
		return nil, err
	}
	// Fetch comments and find one tagged with our key.
	// Use the `since` parameter to only fetch comments newer than the last
	// successful poll, reducing GitHub API payload and rate-limit pressure.
	tag := fmt.Sprintf("[%s]", key)
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/issues/%d/comments?per_page=30&direction=desc", repo, issNum)
	t.mu.Lock()
	if !t.lastPoll.IsZero() {
		apiURL += "&since=" + t.lastPoll.UTC().Format(time.RFC3339)
	}
	t.mu.Unlock()
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("Authorization", "Bearer "+auth)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := deadDropHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var comments []map[string]any
	json.NewDecoder(resp.Body).Decode(&comments)

	t.mu.Lock()
	t.lastPoll = time.Now().UTC()
	t.mu.Unlock()

	for _, c := range comments {
		body, _ := c["body"].(string)
		if strings.HasPrefix(body, tag+"\n") {
			data := strings.TrimPrefix(body, tag+"\n")
			return []byte(data), nil
		}
	}
	return nil, nil // not found yet
}

func (t *githubDeadDrop) delete(auth, channel, key string) error {
	// Comments can't easily be deleted without knowing the comment ID.
	// For now, just leave them — the issue is private and ephemeral.
	return nil
}

func serveGithubDeadDrop(ctx context.Context, emit func(string)) TunnelResult {
	return serveDeadDropTunnel(ctx, &githubDeadDrop{creator: true}, emit)
}

func connectGithubDeadDropClient(ctx context.Context, emit func(string)) TunnelResult {
	return connectDeadDropClient(ctx, &githubDeadDrop{creator: false}, emit)
}

// ═══════════════════════════════════════════════════════════════════════════
// Transport 2: OpenAI Files API dead drop
//
// Uses the same pattern as GitHub: both sides share an API key and derive
// a deterministic session prefix from it. Files are uploaded as .jsonl with
// purpose=fine-tune (allows both upload AND content download).
//
// write:  POST /v1/files (multipart, purpose=fine-tune, filename=prefix_key.jsonl)
// read:   GET  /v1/files (list by prefix), then GET /v1/files/{id}/content
// delete: DELETE /v1/files/{id}
// Auth:   OPENAI_API_KEY (both sides use same key)
//
// Creator (server) cleans up stale session files on start. Non-creator
// (client) waits until the READY signal file appears.
// ═══════════════════════════════════════════════════════════════════════════

type openaiDeadDrop struct {
	mu      sync.Mutex
	prefix  string // "pw_<session[:12]>" — all session files share this prefix
	creator bool
}

func (t *openaiDeadDrop) name() string { return "OpenAI" }

func (t *openaiDeadDrop) sessionPrefix(channel string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.prefix == "" {
		t.prefix = "pw_" + channel[:12]
	}
	return t.prefix
}

func (t *openaiDeadDrop) filename(channel, key string) string {
	return t.sessionPrefix(channel) + "_" + strings.ReplaceAll(key, "/", "_") + ".jsonl"
}

// listSessionFiles returns all files matching our session prefix.
func (t *openaiDeadDrop) listSessionFiles(auth, channel string) ([]struct {
	ID       string
	Filename string
}, error) {
	prefix := t.sessionPrefix(channel)
	req, _ := http.NewRequest("GET", "https://api.openai.com/v1/files?purpose=fine-tune", nil)
	req.Header.Set("Authorization", "Bearer "+auth)
	resp, err := deadDropHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result struct {
		Data []struct {
			ID       string `json:"id"`
			Filename string `json:"filename"`
		} `json:"data"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	var matched []struct {
		ID       string
		Filename string
	}
	for _, f := range result.Data {
		if strings.HasPrefix(f.Filename, prefix) {
			matched = append(matched, struct {
				ID       string
				Filename string
			}{f.ID, f.Filename})
		}
	}
	return matched, nil
}

// cleanupStaleFiles removes all files matching the session prefix (creator only).
func (t *openaiDeadDrop) cleanupStaleFiles(auth, channel string) {
	files, err := t.listSessionFiles(auth, channel)
	if err != nil {
		return
	}
	for _, f := range files {
		req, _ := http.NewRequest("DELETE", "https://api.openai.com/v1/files/"+f.ID, nil)
		req.Header.Set("Authorization", "Bearer "+auth)
		resp, err := deadDropHTTPClient.Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}
}

func (t *openaiDeadDrop) write(auth, channel, key string, data []byte) error {
	fname := t.filename(channel, key)
	// Wrap data as JSONL so OpenAI accepts it with purpose=fine-tune.
	jsonlLine, _ := json.Marshal(map[string]string{"d": string(data)})
	jsonlLine = append(jsonlLine, '\n')

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("purpose", "fine-tune")
	part, err := w.CreateFormFile("file", fname)
	if err != nil {
		return err
	}
	part.Write(jsonlLine)
	w.Close()

	req, _ := http.NewRequest("POST", "https://api.openai.com/v1/files", &buf)
	req.Header.Set("Authorization", "Bearer "+auth)
	req.Header.Set("Content-Type", w.FormDataContentType())

	resp, err := deadDropHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("openAI write %s: status %d: %s", fname, resp.StatusCode, string(body[:min(len(body), 200)]))
	}
	return nil
}

func (t *openaiDeadDrop) read(auth, channel, key string) ([]byte, error) {
	fname := t.filename(channel, key)
	// List files and find by exact filename match.
	files, err := t.listSessionFiles(auth, channel)
	if err != nil {
		return nil, err
	}
	var fileID string
	for _, f := range files {
		if f.Filename == fname {
			fileID = f.ID
			break
		}
	}
	if fileID == "" {
		return nil, nil // not found yet
	}

	// Download content.
	req, _ := http.NewRequest("GET", "https://api.openai.com/v1/files/"+fileID+"/content", nil)
	req.Header.Set("Authorization", "Bearer "+auth)
	resp, err := deadDropHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("openAI read %s: status %d: %s", fileID, resp.StatusCode, string(body[:min(len(body), 200)]))
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// Unwrap JSONL envelope.
	var envelope struct {
		D string `json:"d"`
	}
	if json.Unmarshal(bytes.TrimSpace(raw), &envelope) == nil && envelope.D != "" {
		return []byte(envelope.D), nil
	}
	return raw, nil
}

func (t *openaiDeadDrop) delete(auth, channel, key string) error {
	fname := t.filename(channel, key)
	files, err := t.listSessionFiles(auth, channel)
	if err != nil {
		return err
	}
	for _, f := range files {
		if f.Filename == fname {
			req, _ := http.NewRequest("DELETE", "https://api.openai.com/v1/files/"+f.ID, nil)
			req.Header.Set("Authorization", "Bearer "+auth)
			resp, err := deadDropHTTPClient.Do(req)
			if err == nil {
				resp.Body.Close()
			}
			return nil
		}
	}
	return nil
}

func serveOpenAIDeadDrop(ctx context.Context, emit func(string)) TunnelResult {
	t := &openaiDeadDrop{creator: true}
	auth := getServiceKey(t.name())
	if auth == "" {
		return TunnelResult{Error: fmt.Errorf("no credentials for OpenAI dead drop")}
	}
	sessionID := deadDropSessionID(auth)
	// Creator cleans up stale files from previous sessions before starting.
	t.cleanupStaleFiles(auth, sessionID)
	return serveDeadDropTunnelWithAuth(ctx, t, auth, emit)
}

func connectOpenAIDeadDropClient(ctx context.Context, emit func(string)) TunnelResult {
	return connectDeadDropClient(ctx, &openaiDeadDrop{creator: false}, emit)
}
