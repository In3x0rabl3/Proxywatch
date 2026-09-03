package shared

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProtoProbeEnabled is the runtime toggle for active TLS probing of
// remote endpoints. Set by the CLI from the -proto-probe flag (or
// the PROXYWATCH_PROTO_PROBE env var). When false, EnqueueProbe is a
// no-op and the dashboard PROTO column behaves as it did before
// Tier B landed (port + lib + name only).
//
// Default true; operators in restricted environments flip it off.
var ProtoProbeEnabled = true

// ProbeVerdict captures what we learned about a remote endpoint
// from a single TLS handshake. Cached for ProbeCacheTTL after the
// probe completes; stale entries are re-probed on demand.
//
// TLSConfirmed=false + ProbedAt!=zero means the probe ran but TLS
// failed (plain TCP service, refused, timed out). The display layer
// uses ProbedAt to skip re-enqueuing inside the TTL window.
type ProbeVerdict struct {
	TLSConfirmed bool
	ALPN         string // "h2" / "http/1.1" / "imap" / etc.; empty when server picked none
	JA3S         string // 32-char lowercase MD5; empty when handshake didn't produce a ServerHello
	ProbedAt     time.Time
}

// ProbeCacheTTL controls how long a ProbeVerdict stays valid. 1h
// matches typical TLS cert + JA3S stability windows for vendor CDNs.
const ProbeCacheTTL = time.Hour

// probeTimeout is the per-handshake deadline. Probes block one of
// the worker goroutines for up to this duration; bigger numbers
// reduce throughput, smaller numbers miss slow handshakes.
const probeTimeout = 3 * time.Second

// probeWorkerCount is the global concurrency cap for outbound
// probes. Keeps the worker pool from saturating the operator's
// network on a busy candidate list.
const probeWorkerCount = 5

// probeQueueSize bounds the buffered task channel. Drops are
// acceptable — the next render cycle re-enqueues anything still
// missing from the cache.
const probeQueueSize = 256

var (
	probeMu       sync.RWMutex
	probeCache    = make(map[string]ProbeVerdict)
	probeInFlight = make(map[string]struct{})

	probeQueue chan string
	probeOnce  sync.Once
)

// LookupProbeVerdict returns the cached verdict for ip:port, or a
// zero-value verdict + ok=false if none / stale. Stale entries are
// reported as misses so the next EnqueueProbe re-runs the handshake.
func LookupProbeVerdict(ip string, port int) (ProbeVerdict, bool) {
	if ip == "" || port <= 0 {
		return ProbeVerdict{}, false
	}
	key := endpointKey(ip, port)
	probeMu.RLock()
	v, ok := probeCache[key]
	probeMu.RUnlock()
	if !ok {
		return ProbeVerdict{}, false
	}
	if time.Since(v.ProbedAt) > ProbeCacheTTL {
		return ProbeVerdict{}, false
	}
	return v, true
}

// EnqueueProbe asks the worker pool to probe ip:port if it isn't
// already cached / in flight. Internal IPs and loopback are skipped
// silently — probing them trips IDS / SOC tooling.
//
// Non-blocking. When the queue is full, the request is dropped; the
// next render cycle that finds the cache still empty will retry.
func EnqueueProbe(ip string, port int) {
	if !ProtoProbeEnabled {
		return
	}
	if ip == "" || port <= 0 {
		return
	}
	if IsLoopbackIP(ip) || IsInternalIP(ip) || IsWildcardIP(ip) {
		return
	}
	if _, fresh := LookupProbeVerdict(ip, port); fresh {
		return
	}
	probeOnce.Do(startProbeWorkers)

	key := endpointKey(ip, port)
	probeMu.Lock()
	if _, busy := probeInFlight[key]; busy {
		probeMu.Unlock()
		return
	}
	probeInFlight[key] = struct{}{}
	probeMu.Unlock()

	select {
	case probeQueue <- key:
		// queued — worker will run it
	default:
		// queue full; release the in-flight slot so the next call
		// can retry, and drop this request.
		probeMu.Lock()
		delete(probeInFlight, key)
		probeMu.Unlock()
	}
}

func endpointKey(ip string, port int) string {
	return net.JoinHostPort(ip, strconv.Itoa(port))
}

func startProbeWorkers() {
	probeQueue = make(chan string, probeQueueSize)
	for i := 0; i < probeWorkerCount; i++ {
		go probeWorker()
	}
}

func probeWorker() {
	for key := range probeQueue {
		host, portStr, err := net.SplitHostPort(key)
		if err != nil {
			probeMu.Lock()
			delete(probeInFlight, key)
			probeMu.Unlock()
			continue
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			probeMu.Lock()
			delete(probeInFlight, key)
			probeMu.Unlock()
			continue
		}
		v := runProbe(host, port)
		v.ProbedAt = time.Now()
		probeMu.Lock()
		probeCache[key] = v
		delete(probeInFlight, key)
		probeMu.Unlock()
	}
}

// runProbe dials host:port, performs a standard TLS 1.2/1.3
// handshake with InsecureSkipVerify, and extracts the server's
// JA3S + ALPN. Returns a verdict with TLSConfirmed=false on any
// dial error / non-TLS server.
func runProbe(host string, port int) ProbeVerdict {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()

	dialer := &net.Dialer{Timeout: probeTimeout}
	raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return ProbeVerdict{}
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(probeTimeout))

	rec := &probeRecorder{Conn: raw}
	serverName := host
	if net.ParseIP(serverName) != nil {
		serverName = ""
	}
	tc := tls.Client(rec, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
		// Advertise the common-case ALPN protocols so the server
		// picks one and emits it in its ServerHello — that's the
		// label we want the column to show.
		NextProtos: []string{"h2", "http/1.1"},
	})
	hsErr := tc.HandshakeContext(ctx)
	defer tc.Close()

	stream := rec.read.Bytes()
	if len(stream) == 0 {
		return ProbeVerdict{}
	}
	ja3s, alpn, parseErr := parseProbeServerHello(stream)
	if parseErr != nil && hsErr != nil {
		return ProbeVerdict{}
	}
	return ProbeVerdict{
		TLSConfirmed: ja3s != "",
		ALPN:         alpn,
		JA3S:         ja3s,
	}
}

// probeRecorder is a transparent net.Conn wrapper that copies every
// byte read into an internal buffer. Same shape as contour's
// byteRecorder; renamed to avoid symbol collision when both files
// are linked together.
type probeRecorder struct {
	net.Conn
	mu   sync.Mutex
	read probeRecordBuffer
}

func (b *probeRecorder) Read(p []byte) (int, error) {
	n, err := b.Conn.Read(p)
	if n > 0 {
		b.mu.Lock()
		b.read.Write(p[:n])
		b.mu.Unlock()
	}
	return n, err
}

type probeRecordBuffer struct{ buf []byte }

func (r *probeRecordBuffer) Write(p []byte) (int, error) {
	r.buf = append(r.buf, p...)
	return len(p), nil
}

func (r *probeRecordBuffer) Bytes() []byte { return r.buf }

// parseProbeServerHello finds the first ServerHello in a stream of
// TLS records and returns (JA3S, ALPN, err). JA3S is the canonical
// MD5 of `Version,CipherSuite,Extensions`; ALPN is the protocol the
// server chose ("h2" / "http/1.1" / etc., empty when the server
// didn't pick one).
func parseProbeServerHello(stream []byte) (string, string, error) {
	body, ok := findProbeServerHelloBody(stream)
	if !ok {
		return "", "", errors.New("ServerHello not found")
	}
	version, cipher, extPairs, err := parseProbeServerHelloBody(body)
	if err != nil {
		return "", "", err
	}
	// JA3S string: "<version>,<cipher>,<ext1>-<ext2>-<ext3>".
	parts := []string{
		strconv.Itoa(int(version)),
		strconv.Itoa(int(cipher)),
	}
	if len(extPairs) > 0 {
		ids := make([]string, len(extPairs))
		for i, p := range extPairs {
			ids[i] = strconv.Itoa(int(p.typ))
		}
		parts = append(parts, strings.Join(ids, "-"))
	} else {
		parts = append(parts, "")
	}
	sum := md5.Sum([]byte(strings.Join(parts, ",")))
	ja3s := hex.EncodeToString(sum[:])
	// ALPN extension type is 16 (0x10). Body format (RFC 7301):
	//   ProtocolNameList length (2) + ProtocolName (1-byte len + utf-8)
	// Server returns exactly one ProtocolName in its hello.
	alpn := ""
	for _, p := range extPairs {
		if p.typ == 16 && len(p.body) >= 3 {
			// list length is p.body[:2]; first entry starts at offset 2.
			if int(p.body[2]) >= 1 && len(p.body) >= 3+int(p.body[2]) {
				alpn = string(p.body[3 : 3+int(p.body[2])])
			}
			break
		}
	}
	return ja3s, alpn, nil
}

func findProbeServerHelloBody(stream []byte) ([]byte, bool) {
	off := 0
	for off+5 <= len(stream) {
		contentType := stream[off]
		recLen := int(binary.BigEndian.Uint16(stream[off+3 : off+5]))
		recStart := off + 5
		recEnd := recStart + recLen
		if recEnd > len(stream) {
			return nil, false
		}
		off = recEnd
		if contentType != 22 { // not handshake
			continue
		}
		body := stream[recStart:recEnd]
		bodyOff := 0
		for bodyOff+4 <= len(body) {
			hsType := body[bodyOff]
			hsLen := int(uint(body[bodyOff+1])<<16 |
				uint(body[bodyOff+2])<<8 |
				uint(body[bodyOff+3]))
			start := bodyOff + 4
			end := start + hsLen
			if end > len(body) {
				return nil, false
			}
			if hsType == 2 { // ServerHello
				return body[start:end], true
			}
			bodyOff = end
		}
	}
	return nil, false
}

// probeExt captures both the type ID (used for JA3S) and the raw
// extension body (used for ALPN extraction). Order preserved.
type probeExt struct {
	typ  uint16
	body []byte
}

func parseProbeServerHelloBody(body []byte) (uint16, uint16, []probeExt, error) {
	if len(body) < 38 {
		return 0, 0, nil, errors.New("ServerHello too short")
	}
	off := 0
	version := binary.BigEndian.Uint16(body[off : off+2])
	off += 2
	off += 32 // skip random
	sidLen := int(body[off])
	off++
	if off+sidLen > len(body) {
		return 0, 0, nil, errors.New("session_id overruns body")
	}
	off += sidLen
	if off+2 > len(body) {
		return 0, 0, nil, errors.New("cipher_suite missing")
	}
	cipher := binary.BigEndian.Uint16(body[off : off+2])
	off += 2
	if off+1 > len(body) {
		return 0, 0, nil, errors.New("compression missing")
	}
	off++ // skip compression
	if off >= len(body) {
		// No extensions — valid for SSL 3.0 / older TLS variants.
		return version, cipher, nil, nil
	}
	if off+2 > len(body) {
		return 0, 0, nil, errors.New("extensions_len missing")
	}
	extLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if off+extLen > len(body) {
		return 0, 0, nil, errors.New("extensions overrun body")
	}
	extEnd := off + extLen
	var exts []probeExt
	for off+4 <= extEnd {
		t := binary.BigEndian.Uint16(body[off : off+2])
		l := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		bodyStart := off + 4
		bodyEndExt := bodyStart + l
		if bodyEndExt > extEnd {
			break
		}
		exts = append(exts, probeExt{typ: t, body: body[bodyStart:bodyEndExt]})
		off = bodyEndExt
	}
	return version, cipher, exts, nil
}
