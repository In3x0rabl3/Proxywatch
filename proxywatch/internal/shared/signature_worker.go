package shared

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"proxywatch/internal/safeio"
)

// Posture values for PROXYWATCH_ONLINE_VERIFY.
const (
	OnlineVerifyOff       = "off"
	OnlineVerifyCacheOnly = "cache-only"
	OnlineVerifyLive      = "live"
)

// VerdictEntry is the full record persisted per binary in the reputation
// cache. Keyed by (path, mtime, size) — any of those changing evicts the
// entry, since a binary whose contents rotated requires a fresh verdict.
type VerdictEntry struct {
	Path                 string    `json:"path"`
	ModTimeUnixNanos     int64     `json:"mtime_unix_nanos"`
	Size                 int64     `json:"size"`
	Trust                string    `json:"trust"`
	Publisher            string    `json:"publisher,omitempty"`
	ChainSubjects        []string  `json:"chain_subjects,omitempty"`
	CheckedAt            time.Time `json:"checked_at"`
	OCSPResponseSeen     bool      `json:"ocsp_response_seen"`
	LastErr              string    `json:"last_err,omitempty"`

	// Evidence is the multi-verifier trace — each verifier appends one
	// entry. Authenticode is always present (from the legacy fields above);
	// Phase 6 added pkg-ownership. Phase 6b will add CT + GH attestations.
	Evidence []Evidence `json:"evidence,omitempty"`

	// Cached verifier-specific fields surfaced for quick reads without
	// walking Evidence[]. Pkg* is populated by the pkg-ownership verifier
	// when the binary is dpkg-tracked.
	PkgOwned     bool   `json:"pkg_owned,omitempty"`
	PkgOwnerName string `json:"pkg_owner_name,omitempty"`
}

// signatureWorker owns the on-disk + in-memory verdict cache and the
// background verification goroutine. Exactly one instance per process;
// accessed via the package-level global below.
type signatureWorker struct {
	mu sync.RWMutex

	// In-memory cache keyed by exePath; the authoritative source for
	// telemetry readers. Always populated from disk at startup.
	byPath map[string]*VerdictEntry

	// pending paths awaiting verification. nil when posture is not live.
	queue chan string

	// deduplicates pending enqueues.
	inQueue map[string]struct{}

	// Posture + stats surfaced by /online/status.
	posture      string
	verdictsDone atomic.Int64
	ocspErrors   atomic.Int64
	lastVerdict  atomic.Int64 // unix nanos
	lastErr      atomic.Value // string

	// Lifecycle.
	stopCh chan struct{}
	wg     sync.WaitGroup

	// rateInterval is the minimum time between two verifications. 50ms is
	// the plan default (max 1200/min).
	rateInterval time.Duration
}

var sigWorker = &signatureWorker{
	byPath:       make(map[string]*VerdictEntry),
	inQueue:      make(map[string]struct{}),
	posture:      OnlineVerifyLive,
	rateInterval: 50 * time.Millisecond,
}

// StartSignatureWorker initializes the worker: loads persisted verdicts from
// disk into memory, reads the posture env var, and — only when posture is
// live — spawns the background verification goroutine. Safe to call twice;
// the second call is a no-op unless StopSignatureWorker ran in between.
func StartSignatureWorker() {
	sigWorker.mu.Lock()
	if sigWorker.stopCh != nil {
		sigWorker.mu.Unlock()
		return
	}
	sigWorker.posture = resolvePosture()
	sigWorker.stopCh = make(chan struct{})
	sigWorker.mu.Unlock()

	if err := sigWorker.loadCache(); err != nil {
		LogError("signature", "cache load failed: %v", err)
	}

	if sigWorker.posture != OnlineVerifyLive {
		return
	}

	sigWorker.mu.Lock()
	sigWorker.queue = make(chan string, 512)
	sigWorker.mu.Unlock()

	sigWorker.wg.Add(1)
	go sigWorker.loop()
}

// StopSignatureWorker shuts down the background goroutine with a 5s drain
// deadline. Safe when the worker never started — simply resets state.
func StopSignatureWorker() {
	sigWorker.mu.Lock()
	ch := sigWorker.stopCh
	sigWorker.stopCh = nil
	sigWorker.mu.Unlock()
	if ch == nil {
		return
	}
	close(ch)

	done := make(chan struct{})
	go func() {
		sigWorker.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		LogError("signature", "worker drain timed out")
	}
}

// lookupVerdict returns the cached verdict for exePath if present and still
// matching the on-disk mtime+size. Returns (nil, false) otherwise.
func (w *signatureWorker) lookupVerdict(exePath string) (*VerdictEntry, bool) {
	w.mu.RLock()
	entry, ok := w.byPath[exePath]
	w.mu.RUnlock()
	if !ok || entry == nil {
		return nil, false
	}
	info, err := os.Stat(exePath)
	if err != nil {
		return nil, false
	}
	if info.ModTime().UnixNano() != entry.ModTimeUnixNanos || info.Size() != entry.Size {
		w.mu.Lock()
		delete(w.byPath, exePath)
		w.mu.Unlock()
		_ = os.Remove(cachePathFor(exePath))
		return nil, false
	}
	return entry, true
}

// enqueueLookup adds a path to the pending queue when posture is live.
// Deduplicates paths already queued. No-op when not live.
func (w *signatureWorker) enqueueLookup(exePath string) {
	w.mu.RLock()
	live := w.posture == OnlineVerifyLive
	q := w.queue
	w.mu.RUnlock()
	if !live || q == nil {
		return
	}
	w.mu.Lock()
	if _, busy := w.inQueue[exePath]; busy {
		w.mu.Unlock()
		return
	}
	w.inQueue[exePath] = struct{}{}
	w.mu.Unlock()

	select {
	case q <- exePath:
	default:
		w.mu.Lock()
		delete(w.inQueue, exePath)
		w.mu.Unlock()
	}
}

func (w *signatureWorker) loop() {
	defer w.wg.Done()
	ticker := time.NewTicker(w.rateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-w.stopCh:
			return
		case <-ticker.C:
			w.drainOne()
		}
	}
}

func (w *signatureWorker) drainOne() {
	w.mu.RLock()
	q := w.queue
	w.mu.RUnlock()
	if q == nil {
		return
	}

	var exePath string
	select {
	case exePath = <-q:
	default:
		return
	}

	defer func() {
		w.mu.Lock()
		delete(w.inQueue, exePath)
		w.mu.Unlock()
	}()

	entry := w.verifyNow(exePath)
	if entry == nil {
		return
	}
	w.mu.Lock()
	w.byPath[exePath] = entry
	w.mu.Unlock()
	w.verdictsDone.Add(1)
	w.lastVerdict.Store(time.Now().UnixNano())
	if err := w.persistVerdict(entry); err != nil {
		LogError("signature", "persist verdict for %s: %v", exePath, err)
	}
}

// verifyNow runs one full WinVerifyTrust round-trip on exePath and returns
// a persistable VerdictEntry. Implemented per-OS. On Linux/macOS this
// simply wraps the existing path+ownership heuristic so the cache layer is
// useful even without Authenticode.
func (w *signatureWorker) verifyNow(exePath string) *VerdictEntry {
	info, err := os.Stat(exePath)
	if err != nil {
		w.ocspErrors.Add(1)
		w.lastErr.Store(err.Error())
		return nil
	}
	trust, publisher, chain, ocspSeen, verr := performAuthenticodeVerify(exePath)
	errStr := ""
	if verr != nil {
		errStr = verr.Error()
		w.ocspErrors.Add(1)
		w.lastErr.Store(errStr)
	}
	entry := &VerdictEntry{
		Path:             exePath,
		ModTimeUnixNanos: info.ModTime().UnixNano(),
		Size:             info.Size(),
		Trust:            trust,
		Publisher:        publisher,
		ChainSubjects:    chain,
		CheckedAt:        time.Now().UTC(),
		OCSPResponseSeen: ocspSeen,
		LastErr:          errStr,
	}

	now := time.Now().UTC()

	// Authenticode evidence — always recorded so /fp-report shows the
	// verifier even when trust is unknown.
	entry.Evidence = append(entry.Evidence, Evidence{
		Verifier:   VerifierAuthenticode,
		Verdict:    authenticodeVerdictFromTrust(trust),
		Confidence: authenticodeConfidenceFromTrust(trust, ocspSeen),
		Tags:       authenticodeTags(trust, publisher, ocspSeen),
		Detail:     publisher,
		CheckedAt:  now,
	})

	// Pkg-ownership verifier — Linux-only via build-tagged LookupPackageOwner.
	// Runs unconditionally (no network, no privacy cost) regardless of the
	// online posture. Stub on non-Linux returns "".
	if owner := LookupPackageOwner(exePath); owner != "" {
		entry.PkgOwned = true
		entry.PkgOwnerName = owner
		entry.Evidence = append(entry.Evidence, Evidence{
			Verifier:   VerifierPkgOwnership,
			Verdict:    VerdictPositive,
			Confidence: 90,
			Tags:       []string{"pkg:owned:" + owner},
			Detail:     "owned by OS package " + owner,
			CheckedAt:  now,
		})
	}

	return entry
}

func authenticodeVerdictFromTrust(t string) string {
	switch t {
	case SignatureTrustTrusted:
		return VerdictPositive
	case SignatureTrustUntrusted:
		return VerdictNegative
	default:
		return VerdictNeutral
	}
}

func authenticodeConfidenceFromTrust(t string, ocspSeen bool) int {
	switch t {
	case SignatureTrustTrusted:
		if ocspSeen {
			return 95
		}
		return 70
	case SignatureTrustUntrusted:
		return 95
	default:
		return 0
	}
}

func authenticodeTags(trust, publisher string, ocspSeen bool) []string {
	var out []string
	out = append(out, "authenticode:"+trust)
	if ocspSeen {
		out = append(out, "authenticode:ocsp-verified")
	}
	if publisher != "" {
		out = append(out, "authenticode:publisher:"+publisher)
	}
	return out
}

// persistVerdict atomically writes one JSON file under ~/.proxywatch/reputation/.
func (w *signatureWorker) persistVerdict(entry *VerdictEntry) error {
	if entry == nil {
		return errors.New("nil verdict")
	}
	path := cachePathFor(entry.Path)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// loadCache walks ~/.proxywatch/reputation/ and hydrates the in-memory map.
// Missing directory is not an error (first run).
func (w *signatureWorker) loadCache() error {
	root := cacheRoot()
	loaded := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		data, rerr := safeio.ReadFile(path)
		if rerr != nil {
			return nil
		}
		var entry VerdictEntry
		if jerr := json.Unmarshal(data, &entry); jerr != nil {
			return nil
		}
		if entry.Path == "" {
			return nil
		}
		w.mu.Lock()
		w.byPath[entry.Path] = &entry
		w.mu.Unlock()
		loaded++
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if loaded > 0 {
		LogInfo("signature", "loaded %d cached verdict(s) from %s", loaded, root)
	}
	return nil
}

// OnlineStatus is the JSON payload surfaced at /online/status.
type OnlineStatus struct {
	Mode                string    `json:"mode"`
	QueueDepth          int       `json:"queue_depth"`
	VerdictsCached      int       `json:"verdicts_cached"`
	VerdictsDone        int64     `json:"verdicts_done"`
	OCSPErrors          int64     `json:"ocsp_errors"`
	LastVerdictAt       time.Time `json:"last_verdict_at"`
	LastErr             string    `json:"last_err,omitempty"`
}

// SnapshotOnlineStatus returns a read-only view of the worker's state.
func SnapshotOnlineStatus() OnlineStatus {
	sigWorker.mu.RLock()
	mode := sigWorker.posture
	cached := len(sigWorker.byPath)
	queue := 0
	if sigWorker.queue != nil {
		queue = len(sigWorker.queue)
	}
	sigWorker.mu.RUnlock()
	var lastErr string
	if v := sigWorker.lastErr.Load(); v != nil {
		if s, ok := v.(string); ok {
			lastErr = s
		}
	}
	var lastAt time.Time
	if ns := sigWorker.lastVerdict.Load(); ns > 0 {
		lastAt = time.Unix(0, ns).UTC()
	}
	return OnlineStatus{
		Mode:           mode,
		QueueDepth:     queue,
		VerdictsCached: cached,
		VerdictsDone:   sigWorker.verdictsDone.Load(),
		OCSPErrors:     sigWorker.ocspErrors.Load(),
		LastVerdictAt:  lastAt,
		LastErr:        lastErr,
	}
}

// LookupVerdictForPath returns the cached verdict for exePath or nil if
// nothing is cached. Intended for the /online/verdict endpoint and tests.
func LookupVerdictForPath(exePath string) *VerdictEntry {
	entry, ok := sigWorker.lookupVerdict(exePath)
	if !ok {
		return nil
	}
	cp := *entry
	return &cp
}

func cacheRoot() string {
	return filepath.Join(safeio.ProxywatchDataRoot(), "reputation")
}

func cachePathFor(exePath string) string {
	sum := sha1.Sum([]byte(exePath))
	h := hex.EncodeToString(sum[:])
	return filepath.Join(cacheRoot(), h[:2], h+".json")
}

// resolvePosture picks the online-verification posture.
//
// Default (no env var set) is "live" — Authenticode / OCSP / CT verification
// runs out of the box. Signature checks happen off the hot path on a
// background worker capped at ~1200/min, so there's no user-visible cost and
// nothing to configure for the common case.
//
// Escape hatches via PROXYWATCH_ONLINE_VERIFY for operators who need them:
//   - "off" / "0" / "false" / "disable" — fully disabled. No cache reads, no
//     verification. Use when signature work must not touch disk.
//   - "cache-only" — read persisted verdicts but do not verify. Use in
//     air-gapped or OCSP-blocked environments where the live path would
//     waste retries.
//   - "live" or unset — default, run live verification.
func resolvePosture() string {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("PROXYWATCH_ONLINE_VERIFY")))
	switch raw {
	case "off", "0", "false", "disable", "disabled":
		return OnlineVerifyOff
	case OnlineVerifyCacheOnly, "cache", "offline":
		return OnlineVerifyCacheOnly
	case OnlineVerifyLive, "on", "1", "true", "enable", "enabled":
		return OnlineVerifyLive
	default:
		return OnlineVerifyLive
	}
}
