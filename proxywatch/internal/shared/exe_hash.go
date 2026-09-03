package shared

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// exeHashEntry caches the SHA256 for a path, along with the file identity
// (mtime + size) we computed it for. Cache is invalidated when the file
// on disk changes — same path, different content → recompute.
type exeHashEntry struct {
	sha256     string
	modUnix    int64
	size       int64
	computedAt time.Time
}

var (
	exeHashMu       sync.RWMutex
	exeHashCache    = map[string]exeHashEntry{}
	exeHashInFlight = map[string]struct{}{}

	exeHashQueue chan string
	exeHashOnce  sync.Once
)

// startExeHashWorker launches the background SHA256 computation worker once.
// Called lazily from LookupExeSHA256 on first miss so the worker only
// spins up when actually needed.
func startExeHashWorker() {
	exeHashOnce.Do(func() {
		exeHashQueue = make(chan string, 1024)
		go exeHashWorkerLoop()
	})
}

func exeHashWorkerLoop() {
	for path := range exeHashQueue {
		computeAndCacheExeHash(path)
		exeHashMu.Lock()
		delete(exeHashInFlight, path)
		exeHashMu.Unlock()
	}
}

// LookupExeSHA256 returns the cached SHA256 for exePath, or "" if not yet
// computed. Async: on cache miss, enqueues compute and returns "" —
// next call (after compute finishes) will return the hash.
//
// The cache is invalidated when the file's mtime or size changes, so a
// replaced binary is re-hashed automatically.
//
// Returns "" for empty paths, paths we can't stat, or when the path is
// unreadable. The SHA256 flows downstream to the operator-label lookup;
// empty hash → operator label lookup is skipped → no change vs.
// pre-Phase-9 behavior. Fail-closed by design.
func LookupExeSHA256(exePath string) string {
	exePath = strings.TrimSpace(exePath)
	if exePath == "" {
		return ""
	}
	exeHashMu.RLock()
	entry, ok := exeHashCache[exePath]
	exeHashMu.RUnlock()
	if ok {
		// Validate the cache entry is still current — if the file changed
		// on disk (mtime or size), re-enqueue for recompute but still
		// return the old hash for this cycle. It'll refresh.
		if info, err := os.Stat(exePath); err == nil {
			if info.ModTime().Unix() == entry.modUnix && info.Size() == entry.size {
				return entry.sha256
			}
			// File changed. Invalidate and recompute.
			exeHashMu.Lock()
			delete(exeHashCache, exePath)
			exeHashMu.Unlock()
		} else {
			return entry.sha256 // file vanished; return last-known
		}
	}
	enqueueExeHash(exePath)
	return ""
}

func enqueueExeHash(exePath string) {
	startExeHashWorker()
	exeHashMu.Lock()
	if _, busy := exeHashInFlight[exePath]; busy {
		exeHashMu.Unlock()
		return
	}
	exeHashInFlight[exePath] = struct{}{}
	exeHashMu.Unlock()
	select {
	case exeHashQueue <- exePath:
	default:
		// Queue full — drop this compute. Will retry on next lookup.
		exeHashMu.Lock()
		delete(exeHashInFlight, exePath)
		exeHashMu.Unlock()
	}
}

func computeAndCacheExeHash(exePath string) {
	info, err := os.Stat(exePath)
	if err != nil {
		return
	}
	f, err := os.Open(exePath)
	if err != nil {
		return
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return
	}
	sum := hex.EncodeToString(h.Sum(nil))

	exeHashMu.Lock()
	exeHashCache[exePath] = exeHashEntry{
		sha256:     sum,
		modUnix:    info.ModTime().Unix(),
		size:       info.Size(),
		computedAt: time.Now(),
	}
	exeHashMu.Unlock()
}
