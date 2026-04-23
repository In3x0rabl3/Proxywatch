//go:build darwin

package shared

import (
	"bufio"
	"context"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// pkgutil-based package ownership verifier for macOS. `pkgutil
// --file-info <path>` returns metadata about the .pkg that installed
// a given file, including the pkg-id (reverse-DNS notation) and the
// pkg-version. A non-empty pkg-id is the strongest non-crypto
// identity signal on macOS: Installer.app verifies the pkg's
// Authenticode-equivalent signature at install time.
//
// Pure-Go: pkgutil ships with /usr/sbin/ in every macOS install. The
// subprocess is bounded by a context timeout so a hung pkgutil
// (broken receipts database, network-connected mount) can't stall
// the classifier. Results are cached per exePath for 5 minutes to
// keep the hot path off the process fork.

const darwinPkgCacheTTL = 5 * time.Minute

type darwinPkgCache struct {
	mu      sync.RWMutex
	entries map[string]darwinPkgCacheEntry
}

type darwinPkgCacheEntry struct {
	owner string
	at    time.Time
}

var darwinPkgCacheInst = &darwinPkgCache{
	entries: map[string]darwinPkgCacheEntry{},
}

// LookupPackageOwner returns the pkgutil pkg-id (e.g. "us.zoom.xos")
// that owns exePath, or "" when the binary isn't tracked by a known
// .pkg. Cache-first; a cache miss or stale entry triggers a bounded
// pkgutil subprocess.
func LookupPackageOwner(exePath string) string {
	exePath = strings.TrimSpace(exePath)
	if exePath == "" {
		return ""
	}
	darwinPkgCacheInst.mu.RLock()
	if entry, ok := darwinPkgCacheInst.entries[exePath]; ok {
		if time.Since(entry.at) < darwinPkgCacheTTL {
			darwinPkgCacheInst.mu.RUnlock()
			return entry.owner
		}
	}
	darwinPkgCacheInst.mu.RUnlock()

	owner := runPkgutilFileInfo(exePath)
	darwinPkgCacheInst.mu.Lock()
	darwinPkgCacheInst.entries[exePath] = darwinPkgCacheEntry{owner: owner, at: time.Now()}
	darwinPkgCacheInst.mu.Unlock()
	return owner
}

// runPkgutilFileInfo calls `pkgutil --file-info-plain <path>` and
// extracts the pkgid. The --file-info-plain form is key:value per
// line, simpler to parse than the default format. Expected output:
//
//	volume: /
//	path: /Applications/Zoom.app/Contents/MacOS/zoom.us
//	pkgid: us.zoom.xos
//	pkg-version: 5.15.2
//	install-time: 1690000000
//
// Returns empty string on any failure (no pkg, subprocess hung, etc.);
// the classifier treats an empty owner as "not tracked" without
// penalty.
func runPkgutilFileInfo(exePath string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "pkgutil", "--file-info-plain", exePath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "pkgid:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "pkgid:"))
		}
	}
	return ""
}
