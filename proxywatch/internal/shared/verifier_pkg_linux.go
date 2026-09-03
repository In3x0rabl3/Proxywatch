//go:build linux

package shared

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Dpkg package-ownership verifier.
//
// Walks /var/lib/dpkg/info/*.list once, caches an exePath → packageName
// map. A binary owned by a real dpkg package is a strong benign signal:
// dpkg verified the package's GPG signature at install time, so the file
// on disk traces back to a signed distro release.
//
// Future extensions (not this pass): /var/lib/rpm/rpmdb.sqlite for RPM,
// /var/lib/pacman/local/*/files for pacman, /lib/apk/db/installed for apk.

const (
	dpkgInfoDir = "/var/lib/dpkg/info"
	pkgCacheTTL = 5 * time.Minute
)

type pkgCache struct {
	mu          sync.RWMutex
	ownerByPath map[string]string
	builtAt     time.Time
}

var pkgCacheInst = &pkgCache{
	ownerByPath: map[string]string{},
}

// LookupPackageOwner returns the dpkg package that owns exePath, or "" if
// the binary is not dpkg-tracked. Rebuilds the cache every pkgCacheTTL so
// newly-installed packages become visible without a daemon restart.
func LookupPackageOwner(exePath string) string {
	exePath = strings.TrimSpace(exePath)
	if exePath == "" {
		return ""
	}
	ensurePkgCacheFresh()
	pkgCacheInst.mu.RLock()
	defer pkgCacheInst.mu.RUnlock()
	return pkgCacheInst.ownerByPath[exePath]
}

func ensurePkgCacheFresh() {
	pkgCacheInst.mu.RLock()
	stale := time.Since(pkgCacheInst.builtAt) > pkgCacheTTL || len(pkgCacheInst.ownerByPath) == 0
	pkgCacheInst.mu.RUnlock()
	if !stale {
		return
	}
	rebuildPkgCache()
}

func rebuildPkgCache() {
	owner := make(map[string]string, 16384)

	// Try each package manager in order — they populate the same map.
	// Multiple managers can coexist (e.g. Debian + Flatpak; Arch + AUR); we
	// keep the first claim since that's almost always the OS-native one.
	walkDpkg(owner)
	walkPacman(owner)
	walkApk(owner)
	// rpm omitted — /var/lib/rpm is a BDB or SQLite database; adding a
	// pure-Go SQLite driver or BDB parser is tracked as a follow-up. Until
	// then, RHEL/Fedora hosts get zero pkg-ownership evidence. Publisher-
	// DNS-alignment + other online verifiers still apply.

	pkgCacheInst.mu.Lock()
	pkgCacheInst.ownerByPath = owner
	pkgCacheInst.builtAt = time.Now()
	pkgCacheInst.mu.Unlock()
}

// walkDpkg hydrates owner with paths from /var/lib/dpkg/info/*.list.
func walkDpkg(owner map[string]string) {
	entries, err := os.ReadDir(dpkgInfoDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".list") {
			continue
		}
		pkg := strings.TrimSuffix(name, ".list")
		if idx := strings.IndexByte(pkg, ':'); idx > 0 {
			pkg = pkg[:idx]
		}
		listPath := filepath.Join(dpkgInfoDir, name)
		f, err := os.Open(listPath)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			path := strings.TrimSpace(scanner.Text())
			if path == "" || !strings.HasPrefix(path, "/") {
				continue
			}
			if _, exists := owner[path]; exists {
				continue
			}
			owner[path] = pkg
		}
		_ = f.Close()
	}
}

// walkPacman hydrates owner from /var/lib/pacman/local/<pkg>-<ver>/files.
// Each files file is plain text — first line is "%FILES%", subsequent
// lines are package-relative paths without leading slash.
func walkPacman(owner map[string]string) {
	root := "/var/lib/pacman/local"
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := entry.Name()
		// Pacman dirs are "<pkgname>-<version>-<release>". Strip the last
		// two dash-separated segments to recover the package name.
		pkg := stripPacmanVersion(dir)
		if pkg == "" {
			continue
		}
		listPath := filepath.Join(root, dir, "files")
		f, err := os.Open(listPath)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		inFiles := false
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "%FILES%" {
				inFiles = true
				continue
			}
			if !inFiles || line == "" {
				continue
			}
			path := "/" + strings.TrimPrefix(line, "/")
			if _, exists := owner[path]; exists {
				continue
			}
			owner[path] = pkg
		}
		_ = f.Close()
	}
}

// stripPacmanVersion returns "openssh" from "openssh-9.9p2-1".
func stripPacmanVersion(dir string) string {
	// A pacman dir ends with "<ver>-<rel>"; remove the last two dash-
	// separated chunks unless the remainder is empty.
	parts := strings.Split(dir, "-")
	if len(parts) < 3 {
		return ""
	}
	return strings.Join(parts[:len(parts)-2], "-")
}

// walkApk hydrates owner from /lib/apk/db/installed — Alpine's package DB.
// Multi-record text format: records separated by blank lines; within a
// record, P: = package name, F: = directory (no leading slash),
// R: = file under the most-recent F:.
func walkApk(owner map[string]string) {
	f, err := os.Open("/lib/apk/db/installed")
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var pkg, curDir string
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			pkg, curDir = "", ""
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		key := line[0]
		val := line[2:]
		switch key {
		case 'P':
			pkg = val
		case 'F':
			curDir = val
		case 'R':
			if pkg == "" || curDir == "" {
				continue
			}
			path := "/" + strings.TrimPrefix(curDir, "/") + "/" + val
			if _, exists := owner[path]; exists {
				continue
			}
			owner[path] = pkg
		}
	}
}
