package shared

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DisplayProcessName returns a UI-friendly process label in uppercase
// for military-style display.
func DisplayProcessName(p *ProcessInfo) string {
	if p == nil {
		return "(UNKNOWN)"
	}
	name := strings.TrimSpace(p.Name)
	if name == "" {
		name = "(UNKNOWN)"
	}
	if apt := aptMethodDisplayName(p.ExePath); apt != "" {
		return strings.ToUpper(apt)
	}
	return strings.ToUpper(name)
}

// selfIdentity holds the dynamically resolved identity of the running process,
// used for self-process filtering without any hardcoded binary names.
var (
	selfOnce    sync.Once
	selfPID     int
	selfExeName string // lowercase base name without extension
	selfExePath string // full normalized path
)

func initSelfIdentity() {
	selfOnce.Do(func() {
		selfPID = os.Getpid()
		if exe, err := os.Executable(); err == nil {
			resolved, err := filepath.EvalSymlinks(exe)
			if err == nil {
				exe = resolved
			}
			selfExePath = strings.ToLower(strings.ReplaceAll(filepath.Clean(exe), "\\", "/"))
			selfExeName = strings.TrimSuffix(strings.ToLower(filepath.Base(exe)), ".exe")
		}
	})
}

// IsProxywatchProcess returns true when p represents this running binary or a
// direct child of it. Detection is fully dynamic — the binary's own PID and
// executable path are resolved once at startup and every candidate is compared
// against those values. No hardcoded process names are used.
func IsProxywatchProcess(p *ProcessInfo) bool {
	if p == nil {
		return false
	}
	initSelfIdentity()

	// Direct PID match (local process is us).
	if selfPID > 0 && p.Pid == selfPID {
		return true
	}

	// Immediate child of self (e.g. worker subprocess we spawned).
	if selfPID > 0 && p.ParentPid > 0 && p.ParentPid == selfPID {
		return true
	}

	// Executable path match — covers remote agents running the same binary
	// under a potentially different PID.
	if selfExeName != "" {
		if matchesSelfExe(p.Name) || matchesSelfExe(exeBaseName(p.ExePath)) {
			return true
		}
	}

	// Full path match (handles symlinks, different casing, etc.).
	if selfExePath != "" {
		normalized := strings.ToLower(strings.TrimSpace(p.ExePath))
		normalized = strings.ReplaceAll(normalized, "\\", "/")
		if normalized != "" && normalized == selfExePath {
			return true
		}
	}

	return false
}

// matchesSelfExe compares a candidate name (already lowercase, no ext) to the
// running binary's base name.
func matchesSelfExe(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".exe")
	return name != "" && name == selfExeName
}

// exeBaseName extracts the lowercase filename from an executable path.
func exeBaseName(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	path = strings.ReplaceAll(path, "\\", "/")
	if idx := strings.LastIndexByte(path, '/'); idx >= 0 && idx+1 < len(path) {
		return path[idx+1:]
	}
	return path
}

// FilterProxywatchCandidates removes Proxywatch runtime processes from candidate lists.
func FilterProxywatchCandidates(cands []Candidate) []Candidate {
	if len(cands) == 0 {
		return cands
	}
	out := make([]Candidate, 0, len(cands))
	for _, c := range cands {
		if IsProxywatchProcess(c.Proc) {
			continue
		}
		out = append(out, c)
	}
	return out
}

func aptMethodDisplayName(exePath string) string {
	path := strings.ToLower(strings.TrimSpace(exePath))
	if path == "" {
		return ""
	}
	path = strings.ReplaceAll(path, "\\", "/")
	const prefix = "/usr/lib/apt/methods/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	method := strings.TrimPrefix(path, prefix)
	if method == "" {
		return ""
	}
	if slash := strings.IndexByte(method, '/'); slash >= 0 {
		method = method[:slash]
	}
	method = strings.TrimSpace(method)
	if method == "" {
		return ""
	}
	return "apt-" + method
}

type ProcessMeta struct {
	UserName    string
	ExePath     string
	Company     string
	Integrity   string
	SessionID   uint32
	SessionName string
	// LoadedLibs caches the notable-library enumeration so the (slow
	// and occasionally hang-prone on protected service hosts)
	// EnumProcessModules syscall runs at most once per TTL per PID.
	// Modules don't change inside a 60s window for real workloads;
	// TTL-expiry refreshes long-lived processes naturally.
	LoadedLibs []string
	FetchedAt  time.Time
}

type ProcessMetaCache struct {
	mu      sync.Mutex
	entries map[int]ProcessMeta
}

func NewProcessMetaCache() *ProcessMetaCache {
	return &ProcessMetaCache{
		entries: make(map[int]ProcessMeta),
	}
}

func (c *ProcessMetaCache) Get(pid int, now time.Time) (ProcessMeta, bool) {
	if c == nil {
		return ProcessMeta{}, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	meta, ok := c.entries[pid]
	if !ok {
		return ProcessMeta{}, false
	}
	if now.Sub(meta.FetchedAt) > ProcessMetaCacheTTL {
		delete(c.entries, pid)
		return ProcessMeta{}, false
	}
	return meta, true
}

func (c *ProcessMetaCache) Set(pid int, meta ProcessMeta) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[pid] = meta
}

var ProcMetaCache = NewProcessMetaCache()
