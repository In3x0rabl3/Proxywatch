package shared

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type Whitelist struct {
	mu      sync.RWMutex
	Entries map[string]bool
	Path    string
}

func DefaultWhitelistPath() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return "proxywatch_whitelist.json"
	}
	return filepath.Join(dir, "proxywatch", "whitelist.json")
}

func LoadWhitelist(path string) (*Whitelist, error) {
	if path == "" {
		path = DefaultWhitelistPath()
	}
	w := &Whitelist{
		Entries: make(map[string]bool),
		Path:    path,
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return w, nil
		}
		return nil, err
	}

	var items []string
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, err
	}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		w.Entries[item] = true
	}
	return w, nil
}

func (w *Whitelist) Save() error {
	if w == nil {
		return nil
	}
	path := w.Path
	if path == "" {
		path = DefaultWhitelistPath()
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	w.mu.RLock()
	items := make([]string, 0, len(w.Entries))
	for k := range w.Entries {
		items = append(items, k)
	}
	w.mu.RUnlock()
	sort.Strings(items)

	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func (w *Whitelist) IsWhitelisted(c Candidate) bool {
	if w == nil {
		return false
	}
	key := whitelistKey(c)
	if key == "" {
		return false
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.Entries[key]
}

func (w *Whitelist) AddCandidate(c Candidate) (string, error) {
	if w == nil {
		return "", errors.New("whitelist not configured")
	}
	key := whitelistKey(c)
	if key == "" {
		return "", errors.New("missing process identity")
	}
	w.mu.Lock()
	if w.Entries == nil {
		w.Entries = make(map[string]bool)
	}
	w.Entries[key] = true
	w.mu.Unlock()
	return key, w.Save()
}

func (w *Whitelist) Filter(cands []Candidate) []Candidate {
	if w == nil {
		return cands
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	if len(w.Entries) == 0 {
		return cands
	}
	out := make([]Candidate, 0, len(cands))
	for _, c := range cands {
		if !w.Entries[whitelistKey(c)] {
			out = append(out, c)
		}
	}
	return out
}

func (w *Whitelist) List() []string {
	if w == nil {
		return nil
	}
	w.mu.RLock()
	items := make([]string, 0, len(w.Entries))
	for k := range w.Entries {
		items = append(items, k)
	}
	w.mu.RUnlock()
	sort.Strings(items)
	return items
}

func (w *Whitelist) Remove(key string) error {
	if w == nil {
		return errors.New("whitelist not configured")
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return errors.New("invalid whitelist entry")
	}
	w.mu.Lock()
	if w.Entries != nil {
		delete(w.Entries, key)
	}
	w.mu.Unlock()
	return w.Save()
}

func whitelistKey(c Candidate) string {
	host := DisplayHost(c.Host)
	if c.Proc == nil {
		return ""
	}
	path := strings.TrimSpace(c.Proc.ExePath)
	if path != "" {
		return host + "|path:" + normalizePath(path)
	}
	name := strings.TrimSpace(c.Proc.Name)
	if name == "" {
		return ""
	}
	return host + "|name:" + strings.ToLower(name)
}

func normalizePath(p string) string {
	p = filepath.Clean(p)
	return strings.ToLower(p)
}
