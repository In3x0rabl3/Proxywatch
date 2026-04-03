package shared

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"proxywatch/internal/keystore"
	"proxywatch/internal/safeio"
)

type Whitelist struct {
	mu      sync.RWMutex
	Entries map[string]bool
	Path    string
}

func DefaultWhitelistPath() string {
	return filepath.Join(safeio.ProxywatchDataRoot(), "whitelist.json")
}

func legacyWhitelistPath() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return ""
	}
	return filepath.Join(dir, "proxywatch", "whitelist.json")
}

func normalizeWhitelistPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		path = DefaultWhitelistPath()
	}
	path = safeio.ExpandHomePath(path)
	if filepath.IsAbs(path) {
		return path
	}
	rel := safeio.SanitizeRelativePath(path, "whitelist.json")
	return filepath.Join(safeio.ProxywatchDataRoot(), rel)
}

func LoadWhitelist(path string) (*Whitelist, error) {
	inputPath := strings.TrimSpace(path)
	path = normalizeWhitelistPath(path)
	if path == "" {
		path = DefaultWhitelistPath()
	}
	w := &Whitelist{
		Entries: make(map[string]bool),
		Path:    path,
	}

	data, err := safeio.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Backward compatibility: migrate old config location on first write.
			if inputPath == "" {
				legacy := legacyWhitelistPath()
				if legacy != "" && legacy != path {
					if legacyData, legacyErr := safeio.ReadFile(legacy); legacyErr == nil {
						data = legacyData
						err = nil
					} else if !errors.Is(legacyErr, os.ErrNotExist) {
						return nil, legacyErr
					} else {
						return w, nil
					}
				} else {
					return w, nil
				}
			} else {
				return w, nil
			}
		} else {
			return nil, err
		}
	}

	items, err := decodeWhitelistEntries(data)
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		if !isValidWhitelistEntry(item) {
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
		if err := os.MkdirAll(dir, 0o700); err != nil {
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
	vaultKey := "whitelist"
	if idx := strings.Index(path, ".proxywatch/"); idx >= 0 {
		vaultKey = path[idx+len(".proxywatch/"):]
	}
	return keystore.VaultWrite(vaultKey, data, path)
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
	if !isValidWhitelistEntry(key) {
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

func decodeWhitelistEntries(data []byte) ([]string, error) {
	data = []byte(strings.TrimSpace(string(data)))
	if len(data) == 0 {
		return nil, nil
	}

	var list []string
	if err := json.Unmarshal(data, &list); err == nil {
		return normalizeEntryList(list), nil
	}

	var mapEntries map[string]bool
	if err := json.Unmarshal(data, &mapEntries); err == nil {
		out := make([]string, 0, len(mapEntries))
		for key, enabled := range mapEntries {
			if !enabled {
				continue
			}
			out = append(out, key)
		}
		return normalizeEntryList(out), nil
	}

	var obj struct {
		Entries []string `json:"entries"`
		Items   []string `json:"items"`
	}
	if err := json.Unmarshal(data, &obj); err == nil {
		combined := append([]string{}, obj.Entries...)
		combined = append(combined, obj.Items...)
		return normalizeEntryList(combined), nil
	}

	return nil, errors.New("invalid whitelist file format")
}

func normalizeEntryList(items []string) []string {
	out := make([]string, 0, len(items))
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func isValidWhitelistEntry(entry string) bool {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return false
	}
	parts := strings.SplitN(entry, "|", 2)
	if len(parts) != 2 {
		return false
	}
	host := strings.TrimSpace(parts[0])
	spec := strings.TrimSpace(parts[1])
	if host == "" || spec == "" {
		return false
	}
	return strings.HasPrefix(spec, "path:") || strings.HasPrefix(spec, "name:")
}
