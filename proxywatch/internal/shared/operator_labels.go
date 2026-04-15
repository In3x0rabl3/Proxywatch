package shared

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"proxywatch/internal/safeio"
)

// OperatorLabel is the authoritative human verdict for a specific binary
// identified by its SHA256 hash. Labels ship across hosts: the same
// binary content anywhere gets the same verdict. This is the Tier 1
// anti-spoof primitive — name, path, and cmdline are all ignored.
//
// An operator setting label=benign on a hash means "I've reviewed this
// binary and it's legitimate; don't flag it regardless of behavior."
// malicious = "I've confirmed this is C2/malware; preserve any control
// role detection and boost score."
type OperatorLabel struct {
	SHA256   string    `json:"sha256"`
	Verdict  string    `json:"verdict"` // "benign" | "malicious"
	Reason   string    `json:"reason,omitempty"`
	Host     string    `json:"set_on_host,omitempty"`
	Operator string    `json:"operator,omitempty"`
	SetAt    time.Time `json:"set_at"`
}

const (
	VerdictBenign    = "benign"
	VerdictMalicious = "malicious"
)

// Sentinel reasons appended to c.Reasons when operator label fires. The
// downstream filters and /fp-report key on these strings.
const (
	OperatorLabelBenignReason    = "operator-label:benign"
	OperatorLabelMaliciousReason = "operator-label:malicious"
)

var (
	opLabelMu    sync.RWMutex
	opLabelStore = map[string]OperatorLabel{}
	opLabelInit  sync.Once
)

// LookupOperatorLabel returns the operator's verdict for this hash, or
// nil if unset. Safe for concurrent use.
func LookupOperatorLabel(sha256 string) *OperatorLabel {
	sha256 = strings.TrimSpace(strings.ToLower(sha256))
	if sha256 == "" {
		return nil
	}
	ensureOperatorLabelsLoaded()
	opLabelMu.RLock()
	defer opLabelMu.RUnlock()
	if label, ok := opLabelStore[sha256]; ok {
		cp := label
		return &cp
	}
	return nil
}

// SetOperatorLabel upserts a verdict for a hash and persists to disk.
// The host field is filled from DefaultHostID so operators can see
// where a label was originally applied.
func SetOperatorLabel(sha256, verdict, reason string) error {
	sha256 = strings.TrimSpace(strings.ToLower(sha256))
	if sha256 == "" {
		return errors.New("missing sha256")
	}
	if verdict != VerdictBenign && verdict != VerdictMalicious {
		return errors.New("verdict must be 'benign' or 'malicious'")
	}
	ensureOperatorLabelsLoaded()
	label := OperatorLabel{
		SHA256:  sha256,
		Verdict: verdict,
		Reason:  strings.TrimSpace(reason),
		Host:    DefaultHostID(""),
		SetAt:   time.Now().UTC(),
	}
	opLabelMu.Lock()
	opLabelStore[sha256] = label
	opLabelMu.Unlock()
	return persistOperatorLabel(label)
}

// ClearOperatorLabel removes a verdict and deletes the on-disk file.
// Returns nil when the label didn't exist (idempotent).
func ClearOperatorLabel(sha256 string) error {
	sha256 = strings.TrimSpace(strings.ToLower(sha256))
	if sha256 == "" {
		return errors.New("missing sha256")
	}
	ensureOperatorLabelsLoaded()
	opLabelMu.Lock()
	delete(opLabelStore, sha256)
	opLabelMu.Unlock()
	path := operatorLabelPath(sha256)
	err := os.Remove(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// ListOperatorLabels returns a sorted snapshot of all labels.
func ListOperatorLabels() []OperatorLabel {
	ensureOperatorLabelsLoaded()
	opLabelMu.RLock()
	out := make([]OperatorLabel, 0, len(opLabelStore))
	for _, v := range opLabelStore {
		out = append(out, v)
	}
	opLabelMu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Verdict != out[j].Verdict {
			return out[i].Verdict < out[j].Verdict
		}
		return out[i].SHA256 < out[j].SHA256
	})
	return out
}

// LoadOperatorLabels is invoked from main.go at startup. Safe to call
// multiple times; subsequent calls are no-ops.
func LoadOperatorLabels() error {
	var loadErr error
	opLabelInit.Do(func() {
		loadErr = loadOperatorLabelsFromDisk()
	})
	return loadErr
}

func ensureOperatorLabelsLoaded() {
	_ = LoadOperatorLabels()
}

func loadOperatorLabelsFromDisk() error {
	root := operatorLabelRoot()
	count := 0
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
		var label OperatorLabel
		if jerr := json.Unmarshal(data, &label); jerr != nil {
			return nil
		}
		if label.SHA256 == "" || (label.Verdict != VerdictBenign && label.Verdict != VerdictMalicious) {
			return nil
		}
		opLabelMu.Lock()
		opLabelStore[label.SHA256] = label
		opLabelMu.Unlock()
		count++
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if count > 0 {
		LogInfo("operator-labels", "loaded %d label(s) from %s", count, root)
	}
	return nil
}

func persistOperatorLabel(label OperatorLabel) error {
	path := operatorLabelPath(label.SHA256)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(label, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func operatorLabelRoot() string {
	return filepath.Join(safeio.ProxywatchDataRoot(), "operator_labels")
}

func operatorLabelPath(sha256 string) string {
	prefix := sha256
	if len(prefix) > 2 {
		prefix = prefix[:2]
	}
	return filepath.Join(operatorLabelRoot(), prefix, sha256+".json")
}
