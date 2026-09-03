package shared

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"proxywatch/internal/safeio"
)

// PcapOperatorLabel is the human verdict for a PCAP-mode cluster
// identified by its synthetic cluster name (e.g.
// "pcap:172.16.1.81 → 104.21.0.0/16:443"). PCAP analysis has no
// process metadata so SHA256-keyed operator labels (the live-mode
// primitive) don't apply — but cluster names ARE stable across cycles
// and across re-analyses of the same network because they're derived
// from topology (host IP + /16 prefix + port). That makes them a
// good operator-label key.
//
// An operator setting verdict=benign on a cluster means "I've reviewed
// this destination and it's legitimate; don't flag it as beacon-*
// regardless of signals." malicious = "I've confirmed this is C2 /
// implant / pivot relay; preserve any beacon-* role assignment AND
// boost the training weight."
type PcapOperatorLabel struct {
	ClusterName string    `json:"cluster_name"`
	Verdict     string    `json:"verdict"` // "benign" | "malicious"
	Reason      string    `json:"reason,omitempty"`
	Host        string    `json:"set_on_host,omitempty"`
	SetAt       time.Time `json:"set_at"`
}

// Sentinel reasons appended to c.Reasons when a pcap operator label
// fires. Mirror the live-mode OperatorLabel*Reason constants.
const (
	PcapOperatorLabelBenignReason    = "pcap-operator-label:benign"
	PcapOperatorLabelMaliciousReason = "pcap-operator-label:malicious"
)

var (
	pcapLabelMu    sync.RWMutex
	pcapLabelStore = map[string]PcapOperatorLabel{}
	pcapLabelInit  sync.Once
)

// LookupPcapOperatorLabel returns the operator's verdict for this
// cluster name, or nil if unset. Safe for concurrent use.
func LookupPcapOperatorLabel(clusterName string) *PcapOperatorLabel {
	clusterName = strings.TrimSpace(clusterName)
	if clusterName == "" {
		return nil
	}
	ensurePcapOperatorLabelsLoaded()
	pcapLabelMu.RLock()
	defer pcapLabelMu.RUnlock()
	if label, ok := pcapLabelStore[clusterName]; ok {
		cp := label
		return &cp
	}
	return nil
}

// SetPcapOperatorLabel upserts a verdict for a cluster and persists
// to disk. The host field is filled from DefaultHostID so the operator
// can see which analyzer applied the label.
func SetPcapOperatorLabel(clusterName, verdict, reason string) error {
	clusterName = strings.TrimSpace(clusterName)
	if clusterName == "" {
		return errors.New("missing cluster_name")
	}
	if verdict != VerdictBenign && verdict != VerdictMalicious {
		return errors.New("verdict must be 'benign' or 'malicious'")
	}
	ensurePcapOperatorLabelsLoaded()
	label := PcapOperatorLabel{
		ClusterName: clusterName,
		Verdict:     verdict,
		Reason:      strings.TrimSpace(reason),
		Host:        DefaultHostID(""),
		SetAt:       time.Now().UTC(),
	}
	pcapLabelMu.Lock()
	pcapLabelStore[clusterName] = label
	pcapLabelMu.Unlock()
	return persistPcapOperatorLabel(label)
}

// ClearPcapOperatorLabel removes a verdict and deletes the on-disk
// file. Returns nil when the label didn't exist (idempotent).
func ClearPcapOperatorLabel(clusterName string) error {
	clusterName = strings.TrimSpace(clusterName)
	if clusterName == "" {
		return errors.New("missing cluster_name")
	}
	ensurePcapOperatorLabelsLoaded()
	pcapLabelMu.Lock()
	delete(pcapLabelStore, clusterName)
	pcapLabelMu.Unlock()
	path := pcapOperatorLabelPath(clusterName)
	err := os.Remove(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// LoadPcapOperatorLabels is invoked from main.go at startup. Safe to
// call multiple times; subsequent calls are no-ops.
func LoadPcapOperatorLabels() error {
	var loadErr error
	pcapLabelInit.Do(func() {
		loadErr = loadPcapOperatorLabelsFromDisk()
	})
	return loadErr
}

func ensurePcapOperatorLabelsLoaded() {
	_ = LoadPcapOperatorLabels()
}

func loadPcapOperatorLabelsFromDisk() error {
	root := pcapOperatorLabelRoot()
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
		var label PcapOperatorLabel
		if jerr := json.Unmarshal(data, &label); jerr != nil {
			return nil
		}
		if label.ClusterName == "" || (label.Verdict != VerdictBenign && label.Verdict != VerdictMalicious) {
			return nil
		}
		pcapLabelMu.Lock()
		pcapLabelStore[label.ClusterName] = label
		pcapLabelMu.Unlock()
		count++
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if count > 0 {
		LogInfo("pcap-operator-labels", "loaded %d label(s) from %s", count, root)
	}
	return nil
}

func persistPcapOperatorLabel(label PcapOperatorLabel) error {
	path := pcapOperatorLabelPath(label.ClusterName)
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

func pcapOperatorLabelRoot() string {
	return filepath.Join(safeio.ProxywatchDataRoot(), "pcap_operator_labels")
}

// pcapOperatorLabelPath produces a filesystem-safe path from the
// cluster name. The cluster name contains characters (spaces, "→",
// "/", ":") that would create weird directory layouts or collide
// across OSes — hash + first-2-byte sharding is the same scheme the
// SHA256 store uses, just keyed on the cluster name.
func pcapOperatorLabelPath(clusterName string) string {
	h := pcapLabelFileHash(clusterName)
	prefix := h
	if len(prefix) > 2 {
		prefix = prefix[:2]
	}
	return filepath.Join(pcapOperatorLabelRoot(), prefix, h+".json")
}

// pcapLabelFileHash deterministically produces a 16-hex-char filename
// fragment for a cluster name. FNV-1a is enough — we only need
// uniqueness within an operator's small set of labeled clusters
// (typically dozens, not millions), and the file content carries the
// canonical cluster_name so a hash collision would still be readable
// at load time.
func pcapLabelFileHash(s string) string {
	const (
		offset uint64 = 14695981039346656037
		prime  uint64 = 1099511628211
	)
	h := offset
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= prime
	}
	const hexDigits = "0123456789abcdef"
	b := make([]byte, 16)
	for i := 0; i < 16; i++ {
		b[15-i] = hexDigits[h&0xf]
		h >>= 4
	}
	return string(b)
}
