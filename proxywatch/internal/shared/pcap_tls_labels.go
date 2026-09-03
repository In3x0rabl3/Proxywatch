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

// PcapTLSLabelKind identifies what TLS attribute the label keys on:
// either a JA3 hash (32-hex MD5) or a SNI hostname. Both are derived
// from the TLS ClientHello and observable in pcap mode.
type PcapTLSLabelKind string

const (
	PcapTLSLabelKindJA3 PcapTLSLabelKind = "ja3"
	PcapTLSLabelKindSNI PcapTLSLabelKind = "sni"
)

// PcapTLSLabel is the operator's verdict for a TLS attribute observed
// across captures. Unlike PcapOperatorLabel (cluster-name-keyed; one
// network's labels don't cross to another), JA3 and SNI labels are
// portable: a JA3 hash that's malicious on one rig is equally
// malicious on every rig that sees the same fingerprint.
//
// Apply ordering (in pcap_label_apply.go):
//  1. cluster label (most specific, network-bound)
//  2. SNI label (specific hostname)
//  3. JA3 label (TLS fingerprint, may be shared across processes)
//
// The narrower label wins. Cluster=benign overrides JA3=malicious;
// SNI=malicious overrides JA3=benign.
type PcapTLSLabel struct {
	Kind    PcapTLSLabelKind `json:"kind"`    // "ja3" | "sni"
	Value   string           `json:"value"`   // JA3 hash or SNI hostname
	Verdict string           `json:"verdict"` // "benign" | "malicious"
	Reason  string           `json:"reason,omitempty"`
	Host    string           `json:"set_on_host,omitempty"`
	SetAt   time.Time        `json:"set_at"`
}

const (
	PcapTLSLabelBenignReason    = "pcap-tls-label:benign"
	PcapTLSLabelMaliciousReason = "pcap-tls-label:malicious"
)

var (
	pcapTLSLabelMu    sync.RWMutex
	pcapTLSLabelStore = map[string]PcapTLSLabel{} // key: "ja3:<hash>" or "sni:<host>"
	pcapTLSLabelInit  sync.Once
)

func tlsLabelKey(kind PcapTLSLabelKind, value string) string {
	return string(kind) + ":" + strings.ToLower(strings.TrimSpace(value))
}

// LookupPcapTLSLabel returns the operator's verdict for a TLS attribute
// (JA3 hash or SNI hostname), or nil if unset.
func LookupPcapTLSLabel(kind PcapTLSLabelKind, value string) *PcapTLSLabel {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	ensurePcapTLSLabelsLoaded()
	pcapTLSLabelMu.RLock()
	defer pcapTLSLabelMu.RUnlock()
	if label, ok := pcapTLSLabelStore[tlsLabelKey(kind, value)]; ok {
		cp := label
		return &cp
	}
	return nil
}

// SetPcapTLSLabel upserts a TLS verdict and persists to disk.
func SetPcapTLSLabel(kind PcapTLSLabelKind, value, verdict, reason string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("missing value")
	}
	if kind != PcapTLSLabelKindJA3 && kind != PcapTLSLabelKindSNI {
		return errors.New("kind must be 'ja3' or 'sni'")
	}
	if verdict != VerdictBenign && verdict != VerdictMalicious {
		return errors.New("verdict must be 'benign' or 'malicious'")
	}
	ensurePcapTLSLabelsLoaded()
	label := PcapTLSLabel{
		Kind:    kind,
		Value:   strings.ToLower(value),
		Verdict: verdict,
		Reason:  strings.TrimSpace(reason),
		Host:    DefaultHostID(""),
		SetAt:   time.Now().UTC(),
	}
	key := tlsLabelKey(kind, value)
	pcapTLSLabelMu.Lock()
	pcapTLSLabelStore[key] = label
	pcapTLSLabelMu.Unlock()
	return persistPcapTLSLabel(label)
}

// ClearPcapTLSLabel removes a verdict and deletes the on-disk file.
func ClearPcapTLSLabel(kind PcapTLSLabelKind, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("missing value")
	}
	ensurePcapTLSLabelsLoaded()
	key := tlsLabelKey(kind, value)
	pcapTLSLabelMu.Lock()
	delete(pcapTLSLabelStore, key)
	pcapTLSLabelMu.Unlock()
	path := pcapTLSLabelPath(key)
	err := os.Remove(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// ListPcapTLSLabels returns a sorted snapshot of all TLS labels.
func ListPcapTLSLabels() []PcapTLSLabel {
	ensurePcapTLSLabelsLoaded()
	pcapTLSLabelMu.RLock()
	out := make([]PcapTLSLabel, 0, len(pcapTLSLabelStore))
	for _, v := range pcapTLSLabelStore {
		out = append(out, v)
	}
	pcapTLSLabelMu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Verdict != out[j].Verdict {
			return out[i].Verdict < out[j].Verdict
		}
		return out[i].Value < out[j].Value
	})
	return out
}

// LoadPcapTLSLabels — call once at startup. Idempotent.
func LoadPcapTLSLabels() error {
	var loadErr error
	pcapTLSLabelInit.Do(func() {
		loadErr = loadPcapTLSLabelsFromDisk()
	})
	return loadErr
}

func ensurePcapTLSLabelsLoaded() { _ = LoadPcapTLSLabels() }

func loadPcapTLSLabelsFromDisk() error {
	root := pcapTLSLabelRoot()
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
		var label PcapTLSLabel
		if jerr := json.Unmarshal(data, &label); jerr != nil {
			return nil
		}
		if label.Value == "" ||
			(label.Kind != PcapTLSLabelKindJA3 && label.Kind != PcapTLSLabelKindSNI) ||
			(label.Verdict != VerdictBenign && label.Verdict != VerdictMalicious) {
			return nil
		}
		pcapTLSLabelMu.Lock()
		pcapTLSLabelStore[tlsLabelKey(label.Kind, label.Value)] = label
		pcapTLSLabelMu.Unlock()
		count++
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if count > 0 {
		LogInfo("pcap-tls-labels", "loaded %d TLS label(s) from %s", count, root)
	}
	return nil
}

func persistPcapTLSLabel(label PcapTLSLabel) error {
	key := tlsLabelKey(label.Kind, label.Value)
	path := pcapTLSLabelPath(key)
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

func pcapTLSLabelRoot() string {
	return filepath.Join(safeio.ProxywatchDataRoot(), "pcap_tls_labels")
}

func pcapTLSLabelPath(key string) string {
	h := pcapLabelFileHash(key)
	prefix := h
	if len(prefix) > 2 {
		prefix = prefix[:2]
	}
	return filepath.Join(pcapTLSLabelRoot(), prefix, h+".json")
}
