package gbdt

import (
	"encoding/json"
	"os"
	"path/filepath"

	"proxywatch/internal/detection/features"
)

// ModelJSON is the on-disk format consumed by inference/native.go.
// It must serialize to the exact JSON structure expected by inference.LoadNative.
type ModelJSON struct {
	Format      string     `json:"format"`
	NumClasses  int        `json:"num_classes"`
	NumFeatures int        `json:"num_features"`
	NumTrees    int        `json:"num_trees"`
	RoleClasses []string   `json:"role_classes"`
	Trees       []TreeJSON `json:"trees"`
}

// TreeJSON is one tree in the JSON model.
type TreeJSON struct {
	Class int        `json:"class"`
	Nodes []TreeNode `json:"nodes"`
}

// Export serialises a trained ensemble to the proxywatch-lgbm-v1 JSON format.
// The output file is loadable by inference.LoadNative().
func Export(ensemble *Ensemble, path string) error {
	if ensemble == nil || len(ensemble.Trees) == 0 {
		return &TrainingError{Kind: ErrExport, Op: "export", Detail: "no trees in ensemble"}
	}

	m := ModelJSON{
		Format:      "proxywatch-lgbm-v1",
		NumClasses:  ensemble.NumClasses,
		NumFeatures: features.MaxFeatures,
		NumTrees:    len(ensemble.Trees),
		RoleClasses: ensemble.RoleClasses,
	}

	for i := range ensemble.Trees {
		t := &ensemble.Trees[i]
		m.Trees = append(m.Trees, TreeJSON{
			Class: t.ClassIdx,
			Nodes: t.Nodes,
		})
	}

	data, err := json.Marshal(m)
	if err != nil {
		return &TrainingError{Kind: ErrExport, Op: "export", Detail: "marshal JSON", Wrapped: err}
	}

	// Ensure parent directory exists.
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return &TrainingError{Kind: ErrExport, Op: "export", Detail: "create directory", Wrapped: err}
		}
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return &TrainingError{Kind: ErrExport, Op: "export", Detail: "write file", Wrapped: err}
	}

	return nil
}
