package safeio

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func ReadFile(path string) ([]byte, error) {
	root, name, err := openPathRoot(path)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.ReadFile(name)
}

func Open(path string) (*os.File, func() error, error) {
	root, name, err := openPathRoot(path)
	if err != nil {
		return nil, nil, err
	}
	f, err := root.Open(name)
	if err != nil {
		_ = root.Close()
		return nil, nil, err
	}
	return f, func() error {
		var out error
		if err := f.Close(); err != nil {
			out = err
		}
		if err := root.Close(); err != nil {
			if out != nil {
				return errors.Join(out, err)
			}
			return err
		}
		return out
	}, nil
}

func OpenFile(path string, flag int, perm os.FileMode) (*os.File, func() error, error) {
	root, name, err := openPathRoot(path)
	if err != nil {
		return nil, nil, err
	}
	f, err := root.OpenFile(name, flag, perm)
	if err != nil {
		_ = root.Close()
		return nil, nil, err
	}
	return f, func() error {
		var out error
		if err := f.Close(); err != nil {
			out = err
		}
		if err := root.Close(); err != nil {
			if out != nil {
				return errors.Join(out, err)
			}
			return err
		}
		return out
	}, nil
}

// ProxywatchDataRoot returns the path to the .proxywatch data directory
// under the user's home directory, falling back to a relative path.
func ProxywatchDataRoot() string {
	home := UserHomeDir()
	if home == "" {
		return ".proxywatch"
	}
	return filepath.Join(home, ".proxywatch")
}

// UserHomeDir returns the current user's home directory using os.UserHomeDir
// with fallbacks to common environment variables.
func UserHomeDir() string {
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		return strings.TrimSpace(home)
	}
	for _, key := range []string{"HOME", "USERPROFILE"} {
		if val := strings.TrimSpace(os.Getenv(key)); val != "" {
			return val
		}
	}
	drive := strings.TrimSpace(os.Getenv("HOMEDRIVE"))
	path := strings.TrimSpace(os.Getenv("HOMEPATH"))
	if drive != "" && path != "" {
		return drive + path
	}
	return ""
}

// ExpandHomePath replaces a leading ~ with the user's home directory.
func ExpandHomePath(path string) string {
	if path == "" || path[0] != '~' {
		return path
	}
	home := UserHomeDir()
	if home == "" {
		return path
	}
	if path == "~" {
		return home
	}
	if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, "~\\") {
		return filepath.Join(home, path[2:])
	}
	return path
}

// SanitizeRelativePath cleans a relative path, strips leading dot, .proxywatch,
// and parent traversal segments, and returns fallback if the result is empty or unsafe.
func SanitizeRelativePath(path, fallback string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return fallback
	}
	path = filepath.Clean(path)
	if path == "." || path == "" {
		return fallback
	}
	if strings.HasPrefix(path, ".proxywatch"+string(filepath.Separator)) {
		path = strings.TrimPrefix(path, ".proxywatch"+string(filepath.Separator))
	}
	for strings.HasPrefix(path, "."+string(filepath.Separator)) {
		path = strings.TrimPrefix(path, "."+string(filepath.Separator))
	}
	path = strings.TrimLeft(path, string(filepath.Separator))
	parentPrefix := ".." + string(filepath.Separator)
	for path == ".." || strings.HasPrefix(path, parentPrefix) {
		if path == ".." {
			return fallback
		}
		path = strings.TrimPrefix(path, parentPrefix)
	}
	if path == "" || path == "." {
		return fallback
	}
	return path
}

func openPathRoot(path string) (*os.Root, string, error) {
	clean := filepath.Clean(strings.TrimSpace(path))
	if clean == "" || clean == "." || clean == string(filepath.Separator) {
		return nil, "", errors.New("invalid path")
	}
	dir := filepath.Dir(clean)
	name := filepath.Base(clean)
	if strings.TrimSpace(name) == "" || name == "." || name == string(filepath.Separator) {
		return nil, "", errors.New("invalid file name")
	}
	if strings.TrimSpace(dir) == "" {
		dir = "."
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, "", err
	}
	return root, name, nil
}

// NormalizeJSONOutputPath normalizes a JSON output file path.
// defaultPath is used when path is empty. baseDir is the parent for relative paths.
func NormalizeJSONOutputPath(path, defaultPath, baseDir string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		path = defaultPath
	}
	path = ExpandHomePath(path)
	if filepath.IsAbs(path) {
		path = filepath.Clean(path)
	} else {
		path = filepath.Join(baseDir, SanitizeRelativePath(path, "latest.json"))
	}
	if !strings.HasSuffix(strings.ToLower(path), ".json") {
		path += ".json"
	}
	return path
}
