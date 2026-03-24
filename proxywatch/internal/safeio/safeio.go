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
