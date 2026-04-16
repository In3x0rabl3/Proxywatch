package safeio

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestUserHomeDir_FromHOMEEnv(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	// On Windows, os.UserHomeDir uses USERPROFILE first; set it as well.
	t.Setenv("USERPROFILE", tmp)
	got := UserHomeDir()
	if got != tmp {
		t.Errorf("UserHomeDir() = %q, want %q", got, tmp)
	}
}

func TestProxywatchDataRoot_JoinsHome(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("USERPROFILE", tmp)
	got := ProxywatchDataRoot()
	want := filepath.Join(tmp, ".proxywatch")
	if got != want {
		t.Errorf("ProxywatchDataRoot() = %q, want %q", got, want)
	}
}

func TestExpandHomePath(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("USERPROFILE", tmp)

	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"~", tmp},
		{"~/foo/bar", filepath.Join(tmp, "foo/bar")},
		{"/abs/path", "/abs/path"},
		{"relative/path", "relative/path"},
		// A leading ~ followed by something other than / or \ is left alone.
		{"~user/foo", "~user/foo"},
	}
	for _, tc := range cases {
		if got := ExpandHomePath(tc.in); got != tc.want {
			t.Errorf("ExpandHomePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSanitizeRelativePath(t *testing.T) {
	sep := string(filepath.Separator)
	cases := []struct {
		in       string
		fallback string
		want     string
	}{
		// Empty / whitespace → fallback.
		{"", "fb", "fb"},
		{"   ", "fb", "fb"},
		{".", "fb", "fb"},
		// Regular relative path stays.
		{"a/b", "fb", filepath.Clean("a/b")},
		// Strip leading "./".
		{"./a/b", "fb", filepath.Clean("a/b")},
		// Strip leading ".proxywatch/".
		{".proxywatch" + sep + "x", "fb", "x"},
		// Strip leading path separator.
		{sep + "abs-looking", "fb", "abs-looking"},
		// Parent-traversal reduces to fallback.
		{"..", "fb", "fb"},
		{".." + sep + "escape", "fb", "escape"},
	}
	for _, tc := range cases {
		if got := SanitizeRelativePath(tc.in, tc.fallback); got != tc.want {
			t.Errorf("SanitizeRelativePath(%q, %q) = %q, want %q",
				tc.in, tc.fallback, got, tc.want)
		}
	}
}

func TestNormalizeJSONOutputPath(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("USERPROFILE", tmp)
	base := filepath.Join(tmp, "base")

	// Empty → defaultPath honored.
	if got := NormalizeJSONOutputPath("", "/abs/default.json", base); got != "/abs/default.json" {
		t.Errorf("empty path should use defaultPath, got %q", got)
	}

	// Relative path goes under baseDir.
	got := NormalizeJSONOutputPath("sub/out", "def.json", base)
	if !strings.HasPrefix(got, base+string(filepath.Separator)) {
		t.Errorf("relative path should be joined under baseDir: got %q", got)
	}
	if !strings.HasSuffix(strings.ToLower(got), ".json") {
		t.Errorf("missing .json suffix appended: %q", got)
	}

	// Absolute path preserved (plus .json if missing).
	abs := "/tmp/x"
	if runtime.GOOS == "windows" {
		abs = `C:\tmp\x`
	}
	got2 := NormalizeJSONOutputPath(abs, "def.json", base)
	if !strings.HasSuffix(strings.ToLower(got2), ".json") {
		t.Errorf("absolute path missing .json suffix: %q", got2)
	}

	// ~-prefixed path expanded.
	got3 := NormalizeJSONOutputPath("~/result", "def.json", base)
	if !strings.HasPrefix(got3, tmp) {
		t.Errorf("~ should be expanded; got %q (home=%q)", got3, tmp)
	}

	// Already-.json input keeps its name.
	got4 := NormalizeJSONOutputPath("already.json", "def.json", base)
	if !strings.HasSuffix(got4, "already.json") {
		t.Errorf("already-.json path should be preserved: %q", got4)
	}
}

func TestReadFile_RoundTrip(t *testing.T) {
	// Smoke test ReadFile against the OpenRoot-based wrapper — writes a file,
	// reads it back via safeio.ReadFile.
	dir := t.TempDir()
	p := filepath.Join(dir, "hello.txt")
	payload := []byte("hello-safeio")
	if err := os.WriteFile(p, payload, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := ReadFile(p)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("ReadFile round-trip: got %q, want %q", got, payload)
	}
}

func TestReadFile_MissingFileErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := ReadFile(filepath.Join(dir, "nope.txt")); err == nil {
		t.Errorf("expected error reading missing file")
	}
}
