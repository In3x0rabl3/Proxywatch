package output

import (
	"fmt"
	"path/filepath"
	"strings"

	"proxywatch/internal/shared"
)

// BuildYARARule emits a hash-pinned YARA rule for a single candidate. The
// rule identifies the exact binary by SHA256, with metadata describing the
// behavioral signals proxywatch observed. Returns an empty string when the
// candidate has no SHA256 yet — YARA cannot pin without a hash.
func BuildYARARule(c *shared.Candidate) string {
	if c == nil || c.Proc == nil {
		return ""
	}
	sha := strings.TrimSpace(c.Proc.SHA256)
	if sha == "" {
		return "// SHA256 not computed yet — rule cannot be generated.\n// Re-open this tab after the async hasher catches up."
	}

	base := strings.TrimSpace(c.Proc.Name)
	if base == "" && c.Proc.ExePath != "" {
		base = filepath.Base(c.Proc.ExePath)
	}
	if base == "" {
		base = "proxywatch_candidate"
	}
	ruleName := "proxywatch_" + sanitizeYARAIdent(base) + "_" + shortHash(sha)

	var b strings.Builder
	b.WriteString("import \"hash\"\n\n")
	b.WriteString("rule ")
	b.WriteString(ruleName)
	b.WriteString(" {\n")
	b.WriteString("  meta:\n")
	b.WriteString(fmt.Sprintf("    author = %q\n", "proxywatch"))
	b.WriteString(fmt.Sprintf("    description = %q\n", "Hash-pinned rule for observed "+c.Role+" candidate"))
	b.WriteString(fmt.Sprintf("    role = %q\n", c.Role))
	if c.ControlSubtype != "" {
		b.WriteString(fmt.Sprintf("    control_subtype = %q\n", c.ControlSubtype))
	}
	b.WriteString(fmt.Sprintf("    sha256 = %q\n", sha))
	b.WriteString(fmt.Sprintf("    process_name = %q\n", base))
	if c.Proc.ExePath != "" {
		b.WriteString(fmt.Sprintf("    exe_path = %q\n", c.Proc.ExePath))
	}
	topSig := topN(c.Signals, 5)
	for i, s := range topSig {
		b.WriteString(fmt.Sprintf("    signal_%d = %q\n", i+1, s))
	}
	if c.BeaconIntervalMs > 0 {
		b.WriteString(fmt.Sprintf("    beacon_interval_ms = \"%d\"\n", c.BeaconIntervalMs))
	}
	b.WriteString("  condition:\n")
	b.WriteString("    hash.sha256(0, filesize) == \"")
	b.WriteString(strings.ToLower(sha))
	b.WriteString("\"\n}\n")
	return b.String()
}

func sanitizeYARAIdent(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		return "candidate"
	}
	if out[0] >= '0' && out[0] <= '9' {
		return "p_" + out
	}
	return out
}

func shortHash(sha string) string {
	sha = strings.TrimSpace(strings.ToLower(sha))
	if len(sha) >= 12 {
		return sha[:12]
	}
	return sha
}

func topN(xs []string, n int) []string {
	if len(xs) <= n {
		return xs
	}
	return xs[:n]
}
