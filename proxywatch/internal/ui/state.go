package ui

import (
	"fmt"
	"strings"

	"proxywatch/internal/shared"

	"github.com/gdamore/tcell/v2"
)

/* ---------- helpers ---------- */

func PutString(s tcell.Screen, x, y int, text string) {
	for i, r := range text {
		s.SetContent(x+i, y, r, nil, tcell.StyleDefault)
	}
}

func FindIndexByKey(cands []shared.Candidate, key string) int {
	for i, c := range cands {
		if shared.CandidateKey(c) == key {
			return i
		}
	}
	return -1
}

func TruncateToWidth(s string, w int) string {
	if w <= 0 || len(s) <= w {
		return s
	}
	if w <= 3 {
		return s[:w]
	}
	return s[:w-3] + "..."
}

func MinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func FormatBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}

	div := uint64(unit)
	exp := 0
	for n >= div*unit && exp < 4 {
		div *= unit
		exp++
	}

	value := float64(n) / float64(div)
	suffixes := []string{"KB", "MB", "GB", "TB", "PB"}
	return fmt.Sprintf("%.1f %s", value, suffixes[exp])
}

func FormatBytesPerSec(n uint64) string {
	return FormatBytes(n) + "/s"
}

func FormatIOBytes(read, write, other uint64) string {
	return formatIOMetric(read, write, other, FormatBytes)
}

func FormatIORate(read, write, other uint64) string {
	return formatIOMetric(read, write, other, FormatBytesPerSec)
}

func formatIOMetric(read, write, other uint64, format func(uint64) string) string {
	total := read + write + other
	if total == 0 {
		return format(0)
	}

	parts := make([]string, 0, 3)
	if read > 0 {
		parts = append(parts, "R "+format(read))
	}
	if write > 0 {
		parts = append(parts, "W "+format(write))
	}
	if other > 0 {
		parts = append(parts, "O "+format(other))
	}

	totalStr := format(total)
	if len(parts) == 0 {
		return totalStr
	}
	if len(parts) == 1 {
		label := strings.Fields(parts[0])[0]
		return fmt.Sprintf("%s (%s)", totalStr, label)
	}
	return fmt.Sprintf("%s (%s)", totalStr, strings.Join(parts, " "))
}
