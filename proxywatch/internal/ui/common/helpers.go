package common

import (
	"strings"
	"time"
)

func SpinnerFrame() string {
	frames := []string{"-", "\\", "|", "/"}
	return frames[int(time.Now().UnixNano()/int64(250*time.Millisecond))%len(frames)]
}

func SpinnerElapsed(start time.Time) time.Duration {
	if start.IsZero() {
		return 0
	}
	elapsed := time.Since(start).Round(time.Second)
	if elapsed < 0 {
		return 0
	}
	return elapsed
}

const CalibrationReportLabelWidth = 18

func WrapWords(text string, width int) []string {
	text = strings.TrimSpace(text)
	if text == "" {
		return []string{""}
	}
	if width < 1 {
		return []string{text}
	}
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{""}
	}
	lines := make([]string, 0, 4)
	current := ""
	for _, word := range words {
		for len(word) > width {
			if current != "" {
				lines = append(lines, current)
				current = ""
			}
			lines = append(lines, word[:width])
			word = word[width:]
		}
		if current == "" {
			current = word
			continue
		}
		if len(current)+1+len(word) <= width {
			current += " " + word
		} else {
			lines = append(lines, current)
			current = word
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}
