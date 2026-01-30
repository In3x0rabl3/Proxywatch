package ui

import (
	"fmt"
	"time"

	"proxywatch/internal/shared"
)

var collectDurations = []string{"30s", "1m", "2m", "5m", "10m", "15m"}

func DrawCollect(app *shared.AppState) {
	s := app.Screen
	s.Clear()

	w, _ := s.Size()
	nowUTC := time.Now().UTC()

	PutString(s, 0, 0,
		TruncateToWidth(fmt.Sprintf("UTC: %s", nowUTC.Format("2006-01-02 15:04:05")), w),
	)

	PutString(s, 0, 2,
		TruncateToWidth("Collection | UP/DOWN select | ENTER edit/start | LEFT/RIGHT time | ESC back | q quit", w),
	)

	if app.LastError != "" {
		PutString(s, 0, 3, TruncateToWidth("Status: "+app.LastError, w))
	}

	y := 5
	fields := []struct {
		label string
		value string
		edit  bool
	}{
		{"Output", app.CollectOutput, app.CollectEditing && app.CollectField == 0},
		{"Duration", app.CollectDurationStr, false},
		{"Roles", app.CollectRoles, app.CollectEditing && app.CollectField == 2},
		{"Start/Stop", "", false},
	}

	for i, f := range fields {
		prefix := " "
		if i == app.CollectField {
			prefix = ">"
		}
		value := f.value
		if f.label == "Start/Stop" {
			if app.CollectActive {
				value = "Stop"
			} else {
				value = "Start"
			}
		}
		edit := ""
		if f.edit {
			edit = " [edit]"
		}
		line := fmt.Sprintf("%s %-9s: %s%s", prefix, f.label, value, edit)
		PutString(s, 0, y, TruncateToWidth(line, w))
		y++
	}

	y++
	if app.CollectActive {
		remaining := time.Until(app.CollectUntil).Round(time.Second)
		if remaining < 0 {
			remaining = 0
		}
		PutString(s, 0, y, TruncateToWidth(fmt.Sprintf("Status: collecting (%s remaining)", remaining), w))
	} else {
		PutString(s, 0, y, TruncateToWidth("Status: idle", w))
	}
}

func stepDuration(current string, dir int) string {
	if len(collectDurations) == 0 {
		return current
	}
	index := 0
	for i, v := range collectDurations {
		if v == current {
			index = i
			break
		}
	}
	if dir > 0 {
		index = (index + 1) % len(collectDurations)
	} else if dir < 0 {
		index = (index - 1 + len(collectDurations)) % len(collectDurations)
	}
	return collectDurations[index]
}
