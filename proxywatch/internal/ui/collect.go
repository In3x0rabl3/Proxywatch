package ui

import (
	"fmt"
	"time"

	"proxywatch/internal/shared"
)

func DrawCollect(app *shared.AppState) {
	s := app.Screen
	s.Clear()

	w, _ := s.Size()
	nowUTC := time.Now().UTC()

	PutString(s, 0, 0,
		TruncateToWidth(fmt.Sprintf("UTC: %s", nowUTC.Format("2006-01-02 15:04:05")), w),
	)

	PutString(s, 0, 2,
		TruncateToWidth("Collection | TAB switch | ENTER start/stop | ESC back | q quit", w),
	)

	if app.LastError != "" {
		PutString(s, 0, 3, TruncateToWidth("Status: "+app.LastError, w))
	}

	y := 5
	fields := []struct {
		label string
		value string
	}{
		{"Output", app.CollectOutput},
		{"Duration", app.CollectDurationStr},
		{"Roles", app.CollectRoles},
	}

	for i, f := range fields {
		prefix := " "
		if i == app.CollectField {
			prefix = ">"
		}
		line := fmt.Sprintf("%s %-9s: %s", prefix, f.label, f.value)
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
