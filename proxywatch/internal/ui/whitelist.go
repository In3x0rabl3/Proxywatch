package ui

import (
	"fmt"
	"time"

	"proxywatch/internal/shared"
)

func DrawWhitelist(app *shared.AppState) {
	s := app.Screen
	s.Clear()

	w, _ := s.Size()
	nowUTC := time.Now().UTC()

	PutString(s, 0, 0,
		TruncateToWidth(fmt.Sprintf("UTC: %s", nowUTC.Format("2006-01-02 15:04:05")), w),
	)

	PutString(s, 0, 2,
		TruncateToWidth("Whitelist manager | UP/DOWN select | d remove | ESC back | q quit", w),
	)

	if app.LastError != "" {
		PutString(s, 0, 3, TruncateToWidth("Status: "+app.LastError, w))
	}

	y := 5
	if len(app.WhitelistItems) == 0 {
		PutString(s, 0, y, "whitelist is empty")
		return
	}

	for i, entry := range app.WhitelistItems {
		arrow := " "
		if i == app.WhitelistSelected {
			arrow = ">"
		}
		line := fmt.Sprintf("%s %s", arrow, entry)
		PutString(s, 0, y, TruncateToWidth(line, w))
		y++
	}
}
