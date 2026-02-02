package ui

import (
	"fmt"

	"proxywatch/internal/shared"
)

func DrawWhitelist(app *shared.AppState) {
	s := app.Screen
	s.Clear()

	w, _ := s.Size()
	drawHeader(s, w,
		"Whitelist manager | UP/DOWN select | d remove | ESC back | q quit",
		app.LastError,
	)

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
