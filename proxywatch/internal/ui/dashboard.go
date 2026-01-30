package ui

import (
	"fmt"
	"strings"
	"time"

	"proxywatch/internal/shared"
)

func DrawDashboard(app *shared.AppState) {
	s := app.Screen
	s.Clear()

	w, _ := s.Size()
	nowUTC := time.Now().UTC()

	PutString(s, 0, 0,
		TruncateToWidth(fmt.Sprintf("UTC: %s", nowUTC.Format("2006-01-02 15:04:05")), w),
	)

	PutString(s, 0, 2,
		TruncateToWidth("Use UP/DOWN arrows | ENTER inspect | c collect | w whitelist | W manage whitelist | q quit", w),
	)

	status := app.LastError
	if app.CollectActive {
		remaining := time.Until(app.CollectUntil).Round(time.Second)
		if remaining < 0 {
			remaining = 0
		}
		if status != "" {
			status += " | "
		}
		status += "Collecting (" + remaining.String() + " left)"
	}
	if status != "" {
		PutString(s, 0, 3, TruncateToWidth("Status: "+status, w))
	}

	y := 5
	if len(app.Candidates) == 0 {
		PutString(s, 0, y, "no candidates matching filters")
		return
	}

	hostWidth := len("HOST")
	for i := range app.Candidates {
		host := app.Candidates[i].Host
		if host == "" {
			host = "local"
		}
		if len(host) > hostWidth {
			hostWidth = len(host)
		}
	}

	PutString(s, 0, y,
		fmt.Sprintf("%-1s %-*s %-6s %-22s %-26s %-7s %-11s",
			" ", hostWidth, "HOST", "PID", "NAME", "ROLE", "ACTIVE", "INT/EXT/LO"),
	)
	y++
	PutString(s, 0, y,
		fmt.Sprintf("%-1s %-*s %-6s %-22s %-26s %-7s %-11s",
			" ",
			hostWidth,
			strings.Repeat("-", hostWidth),
			"-----",
			strings.Repeat("-", 22),
			strings.Repeat("-", 26),
			"------",
			"-----------"),
	)
	y++

	for i, c := range app.Candidates {
		arrow := " "
		if i == app.SelectedIdx {
			arrow = ">"
		}

		name := shared.TrimName(c.Proc.Name, 22)
		host := c.Host
		if host == "" {
			host = "local"
		}
		udpInt, udpExt, udpLo := shared.UDPScopeCounts(c.UDPListeners)
		intExt := fmt.Sprintf("%d/%d/%d",
			c.OutInternal+udpInt,
			c.OutExternal+udpExt,
			c.OutLoopback+udpLo,
		)

		line := fmt.Sprintf("%-1s %-*s %-6d %-22s %-26s %-7v %-11s",
			arrow,
			hostWidth,
			host,
			c.Proc.Pid,
			name,
			c.Role,
			c.ActiveProxying,
			intExt,
		)

		PutString(s, 0, y, TruncateToWidth(line, w))
		y++
	}
}
