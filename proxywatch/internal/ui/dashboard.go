package ui

import (
	"fmt"
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
		TruncateToWidth("Use UP/DOWN arrows | ENTER inspect | q quit", w),
	)

	if app.LastError != "" {
		PutString(s, 0, 3, TruncateToWidth("Status: "+app.LastError, w))
	}

	y := 5
	if len(app.Candidates) == 0 {
		PutString(s, 0, y, "no candidates matching filters")
		return
	}

	PutString(s, 0, y,
		fmt.Sprintf("%-1s %-10s %-6s %-22s %-26s %-7s %-11s",
			" ", "HOST", "PID", "NAME", "ROLE", "ACTIVE", "INT/EXT/LO"),
	)
	y++
	PutString(s, 0, y,
		fmt.Sprintf("%-1s %-10s %-6s %-22s %-26s %-7s %-11s",
			" ", "----------", "-----", "----------------------", "--------------------------", "------", "-----------"),
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
		host = shared.TrimName(host, 10)
		udpInt, udpExt, udpLo := shared.UDPScopeCounts(c.UDPListeners)
		intExt := fmt.Sprintf("%d/%d/%d",
			c.OutInternal+udpInt,
			c.OutExternal+udpExt,
			c.OutLoopback+udpLo,
		)

		line := fmt.Sprintf("%-1s %-10s %-6d %-22s %-26s %-7v %-11s",
			arrow,
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
