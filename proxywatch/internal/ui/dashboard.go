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
	drawHeader(s, w,
		"Use UP/DOWN arrows | ENTER inspect | c collect | w whitelist | W manage whitelist | q quit",
		status,
	)

	y := 5
	if len(app.Candidates) == 0 {
		PutString(s, 0, y, "no candidates matching filters")
		return
	}

	hostWidth := len("HOST")
	pidWidth := len("PID")
	nameWidth := len("NAME")
	roleWidth := len("ROLE")
	intExtWidth := len("INT/EXT/LO")

	for i := range app.Candidates {
		host := app.Candidates[i].Host
		if host == "" {
			host = "local"
		}
		if len(host) > hostWidth {
			hostWidth = len(host)
		}
		pidLen := len(fmt.Sprintf("%d", app.Candidates[i].Proc.Pid))
		if pidLen > pidWidth {
			pidWidth = pidLen
		}
		n := shared.TrimName(app.Candidates[i].Proc.Name, 40)
		if len(n) > nameWidth {
			nameWidth = len(n)
		}
		if len(app.Candidates[i].Role) > roleWidth {
			roleWidth = len(app.Candidates[i].Role)
		}
		udpInt, udpExt, udpLo := shared.UDPScopeCounts(app.Candidates[i].UDPListeners)
		intExt := fmt.Sprintf("%d/%d/%d",
			app.Candidates[i].OutInternal+udpInt,
			app.Candidates[i].OutExternal+udpExt,
			app.Candidates[i].OutLoopback+udpLo,
		)
		if len(intExt) > intExtWidth {
			intExtWidth = len(intExt)
		}
	}

	// Cap excessively wide columns to keep UI readable.
	if nameWidth > 32 {
		nameWidth = 32
	}
	if roleWidth < len("ROLE") {
		roleWidth = len("ROLE")
	}

	headerFmt := fmt.Sprintf("%%-1s %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds",
		hostWidth, pidWidth, nameWidth, roleWidth, len("ACTIVE"), intExtWidth)

	PutString(s, 0, y, fmt.Sprintf(headerFmt,
		" ", "HOST", "PID", "NAME", "ROLE", "ACTIVE", "INT/EXT/LO"))
	y++
	PutString(s, 0, y, fmt.Sprintf(headerFmt,
		" ",
		strings.Repeat("-", hostWidth),
		strings.Repeat("-", pidWidth),
		strings.Repeat("-", nameWidth),
		strings.Repeat("-", roleWidth),
		"------",
		strings.Repeat("-", intExtWidth),
	))
	y++

	for i, c := range app.Candidates {
		arrow := " "
		if i == app.SelectedIdx {
			arrow = ">"
		}

		name := shared.TrimName(c.Proc.Name, nameWidth)
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

		line := fmt.Sprintf(headerFmt,
			arrow,
			host,
			fmt.Sprintf("%d", c.Proc.Pid),
			name,
			c.Role,
			fmt.Sprintf("%v", c.ActiveProxying),
			intExt,
		)

		PutString(s, 0, y, TruncateToWidth(line, w))
		y++
	}
}
