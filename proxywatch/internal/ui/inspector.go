package ui

import (
	"fmt"
	"strings"
	"time"

	"proxywatch/internal/shared"
)

func DrawInspector(app *shared.AppState) {
	s := app.Screen
	s.Clear()

	w, h := s.Size()
	nowUTC := time.Now().UTC()

	PutString(s, 0, 0,
		TruncateToWidth(fmt.Sprintf("UTC: %s", nowUTC.Format("2006-01-02 15:04:05")), w),
	)

	var cand *shared.Candidate
	for i := range app.Candidates {
		if shared.CandidateKey(app.Candidates[i]) == app.InspectKey {
			cand = &app.Candidates[i]
			break
		}
	}

	if cand == nil {
		PutString(s, 0, 2, "Process no longer present. Press ESC.")
		return
	}

	y := 2
	title := fmt.Sprintf(" %s (PID %d) ", cand.Proc.Name, cand.Proc.Pid)
	sep := strings.Repeat("─", MinInt(len(title), w))

	PutString(s, 0, y, sep)
	y++
	PutString(s, 0, y, TruncateToWidth(title, w))
	y++
	PutString(s, 0, y, sep)
	y += 2

	PutString(s, 0, y, fmt.Sprintf("Role:  %s", cand.Role))
	y++
	PutString(s, 0, y, fmt.Sprintf("Active: %v", cand.ActiveProxying))
	y++
	host := cand.Host
	if host == "" {
		host = "local"
	}
	PutString(s, 0, y, fmt.Sprintf("Host:  %s", host))
	y += 2

	user := cand.Proc.UserName
	if user == "" {
		user = "(unknown)"
	}
	PutString(s, 2, y, TruncateToWidth(fmt.Sprintf("User: %s", user), w-2))
	y++

	sessionName := cand.Proc.SessionName
	if sessionName == "" && cand.Proc.SessionID != 0 {
		sessionName = fmt.Sprintf("Session-%d", cand.Proc.SessionID)
	}
	if sessionName == "" {
		sessionName = "(unknown)"
	}
	PutString(s, 2, y, TruncateToWidth(fmt.Sprintf("Session: %s (%d)", sessionName, cand.Proc.SessionID), w-2))
	y++

	parentPID := "unknown"
	if cand.Proc.ParentPid > 0 {
		parentPID = fmt.Sprintf("%d", cand.Proc.ParentPid)
	}
	PutString(s, 2, y, fmt.Sprintf("Parent PID: %s", parentPID))
	y++

	path := cand.Proc.ExePath
	if path == "" {
		path = "(unknown)"
	}
	PutString(s, 2, y, TruncateToWidth(fmt.Sprintf("Path: %s", path), w-2))
	y++

	integrity := cand.Proc.Integrity
	if integrity == "" {
		integrity = "(unknown)"
	}
	PutString(s, 2, y, fmt.Sprintf("Integrity: %s", integrity))
	y += 2

	established := 0
	for _, cn := range cand.Conns {
		if cn.State == "ESTABLISHED" {
			established++
		}
	}

	tcpInbound := cand.InboundTotal
	tcpOutbound := cand.OutTotal
	tcpListeners := len(cand.Listeners)
	udpListeners := len(cand.UDPListeners)
	udpInbound := 0
	udpOutbound := 0
	udpEstablished := 0

	PutString(s, 2, y, fmt.Sprintf("%-5s %-8s %-11s %-9s", "Proto", "In/Out", "Established", "Listeners"))
	y++
	PutString(s, 2, y, fmt.Sprintf("%-5s %-8s %-11s %-9s", "-----", "------", "-----------", "---------"))
	y++
	PutString(s, 2, y, fmt.Sprintf("%-5s %-8s %-11d %-9d", "TCP", fmt.Sprintf("%d/%d", tcpInbound, tcpOutbound), established, tcpListeners))
	y++
	PutString(s, 2, y, fmt.Sprintf("%-5s %-8s %-11d %-9d", "UDP", fmt.Sprintf("%d/%d", udpInbound, udpOutbound), udpEstablished, udpListeners))
	y++
	y++
	y++
	PutString(s, 2, y,
		TruncateToWidth(
			fmt.Sprintf(
				"IO bytes: %s",
				FormatIOBytes(cand.Proc.IOReadBytes, cand.Proc.IOWriteBytes, cand.Proc.IOOtherBytes),
			),
			w-2,
		),
	)
	y++
	PutString(s, 2, y,
		TruncateToWidth(
			fmt.Sprintf(
				"IO rate:  %s",
				FormatIORate(cand.Proc.IOReadBps, cand.Proc.IOWriteBps, cand.Proc.IOOtherBps),
			),
			w-2,
		),
	)
	y++
	y++

	if (len(cand.Conns) > 0 || len(cand.UDPListeners) > 0) && y < h-3 {
		PutString(s, 2, y, "Proto Local                 Remote                State        Scope")
		y++
		PutString(s, 2, y, "----- --------------------  --------------------  -----------  -------")
		y++

		seen := make(map[string]struct{})

		for _, cn := range cand.Conns {
			if y >= h-2 {
				break
			}

			scope := ""
			if cn.RemoteAddress != "" &&
				!shared.IsWildcardIP(cn.RemoteAddress) &&
				!shared.IsLoopbackIP(cn.RemoteAddress) {

				if shared.IsInternalIP(cn.RemoteAddress) {
					scope = "internal"
				} else {
					scope = "external"
				}
			}

			l := fmt.Sprintf("%s:%d", cn.LocalAddress, cn.LocalPort)
			r := fmt.Sprintf("%s:%d", cn.RemoteAddress, cn.RemotePort)
			key := fmt.Sprintf("tcp|%s|%s|%s|%s", l, r, cn.State, scope)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}

			line := fmt.Sprintf("%-5s %-20s %-20s %-11s %-7s", "TCP", l, r, cn.State, scope)
			PutString(s, 2, y, TruncateToWidth(line, w-2))
			y++
		}

		for _, ul := range cand.UDPListeners {
			if y >= h-2 {
				break
			}

			l := fmt.Sprintf("%s:%d", ul.LocalAddress, ul.LocalPort)
			r := "*:*"
			scope := shared.ScopeLabelForLocalAddress(ul.LocalAddress)
			key := fmt.Sprintf("udp|%s|%s|%s", l, r, scope)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			line := fmt.Sprintf("%-5s %-20s %-20s %-11s %-7s", "UDP", l, r, "LISTEN", scope)
			PutString(s, 2, y, TruncateToWidth(line, w-2))
			y++
		}
	}

	if app.LastError != "" && h >= 2 {
		PutString(s, 0, h-2, TruncateToWidth("Status: "+app.LastError, w))
	}

	if app.ConfirmKill && app.ConfirmKillKey == app.InspectKey && time.Now().Before(app.ConfirmKillDeadline) && h >= 2 {
		msg := fmt.Sprintf(
			"Confirm kill %s (%s): press k again or y within %s",
			app.InspectKey,
			cand.Proc.Name,
			app.ConfirmKillTimeout,
		)
		PutString(s, 0, h-2, TruncateToWidth(msg, w))
	}

	PutString(s, 0, h-1, "ESC return | k kill | q quit")
}
