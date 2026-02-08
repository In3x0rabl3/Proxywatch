package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"proxywatch/internal/agent"
	"proxywatch/internal/classifier"
	"proxywatch/internal/shared"
	"proxywatch/internal/telemetry"
	"proxywatch/internal/ui"
)

/* ---------------- CLI helpers ---------------- */

func defaultUIRoleFilter() map[string]bool {
	return map[string]bool{
		"susp-session": true,
		"susp-beacon":  true,
		"susp-tun":     true,
	}
}

/* ---------------- main ---------------- */

func main() {
	roles := flag.String("roles", "", "Comma-separated list of roles to display (supports families: tunnel, session, beacon, listener, outbound)")
	interval := flag.Duration("interval", 250*time.Millisecond, "Refresh interval (e.g. 250ms, 1s)")
	incremental := flag.Bool("incremental", false, "Reuse classification for unchanged PIDs (faster, slightly less accurate)")
	listen := flag.String("listen", "", "Listen address for Proxywatch agent ingest (e.g. 0.0.0.0:50051)")
	staleAfter := flag.Duration("stale", 0, "Drop remote hosts after this duration without updates (0 = keep)")

	flag.Parse()

	roleFilter := shared.ParseRoleFilter(*roles)
	roleFilterSet := strings.TrimSpace(*roles) != ""
	minScore := 15

	// -------- interactive TUI --------
	app := &shared.AppState{
		RefreshInt:         *interval,
		ConfirmKill:        true,
		ConfirmKillTimeout: 3 * time.Second,
	}

	whitelist, err := shared.LoadWhitelist("")
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	app.Whitelist = whitelist

	app.CollectDurationStr = "5m"
	app.CollectRoles = "tunnel,session,beacon"
	app.CollectOutput = "proxywatch-collection.json"

	uiRoleFilter := roleFilter
	if !roleFilterSet {
		uiRoleFilter = defaultUIRoleFilter()
	}

	if *listen != "" {
		store := agent.NewStore()
		remoteSrv, grpcServer, lis, err := agent.ListenAndServe(*listen, store)
		if err != nil {
			fmt.Println("error:", err)
			os.Exit(1)
		}
		defer grpcServer.Stop()
		defer lis.Close()

		app.LocalHost = ""
		app.RemoteKill = func(host string, pid int) error {
			return remoteSrv.Kill(host, pid)
		}
		sc := &agent.RemoteScanner{
			Store:      store,
			StaleAfter: *staleAfter,
			MinScore:   minScore,
			RoleFilter: uiRoleFilter,
			Whitelist:  whitelist,
			LingerFor:  shared.CandidateLingerTTL,
		}

		if err := ui.Run(app, sc); err != nil {
			fmt.Println("error:", err)
			os.Exit(1)
		}
		return
	}

	hostID := shared.DefaultHostID("local")
	app.LocalHost = hostID
	sc := &shared.ScannerAdapter{
		Options: shared.ClassifyOptions{
			MinScore:    minScore,
			RoleFilter:  uiRoleFilter,
			Incremental: *incremental,
		},
		Collect:   telemetry.Collect,
		Classify:  classifier.Classify,
		HostID:    hostID,
		Whitelist: whitelist,
		LingerFor: shared.CandidateLingerTTL,
	}

	if err := ui.Run(app, sc); err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
}
