//go:build windows
// +build windows

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"proxywatch/internal/beaconhunter"
	"proxywatch/internal/classifier"
	"proxywatch/internal/shared"
	"proxywatch/internal/telemetry"
	"proxywatch/internal/ui"
)

/* ---------------- CLI helpers ---------------- */

func defaultHostID() string {
	name, err := os.Hostname()
	if err == nil {
		name = strings.TrimSpace(name)
	}
	if name == "" {
		return "local"
	}
	return name
}

func defaultUIRoleFilter() map[string]bool {
	return map[string]bool{
		"susp-session": true,
		"susp-beacon":  true,
		"susp-tun":     true,
	}
}

/* ---------------- main ---------------- */

func main() {
	once := flag.Bool("once", false, "Run one scan and exit")
	roles := flag.String("roles", "", "Comma-separated list of roles to display")
	interval := flag.Duration("interval", 250*time.Millisecond, "Refresh interval (e.g. 250ms, 1s)")
	incremental := flag.Bool("incremental", false, "Reuse classification for unchanged PIDs (faster, slightly less accurate)")
	listen := flag.String("listen", "", "Listen address for Beaconhunter agent ingest (e.g. 0.0.0.0:50051)")
	staleAfter := flag.Duration("stale", 0, "Drop remote hosts after this duration without updates (0 = keep)")

	flag.Parse()

	roleFilter := shared.ParseRoleFilter(*roles)
	roleFilterSet := strings.TrimSpace(*roles) != ""
	minScore := 15

	// -------- one-shot mode --------
	if *once {
		if *listen != "" {
			fmt.Println("error: -listen cannot be used with -once")
			os.Exit(1)
		}
		snap, err := telemetry.Collect()
		if err != nil {
			fmt.Println("error:", err)
			os.Exit(1)
		}

		cands := classifier.Classify(snap, shared.ClassifyOptions{
			MinScore:    minScore,
			RoleFilter:  roleFilter,
			Incremental: false,
		}, nil)
		hostID := defaultHostID()
		for i := range cands {
			cands[i].Host = hostID
		}

		for _, c := range cands {
			udpInt, udpExt, udpLo := shared.UDPScopeCounts(c.UDPListeners)
			fmt.Printf(
				"pid=%d role=%s active=%v out_int=%d out_ext=%d out_lo=%d\n",
				c.Proc.Pid,
				c.Role,
				c.ActiveProxying,
				c.OutInternal+udpInt,
				c.OutExternal+udpExt,
				c.OutLoopback+udpLo,
			)
		}

		return
	}

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
	app.CollectRoles = "susp-session,susp-beacon,susp-tun"
	app.CollectOutput = "proxywatch-collection.json"

	uiRoleFilter := roleFilter
	if !roleFilterSet {
		uiRoleFilter = defaultUIRoleFilter()
	}

	if *listen != "" {
		store := beaconhunter.NewStore()
		remoteSrv, grpcServer, lis, err := beaconhunter.ListenAndServe(*listen, store)
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
		sc := &beaconhunter.RemoteScanner{
			Store:      store,
			StaleAfter: *staleAfter,
			MinScore:   minScore,
			RoleFilter: uiRoleFilter,
			Whitelist:  whitelist,
		}

		if err := ui.Run(app, sc); err != nil {
			fmt.Println("error:", err)
			os.Exit(1)
		}
		return
	}

	hostID := defaultHostID()
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
	}

	if err := ui.Run(app, sc); err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
}
