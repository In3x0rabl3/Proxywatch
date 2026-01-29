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

func parseRoleFilter(s string) map[string]bool {
	out := make(map[string]bool)
	if s == "" {
		return out
	}
	for _, r := range strings.Split(s, ",") {
		r = strings.TrimSpace(r)
		if r != "" {
			out[r] = true
		}
	}
	return out
}

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

/* ---------------- main ---------------- */

func main() {
	once := flag.Bool("once", false, "Run one scan and exit")
	roles := flag.String("roles", "", "Comma-separated list of roles to display")
	interval := flag.Duration("interval", 1*time.Second, "Refresh interval (e.g. 250ms, 1s)")
	incremental := flag.Bool("incremental", false, "Reuse classification for unchanged PIDs (faster, slightly less accurate)")
	jsonOut := flag.String("json", "", "Write pretty JSON snapshots to a file (use '-' for stdout)")
	listen := flag.String("listen", "", "Listen address for Beaconhunter agent ingest (e.g. 0.0.0.0:50051)")
	staleAfter := flag.Duration("stale", 0, "Drop remote hosts after this duration without updates (0 = keep)")

	flag.Parse()

	roleFilter := parseRoleFilter(*roles)
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

		// intentionally minimal, machine-friendly output
		if *jsonOut != "" {
			logger, err := shared.NewJSONLogger(*jsonOut, true)
			if err != nil {
				fmt.Println("error:", err)
				os.Exit(1)
			}
			_ = logger.WriteSnapshot(snap, cands)
			_ = logger.Close()
			return
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

	logger, err := shared.NewJSONLogger(*jsonOut, true)
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}

	if *listen != "" {
		store := beaconhunter.NewStore()
		server, lis, err := beaconhunter.ListenAndServe(*listen, store)
		if err != nil {
			fmt.Println("error:", err)
			if logger != nil {
				_ = logger.Close()
			}
			os.Exit(1)
		}
		defer server.Stop()
		defer lis.Close()

		app.LocalHost = ""
		sc := &beaconhunter.RemoteScanner{
			Store:      store,
			StaleAfter: *staleAfter,
			MinScore:   minScore,
			RoleFilter: roleFilter,
			Logger:     logger,
		}

		if err := ui.Run(app, sc); err != nil {
			fmt.Println("error:", err)
			if logger != nil {
				_ = logger.Close()
			}
			os.Exit(1)
		}

		if logger != nil {
			_ = logger.Close()
		}
		return
	}

	hostID := defaultHostID()
	app.LocalHost = hostID
	sc := &shared.ScannerAdapter{
		Options: shared.ClassifyOptions{
			MinScore:    minScore,
			RoleFilter:  roleFilter,
			Incremental: *incremental,
		},
		Collect:  telemetry.Collect,
		Classify: classifier.Classify,
		Logger:   logger,
		HostID:   hostID,
	}

	if err := ui.Run(app, sc); err != nil {
		fmt.Println("error:", err)
		if logger != nil {
			_ = logger.Close()
		}
		os.Exit(1)
	}

	if logger != nil {
		_ = logger.Close()
	}
}
