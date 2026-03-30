package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"proxywatch/internal/agent"
	"proxywatch/internal/calibration"
	"proxywatch/internal/contour"
	"proxywatch/internal/detection"
	"proxywatch/internal/keystore"
	"proxywatch/internal/shared"
	"proxywatch/internal/telemetry"
	"proxywatch/internal/ui"
)

/* ---------------- CLI helpers ---------------- */

func defaultUIRoleFilter() map[string]bool {
	return shared.ParseRoleFilter("all")
}

const (
	defaultUIRefreshInterval    = 250 * time.Millisecond
	defaultAgentSendInterval    = 250 * time.Millisecond
	defaultRemoteHostStaleAfter = 0 * time.Second
)

/* ---------------- main ---------------- */

func main() {
	connectAddr := flag.String("connect", "", "Run integrated agent mode and stream to remote ingest (e.g. 10.0.0.5:50051)")
	agentHostID := flag.String("id", "", "Host identifier for integrated agent mode (default: hostname)")
	agentToken := flag.String("agent-token", "", "Shared token for agent->server auth (overrides local token file)")
	listen := flag.String("listen", "", "Listen address for Proxywatch agent ingest (e.g. 0.0.0.0:50051)")
	serviceMode := flag.Bool("service", false, "Run as a Windows service (SCM only)")
	install := flag.Bool("install", false, "Install the Windows service")
	uninstall := flag.Bool("uninstall", false, "Uninstall the Windows service")
	start := flag.Bool("start", false, "Start the Windows service")
	stopSvc := flag.Bool("stop", false, "Stop the Windows service")

	flag.Parse()

	if err := bootstrapRuntimeConfig(keystore.DefaultPath()); err != nil {
		fmt.Println("warning:", "runtime config load failed:", err)
	}
	if err := configureDetectionOutputsFromRuntime(); err != nil {
		fmt.Println("error:", "failed to configure detection outputs:", err)
		os.Exit(1)
	}
	selectedAgentToken := strings.TrimSpace(*agentToken)
	if selectedAgentToken != "" {
		if err := agent.SetAgentToken(selectedAgentToken); err != nil {
			fmt.Println("error:", "failed to persist agent token:", err)
			os.Exit(1)
		}
	}
	targetAddr := strings.TrimSpace(*connectAddr)

	if *install || *uninstall || *start || *stopSvc {
		if *serviceMode {
			fmt.Println("error: -service cannot be used with install/start/stop commands")
			os.Exit(1)
		}
		if strings.TrimSpace(*listen) != "" {
			fmt.Println("error: -listen cannot be used with service install/start/stop commands")
			os.Exit(1)
		}
		hostID := shared.DefaultHostID(strings.TrimSpace(*agentHostID))
		if *install {
			if targetAddr == "" {
				fmt.Println("error: -connect is required for -install")
				os.Exit(1)
			}
			args := buildServiceArgs(targetAddr, hostID)
			exePath, err := os.Executable()
			if err != nil {
				fmt.Println("error:", err)
				os.Exit(1)
			}
			if err := installService(exePath, args); err != nil {
				fmt.Println("error:", err)
				os.Exit(1)
			}
		}
		if *start {
			if err := startService(); err != nil {
				fmt.Println("error:", err)
				os.Exit(1)
			}
		}
		if *stopSvc {
			if err := stopService(); err != nil {
				fmt.Println("error:", err)
				os.Exit(1)
			}
		}
		if *uninstall {
			if err := removeService(); err != nil {
				fmt.Println("error:", err)
				os.Exit(1)
			}
		}
		return
	}

	if *serviceMode {
		if targetAddr == "" {
			fmt.Println("error: -connect is required for -service")
			os.Exit(1)
		}
		if strings.TrimSpace(*listen) != "" {
			fmt.Println("error: -connect and -listen cannot be used together")
			os.Exit(1)
		}
		hostID := shared.DefaultHostID(strings.TrimSpace(*agentHostID))
		if err := runService(targetAddr, hostID, selectedAgentToken); err != nil {
			fmt.Println("error:", err)
			os.Exit(1)
		}
		return
	}

	memoryLoadErr := shared.LoadClassifierMemory("")
	if memoryLoadErr != nil && errors.Is(memoryLoadErr, os.ErrNotExist) {
		memoryLoadErr = nil
	}
	defer func() {
		_ = shared.SaveClassifierMemory("")
	}()

	minScore := 15

	if targetAddr != "" {
		if strings.TrimSpace(*listen) != "" {
			fmt.Println("error: -connect and -listen cannot be used together")
			os.Exit(1)
		}
		if memoryLoadErr != nil {
			fmt.Println("warning:", "classifier memory load failed:", memoryLoadErr)
		}
		hostID := shared.DefaultHostID(strings.TrimSpace(*agentHostID))
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		if err := agent.RunClientLoop(ctx, agent.ClientOptions{
			Addr:        targetAddr,
			HostID:      hostID,
			Token:       selectedAgentToken,
			Interval:    defaultAgentSendInterval,
			Incremental: false,
			MinScore:    minScore,
		}); err != nil {
			fmt.Println("error:", err)
			os.Exit(1)
		}
		return
	}

	// -------- interactive terminal UI --------
	app := &shared.AppState{
		RefreshInt:         defaultUIRefreshInterval,
		ConfirmKill:        true,
		ConfirmKillTimeout: 3 * time.Second,
		RolePreset:         "all",
		SortPreset:         "default",
	}
	if memoryLoadErr != nil {
		app.LastError = "classifier memory load failed: " + memoryLoadErr.Error()
	}

	whitelist, err := shared.LoadWhitelist("")
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	app.Whitelist = whitelist

	app.CollectDurationStr = "5m"
	app.CollectOutput = "~/.proxywatch/collections/proxywatch-collection.json"
	app.CollectSource = "local " + shared.DefaultHostID("local")
	app.ContourDuration = "5m"
	app.ContourOutput = contour.DefaultOutputPath()
	app.ContourSource = "all"
	app.ContourProbeEndpoint = "127.0.0.1"
	app.ContourProbeMode = contour.DefaultProbeMode()
	app.ContourProbeRole = contour.DefaultProbeRole()
	app.CalibrateDuration = "1h"
	app.CalibrateProvider = calibration.ProviderKey("OpenAI")
	app.CalibrateModel = calibration.DefaultModel(app.CalibrateProvider)
	app.CalibrateProfile = "tuning.json"
	app.CalibrateOutput = calibration.DefaultOutputPath()
	app.KeystorePath = keystore.DefaultPath()
	bootstrapKeystore(app)
	if cfg, err := calibration.LoadAndApplyActiveProfile(); err == nil && strings.TrimSpace(cfg.Profile) != "" {
		app.CalibrateProfile = cfg.Profile
		app.CalibrateAppliedProfile = cfg.Profile
	}

	uiRoleFilter := defaultUIRoleFilter()

	if *listen != "" {
		if _, err := agent.EnsureServerAgentToken(); err != nil {
			fmt.Println("error:", "failed to initialize server agent token:", err)
			os.Exit(1)
		}

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
		app.RemoveRemoteHost = func(host string) error {
			if remoteSrv.HostConnected(host) {
				return fmt.Errorf("host %s is still connected", host)
			}
			if !store.RemoveHost(host) {
				return fmt.Errorf("host %s not found", host)
			}
			return nil
		}
		sc := &agent.RemoteScanner{
			Store:      store,
			StaleAfter: defaultRemoteHostStaleAfter,
			MinScore:   minScore,
			RoleFilter: uiRoleFilter,
			Connected:  remoteSrv.ConnectedHosts,
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
	app.CalibrationCollect = telemetry.Collect
	sc := &shared.ScannerAdapter{
		Options: shared.ClassifyOptions{
			MinScore:    minScore,
			RoleFilter:  uiRoleFilter,
			Incremental: false,
			HostScope:   hostID,
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

func bootstrapKeystore(app *shared.AppState) {
	if app == nil {
		return
	}
	if strings.TrimSpace(app.KeystorePath) == "" {
		app.KeystorePath = keystore.DefaultPath()
	}

	// Skip secure keystores at startup — they require YubiKey touch
	// which the user must initiate explicitly from the Keystore view.
	entries := keystore.ListKeystores()
	for _, entry := range entries {
		if entry.Path == keystore.NormalizePath(app.KeystorePath) && entry.Secure {
			app.KeystoreValues = keystore.EmptyValues()
			keystore.ApplyToRuntime(app.KeystoreValues)
			return
		}
	}

	values, err := keystore.Load(app.KeystorePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			app.KeystoreValues = keystore.EmptyValues()
			keystore.ApplyToRuntime(app.KeystoreValues)
			return
		}
		// Keep startup non-fatal; users can recover from Keystore menu.
		app.KeystoreValues = keystore.EmptyValues()
		keystore.ApplyToRuntime(app.KeystoreValues)
		return
	}
	app.KeystoreValues = values
	app.KeystoreUnlocked = true
	keystore.ApplyToRuntime(values)
}

func bootstrapRuntimeConfig(path string) error {
	values, err := keystore.Load(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			keystore.ApplyToRuntime(keystore.EmptyValues())
			return nil
		}
		keystore.ApplyToRuntime(keystore.EmptyValues())
		return err
	}
	keystore.ApplyToRuntime(values)
	return nil
}

func buildServiceArgs(serverAddr, hostID string) []string {
	args := []string{
		"-service",
		"-connect", serverAddr,
	}
	if strings.TrimSpace(hostID) != "" {
		args = append(args, "-id", strings.TrimSpace(hostID))
	}
	return args
}

func configureDetectionOutputsFromRuntime() error {
	debugOutputPath := strings.TrimSpace(keystore.RuntimeValue("PROXYWATCH_DETECT_DEBUG_LOG"))
	defenderOutputPath := strings.TrimSpace(keystore.RuntimeValue("PROXYWATCH_DETECT_RULES_JSON"))
	return classifier.ConfigureDetectionOutputs(debugOutputPath, defenderOutputPath)
}
