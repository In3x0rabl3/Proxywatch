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

	"path/filepath"

	"proxywatch/internal/agent"
	"proxywatch/internal/agent/auth"
	"proxywatch/internal/agent/pb"
	"proxywatch/internal/contour"
	contourapi "proxywatch/internal/contour/api"
	"proxywatch/internal/detection"
	"proxywatch/internal/detection/features"
	gbdt "proxywatch/internal/detection/gbdt"
	"proxywatch/internal/detection/ml"
	"proxywatch/internal/detection/model"
	"proxywatch/internal/detection/output"
	"proxywatch/internal/detection/telemetry"
	"proxywatch/internal/keystore"
	"proxywatch/internal/safeio"
	"proxywatch/internal/shared"
	"proxywatch/internal/ui"
)

func defaultUIRoleFilter() map[string]bool {
	return shared.ParseRoleFilter("all")
}

const (
	defaultUIRefreshInterval    = 250 * time.Millisecond
	defaultAgentSendInterval    = 250 * time.Millisecond
	defaultRemoteHostStaleAfter = 0 * time.Second
)

func main() {
	connectAddr := flag.String("connect", "", "Run integrated agent mode and stream to remote ingest (e.g. 10.0.0.5:50051)")
	agentHostID := flag.String("id", "", "Host identifier for integrated agent mode (default: hostname)")
	agentToken := flag.String("agent-token", "", "Shared token for agent->server auth (overrides local token file)")
	listen := flag.String("listen", "", "Listen address for Proxywatch agent ingest (e.g. 0.0.0.0:50051)")
	trainingExport := flag.String("training-export", "", "Export ML training telemetry to directory (NDJSON)")
	debugAPIAddr := flag.String("debug-api", "", "Listen address for HTTP debug API (e.g. 127.0.0.1:7890). Exposes current detection state as JSON for testing.")
	agentDebugAPIAddr := flag.String("agent-debug-api", "", "Connect-mode only: listen address for agent-side HTTP introspection (e.g. 127.0.0.1:7891). Exposes the agent's last classified candidates so server-mode output can be diffed against standalone for parity verification.")
	serviceMode := flag.Bool("service", false, "Run as a Windows service (SCM only)")
	install := flag.Bool("install", false, "Install the Windows service")
	uninstall := flag.Bool("uninstall", false, "Uninstall the Windows service")
	start := flag.Bool("start", false, "Start the Windows service")
	stopSvc := flag.Bool("stop", false, "Stop the Windows service")

	contourServer := flag.Bool("contour-server", false, "Run as headless contour tunnel server (no TUI)")
	contourClient := flag.String("contour-client", "", "Run as headless contour tunnel client, connecting to this server address (e.g. 10.0.0.5)")
	contourAPIAddr := flag.String("contour-api", "", "Listen address for contour HTTP API (e.g. 127.0.0.1:7891). Exposes tunnel status and protocol verification.")
	contourProto := flag.String("contour-proto", "http", "Tunnel protocol for contour server/client mode (http, https, ws, dns, ssh, smtp, ftp, redis, postgres, socks5, ...)")
	contourPorts := flag.String("contour-ports", "8080", "Comma-separated port(s) for contour tunnel (e.g. 8080 or 8080,8443)")
	contourDirection := flag.String("contour-direction", "Forward", "Tunnel direction: Forward (client has SOCKS) or Reverse (server has SOCKS)")

	flag.Parse()

	isContourMode := *contourServer || strings.TrimSpace(*contourClient) != ""
	if isContourMode || strings.TrimSpace(*contourAPIAddr) != "" {
		runContourMode(*contourServer, strings.TrimSpace(*contourClient),
			strings.TrimSpace(*contourAPIAddr), *contourProto,
			*contourPorts, *contourDirection)
		return
	}

	if err := bootstrapRuntimeConfig(keystore.DefaultPath()); err != nil {
		fmt.Println("warning:", "runtime config load failed:", err)
	}
	if err := configureDetectionOutputsFromRuntime(); err != nil {
		fmt.Println("error:", "failed to configure detection outputs:", err)
		os.Exit(1)
	}
	selectedAgentToken := strings.TrimSpace(*agentToken)
	if selectedAgentToken != "" {
		if err := auth.SetAgentToken(selectedAgentToken); err != nil {
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

	if *trainingExport != "" {
		exp, err := gbdt.NewExporter(*trainingExport)
		if err != nil {
			fmt.Println("warning: training export failed:", err)
		} else {
			detection.TrainingExporter = exp
			defer exp.Close()
			if !isStdinTTY() {
				fmt.Fprintf(os.Stderr, "[ml] training export → %s\n", *trainingExport)
			}
		}
	}

	{
		var initialPred ml.Predictor
		modelPaths := []string{
			filepath.Join(safeio.ProxywatchDataRoot(), "models", "active", "role_classifier.json"),
			filepath.Join(safeio.ProxywatchDataRoot(), "models", "role_classifier.json"),
		}
		for _, mp := range modelPaths {
			if pred, err := ml.LoadNative(mp); err == nil {
				initialPred = pred
				if !isStdinTTY() {
					fmt.Fprintf(os.Stderr, "[ml] loaded baseline model: %s (%s)\n", mp, pred.ModelVersion())
				}
				break
			}
		}
		learner := ml.NewContinuousLearner(initialPred)
		detection.MLLearner = learner

		if initialPred != nil {
			detection.MLPrimary = true
		}
		learner.OnModelSwapped = func() {
			detection.MLPrimary = true
		}

		if targetAddr == "" {
			learner.Start()
			defer learner.Stop()
		}

		shared.StartSignatureWorker()
		defer shared.StopSignatureWorker()

		agent.ModelPushHandler = func(artifact *pb.ModelArtifact) error {
			if artifact == nil || len(artifact.ModelJson) == 0 {
				return fmt.Errorf("empty model artifact")
			}
			modelDir := filepath.Join(safeio.ProxywatchDataRoot(), "models", "active")
			_ = os.MkdirAll(modelDir, 0o700)
			modelPath := filepath.Join(modelDir, "role_classifier.json")
			if err := os.WriteFile(modelPath, artifact.ModelJson, 0o600); err != nil {
				return fmt.Errorf("write model: %w", err)
			}

			newPred, err := ml.LoadNative(modelPath)
			if err != nil {
				return fmt.Errorf("load new model: %w", err)
			}
			learner.SwapPredictor(newPred)
			detection.MLPrimary = true
			shared.LogInfo("ml", "model hot-swapped to version %s from server", artifact.Version)
			return nil
		}
		if !isStdinTTY() {

			if initialPred != nil {
				fmt.Fprintf(os.Stderr, "[ml] continuous learning active (baseline loaded)\n")
			} else {
				fmt.Fprintf(os.Stderr, "[ml] continuous learning active (no baseline — collecting data)\n")
			}
		}
	}

	if addr := strings.TrimSpace(*debugAPIAddr); addr != "" {
		srv, err := output.StartDebugAPIServer(addr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[debug-api] failed to start: %v\n", err)
		} else if !isStdinTTY() {

			fmt.Fprintf(os.Stderr, "[debug-api] listening on %s\n", addr)
			defer srv.Close()
		} else {
			defer srv.Close()
		}
	}

	if err := shared.LoadOperatorLabels(); err != nil {
		fmt.Fprintf(os.Stderr, "[operator-labels] load failed: %v\n", err)
	}

	memoryLoadErr := shared.LoadClassifierMemory("")
	if memoryLoadErr != nil && errors.Is(memoryLoadErr, os.ErrNotExist) {
		memoryLoadErr = nil
	}

	isAgentMode := targetAddr != ""
	if !isAgentMode {
		_ = model.Load()
	}
	defer func() {
		_ = shared.SaveClassifierMemory("")
		if !isAgentMode {
			_ = model.Save()
		}
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

		shared.StartSignatureWorker()
		defer shared.StopSignatureWorker()
		hostID := shared.DefaultHostID(strings.TrimSpace(*agentHostID))
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		if dbgAddr := strings.TrimSpace(*agentDebugAPIAddr); dbgAddr != "" {
			srv, err := agent.StartDebugServer(dbgAddr, hostID, targetAddr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[agent-debug-api] failed to start: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "[agent-debug-api] listening on %s\n", dbgAddr)
				defer srv.Close()
			}
		}
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

	app := &shared.AppState{
		RefreshInt:         defaultUIRefreshInterval,
		ConfirmKill:        true,
		ConfirmKillTimeout: 3 * time.Second,
		RolePreset:         "all",
		SortPreset:         "role",
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
	app.KeystorePath = keystore.DefaultPath()
	bootstrapKeystore(app)

	uiRoleFilter := defaultUIRoleFilter()

	if *listen != "" {
		if _, err := auth.EnsureServerAgentToken(); err != nil {
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

		output.RegisterAgentStore(agent.NewDebugStoreProvider(remoteSrv, store))
		defer output.RegisterAgentStore(nil)

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

			PredictCandidate: func(c *shared.Candidate, key string) {
				if detection.MLLearner == nil {
					return
				}
				pred := detection.MLLearner.Predictor()
				if pred == nil {
					return
				}
				behavior := shared.ProcessBehaviorByKey[key]
				profile := model.ResolveProfile(key)
				fv := features.Extract(c, behavior, profile)
				if !fv.Valid {
					return
				}
				result := pred.PredictRole(fv)
				c.MLRole = result.TopRole
				c.MLConfidence = result.TopProb
				c.MLActive = true
				for _, rp := range result.TopN {
					c.MLTopN = append(c.MLTopN, shared.MLRolePrediction{
						Role: rp.Role,
						Prob: rp.Prob,
					})
				}

				ruleRole := shared.InferRoleFromSignals(c.Signals, c.ControlSubtype, c.Role)
				// SSH servers should not be classified as beacons regardless of ML prediction
				if shared.IsSSHServerProcess(c.Proc) {
					c.Role = "listener"
					c.Score = 20
				} else {
					c.Role = result.TopRole
					c.Score = int(result.TopProb * 100)
				}

				model.RecordShadowComparison(result.TopRole == ruleRole)
				committed := ""
				if profile != nil {
					committed = profile.ExperienceLastRole
				}
				model.RecordMLPrediction(result.TopProb, result.TopRole == committed)
			},

			BufferCandidate: func(c *shared.Candidate, key string) {
				if detection.MLLearner == nil {
					return
				}
				behavior := shared.ProcessBehaviorByKey[key]
				profile := model.ResolveProfile(key)
				fv := features.Extract(c, behavior, profile)
				if !fv.Valid {
					return
				}
				rec := gbdt.TrainingRecord{
					Timestamp:       time.Now().UTC(),
					Host:            c.Host,
					ProcessKey:      key,
					ProcessName:     c.Proc.Name,
					ProcessPath:     c.Proc.ExePath,
					User:            c.Proc.UserName,
					Company:         c.Proc.Company,
					Features:        fv.ToMap(),
					Signals:         c.Signals,
					RuleRole:        c.Role,
					RuleScore:       c.Score,
					StrongEvidence:  c.StrongEvidence,
					TrafficVerified: c.TrafficVerified,
				}
				if profile != nil {
					rec.ExperienceObservations = profile.ExperienceObservations
					rec.ExperienceStability = profile.RoleStability
					rec.ExperienceRole = profile.DominantRole
					rec.UserVerdict = profile.UserVerdict
					rec.CalibrationVerdict = profile.CalibrationVerdict
					if profile.TrainingLabel != "" {
						label := profile.TrainingLabel
						rec.OperatorLabel = &label
					}
				}
				detection.MLLearner.Buffer().Add(rec)
			},
		}

		agent.TrainingBatchHandler = func(hostID string, records []*pb.TrainingRecord) {
			if detection.MLLearner == nil {
				return
			}
			for _, rec := range records {
				if rec == nil {
					continue
				}
				tr := gbdt.TrainingRecord{
					Timestamp:              time.Unix(rec.TimestampUnix, 0).UTC(),
					Host:                   hostID,
					ProcessKey:             rec.ProcessKey,
					ProcessName:            rec.ProcessName,
					RuleRole:               rec.RuleRole,
					RuleScore:              int(rec.RuleScore),
					StrongEvidence:         rec.StrongEvidence,
					TrafficVerified:        rec.TrafficVerified,
					ExperienceObservations: int(rec.ExperienceObservations),
					ExperienceStability:    rec.ExperienceStability,
					ExperienceRole:         rec.ExperienceRole,
				}
				if rec.OperatorLabel != "" {
					label := rec.OperatorLabel
					tr.OperatorLabel = &label
				}
				if len(rec.Features) > 0 {
					fnames := features.FeatureNames()
					tr.Features = make(map[string]float64, len(fnames))
					for i, name := range fnames {
						if i < len(rec.Features) {
							tr.Features[name] = rec.Features[i]
						}
					}
				}
				tr.Signals = rec.Signals
				detection.MLLearner.Buffer().Add(tr)
			}
		}

		serverOrch := detection.NewOrchestrator()
		app.TrainingOrchestrator = serverOrch
		app.TrainingLearner = detection.MLLearner
		app.MLClassifierPrimary = detection.MLPrimary
		app.MLPrimarySource = &detection.MLPrimary

		if detection.MLLearner != nil {
			serverOrch.OnTrainDone = detection.MLLearner.NotifyTrainingDone
			detection.MLLearner.TriggerTrain = func(reason string) {
				serverOrch.TriggerRetrain(reason, detection.MLLearner.Buffer())
			}
		}

		if !isStdinTTY() {
			fmt.Fprintln(os.Stderr, "[headless] server mode, no TTY — debug API only")
			ctx, cancel := context.WithCancel(context.Background())
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, os.Interrupt)
			go func() { <-sigCh; cancel() }()
			ticker := time.NewTicker(defaultUIRefreshInterval)
			defer ticker.Stop()
			cycle := 0
			for {
				func() {
					defer func() { _ = recover() }()
					sc.Refresh(app)
					cycle++
					if cycle%20 == 0 {
						fmt.Fprintf(os.Stderr, "[headless] server cycle %d — scanner alive\n", cycle)
					}
				}()
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
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
			Incremental: false,
			HostScope:   hostID,
		},
		Collect:   telemetry.Collect,
		Classify:  detection.Classify,
		HostID:    hostID,
		Whitelist: whitelist,
		LingerFor: shared.CandidateLingerTTL,
	}

	orch := detection.NewOrchestrator()
	app.TrainingOrchestrator = orch
	app.TrainingLearner = detection.MLLearner
	app.MLClassifierPrimary = detection.MLPrimary
	app.MLPrimarySource = &detection.MLPrimary

	if detection.MLLearner != nil {
		orch.OnTrainDone = detection.MLLearner.NotifyTrainingDone
		detection.MLLearner.TriggerTrain = func(reason string) {
			orch.TriggerRetrain(reason, detection.MLLearner.Buffer())
		}
	}

	if strings.TrimSpace(*debugAPIAddr) != "" {
		fmt.Fprintf(os.Stderr, "[headless] running without TUI — debug API only\n")
		ctx, cancel := context.WithCancel(context.Background())
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt)
		go func() {
			<-sigCh
			cancel()
		}()
		ticker := time.NewTicker(defaultUIRefreshInterval)
		defer ticker.Stop()
		cycle := 0
		for {
			func() {
				defer func() {
					if r := recover(); r != nil {
						fmt.Fprintf(os.Stderr, "[headless] recovered from panic in Refresh: %v\n", r)
					}
				}()
				sc.Refresh(app)
				cycle++
				if cycle%20 == 0 {
					fmt.Fprintf(os.Stderr, "[headless] cycle %d — scanner alive\n", cycle)
				}
			}()
			select {
			case <-ctx.Done():
				fmt.Fprintf(os.Stderr, "[headless] shutting down\n")
				return
			case <-ticker.C:
			}
		}
	}

	if err := ui.Run(app, sc); err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
}

func isStdinTTY() bool {
	for _, f := range []*os.File{os.Stdin, os.Stdout, os.Stderr} {
		fi, err := f.Stat()
		if err != nil {
			return false
		}
		if (fi.Mode() & os.ModeCharDevice) == 0 {
			return false
		}
	}
	return true
}

func bootstrapKeystore(app *shared.AppState) {
	if app == nil {
		return
	}
	if strings.TrimSpace(app.KeystorePath) == "" {
		app.KeystorePath = keystore.DefaultPath()
	}

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
	return detection.ConfigureDetectionOutputs(debugOutputPath, defenderOutputPath)
}

func runContourMode(isServer bool, clientTarget, apiAddr, proto, portsStr, direction string) {

	ports := parsePorts(portsStr)
	if len(ports) == 0 {
		ports = []int{8080}
	}

	role := ""
	switch {
	case isServer:
		role = "Server"
	case clientTarget != "":
		role = "Client"
	}

	var apiSrv *contourapi.Server
	if apiAddr != "" {
		srv, err := contourapi.Start(apiAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[contour-api] failed to start on %s: %v\n", apiAddr, err)
		} else {
			apiSrv = srv
			fmt.Fprintf(os.Stderr, "[contour-api] listening on %s\n", apiAddr)
			defer apiSrv.Close()
		}
	}

	if role == "" {
		if apiSrv == nil {
			fmt.Fprintln(os.Stderr, "error: --contour-api, --contour-server, or --contour-client required")
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "[contour] running in verify-only mode — use %s/verify/all to test protocols\n", apiAddr)
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt)
		<-sigCh
		fmt.Fprintln(os.Stderr, "[contour] shutting down")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if apiSrv != nil {
		apiSrv.SetActiveTunnel(role, proto, direction, ports, clientTarget, cancel)
	}

	emit := func(line string) {
		fmt.Fprintln(os.Stderr, line)
		if apiSrv != nil {
			apiSrv.AppendLog(line)
		}
	}

	fmt.Fprintf(os.Stderr, "[contour] role=%s proto=%s ports=%v direction=%s\n", role, proto, ports, direction)

	tunnelDone := make(chan error, 1)
	go func() {
		result := contour.RunTunnel(ctx, contour.TunnelInput{
			Role:      role,
			Method:    proto,
			Ports:     ports,
			Target:    clientTarget,
			Direction: direction,
			Emit:      emit,
		})
		if apiSrv != nil {
			apiSrv.MarkStopped()
		}
		tunnelDone <- result.Error
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	select {
	case <-sigCh:
		fmt.Fprintln(os.Stderr, "\n[contour] interrupted, shutting down")
		cancel()
		<-tunnelDone
	case err := <-tunnelDone:
		if err != nil {
			fmt.Fprintf(os.Stderr, "[contour] tunnel exited: %v\n", err)
		} else {
			fmt.Fprintln(os.Stderr, "[contour] tunnel exited cleanly")
		}

		if apiSrv != nil {
			fmt.Fprintln(os.Stderr, "[contour] API still running — press Ctrl-C to exit")
			<-sigCh
		}
	}
}

func parsePorts(s string) []int {
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n := 0
		for _, ch := range part {
			if ch < '0' || ch > '9' {
				n = 0
				break
			}
			n = n*10 + int(ch-'0')
		}
		if n > 0 && n <= 65535 {
			out = append(out, n)
		}
	}
	return out
}
