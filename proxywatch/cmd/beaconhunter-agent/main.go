//go:build windows
// +build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"time"

	"proxywatch/internal/beaconhunter"
	"proxywatch/internal/beaconhunter/pb"
	"proxywatch/internal/classifier"
	"proxywatch/internal/shared"
	"proxywatch/internal/telemetry"

	"google.golang.org/grpc"
)

func main() {
	serverAddr := flag.String("server", "", "Beaconhunter server address (e.g. 10.0.0.5:50051)")
	hostID := flag.String("id", "", "Host identifier (default: hostname)")
	interval := flag.Duration("interval", 250*time.Millisecond, "Refresh interval (e.g. 250ms, 1s)")
	incremental := flag.Bool("incremental", false, "Reuse classification for unchanged PIDs")
	serviceMode := flag.Bool("service", false, "Run as a Windows service (SCM only)")
	install := flag.Bool("install", false, "Install the Windows service")
	uninstall := flag.Bool("uninstall", false, "Uninstall the Windows service")
	start := flag.Bool("start", false, "Start the Windows service")
	stop := flag.Bool("stop", false, "Stop the Windows service")
	flag.Parse()

	if *install || *uninstall || *start || *stop {
		if *serviceMode {
			fmt.Println("error: --service cannot be used with install/start/stop commands")
			os.Exit(1)
		}
		if *install {
			if *serverAddr == "" {
				fmt.Println("error: -server is required for --install")
				os.Exit(1)
			}
			if *hostID == "" {
				*hostID = defaultHostID()
			}
			args := buildServiceArgs(*serverAddr, *hostID, *interval, *incremental)
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
		if *stop {
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

	if *serverAddr == "" {
		fmt.Println("error: -server is required")
		os.Exit(1)
	}

	if *hostID == "" {
		*hostID = defaultHostID()
	}

	if *serviceMode {
		if err := runService(*serverAddr, *hostID, *interval, *incremental); err != nil {
			fmt.Println("error:", err)
			os.Exit(1)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	cache := shared.ClassifierCache{}
	lastIO := map[int]shared.IOSample{}

	runAgentLoop(ctx, *serverAddr, *hostID, *interval, *incremental, &cache, &lastIO)
}

func defaultHostID() string {
	name, err := os.Hostname()
	if err == nil && name != "" {
		return name
	}
	return "unknown"
}

func buildServiceArgs(serverAddr, hostID string, interval time.Duration, incremental bool) []string {
	args := []string{
		"--service",
		"--server", serverAddr,
		"--interval", interval.String(),
	}
	if hostID != "" {
		args = append(args, "--id", hostID)
	}
	if incremental {
		args = append(args, "--incremental")
	}
	return args
}

func runAgentLoop(
	ctx context.Context,
	addr string,
	hostID string,
	interval time.Duration,
	incremental bool,
	cache *shared.ClassifierCache,
	lastIO *map[int]shared.IOSample,
) {
	for {
		if err := runAgent(ctx, addr, hostID, interval, incremental, cache, lastIO); err != nil {
			if ctx.Err() != nil {
				return
			}
			fmt.Println("agent error:", err)
			time.Sleep(2 * time.Second)
		} else {
			return
		}
	}
}

func runAgent(
	ctx context.Context,
	addr string,
	hostID string,
	interval time.Duration,
	incremental bool,
	cache *shared.ClassifierCache,
	lastIO *map[int]shared.IOSample,
) error {
	conn, err := grpc.DialContext(
		ctx,
		addr,
		grpc.WithInsecure(),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(beaconhunter.JSONCodec())),
	)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := pb.NewBeaconHunterClient(conn)
	stream, err := client.StreamCandidates(ctx)
	if err != nil {
		return err
	}

	sendCh := make(chan *pb.ClientMessage, 16)
	sendDone := make(chan error, 1)
	var closeOnce sync.Once
	shutdown := func() {
		closeOnce.Do(func() {
			close(sendCh)
			_ = stream.CloseSend()
		})
	}
	go func() {
		for msg := range sendCh {
			if err := stream.Send(msg); err != nil {
				sendDone <- err
				return
			}
		}
		sendDone <- nil
	}()

	recvDone := make(chan error, 1)
	go func() {
		for {
			cmd, err := stream.Recv()
			if err != nil {
				recvDone <- err
				return
			}
			if cmd == nil {
				continue
			}
			if cmd.Type == "kill" && cmd.Pid > 0 {
				killErr := telemetry.KillProcess(int(cmd.Pid))
				resp := &pb.CommandResponse{
					RequestId: cmd.RequestId,
					Success:   killErr == nil,
				}
				if killErr != nil {
					resp.Error = killErr.Error()
				}
				select {
				case sendCh <- &pb.ClientMessage{CommandResponse: resp}:
				case <-ctx.Done():
					recvDone <- ctx.Err()
					return
				}
			}
		}
	}()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			shutdown()
			return nil
		case err := <-sendDone:
			shutdown()
			if err != nil {
				return err
			}
			return nil
		case err := <-recvDone:
			shutdown()
			if err != nil {
				return err
			}
			return nil
		case <-ticker.C:
			snap, err := telemetry.Collect()
			if err != nil {
				continue
			}

			cands := classifier.Classify(snap, shared.ClassifyOptions{
				MinScore:    15,
				RoleFilter:  nil,
				Incremental: incremental,
			}, cache)
			selfPID := os.Getpid()
			filtered := make([]shared.Candidate, 0, len(cands))
			for _, c := range cands {
				if c.Proc != nil && c.Proc.Pid == selfPID {
					continue
				}
				filtered = append(filtered, c)
			}
			cands = filtered

			now := time.Now().UTC()
			shared.ApplyIORates(cands, now, lastIO)
			for i := range cands {
				cands[i].Host = hostID
			}

			env := beaconhunter.ToEnvelope(hostID, now, cands)
			msg := &pb.ClientMessage{Envelope: env}
			select {
			case sendCh <- msg:
			case <-ctx.Done():
				return nil
			}
		}
	}
}
