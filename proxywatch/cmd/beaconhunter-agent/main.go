//go:build windows
// +build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
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
	interval := flag.Duration("interval", 1*time.Second, "Refresh interval (e.g. 250ms, 1s)")
	incremental := flag.Bool("incremental", false, "Reuse classification for unchanged PIDs")
	flag.Parse()

	if *serverAddr == "" {
		fmt.Println("error: -server is required")
		os.Exit(1)
	}

	if *hostID == "" {
		name, err := os.Hostname()
		if err == nil && name != "" {
			*hostID = name
		} else {
			*hostID = "unknown"
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	cache := shared.ClassifierCache{}
	lastIO := map[int]shared.IOSample{}

	for {
		if err := runAgent(ctx, *serverAddr, *hostID, *interval, *incremental, &cache, &lastIO); err != nil {
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

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			_, _ = stream.CloseAndRecv()
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

			now := time.Now().UTC()
			shared.ApplyIORates(cands, now, lastIO)
			for i := range cands {
				cands[i].Host = hostID
			}

			env := beaconhunter.ToEnvelope(hostID, now, cands)
			if err := stream.Send(env); err != nil {
				return err
			}
		}
	}
}
