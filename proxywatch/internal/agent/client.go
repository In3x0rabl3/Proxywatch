package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"proxywatch/internal/agent/pb"
	"proxywatch/internal/detection"
	"proxywatch/internal/keystore"
	"proxywatch/internal/shared"
	"proxywatch/internal/telemetry"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type ClientOptions struct {
	Addr        string
	HostID      string
	Token       string
	Interval    time.Duration
	Incremental bool
	MinScore    int
}

var (
	errAgentTrustNotEnrolled = errors.New("agent trust not enrolled")
	errAgentTokenMissing     = errors.New("agent token missing")
)

func RunClientLoop(ctx context.Context, opts ClientOptions) error {
	opts = normalizeClientOptions(opts)
	cache := shared.ClassifierCache{}
	lastIO := map[int]shared.IOSample{}

	for {
		err := runClientOnce(ctx, opts, &cache, &lastIO)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return nil
		}
		if isPermanentClientError(err) {
			return err
		}
		fmt.Println("agent error:", err)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(2 * time.Second):
		}
	}
}

func normalizeClientOptions(opts ClientOptions) ClientOptions {
	if opts.Interval <= 0 {
		opts.Interval = 250 * time.Millisecond
	}
	if opts.MinScore <= 0 {
		opts.MinScore = 15
	}
	opts.HostID = shared.DefaultHostID(opts.HostID)
	opts.Token = strings.TrimSpace(opts.Token)
	return opts
}

func runClientOnce(
	ctx context.Context,
	opts ClientOptions,
	cache *shared.ClassifierCache,
	lastIO *map[int]shared.IOSample,
) error {
	conn, stream, err := openSecureStream(ctx, opts.Addr, opts.Token)
	if err != nil {
		return err
	}
	defer conn.Close()

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

	ticker := time.NewTicker(opts.Interval)
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
				MinScore:    opts.MinScore,
				RoleFilter:  nil,
				Incremental: opts.Incremental,
				HostScope:   opts.HostID,
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
				cands[i].Host = opts.HostID
			}

			env := ToEnvelope(opts.HostID, now, cands)
			msg := &pb.ClientMessage{Envelope: env}
			select {
			case sendCh <- msg:
			case <-ctx.Done():
				return nil
			}
		}
	}
}

func openSecureStream(
	ctx context.Context,
	addr string,
	tokenOverride string,
) (*grpc.ClientConn, pb.ProxyWatchAgent_StreamCandidatesClient, error) {
	token := strings.TrimSpace(tokenOverride)
	if token == "" {
		token = strings.TrimSpace(keystore.RuntimeValue("PROXYWATCH_AGENT_TOKEN"))
	}
	if token == "" {
		token = strings.TrimSpace(readTokenFile(agentTokenPath()))
	}
	if tokenOverride != "" {
		values := keystore.ValuesFromRuntime()
		if strings.TrimSpace(values["PROXYWATCH_AGENT_TOKEN"]) != token {
			values["PROXYWATCH_AGENT_TOKEN"] = token
			keystore.ApplyToRuntime(values)
		}
		_ = writeFileAtomic(agentTokenPath(), []byte(token+"\n"), tlsPrivateFileMode)
	}

	primaryTLS, err := AgentTLSConfig()
	if err != nil {
		return nil, nil, err
	}
	conn, stream, primaryErr := dialStreamWithAuth(ctx, addr, primaryTLS, token)
	if primaryErr == nil {
		return conn, stream, nil
	}

	bootstrapTLS, bootstrapToken, bootstrapErr := loadBootstrapClientTLS()
	if token == "" && bootstrapToken != "" {
		token = bootstrapToken
	}
	if bootstrapErr == nil {
		fallbackConn, fallbackStream, fallbackErr := dialStreamWithAuth(ctx, addr, bootstrapTLS, token)
		if fallbackErr == nil {
			return fallbackConn, fallbackStream, nil
		}
	}

	var (
		pinnedConn   *grpc.ClientConn
		pinnedStream pb.ProxyWatchAgent_StreamCandidatesClient
		pinnedErr    error
		enrollErr    error
	)
	pinnedErr = dialWithPinnedOrTOFU(func(tlsCfg *tls.Config) error {
		var err error
		pinnedConn, pinnedStream, err = dialStreamWithAuth(ctx, addr, tlsCfg, token)
		return err
	}, addr)
	if pinnedErr == nil {
		return pinnedConn, pinnedStream, nil
	}

	if token != "" && shouldAttemptTokenEnroll(pinnedErr) {
		enrollErr = enrollTrustWithToken(ctx, addr, token)
		if enrollErr == nil {
			pinnedErr = dialWithPinnedOrTOFU(func(tlsCfg *tls.Config) error {
				var err error
				pinnedConn, pinnedStream, err = dialStreamWithAuth(ctx, addr, tlsCfg, token)
				return err
			}, addr)
			if pinnedErr == nil {
				return pinnedConn, pinnedStream, nil
			}
		}
	}

	if token == "" {
		return nil, nil, fmt.Errorf(
			"%w: configure PROXYWATCH_AGENT_TOKEN in keystore or provide bootstrap at %s",
			errAgentTokenMissing,
			agentBootstrapPath(),
		)
	}

	if errors.Is(bootstrapErr, os.ErrNotExist) && errors.Is(pinnedErr, os.ErrNotExist) {
		if enrollErr != nil {
			return nil, nil, fmt.Errorf(
				"%w for %s: token enrollment failed: %v; no bootstrap bundle at %s and no trust pin at %s",
				errAgentTrustNotEnrolled,
				addr,
				enrollErr,
				agentBootstrapPath(),
				agentTrustPath(addr),
			)
		}
		return nil, nil, fmt.Errorf(
			"%w for %s: no bootstrap bundle at %s and no trust pin at %s; copy bootstrap.json from the server or set a valid token to auto-enroll trust",
			errAgentTrustNotEnrolled,
			addr,
			agentBootstrapPath(),
			agentTrustPath(addr),
		)
	}

	if bootstrapErr != nil {
		return nil, nil, fmt.Errorf("%v; bootstrap trust bundle unavailable (%s): %v; pinned trust (%s) failed: %v", primaryErr, agentBootstrapPath(), bootstrapErr, agentTrustPath(addr), pinnedErr)
	}
	return nil, nil, fmt.Errorf("%v; bootstrap mode failed (%s); pinned trust (%s) failed: %v", primaryErr, agentBootstrapPath(), agentTrustPath(addr), pinnedErr)
}

func shouldAttemptTokenEnroll(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	if msg == "" {
		return false
	}
	if strings.Contains(msg, "server certificate fingerprint mismatch") {
		return true
	}
	if strings.Contains(msg, "invalid trust pin") || strings.Contains(msg, "empty trust pin") {
		return true
	}
	if strings.Contains(msg, "certificate signed by unknown authority") {
		return true
	}
	return false
}

func enrollTrustWithToken(ctx context.Context, addr, token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("missing token for enrollment")
	}
	clientNonce, err := randomNonceBase64(24)
	if err != nil {
		return err
	}
	clientUnix := time.Now().UTC().Unix()
	req := &pb.EnrollRequest{
		ClientNonce: clientNonce,
		ClientUnix:  clientUnix,
		ClientProof: buildEnrollClientProof(token, clientNonce, clientUnix),
	}
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	}
	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(JSONCodec())),
	)
	if err != nil {
		return err
	}
	defer conn.Close()
	client := pb.NewProxyWatchAgentClient(conn)
	rpcCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	resp, err := client.Enroll(rpcCtx, req)
	if err != nil {
		return err
	}
	if resp == nil {
		return errors.New("empty enrollment response")
	}
	serverPin := strings.ToLower(strings.TrimSpace(resp.ServerFingerprint))
	if !validFingerprintHex(serverPin) {
		return errors.New("invalid server fingerprint from enrollment")
	}
	expectedProof := buildEnrollServerProof(token, clientNonce, clientUnix, resp.ServerNonce, serverPin)
	if !constantTimeHexEqual(strings.TrimSpace(resp.ServerProof), expectedProof) {
		return errors.New("invalid server enrollment proof")
	}
	return savePinnedServerFingerprint(addr, serverPin)
}

func isPermanentClientError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errAgentTrustNotEnrolled) || errors.Is(err, errAgentTokenMissing) {
		return true
	}
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "invalid agent token") {
		return true
	}
	if strings.Contains(lower, "unsupported bootstrap version") ||
		strings.Contains(lower, "bootstrap missing ca certificate") ||
		strings.Contains(lower, "bootstrap ca certificate is invalid") ||
		strings.Contains(lower, "invalid trust pin") ||
		strings.Contains(lower, "empty trust pin") ||
		strings.Contains(lower, "certificate signed by unknown authority") ||
		strings.Contains(lower, "invalid enrollment proof") {
		return true
	}
	return false
}

func dialStreamWithAuth(
	ctx context.Context,
	addr string,
	tlsCfg *tls.Config,
	token string,
) (*grpc.ClientConn, pb.ProxyWatchAgent_StreamCandidatesClient, error) {
	conn, err := grpc.NewClient(
		addr,
		SecureDialOptionsWithToken(tlsCfg, token)...,
	)
	if err != nil {
		return nil, nil, err
	}
	client := pb.NewProxyWatchAgentClient(conn)
	stream, err := client.StreamCandidates(ctx)
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return conn, stream, nil
}
