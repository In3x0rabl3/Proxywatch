package beaconhunter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"proxywatch/internal/beaconhunter/pb"
	"proxywatch/internal/shared"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

type Server struct {
	Store   *Store
	mu      sync.RWMutex
	agents  map[string]*agentConn
	pending map[string]chan error
	seq     uint64
	maxMessagesPS int
}

type agentConn struct {
	stream pb.BeaconHunter_StreamCandidatesServer
	mu     sync.Mutex
	closed bool
	host   string
	ident  string
}

func (a *agentConn) Send(cmd *pb.ServerCommand) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return errors.New("agent stream closed")
	}
	return a.stream.Send(cmd)
}

func (a *agentConn) Close() {
	a.mu.Lock()
	a.closed = true
	a.mu.Unlock()
}

func (s *Server) StreamCandidates(stream pb.BeaconHunter_StreamCandidatesServer) error {
	if s.Store == nil {
		return fmt.Errorf("store not configured")
	}
	if s.agents == nil {
		s.agents = make(map[string]*agentConn)
	}
	if s.pending == nil {
		s.pending = make(map[string]chan error)
	}

	agent := &agentConn{stream: stream}
	defer agent.Close()

	var host string
	identity, _ := identityFromContext(stream.Context())
	if identity != "" {
		agent.ident = identity
	}
	windowStart := time.Now()
	windowCount := 0
	defer func() {
		if host != "" {
			s.mu.Lock()
			if cur, ok := s.agents[host]; ok && cur == agent {
				delete(s.agents, host)
			}
			s.mu.Unlock()
		}
	}()

	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if msg == nil {
			continue
		}
		if s.maxMessagesPS > 0 {
			now := time.Now()
			if now.Sub(windowStart) >= time.Second {
				windowStart = now
				windowCount = 0
			}
			windowCount++
			if windowCount > s.maxMessagesPS {
				return fmt.Errorf("agent rate limit exceeded")
			}
		}

		if env := msg.Envelope; env != nil {
			if env.HostId != "" {
				if agent.ident != "" {
					if host == "" {
						host = agent.ident
						agent.host = host
						s.mu.Lock()
						s.agents[host] = agent
						s.mu.Unlock()
					}
				} else if host != env.HostId {
					host = sanitizeHostID(env.HostId)
					if host == "" {
						host = "unknown"
					}
					agent.host = host
					s.mu.Lock()
					s.agents[host] = agent
					s.mu.Unlock()
				}
			}
			ts := time.Unix(env.TimestampUnix, 0).UTC()
			cands := make([]shared.Candidate, 0, len(env.Candidates))
			for _, c := range env.Candidates {
				if c == nil {
					continue
				}
				cands = append(cands, FromPBCandidate(c, host))
			}
			s.Store.Update(host, ts, cands)
		}

		if resp := msg.CommandResponse; resp != nil {
			s.handleCommandResponse(resp)
		}
	}
}

func (s *Server) Kill(host string, pid int) error {
	if s == nil {
		return errors.New("server not configured")
	}
	if host == "" {
		return errors.New("missing host")
	}

	s.mu.RLock()
	agent := s.agents[host]
	s.mu.RUnlock()
	if agent == nil {
		return fmt.Errorf("no agent connected for host %s", host)
	}

	reqID := fmt.Sprintf("%s-%d", host, atomic.AddUint64(&s.seq, 1))
	respCh := make(chan error, 1)

	s.mu.Lock()
	if s.pending == nil {
		s.pending = make(map[string]chan error)
	}
	s.pending[reqID] = respCh
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.pending, reqID)
		s.mu.Unlock()
	}()

	cmd := &pb.ServerCommand{
		RequestId: reqID,
		Type:      "kill",
		Pid:       int32(pid),
	}
	if err := agent.Send(cmd); err != nil {
		return err
	}

	select {
	case err := <-respCh:
		return err
	case <-time.After(5 * time.Second):
		return errors.New("remote kill timed out")
	}
}

func (s *Server) handleCommandResponse(resp *pb.CommandResponse) {
	if resp == nil {
		return
	}
	s.mu.RLock()
	ch := s.pending[resp.RequestId]
	s.mu.RUnlock()
	if ch == nil {
		return
	}
	if resp.Success {
		select {
		case ch <- nil:
		default:
		}
		return
	}
	if resp.Error == "" {
		select {
		case ch <- errors.New("remote kill failed"):
		default:
		}
		return
	}
	select {
	case ch <- errors.New(resp.Error):
	default:
	}
}

func ListenAndServe(addr string, store *Store) (*Server, *grpc.Server, net.Listener, error) {
	if store == nil {
		return nil, nil, nil, fmt.Errorf("store is nil")
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, nil, err
	}

	tlsCfg, err := ServerTLSConfig()
	if err != nil {
		return nil, nil, nil, err
	}
	srv := &Server{Store: store, maxMessagesPS: 200}
	grpcServer := grpc.NewServer(
		grpc.ForceServerCodec(jsonCodec{}),
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.MaxRecvMsgSize(4<<20),
		grpc.MaxSendMsgSize(4<<20),
	)
	pb.RegisterBeaconHunterServer(grpcServer, srv)

	go func() {
		_ = grpcServer.Serve(lis)
	}()

	return srv, grpcServer, lis, nil
}

func identityFromContext(ctx context.Context) (string, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", false
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", false
	}
	state := tlsInfo.State
	if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return "", false
	}
	cert := state.VerifiedChains[0][0]
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName, true
	}
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0], true
	}
	return "", false
}

func sanitizeHostID(in string) string {
	if len(in) > 128 {
		in = in[:128]
	}
	out := make([]rune, 0, len(in))
	for _, r := range in {
		switch {
		case r >= 'a' && r <= 'z':
			out = append(out, r)
		case r >= 'A' && r <= 'Z':
			out = append(out, r)
		case r >= '0' && r <= '9':
			out = append(out, r)
		case r == '-' || r == '_' || r == '.':
			out = append(out, r)
		}
	}
	return string(out)
}
