package agent

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"proxywatch/internal/agent/pb"
	"proxywatch/internal/shared"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding"
)

const jsonCodecName = "json"

type jsonCodec struct{}

func (jsonCodec) Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func (jsonCodec) Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

func (jsonCodec) Name() string {
	return jsonCodecName
}

func init() {
	encoding.RegisterCodec(jsonCodec{})
}

func JSONCodec() encoding.Codec {
	return jsonCodec{}
}

type Store struct {
	mu    sync.RWMutex
	hosts map[string]hostState
}

type hostState struct {
	updated time.Time
	cands   []shared.Candidate
}

func NewStore() *Store {
	return &Store{
		hosts: make(map[string]hostState),
	}
}

func (s *Store) Update(host string, ts time.Time, cands []shared.Candidate) {
	if host == "" {
		host = "unknown"
	}
	for i := range cands {
		if cands[i].Host == "" {
			cands[i].Host = host
		}
	}
	s.mu.Lock()
	s.hosts[host] = hostState{
		updated: ts,
		cands:   cands,
	}
	s.mu.Unlock()
}

func (s *Store) Snapshot(staleAfter time.Duration) []shared.Candidate {
	now := time.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []shared.Candidate
	for host, state := range s.hosts {
		if staleAfter > 0 && now.Sub(state.updated) > staleAfter {
			continue
		}
		for i := range state.cands {
			c := state.cands[i]
			if c.Host == "" {
				c.Host = host
			}
			if c.Proc == nil {
				continue
			}
			out = append(out, c)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		return shared.CandidateLess(out[i], out[j])
	})

	return out
}

type RemoteScanner struct {
	Store       *Store
	StaleAfter  time.Duration
	MinScore    int
	RoleFilter  map[string]bool
	Whitelist   *shared.Whitelist
	LingerFor   time.Duration
	LingerCache map[string]shared.LingerEntry
}

func (r *RemoteScanner) Refresh(app *shared.AppState) {
	if r.Store == nil {
		shared.ResetAppState(app, "remote store not configured")
		return
	}

	roleFilter := r.RoleFilter
	if app != nil && len(app.RoleFilterOverride) > 0 {
		roleFilter = app.RoleFilterOverride
	}
	now := time.Now().UTC()
	cands := r.Store.Snapshot(r.StaleAfter)
	cands = shared.ApplyCandidateLinger(cands, now, r.LingerFor, &r.LingerCache)
	cands = shared.ApplyScoreAndRoleFilters(cands, r.MinScore, roleFilter)
	cands = shared.ApplyWhitelist(cands, r.Whitelist)
	shared.ApplySelection(app, cands, now)
}

type Server struct {
	Store         *Store
	mu            sync.RWMutex
	agents        map[string]*agentConn
	pending       map[string]chan error
	seq           uint64
	maxMessagesPS int
}

type agentConn struct {
	stream pb.ProxyWatchAgent_StreamCandidatesServer
	mu     sync.Mutex
	closed bool
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

func (s *Server) StreamCandidates(stream pb.ProxyWatchAgent_StreamCandidatesServer) error {
	if s.Store == nil {
		return fmt.Errorf("store not configured")
	}
	s.ensureRuntimeMaps()

	agent := &agentConn{stream: stream}
	defer agent.Close()

	var host string
	windowStart := time.Now()
	windowCount := 0
	defer s.unregisterAgentIfCurrent(host, agent)

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
		if err := enforceRateLimit(s.maxMessagesPS, &windowStart, &windowCount); err != nil {
			return err
		}

		host = s.processEnvelope(msg.Envelope, host, agent)

		if resp := msg.CommandResponse; resp != nil {
			s.handleCommandResponse(resp)
		}
	}
}

func (s *Server) ensureRuntimeMaps() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.agents == nil {
		s.agents = make(map[string]*agentConn)
	}
	if s.pending == nil {
		s.pending = make(map[string]chan error)
	}
}

func enforceRateLimit(maxMessagesPS int, windowStart *time.Time, windowCount *int) error {
	if maxMessagesPS <= 0 {
		return nil
	}
	now := time.Now()
	if now.Sub(*windowStart) >= time.Second {
		*windowStart = now
		*windowCount = 0
	}
	*windowCount++
	if *windowCount > maxMessagesPS {
		return fmt.Errorf("agent rate limit exceeded")
	}
	return nil
}

func (s *Server) processEnvelope(env *pb.CandidateEnvelope, currentHost string, agent *agentConn) string {
	if env == nil {
		return currentHost
	}

	host := currentHost
	if env.HostId != "" && host != env.HostId {
		host = sanitizeHostID(env.HostId)
		if host == "" {
			host = "unknown"
		}
		s.registerAgent(host, agent)
	}

	ts := time.Unix(env.TimestampUnix, 0).UTC()
	s.Store.Update(host, ts, envelopeCandidatesToShared(env.Candidates, host))
	return host
}

func envelopeCandidatesToShared(in []*pb.Candidate, host string) []shared.Candidate {
	out := make([]shared.Candidate, 0, len(in))
	for _, c := range in {
		if c == nil {
			continue
		}
		out = append(out, FromPBCandidate(c, host))
	}
	return out
}

func (s *Server) registerAgent(host string, agent *agentConn) {
	s.mu.Lock()
	s.agents[host] = agent
	s.mu.Unlock()
}

func (s *Server) unregisterAgentIfCurrent(host string, agent *agentConn) {
	if host == "" {
		return
	}
	s.mu.Lock()
	if cur, ok := s.agents[host]; ok && cur == agent {
		delete(s.agents, host)
	}
	s.mu.Unlock()
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
	pb.RegisterProxyWatchAgentServer(grpcServer, srv)

	go func() {
		_ = grpcServer.Serve(lis)
	}()

	return srv, grpcServer, lis, nil
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

func ServerTLSConfig() (*tls.Config, error) {
	serverCert, err := tls.X509KeyPair([]byte(generatedServerCertPEM), []byte(generatedServerKeyPEM))
	if err != nil {
		return nil, err
	}

	pool, err := embeddedCAPool()
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func AgentTLSConfig() (*tls.Config, error) {
	clientCert, err := tls.X509KeyPair([]byte(generatedClientCertPEM), []byte(generatedClientKeyPEM))
	if err != nil {
		return nil, err
	}

	pool, err := embeddedCAPool()
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      pool,
		ServerName:   "proxywatch",
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func embeddedCAPool() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(generatedCACertPEM)) {
		return nil, errors.New("failed to parse embedded CA")
	}
	return pool, nil
}
