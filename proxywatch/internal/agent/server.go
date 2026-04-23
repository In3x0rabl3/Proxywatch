package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"proxywatch/internal/agent/auth"
	"proxywatch/internal/agent/pb"
	"proxywatch/internal/detection/model"
	"proxywatch/internal/shared"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const connectedHostFreshness = 3 * time.Second
const reconnectHostTakeoverAfter = 10 * time.Second

type Store struct {
	mu    sync.RWMutex
	hosts map[string]hostState
}

type hostState struct {
	firstSeen time.Time
	updated   time.Time
	cands     []shared.Candidate
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
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	for i := range cands {
		if cands[i].Host == "" {
			cands[i].Host = host
		}
	}
	s.mu.Lock()
	firstSeen := ts
	if prev, ok := s.hosts[host]; ok && !prev.firstSeen.IsZero() {
		firstSeen = prev.firstSeen
	}
	s.hosts[host] = hostState{
		firstSeen: firstSeen,
		updated:   ts,
		cands:     cands,
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

// SnapshotHost returns the candidates and last-update timestamp for one host.
// The lookup is tolerant: it tries the exact key first, then a case-insensitive
// match on either the raw key or the display-formatted form. Used by the debug
// API's /agent/<host>/* endpoints.
func (s *Store) SnapshotHost(host string) ([]shared.Candidate, time.Time, bool) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, time.Time{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	state, ok := s.hosts[host]
	if !ok {
		needle := strings.ToLower(shared.DisplayHost(host))
		for key, st := range s.hosts {
			if strings.EqualFold(key, host) || strings.ToLower(shared.DisplayHost(key)) == needle {
				state = st
				ok = true
				host = key
				break
			}
		}
	}
	if !ok {
		return nil, time.Time{}, false
	}
	out := make([]shared.Candidate, 0, len(state.cands))
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
	sort.Slice(out, func(i, j int) bool {
		return shared.CandidateLess(out[i], out[j])
	})
	return out, state.updated, true
}

// HostKeys returns all known host keys with their first/last timestamps and
// candidate counts. Used to build the /agents listing.
type HostStat struct {
	Host       string
	FirstSeen  time.Time
	LastSeen   time.Time
	Candidates int
}

func (s *Store) HostKeys() []HostStat {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]HostStat, 0, len(s.hosts))
	for host, state := range s.hosts {
		count := 0
		for i := range state.cands {
			if state.cands[i].Proc != nil {
				count++
			}
		}
		out = append(out, HostStat{
			Host:       host,
			FirstSeen:  state.firstSeen,
			LastSeen:   state.updated,
			Candidates: count,
		})
	}
	return out
}

func (s *Store) RemoveHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Fast path for exact key.
	if _, ok := s.hosts[host]; ok {
		delete(s.hosts, host)
		return true
	}

	needle := strings.ToLower(shared.DisplayHost(host))
	for key := range s.hosts {
		if strings.EqualFold(key, host) || strings.ToLower(shared.DisplayHost(key)) == needle {
			delete(s.hosts, key)
			return true
		}
	}
	return false
}

func (s *Store) HostSummaries(staleAfter time.Duration, minScore int, roleFilter map[string]bool, connectedHosts map[string]bool) []shared.HostSummary {
	now := time.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()

	connectedByHost := map[string]bool{}
	connectedByDisplay := map[string]bool{}
	for host := range connectedHosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		connectedByHost[strings.ToLower(host)] = true
		connectedByDisplay[strings.ToLower(shared.DisplayHost(host))] = true
	}

	out := make([]shared.HostSummary, 0, len(s.hosts))
	for host, state := range s.hosts {
		displayHost := shared.DisplayHost(host)
		status := "connected"
		if connectedHosts == nil {
			if staleAfter > 0 && now.Sub(state.updated) > staleAfter {
				status = "disconnected"
			}
		} else {
			mapConnected := connectedByHost[strings.ToLower(host)] || connectedByDisplay[strings.ToLower(displayHost)]
			recentUpdate := !state.updated.IsZero() && now.Sub(state.updated) <= connectedHostFreshness
			if staleAfter > 0 && !state.updated.IsZero() && now.Sub(state.updated) > staleAfter {
				recentUpdate = false
			}
			if !mapConnected || !recentUpdate {
				status = "disconnected"
			}
		}

		summary := shared.HostSummary{
			Host:      displayHost,
			Status:    status,
			FirstSeen: state.firstSeen,
			LastSeen:  state.updated,
		}

		filtered := shared.ApplyScoreAndRoleFilters(state.cands, minScore, roleFilter)
		roleFamilies := map[string]struct{}{}
		for _, cand := range filtered {
			if cand.Proc == nil {
				continue
			}
			if shared.IsProxywatchProcess(cand.Proc) {
				continue
			}
			summary.Processes++
			switch shared.CandidateState(cand) {
			case "tunneling":
				summary.Tunneling++
			default:
				summary.Watch++
			}
			roleFamilies[shared.RoleFamily(cand.Role)] = struct{}{}
		}
		summary.Roles = len(roleFamilies)
		out = append(out, summary)
	}

	sort.Slice(out, func(i, j int) bool {
		iConnected := strings.EqualFold(out[i].Status, "connected")
		jConnected := strings.EqualFold(out[j].Status, "connected")
		if iConnected != jConnected {
			return iConnected
		}
		hostI := out[i].Host
		hostJ := out[j].Host
		if hostI == hostJ {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return hostI < hostJ
	})
	return out
}

func (s *Store) LastUpdate(host string) (time.Time, bool) {
	host = strings.TrimSpace(host)
	if host == "" {
		return time.Time{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.hosts[host]
	if !ok || state.updated.IsZero() {
		return time.Time{}, false
	}
	return state.updated, true
}

type RemoteScanner struct {
	Store       *Store
	StaleAfter  time.Duration
	MinScore    int
	RoleFilter  map[string]bool
	Connected   func() map[string]bool
	Whitelist   *shared.Whitelist
	LingerFor   time.Duration
	LingerCache map[string]shared.LingerEntry
	LastIO      map[int]shared.IOSample

	// PredictCandidate runs the ML predictor on a candidate and records
	// shadow comparison metrics. Parity with standalone Classify().
	PredictCandidate func(c *shared.Candidate, key string)

	// BufferCandidate extracts features and adds to the training buffer.
	// Parity with standalone Classify().
	BufferCandidate func(c *shared.Candidate, key string)
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
	connected := map[string]bool(nil)
	if r.Connected != nil {
		connected = r.Connected()
	}
	hostSummaries := r.Store.HostSummaries(r.StaleAfter, r.MinScore, roleFilter, connected)
	cands := r.Store.Snapshot(r.StaleAfter)
	cands = shared.FilterProxywatchCandidates(cands)
	shared.ApplyIORates(cands, now, &r.LastIO)
	cands = shared.ApplyScoreAndRoleFilters(cands, r.MinScore, roleFilter)
	cands = shared.ApplyCandidateLinger(cands, now, r.LingerFor, &r.LingerCache)
	// Post-linger: correlate exited children with live parents (parity with standalone).
	shared.AggregateLingerChildEvidence(cands, now)
	// Keep role/score filtering authoritative after linger rehydrates stale rows.
	cands = shared.ApplyScoreAndRoleFilters(cands, r.MinScore, roleFilter)
	if app != nil {
		app.SnapshotCandidates = cands
		app.HostSummaries = hostSummaries
	}
	// Apply the master model to incoming candidates and record experience.
	// The server's model accumulates intelligence from ALL agents, making it
	// the most informed authority. It can override agent-local decisions when
	// the aggregated evidence is stronger.
	if len(cands) > 0 {
		expRecords := make([]model.ExperienceRecord, 0, len(cands))
		for i := range cands {
			c := &cands[i]
			if c.Proc == nil {
				continue
			}
			key := serverCandidateKey(c)

			model.RecordObservationForMaturity()

			// Signal-based role inference — kept local for the override
			// tiebreaker logic below. Do NOT assign to c.SuggestedRole — that
			// field stores rank.go's topology decision and must not be
			// overwritten with weaker signal-only inference.
			ruleRole := shared.InferRoleFromSignals(c.Signals, c.ControlSubtype, c.Role)

			// ML prediction — parity with standalone classifier.Classify().
			mlAssigned := false
			if r.PredictCandidate != nil {
				prevRole := c.Role
				r.PredictCandidate(c, key)
				if c.Role != prevRole {
					mlAssigned = true
				}
			}

			// If ML didn't assign (no model loaded), use signal inference.
			if !mlAssigned {
				c.Role = ruleRole
			}

			// Signal override: trust live signals over model when they disagree.
			// Case 1: ML says suspicious, signals say benign → trust signals (prevent FP)
			if mlAssigned && shared.IsControlRole(c.Role) && (ruleRole == "outbound" || ruleRole == "listener") {
				c.Role = ruleRole
				c.Score = 0
			}
			// Case 2: ML says benign, signals say suspicious → trust signals (prevent FN)
			if !shared.IsControlRole(c.Role) && shared.IsControlRole(ruleRole) {
				c.Role = ruleRole
			}

			// Role stability — prevent control-channel → outbound flapping
			// between beacon callbacks. Same logic as standalone classifier.
			if c.Proc != nil {
				scopedPID := c.Proc.Pid
				hist := shared.ProcHistoryByPID[scopedPID]
				if hist == nil {
					hist = &shared.ProcHistory{}
					shared.ProcHistoryByPID[scopedPID] = hist
				}
				if hist.LastRole != "" && c.Role != hist.LastRole {
					prevMal := shared.IsControlRole(hist.LastRole)
					newMal := shared.IsControlRole(c.Role)
					if prevMal && !newMal {
						if now.Sub(hist.LastRoleChange) < shared.MaliciousRoleDemoteCooldown {
							c.Role = hist.LastRole
						}
					}
				}
				if hist.LastRole == c.Role && hist.LastRole != "" {
					hist.RoleStableStreak++
				} else {
					hist.RoleStableStreak = 1
					hist.LastRoleChange = now
				}
				hist.LastRole = c.Role
			}

			// Operator overrides (training labels, kill/whitelist).
			decision := model.ApplyOperatorOverrides(key, c.Role, c.Score, c.Proc,
				c.OutExternal, c.OutInternal, len(c.Listeners) > 0)
			if decision.Override {
				c.Role = decision.Role
				c.Reasons = append(c.Reasons, decision.Reason)
			}

			// Publisher → destination DNS alignment — parity with standalone
			// Classify(). Runs before FP-shape so the evidence tag feeds
			// the publisher-destinations-aligned indicator. Async-cached
			// DNS; never blocks.
			if c.Proc != nil {
				if aligned, tags := shared.EvaluatePublisherDNSAlignment(c); aligned {
					c.Proc.PublisherDNSAligned = true
					c.Proc.OnlineEvidence = append(c.Proc.OnlineEvidence, tags...)
				}
			}

			// Shape-only control-channel demotion — parity with standalone.
			if c.Proc != nil {
				shared.DemoteShapeOnlyControlRole(c)
				shared.UpgradeSleepingBeaconProfile(c)
			}

			// Vendor-update-cadence FP rule — parity with standalone Classify().
			// See shared.ApplyVendorUpdateSuppression: decisive pivot signals
			// always block this demotion.
			shared.ApplyVendorUpdateSuppression(c)

			// Vendor-agnostic FP-shape rule — parity with standalone
			// Classify(). Blocker set (shared.VendorFPBlockerSignals) is
			// the single source of truth for "preserve control-*/tunneling".
			shared.ApplyVendorFPShape(c)
			// Narrow rescue for signed desktop/Electron apps with
			// rich-local-ipc-shape. See shared/vendor_fp_shape.go —
			// parity with standalone Classify().
			shared.ApplyVendorIPCRescue(c)

			// Feed training buffer — parity with standalone classifier.Classify().
			if r.BufferCandidate != nil {
				r.BufferCandidate(c, key)
			}

			// Use final role.
			role := c.Role

			// Track role stability for maturity — parity with standalone.
			if !c.MLActive {
				if profile := model.ResolveProfile(key); profile != nil && profile.ExperienceLastRole != "" {
					model.RecordRoleAssignment(role == profile.ExperienceLastRole, c.Score)
				}
			}

			expRecords = append(expRecords, model.ExperienceRecord{
				ProcessKey:   key,
				Name:         c.Proc.Name,
				Role:         role,
				Score:        c.Score,
				Signals:      c.Signals,
				IOReadBytes:  c.Proc.IOReadBytes,
				IOWriteBytes: c.Proc.IOWriteBytes,
			})
		}
		model.RecordExperience(expRecords)
		model.MaybeSave(now)
	}

	filtered := shared.ApplyWhitelist(cands, r.Whitelist)
	shared.ApplySelection(app, filtered, now)
}

type Server struct {
	Store         *Store
	mu            sync.RWMutex
	agents        map[string]*agentConn
	pending       map[string]pendingCommand
	seq           uint64
	maxMessagesPS int
	serverPin     string
}

type agentConn struct {
	stream   pb.ProxyWatchAgent_StreamCandidatesServer
	peerHost string
	mu       sync.Mutex
	closed   bool
}

type pendingCommand struct {
	agent *agentConn
	ch    chan error
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

func (a *agentConn) Closed() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closed
}

func (a *agentConn) SamePeerHost(other *agentConn) bool {
	if a == nil || other == nil {
		return false
	}
	if a.peerHost == "" || other.peerHost == "" {
		return false
	}
	return strings.EqualFold(a.peerHost, other.peerHost)
}

func (s *Server) StreamCandidates(stream pb.ProxyWatchAgent_StreamCandidatesServer) error {
	if s.Store == nil {
		return fmt.Errorf("store not configured")
	}
	s.ensureRuntimeMaps()

	agent := &agentConn{
		stream:   stream,
		peerHost: streamPeerHost(stream),
	}
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

		// Process training telemetry from agents.
		if batch := msg.TrainingBatch; batch != nil {
			s.processTrainingBatch(batch)
		}

		if resp := msg.CommandResponse; resp != nil {
			s.handleCommandResponse(agent, resp)
		}
	}
}

func (s *Server) Enroll(ctx context.Context, req *pb.EnrollRequest) (*pb.EnrollResponse, error) {
	_ = ctx
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "missing enrollment request")
	}
	token := strings.TrimSpace(auth.ExpectedAgentToken())
	if token == "" {
		return nil, status.Error(codes.FailedPrecondition, "agent token not configured on server")
	}
	clientNonce := strings.TrimSpace(req.ClientNonce)
	clientProof := strings.TrimSpace(req.ClientProof)
	if clientNonce == "" || clientProof == "" {
		return nil, status.Error(codes.InvalidArgument, "missing enrollment proof")
	}
	if !auth.WithinEnrollmentSkew(req.ClientUnix, time.Now().UTC()) {
		return nil, status.Error(codes.Unauthenticated, "enrollment request expired")
	}
	expectedClientProof := auth.BuildEnrollClientProof(token, clientNonce, req.ClientUnix)
	if !auth.ConstantTimeHexEqual(clientProof, expectedClientProof) {
		return nil, status.Error(codes.Unauthenticated, "invalid enrollment proof")
	}

	serverNonce, err := auth.RandomNonceBase64(24)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate enrollment nonce")
	}
	serverPin := strings.ToLower(strings.TrimSpace(s.serverPin))
	if !auth.ValidFingerprintHex(serverPin) {
		return nil, status.Error(codes.Internal, "server fingerprint unavailable")
	}
	serverProof := auth.BuildEnrollServerProof(token, clientNonce, req.ClientUnix, serverNonce, serverPin)
	return &pb.EnrollResponse{
		ServerNonce:       serverNonce,
		ServerUnix:        time.Now().UTC().Unix(),
		ServerFingerprint: serverPin,
		ServerProof:       serverProof,
	}, nil
}

func (s *Server) ensureRuntimeMaps() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.agents == nil {
		s.agents = make(map[string]*agentConn)
	}
	if s.pending == nil {
		s.pending = make(map[string]pendingCommand)
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

	host := strings.TrimSpace(currentHost)
	if host == "" {
		nextHost := sanitizeHostID(env.HostId)
		if nextHost == "" {
			nextHost = "unknown"
		}
		host = s.registerAgent(nextHost, agent)
	}

	ts := time.Now().UTC()
	cands := envelopeCandidatesToShared(env.Candidates, host)
	cands = shared.FilterProxywatchCandidates(cands)
	// Apply server-side FP-shape transforms BEFORE storing. The store is
	// read by /fp-report/<host> (via SnapshotHost) and by RemoteScanner
	// which takes copies via Snapshot, so mutations applied later in
	// Refresh don't write back. Doing the demotion here guarantees the
	// debug API and the TUI see the same post-policy classification.
	for i := range cands {
		if cands[i].Proc == nil {
			continue
		}
		shared.DemoteShapeOnlyControlRole(&cands[i])
		shared.UpgradeSleepingBeaconProfile(&cands[i])
	}
	s.Store.Update(host, ts, cands)
	return host
}

const (
	maxCandidatesPerEnvelope = 5000
	maxConnsPerCandidate     = 10000
	maxSignalsPerCandidate   = 200
	maxReasonsPerCandidate   = 50
	maxStringFieldLen        = 4096
)

func envelopeCandidatesToShared(in []*pb.Candidate, host string) []shared.Candidate {
	// Cap candidate count to prevent memory exhaustion from rogue agents.
	if len(in) > maxCandidatesPerEnvelope {
		in = in[:maxCandidatesPerEnvelope]
	}
	out := make([]shared.Candidate, 0, len(in))
	for _, c := range in {
		if c == nil {
			continue
		}
		// Cap per-candidate arrays.
		if len(c.Conns) > maxConnsPerCandidate {
			c.Conns = c.Conns[:maxConnsPerCandidate]
		}
		if len(c.Signals) > maxSignalsPerCandidate {
			c.Signals = c.Signals[:maxSignalsPerCandidate]
		}
		if len(c.Reasons) > maxReasonsPerCandidate {
			c.Reasons = c.Reasons[:maxReasonsPerCandidate]
		}
		out = append(out, FromPBCandidate(c, host))
	}
	return out
}

func (s *Server) registerAgent(host string, agent *agentConn) string {
	host = strings.TrimSpace(host)
	if host == "" {
		host = "unknown"
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, cur := range s.agents {
		// A single stream should map to exactly one host key.
		if cur == agent && !strings.EqualFold(key, host) {
			delete(s.agents, key)
		}
	}

	// Prevent a new stream from silently taking over an existing host key.
	if cur, ok := s.agents[host]; ok && cur != nil && cur != agent {
		// Reclaim the base host key when a stream is stale/closed, or when the
		// reconnect is from the same peer host (same source IP, new source port).
		// Keep suffix behavior for truly concurrent peers that share host ids.
		if cur.Closed() || cur.SamePeerHost(agent) || s.hostStreamLikelyStale(host) {
			cur.Close()
			s.agents[host] = agent
			return host
		}
		base := host
		for suffix := 2; ; suffix++ {
			candidate := fmt.Sprintf("%s-%d", base, suffix)
			if existing, used := s.agents[candidate]; !used || existing == agent {
				host = candidate
				break
			}
		}
	}
	s.agents[host] = agent
	return host
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

func (s *Server) hostStreamLikelyStale(host string) bool {
	if s == nil || s.Store == nil {
		return false
	}
	last, ok := s.Store.LastUpdate(host)
	if !ok {
		return false
	}
	return time.Since(last) > reconnectHostTakeoverAfter
}

// serverCandidateKey delegates to shared.CandidateBehaviorKey — single source of truth.
func serverCandidateKey(c *shared.Candidate) string {
	return shared.CandidateBehaviorKey(c)
}

func streamPeerHost(stream pb.ProxyWatchAgent_StreamCandidatesServer) string {
	if stream == nil {
		return ""
	}
	info, ok := peer.FromContext(stream.Context())
	if !ok || info == nil || info.Addr == nil {
		return ""
	}
	return normalizePeerHost(info.Addr.String())
}

func normalizePeerHost(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Keep best-effort host matching when the peer address has no port.
		host = addr
	}
	host = strings.TrimSpace(host)
	return strings.Trim(host, "[]")
}

func (s *Server) ConnectedHosts() map[string]bool {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make(map[string]bool, len(s.agents))
	for host, conn := range s.agents {
		if conn == nil {
			continue
		}
		out[host] = true
	}
	return out
}

func (s *Server) HostConnected(host string) bool {
	if s == nil {
		return false
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	targetDisplay := strings.ToLower(shared.DisplayHost(host))

	s.mu.RLock()
	defer s.mu.RUnlock()
	for key, conn := range s.agents {
		if conn == nil {
			continue
		}
		if strings.EqualFold(key, host) || strings.ToLower(shared.DisplayHost(key)) == targetDisplay {
			return true
		}
	}
	return false
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
		s.pending = make(map[string]pendingCommand)
	}
	s.pending[reqID] = pendingCommand{
		agent: agent,
		ch:    respCh,
	}
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.pending, reqID)
		s.mu.Unlock()
	}()

	cmd := &pb.ServerCommand{
		RequestId: reqID,
		Type:      "kill",
		Pid:       clampInt32(pid),
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

func (s *Server) handleCommandResponse(source *agentConn, resp *pb.CommandResponse) {
	if resp == nil {
		return
	}
	s.mu.RLock()
	pending := s.pending[resp.RequestId]
	s.mu.RUnlock()
	if pending.ch == nil {
		return
	}
	// Bind responses to the originating authenticated stream.
	if pending.agent != nil && source != nil && pending.agent != source {
		return
	}
	if resp.Success {
		select {
		case pending.ch <- nil:
		default:
		}
		return
	}
	if resp.Error == "" {
		select {
		case pending.ch <- errors.New("remote kill failed"):
		default:
		}
		return
	}
	select {
	case pending.ch <- errors.New(resp.Error):
	default:
	}
}

// ModelPushHandler is set externally to handle model updates from the server.
// Called on agents when they receive a model_push command.
var ModelPushHandler func(artifact *pb.ModelArtifact) error

// TrainingBatchHandler is set externally to process training data from agents.
// This avoids import cycles — the handler is wired in main.go.
var TrainingBatchHandler func(hostID string, records []*pb.TrainingRecord)

func (s *Server) processTrainingBatch(batch *pb.TrainingBatch) {
	if batch == nil || len(batch.Records) == 0 {
		return
	}
	if TrainingBatchHandler == nil {
		return
	}
	// Cap records to prevent abuse.
	records := batch.Records
	if len(records) > 5000 {
		records = records[:5000]
	}
	shared.LogInfo("server", "received training batch from %s: %d records (schema %s)",
		batch.HostId, len(records), batch.SchemaHash)
	TrainingBatchHandler(batch.HostId, records)
}

func ListenAndServe(addr string, store *Store) (*Server, *grpc.Server, net.Listener, error) {
	if store == nil {
		return nil, nil, nil, fmt.Errorf("store is nil")
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, nil, err
	}

	tlsCfg, err := auth.ServerTLSConfig()
	if err != nil {
		return nil, nil, nil, err
	}
	serverPin, err := auth.TLSConfigLeafFingerprint(tlsCfg)
	if err != nil {
		return nil, nil, nil, err
	}
	srv := &Server{Store: store, maxMessagesPS: 200, serverPin: serverPin}
	grpcServer := grpc.NewServer(
		grpc.ForceServerCodec(auth.JSONCodec()),
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.StreamInterceptor(auth.AgentStreamAuthInterceptor()),
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
