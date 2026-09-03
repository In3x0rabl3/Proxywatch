package pcap

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"proxywatch/internal/detection"
	"proxywatch/internal/detection/model"
	"proxywatch/internal/detection/output"
	"proxywatch/internal/detection/scoring"
	"proxywatch/internal/shared"
)

// SyntheticPIDBase is the starting PID for offline-attributed synthetic
// processes. Chosen well above any plausible live PID range so cross-
// contamination with live capture is impossible. Each distinct local IP
// observed in a pcap gets a sequential PID starting here.
const SyntheticPIDBase = 0x7fff_0000

// Window is the snapshot window cadence used during replay. Matches the
// live capture's ~1s tick so timing-based detectors (beacon-interval,
// syn-cycle, session-persistence) see the same temporal granularity offline
// as they do live.
const Window = 1 * time.Second

// IngestProgress is sent on the progress channel periodically during
// ingest so the UI can render a live counter + spinner. Stage values are
// "parsing", "replaying", "done", or "error".
type IngestProgress struct {
	Stage            string
	PacketsProcessed uint64
	FlowsObserved    int
	WindowsReplayed  int
	WindowsTotal     int
}

// IngestResult is the final payload sent on the result channel when
// IngestPCAP completes (successfully or otherwise). Candidates is the
// last replay window's classification — the authoritative state at pcap
// end-time. UnionSignals/UnionReasons accumulate every signal/reason
// fired across all windows so detectors that fired-then-stopped (e.g. a
// beacon that disconnected mid-pcap) still surface in the report.
type IngestResult struct {
	Path          string
	PacketsTotal  uint64
	FlowsTotal    int
	WindowsTotal  int
	PcapStart     time.Time
	PcapEnd       time.Time
	LocalIPs      []string
	SyntheticPIDs []int
	Candidates    []shared.Candidate
	UnionSignals  map[int][]string
	UnionReasons  map[int][]string
	// Per-synthetic-PID totals across the whole pcap, so the packet
	// view can show "for this host, X packets across Y flows totalling
	// Z bytes" without recomputing from the per-window snapshot.
	PacketsByPID map[int]uint64
	FlowsByPID   map[int]int
	BytesByPID   map[int]uint64
	// Split byte totals by direction relative to the local host. The
	// offline tunneling gate uses these to require throughput
	// symmetry (a real forwarder shows bytes-in ≈ bytes-out;
	// "server with unrelated outbound client" usually doesn't).
	BytesInByPID  map[int]uint64
	BytesOutByPID map[int]uint64
	// ObservationByPID is the pcap-time span between the candidate's
	// first and last observed packet — i.e. how long we watched this
	// host. Powers the tunneling gate's observation-time floor:
	// short-lived blips don't get to commit to a relay verdict, only
	// candidates we've seen sustained activity from. Same time-base
	// as flow timestamps so the value is meaningful in both one-shot
	// (pcap span) and tail (wallclock-as-it-grows) modes.
	ObservationByPID map[int]time.Duration
	// FirstPacketByPID / LastPacketByPID expose the actual timestamps
	// (not just the duration) so the TUI can render pcap-relative
	// offsets like "T+02:34" and emit Wireshark frame.time filters.
	FirstPacketByPID map[int]time.Time
	LastPacketByPID  map[int]time.Time
	// FirstFrameByPID is the 1-based packet/frame number (matching
	// Wireshark's display) of the earliest packet attributed to this
	// candidate. Lets the TUI show operators a stable identifier
	// they can paste into `frame.number == N` to jump to the start
	// of this finding's traffic in their pcap reader.
	FirstFrameByPID map[int]uint64
	// PerWindowBytesByPID is a chronologically-ordered series of
	// total-bytes-per-analysis-window for each candidate. len matches
	// len(windows). Drives the activity sparkline + peak detection.
	PerWindowBytesByPID map[int][]uint64
	// PeakWindowByPID is the windowEnd timestamp of the
	// highest-bytes window for each candidate. The TUI uses this to
	// suggest a Wireshark filter narrowed to the most active span.
	PeakWindowByPID map[int]time.Time
	// DecisiveFlowsByPID is the top-N (default 5) flows by total
	// bytes per candidate. Lets the TUI emit per-flow Wireshark
	// filters and IOC lists without re-walking the pcap.
	DecisiveFlowsByPID map[int][]FlowSummary
	// HourBucketByPID counts packets per hour-of-day per candidate.
	// Only meaningfully populated for long pcaps (≥4h span);
	// renderer suppresses the heatmap section otherwise.
	HourBucketByPID map[int][24]uint64
	// BytesByEndpointPID is the full per-candidate byte total
	// (every flow attributed to this endpoint, both directions).
	// Distinct from BytesByPID (per-IP roll-up) and from the sum of
	// DecisiveFlowsByPID (top-5 only). The TUI uses this for the
	// per-row BYTES column + threat-summary host roll-up so the
	// number stays consistent regardless of which subset of flows
	// the renderer enumerates.
	BytesByEndpointPID map[int]uint64
	// FlowsMeta surfaces per-flow metadata extracted during ingest so
	// alternative-grouping projections (JA3, ASN, session, behavior)
	// in the TUI can read flow-level attributes without re-parsing
	// packets. Keyed on the canonical flow ID (LocalAddr:LocalPort →
	// RemoteAddr:RemotePort). Populated by buildPcapAttribution.
	FlowsMeta map[FlowID]FlowMeta
	// BeaconShapeByPID holds the TS+DS statistical scores for each
	// cluster candidate that has ≥4 flows (the minimum needed for ≥3
	// inter-connection intervals). Used by the post-pass beacon signal
	// stampers to fire `beacon-interval-statistical` and
	// `beacon-payload-size-uniform` on clusters whose flow timing /
	// payload sizes are uniform enough to be a real beacon.
	BeaconShapeByPID map[int]BeaconShape
	// OpenConnByPID counts flows that were still "open" at the
	// analysis boundary (synSeen && !finSeen && !rstSeen). Pairs with
	// `session-still-open-at-boundary` — a strong corroborating
	// signal that the cluster is a long-running interactive control
	// channel, not a transient series of HTTPS API calls.
	OpenConnByPID map[int]int
	// Timeline is one entry per replay window in chronological order,
	// holding the worst-severity state observed across all candidates
	// in that window. Drives the top-of-view tunneling timeline strip
	// in the pcap analyzer view — analysts see at a glance the exact
	// second a tunnel opened or quieted, like a heart-rate trace for
	// the capture.
	Timeline []TimelineWindow
	Warnings []string
	Err      error
}

// BeaconShape carries the statistical sub-scores for a cluster
// candidate. TS scores the inter-connection interval
// distribution; DS scores the per-flow payload size distribution.
// Both range [0, 1] — higher means more uniform / more beacon-like.
// SampleCount is the number of flows that fed the score (always ≥4
// when scored; clusters with fewer flows skip scoring).
type BeaconShape struct {
	TSScore     float64
	DSScore     float64
	SampleCount int
}

// FlowID canonicalizes a 5-tuple flow for cross-pass lookup. Used as
// the key for FlowsMeta in IngestResult so view-time projections (JA3,
// ASN, session, behavior groupings) can resolve flow-level attributes
// from a per-connection ConnectionInfo without re-walking packets.
type FlowID struct {
	LocalIP    string
	LocalPort  int
	RemoteIP   string
	RemotePort int
}

// FlowMeta is the operator-relevant per-flow metadata surfaced by
// pcap ingest for view-time projections. All fields are best-effort —
// flows that didn't carry TLS / DNS / SSH leave the corresponding
// fields empty.
type FlowMeta struct {
	JA3       string // client TLS ClientHello fingerprint
	JA3S      string // server TLS ServerHello fingerprint
	SNI       string // first SNI extension hostname
	HTTPHost  string // HTTP/1.x Host header
	HTTPURI   string // HTTP/1.x request URI
	BytesSum  uint64 // bytes both directions
	FirstSeen time.Time
	LastSeen  time.Time
}

// TimelineWindow summarizes one replay window's per-host state mix
// for the timeline strip. Severity is encoded compactly so the
// renderer can pick a glyph + color without recomputing.
type TimelineWindow struct {
	WindowEndAt    time.Time
	TunnelingCount int
	ControlPivot   int
	ControlChannel int
	Analyzing      int
	Outbound       int
	Listener       int
	// Severity is the precomputed worst-of state for this window:
	// 0 = quiet (no candidates / only outbound)
	// 1 = analyzing
	// 2 = beacon observed somewhere
	// 3 = pivot observed (relay topology)
	// 4 = tunneling actively flowing
	Severity uint8
}

// FlowSummary is the IngestResult-exposed projection of a single
// flow's contribution to a candidate. Used by the TUI to print
// per-flow Wireshark filters and IOC lists. Bytes are total
// init-to-resp + resp-to-init (the operator-facing view).
type FlowSummary struct {
	Proto           string
	LocalIP         string
	LocalPort       int
	RemoteIP        string
	RemotePort      int
	BytesInitToResp uint64
	BytesRespToInit uint64
	FirstPacket     time.Time
	LastPacket      time.Time
}

// summarizeWindow tallies a single replay window's per-state counts
// for the timeline strip. Severity is the worst-of state observed
// across all candidates so the strip's per-cell color tracks the
// most-suspicious thing happening in that second.
//
// Acquires ClassifyMu.RLock for the duration of the iteration
// because CandidateStateUnsafe reads multiple global classifier maps
// (PivotUntil, ConnFirstSeen, ConnKeysByPID, ProcHistoryByPID). The
// pcap classify loop runs OUTSIDE the lock between windows; if a
// concurrent live-scanner Refresh runs Classify in the meantime, its
// exclusive Lock would race our reads and trip the runtime's
// concurrent-map panic. RLock cooperates with that exclusive Lock.
func summarizeWindow(windowEnd time.Time, cands []shared.Candidate) TimelineWindow {
	tw := TimelineWindow{WindowEndAt: windowEnd}
	shared.ClassifyMu.RLock()
	defer shared.ClassifyMu.RUnlock()
	for _, c := range cands {
		if c.Proc == nil {
			continue
		}
		state := shared.CandidateStateUnsafe(c)
		family := shared.RoleFamily(c.Role)
		switch family {
		case "pivot":
			tw.ControlPivot++
		case "beacon":
			tw.ControlChannel++
		case "outbound":
			tw.Outbound++
			// Outbound candidates with decisive C2 signals get
			// promoted to beacon by the offline findings
			// filter (the live ML/scoring layer does the actual
			// promotion in normal mode, but pcap analysis runs
			// without it). Mirror that promotion here so the
			// timeline's "beacon" tally matches what the
			// FINDINGS table renders — without this the bar shows
			// "channel 0%" while findings are full of beacon
			// rows. Signals captured by hasOutboundC2Evidence
			// below mirror views/pcap.go:hasOutboundControlChannelEvidence.
			if hasOutboundC2Evidence(c.Signals) {
				tw.ControlChannel++
			}
		case "listener":
			tw.Listener++
		}
		// Any candidate that owns at least one bound port — even when
		// the role is something else (pivot via child-tunnel
		// promotion, e.g.) — counts as a listener for the timeline's
		// "listener present in this window" tally. Operators reading
		// the timeline strip want to know "did anything bind a port
		// here" regardless of whether it got promoted.
		if len(c.Listeners) > 0 || len(c.UDPListeners) > 0 {
			if shared.RoleFamily(c.Role) != "listener" {
				tw.Listener++
			}
		}
		switch state {
		case "tunneling":
			tw.TunnelingCount++
			if tw.Severity < 4 {
				tw.Severity = 4
			}
		case "analyzing":
			tw.Analyzing++
			if tw.Severity < 1 {
				tw.Severity = 1
			}
		}
		// Bump severity on confirmed beacon-* roles even when the
		// cycle's state lands on watch (no fresh data flow yet).
		if shared.RoleFamily(c.Role) == "pivot" && tw.Severity < 3 {
			tw.Severity = 3
		} else if shared.RoleFamily(c.Role) == "beacon" && tw.Severity < 2 {
			tw.Severity = 2
		}
	}
	return tw
}

// hasOutboundC2Evidence mirrors the offline findings filter's
// outbound→beacon promotion gate so the Timeline's
// `ControlChannel` tally counts the same set of candidates the
// FINDINGS table promotes. Kept in sync with views/pcap.go's
// hasOutboundControlChannelEvidence — duplicated here because the
// pcap package can't import the views package (would create a cycle).
//
// CDN-fronted-C2 alone is sufficient (the signal is precise, rarely
// fires on real CDN traffic). Persistent single-peer control channel
// + a hard beacon shape (rotation / static crypto / HTTP beacon /
// confirmed interval) is also distinctive enough to call out offline.
func hasOutboundC2Evidence(signals []string) bool {
	hasSig := func(want string) bool {
		for _, s := range signals {
			if s == want {
				return true
			}
		}
		return false
	}
	if hasSig("cdn-fronted-c2-candidate") {
		return true
	}
	if hasSig("session-persistent-channel") {
		if hasSig("beacon-endpoint-rotation") || hasSig("beacon-static-crypto-likely") ||
			hasSig("beacon-http-channel") || hasSig("beacon-interval-confirmed") {
			return true
		}
	}
	return false
}

// flowKey identifies a TCP flow by its 5-tuple in canonical (initiator,
// responder) order. The first SYN seen pins the orientation.
type flowKey struct {
	InitIP   string
	InitPort int
	RespIP   string
	RespPort int
}

type flowState struct {
	key         flowKey
	isUDP       bool // true for UDP flows (DNS), false for TCP
	firstPacket time.Time
	lastPacket  time.Time
	// firstFrameNum is the 1-based packet index (a.k.a. frame number,
	// matching Wireshark's display) of the flow's earliest observed
	// packet. Surfaced via IngestResult.FirstFrameByPID so the TUI
	// can show operators a stable pcap-local reference they can paste
	// into `frame.number == N` to jump straight to the packet that
	// kicked the flow off.
	firstFrameNum   uint64
	synSeen         bool
	synAckSeen      bool
	finSeen         bool
	rstSeen         bool
	bytesInitToResp uint64
	bytesRespToInit uint64
	packetsTotal    int
	// bytesByWindow records actual per-window payload bytes (sparse,
	// only windows with traffic have entries; key is window index
	// relative to pcapStart). Drives the timeline bar's per-window
	// activity matrix so cells light up only where the flow had
	// real packets, not where the uniform-distribution estimate
	// would have spread bytes evenly across the [first, last] range.
	bytesByWindow map[int]uint64
	// HTTP-passive fields — populated by parseHTTPRequest the FIRST
	// time the initiator-side payload looks like an HTTP request line.
	// Re-parses are skipped (httpParseAttempted) so multi-request
	// keepalive flows record only the first request's headers (the
	// most diagnostic — beacons typically open a fresh connection per
	// callback so the first request tells the whole story).
	httpParseAttempted bool
	httpURI            string
	httpHost           string
	httpUserAgent      string
	// HTTP response side — populated by parseHTTPResponseIntoFlow on
	// the FIRST responder-side payload that begins with "HTTP/1.".
	// Captures status / Content-Type / Content-Length / Server so the
	// post-pass enricher can match Mythic-style C2 response shapes.
	httpRespParseAttempted bool
	httpRespStatus         int
	httpRespContentType    string
	httpRespContentLength  int
	httpRespServer         string

	// TLS-passive fields — populated by parseTLSClientHello the FIRST
	// time the initiator-side payload begins with a TLS handshake
	// record (0x16 0x03 ...). One ClientHello per flow; subsequent
	// handshakes (TLS 1.3 post-handshake auth, renegotiation) are
	// skipped via tlsParseAttempted. Yields JA3 hash + SNI for the
	// post-pass C2 fingerprint matcher.
	tlsParseAttempted bool
	tlsJA3            string
	tlsJA3Raw         string
	tlsSNI            string
	tlsALPN           []string
	// ServerHello side: tlsServerParseAttempted gates one parse on the
	// first responder-side handshake record. Records JA3S hash for the
	// post-pass C2 redirector matcher.
	tlsServerParseAttempted bool
	tlsJA3S                 string

	// SSH banner extraction — gated on the "SSH-" magic prefix on
	// either side of the flow. We capture the SOFTWARE TOKEN from the
	// first banner sent by EACH peer (initiator + responder may run
	// different SSH stacks; sshd-z reverse pivot is detected by the
	// SERVER banner mismatching the host's expected stack).
	sshClientBannerAttempted bool
	sshClientBanner          string
	sshClientSoftware        string
	sshServerBannerAttempted bool
	sshServerBanner          string
	sshServerSoftware        string
}


// StreamingBatchSize is how many windows to process before emitting an
// intermediate result during streaming one-shot analysis. Lower values
// give more responsive display but increase overhead.
const StreamingBatchSize = 16

// IngestWithStreaming is like IngestWithProgress but emits intermediate
// IngestResult snapshots to resultCh as windows are processed. This enables
// real-time findings display during one-shot analysis (like continuous mode)
// and provides the timeline data needed for playback controls.
//
// The final result has WindowsReplayed == WindowsTotal in the last progress
// message. Caller should close resultCh after the function returns.
func IngestWithStreaming(ctx context.Context, path string, progressCh chan<- IngestProgress, resultCh chan<- IngestResult) IngestResult {
	shared.PcapModeActive.Store(true)
	defer shared.PcapModeActive.Store(false)
	result := IngestResult{Path: path}

	send := func(p IngestProgress) {
		if progressCh == nil {
			return
		}
		select {
		case progressCh <- p:
		default:
		}
	}
	emit := func(r IngestResult) {
		if resultCh == nil {
			return
		}
		select {
		case resultCh <- r:
		default:
		}
	}

	send(IngestProgress{Stage: "parsing"})

	flows, dnsByHost, packets, pcapStart, pcapEnd, warnings, err := walkPcap(ctx, path)
	result.Warnings = warnings
	if err != nil {
		result.Err = err
		send(IngestProgress{Stage: "error"})
		return result
	}
	result.PacketsTotal = packets
	result.FlowsTotal = len(flows)
	result.PcapStart = pcapStart
	result.PcapEnd = pcapEnd

	if len(flows) == 0 {
		send(IngestProgress{Stage: "done"})
		return result
	}

	reorientSynlessFlows(flows)

	shift := time.Now().Sub(pcapStart)
	for _, st := range flows {
		st.firstPacket = st.firstPacket.Add(shift)
		st.lastPacket = st.lastPacket.Add(shift)
	}
	shiftedStart := pcapStart.Add(shift)
	shiftedEnd := pcapEnd.Add(shift)
	shared.PcapClockNanos.Store(shiftedEnd.UnixNano())
	defer shared.PcapClockNanos.Store(0)

	unshift := func(t time.Time) time.Time {
		if t.IsZero() {
			return t
		}
		return t.Add(-shift)
	}

	prevStartedAt := shared.ProxywatchStartedAt
	shared.ProxywatchStartedAt = shiftedStart.Add(-10 * shared.StartupGracePeriod)
	defer func() { shared.ProxywatchStartedAt = prevStartedAt }()

	localIPs := inferLocalIPs(flows)
	result.LocalIPs = localIPs
	pidByIP := assignSyntheticPIDs(localIPs)
	attr := buildPcapAttribution(sortFlowsForReplay(flows), localIPs)
	for _, pid := range attr.allPIDs {
		result.SyntheticPIDs = append(result.SyntheticPIDs, pid)
	}
	sort.Ints(result.SyntheticPIDs)

	resetSyntheticPIDState(result.SyntheticPIDs)
	defer cleanupSyntheticPIDState(result.SyntheticPIDs)

	sortedFlows := sortFlowsForReplay(flows)

	// Build per-PID flow accounting for intermediate results
	bumpRange := func(m map[int]time.Time, pid int, t time.Time, wantMin bool) {
		if t.IsZero() {
			return
		}
		existing, ok := m[pid]
		if !ok {
			m[pid] = t
			return
		}
		if wantMin && t.Before(existing) {
			m[pid] = t
		}
		if !wantMin && t.After(existing) {
			m[pid] = t
		}
	}
	bumpFrame := func(pid int, frame uint64) {
		if frame == 0 {
			return
		}
		if existing, ok := result.FirstFrameByPID[pid]; !ok || frame < existing {
			result.FirstFrameByPID[pid] = frame
		}
	}
	result.FirstPacketByPID = make(map[int]time.Time, len(attr.allPIDs))
	result.LastPacketByPID = make(map[int]time.Time, len(attr.allPIDs))
	result.FirstFrameByPID = make(map[int]uint64, len(attr.allPIDs))
	result.HourBucketByPID = make(map[int][24]uint64, len(attr.allPIDs))
	result.BytesByEndpointPID = make(map[int]uint64, len(attr.allPIDs))
	flowsByEndpointPID := make(map[int][]FlowSummary, len(attr.allPIDs))
	pcapSpanHours := pcapEnd.Sub(pcapStart).Hours()

	addEndpointBytes := func(pid int, st *flowState, summary FlowSummary) {
		bumpRange(result.FirstPacketByPID, pid, unshift(st.firstPacket), true)
		bumpRange(result.LastPacketByPID, pid, unshift(st.lastPacket), false)
		bumpFrame(pid, st.firstFrameNum)
		result.BytesByEndpointPID[pid] += st.bytesInitToResp + st.bytesRespToInit
		flowsByEndpointPID[pid] = append(flowsByEndpointPID[pid], summary)
		if pcapSpanHours >= 1 {
			hour := st.firstPacket.Hour()
			if hour >= 0 && hour < 24 {
				bucket := result.HourBucketByPID[pid]
				bucket[hour] += uint64(st.packetsTotal)
				result.HourBucketByPID[pid] = bucket
			}
		}
	}
	for _, st := range sortedFlows {
		summary := FlowSummary{
			Proto:           "tcp",
			LocalIP:         st.key.InitIP,
			LocalPort:       st.key.InitPort,
			RemoteIP:        st.key.RespIP,
			RemotePort:      st.key.RespPort,
			BytesInitToResp: st.bytesInitToResp,
			BytesRespToInit: st.bytesRespToInit,
			FirstPacket:     unshift(st.firstPacket),
			LastPacket:      unshift(st.lastPacket),
		}
		// Per-IP stats
		if pid, ok := pidByIP[st.key.InitIP]; ok {
			bumpRange(result.FirstPacketByPID, pid, unshift(st.firstPacket), true)
			bumpRange(result.LastPacketByPID, pid, unshift(st.lastPacket), false)
		}
		// Per-endpoint stats
		if epPID, ok := attr.outboundFlowPIDFor(st.key.InitIP, st.key.RespIP, st.key.RespPort); ok {
			addEndpointBytes(epPID, st, summary)
		}
	}

	windows := buildWindows(shiftedStart, shiftedEnd)
	result.WindowsTotal = len(windows)
	send(IngestProgress{Stage: "replaying", FlowsObserved: len(flows), WindowsTotal: len(windows)})

	// Per-window byte tracking
	result.PerWindowBytesByPID = make(map[int][]uint64, len(attr.allPIDs))
	for _, pid := range attr.allPIDs {
		result.PerWindowBytesByPID[pid] = make([]uint64, len(windows))
	}
	for _, st := range sortedFlows {
		if len(st.bytesByWindow) == 0 {
			continue
		}
		for wi, bytes := range st.bytesByWindow {
			if bytes == 0 || wi < 0 || wi >= len(windows) {
				continue
			}
			if epPID, ok := attr.outboundPIDFor(st.key.InitIP, st.key.RespIP); ok {
				result.PerWindowBytesByPID[epPID][wi] += bytes
			}
			if flowPID, ok := attr.outboundFlowPIDFor(st.key.InitIP, st.key.RespIP, st.key.RespPort); ok {
				result.PerWindowBytesByPID[flowPID][wi] += bytes
			}
			if epPID, ok := attr.listenerPID[attr.listenerKey(st.key.RespIP, st.key.RespPort)]; ok {
				result.PerWindowBytesByPID[epPID][wi] += bytes
			}
		}
	}

	unionSignals := make(map[int][]string)
	unionReasons := make(map[int][]string)
	mergeUnion := func(pid int, items []string, dst map[int][]string) {
		if len(items) == 0 {
			return
		}
		seen := make(map[string]struct{}, len(dst[pid]))
		for _, s := range dst[pid] {
			seen[s] = struct{}{}
		}
		for _, s := range items {
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			dst[pid] = append(dst[pid], s)
		}
	}

	var lastCands []shared.Candidate
	result.Timeline = make([]TimelineWindow, 0, len(windows))

	for i, windowEnd := range windows {
		select {
		case <-ctx.Done():
			result.Err = ctx.Err()
			send(IngestProgress{Stage: "error"})
			return result
		default:
		}

		snap := buildSnapshotForWindow(sortedFlows, attr, localIPs, windowEnd, windows)
		cands := detection.Classify(snap, shared.ClassifyOptions{HostScope: "pcap-replay"}, nil)

		result.Timeline = append(result.Timeline, summarizeWindow(unshift(windowEnd), cands))

		for _, c := range cands {
			if c.Proc == nil {
				continue
			}
			mergeUnion(c.Proc.Pid, c.Signals, unionSignals)
			mergeUnion(c.Proc.Pid, c.Reasons, unionReasons)
		}
		lastCands = cands

		// Emit intermediate result every StreamingBatchSize windows
		if (i+1)%StreamingBatchSize == 0 {
			intermediate := IngestResult{
				Path:                result.Path,
				PacketsTotal:        result.PacketsTotal,
				FlowsTotal:          result.FlowsTotal,
				PcapStart:           result.PcapStart,
				PcapEnd:             result.PcapEnd,
				LocalIPs:            result.LocalIPs,
				SyntheticPIDs:       result.SyntheticPIDs,
				Timeline:            append([]TimelineWindow(nil), result.Timeline...),
				WindowsTotal:        result.WindowsTotal,
				Candidates:          append([]shared.Candidate(nil), cands...),
				UnionSignals:        copyStrSliceMap(unionSignals),
				UnionReasons:        copyStrSliceMap(unionReasons),
				FirstPacketByPID:    result.FirstPacketByPID,
				LastPacketByPID:     result.LastPacketByPID,
				BytesByEndpointPID:  result.BytesByEndpointPID,
				FirstFrameByPID:     result.FirstFrameByPID,
				PerWindowBytesByPID: result.PerWindowBytesByPID,
			}
			emit(intermediate)

			send(IngestProgress{
				Stage:            "replaying",
				PacketsProcessed: packets,
				FlowsObserved:    len(flows),
				WindowsReplayed:  i + 1,
				WindowsTotal:     len(windows),
			})
		}
	}

	// Stabilization pass
	const stabilizationPasses = 3
	if len(windows) > 0 {
		lastWindowEnd := windows[len(windows)-1]
		for p := 0; p < stabilizationPasses; p++ {
			select {
			case <-ctx.Done():
				result.Err = ctx.Err()
				send(IngestProgress{Stage: "error"})
				return result
			default:
			}
			snap := buildSnapshotForWindow(sortedFlows, attr, localIPs, lastWindowEnd, windows)
			cands := detection.Classify(snap, shared.ClassifyOptions{HostScope: "pcap-replay"}, nil)
			for _, c := range cands {
				if c.Proc == nil {
					continue
				}
				mergeUnion(c.Proc.Pid, c.Signals, unionSignals)
				mergeUnion(c.Proc.Pid, c.Reasons, unionReasons)
			}
			lastCands = cands
		}
	}

	// Post-processing passes (same as IngestWithProgress)
	processes := make(map[int]*shared.ProcessInfo, len(lastCands))
	for i := range lastCands {
		if lastCands[i].Proc != nil {
			processes[lastCands[i].Proc.Pid] = lastCands[i].Proc
		}
	}
	now := shared.PcapNow()
	scoring.AggregateChildTunnelEvidence(lastCands, processes, now)
	enrichPcapWithCrossCandidatePivotSignals(lastCands)
	enrichPcapWithHTTPSignals(sortedFlows, attr, lastCands)
	enrichPcapWithTLSSignals(sortedFlows, attr, lastCands)
	enrichPcapWithSSHBannerSignals(sortedFlows, attr, lastCands)
	enrichPcapWithDNSSignals(dnsByHost, lastCands)
	enrichPcapWithRareSignatures(sortedFlows, attr, lastCands)
	scoring.ApplyPivotLinger(lastCands, processes, now)
	restoreSyntheticRoleFromAnalyzing(lastCands)
	demoteUnderEvidencedSyntheticPivots(lastCands)
	shared.ApplyPcapModeRoleGuard(lastCands)
	promoteHostPivotsWhenC2Active(lastCands)

	// Shape/rhythm signal stamping
	result.BeaconShapeByPID = make(map[int]BeaconShape, len(flowsByEndpointPID))
	for pid, list := range flowsByEndpointPID {
		if shape, ok := computeBeaconShape(list); ok {
			result.BeaconShapeByPID[pid] = shape
		}
	}
	// HourBucketByPID was already populated inline during flow processing
	result.OpenConnByPID = countOpenConnsByPID(sortedFlows, attr)
	stampBeaconShapeSignals(lastCands, result.BeaconShapeByPID)
	stampDayRhythmSignals(lastCands, result.HourBucketByPID)
	stampStrobeSignals(lastCands, flowsByEndpointPID)
	stampPrevalenceSignals(lastCands, sortedFlows)
	stampSMBLateralSignals(lastCands, sortedFlows, attr)
	stampOpenBoundarySignals(lastCands, result.OpenConnByPID)
	shared.ApplyPcapModeRoleGuard(lastCands)
	demoteBenignLANDiscoveryClusters(lastCands)
	applyPcapOperatorLabels(lastCands)

	for _, c := range lastCands {
		if c.Proc == nil {
			continue
		}
		mergeUnion(c.Proc.Pid, c.Signals, unionSignals)
		mergeUnion(c.Proc.Pid, c.Reasons, unionReasons)
	}

	shared.ClassifyMu.RLock()
	output.UpdateDebugAPISnapshot(output.NextDetectionOutputCycle(), "pcap-replay", lastCands)
	shared.ClassifyMu.RUnlock()

	result.Candidates = lastCands
	result.UnionSignals = unionSignals
	result.UnionReasons = unionReasons

	// Final result
	emit(result)
	send(IngestProgress{Stage: "done", PacketsProcessed: packets, FlowsObserved: len(flows), WindowsReplayed: len(windows), WindowsTotal: len(windows)})
	return result
}

func copyStrSliceMap(src map[int][]string) map[int][]string {
	dst := make(map[int][]string, len(src))
	for k, v := range src {
		dst[k] = append([]string(nil), v...)
	}
	return dst
}

func walkPcap(ctx context.Context, path string) (map[flowKey]*flowState, map[string]*dnsHostStats, uint64, time.Time, time.Time, []string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	if _, err := os.Stat(abs); err != nil {
		return nil, nil, 0, time.Time{}, time.Time{}, nil, fmt.Errorf("pcap not found: %w", err)
	}

	f, err := os.Open(abs)
	if err != nil {
		return nil, nil, 0, time.Time{}, time.Time{}, nil, fmt.Errorf("open pcap: %w", err)
	}
	defer f.Close()

	reader, perr := pcapgo.NewReader(f)
	if perr != nil {
		if _, err := f.Seek(0, 0); err != nil {
			return nil, nil, 0, time.Time{}, time.Time{}, nil, fmt.Errorf("rewind: %w", err)
		}
		ngReader, ngErr := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
		if ngErr != nil {
			return nil, nil, 0, time.Time{}, time.Time{}, nil, fmt.Errorf("not a pcap or pcapng (legacy: %v, ng: %v)", perr, ngErr)
		}
		return walkNgPcap(ctx, ngReader)
	}

	flows := make(map[flowKey]*flowState)
	dnsByHost := make(map[string]*dnsHostStats)
	var packets uint64
	var pcapStart, pcapEnd time.Time
	var warnings []string
	linkType := reader.LinkType()

	for {
		select {
		case <-ctx.Done():
			return flows, dnsByHost, packets, pcapStart, pcapEnd, warnings, ctx.Err()
		default:
		}
		data, ci, err := reader.ReadPacketData()
		if err != nil {
			break
		}
		packets++
		if pcapStart.IsZero() || ci.Timestamp.Before(pcapStart) {
			pcapStart = ci.Timestamp
		}
		if ci.Timestamp.After(pcapEnd) {
			pcapEnd = ci.Timestamp
		}
		processPacket(data, linkType, ci.Timestamp, pcapStart, packets, flows, dnsByHost)
	}
	return flows, dnsByHost, packets, pcapStart, pcapEnd, warnings, nil
}

func walkNgPcap(ctx context.Context, reader *pcapgo.NgReader) (map[flowKey]*flowState, map[string]*dnsHostStats, uint64, time.Time, time.Time, []string, error) {
	flows := make(map[flowKey]*flowState)
	dnsByHost := make(map[string]*dnsHostStats)
	var packets uint64
	var pcapStart, pcapEnd time.Time
	var warnings []string

	for {
		select {
		case <-ctx.Done():
			return flows, dnsByHost, packets, pcapStart, pcapEnd, warnings, ctx.Err()
		default:
		}
		data, ci, err := reader.ReadPacketData()
		if err != nil {
			break
		}
		packets++
		if pcapStart.IsZero() || ci.Timestamp.Before(pcapStart) {
			pcapStart = ci.Timestamp
		}
		if ci.Timestamp.After(pcapEnd) {
			pcapEnd = ci.Timestamp
		}
		linkType := reader.LinkType()
		processPacket(data, linkType, ci.Timestamp, pcapStart, packets, flows, dnsByHost)
	}
	return flows, dnsByHost, packets, pcapStart, pcapEnd, warnings, nil
}

func processPacket(data []byte, linkType layers.LinkType, ts time.Time, pcapStart time.Time, frameNum uint64, flows map[flowKey]*flowState, dnsByHost map[string]*dnsHostStats) {
	pkt := gopacket.NewPacket(data, linkType, gopacket.NoCopy)

	// Extract source/dest IPs first — DNS path needs them too.
	var srcIP, dstIP string
	if ip4 := pkt.Layer(layers.LayerTypeIPv4); ip4 != nil {
		v4, _ := ip4.(*layers.IPv4)
		srcIP = v4.SrcIP.String()
		dstIP = v4.DstIP.String()
	} else if ip6 := pkt.Layer(layers.LayerTypeIPv6); ip6 != nil {
		v6, _ := ip6.(*layers.IPv6)
		srcIP = v6.SrcIP.String()
		dstIP = v6.DstIP.String()
	}

	// UDP DNS handling — capture queries / responses for the per-host
	// DGA / tunnel-shape post-pass enrichment. We accept any UDP flow
	// whose dst OR src port is 53 (standard DNS); 5353 (mDNS) is
	// intentionally excluded because mDNS subdomain entropy on a
	// well-known LAN service is benign by construction.
	//
	// Also track UDP DNS as flows so that :53/:853 clusters are created
	// for DNS C2 detection (plain DNS tunneling, DoQ). Added 2026-08-29.
	if srcIP != "" && dstIP != "" {
		if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			srcPort := int(udp.SrcPort)
			dstPort := int(udp.DstPort)
			isDNS53 := srcPort == 53 || dstPort == 53
			isDNS853 := srcPort == 853 || dstPort == 853 // DoQ / DoT over UDP
			if isDNS53 && len(udp.Payload) > 0 && dnsByHost != nil {
				if dnsPkt := parseDNSPacket(udp.Payload); dnsPkt != nil {
					// Client IP = whichever side is NOT port 53.
					clientIP := srcIP
					fwd := true
					if srcPort == 53 {
						clientIP = dstIP
						fwd = false
					}
					stats, ok := dnsByHost[clientIP]
					if !ok {
						stats = &dnsHostStats{}
						dnsByHost[clientIP] = stats
					}
					recordDNSPacket(stats, dnsPkt, fwd)
				}
			}
			// Track UDP DNS/DoQ as flow for cluster creation.
			if (isDNS53 || isDNS853) && len(udp.Payload) > 0 {
				payload := uint64(len(udp.Payload))
				var keyFwd flowKey
				// Server port is 53 or 853
				serverPort := 53
				if isDNS853 {
					serverPort = 853
				}
				if dstPort == serverPort {
					keyFwd = flowKey{InitIP: srcIP, InitPort: srcPort, RespIP: dstIP, RespPort: dstPort}
				} else {
					keyFwd = flowKey{InitIP: dstIP, InitPort: dstPort, RespIP: srcIP, RespPort: srcPort}
				}
				st, ok := flows[keyFwd]
				if !ok {
					st = &flowState{
						key:           keyFwd,
						firstPacket:   ts,
						lastPacket:    ts,
						firstFrameNum: frameNum,
						isUDP:         true,
					}
					flows[keyFwd] = st
				}
				if ts.Before(st.firstPacket) {
					st.firstPacket = ts
				}
				if ts.After(st.lastPacket) {
					st.lastPacket = ts
				}
				st.packetsTotal++
				if dstPort == serverPort {
					st.bytesInitToResp += payload
				} else {
					st.bytesRespToInit += payload
				}
			}
		}
	}

	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp, _ := tcpLayer.(*layers.TCP)

	if srcIP == "" || dstIP == "" {
		return
	}

	srcPort := int(tcp.SrcPort)
	dstPort := int(tcp.DstPort)
	payload := uint64(len(tcp.Payload))

	keyFwd := flowKey{InitIP: srcIP, InitPort: srcPort, RespIP: dstIP, RespPort: dstPort}
	keyRev := flowKey{InitIP: dstIP, InitPort: dstPort, RespIP: srcIP, RespPort: srcPort}

	st, fwd := flows[keyFwd]
	if st == nil {
		if rev, ok := flows[keyRev]; ok {
			st = rev
			fwd = false
		}
	}
	if st == nil {
		st = &flowState{
			key:           keyFwd,
			firstPacket:   ts,
			lastPacket:    ts,
			firstFrameNum: frameNum,
		}
		flows[keyFwd] = st
		fwd = true
	}
	if ts.Before(st.firstPacket) {
		st.firstPacket = ts
	}
	if ts.After(st.lastPacket) {
		st.lastPacket = ts
	}
	st.packetsTotal++
	if fwd {
		st.bytesInitToResp += payload
	} else {
		st.bytesRespToInit += payload
	}
	// Passive HTTP request extraction — runs once per flow on the
	// first initiator-side payload to a port that typically carries
	// cleartext HTTP. Records URI / Host / User-Agent on the flow
	// for the post-pass C2 pattern matcher.
	if fwd && payload > 0 && !st.httpParseAttempted &&
		shouldAttemptHTTPParse(st.key.RespPort) && len(tcp.Payload) > 0 {
		parseHTTPRequestIntoFlow(tcp.Payload, st)
	}
	// Passive HTTP response parsing — runs once per flow on the first
	// responder-side payload that begins with "HTTP/1.". Captures
	// status / Content-Type / Content-Length / Server for the Mythic
	// agent_message-style response-shape matcher.
	if !fwd && payload > 0 && !st.httpRespParseAttempted &&
		shouldAttemptHTTPParse(st.key.RespPort) && len(tcp.Payload) > 0 &&
		shouldAttemptHTTPResponseParse(tcp.Payload) {
		parseHTTPResponseIntoFlow(tcp.Payload, st)
	}
	// Passive TLS ClientHello extraction — runs once per flow on the
	// first initiator-side handshake record. Records JA3 hash, SNI,
	// and ALPN on the flow for the post-pass TLS fingerprint matcher.
	// Port-agnostic (gated only on the TLS handshake magic bytes), so
	// C2 frameworks running TLS on non-443 ports still get fingerprinted.
	if fwd && payload > 0 && !st.tlsParseAttempted &&
		len(tcp.Payload) > 0 && shouldAttemptTLSParse(tcp.Payload) {
		st.tlsParseAttempted = true
		if fp := parseTLSClientHello(tcp.Payload); fp != nil {
			raw, hash := fp.JA3()
			st.tlsJA3 = hash
			st.tlsJA3Raw = raw
			st.tlsSNI = fp.SNI
			st.tlsALPN = fp.ALPN
		}
	}
	// Passive TLS ServerHello extraction — runs once per flow on the
	// first responder-side handshake record. Records JA3S hash on the
	// flow for the C2-redirector matcher. Same gating: non-handshake
	// payloads (TLS application data, raw bytes) are skipped cheaply.
	if !fwd && payload > 0 && !st.tlsServerParseAttempted &&
		len(tcp.Payload) > 0 && shouldAttemptTLSServerParse(tcp.Payload) {
		st.tlsServerParseAttempted = true
		if sfp := parseTLSServerHello(tcp.Payload); sfp != nil {
			_, hash := sfp.JA3S()
			st.tlsJA3S = hash
		}
	}
	// Passive SSH banner extraction — captures BOTH peers' banners on
	// any TCP flow whose first payload bytes match "SSH-". Port-agnostic
	// (custom C2 frameworks expose SSH on non-22 ports). Each side
	// parses at most once; subsequent payload bytes (the actual SSH
	// handshake / encrypted channel) are skipped cheaply.
	if payload > 0 && len(tcp.Payload) > 0 && shouldAttemptSSHParse(tcp.Payload) {
		if fwd && !st.sshClientBannerAttempted {
			st.sshClientBannerAttempted = true
			if b := parseSSHBanner(tcp.Payload); b != nil {
				st.sshClientBanner = b.Raw
				st.sshClientSoftware = b.Software
			}
		} else if !fwd && !st.sshServerBannerAttempted {
			st.sshServerBannerAttempted = true
			if b := parseSSHBanner(tcp.Payload); b != nil {
				st.sshServerBanner = b.Raw
				st.sshServerSoftware = b.Software
			}
		}
	}
	// Per-window byte tracking: the timeline bar paints cells based
	// on actual per-window byte volume rather than uniformly-spread
	// estimates. Keyed by window index relative to pcapStart;
	// negative indices clamp to 0 (out-of-order packets earlier than
	// pcapStart, rare but possible).
	if !pcapStart.IsZero() {
		windowIdx := int(ts.Sub(pcapStart) / Window)
		if windowIdx < 0 {
			windowIdx = 0
		}
		if st.bytesByWindow == nil {
			st.bytesByWindow = make(map[int]uint64)
		}
		st.bytesByWindow[windowIdx] += payload
	}
	if tcp.SYN {
		if !tcp.ACK {
			st.synSeen = true
			if !fwd {
				newKey := flowKey{InitIP: srcIP, InitPort: srcPort, RespIP: dstIP, RespPort: dstPort}
				if _, exists := flows[newKey]; !exists {
					st.key = newKey
					st.bytesInitToResp, st.bytesRespToInit = st.bytesRespToInit, st.bytesInitToResp
					delete(flows, keyRev)
					flows[newKey] = st
				}
			}
		} else {
			st.synAckSeen = true
		}
	}
	if tcp.FIN {
		st.finSeen = true
	}
	if tcp.RST {
		st.rstSeen = true
	}
}

// inferLocalIPs picks the IPs that should be treated as "local" — the
// per-host scope each detector run will see. Heuristic: any IP that
// appears as the initiator side of >=2 distinct flows is a local
// candidate. Falls back to all IPs ranked by appearance count if no
// flows have a confirmed initiator (rare; pcap with no SYN packets).
//
// Loopback addresses (127.0.0.0/8, ::1) are excluded — they're not
// hosts, just intra-process IPC. Including them produces phantom
// findings (a loopback↔loopback flow is never a tunnel or beacon).
// Wildcard / unspecified IPs (0.0.0.0, ::) are excluded for the same
// reason.
func inferLocalIPs(flows map[flowKey]*flowState) []string {
	skip := func(ip string) bool {
		return ip == "" || shared.IsLoopbackIP(ip) || shared.IsWildcardIP(ip)
	}

	initCounts := make(map[string]int)
	allCounts := make(map[string]int)
	for _, st := range flows {
		if !skip(st.key.InitIP) {
			allCounts[st.key.InitIP]++
		}
		if !skip(st.key.RespIP) {
			allCounts[st.key.RespIP]++
		}
		if st.synSeen && !skip(st.key.InitIP) {
			initCounts[st.key.InitIP]++
		}
	}

	type ipScore struct {
		ip    string
		score int
	}
	var ranked []ipScore
	for ip, c := range initCounts {
		ranked = append(ranked, ipScore{ip: ip, score: c})
	}
	if len(ranked) == 0 {
		for ip, c := range allCounts {
			ranked = append(ranked, ipScore{ip: ip, score: c})
		}
	}
	// Score desc; ties broken by IP string ascending so synthetic-PID
	// assignment is deterministic across runs.
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].score != ranked[j].score {
			return ranked[i].score > ranked[j].score
		}
		return ranked[i].ip < ranked[j].ip
	})

	out := make([]string, 0, len(ranked))
	seen := make(map[string]bool)
	for _, r := range ranked {
		if r.score < 1 {
			continue
		}
		if seen[r.ip] {
			continue
		}
		seen[r.ip] = true
		out = append(out, r.ip)
	}
	return out
}

func assignSyntheticPIDs(localIPs []string) map[string]int {
	out := make(map[string]int, len(localIPs))
	for i, ip := range localIPs {
		out[ip] = SyntheticPIDBase + i
	}
	return out
}

// pcapAttribution distributes synthetic PIDs at process-like
// granularity instead of per-IP. The classifier sees a separate
// candidate for:
//
//   - each (local_ip, listener_port) — a single listener candidate per
//     bound port, e.g. sshd:22.
//   - each (local_ip, "ext") — one catch-all candidate for outbound
//     flows from this IP whose remote target is external (non-RFC1918
//     and non-loopback). Captures beacon shapes like cheerful_glove
//     calling out to Cloudflare.
//   - each (local_ip, "int") — one catch-all candidate for outbound
//     flows from this IP whose remote target is internal RFC1918.
//     Captures relay shapes like sshd-z's SOCKS-forwarded TCP to
//     internal targets.
//
// Splitting outbound by external/internal is what lets a host that's
// running BOTH a beacon (cheerful → external) and a SOCKS relay
// (sshd-z → internal) classify both sides independently. Without the
// split, the merged outbound candidate would have OutExternal>0 AND
// OutInternal>0 simultaneously, suppressing the pivot-non-loopback-
// internal signal (which requires OutExternal==0).
//
// Outbound candidates have ParentPid set to a listener candidate on the
// same local IP when one exists, so AggregateChildTunnelEvidence /
// ApplyPivotLinger's parent-chain walk correlates them — promoting the
// listener to pivot when the internal-outbound candidate
// matches the relay shape (the test.pcap sshd-tunnel scenario).
type pcapAttribution struct {
	// listenerPID maps "ip:port" → synthetic PID for the listener
	// candidate at that endpoint.
	listenerPID map[string]int
	// outboundExtPID maps local IP → synthetic PID for that IP's
	// external-outbound rollup candidate (aggregates ALL external
	// destinations from that local IP into one row — kept for
	// backward compat with the original ground-truth tests and for
	// per-host overview).
	outboundExtPID map[string]int
	// outboundIntPID maps local IP → synthetic PID for that IP's
	// internal-outbound rollup candidate.
	outboundIntPID map[string]int
	// outboundClusterPID maps (LocalIP, /16-prefix, RemotePort) →
	// synthetic PID for the cluster candidate that bundles every
	// flow whose remote IP shares the same /16 network and port.
	// This approximates "one process talking to one service": all
	// flows from 172.16.1.81 to 104.21.x:443 (Cloudflare PoPs) end
	// up under one cluster PID with cumulative connection count,
	// burst tracking, and beacon-shape signals. Live mode achieves
	// the same view via per-PID attribution; pcap mode synthesises
	// it via destination-network bucketing.
	//
	// /16 was chosen as the cluster key because most CDN providers
	// segment their PoPs into /16 (or smaller) ranges that still
	// belong to one ASN-org, so a /16 typically maps to a single
	// service. Coarser (/8) blends unrelated networks; finer (/24)
	// over-fragments CDN PoP allocations. Cross-/16 service spans
	// (e.g. Cloudflare's many disparate /16s) end up as separate
	// clusters — that's preferable to bundling Cloudflare with
	// random AWS endpoints under a coarser key.
	outboundClusterPID map[flowCluster]int
	// listenerOnIP maps local IP → first listener PID on that IP
	// (used as ParentPid for outbound candidates so the
	// AggregateChildTunnelEvidence walk finds the listener).
	listenerOnIP map[string]int
	// procName maps PID → display name.
	procName map[int]string
	// allPIDs is every synthetic PID this attribution allocated, for
	// the resetSyntheticPIDState cleanup pass.
	allPIDs []int
}

// flowCluster keys destination-clustered outbound candidates. The
// LocalIP is the source host; Prefix is the /16 prefix of the remote
// (e.g. "104.21" for 104.21.70.108) — for IPv6 the first 32 bits
// (4 hextets). One synthetic candidate per (LocalIP, Prefix, Port).
type flowCluster struct {
	LocalIP    string
	Prefix     string
	RemotePort int
}

// isInternalPrefix reports whether a cluster /16 prefix (e.g. "172.16",
// "10.42", "192.168") falls in RFC1918 / link-local / loopback ranges.
// Used by the outbound-only-pivot linkage path to identify clusters
// whose ParentPid should point at the host's outbound-ext aggregate
// (the parent C2 callback) rather than another listener.
func isInternalPrefix(prefix string) bool {
	if prefix == "" {
		return false
	}
	if strings.HasPrefix(prefix, "127.") || prefix == "127" {
		return true
	}
	if strings.HasPrefix(prefix, "10.") || prefix == "10" {
		return true
	}
	if strings.HasPrefix(prefix, "192.168") {
		return true
	}
	if strings.HasPrefix(prefix, "169.254") {
		return true
	}
	// 172.16/12 — second octet 16..31 inclusive.
	if strings.HasPrefix(prefix, "172.") {
		rest := strings.TrimPrefix(prefix, "172.")
		// rest is the second octet as a string
		var oct int
		for _, r := range rest {
			if r < '0' || r > '9' {
				oct = -1
				break
			}
			oct = oct*10 + int(r-'0')
		}
		if oct >= 16 && oct <= 31 {
			return true
		}
	}
	return false
}

// remotePrefix16 returns the cluster prefix for an IP. IPv4 → first
// two octets. IPv6 → first 4 hextets. Empty input or unparseable IP
// returns the input unchanged so the cluster key stays stable.
func remotePrefix16(ip string) string {
	if ip == "" {
		return ip
	}
	// IPv6 fast path: contains ':' before any '.'
	if strings.Contains(ip, ":") && !strings.Contains(ip, ".") {
		// Strip optional zone id.
		if idx := strings.Index(ip, "%"); idx >= 0 {
			ip = ip[:idx]
		}
		// Take first 4 hextets joined by ':'.
		parts := strings.SplitN(ip, ":", 5)
		if len(parts) >= 4 {
			return strings.Join(parts[:4], ":")
		}
		return ip
	}
	// IPv4 (possibly mixed v4-mapped form)
	parts := strings.Split(ip, ".")
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return ip
}

func (a *pcapAttribution) listenerKey(ip string, port int) string {
	return fmt.Sprintf("%s:%d", ip, port)
}

// outboundPIDFor returns the synthetic PID for the outbound rollup
// candidate on localIP whose scope (external vs internal) matches
// remoteIP. Used for per-host aggregate views (overview, ground-truth
// tests). For per-destination granularity use outboundFlowPIDFor.
func (a *pcapAttribution) outboundPIDFor(localIP, remoteIP string) (int, bool) {
	if shared.IsInternalIP(remoteIP) && !shared.IsLoopbackIP(remoteIP) {
		pid, ok := a.outboundIntPID[localIP]
		return pid, ok
	}
	pid, ok := a.outboundExtPID[localIP]
	return pid, ok
}

// outboundFlowPIDFor returns the synthetic PID for the cluster
// candidate covering (localIP → /16-prefix:remotePort). All flows
// whose remote IP shares the same /16 and port get bucketed under
// one synthetic PID so cumulative beacon / session signals fire on
// the cluster as a unit (the pcap analog of live mode's per-PID
// attribution).
//
// Kept under the original "outboundFlowPIDFor" name so the
// classifier post-passes that look up "the PID for this flow" still
// resolve, just to a coarser granularity.
func (a *pcapAttribution) outboundFlowPIDFor(localIP, remoteIP string, remotePort int) (int, bool) {
	pid, ok := a.outboundClusterPID[flowCluster{
		LocalIP:    localIP,
		Prefix:     remotePrefix16(remoteIP),
		RemotePort: remotePort,
	}]
	return pid, ok
}

// buildPcapAttribution scans the flow set once to discover every
// listener endpoint, every per-host outbound rollup, and every
// per-cluster destination flow, then allocates a sequential synthetic
// PID for each. Allocation order is fixed (listeners → outbound-ext
// rollups → outbound-int rollups → cluster ext → cluster int) so
// two analyses of the same pcap produce identical PID assignments —
// important for cleanup and tests.
func buildPcapAttribution(flows []*flowState, localIPs []string) *pcapAttribution {
	localSet := make(map[string]bool, len(localIPs))
	for _, ip := range localIPs {
		localSet[ip] = true
	}
	listenerSet := make(map[string]struct{})        // "ip:port" keys
	outboundExtSet := make(map[string]struct{})     // ip keys (rollup)
	outboundIntSet := make(map[string]struct{})     // ip keys (rollup)
	clusterExtSet := make(map[flowCluster]struct{}) // per-/16 external clusters
	clusterIntSet := make(map[flowCluster]struct{}) // per-/16 internal clusters
	externalIPSet := make(map[string]struct{})      // distinct external IPs for ASN seeding
	for _, st := range flows {
		if localSet[st.key.RespIP] {
			listenerSet[fmt.Sprintf("%s:%d", st.key.RespIP, st.key.RespPort)] = struct{}{}
		}
		if localSet[st.key.InitIP] {
			cluster := flowCluster{
				LocalIP:    st.key.InitIP,
				Prefix:     remotePrefix16(st.key.RespIP),
				RemotePort: st.key.RespPort,
			}
			if shared.IsInternalIP(st.key.RespIP) && !shared.IsLoopbackIP(st.key.RespIP) {
				outboundIntSet[st.key.InitIP] = struct{}{}
				clusterIntSet[cluster] = struct{}{}
			} else {
				outboundExtSet[st.key.InitIP] = struct{}{}
				clusterExtSet[cluster] = struct{}{}
				externalIPSet[st.key.RespIP] = struct{}{}
			}
		}
	}
	// Seed the ASN cache with external destination IPs so the pcap
	// destinations panel can render ASN/Org per /16 cluster. Async —
	// returns immediately, populates cache as DNS lookups complete.
	if len(externalIPSet) > 0 {
		ips := make([]string, 0, len(externalIPSet))
		for ip := range externalIPSet {
			ips = append(ips, ip)
		}
		shared.QueueASNLookupsForIPs(ips)
	}
	listenerKeys := make([]string, 0, len(listenerSet))
	for k := range listenerSet {
		listenerKeys = append(listenerKeys, k)
	}
	sort.Strings(listenerKeys)
	extKeys := make([]string, 0, len(outboundExtSet))
	for k := range outboundExtSet {
		extKeys = append(extKeys, k)
	}
	sort.Strings(extKeys)
	intKeys := make([]string, 0, len(outboundIntSet))
	for k := range outboundIntSet {
		intKeys = append(intKeys, k)
	}
	sort.Strings(intKeys)
	extClusterKeys := sortedFlowClusters(clusterExtSet)
	intClusterKeys := sortedFlowClusters(clusterIntSet)

	a := &pcapAttribution{
		listenerPID:        make(map[string]int, len(listenerKeys)),
		outboundExtPID:     make(map[string]int, len(extKeys)),
		outboundIntPID:     make(map[string]int, len(intKeys)),
		outboundClusterPID: make(map[flowCluster]int, len(extClusterKeys)+len(intClusterKeys)),
		listenerOnIP:       make(map[string]int),
		procName:           make(map[int]string),
	}
	pid := SyntheticPIDBase
	for _, k := range listenerKeys {
		a.listenerPID[k] = pid
		a.procName[pid] = "pcap:" + k
		a.allPIDs = append(a.allPIDs, pid)
		// Record the first listener PID per IP for ParentPid linkage
		// from outbound candidates.
		ip := k
		if i := strings.LastIndex(k, ":"); i > 0 {
			ip = k[:i]
		}
		if _, ok := a.listenerOnIP[ip]; !ok {
			a.listenerOnIP[ip] = pid
		}
		pid++
	}
	for _, ip := range extKeys {
		a.outboundExtPID[ip] = pid
		a.procName[pid] = "pcap:" + ip + " outbound-ext"
		a.allPIDs = append(a.allPIDs, pid)
		pid++
	}
	for _, ip := range intKeys {
		a.outboundIntPID[ip] = pid
		a.procName[pid] = "pcap:" + ip + " outbound-int"
		a.allPIDs = append(a.allPIDs, pid)
		pid++
	}
	for _, c := range extClusterKeys {
		a.outboundClusterPID[c] = pid
		a.procName[pid] = fmt.Sprintf("pcap:%s → %s.0.0/16:%d", c.LocalIP, c.Prefix, c.RemotePort)
		a.allPIDs = append(a.allPIDs, pid)
		pid++
	}
	for _, c := range intClusterKeys {
		a.outboundClusterPID[c] = pid
		a.procName[pid] = fmt.Sprintf("pcap:%s → %s.0.0/16:%d", c.LocalIP, c.Prefix, c.RemotePort)
		a.allPIDs = append(a.allPIDs, pid)
		pid++
	}
	return a
}

// sortedFlowClusters returns the set's keys in deterministic order
// (LocalIP → Prefix → RemotePort) so PID assignment is stable
// across runs.
func sortedFlowClusters(set map[flowCluster]struct{}) []flowCluster {
	out := make([]flowCluster, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LocalIP != out[j].LocalIP {
			return out[i].LocalIP < out[j].LocalIP
		}
		if out[i].Prefix != out[j].Prefix {
			return out[i].Prefix < out[j].Prefix
		}
		return out[i].RemotePort < out[j].RemotePort
	})
	return out
}

// buildWindows produces a sorted list of window-end timestamps from
// pcapStart+W up to pcapEnd, inclusive of the final partial window. Always
// returns at least one window.
func buildWindows(pcapStart, pcapEnd time.Time) []time.Time {
	if pcapStart.IsZero() || pcapEnd.IsZero() || !pcapEnd.After(pcapStart) {
		return []time.Time{pcapEnd}
	}
	var out []time.Time
	t := pcapStart.Add(Window)
	for !t.After(pcapEnd) {
		out = append(out, t)
		t = t.Add(Window)
	}
	if len(out) == 0 || !out[len(out)-1].Equal(pcapEnd) {
		out = append(out, pcapEnd)
	}
	return out
}

// buildSnapshotForWindow constructs the shared.Snapshot the orchestrator
// expects, scoped to flows that are alive at windowEnd. A flow is alive
// restoreSyntheticRoleFromAnalyzing reverts model.DecideRole's
// "analyzing" override for synthetic pcap PIDs back to the
// signal-based suggestion stored on c.SuggestedRole. The model's
// analyzing-hold is correct for live capture (give an unknown
// process time to accumulate evidence before classifying), but pcap
// analysis is a one-shot replay where every synthetic PID is
// unknown and observations never accumulate past the pcap's window
// count — so the hold permanently masks the real role. Live PIDs
// untouched.
func restoreSyntheticRoleFromAnalyzing(candidates []shared.Candidate) {
	for i := range candidates {
		c := &candidates[i]
		if c.Proc == nil || !IsSyntheticPID(c.Proc.Pid) {
			continue
		}
		if c.Role != "analyzing" {
			continue
		}
		if c.SuggestedRole == "" || c.SuggestedRole == "analyzing" {
			continue
		}
		c.Role = c.SuggestedRole
	}
}

// demoteUnderEvidencedSyntheticPivots reverts beacon-* role on
// synthetic-PID candidates that lack pcap-grade proof of an active
// implant or relay. Live PIDs are untouched. Also clears residual
// ActiveProxying / PivotUntil / TunnelingSeen so downstream
// tunneling-state checks don't re-apply the FP role.
//
// Holds shared.ClassifyMu around the map deletes — when pcap mode runs
// alongside the live scanner (operator opens the pcap analyzer view
// while live capture continues classifying real processes), both
// write to the same global maps and concurrent-map-write panics
// otherwise. Live capture's writers go through Classify which already
// takes ClassifyMu; this matches that invariant.
//
// The pcap analyzer aggregates per-host × scope, so a single host's
// synthetic outbound-int / outbound-ext candidate accumulates
// pivot/session/beacon signals from any number of admin or vendor
// workflows on that host. Network-shape signals alone (mixed-protocol
// internal, beacon-endpoint-rotation, beacon-non-standard-port,
// cdn-fronted-c2-candidate, persistent-beacon) are not
// enough — admin/dev hosts routinely trip them while doing varied
// admin work (SSH + HTTP + SMB to a few internal targets), and any
// device doing CDN-fronted phone-home (Android FCM keep-alive on
// 5228, browser background sync, mobile-push helpers) lights up the
// beacon-* set.
//
// The genuine "implant or relay topology is here" evidence in
// pcap-only data is one of:
//   - the host has a listener candidate (`pcap:<ip>:<port>`) with
//     inbound traffic on the same IP — proves the host is accepting
//     inbound, so it's a server/relay endpoint where beacon
//     and pivot verdicts have a topological basis, OR
//   - the candidate carries the `child-tunnel-relay` signal stamped
//     by AggregateChildTunnelEvidence, which only fires when a parent
//     listener has children forwarding internal connections.
//
// Without either, beacon-* roles on synthetic-PID candidates are
// demoted to outbound regardless of which beacon/session/pivot
// signals fired. This mirrors the live-detection principle (recent
// commit 8b37a00) that listener-state from the OS is the deciding
// factor on whether a beacon-* role is admissible — pcap's
// equivalent of "OS-reported listener" is "host has a listener
// candidate with inbound in the capture".
func demoteUnderEvidencedSyntheticPivots(candidates []shared.Candidate) {
	for i := range candidates {
		c := &candidates[i]
		if c.Proc == nil || !IsSyntheticPID(c.Proc.Pid) {
			continue
		}
		if c.Role != "pivot" && c.Role != "beacon" {
			continue
		}
		// DNS to external resolvers (port 53) should not be beacon unless
		// there's explicit dns-tunnel-shape evidence. Normal DNS queries
		// to public resolvers fire weak beacon signals (single target,
		// persistent connection) but are not C2.
		if isDNSPortCluster(c) {
			hasDNSTunnelEvidence := false
			for _, sig := range c.Signals {
				if sig == "dns-tunnel-shape" || sig == "high-dns-volume" {
					hasDNSTunnelEvidence = true
					break
				}
			}
			if !hasDNSTunnelEvidence {
				c.Role = "outbound"
				c.ActiveProxying = false
				continue
			}
		}
		// child-tunnel-relay is only stamped by AggregateChildTunnelEvidence
		// on parent listeners with children forwarding internal traffic —
		// hard proof of a real relay topology. Preserve those.
		hasChildTunnelRelay := false
		hasSSHTunnelFlags := false
		hasNamedPipeC2 := false
		for _, sig := range c.Signals {
			switch sig {
			case "child-tunnel-relay":
				hasChildTunnelRelay = true
			case "pivot-ssh-tunnel-flags":
				hasSSHTunnelFlags = true
			case "pivot-named-pipe-c2-pattern":
				hasNamedPipeC2 = true
			}
		}
		if hasChildTunnelRelay || hasSSHTunnelFlags || hasNamedPipeC2 {
			continue
		}
		// Pcap-mode decisive-signal rescue. The signal sets in
		// shared.HasPacketDecisiveSignal cover the topology evidence
		// THIS function checks for hard-distinguishers (SOCKS bytes,
		// SYN cycling, listener+egress, tunnel-shape) PLUS the
		// 2-of-N beacon-shape rule that catches Cloudflare-fronted
		// HTTP beacons (Sliver / Mythic) with corroborated cadence +
		// persistent control + CDN destination on a single external
		// flow. Without this rescue, demoteUnderEvidencedSyntheticPivots
		// undoes my pcap-mode role guard's promotion of those beacons
		// — observed live 2026-05-01: cheerful_glove → Cloudflare
		// flows fired 6+ beacon-shape signals and out_external=1, my
		// guard correctly kept them beacon, then this
		// function demoted them all to outbound because none of the
		// three hard distinguishers fired.
		if shared.HasPacketDecisiveSignal(c) {
			continue
		}
		// Pivot-chain rescue removed 2026-05-01: synthetic-PID
		// conflation makes child-tunnel-relay fire on admin sshd
		// listeners (per-host outbound aggregate looks like a "child"
		// of the listener via synthetic ParentPid linkage). That
		// poisoned the rescue: every host with sshd + admin AD
		// traffic ended up preserving every outbound flow as beacon-
		// channel. The per-candidate HasPacketDecisiveSignal check
		// above is the only authoritative rescue.
		c.Role = "outbound"
		c.ActiveProxying = false
		shared.ClassifyMu.Lock()
		delete(shared.PivotUntil, c.Proc.Pid)
		delete(shared.TunnelingSeen, c.Proc.Pid)
		shared.ClassifyMu.Unlock()
	}
}

// hostC2StickyWindow is how long a host stays "C2-active" after the
// last cycle that classified it as such. In tail mode, cheerful's
// external CDN cluster only carries beacon during cycles
// that contain a fresh beacon packet (3-min intervals); without a
// sticky window, internal-pivot promotion on the same host flickers
// in and out as cheerful's beacon comes and goes. Window must be
// longer than the longest realistic beacon interval — 30 minutes
// covers Sliver/Mythic defaults and admin-tool callback patterns.
const hostC2StickyWindow = 30 * time.Minute

var (
	hostC2SeenMu sync.Mutex
	hostC2Seen   = make(map[string]time.Time) // local-IP → last cycle that confirmed C2
)

// promoteHostPivotsWhenC2Active scans for hosts with at least one
// confirmed beacon synthetic candidate (active external C2
// callback) and promotes their internal-targeted clusters
// (outbound-int rollup + RFC1918-prefix /16 clusters) to
// pivot. This catches the SOCKS-tunneled lateral movement
// pattern where a beacon on host X uses its C2 channel to relay
// scans/shells to internal targets — each internal-target cluster
// in isolation looks innocuous (matches Chrome's LAN printer
// discovery pattern), but in CONTEXT of the same host having an
// active C2 callback the promotion is well-founded.
//
// Sticky behaviour: hosts that have been seen as C2-active in the
// last hostC2StickyWindow keep promoting internal clusters even
// when the C2 cluster doesn't classify as beacon THIS
// cycle (typical in tail mode where the per-cycle 1-second bps
// window misses sleeping-beacon idle periods). Without the sticky
// window the operator sees the SOCKS-tunneled scans flicker in and
// out of pivot every classify tick.
//
// Runs after demoteUnderEvidencedSyntheticPivots so the C2 detection
// is the post-rescue, post-FP-scrub one.
func promoteHostPivotsWhenC2Active(candidates []shared.Candidate) {
	now := shared.PcapNow()
	hostsWithC2 := make(map[string]bool)
	hostC2SeenMu.Lock()
	for i := range candidates {
		c := &candidates[i]
		if c.Proc == nil || !IsSyntheticPID(c.Proc.Pid) {
			continue
		}
		if c.Role != "beacon" {
			continue
		}
		host := pcapHostFromName(c.Proc.Name)
		if host != "" {
			hostsWithC2[host] = true
			hostC2Seen[host] = now
		}
	}
	// Inherit sticky-window hosts: any host last confirmed within the
	// sticky window is still considered C2-active for promotion.
	for host, t := range hostC2Seen {
		if now.Sub(t) > hostC2StickyWindow {
			delete(hostC2Seen, host)
			continue
		}
		hostsWithC2[host] = true
	}
	hostC2SeenMu.Unlock()
	if len(hostsWithC2) == 0 {
		return
	}
	for i := range candidates {
		c := &candidates[i]
		if c.Proc == nil || !IsSyntheticPID(c.Proc.Pid) {
			continue
		}
		if c.Role != "outbound" && c.Role != "analyzing" {
			continue
		}
		host := pcapHostFromName(c.Proc.Name)
		if host == "" || !hostsWithC2[host] {
			continue
		}
		if !pcapIsInternalTargetCluster(c) {
			continue
		}
		// Benign LAN-discovery guard. Even when the host has confirmed
		// external C2, certain internal-target clusters from the same
		// host are clearly browser/OS LAN service discovery — Chrome
		// scanning for Chromecasts (port 8009/8008), printers (631
		// IPP, 80, 9100), mDNS (5353), SSDP (1900), WS-Discovery (3702),
		// NetBIOS (137-139). The memory note from 2026-05-02 documents
		// this exact FP class:
		//   pcap:172.16.1.81 → 172.16.0.0/16:8009 was Chrome Chromecast
		//   discovery, not cheerful's tunnel — the internal-pivot rescue
		//   rule produced 100% FPs.
		// Real C2 SOCKS-relayed scans either move ≥10 KB through the
		// cluster (proxychains nmap) or go to non-LAN-service ports.
		if isBenignLANDiscoveryCluster(c) {
			continue
		}
		// Skip clusters whose destination port is ephemeral
		// (≥49152). Internal traffic to a high-port destination is
		// almost always client-side ephemeral (router LAN management,
		// peer-to-peer software, IPC). Real implant relays target
		// service ports (445 SMB, 22 SSH, 80/443, 3389 RDP, 8080).
		// Operator-confirmed FP 2026-05-04: 192.168.2.14 →
		// 192.168.2.1:49152 (gateway router on a high port) was
		// being stamped as pivot+tunnel because the host
		// has confirmed C2; rule fired blindly.
		if isEphemeralDestPortCluster(c) {
			continue
		}
		c.Role = "pivot"
		c.SuggestedRole = "pivot"
		c.ActiveProxying = true
		c.Signals = appendUniqueSignal(c.Signals, "host-c2-active-pivot")
		c.Reasons = appendUniqueSignal(c.Reasons, "Host has active C2 callback; internal-target traffic is the implant's relay")
		shared.ClassifyMu.Lock()
		shared.PivotUntil[c.Proc.Pid] = now.Add(60 * time.Second)
		shared.TunnelingSeen[c.Proc.Pid] = now
		shared.ClassifyMu.Unlock()
	}
}

// benignLANDiscoveryPorts lists destination ports used by browsers, OSes,
// and shared peripherals for LAN service discovery. Clusters targeting
// one of these ports with low byte volume look exactly like internal
// pivots in pcap (many short connections to internal IPs) — but they
// are benign and never auto-promote to pivot via the
// host-c2-active-pivot rule.
var benignLANDiscoveryPorts = map[int]string{
	53:   "DNS",
	80:   "HTTP printer/admin",
	123:  "NTP",
	631:  "IPP printer",
	5353: "mDNS",
	1900: "SSDP / UPnP",
	8008: "Chromecast (HTTP)",
	8009: "Chromecast (TLS)",
	9100: "JetDirect printer",
	137:  "NetBIOS Name",
	138:  "NetBIOS Datagram",
	139:  "NetBIOS Session",
	3702: "WS-Discovery",
	5355: "LLMNR",
	1701: "L2TP",
	5060: "SIP",
}

// demoteBenignLANDiscoveryClusters is the FINAL FP-scrub pass for
// pcap mode. Runs after every promotion path (rule engine, linger,
// role guard, host-C2 promotion) but BEFORE applyPcapOperatorLabels
// so an operator can still override with a malicious label.
//
// What it catches: synthetic-PID outbound clusters that hit a known
// LAN-discovery port (Chromecast 8008/8009, mDNS 5353, SSDP 1900,
// IPP 631, JetDirect 9100, NetBIOS 137-139, WS-Discovery 3702, LLMNR
// 5355, plain LAN HTTP 80) AND have moved less than 10 KiB total.
// Chrome / Edge / Windows OS service-discovery is the dominant
// pattern at this signature; real C2 SOCKS-relayed scans clear
// 10 KiB within seconds and don't target these ports.
//
// What it preserves: clusters with hard relay evidence
// (child-tunnel-relay, pivot-socks-candidate, pivot-ssh-tunnel-flags,
// pivot-named-pipe-c2-pattern, host-c2-active-pivot, listener-
// inbound-external) bypass the demote — those are real packet
// observations of relay activity, not topology heuristics.
//
// Operator confirmation 2026-05-03: pcap:172.16.1.81 → 172.16.0.0/16:8009
// kept showing as pivot despite earlier fixes because the
// promotion happened in rank.go BEFORE the linger gate; this pass
// catches it AFTER everything else has run.
func demoteBenignLANDiscoveryClusters(candidates []shared.Candidate) {
	for i := range candidates {
		c := &candidates[i]
		if c.Proc == nil || !IsSyntheticPID(c.Proc.Pid) {
			continue
		}
		role := strings.ToLower(c.Role)
		if role != "beacon" && role != "pivot" &&
			role != "smb-pipe" && role != "tunnel" {
			continue
		}
		// Hard relay evidence overrides the demote. These signals are
		// derived from actual packet observations (parent-child
		// aggregation, SOCKS handshake bytes, ssh -D / -L flags in
		// banner, named-pipe C2 framing) — not from topology heuristics.
		if hasAnyRelayEvidence(c) {
			continue
		}
		if !isBenignLANDiscoveryCluster(c) {
			continue
		}
		c.Role = "outbound"
		c.SuggestedRole = "outbound"
		c.ActiveProxying = false
		c.Reasons = appendUniqueSignal(c.Reasons,
			"Demoted: LAN service discovery (Chromecast / printer / mDNS / SSDP) at low byte volume")
	}
}

// hasAnyRelayEvidence checks for hard packet-derived relay signals.
// These bypass the LAN-discovery demote because they're real evidence
// of relay activity, not topology heuristics. host-c2-active-pivot is
// intentionally EXCLUDED — it's a blanket stamp applied to every
// internal cluster from a host with confirmed C2, so it shields
// benign service traffic (Chromecast media casts, printer use) from
// the demote. The SOCKS-scan case the operator confirmed earlier is
// still covered by the distinctInternal>=5 check on the cluster's
// own connection set, and by the high-distinct-IP discriminator in
// isBenignLANDiscoveryCluster (≥5 IPs = non-benign sweep).
func hasAnyRelayEvidence(c *shared.Candidate) bool {
	if c == nil {
		return false
	}
	// Many-target SYN scan shape: a cluster with ≥5 distinct internal
	// target IPs is a port scan / SOCKS sweep, not LAN service use.
	// Chrome / Edge probe a small set of known Chromecast / printer
	// IPs (1-3); a single Chromecast cast targets 1 IP. SOCKS-tunneled
	// nmap hits every IP in the /24.
	distinctInternal := make(map[string]struct{})
	for _, conn := range c.Conns {
		if conn.RemoteAddress == "" {
			continue
		}
		if shared.IsLoopbackIP(conn.RemoteAddress) || shared.IsWildcardIP(conn.RemoteAddress) {
			continue
		}
		if !shared.IsInternalIP(conn.RemoteAddress) {
			continue
		}
		distinctInternal[conn.RemoteAddress] = struct{}{}
	}
	if len(distinctInternal) >= 5 {
		return true
	}
	for _, s := range c.Signals {
		switch s {
		case "child-tunnel-relay",
			"pivot-socks-candidate",
			"pivot-ssh-tunnel-flags",
			"pivot-named-pipe-c2-pattern",
			"listener-inbound-external",
			"forward-tunnel-shape",
			"reverse-beacon-shape":
			return true
		}
	}
	return false
}

// isBenignLANDiscoveryCluster reports whether the synthetic candidate's
// cluster name targets a known LAN-discovery port AND has a connection
// shape consistent with benign service interaction rather than a relay.
//
// Discriminator on distinct internal IPs:
//   - ≤4 distinct IPs → benign service use, ANY byte volume.
//     Real Chromecast media casting can hit megabytes — operator-
//     confirmed FP 2026-05-04: cheerful's host (172.16.1.81) had
//     1.2 MB of legit Chromecast traffic on 8009 to one device get
//     promoted as pivot because the byte cap was exceeded.
//   - ≥5 distinct IPs → sweep/scan, NOT benign. Caught by
//     hasAnyRelayEvidence's distinctInternal≥5 gate so the demote
//     is bypassed for real SOCKS-tunneled scans.
//
// This replaces the prior 10 KiB byte cap, which conflated traffic-
// volume with relay-likelihood. The shape (one device vs. sweep)
// is the load-bearing signal; volume is too coarse for media-capable
// LAN services like Chromecast on 8008/8009.
// isEphemeralDestPortCluster reports whether the cluster's
// destination port (parsed from the cluster name's trailing :port)
// is in the ephemeral-port range. Ephemeral ports are OS-allocated
// for client-side connections — Linux: 32768-60999, Windows:
// 49152-65535. We use 49152 as the floor (matches Windows + IANA).
//
// A real implant relay or pivot terminates on a SERVICE port (22 SSH,
// 80/443 HTTP/S, 445 SMB, 3389 RDP, 1080 SOCKS, 8080/8443). Internal
// traffic to a high-port destination is gateway-router LAN
// management, peer-to-peer software, IPC — never an implant pivot
// surface. Used by promoteHostPivotsWhenC2Active to gate the
// host-c2-active-pivot blanket stamp.
func isEphemeralDestPortCluster(c *shared.Candidate) bool {
	if c == nil || c.Proc == nil {
		return false
	}
	idx := strings.LastIndex(c.Proc.Name, ":")
	if idx <= 0 {
		return false
	}
	portStr := c.Proc.Name[idx+1:]
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}
	const ephemeralPortFloor = 49152
	return port >= ephemeralPortFloor
}

// isDNSPortCluster returns true if the cluster's destination port is 53 (DNS)
// or 853 (DNS over TLS). Used to demote DNS traffic that doesn't have
// explicit dns-tunnel-shape evidence.
func isDNSPortCluster(c *shared.Candidate) bool {
	if c == nil || c.Proc == nil {
		return false
	}
	idx := strings.LastIndex(c.Proc.Name, ":")
	if idx <= 0 {
		return false
	}
	portStr := c.Proc.Name[idx+1:]
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}
	return port == 53 || port == 853
}

func isBenignLANDiscoveryCluster(c *shared.Candidate) bool {
	if c == nil || c.Proc == nil {
		return false
	}
	idx := strings.LastIndex(c.Proc.Name, ":")
	if idx <= 0 {
		return false
	}
	portStr := c.Proc.Name[idx+1:]
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}
	if _, ok := benignLANDiscoveryPorts[port]; !ok {
		return false
	}
	// LAN discovery is by definition an INTERNAL cluster — Chrome
	// printer probes hit 192.168.x:80, Chromecast probes hit 10.x:8009.
	// Operator-confirmed FP 2026-05-04 on mythic_24hr.pcap: the Mythic
	// C2 cluster `pcap:10.0.0.60 → 157.230.0.0/16:80` was being demoted
	// here because the prior check `len(distinctInternal) <= 4` passed
	// trivially at 0 (no internal targets at all — the destination is
	// DigitalOcean external). Real LAN discovery has at least ONE
	// internal destination AND at most four; an external cluster has
	// zero internal destinations and must not match.
	distinctInternal := make(map[string]struct{})
	for _, conn := range c.Conns {
		if conn.RemoteAddress == "" {
			continue
		}
		if shared.IsLoopbackIP(conn.RemoteAddress) || shared.IsWildcardIP(conn.RemoteAddress) {
			continue
		}
		if !shared.IsInternalIP(conn.RemoteAddress) {
			continue
		}
		distinctInternal[conn.RemoteAddress] = struct{}{}
	}
	// 1-4 distinct internal targets on a benign LAN port = real
	// service interaction (Chromecast cast, printer print job, mDNS
	// lookup). 5+ targets = sweep — let it stand for further analysis.
	// 0 = no internal connections observed — the cluster is external,
	// not LAN discovery, so don't demote.
	return len(distinctInternal) >= 1 && len(distinctInternal) <= 4
}

// pcapHostFromName extracts the local-host IP from a synthetic-PID
// candidate name. Matches three cluster name shapes:
//   - "pcap:<ip> outbound-ext" / "outbound-int"
//   - "pcap:<ip> → <prefix>:<port>"
//   - "pcap:<ip>:<port>" (listener)
func pcapHostFromName(name string) string {
	if !strings.HasPrefix(name, "pcap:") {
		return ""
	}
	body := strings.TrimPrefix(name, "pcap:")
	if i := strings.Index(body, " "); i > 0 {
		return body[:i]
	}
	if i := strings.LastIndex(body, ":"); i > 0 {
		return body[:i]
	}
	return body
}

// pcapIsInternalTargetCluster reports whether the candidate is the
// per-host outbound-int rollup or a /16 cluster targeting an
// RFC1918 / link-local prefix. Only those clusters are valid
// promotion targets for host-C2-active pivot.
func pcapIsInternalTargetCluster(c *shared.Candidate) bool {
	if c == nil || c.Proc == nil {
		return false
	}
	if strings.HasSuffix(c.Proc.Name, " outbound-int") {
		return true
	}
	idx := strings.Index(c.Proc.Name, "→")
	if idx < 0 {
		return false
	}
	rest := strings.TrimSpace(c.Proc.Name[idx+len("→"):])
	if i := strings.Index(rest, ":"); i > 0 {
		rest = rest[:i]
	}
	if i := strings.Index(rest, "/"); i >= 0 {
		rest = rest[:i]
	}
	parts := strings.Split(rest, ".")
	if len(parts) >= 2 {
		return isInternalPrefix(parts[0] + "." + parts[1])
	}
	return false
}

func appendUniqueSignal(slice []string, s string) []string {
	for _, x := range slice {
		if x == s {
			return slice
		}
	}
	return append(slice, s)
}

// computeBeaconShape returns the TS+DS scores for a flow list.
// Returns ok=false when the cluster has too few flows for the math to
// be meaningful (requires ≥4 timestamps for ≥3 intervals).
//
// TS uses inter-flow start-time deltas with the timestamp default-MAD
// score (1.0 — under-sampled timing is treated as "no opinion" rather
// than "chaotic"). DS uses per-flow total-byte sizes with the
// data-size default-MAD (0.0 — tiny payloads are treated as
// non-uniform by default).
func computeBeaconShape(flows []FlowSummary) (BeaconShape, bool) {
	const minFlowsForShape = 4
	if len(flows) < minFlowsForShape {
		return BeaconShape{}, false
	}
	// Sort by FirstPacket ascending so consecutive deltas are real
	// inter-arrival gaps, not a permutation of the flow set.
	sorted := make([]FlowSummary, len(flows))
	copy(sorted, flows)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].FirstPacket.Before(sorted[j].FirstPacket) })

	// TS samples: inter-flow start-time deltas in seconds.
	intervals := make([]float64, 0, len(sorted)-1)
	for i := 1; i < len(sorted); i++ {
		d := sorted[i].FirstPacket.Sub(sorted[i-1].FirstPacket).Seconds()
		if d > 0 {
			intervals = append(intervals, d)
		}
	}
	// DS samples: per-flow total bytes (init→resp + resp→init).
	sizes := make([]float64, 0, len(sorted))
	for _, f := range sorted {
		sizes = append(sizes, float64(f.BytesInitToResp+f.BytesRespToInit))
	}

	tsScore := shared.StatisticalScore(intervals, 1.0)
	dsScore := shared.StatisticalScore(sizes, 0.0)
	return BeaconShape{TSScore: tsScore, DSScore: dsScore, SampleCount: len(sorted)}, true
}

// stampBeaconShapeSignals walks the candidate set and stamps shape
// signals on cluster candidates whose stored scores cross the 0.7
// threshold (promotes host-pair to "low-band beacon"). Independent
// of the existing beacon-* signal emitters — adds corroborating
// evidence without removing anything.
//
// `beacon-interval-statistical`  TSScore ≥ 0.7 = jitter consistent
// `beacon-payload-size-uniform`  DSScore ≥ 0.7 = sizes consistent
//
// Both fire only on synthetic-PID cluster candidates where the
// classifier already has the per-flow data; live mode falls back to
// the existing burst-tracker signals (which it already has).
func stampBeaconShapeSignals(candidates []shared.Candidate, shapesByPID map[int]BeaconShape) {
	const beaconShapeThreshold = 0.7
	// High-confidence thresholds: a cluster with 100+ flows whose timing
	// AND size are >=0.95 score is incontestable beacon shape — that
	// many regularly-spaced uniform flows do not occur in browsing,
	// API calls, or polling clients (which vary in payload). Operator-
	// confirmed 2026-05-04 on mythic_24hr.pcap: the Mythic /16 cluster
	// had 7610 flows with TS=1.00 + DS=1.00 but Path D's byte floor
	// blocked promotion because the synthetic capture had near-zero
	// payload bytes per flow. This high-confidence variant lets Path D
	// override the byte floor when shape evidence is overwhelming.
	const highConfidenceShapeThreshold = 0.95
	const highConfidenceMinSamples = 100
	for i := range candidates {
		c := &candidates[i]
		if c.Proc == nil || !IsSyntheticPID(c.Proc.Pid) {
			continue
		}
		shape, ok := shapesByPID[c.Proc.Pid]
		if !ok {
			continue
		}
		if shape.TSScore >= beaconShapeThreshold {
			c.Signals = shared.AppendUniqueSignal(c.Signals, "beacon-interval-statistical")
			c.Reasons = shared.AppendUniqueSignal(c.Reasons,
				fmt.Sprintf("Flow intervals consistent across %d connections (statistical score %.2f)",
					shape.SampleCount, shape.TSScore))
		}
		if shape.DSScore >= beaconShapeThreshold {
			c.Signals = shared.AppendUniqueSignal(c.Signals, "beacon-payload-size-uniform")
			c.Reasons = shared.AppendUniqueSignal(c.Reasons,
				fmt.Sprintf("Per-flow payload sizes uniform across %d connections (statistical score %.2f)",
					shape.SampleCount, shape.DSScore))
		}
		if shape.TSScore >= highConfidenceShapeThreshold &&
			shape.DSScore >= highConfidenceShapeThreshold &&
			shape.SampleCount >= highConfidenceMinSamples {
			c.Signals = shared.AppendUniqueSignal(c.Signals, "beacon-shape-high-confidence")
			c.Reasons = shared.AppendUniqueSignal(c.Reasons,
				fmt.Sprintf("Beacon shape with overwhelming evidence: %d flows, TS=%.2f, DS=%.2f",
					shape.SampleCount, shape.TSScore, shape.DSScore))
		}
	}
}

// countOpenConnsByPID returns a per-PID count of flows that were
// still "open" at the analysis boundary — synSeen && !finSeen &&
// !rstSeen. Maps to both the rollup PID and the per-/16 cluster PID,
// matching the same dual-attribution pattern flowsByEndpointPID uses.
//
// "Open" here is the conservative definition: we saw the SYN that
// opened the flow but we did not see a clean teardown (FIN) or a
// reset (RST). That includes long-lived connections still active
// when the pcap ended AND short-lived connections we lost track of.
// The signal stamper gates on prior decisive evidence so transient
// keepalives don't pollute the panel.
func countOpenConnsByPID(flows []*flowState, attr *pcapAttribution) map[int]int {
	if attr == nil || len(flows) == 0 {
		return nil
	}
	out := make(map[int]int, 16)
	for _, st := range flows {
		if st == nil || !st.synSeen || st.finSeen || st.rstSeen {
			continue
		}
		if pid, ok := attr.outboundPIDFor(st.key.InitIP, st.key.RespIP); ok {
			out[pid]++
		}
		if pid, ok := attr.outboundFlowPIDFor(st.key.InitIP, st.key.RespIP, st.key.RespPort); ok {
			out[pid]++
		}
	}
	return out
}

// stampOpenBoundarySignals emits `session-still-open-at-boundary` on
// cluster candidates that have ≥1 open flow AND already carry some
// decisive evidence from upstream passes. The decisive-evidence gate
// is critical: every TCP connection is briefly "open" between SYN
// and FIN, so a naive open-count signal would fire on every benign
// cluster. Pairing it with prior decisive evidence narrows the
// signal to "this beacon-* candidate has live persistent flows" —
// the canonical interactive-implant shape.
//
// Decisive-evidence gate: any of the existing pcapDecisiveSignals,
// the new beacon-interval-statistical / beacon-payload-size-uniform,
// session-long-connection, or tls-rare-signature.
func stampOpenBoundarySignals(candidates []shared.Candidate, openByPID map[int]int) {
	if len(openByPID) == 0 {
		return
	}
	gate := map[string]bool{
		"beacon-interval-statistical": true,
		"beacon-payload-size-uniform": true,
		"beacon-strobe-pattern":       true,
		"session-long-connection":     true,
		"tls-rare-signature":          true,
		"http-rare-signature":         true,
		"http-c2-known-ua":            true,
		"http-c2-uri-pattern":         true,
		"http-mime-uri-mismatch":      true,
		"cdn-fronted-c2-candidate":    true,
		"session-persistent-channel":  true,
		"child-tunnel-relay":          true,
		"pivot-socks-candidate":       true,
		"listener-inbound-external":   true,
	}
	for i := range candidates {
		c := &candidates[i]
		if c.Proc == nil || !IsSyntheticPID(c.Proc.Pid) {
			continue
		}
		open := openByPID[c.Proc.Pid]
		if open == 0 {
			continue
		}
		armed := false
		for _, s := range c.Signals {
			if gate[s] {
				armed = true
				break
			}
		}
		if !armed {
			continue
		}
		c.Signals = shared.AppendUniqueSignal(c.Signals, "session-still-open-at-boundary")
		c.Reasons = shared.AppendUniqueSignal(c.Reasons,
			fmt.Sprintf("%d connection(s) still open at end of capture (no FIN/RST observed)", open))
	}
}

// stampDayRhythmSignals emits `beacon-day-rhythm` on cluster
// candidates whose hour-of-day distribution is consistent across
// many hours — histogram-fit score simplified to the coefficient-of-
// variation discriminator.
//
// A long-running implant typically shows EITHER a flat 24-hour
// distribution (always-on heartbeats) OR a "business-hours" bimodal
// shape (operator-driven activity). Both produce LOW CV across the
// hours that actually saw traffic — random one-shot bursts on a
// given hour produce HIGH CV. Thresholds:
//
//   - hours_seen ≥ 6
//   - CV(non-zero buckets) ≤ 0.5 — flat enough to suggest schedule
//
// Only fires when the underlying pcap span is ≥6 hours; the data
// itself isn't populated for shorter captures (see ingest line ~613).
func stampDayRhythmSignals(candidates []shared.Candidate, hourBucketsByPID map[int][24]uint64) {
	const minHoursSeen = 6
	const maxCVForRhythm = 0.5
	for i := range candidates {
		c := &candidates[i]
		if c.Proc == nil || !IsSyntheticPID(c.Proc.Pid) {
			continue
		}
		buckets, ok := hourBucketsByPID[c.Proc.Pid]
		if !ok {
			continue
		}
		var nonZero []float64
		for _, count := range buckets {
			if count > 0 {
				nonZero = append(nonZero, float64(count))
			}
		}
		if len(nonZero) < minHoursSeen {
			continue
		}
		cv := shared.CoefficientOfVariation(nonZero)
		if cv > maxCVForRhythm {
			continue
		}
		c.Signals = shared.AppendUniqueSignal(c.Signals, "beacon-day-rhythm")
		c.Reasons = shared.AppendUniqueSignal(c.Reasons,
			fmt.Sprintf("Active across %d hours-of-day with low variation (CV %.2f) — schedule-driven beacon",
				len(nonZero), cv))
	}
}

// stampStrobeSignals emits `beacon-strobe-pattern` on cluster
// candidates whose connection rate (flows / observation seconds)
// crosses a sustained strobe threshold. Flags any host-pair whose
// unique-connection count would exceed 86,400 over 24 h (1/sec
// average); expressed as a rate so it applies to short pcaps too.
//
// Thresholds (all must hold):
//   - flow_count ≥ 60          — avoid "burst of 3" tiny-window FPs
//   - observation ≥ 60 seconds — same
//   - rate ≥ 0.5 conn/sec      — sustained over the cluster's lifetime
//
// A real C2 callback at 60s interval is well below 0.5/sec; a
// strobe is a different pathology (DoS-shape, broken implant
// reconnect storm, or a port scan from the implant).
func stampStrobeSignals(candidates []shared.Candidate, flowsByPID map[int][]FlowSummary) {
	const minFlowsForStrobe = 60
	const minObservationSec = 60.0
	const minStrobeRate = 0.5
	for i := range candidates {
		c := &candidates[i]
		if c.Proc == nil || !IsSyntheticPID(c.Proc.Pid) {
			continue
		}
		flows := flowsByPID[c.Proc.Pid]
		if len(flows) < minFlowsForStrobe {
			continue
		}
		first, last := flows[0].FirstPacket, flows[0].LastPacket
		for _, f := range flows {
			if f.FirstPacket.Before(first) {
				first = f.FirstPacket
			}
			if f.LastPacket.After(last) {
				last = f.LastPacket
			}
		}
		obs := last.Sub(first).Seconds()
		if obs < minObservationSec {
			continue
		}
		rate := float64(len(flows)) / obs
		if rate < minStrobeRate {
			continue
		}
		c.Signals = shared.AppendUniqueSignal(c.Signals, "beacon-strobe-pattern")
		c.Reasons = shared.AppendUniqueSignal(c.Reasons,
			fmt.Sprintf("Strobe shape: %d flows over %.0fs (%.2f conn/sec sustained)",
				len(flows), obs, rate))
	}
}

// stampPrevalenceSignals emits `outbound-rare-destination` and
// `outbound-common-destination` based on network-prevalence — the
// count of distinct internal hosts that reach a given external
// destination as a fraction of network size.
//
// `outbound-rare-destination`   prevalence ≤ 2%   (one-off implant target)
// `outbound-common-destination` prevalence ≥ 50%  (vendor service everyone hits)
//
// The "common" signal is a SUPPRESSION-class signal — its presence
// argues AGAINST malice (a destination that every host on the
// network reaches is a vendor update endpoint, OS telemetry, etc.).
// Skips when network has fewer than 3 distinct hosts (prevalence
// math is meaningless on single-host pcaps).
func stampPrevalenceSignals(candidates []shared.Candidate, flows []*flowState) {
	if len(flows) == 0 {
		return
	}
	// Build distinct-local-hosts-per-remote-IP map. Only consider
	// external destinations.
	hostsByDest := make(map[string]map[string]struct{})
	allLocals := make(map[string]struct{})
	for _, st := range flows {
		if st == nil {
			continue
		}
		if shared.IsInternalIP(st.key.RespIP) || shared.IsLoopbackIP(st.key.RespIP) {
			continue
		}
		allLocals[st.key.InitIP] = struct{}{}
		set, ok := hostsByDest[st.key.RespIP]
		if !ok {
			set = make(map[string]struct{})
			hostsByDest[st.key.RespIP] = set
		}
		set[st.key.InitIP] = struct{}{}
	}
	netSize := len(allLocals)
	const minNetSize = 3
	if netSize < minNetSize {
		return
	}
	const rareThreshold = 0.02  // ≤2% of hosts → rare
	const commonThreshold = 0.5 // ≥50% of hosts → common

	for i := range candidates {
		c := &candidates[i]
		if c.Proc == nil || !IsSyntheticPID(c.Proc.Pid) {
			continue
		}
		// Find the most-prevalent and least-prevalent external dest
		// across the cluster's connection list. A cluster's verdict
		// is based on its WORST (least common) dest — that's the one
		// that argues for malice. The MOST common one only matters
		// when ALL flows in the cluster go to common dests.
		minPrev, maxPrev := 1.1, -0.1
		var minPrevIP, maxPrevIP string
		for _, conn := range c.Conns {
			if conn.RemoteAddress == "" {
				continue
			}
			if shared.IsInternalIP(conn.RemoteAddress) || shared.IsLoopbackIP(conn.RemoteAddress) {
				continue
			}
			set, ok := hostsByDest[conn.RemoteAddress]
			if !ok {
				continue
			}
			prev := float64(len(set)) / float64(netSize)
			if prev < minPrev {
				minPrev = prev
				minPrevIP = conn.RemoteAddress
			}
			if prev > maxPrev {
				maxPrev = prev
				maxPrevIP = conn.RemoteAddress
			}
		}
		if minPrev <= rareThreshold && minPrevIP != "" {
			c.Signals = shared.AppendUniqueSignal(c.Signals, "outbound-rare-destination")
			c.Reasons = shared.AppendUniqueSignal(c.Reasons,
				fmt.Sprintf("Destination %s reached by only %.0f%% of hosts in capture (rare)",
					minPrevIP, minPrev*100))
		}
		if maxPrev >= commonThreshold && maxPrevIP != "" && minPrev >= commonThreshold {
			// Only stamp common when EVERY external dest in the cluster
			// is common — if even one rare dest exists, the cluster is
			// suspicious overall and we don't want to soften it.
			c.Signals = shared.AppendUniqueSignal(c.Signals, "outbound-common-destination")
			c.Reasons = shared.AppendUniqueSignal(c.Reasons,
				fmt.Sprintf("All external destinations reached by ≥%.0f%% of hosts (vendor-service shape)",
					commonThreshold*100))
		}
	}
}

// stampSMBLateralSignals stamps `internal-smb-lateral` on internal cluster
// candidates that show SMB-based agent-to-agent or lateral movement patterns.
// This catches C2 frameworks like AdaptixC2 that use SMB/named-pipes for
// internal communication between compromised hosts. Added 2026-08-29.
//
// Signals are stamped when an internal cluster to port 445/139 shows:
//   - Persistent connection (long duration)
//   - Significant bidirectional data transfer
//   - Multiple connections over time (reconnection pattern)
//
// This signal is decisive for pcap mode promotion of internal C2.
func stampSMBLateralSignals(candidates []shared.Candidate, flows []*flowState, attr *pcapAttribution) {
	if len(flows) == 0 || attr == nil {
		return
	}

	// Build SMB flow stats per internal cluster
	type smbStats struct {
		totalBytes    uint64
		totalDuration float64
		connCount     int
	}
	smbByCluster := make(map[int]*smbStats)

	for _, st := range flows {
		if st == nil {
			continue
		}
		// Only internal-to-internal flows
		if !shared.IsInternalIP(st.key.RespIP) {
			continue
		}
		// SMB ports: 445 (modern), 139 (NetBIOS)
		if st.key.RespPort != 445 && st.key.RespPort != 139 {
			continue
		}
		// Find the cluster PID for this flow
		prefix := remotePrefix16(st.key.RespIP)
		if prefix == "" {
			continue
		}
		cluster := flowCluster{
			LocalIP:    st.key.InitIP,
			Prefix:     prefix,
			RemotePort: st.key.RespPort,
		}
		pid, ok := attr.outboundClusterPID[cluster]
		if !ok {
			// Try the outbound-int rollup
			pid, ok = attr.outboundIntPID[st.key.InitIP]
			if !ok {
				continue
			}
		}
		stats, ok := smbByCluster[pid]
		if !ok {
			stats = &smbStats{}
			smbByCluster[pid] = stats
		}
		stats.totalBytes += st.bytesInitToResp + st.bytesRespToInit
		stats.totalDuration += st.lastPacket.Sub(st.firstPacket).Seconds()
		stats.connCount++
	}

	// Stamp signals on suspicious SMB clusters
	const minBytesForSMBLateral = 100 * 1024 // 100KB
	const minDurationForSMBLateral = 60.0    // 60 seconds
	const minConnsForSMBReconnect = 3        // 3 reconnections

	for i := range candidates {
		c := &candidates[i]
		if c.Proc == nil || !IsSyntheticPID(c.Proc.Pid) {
			continue
		}
		stats, ok := smbByCluster[c.Proc.Pid]
		if !ok {
			continue
		}
		// Check for suspicious patterns
		suspicious := false
		var reason string
		if stats.totalBytes >= minBytesForSMBLateral && stats.totalDuration >= minDurationForSMBLateral {
			suspicious = true
			reason = fmt.Sprintf("Persistent internal SMB: %.0f seconds, %s bytes, %d connections",
				stats.totalDuration, humanBytes(stats.totalBytes), stats.connCount)
		} else if stats.connCount >= minConnsForSMBReconnect && stats.totalBytes >= minBytesForSMBLateral/2 {
			suspicious = true
			reason = fmt.Sprintf("SMB reconnection pattern: %d connections, %s bytes",
				stats.connCount, humanBytes(stats.totalBytes))
		}
		if suspicious {
			c.Signals = shared.AppendUniqueSignal(c.Signals, "internal-smb-lateral")
			c.Reasons = shared.AppendUniqueSignal(c.Reasons, reason)
		}
	}
}

// reorientSynlessFlows fixes initiator/responder for flows where the
// SYN was never observed in the capture window. Without a SYN, the
// flow's InitIP/RespIP is whatever side sent the first packet seen —
// for any connection that started before the capture began, that's
// the SERVER's response (the client is idle waiting for data), so the
// roles get inverted and the analyzer treats the client's high
// ephemeral port as a "listener" on a weird port.
//
// Heuristic: if SYN was never seen AND one side's port is a known
// service port (or significantly lower than the other side's port),
// treat the lower-port side as the responder. Re-key the flow in
// place and swap byte counters so directionality stays correct.
func reorientSynlessFlows(flows map[flowKey]*flowState) {
	// Common service ports the heuristic should recognize even when
	// they're above the privileged range (>1024). Mirror live-mode's
	// well-known list so pcap and live agree on what "looks like a
	// server".
	wellKnown := map[int]struct{}{
		22: {}, 25: {}, 53: {}, 80: {}, 110: {}, 143: {}, 443: {},
		445: {}, 465: {}, 587: {}, 636: {}, 993: {}, 995: {},
		1433: {}, 1720: {}, 1723: {}, 2049: {}, 3306: {}, 3389: {},
		5432: {}, 5900: {}, 5985: {}, 5986: {}, 6379: {}, 8009: {},
		8080: {}, 8443: {}, 8888: {}, 9000: {}, 9090: {}, 9200: {},
	}
	isService := func(port int) bool {
		if port > 0 && port < 1024 {
			return true
		}
		_, ok := wellKnown[port]
		return ok
	}

	type flip struct {
		oldKey, newKey flowKey
		st             *flowState
	}
	var flips []flip
	for k, st := range flows {
		if st == nil || st.synSeen {
			continue
		}
		initIsService := isService(st.key.InitPort)
		respIsService := isService(st.key.RespPort)
		// Only flip when the well-known heuristic clearly disagrees:
		// the current "initiator" is the well-known service side AND
		// the current "responder" is on a high ephemeral port.
		if !initIsService || respIsService {
			continue
		}
		newKey := flowKey{
			InitIP:   st.key.RespIP,
			InitPort: st.key.RespPort,
			RespIP:   st.key.InitIP,
			RespPort: st.key.InitPort,
		}
		// Skip if the reversed direction already exists as its own
		// flow (rare race: both directions independently bucketed
		// before they were merged).
		if _, exists := flows[newKey]; exists {
			continue
		}
		flips = append(flips, flip{oldKey: k, newKey: newKey, st: st})
	}
	for _, f := range flips {
		f.st.key = f.newKey
		f.st.bytesInitToResp, f.st.bytesRespToInit = f.st.bytesRespToInit, f.st.bytesInitToResp
		delete(flows, f.oldKey)
		flows[f.newKey] = f.st
	}
}

// when its first packet was at-or-before windowEnd AND it has not yet
// sortFlowsForReplay turns the flow map into a deterministic slice
// keyed lexicographically on (init-ip, init-port, resp-ip, resp-port).
// Ensures the orchestrator sees the same Listener / Connection order
// across re-analyses of the same pcap, which is the root cause of
// "results differ every run" — Go map iteration order is randomized.
func sortFlowsForReplay(flows map[flowKey]*flowState) []*flowState {
	out := make([]*flowState, 0, len(flows))
	for _, st := range flows {
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool {
		ai, aj := out[i].key, out[j].key
		if ai.InitIP != aj.InitIP {
			return ai.InitIP < aj.InitIP
		}
		if ai.InitPort != aj.InitPort {
			return ai.InitPort < aj.InitPort
		}
		if ai.RespIP != aj.RespIP {
			return ai.RespIP < aj.RespIP
		}
		return ai.RespPort < aj.RespPort
	})
	return out
}

// fully closed (FIN or RST seen). State string follows the live-capture
// vocabulary: "ESTABLISHED", "SYN_SENT", "TIME_WAIT".
func buildSnapshotForWindow(
	flows []*flowState,
	attr *pcapAttribution,
	localIPs []string,
	windowEnd time.Time,
	allWindows []time.Time,
) *shared.Snapshot {
	localSet := make(map[string]bool, len(localIPs))
	for _, ip := range localIPs {
		localSet[ip] = true
	}

	procs := make(map[int]*shared.ProcessInfo, len(attr.allPIDs))
	for _, pid := range attr.allPIDs {
		procs[pid] = &shared.ProcessInfo{
			Pid:  pid,
			Name: attr.procName[pid],
		}
	}
	// Link outbound candidates to a listener candidate on the same IP.
	// AggregateChildTunnelEvidence + ApplyPivotLinger walk parent_pid
	// up to 4 levels looking for a listener — this single hop is what
	// lets the classifier promote the relay-child outbound-int candidate
	// to pivot AND propagate child-tunnel-relay back to the
	// listener parent (e.g. sshd:22 in the test.pcap SSH-D scenario).
	// Both rollup AND per-flow candidates link to the same listener so
	// every per-destination candidate also benefits from the parent
	// listener's child-tunnel-relay propagation.
	for ip, listenerPID := range attr.listenerOnIP {
		if pid, ok := attr.outboundExtPID[ip]; ok {
			procs[pid].ParentPid = listenerPID
		}
		if pid, ok := attr.outboundIntPID[ip]; ok {
			procs[pid].ParentPid = listenerPID
		}
	}
	for cluster, clusterPID := range attr.outboundClusterPID {
		if listenerPID, ok := attr.listenerOnIP[cluster.LocalIP]; ok {
			procs[clusterPID].ParentPid = listenerPID
		}
	}
	// Outbound-only agent topology: when a host has NO listener but
	// makes BOTH external (C2 callback) AND internal (commanded
	// targets) connections, the agent is acting as a pivot — Sliver's
	// command-execution shape, where C2 issues "connect to X internally,
	// report back" through a single outbound-only process.
	//
	// Wire outbound-int.ParentPid = outbound-ext.PID for that host so
	// AggregateChildTunnelEvidence sees "parent=outbound-ext has
	// child=outbound-int with internal forwarding" and stamps
	// child-tunnel-relay on the parent. The same chain promotes every
	// per-cluster candidate that is also routed through the parent
	// outbound-ext, so the operator sees the per-destination cluster
	// flagged when the host is acting as an outbound-only pivot.
	//
	// Skip when a listener already exists on the host (sshd-style relay
	// path is the more specific topology and gets the listener as parent).
	for ip, extPID := range attr.outboundExtPID {
		if _, hasListener := attr.listenerOnIP[ip]; hasListener {
			continue
		}
		if intPID, ok := attr.outboundIntPID[ip]; ok {
			procs[intPID].ParentPid = extPID
		}
		// Also link per-cluster internal candidates on the same host
		// to the outbound-ext aggregate — without this, only the
		// outbound-int aggregate gets the linkage and the specific
		// cluster (172.16.1.1:80 etc) misses the cross-promotion.
		for cluster, clusterPID := range attr.outboundClusterPID {
			if cluster.LocalIP != ip {
				continue
			}
			// Internal-target clusters only — external clusters ARE
			// the ones routing through outbound-ext, they shouldn't
			// be their own parent.
			if !isInternalPrefix(cluster.Prefix) {
				continue
			}
			procs[clusterPID].ParentPid = extPID
		}
	}

	var listeners []shared.ListenerInfo
	var conns []shared.ConnectionInfo
	listenerKeys := make(map[shared.ListenerKey]struct{})

	windowStart := windowEnd.Add(-Window)
	// Tail mode passes allWindows=nil because the windowing universe
	// is unbounded — there's no "first window" to clamp against. The
	// per-flow first/last-packet checks below already gate which
	// flows count, so the clamp is a one-shot-only refinement.
	if len(allWindows) > 0 && !allWindows[0].After(windowStart) {
		windowStart = allWindows[0].Add(-Window)
	}

	bpsRead := make(map[int]uint64)
	bpsWrite := make(map[int]uint64)
	bytesRead := make(map[int]uint64)
	bytesWrite := make(map[int]uint64)

	for _, st := range flows {
		if st.firstPacket.After(windowEnd) {
			continue
		}

		state := stateForFlow(st, windowEnd)
		if state == "" {
			continue
		}

		initIsLocal := localSet[st.key.InitIP]
		respIsLocal := localSet[st.key.RespIP]
		if !initIsLocal && !respIsLocal {
			continue
		}

		if respIsLocal {
			// Per-listener-port attribution: each listening port on a
			// local IP becomes its own candidate. sshd:22 separates
			// from a beacon's outbound on the same host.
			lkey := attr.listenerKey(st.key.RespIP, st.key.RespPort)
			pid, ok := attr.listenerPID[lkey]
			if !ok {
				continue
			}
			lk := shared.ListenerKey{Pid: pid, Addr: st.key.RespIP, Port: st.key.RespPort}
			if _, ok := listenerKeys[lk]; !ok {
				listenerKeys[lk] = struct{}{}
				listeners = append(listeners, shared.ListenerInfo{
					Pid:          pid,
					LocalAddress: st.key.RespIP,
					LocalPort:    st.key.RespPort,
					State:        "LISTEN",
				})
			}
			if state == "ESTABLISHED" {
				conns = append(conns, shared.ConnectionInfo{
					Pid:           pid,
					LocalAddress:  st.key.RespIP,
					LocalPort:     st.key.RespPort,
					RemoteAddress: st.key.InitIP,
					RemotePort:    st.key.InitPort,
					State:         state,
				})
			}
		}

		if initIsLocal {
			// Outbound flows route to:
			//   - the per-host scope rollup (outbound-ext or outbound-int)
			//     so the classic per-host overview signals fire (mixed-
			//     protocol-internal, multi-external-cdn, etc.).
			//   - the per-destination flow candidate (one per
			//     remote-IP:port) so each destination carries its own
			//     role (`liquid_mezzanine → Cloudflare:443` reads
			//     beacon while `backgroundtaskhost → Akamai:443`
			//     reads outbound).
			// Both candidates record the same connection in their own
			// row — the classifier scores them independently.
			rollupPID, rollupOK := attr.outboundPIDFor(st.key.InitIP, st.key.RespIP)
			flowPID, flowOK := attr.outboundFlowPIDFor(st.key.InitIP, st.key.RespIP, st.key.RespPort)
			if !rollupOK && !flowOK {
				continue
			}
			if rollupOK {
				conns = append(conns, shared.ConnectionInfo{
					Pid:           rollupPID,
					LocalAddress:  st.key.InitIP,
					LocalPort:     st.key.InitPort,
					RemoteAddress: st.key.RespIP,
					RemotePort:    st.key.RespPort,
					State:         state,
				})
			}
			if flowOK {
				conns = append(conns, shared.ConnectionInfo{
					Pid:           flowPID,
					LocalAddress:  st.key.InitIP,
					LocalPort:     st.key.InitPort,
					RemoteAddress: st.key.RespIP,
					RemotePort:    st.key.RespPort,
					State:         state,
				})
			}
		}

		// Cumulative bytes path — sum every flow's bytes regardless of
		// window position. Used by candidate.go's pcap-mode tunneling-
		// state shortcut as a fallback when the windowed bps math reads
		// 0 because lastPacket fell outside the [windowStart, windowEnd]
		// 1-second window (typical in tail mode where windowEnd is wall-
		// clock now() and flow.lastPacket is pcap-time-bound to the
		// most recent capture write).
		if initIsLocal {
			if pid, ok := attr.outboundPIDFor(st.key.InitIP, st.key.RespIP); ok {
				bytesWrite[pid] += st.bytesInitToResp
				bytesRead[pid] += st.bytesRespToInit
			}
			if pid, ok := attr.outboundFlowPIDFor(st.key.InitIP, st.key.RespIP, st.key.RespPort); ok {
				bytesWrite[pid] += st.bytesInitToResp
				bytesRead[pid] += st.bytesRespToInit
			}
		}
		if respIsLocal {
			lkey := attr.listenerKey(st.key.RespIP, st.key.RespPort)
			if pid, ok := attr.listenerPID[lkey]; ok {
				bytesWrite[pid] += st.bytesRespToInit
				bytesRead[pid] += st.bytesInitToResp
			}
		}
		if st.lastPacket.After(windowStart) && !st.lastPacket.After(windowEnd) {
			windowSpan := Window.Seconds()
			if windowSpan <= 0 {
				windowSpan = 1
			}
			if initIsLocal {
				if pid, ok := attr.outboundPIDFor(st.key.InitIP, st.key.RespIP); ok {
					bpsWrite[pid] += uint64(float64(st.bytesInitToResp) / windowSpan)
					bpsRead[pid] += uint64(float64(st.bytesRespToInit) / windowSpan)
				}
				if pid, ok := attr.outboundFlowPIDFor(st.key.InitIP, st.key.RespIP, st.key.RespPort); ok {
					bpsWrite[pid] += uint64(float64(st.bytesInitToResp) / windowSpan)
					bpsRead[pid] += uint64(float64(st.bytesRespToInit) / windowSpan)
				}
			}
			if respIsLocal {
				lkey := attr.listenerKey(st.key.RespIP, st.key.RespPort)
				if pid, ok := attr.listenerPID[lkey]; ok {
					bpsWrite[pid] += uint64(float64(st.bytesRespToInit) / windowSpan)
					bpsRead[pid] += uint64(float64(st.bytesInitToResp) / windowSpan)
				}
			}
		}
	}

	for pid, proc := range procs {
		proc.IOReadBps = bpsRead[pid]
		proc.IOWriteBps = bpsWrite[pid]
		proc.IOReadBytes = bytesRead[pid]
		proc.IOWriteBytes = bytesWrite[pid]
	}

	return &shared.Snapshot{
		Timestamp:   windowEnd,
		Processes:   procs,
		Listeners:   listeners,
		Connections: conns,
	}
}

// stateForFlow returns the conn state string the orchestrator expects.
// "" means "drop this flow from the snapshot" (already closed before
// windowEnd or not yet started).
func stateForFlow(st *flowState, windowEnd time.Time) string {
	if st.firstPacket.After(windowEnd) {
		return ""
	}
	if st.rstSeen && !st.lastPacket.After(windowEnd) {
		return ""
	}
	if st.finSeen && !st.lastPacket.After(windowEnd) {
		return ""
	}
	if !st.synAckSeen && st.synSeen {
		return "SYN_SENT"
	}
	if st.synAckSeen || st.synSeen {
		return "ESTABLISHED"
	}
	return "ESTABLISHED"
}

// IsSyntheticPID reports whether a PID was assigned by the pcap ingest
// layer. Live capture should never produce PIDs in this range; check used
// by UI and debugging code to flag offline-attributed candidates.
func IsSyntheticPID(pid int) bool {
	return pid >= SyntheticPIDBase && pid < SyntheticPIDBase+0x10000
}

// resetSyntheticPIDState wipes every shared package-level map entry
// keyed on (or containing) a synthetic PID, plus any
// ProcessBehaviorByKey entries our synthetic candidates would create.
// Called before AND after each ingest run so consecutive analyses of
// the same pcap produce identical findings — the orchestrator's
// behavioral-baseline maps don't accumulate across runs.
//
// The behavior-key cleanup is essential: shared.CandidateBehaviorKey
// folds in process Name + PID, both deterministic for our synthetic
// PIDs, so without explicit removal the second run would inherit
// stable-streak counts and committed-role hints from the first and
// produce different verdicts.
func resetSyntheticPIDState(pids []int) {
	if len(pids) == 0 {
		return
	}
	pidSet := make(map[int]struct{}, len(pids))
	for _, pid := range pids {
		pidSet[pid] = struct{}{}
	}
	shared.ClassifyMu.Lock()
	defer shared.ClassifyMu.Unlock()

	for pid := range pidSet {
		delete(shared.ProcHistoryByPID, pid)
		delete(shared.PivotUntil, pid)
		delete(shared.TunnelingSeen, pid)
		delete(shared.TunnelActivitySeen, pid)
		delete(shared.BeaconSeen, pid)
		delete(shared.ShortLivedBurstLast, pid)
		delete(shared.ShortLivedBurstFirst, pid)
		delete(shared.ShortLivedBurstCount, pid)
		delete(shared.ShortLivedBurstInterval, pid)
		delete(shared.ShortLivedBurstHits, pid)
		delete(shared.ShortLivedIntervals, pid)
		delete(shared.InboundBurstLast, pid)
		delete(shared.InboundBurstCount, pid)
		delete(shared.PivotInternalSeen, pid)
		delete(shared.SYNCycleByPID, pid)
		delete(shared.IOBurstHistory, pid)
		delete(shared.ConnCountHistory, pid)
		delete(shared.RecentClientSeen, pid)
		delete(shared.RecentOutboundSeen, pid)
		delete(shared.RecentInternalScanSeen, pid)
		delete(shared.SMBPipeSeen, pid)
		delete(shared.LocalTransportLast, pid)
		// PendingControlByPID is the per-(target) pending-beacon
		// tracker — a counter that grows monotonically across windows
		// when a candidate maintains a single-target outbound. Without
		// this delete, run #2 of the same pcap inherits the counters
		// from run #1, hist.Observations starts non-zero, and
		// behaviorStable / SuspiciousObservations diverges by 1 →
		// outbound-baseline-verified (or pivot-service-like-no-service)
		// flips between runs.
		delete(shared.PendingControlByPID, pid)
		delete(shared.ObservedExternalPortProcessCount, pid)
		delete(shared.ObservedExternalPortPrefixCount, pid)
		delete(shared.ObservedExternalPortConnCount, pid)
	}
	for key := range shared.ConnFirstSeen {
		if _, ok := pidSet[key.Pid]; ok {
			delete(shared.ConnFirstSeen, key)
		}
	}
	for key := range shared.ConnLastSeen {
		if _, ok := pidSet[key.Pid]; ok {
			delete(shared.ConnLastSeen, key)
		}
	}
	// ProcessBehaviorByKey is keyed by behavior key, not PID. Our
	// synthetic candidates always use process Name = "pcap:<ip>", so
	// any key with that segment is from a previous pcap run. Wiping
	// these is the difference between "same pcap, same verdict" and
	// "results drift every re-analyze".
	for key := range shared.ProcessBehaviorByKey {
		if strings.Contains(key, "|pcap:") {
			delete(shared.ProcessBehaviorByKey, key)
		}
	}
	// Per-process model profiles also persist across runs (committed
	// roles, dominant roles, experience counts). Without this wipe,
	// re-analyzing the same pcap shows reasons like "model: smb-pipe
	// (96% of 130 observations)" that drift between runs because the
	// observation count keeps growing. Host-scoped delete only
	// touches the synthetic "pcap-replay" namespace; live-capture
	// host profiles are untouched.
	model.DeleteProfilesForHost("pcap-replay")
}

// cleanupSyntheticPIDState is kept as an alias for callers that read as
// "cleanup after run" — the implementation is identical to the reset
// performed before each run.
func cleanupSyntheticPIDState(pids []int) {
	resetSyntheticPIDState(pids)
}

// IsValidExtension returns true for filenames ending in .pcap, .pcapng,
// or .log (case-insensitive). Used by the picker to gate analysis.
func IsValidExtension(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".pcap") ||
		strings.HasSuffix(lower, ".pcapng") ||
		strings.HasSuffix(lower, ".log")
}

// IsZeekLog returns true if the path is a Zeek log file or directory.
// For single .log files, checks if the parent directory contains conn.log
// (required for Zeek analysis).
func IsZeekLog(path string) bool {
	lower := strings.ToLower(path)
	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	// Check if it's a directory containing conn.log
	if info.IsDir() {
		if _, err := os.Stat(filepath.Join(path, "conn.log")); err == nil {
			return true
		}
		if _, err := os.Stat(filepath.Join(path, "conn.log.gz")); err == nil {
			return true
		}
		return false
	}

	// It's a file - check extension
	if !strings.HasSuffix(lower, ".log") {
		return false
	}

	// For single .log files, check if parent has conn.log
	dir := filepath.Dir(path)
	if _, err := os.Stat(filepath.Join(dir, "conn.log")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(dir, "conn.log.gz")); err == nil {
		return true
	}

	// Allow conn.log itself
	base := filepath.Base(lower)
	return base == "conn.log" || base == "conn.log.gz"
}
