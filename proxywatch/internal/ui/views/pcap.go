package views

import (
	"context"
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/gdamore/tcell/v2"

	"proxywatch/internal/detection/model"
	"proxywatch/internal/pcap"
	"proxywatch/internal/shared"
	"proxywatch/internal/ui/platform"
)

// PCAP analyzer stage strings (kept in sync with keys/pcap.go constants).
const (
	pcapStagePicking   = "picking"
	pcapStageAnalyzing = "analyzing"
	pcapStageResults   = "results"
)

// PCAP analyzer SETUP form field indices (mirror keys/pcap.go).
const (
	pcapFieldFile   = 0
	pcapFieldAction = 1
)

// dataFlowOfflineThreshold mirrors the live CandidateState's 512 BPS gate
// for "actively-flowing" tunnel detection. Exposed here so the offline
// bucketer applies the same threshold without relying on wallclock.
const dataFlowOfflineThreshold = 512

// PcapAnalysisProgressMsg is delivered each time the ingest goroutine
// emits a progress update. The view stores the latest, re-issues the
// listen-cmd, and keeps spinning.
type PcapAnalysisProgressMsg struct {
	Progress pcap.IngestProgress
}

// PcapAnalysisResultMsg is delivered exactly once when the ingest
// goroutine completes (successfully or with error or via cancel).
type PcapAnalysisResultMsg struct {
	Result pcap.IngestResult
}

// PcapAnalysisStartedMsg is the model's own internal signal: the
// goroutine has been spawned and the listen-cmds should attach.
// `tail` distinguishes one-shot mode (single result, channel closes
// after that one send) from watch mode (incremental results until
// ctx cancels). The view re-arms waitPcapResult after each receive
// regardless of mode; the difference is only what closes the channel.
// `streaming` indicates one-shot mode with intermediate results for
// playback support.
type PcapAnalysisStartedMsg struct {
	progressCh chan pcap.IngestProgress
	resultCh   chan pcap.IngestResult
	tail       bool
	streaming  bool
}

// pcapProgressClosedMsg fires when the progress channel closes, so the
// view stops re-issuing waitPcapProgress. Result still flows separately.
type pcapProgressClosedMsg struct{}

// pcapResultClosedMsg fires when the result channel closes — the
// definitive end-of-stream signal for both one-shot (after the single
// final result) and tail mode (when ctx cancels and IngestTail
// unwinds). Stops the view from re-issuing waitPcapResult.
type pcapResultClosedMsg struct{}

// PcapAnalyzerModel is the bubbletea view for the PCAP analyzer. Layout
// mirrors the other dashboard views: bordered header (renderPanel), an
// editable SETUP form (renderSetupPanel), and a scrollable DISPLAY
// report area (renderReportPanel).
type PcapAnalyzerModel struct {
	app *shared.AppState

	width  int
	height int

	// Picker / analyzing stages use the single fallback viewport.
	// Results stage uses two stacked viewports — viewportFindings
	// (top, with operator's row cursor) and viewportDetail (bottom,
	// auto-syncs with the selected row).
	viewport         viewport.Model
	viewportFindings viewport.Model
	viewportDetail   viewport.Model
	ready            bool
	findingsKey      uint64
	detailKey        uint64

	progress   pcap.IngestProgress
	result     *pcap.IngestResult
	progressCh chan pcap.IngestProgress
	resultCh   chan pcap.IngestResult
	tailing    bool // true while a watch session is active

	// findings is the post-analysis flat list — one row per
	// "interesting" candidate, ordered for operator triage (highest
	// score first, then beacon-* roles before plain outbound/listen).
	// tunneling[i] mirrors findings[i] and marks rows that meet the
	// active-tunneling shape gates so the table can show a TUNNEL
	// indicator without re-running the bucketer per render.
	findings  []shared.Candidate
	tunneling []bool
	// findingsParamShowAll caches whether the cached findings slice
	// was derived under "show all" or the default beacon-* filter.
	// The 'a' key mutates AppState; ensureFindingsCurrent re-derives
	// on mismatch.
	findingsParamShowAll bool

	// stickyFindings holds candidates that were classified beacon-*
	// (or tunneling) in any tail-mode tick. Once a candidate enters
	// this map it is preserved in the FINDINGS table even if a later
	// classify cycle demotes its role — the operator's complaint was
	// "findings appear and disappear" as the per-tick role wobbled.
	// Reset on PcapAnalysisStartedMsg so a new analysis starts fresh.
	//
	// Map key is c.Proc.Name (e.g. "pcap:172.16.1.81 → 104.21.0.0/16:443"),
	// NOT PID — pcap synthesis re-allocates PIDs every tick from
	// SyntheticPIDBase upwards in sorted-set order, so a candidate's
	// PID shifts when new clusters appear before it alphabetically.
	// Names are stable.
	//
	// stickyFindingBytes holds the byte count seen at the moment the
	// candidate was first stuck. Required because the zero-byte filter
	// in buildFindings drops entries when pcapTotalBytes returns 0,
	// and the byte lookup is PID-keyed via res.BytesByEndpointPID. A
	// sticky candidate whose PID has shifted across ticks (or whose
	// cluster aged out of the current snapshot) misses that lookup
	// and gets filtered out — undoing the stick. Saving the snapshot
	// bytes here lets buildFindingsWithSticky patch them into the
	// merged result so the row stays visible.
	stickyFindings        map[string]shared.Candidate
	stickyFindingBytes    map[string]uint64
	stickyFindingLastSeen map[string]time.Time // per-cluster last refresh time for TTL eviction
	// stickyFindingFirstFrame caches the first-packet frame number per
	// cluster name so the FINDINGS table's ID column stays stable across
	// cycles. Without this, the ID is looked up via res.FirstFrameByPID
	// using the candidate's CURRENT synthetic PID — but pcap re-allocates
	// PIDs each cycle, and sticky-only rows (cluster aged out of
	// res.Candidates entirely) carry the ORIGINAL PID which no longer
	// has an entry in res.FirstFrameByPID. Result: the ID disappears or
	// flickers. Capturing once and reading from this name-keyed cache
	// gives a stable ID for the lifetime of the sticky entry.
	stickyFindingFirstFrame  map[string]uint64
	stickyFindingFirstPacket map[string]time.Time
	// stickyFindingLastPacket caches the last-packet time per cluster
	// so the tunneling recency check can determine if traffic ended.
	stickyFindingLastPacket map[string]time.Time

	// stickyDetailConns keeps per-cluster connection history for the
	// CONNECTIONS detail panel. Mirrors the Inspector's
	// shared.InspectorStickyConns behaviour: closed/transient
	// connections stay visible for stickyDetailConnTTL after they
	// disappear from the live snapshot, deduplicated by (local, remote)
	// tuple. Operator request 2026-05-02 — without this, the panel
	// blanks the moment a connection closes, even when it's the
	// connection the operator was just inspecting.
	stickyDetailConns map[string]map[string]stickyDetailConnEntry

	spinnerIdx int

	// Playback state for one-shot streaming mode
	playbackSnapshots []pcap.IngestResult // buffered snapshots for playback
	playbackPos       int                 // current playback position (0-based index)
	playbackPaused    bool                // true when playback is paused
	playbackSpeed     float64             // playback speed multiplier (0.5, 1.0, 2.0, 4.0)
	streaming         bool                // true during streaming one-shot analysis
}

// stickyFindingTTL caps how long a beacon-* finding stays in the
// FINDINGS sticky cache without being re-confirmed by a current
// classify cycle. Long enough to span the longest realistic beacon
// gap (cheerful's 3-min, smb_pivot's 17-min) while short enough that
// briefly-promoted FPs that go silent expire from the panel before
// they sit there confusing operators.
const stickyFindingTTL = 20 * time.Minute

// stickyDetailConnTTL is how long a connection stays visible in the
// PCAP analyzer's CONNECTIONS detail panel after the live snapshot
// stops including it. Mirrors InspectorConnStickyWindow.
const stickyDetailConnTTL = 10 * time.Minute

type stickyDetailConnEntry struct {
	conn     shared.ConnectionInfo
	lastSeen time.Time
}

// refreshStickyDetailConns merges the candidate's current Conns into
// the per-cluster sticky-conn cache, expires entries older than
// stickyDetailConnTTL, and returns the union ordered by remote then
// local for stable display. Dedup is keyed by (local, remote) tuple
// so the same flow appears once even when state transitions.
func (m *PcapAnalyzerModel) refreshStickyDetailConns(c *shared.Candidate) []shared.ConnectionInfo {
	if c == nil || c.Proc == nil || c.Proc.Name == "" {
		if c == nil {
			return nil
		}
		return c.Conns
	}
	if m.stickyDetailConns == nil {
		m.stickyDetailConns = make(map[string]map[string]stickyDetailConnEntry)
	}
	per, ok := m.stickyDetailConns[c.Proc.Name]
	if !ok {
		per = make(map[string]stickyDetailConnEntry)
		m.stickyDetailConns[c.Proc.Name] = per
	}
	now := time.Now()
	for _, cn := range c.Conns {
		key := fmt.Sprintf("%s:%d|%s:%d", cn.LocalAddress, cn.LocalPort, cn.RemoteAddress, cn.RemotePort)
		per[key] = stickyDetailConnEntry{conn: cn, lastSeen: now}
	}
	for k, e := range per {
		if now.Sub(e.lastSeen) > stickyDetailConnTTL {
			delete(per, k)
		}
	}
	if len(per) == 0 {
		delete(m.stickyDetailConns, c.Proc.Name)
		return nil
	}
	out := make([]shared.ConnectionInfo, 0, len(per))
	for _, e := range per {
		out = append(out, e.conn)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].RemoteAddress != out[j].RemoteAddress {
			return out[i].RemoteAddress < out[j].RemoteAddress
		}
		if out[i].RemotePort != out[j].RemotePort {
			return out[i].RemotePort < out[j].RemotePort
		}
		if out[i].LocalAddress != out[j].LocalAddress {
			return out[i].LocalAddress < out[j].LocalAddress
		}
		return out[i].LocalPort < out[j].LocalPort
	})
	return out
}

// ensureFindingsCurrent re-derives the findings slice when the
// operator toggled the filter since the last build. Cheap no-op on
// the common case (no toggle since last render).
func (m *PcapAnalyzerModel) ensureFindingsCurrent() {
	if m.result == nil {
		return
	}
	if m.findingsParamShowAll == m.app.PcapShowAllFindings && m.findings != nil {
		return
	}
	m.findings, m.tunneling = buildFindingsWithSticky(m.result, m.app.PcapShowAllFindings, m.app.PcapSortMode, m.app.PcapGroupBy, m.stickyFindings, m.stickyFindingBytes, m.stickyFindingFirstFrame, m.stickyFindingFirstPacket, m.stickyFindingLastPacket)
	m.findingsParamShowAll = m.app.PcapShowAllFindings
}

func NewPcapAnalyzerModel(app *shared.AppState) PcapAnalyzerModel {
	return PcapAnalyzerModel{app: app}
}

func (m PcapAnalyzerModel) Init() tea.Cmd { return nil }

func (m PcapAnalyzerModel) Update(msg tea.Msg) (PcapAnalyzerModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.InitViewport()
		m.RefreshContent()
		return m, nil

	case PcapAnalysisStartedMsg:
		m.progressCh = msg.progressCh
		m.resultCh = msg.resultCh
		m.tailing = msg.tail
		m.streaming = msg.streaming
		// Reset the cumulative findings cache for the new run so
		// stale rows from the previous analysis don't bleed in.
		m.findings = nil
		m.tunneling = nil
		m.stickyFindings = nil
		m.stickyFindingLastSeen = nil
		m.stickyFindingBytes = nil
		m.stickyFindingFirstFrame = nil
		m.stickyFindingFirstPacket = nil
		m.stickyDetailConns = nil
		// Reset playback state for streaming mode
		m.playbackSnapshots = nil
		m.playbackPos = 0
		m.playbackPaused = false
		m.playbackSpeed = 1.0
		return m, tea.Batch(
			waitPcapProgress(msg.progressCh),
			waitPcapResult(msg.resultCh),
		)

	case PcapAnalysisProgressMsg:
		m.progress = msg.Progress
		m.spinnerIdx++
		m.RefreshContent()
		if m.progressCh != nil {
			return m, waitPcapProgress(m.progressCh)
		}
		return m, nil

	case pcapProgressClosedMsg:
		m.progressCh = nil
		return m, nil

	case PcapAnalysisResultMsg:
		res := msg.Result
		if res.Err != nil {
			m.app.PcapAnalysisRun = false
			m.app.PcapCancelFunc = nil
			m.app.PcapStage = pcapStagePicking
			m.app.PcapError = res.Err.Error()
			m.result = &res
			m.RefreshContent()
			return m, nil
		}
		// Buffer snapshots for playback in streaming mode
		if m.streaming {
			m.playbackSnapshots = append(m.playbackSnapshots, res)
			// If paused, keep buffering but don't update display
			if m.playbackPaused {
				// Still need to re-arm result listener
				if m.resultCh != nil {
					return m, waitPcapResult(m.resultCh)
				}
				return m, nil
			}
			// Advance to latest when not paused
			m.playbackPos = len(m.playbackSnapshots) - 1
			m.result = &m.playbackSnapshots[m.playbackPos]
		} else {
			m.result = &res
		}
		// Tail mode keeps streaming results until the channel closes.
		// We move to the results stage on the FIRST receive, then stay
		// there while subsequent updates re-render the table. One-shot
		// behaves the same way — the only structural difference is
		// whether more results are coming.
		m.app.PcapStage = pcapStageResults
		m.app.PcapBucketIdx = 0
		// Cursor only resets on the very first result; later updates
		// preserve the operator's row selection.
		if m.findings == nil {
			m.app.PcapRowCursor = 0
		}
		// Stick-promote any candidate this result classified as
		// beacon-* / smb-pipe / tunnel. Once promoted, it stays in
		// the FINDINGS table for the rest of the watch session even
		// if a later tick demotes it. Sticks the most recent role &
		// signal set so the row stays accurate as evidence grows;
		// only role-DEMOTIONS are ignored.
		if m.stickyFindings == nil {
			m.stickyFindings = make(map[string]shared.Candidate)
			m.stickyFindingBytes = make(map[string]uint64)
			m.stickyFindingLastSeen = make(map[string]time.Time)
			m.stickyFindingFirstFrame = make(map[string]uint64)
			m.stickyFindingFirstPacket = make(map[string]time.Time)
			m.stickyFindingLastPacket = make(map[string]time.Time)
		}
		now := time.Now()
		for _, c := range res.Candidates {
			if c.Proc == nil || c.Proc.Name == "" {
				continue
			}
			r := strings.ToLower(c.Role)
			if r == "beacon" || r == "pivot" || r == "smb-pipe" || r == "tunnel" {
				m.stickyFindings[c.Proc.Name] = c
				m.stickyFindingLastSeen[c.Proc.Name] = now
				// Save the byte count seen at this moment so the
				// zero-byte filter doesn't later drop the sticky row
				// when the PID re-allocation breaks the
				// BytesByEndpointPID lookup.
				if v, ok := res.BytesByEndpointPID[c.Proc.Pid]; ok && v > 0 {
					m.stickyFindingBytes[c.Proc.Name] = v
				} else if v := res.BytesByPID[c.Proc.Pid]; v > 0 {
					m.stickyFindingBytes[c.Proc.Name] = v
				}
				// Capture stable identifiers so the FINDINGS ID column
				// (#frame) and TIME column don't go blank when the
				// cluster's synthetic PID changes between cycles or the
				// cluster ages out of res entirely.
				if f, ok := res.FirstFrameByPID[c.Proc.Pid]; ok && f > 0 {
					if _, already := m.stickyFindingFirstFrame[c.Proc.Name]; !already {
						m.stickyFindingFirstFrame[c.Proc.Name] = f
					}
				}
				if t, ok := res.FirstPacketByPID[c.Proc.Pid]; ok && !t.IsZero() {
					if _, already := m.stickyFindingFirstPacket[c.Proc.Name]; !already {
						m.stickyFindingFirstPacket[c.Proc.Name] = t
					}
				}
				// Always update last packet time (not just first store)
				// so the tunneling recency check has accurate data.
				if t, ok := res.LastPacketByPID[c.Proc.Pid]; ok && !t.IsZero() {
					m.stickyFindingLastPacket[c.Proc.Name] = t
				}
			}
			// NOTE: previously this branch deleted demoted entries
			// from sticky immediately. Operator reported 2026-05-02
			// that valid pivots (sshd:22 SOCKS-tunnel listener)
			// flickered between pivot and outbound across
			// cycles because per-cycle signal evaluation drops
			// child-tunnel-relay during quiet windows — the delete
			// turned that flicker into permanent loss.
			//
			// Now: rely solely on the TTL eviction below to clean up
			// stale entries. A cluster that's genuinely demoted will
			// stop being re-confirmed in subsequent cycles and drop
			// out at stickyFindingTTL. A cluster that's flickering
			// (beacon-* most cycles, outbound briefly) stays.
		}
		// Time-based eviction: drop sticky entries that haven't been
		// refreshed (re-confirmed as beacon-* in a subsequent cycle)
		// in the last stickyFindingTTL. Operator reported 2026-05-02 a
		// SSH client cluster from 1+ hour ago still showing as beacon-
		// pivot; the demote-on-non-control branch above only fires
		// when the cluster reappears in candidates, but stale clusters
		// often disappear from candidates entirely (no fresh packets
		// in window) — without TTL eviction they stay sticky forever.
		// 10 minutes covers cheerful's 3-min beacon cycle (re-touched
		// every beacon) while purging anything truly idle.
		for name, t := range m.stickyFindingLastSeen {
			if now.Sub(t) > stickyFindingTTL {
				delete(m.stickyFindings, name)
				delete(m.stickyFindingBytes, name)
				delete(m.stickyFindingLastSeen, name)
				delete(m.stickyFindingFirstFrame, name)
				delete(m.stickyFindingFirstPacket, name)
			}
		}
		m.findings, m.tunneling = buildFindingsWithSticky(&res, m.app.PcapShowAllFindings, m.app.PcapSortMode, m.app.PcapGroupBy, m.stickyFindings, m.stickyFindingBytes, m.stickyFindingFirstFrame, m.stickyFindingFirstPacket, m.stickyFindingLastPacket)
		m.findingsParamShowAll = m.app.PcapShowAllFindings
		m.RefreshContent()
		// Re-arm the result listener for both modes — one-shot's
		// channel will close after the next read, tail's stays open.
		// Either way pcapResultClosedMsg eventually fires and we stop.
		if m.resultCh != nil {
			return m, waitPcapResult(m.resultCh)
		}
		return m, nil

	case pcapResultClosedMsg:
		wasTailing := m.tailing
		m.resultCh = nil
		m.tailing = false
		m.app.PcapAnalysisRun = false
		m.app.PcapCancelFunc = nil
		// If a watch session ended (Esc pressed, file gone, etc),
		// hop back to the picker so the SETUP form is interactive
		// again — the operator can immediately press the Action
		// button to start another watch on the same path. Without
		// this they'd be stuck in the results stage where Enter
		// would drill into a finding instead of restarting.
		if wasTailing {
			m.app.PcapStage = pcapStagePicking
		}
		m.RefreshContent()
		return m, nil

	case tea.KeyMsg:
		tev := convertKeyMsg(msg)

		handled, shouldQuit := handleQuitConfirmKey(m.app, tev)
		if handled {
			if shouldQuit {
				return m, tea.Quit
			}
			return m, nil
		}

		// Number key workflow jumping - allow switching dashboards from any stage,
		// but not when editing text fields (file path input) or browsing files.
		// Only block during picking stage when actively in edit or browse mode.
		inTextInput := m.app.PcapStage == pcapStagePicking && (m.app.PcapEditing || m.app.PcapBrowsing)
		if !inTextInput && jumpToWorkflow(m.app, tev.Rune()) {
			return m, nil
		}

		// Playback controls for streaming mode (works during both analyzing and results stages)
		// Skip when editing text to allow typing '.', ',', '<', '>', etc.
		if !inTextInput && m.streaming && len(m.playbackSnapshots) > 0 {
			if cmd := m.handlePlaybackKey(tev); cmd != nil {
				return m, cmd
			}
		}

		// Results stage: PgUp / PgDn scroll the Details panel
		// independently of the Findings cursor (Up/Down). Keeps the
		// findings table navigation snappy while the operator can
		// still scroll long detail content.
		if m.app.PcapStage == pcapStageResults && m.handleDetailsScroll(tev) {
			return m, nil
		}
		preStage := m.app.PcapStage
		if HandlePcapAnalyzerKey != nil {
			HandlePcapAnalyzerKey(m.app, tev)
		}
		// Consume any pending operator-label request — written by the
		// keys/pcap.go handler when the operator hits m/b/c on the
		// FINDINGS panel. The verdict applies to the cluster name of
		// the currently-selected finding; persists to disk via
		// shared.SetPcapOperatorLabel so it survives restarts and
		// re-analyses.
		if req := m.app.PcapLabelRequest; req != "" {
			m.app.PcapLabelRequest = ""
			if c, ok := m.selectedFinding(); ok && c.Proc != nil && c.Proc.Name != "" {
				switch req {
				case "malicious":
					_ = shared.SetPcapOperatorLabel(c.Proc.Name, shared.VerdictMalicious, "")
				case "benign":
					_ = shared.SetPcapOperatorLabel(c.Proc.Name, shared.VerdictBenign, "")
				case "clear":
					_ = shared.ClearPcapOperatorLabel(c.Proc.Name)
				case "tls-malicious", "tls-benign", "tls-clear":
					applyTLSLabelToFinding(c, req)
				}
			}
		}
		if preStage == pcapStagePicking && m.app.PcapStage == pcapStageAnalyzing {
			m.RefreshContent()
			return m, m.startAnalysis()
		}

		m.RefreshContent()
		return m, nil
	}

	return m, nil
}

// handleDetailsScroll consumes scroll keys aimed at the lower Details
// panel during the results stage. Returns true when the key was a
// scroll key and the viewport moved — false means hand the event to
// the regular keys/pcap.go dispatcher (which moves the Findings
// cursor on Up/Down).
//
// Key mapping (results stage):
//
//	Up / Down             — Findings cursor by 1 row (auto-scrolls)
//	PgUp / PgDn           — Findings cursor jumps by viewport page
//	Ctrl+PgUp / Ctrl+PgDn — Details panel page scroll
//	[ / ]                 — Details panel line scroll (CONNECTIONS box)
//	Home / End            — Findings cursor first / last row
//
// The [ and ] bindings give the operator a no-modifier way to scroll
// the CONNECTIONS / SIGNALS detail panel — the Ctrl+PgUp/PgDn pairing
// existed but operators report it as undiscoverable.
// applyTLSLabelToFinding sets / clears a TLS label (JA3 + SNI both)
// for the candidate's observed TLS attributes. The TLS enrich pass
// stamps "TLS JA3 ..." and "TLS SNI: ..." reasons on the candidate;
// this helper extracts every JA3 hash and SNI hostname from those
// reasons and applies the verdict to all of them so a single hotkey
// labels the entire TLS shape of the finding.
func applyTLSLabelToFinding(c shared.Candidate, req string) {
	verdict := ""
	clear := false
	switch req {
	case "tls-malicious":
		verdict = shared.VerdictMalicious
	case "tls-benign":
		verdict = shared.VerdictBenign
	case "tls-clear":
		clear = true
	default:
		return
	}

	// Walk reasons for SNI hostnames and JA3 hashes.
	const sniPrefix = "TLS SNI: "
	for _, r := range c.Reasons {
		if strings.HasPrefix(r, sniPrefix) {
			body := r[len(sniPrefix):]
			for _, h := range strings.Split(body, ",") {
				h = strings.TrimSpace(h)
				if h == "" {
					continue
				}
				if clear {
					_ = shared.ClearPcapTLSLabel(shared.PcapTLSLabelKindSNI, h)
				} else {
					_ = shared.SetPcapTLSLabel(shared.PcapTLSLabelKindSNI, h, verdict, "")
				}
			}
		}
		if strings.Contains(r, "JA3") {
			// Extract any 32-hex-char run as a JA3 hash.
			for i := 0; i+32 <= len(r); i++ {
				slice := r[i : i+32]
				ok := true
				for j := 0; j < 32; j++ {
					b := slice[j]
					if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')) {
						ok = false
						break
					}
				}
				if !ok {
					continue
				}
				// Bound on non-hex (or string edge).
				if i > 0 {
					b := r[i-1]
					if (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') {
						continue
					}
				}
				if i+32 < len(r) {
					b := r[i+32]
					if (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') {
						continue
					}
				}
				if clear {
					_ = shared.ClearPcapTLSLabel(shared.PcapTLSLabelKindJA3, slice)
				} else {
					_ = shared.SetPcapTLSLabel(shared.PcapTLSLabelKindJA3, slice, verdict, "")
				}
				break
			}
		}
	}
}

func (m *PcapAnalyzerModel) handleDetailsScroll(tev *tcell.EventKey) bool {
	if !m.ready {
		return false
	}
	switch tev.Key() {
	case tcell.KeyPgUp:
		// Ctrl modifier → details scroll. Plain PgUp falls through to
		// the findings dispatcher in keys/pcap.go.
		if tev.Modifiers()&tcell.ModCtrl != 0 {
			m.viewportDetail.ScrollUp(m.viewportDetail.VisibleLineCount())
			return true
		}
		// Plain PgUp jumps the findings cursor up by a page.
		m.app.PcapRowCursor -= max(1, m.viewportFindings.VisibleLineCount()-1)
		if m.app.PcapRowCursor < 0 {
			m.app.PcapRowCursor = 0
		}
		return true
	case tcell.KeyPgDn:
		if tev.Modifiers()&tcell.ModCtrl != 0 {
			m.viewportDetail.ScrollDown(m.viewportDetail.VisibleLineCount())
			return true
		}
		m.app.PcapRowCursor += max(1, m.viewportFindings.VisibleLineCount()-1)
		if m.app.PcapRowCursor >= len(m.findings) {
			m.app.PcapRowCursor = len(m.findings) - 1
		}
		if m.app.PcapRowCursor < 0 {
			m.app.PcapRowCursor = 0
		}
		return true
	case tcell.KeyRune:
		// Bracket keys scroll the lower CONNECTIONS / SIGNALS panel
		// line-by-line. '[' = up, ']' = down. Held repeats scroll
		// continuously like any normal viewport.
		switch tev.Rune() {
		case '[':
			m.viewportDetail.ScrollUp(1)
			return true
		case ']':
			m.viewportDetail.ScrollDown(1)
			return true
		case '{':
			// Shift+[ — page up in the details panel.
			m.viewportDetail.ScrollUp(max(1, m.viewportDetail.VisibleLineCount()-1))
			return true
		case '}':
			// Shift+] — page down in the details panel.
			m.viewportDetail.ScrollDown(max(1, m.viewportDetail.VisibleLineCount()-1))
			return true
		}
	}
	return false
}

// handlePlaybackKey processes playback control keys for streaming mode.
// Returns a tea.Cmd if the key was consumed, nil otherwise.
//
// Key mapping:
//
//	Space         — pause/resume playback
//	, or <        — seek backward 1 snapshot
//	. or >        — seek forward 1 snapshot
//	Home          — jump to first snapshot
//	End           — jump to last snapshot
//	+/=           — increase playback speed (0.5x → 1x → 2x → 4x)
//	-             — decrease playback speed
func (m *PcapAnalyzerModel) handlePlaybackKey(tev *tcell.EventKey) tea.Cmd {
	switch tev.Key() {
	case tcell.KeyRune:
		switch tev.Rune() {
		case ' ':
			// Space: toggle pause
			m.playbackPaused = !m.playbackPaused
			m.RefreshContent()
			return func() tea.Msg { return nil }
		case '+', '=':
			// Increase speed
			switch m.playbackSpeed {
			case 0.5:
				m.playbackSpeed = 1.0
			case 1.0:
				m.playbackSpeed = 2.0
			case 2.0:
				m.playbackSpeed = 4.0
			}
			m.RefreshContent()
			return func() tea.Msg { return nil }
		case '-':
			// Decrease speed
			switch m.playbackSpeed {
			case 4.0:
				m.playbackSpeed = 2.0
			case 2.0:
				m.playbackSpeed = 1.0
			case 1.0:
				m.playbackSpeed = 0.5
			}
			m.RefreshContent()
			return func() tea.Msg { return nil }
		case '<', ',':
			// Seek backward (< or ,)
			m.playbackPos--
			if m.playbackPos < 0 {
				m.playbackPos = 0
			}
			m.playbackPaused = true
			if m.playbackPos < len(m.playbackSnapshots) {
				m.result = &m.playbackSnapshots[m.playbackPos]
				m.findings, m.tunneling = buildFindingsWithSticky(m.result, m.app.PcapShowAllFindings, m.app.PcapSortMode, m.app.PcapGroupBy, m.stickyFindings, m.stickyFindingBytes, m.stickyFindingFirstFrame, m.stickyFindingFirstPacket, m.stickyFindingLastPacket)
			}
			m.RefreshContent()
			return func() tea.Msg { return nil }
		case '>', '.':
			// Seek forward (> or .)
			m.playbackPos++
			maxPos := len(m.playbackSnapshots) - 1
			if maxPos < 0 {
				maxPos = 0
			}
			if m.playbackPos > maxPos {
				m.playbackPos = maxPos
			}
			m.playbackPaused = true
			if m.playbackPos < len(m.playbackSnapshots) {
				m.result = &m.playbackSnapshots[m.playbackPos]
				m.findings, m.tunneling = buildFindingsWithSticky(m.result, m.app.PcapShowAllFindings, m.app.PcapSortMode, m.app.PcapGroupBy, m.stickyFindings, m.stickyFindingBytes, m.stickyFindingFirstFrame, m.stickyFindingFirstPacket, m.stickyFindingLastPacket)
			}
			m.RefreshContent()
			return func() tea.Msg { return nil }
		}
	case tcell.KeyHome:
		// Jump to start
		m.playbackPos = 0
		m.playbackPaused = true
		if len(m.playbackSnapshots) > 0 {
			m.result = &m.playbackSnapshots[m.playbackPos]
			m.findings, m.tunneling = buildFindingsWithSticky(m.result, m.app.PcapShowAllFindings, m.app.PcapSortMode, m.app.PcapGroupBy, m.stickyFindings, m.stickyFindingBytes, m.stickyFindingFirstFrame, m.stickyFindingFirstPacket, m.stickyFindingLastPacket)
		}
		m.RefreshContent()
		return func() tea.Msg { return nil }
	case tcell.KeyEnd:
		// Jump to end
		m.playbackPos = len(m.playbackSnapshots) - 1
		if m.playbackPos < 0 {
			m.playbackPos = 0
		}
		m.playbackPaused = true
		if len(m.playbackSnapshots) > 0 {
			m.result = &m.playbackSnapshots[m.playbackPos]
			m.findings, m.tunneling = buildFindingsWithSticky(m.result, m.app.PcapShowAllFindings, m.app.PcapSortMode, m.app.PcapGroupBy, m.stickyFindings, m.stickyFindingBytes, m.stickyFindingFirstFrame, m.stickyFindingFirstPacket, m.stickyFindingLastPacket)
		}
		m.RefreshContent()
		return func() tea.Msg { return nil }
	}
	return nil
}

// startAnalysis kicks off the ingest goroutine and seeds the channel
// listeners. Returns a tea.Cmd that delivers PcapAnalysisStartedMsg so
// the listeners attach inside Update (not on a background goroutine).
//
// Automatically detects Zeek logs (.log files or directories with conn.log)
// and routes to the appropriate parser. All modes use streaming for
// real-time display and playback support.
func (m *PcapAnalyzerModel) startAnalysis() tea.Cmd {
	path := strings.TrimSpace(m.app.PcapPath)
	isZeek := pcap.IsZeekLog(path)

	progressCh := make(chan pcap.IngestProgress, 32)
	resultCh := make(chan pcap.IngestResult, 8)

	ctx, cancel := context.WithCancel(context.Background())
	m.app.PcapCancelFunc = cancel
	m.app.PcapAnalysisRun = true

	if isZeek {
		// Zeek log analysis with streaming
		go func() {
			defer close(progressCh)
			defer close(resultCh)
			pcap.IngestZeekWithStreaming(ctx, path, progressCh, resultCh)
		}()
	} else {
		// PCAP/PCAPNG with streaming: emits intermediate results for
		// real-time display + playback support.
		go func() {
			defer close(progressCh)
			defer close(resultCh)
			pcap.IngestWithStreaming(ctx, path, progressCh, resultCh)
		}()
	}

	return func() tea.Msg {
		return PcapAnalysisStartedMsg{progressCh: progressCh, resultCh: resultCh, tail: false, streaming: true}
	}
}

func waitPcapProgress(ch chan pcap.IngestProgress) tea.Cmd {
	return func() tea.Msg {
		p, ok := <-ch
		if !ok {
			return pcapProgressClosedMsg{}
		}
		return PcapAnalysisProgressMsg{Progress: p}
	}
}

// waitPcapResult blocks on the next result. Tail mode sends many; the
// channel close (returned as ok=false) signals end-of-stream, which we
// flag via the closed bool so the model stops re-issuing the wait cmd.
func waitPcapResult(ch chan pcap.IngestResult) tea.Cmd {
	return func() tea.Msg {
		r, ok := <-ch
		if !ok {
			return pcapResultClosedMsg{}
		}
		return PcapAnalysisResultMsg{Result: r}
	}
}

// ── view layout ────────────────────────────────────────────────────────

func (m PcapAnalyzerModel) View() string {
	w := m.width
	h := m.height
	if w <= 0 || h <= 0 {
		return ""
	}

	var sections []string
	sections = append(sections, m.renderHeader())
	sections = append(sections, m.renderSetup())

	bottom := m.renderBottomBar(w)

	used := 0
	for _, s := range sections {
		used += lipgloss.Height(s)
	}
	used += lipgloss.Height(bottom)
	// Reserve ONE row of margin so the bottom panel's bottom border is
	// never pushed off-screen by PadViewToTerminal's clipping. Without
	// this, the CONNECTIONS box's bottom border was clipped — operator
	// reported the panel ending in content rather than a "╰────╯" line.
	const bottomBorderSafetyMargin = 1
	remaining := h - used - bottomBorderSafetyMargin
	if remaining < 4 {
		remaining = 4
	}

	// Always render the two stacked panels (FINDINGS / DETAILS)
	// regardless of stage. The user wants the layout in place from
	// the moment the pcap analyzer view opens — not snapping in
	// only after results land. Stages that don't yet have data
	// render placeholder content inside each panel instead of
	// swapping in a separate full-screen layout.
	mp := &m
	mp.ensureFindingsCurrent()
	panelsH := remaining
	if panelsH < 6 {
		panelsH = 6
	}
	findingsH, detailH := splitPanelHeights(panelsH)
	findingsPanel := m.renderFindingsPanel(w, findingsH)
	detailPanel := m.renderDetailsPanel(w, detailH)
	sections = append(sections, findingsPanel, detailPanel, bottom)

	view := lipgloss.JoinVertical(lipgloss.Left, sections...)

	if m.app.PcapBrowsing {
		view = overlayCenter(view, renderPcapBrowserPanel(m.app, w, h), w, h)
	}
	if m.app.PcapShowHelp {
		view = overlayCenter(view, renderHelpPanel("PCAP Analyzer Menu", pcapAnalyzerMenuHelpOptions(), w), w, h)
	}
	if m.app.ShowQuitConfirm && m.app.QuitConfirmDeadline.After(time.Now()) {
		view = overlayCenter(view, renderQuitConfirm(m.app.QuitConfirmDeadline, w), w, h)
	}
	return view
}

// renderPcapBrowserPanel draws the directory-browser overlay shown
// when the operator presses Tab (or `b`) on the File field. Layout:
//
//	╭─ Browse — <path> ───────────────────╮
//	│  > ../                              │
//	│    Documents/                       │
//	│    Downloads/                       │
//	│    capture.pcap                     │
//	│    sample.pcapng                    │
//	│ ↑/↓ navigate  ↵ select  Esc cancel  │
//	╰─────────────────────────────────────╯
//
// Selection highlights with the same accent style the help panel uses.
// The directory header is truncated to fit the panel width.
func renderPcapBrowserPanel(app *shared.AppState, screenW, screenH int) string {
	const minW = 40
	width := screenW * 2 / 3
	if width < minW {
		width = minW
	}
	if width > screenW-4 {
		width = screenW - 4
	}
	if width < minW {
		width = minW
	}
	maxRows := screenH - 8
	if maxRows < 5 {
		maxRows = 5
	}
	if maxRows > 18 {
		maxRows = 18
	}

	entries := app.PcapBrowseEntries
	cursor := app.PcapBrowseCursor
	if cursor < 0 {
		cursor = 0
	}
	if cursor >= len(entries) {
		cursor = len(entries) - 1
	}
	// Scroll window so the cursor stays in view.
	start := 0
	if len(entries) > maxRows {
		half := maxRows / 2
		start = cursor - half
		if start < 0 {
			start = 0
		}
		if start > len(entries)-maxRows {
			start = len(entries) - maxRows
		}
	}
	end := start + maxRows
	if end > len(entries) {
		end = len(entries)
	}

	titleDir := app.PcapBrowseDir
	header := "Browse — " + titleDir
	if w := width - 4; len(header) > w && w > 5 {
		header = "Browse — …" + titleDir[len(titleDir)-(w-11):]
	}

	rowStyle := lipgloss.NewStyle()
	dimStyle := lipgloss.NewStyle().Foreground(colorDim)
	cursorStyle := lipgloss.NewStyle().Foreground(colorCyan).Bold(true)

	var lines []string
	for i := start; i < end; i++ {
		entry := entries[i]
		marker := "  "
		render := rowStyle
		if i == cursor {
			marker = "> "
			render = cursorStyle
		}
		// Make directories visually distinct from files.
		styled := entry
		if strings.HasSuffix(entry, "/") {
			styled = render.Render(entry)
		} else if entry == "../" {
			styled = render.Render(entry)
		} else {
			styled = render.Render(entry)
		}
		_ = styled
		line := marker + render.Render(entry)
		// Truncate to interior width (panel border eats 2 chars on each side).
		line = TruncateToWidth(line, width-4)
		lines = append(lines, "  "+line)
	}
	if len(lines) == 0 {
		lines = append(lines, dimStyle.Render("   (no .pcap or .pcapng files in this directory)"))
	}
	footer := dimStyle.Render("  ↑/↓ navigate  ⏎ select  ⌫ up  Tab edit path  Esc cancel")
	body := strings.Join(append(lines, "", footer), "\n")
	return renderAccentPanel(width, len(lines)+4, header, body)
}

// splitPanelHeights divides the available DISPLAY area between the
// Findings panel (top) and the Details panel (bottom). 60/40 split
// favoring Findings since that's the operator's primary navigation
// surface; Details holds whatever the selected row's content is.
// Both panels need at least 5 lines to render their border + at
// least one viewport line.
func splitPanelHeights(total int) (findings, details int) {
	if total < 10 {
		// Cramped; give Findings everything past the minimum Details.
		details = 5
		findings = total - details
		if findings < 5 {
			findings = 5
		}
		return
	}
	findings = total * 60 / 100
	if findings < 5 {
		findings = 5
	}
	details = total - findings
	if details < 5 {
		details = 5
		findings = total - details
	}
	return
}

func (m PcapAnalyzerModel) renderHeader() string {
	w := m.width
	if w <= 0 {
		w = 80
	}
	return shellBanner(w)
}

func (m PcapAnalyzerModel) renderBottomBar(w int) string {
	var line string
	// Show playback controls when streaming with snapshots (during both analyzing and results)
	if m.streaming && len(m.playbackSnapshots) > 0 {
		status := "▶"
		if m.playbackPaused {
			status = "⏸"
		}
		speedStr := fmt.Sprintf("%.1fx", m.playbackSpeed)
		pos := m.playbackPos + 1
		total := len(m.playbackSnapshots)
		playbackInfo := fmt.Sprintf("%s %d/%d  %s", status, pos, total, speedStr)
		controls := "space pause/play  ,/. seek  Home/End jump  +/- speed"
		line = bgSp(1) + dimText.Render(playbackInfo+"    "+controls)
	} else {
		line = bgSp(1) + dimText.Render("esc dashboard    ↑↓ select    tab browse    g gui    enter analyze    ? menu")
	}
	if pad := w - lipgloss.Width(line); pad > 0 {
		line += bgSp(pad)
	}
	return line
}

func (m PcapAnalyzerModel) renderSetup() string {
	w := m.width
	if w <= 0 {
		w = 80
	}

	pathValue := m.app.PcapPath
	if strings.TrimSpace(pathValue) == "" {
		pathValue = ""
	}

	// Single action mode: Analyze / Cancel / Re-analyze
	actionLabel := platform.IconPlay + " Analyze"
	switch m.app.PcapStage {
	case pcapStageAnalyzing:
		// Inline mini progress bar next to the Cancel button
		done := int(m.progress.WindowsReplayed)
		total := int(m.progress.WindowsTotal)
		if total <= 0 {
			total = done
		}
		pct := 0
		if total > 0 {
			if done > total {
				done = total
			}
			pct = (done * 100) / total
		}
		actionLabel = platform.IconStop + " Cancel  " +
			plainProgressBar(done, total, 16) +
			fmt.Sprintf("  %3d%%", pct)
	case pcapStageResults:
		actionLabel = platform.IconReload + " Re-analyze"
	}

	rows := []FormRow{
		{
			Field:     pcapFieldFile,
			Label:     "File",
			Value:     pathValue,
			Editable:  true,
			CursorPos: m.app.PcapPathCursor,
		},
		{
			Field: pcapFieldAction,
			Label: "Action",
			Value: actionLabel,
		},
	}
	return renderSetupPanel("SETUP", rows, m.app.PcapField, m.app.PcapEditing, w)
}

func (m *PcapAnalyzerModel) InitViewport() {
	if m.width <= 0 || m.height <= 0 {
		return
	}
	var above []string
	above = append(above, m.renderHeader())
	above = append(above, m.renderSetup())
	used := 0
	for _, s := range above {
		used += lipgloss.Height(s)
	}
	// Match the View() bottom-border safety margin so viewport heights
	// stay in sync with layout heights (otherwise the viewport thinks
	// it has 1 more row than the rendered panel actually shows).
	// Also account for the bottom bar (1 line).
	reportH := m.height - used - 2
	if reportH < 4 {
		reportH = 4
	}
	reportW := m.width - 2
	if reportW < 8 {
		reportW = 8
	}

	// Initialise the two viewports the first time we have geometry;
	// the legacy single viewport stays around for any callers that
	// might still touch it but the 3-panel layout drives the visible
	// content.
	if !m.ready {
		m.viewport = viewport.New(reportW, 4)
		m.viewport.Style = lipgloss.NewStyle()
		m.viewportFindings = viewport.New(reportW, 4)
		m.viewportFindings.Style = lipgloss.NewStyle()
		m.viewportDetail = viewport.New(reportW, 4)
		m.viewportDetail.Style = lipgloss.NewStyle()
		m.ready = true
	}

	// Always size the two stacked viewports for the 2-panel layout.
	// The DISPLAY area is split 60/40 Findings / Details.
	panelsH := reportH
	if panelsH < 10 {
		panelsH = 10
	}
	findingsPanelH, detailPanelH := splitPanelHeights(panelsH)
	findingsVpH := findingsPanelH - 2
	detailVpH := detailPanelH - 2
	if findingsVpH < 2 {
		findingsVpH = 2
	}
	if detailVpH < 2 {
		detailVpH = 2
	}
	m.viewportFindings.Width = reportW
	m.viewportFindings.Height = findingsVpH
	m.viewportDetail.Width = reportW
	m.viewportDetail.Height = detailVpH
}

func (m *PcapAnalyzerModel) RefreshContent() {
	if !m.ready {
		m.InitViewport()
	}
	if !m.ready {
		return
	}
	// Always drive both viewports — picker / analyzing / results all
	// share the same 3-panel layout so the operator sees the
	// structure from the moment they enter the view. Stages that
	// don't yet have findings render placeholder content into the
	// Findings panel; the Details panel is empty until a finding is
	// selected.
	m.InitViewport() // re-size in case the timeline band toggled
	findings := m.buildContent()
	if h := fnvHash(findings); h != m.findingsKey {
		m.findingsKey = h
		m.viewportFindings.SetContent(findings)
	}
	m.ensureFindingsCursorVisible()
	detail := m.buildDetailContent()
	if h := fnvHash(detail); h != m.detailKey {
		m.detailKey = h
		m.viewportDetail.SetContent(detail)
	}
}

// ensureFindingsCursorVisible scrolls viewportFindings so the cursor
// row stays within the visible window. The findings content lays out
// as: line 0 = header, line 1+i = finding i. When the operator
// arrows past the bottom of the visible area, the viewport scrolls
// down to keep the cursor in view; same in reverse for up-arrows.
//
// Also clamps app.PcapRowCursor in place. Without this write-back, the
// KeyDown handler in keys/pcap.go would let the cursor index drift
// far past len(findings) when the user holds the down arrow, requiring
// the same number of up-arrow presses to reach the visible area again
// (operator-reported 2026-05-02 — "have to hold the up arrow to move
// up in the findings box"). Clamping here fixes it without changing
// the keymap.
func (m *PcapAnalyzerModel) ensureFindingsCursorVisible() {
	if !m.ready || len(m.findings) == 0 {
		return
	}
	h := m.viewportFindings.Height
	if h <= 0 {
		return
	}
	cursor := m.app.PcapRowCursor
	if cursor < 0 {
		cursor = 0
	}
	if cursor >= len(m.findings) {
		cursor = len(m.findings) - 1
	}
	m.app.PcapRowCursor = cursor
	cursorLine := 1 + cursor // header occupies line 0
	yo := m.viewportFindings.YOffset
	switch {
	case cursorLine < yo:
		m.viewportFindings.SetYOffset(cursorLine)
	case cursorLine >= yo+h:
		m.viewportFindings.SetYOffset(cursorLine - h + 1)
	}
}

// buildContent renders the body that lives inside the DISPLAY scroll
// region. The header + SETUP frame stay constant; only this string
// changes per stage.
func (m PcapAnalyzerModel) buildContent() string {
	switch m.app.PcapStage {
	case pcapStageAnalyzing:
		return m.buildAnalyzingContent()
	case pcapStageResults:
		if m.app.PcapResultsTab == "destinations" {
			return m.buildC2DestinationsContent()
		}
		return m.buildResultsContent()
	default:
		return m.buildPickerContent()
	}
}

func (m PcapAnalyzerModel) buildPickerContent() string {
	var b strings.Builder
	if m.app.PcapError != "" {
		b.WriteString(statusFail.Render("  error: " + m.app.PcapError))
		b.WriteString("\n\n")
	}
	b.WriteString(dimText.Render("  Pick a pcap file in the SETUP form above and"))
	b.WriteString("\n")
	b.WriteString(dimText.Render("  hit "))
	b.WriteString(lipgloss.NewStyle().Foreground(colorAccent).Bold(true).Render("Action"))
	b.WriteString(dimText.Render(" to start the analyzer."))
	b.WriteString("\n\n")
	b.WriteString(dimText.Render("  Findings, timeline, and per-row details will populate here."))
	return b.String()
}

// buildAnalyzingContent renders the FINDINGS panel content during the
// analyzing stage. The progress feedback (spinner / packet counters /
// progress bar) used to live here but was visually noisy — operators
// already see analysis progress from the TIMELINE bar filling in
// left-to-right and the SETUP Action button switching to "Cancel
// analysis". Keep this stage-specific content minimal: a single-line
// status so the panel doesn't look frozen, no spinner glyphs.
func (m PcapAnalyzerModel) buildAnalyzingContent() string {
	var b strings.Builder
	b.WriteString(dimText.Render("  Analyzing capture..."))
	b.WriteString("\n\n")
	b.WriteString(dimText.Render("  Findings will populate here as the replay progresses."))
	return b.String()
}

// plainProgressBar produces a width-correct ASCII/Unicode progress
// bar without any embedded lipgloss style escapes. Used inside form
// rows where the parent (selection-highlighted) row applies its own
// style: embedding inner styles here would emit ANSI colour codes
// mid-string and break the outer row's bg padding.
func plainProgressBar(done, total, width int) string {
	if width < 4 {
		width = 4
	}
	if total <= 0 {
		return strings.Repeat(" ", width)
	}
	if done < 0 {
		done = 0
	}
	if done > total {
		done = total
	}
	fillCount := (done * width) / total
	if fillCount < 0 {
		fillCount = 0
	}
	if fillCount > width {
		fillCount = width
	}
	// Square blocks: ■ for filled, □ for empty (matches ML dashboard, no brackets)
	return strings.Repeat("■", fillCount) + strings.Repeat("□", width-fillCount)
}

func (m PcapAnalyzerModel) buildResultsContent() string {
	if m.result == nil {
		return inspValue.Render("No result yet.")
	}
	mp := &m
	mp.ensureFindingsCurrent()
	res := mp.result

	// Use the FINDINGS panel's viewport width when in the split-panel
	// results stage; fall back to the legacy single viewport for
	// safety when the model hasn't been initialised yet.
	contentW := m.viewportFindings.Width
	if contentW <= 0 {
		contentW = m.viewport.Width
	}
	if contentW < 60 {
		contentW = 60
	}

	var b strings.Builder

	// Timeline strip is rendered as a fixed band in View() (above the
	// FINDINGS panel) — no longer inside the scrollable viewport.

	if len(mp.findings) == 0 {
		// Debug: show why no findings
		if mp.result != nil {
			b.WriteString(dimText.Render(fmt.Sprintf("  No findings (%d candidates in result). Press 'a' to show all.", len(mp.result.Candidates))))
		} else {
			b.WriteString(dimText.Render("  No result yet. Press 'a' to show all traffic."))
		}
		return b.String()
	}

	cursor := m.app.PcapRowCursor
	if cursor < 0 {
		cursor = 0
	}
	if cursor >= len(mp.findings) {
		cursor = len(mp.findings) - 1
	}

	cols := computePcapFindingCols(contentW, mp.findings, res)
	b.WriteString(renderPcapFindingHeader(cols))
	b.WriteString("\n")
	for i, c := range mp.findings {
		b.WriteString(renderPcapFindingLine(c, mp.tunneling[i], i == cursor, cols, res))
		b.WriteString("\n")
	}
	return b.String()
}

// buildC2DestinationsContent renders a contour-style panel listing
// every external destination contacted in the capture, ordered worst-
// role first. One row per per-flow candidate (the per-destination
// candidates allocated by Phase-1 attribution); per-host rollups and
// listener candidates are excluded so this view stays focused on
// "where did the host call out to and what did the analyzer think".
//
// Compensates for pcap mode's lack of process names: an analyst gets
// to see "this destination got beacon" + ASN, instead of
// just "the host had beacon somewhere".
func (m PcapAnalyzerModel) buildC2DestinationsContent() string {
	if m.result == nil {
		return inspValue.Render("No result yet.")
	}
	res := m.result

	contentW := m.viewportFindings.Width
	if contentW <= 0 {
		contentW = m.viewport.Width
	}
	if contentW < 60 {
		contentW = 60
	}

	rows := collectDestinationRows(res)
	if len(rows) == 0 {
		return dimText.Render("  No external destinations in this capture.")
	}

	// Timeline strip rendered as a fixed band by View(); not duplicated here.
	var b strings.Builder

	hdrStyle := lipgloss.NewStyle().Bold(true).Foreground(colorTextHi)
	const (
		remoteW = 24
		asnW    = 22
		bytesW  = 10
		firstW  = 10
		roleW   = 10 // "Outbound" is 8 chars
		tunnelW = 6  // "ACTIVE" is 6 chars
		gutter  = 2
		marginL = 2
	)
	used := marginL + remoteW + asnW + bytesW + firstW + roleW + tunnelW + gutter*5
	_ = used

	b.WriteString("  ")
	b.WriteString(hdrStyle.Render(padRight("REMOTE", remoteW)))
	b.WriteString("  ")
	b.WriteString(hdrStyle.Render(padRight("ASN / ORG", asnW)))
	b.WriteString("  ")
	b.WriteString(hdrStyle.Render(padLeft("BYTES", bytesW)))
	b.WriteString("  ")
	b.WriteString(hdrStyle.Render(padRight("FIRST", firstW)))
	b.WriteString("  ")
	b.WriteString(hdrStyle.Render(padRight("ROLE", roleW)))
	b.WriteString("  ")
	b.WriteString(hdrStyle.Render(padCenter("TUNNEL", tunnelW)))
	b.WriteString("\n")

	for _, r := range rows {
		// Role color matches the findings table's coloring.
		roleStyle := bodyText
		switch shared.RoleFamily(r.role) {
		case "beacon":
			roleStyle = lipgloss.NewStyle().Foreground(colorAlert) // Red for beacon
		case "pivot":
			roleStyle = lipgloss.NewStyle().Foreground(colorWarn) // Yellow for pivot
		}
		// Match main dashboard STATUS column styling
		tunnelCell := lipgloss.NewStyle().Foreground(colorDim).Render("--")
		if r.tunneling {
			tunnelCell = lipgloss.NewStyle().Foreground(colorAlert).Bold(true).Render("ACTIVE")
		}
		b.WriteString("  ")
		b.WriteString(padRight(truncRight(r.remote, remoteW), remoteW))
		b.WriteString("  ")
		b.WriteString(dimText.Render(padRight(truncRight(r.asn, asnW), asnW)))
		b.WriteString("  ")
		b.WriteString(padLeft(formatBytesShort(r.bytes), bytesW))
		b.WriteString("  ")
		b.WriteString(dimText.Render(padRight(r.first, firstW)))
		b.WriteString("  ")
		b.WriteString(roleStyle.Render(padRight(r.role, roleW)))
		b.WriteString("  ")
		b.WriteString(padCenter(tunnelCell, tunnelW))
		b.WriteString("\n")
	}
	return b.String()
}

type destRow struct {
	remote    string // ip:port
	asn       string
	bytes     uint64
	first     string // HH:MM:SS
	role      string
	tunneling bool
}

// collectDestinationRows walks the per-flow candidates and projects
// them into display rows for the C2 panel. Each row is one
// (localIP, remoteIP, remotePort) destination — the per-host rollups
// (`pcap:<ip> outbound-ext|int`) are skipped since the per-flow rows
// already cover them with finer granularity. Sorted worst-role first.
func collectDestinationRows(res *pcap.IngestResult) []destRow {
	out := make([]destRow, 0, len(res.Candidates))
	for i := range res.Candidates {
		c := &res.Candidates[i]
		if c.Proc == nil {
			continue
		}
		// Only per-flow candidates: name has the "→" arrow separator
		// inserted by buildPcapAttribution.
		if !strings.Contains(c.Proc.Name, "→") {
			continue
		}
		// Extract remote (everything after "→ ").
		idx := strings.Index(c.Proc.Name, "→")
		if idx < 0 {
			continue
		}
		remote := strings.TrimSpace(c.Proc.Name[idx+len("→"):])
		// Skip internal-RFC1918 destinations from the C2 panel — that's
		// the lateral-movement view, not the C2-callout view. Operator
		// can still see them in the per-flow findings table.
		hostPart := remote
		if i := strings.LastIndex(remote, ":"); i > 0 {
			hostPart = remote[:i]
		}
		if shared.IsLoopbackIP(hostPart) || shared.IsInternalIP(hostPart) {
			continue
		}
		asnLabel := ""
		if orgs := shared.LookupCachedASNOrgsForIP(hostPart); len(orgs) > 0 {
			asnLabel = orgs[0]
		} else if strings.Contains(hostPart, "/") {
			// Cluster name carries a /16 prefix (e.g. "104.21.0.0/16")
			// rather than an exact IP; fall back to scanning the cache
			// for any cached IP in that /16 and return its orgs.
			if orgs := shared.LookupCachedASNOrgsForPrefix(hostPart); len(orgs) > 0 {
				asnLabel = orgs[0]
			}
		}
		first := ""
		if t, ok := res.FirstPacketByPID[c.Proc.Pid]; ok {
			first = t.Format("15:04:05")
		}
		bytes := res.BytesByEndpointPID[c.Proc.Pid]
		row := destRow{
			remote:    remote,
			asn:       asnLabel,
			bytes:     bytes,
			first:     first,
			role:      c.Role,
			tunneling: isPcapTunnelingActive(*c, res),
		}
		out = append(out, row)
	}
	// Worst-role first: tunneling > pivot > beacon >
	// outbound > everything else. Within a role bucket: highest bytes
	// first.
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := destRoleRank(out[i]), destRoleRank(out[j])
		if ri != rj {
			return ri > rj
		}
		return out[i].bytes > out[j].bytes
	})
	return out
}

func destRoleRank(r destRow) int {
	if r.tunneling {
		return 5
	}
	switch shared.RoleFamily(r.role) {
	case "pivot":
		return 4
	case "beacon":
		return 3
	case "outbound":
		return 1
	}
	return 0
}

// formatBytesShort returns "1.2 KB", "8.3 MB" — short enough for the
// table column. Mirrors the style used elsewhere in the dashboard.
func formatBytesShort(n uint64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	if n < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	}
	if n < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(n)/(1024*1024))
	}
	return fmt.Sprintf("%.2f GB", float64(n)/(1024*1024*1024))
}

func truncRight(s string, w int) string {
	if len(s) <= w {
		return s
	}
	if w <= 1 {
		return s[:w]
	}
	return s[:w-1] + "…"
}


// pcapFindingCols holds the per-column widths used by the FINDINGS
// list. Layout mirrors the dashboard's PROCESS VIEW: all columns
// left-aligned, simple two-space gutters, no centered arrow column.
type pcapFindingCols struct {
	frameW  int // pcap frame # of finding's first packet
	localW  int // local ip:port
	remoteW int // remote ip:port
	roleW   int // role label
	tunnelW int // "yes" / "" tunneling flag
	bytesW  int // bytes (formatted)
	timeW   int // exact date+time of finding's first packet
}

// pcapFindingTimeFormat is the date+time format used in the FINDINGS
// table's TIME column. Width MUST match pcapFindingCols.timeW so the
// header lines up with the rendered values.
const pcapFindingTimeFormat = "2006-01-02 15:04:05"
const pcapFindingTimeWidth = 19

// pcapFindingFrameWidth is the column width for the pcap frame
// identifier (1-based packet number). Wide enough to hold #99,999,999
// — well past anything you'd see in even a long pcap.
const pcapFindingFrameWidth = 9

func computePcapFindingCols(width int, findings []shared.Candidate, res *pcap.IngestResult) pcapFindingCols {
	const (
		localMin    = 18 // smallest sane IP:port column
		remoteMin   = 18
		roleW       = 10 // "Outbound" is 8 chars
		tunnelW     = 6  // "ACTIVE" is 6 chars
		bytesW      = 10
		gutter      = 2 // spaces between columns (matches process view)
		marginLeft  = 2 // initial indent (matches '> ' selection prefix)
		marginRight = 2
	)
	// Measure the actual max width needed for LOCAL and REMOTE based
	// on the rendered tuples — capped so a single freakishly long IPv6
	// row can't blow the column out, but flexible enough that a
	// typical IPv4:port (max 21 chars) fits without truncation.
	localNeed := localMin
	remoteNeed := remoteMin
	for _, c := range findings {
		local, remote := pcapTupleFor(c, res)
		if w := lipgloss.Width(local); w > localNeed {
			localNeed = w
		}
		if w := lipgloss.Width(remote); w > remoteNeed {
			remoteNeed = w
		}
	}
	const localMax = 30 // truncate at this; covers IPv6:port comfortably
	if localNeed > localMax {
		localNeed = localMax
	}
	if remoteNeed > localMax {
		remoteNeed = localMax
	}
	cols := pcapFindingCols{
		frameW:  pcapFindingFrameWidth,
		localW:  localNeed,
		remoteW: remoteNeed,
		roleW:   roleW,
		tunnelW: tunnelW,
		bytesW:  bytesW,
		timeW:   pcapFindingTimeWidth,
	}
	// Mirrors the dashboard process view: grow LOCAL / REMOTE up to
	// content need only, leave any leftover as trailing whitespace
	// instead of stretching the columns. Eliminates the giant gaps
	// between LOCAL ↔ REMOTE ↔ ROLE on wide terminals.
	_ = width
	_ = marginLeft
	_ = marginRight
	_ = gutter
	return cols
}

// renderPcapFindingHeader renders the bold header row using the same
// "%-*s" left-aligned padding the dashboard process view uses, two-
// space inter-column gutters, no centered arrow column.
func renderPcapFindingHeader(cols pcapFindingCols) string {
	hdr := lipgloss.NewStyle().Bold(true).Foreground(colorTextHi)
	return "  " +
		hdr.Render(fmt.Sprintf("%-*s", cols.frameW, "ID")) + "  " +
		hdr.Render(fmt.Sprintf("%-*s", cols.localW, "LOCAL")) + "  " +
		hdr.Render(fmt.Sprintf("%-*s", cols.remoteW, "REMOTE")) + "  " +
		hdr.Render(fmt.Sprintf("%-*s", cols.roleW, "ROLE")) + "  " +
		hdr.Render(padCenter("TUNNEL", cols.tunnelW)) + "  " +
		hdr.Render(fmt.Sprintf("%-*s", cols.bytesW, "BYTES")) + "  " +
		hdr.Render(fmt.Sprintf("%-*s", cols.timeW, "TIME"))
}

// rowVisibleWidth returns the total visible width of a rendered row,
// matching the layout in renderPcapFindingLine. Used to extend the
// selection background across the entire line.
func rowVisibleWidth(cols pcapFindingCols) int {
	// 2 (prefix+space) + frameW + 2 + localW + 2 + remoteW + 2 + roleW + 2 + tunnelW + 2 + bytesW + 2 + timeW
	return 2 + cols.frameW + 2 + cols.localW + 2 + cols.remoteW + 2 + cols.roleW + 2 + cols.tunnelW + 2 + cols.bytesW + 2 + cols.timeW
}

// renderPcapFindingLine renders one finding as a single columnar row
// in the same shape as the dashboard's PROCESS VIEW:
//
//	ID  LOCAL  REMOTE  ROLE  TUNNEL  BYTES  TIME
//
// All columns left-aligned with %-*s padding, two-space gutters.
// TUNNEL is "yes" when the offline tunneling-shape gate fires, blank
// otherwise. ID is the 1-based pcap frame number of the finding's
// first packet (matches Wireshark's frame.number).
func renderPcapFindingLine(c shared.Candidate, tunnel bool, selected bool, cols pcapFindingCols, res *pcap.IngestResult) string {
	if c.Proc == nil {
		return ""
	}
	local, remote := pcapTupleFor(c, res)
	// Keep canonical family for color styling (lgRoleStyle dispatches
	// on RoleFamily) and use displayRoleLabel for the visible cell —
	// matches the dashboard convention so operators see "Beacon" /
	// "Pivot" / "Tunnel" everywhere with consistent colors.
	roleFamily := strings.ToLower(c.Role)
	role := displayRoleLabel(shared.RoleFamily(roleFamily))

	tunnelLabel := "--"
	if tunnel {
		tunnelLabel = "ACTIVE"
	}

	bytesStr := FormatBytes(pcapTotalBytes(res, c))

	timeStr := ""
	frameStr := ""
	if res != nil {
		if t, ok := res.FirstPacketByPID[c.Proc.Pid]; ok && !t.IsZero() {
			timeStr = t.UTC().Format(pcapFindingTimeFormat)
		}
		if f, ok := res.FirstFrameByPID[c.Proc.Pid]; ok && f > 0 {
			frameStr = fmt.Sprintf("#%d", f)
		}
	}

	prefix := " "
	// Operator-label indicator. Replaces the cursor space when the
	// finding's cluster has been hand-labeled. M = malicious (red),
	// B = benign (green). Selected row's ">" cursor still wins
	// visually since it overrides this prefix below.
	if c.Proc != nil && c.Proc.Name != "" {
		if pl := shared.LookupPcapOperatorLabel(c.Proc.Name); pl != nil {
			switch pl.Verdict {
			case shared.VerdictMalicious:
				prefix = "M"
			case shared.VerdictBenign:
				prefix = "B"
			}
		}
	}
	prefixStyle := bodyText
	frameStyle := dimText
	localStyle := bodyText
	remoteStyle := bodyText
	bytesStyle := dimText
	timeStyle := dimText
	if selected {
		prefix = ">"
		prefixStyle = lgSelectCursor
		frameStyle = lipgloss.NewStyle().Bold(true).Foreground(colorMuted)
		localStyle = lipgloss.NewStyle().Bold(true).Foreground(colorTextHi)
		remoteStyle = lipgloss.NewStyle().Bold(true).Foreground(colorTextHi)
		bytesStyle = lipgloss.NewStyle().Bold(true).Foreground(colorMuted)
		timeStyle = lipgloss.NewStyle().Bold(true).Foreground(colorMuted)
	}

	// Match main dashboard STATUS column styling
	tunnelStyle := lipgloss.NewStyle().Foreground(colorDim)
	if tunnel {
		tunnelStyle = lipgloss.NewStyle().Foreground(colorAlert).Bold(true)
	}

	// Gap style fills the inter-column spaces with the selection bg
	// (or transparent when not selected) so the highlight looks like
	// one continuous bar instead of leaving holes between cells.
	gap := applySelectBg(bodyText, selected)

	row := applySelectBg(prefixStyle, selected).Render(prefix) + gap.Render(" ") +
		applySelectBg(frameStyle, selected).Render(fmt.Sprintf("%-*s", cols.frameW, TruncateToWidth(frameStr, cols.frameW))) + gap.Render("  ") +
		applySelectBg(localStyle, selected).Render(fmt.Sprintf("%-*s", cols.localW, TruncateToWidth(local, cols.localW))) + gap.Render("  ") +
		applySelectBg(remoteStyle, selected).Render(fmt.Sprintf("%-*s", cols.remoteW, TruncateToWidth(remote, cols.remoteW))) + gap.Render("  ") +
		applySelectBg(lgRoleStyle(roleFamily), selected).Render(fmt.Sprintf("%-*s", cols.roleW, TruncateToWidth(role, cols.roleW))) + gap.Render("  ") +
		applySelectBg(tunnelStyle, selected).Render(padCenter(tunnelLabel, cols.tunnelW)) + gap.Render("  ") +
		applySelectBg(bytesStyle, selected).Render(fmt.Sprintf("%-*s", cols.bytesW, TruncateToWidth(bytesStr, cols.bytesW))) + gap.Render("  ") +
		applySelectBg(timeStyle, selected).Render(fmt.Sprintf("%-*s", cols.timeW, TruncateToWidth(timeStr, cols.timeW)))

	if selected {
		row = lgSelectBg.Width(rowVisibleWidth(cols)).Render(row)
	}
	return row
}

// padCenter centers s within a field of width w.
func padCenter(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if lipgloss.Width(s) >= w {
		return TruncateToWidth(s, w)
	}
	pad := w - lipgloss.Width(s)
	left := pad / 2
	right := pad - left
	return strings.Repeat(" ", left) + s + strings.Repeat(" ", right)
}

// padRight truncates or right-pads s to the given width, returning a
// fixed-width string for column alignment.
func padRight(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if lipgloss.Width(s) > w {
		return TruncateToWidth(s, w)
	}
	return s + strings.Repeat(" ", w-lipgloss.Width(s))
}

// padLeft truncates or left-pads s to the given width.
func padLeft(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if lipgloss.Width(s) > w {
		return TruncateToWidth(s, w)
	}
	return strings.Repeat(" ", w-lipgloss.Width(s)) + s
}

// pcapTupleFor returns the local and remote endpoint strings for the
// candidate's most-decisive flow (or a listener fallback).
func pcapTupleFor(c shared.Candidate, res *pcap.IngestResult) (string, string) {
	if res != nil && c.Proc != nil {
		if flows, ok := res.DecisiveFlowsByPID[c.Proc.Pid]; ok && len(flows) > 0 {
			f := flows[0]
			return fmt.Sprintf("%s:%d", f.LocalIP, f.LocalPort),
				fmt.Sprintf("%s:%d", f.RemoteIP, f.RemotePort)
		}
	}
	// Fallback to c.Conns — per-host rollup outbound candidates
	// (`pcap:<ip> outbound-ext` / `outbound-int`) don't always have
	// DecisiveFlowsByPID populated because that index is keyed off
	// per-flow PIDs. Without this fallback, those rows showed as
	// `—  ===> —` even though the candidate had real connections.
	for _, conn := range c.Conns {
		if conn.RemoteAddress == "" || conn.RemotePort <= 0 {
			continue
		}
		local := "—"
		if conn.LocalAddress != "" && conn.LocalPort > 0 {
			local = fmt.Sprintf("%s:%d", conn.LocalAddress, conn.LocalPort)
		}
		return local, fmt.Sprintf("%s:%d", conn.RemoteAddress, conn.RemotePort)
	}
	if len(c.Listeners) > 0 {
		l := c.Listeners[0]
		return fmt.Sprintf("%s:%d", l.LocalAddress, l.LocalPort), "*:*"
	}
	return "—", "—"
}

// pcapDestEndpoint returns the most operator-relevant remote target.
// Selection order is role-aware so the column shows the meaningful
// peer rather than whichever connection happens to be first in the
// slice:
//
//   - pivot: prefer the INTERNAL relay target (the leg the
//     pivot is forwarding to). If none is internal, fall back to the
//     first established remote, then any remote.
//   - beacon: prefer the ESTABLISHED external remote (the
//     C2 callback channel). If no external is established, fall back
//     to the first established remote, then any remote.
//   - everything else: first established remote, then any remote,
//     then a listener "*:port", then "—".
//
// Ties broken by remote address ascending so re-analyses pick the
// same connection (determinism guarantee).

// buildFindings flattens the orchestrator's candidate slice into a
// single triage-ordered list plus a parallel "is actively tunneling"
// boolean slice.
//
// Two filter modes drive selection:
//
//   - showAll=false (default, the analyst's "did anything bad happen?"
//     view): include candidates that are beacon /
//     pivot / smb-pipe / tunnel by role, OR whose state hits
//     the offline tunneling shape, OR whose synthetic PID is the
//     parent_pid of any other included candidate (so the listener
//     that parents a SOCKS-relay child is always shown for context).
//     A high-precision evidence gate (hasDecisivePcapEvidence) further
//     filters out weak "long-lived HTTPS" verdicts that fire on
//     vendor traffic when offline.
//
//   - showAll=true: include every candidate the analyzer produced.
//     For full-population context when the default view is too
//     aggressive.
//
// Sort modes (driven by app.PcapSortMode):
//
//   - "" / "severity" (default): score desc, beacon-* roles first.
//   - "time": activity peak time (FirstPacketByPID) ascending —
//     follow the pcap's natural chronology.
//   - "bytes": total bytes desc — biggest hitters first.
//
// buildFindingsWithSticky wraps buildFindings and ensures any candidate
// previously classified beacon-* (recorded in `sticky` by the watch
// loop in PcapAnalyzerModel.Update) is preserved in the FINDINGS list
// even if the most-recent classify cycle demoted its role. This stops
// rows from flickering in/out as the per-tick role wobbles between
// outbound and beacon-* on borderline-evidence candidates.
//
// The merge strategy:
//
//  1. Walk res.Candidates. If a candidate's PID is in sticky AND its
//     current role is non-beacon-*, overwrite c.Role/c.Signals with
//     the sticky snapshot so it passes keepCandidate's role gate and
//     surfaces in the table.
//  2. Walk sticky entries that AREN'T in res.Candidates (the per-flow
//     candidate aged out of the latest snapshot). Append them so they
//     keep showing.
//
// Per-flow stats (bytes, ports, FirstFrame) come from res — sticky's
// stats may be stale, but role/signals stay sticky.
func buildFindingsWithSticky(res *pcap.IngestResult, showAll bool, sortMode string, groupBy string, sticky map[string]shared.Candidate, stickyBytes map[string]uint64, stickyFirstFrame map[string]uint64, stickyFirstPacket map[string]time.Time, stickyLastPacket map[string]time.Time) ([]shared.Candidate, []bool) {
	if res == nil {
		return nil, nil
	}
	if len(sticky) == 0 {
		return buildFindings(res, showAll, sortMode, groupBy)
	}
	// Sticky map is keyed by candidate Name (e.g.
	// "pcap:172.16.1.81 → 104.21.0.0/16:443") because pcap synthesis
	// re-allocates PIDs each tick — keying by PID would lose the
	// overlay whenever the cluster set changes alphabetical order.
	//
	// Build a copy of the result with the sticky overlay applied so we
	// don't mutate the live IngestResult shared with other consumers
	// (the orchestrator, debug API, timeline accumulator). Byte maps
	// must also be copied (not just aliased) because we patch sticky
	// entries into them so the zero-byte filter in buildFindings sees
	// real values for sticky-only candidates.
	merged := *res
	merged.Candidates = make([]shared.Candidate, 0, len(res.Candidates)+len(sticky))
	merged.BytesByEndpointPID = make(map[int]uint64, len(res.BytesByEndpointPID)+len(sticky))
	for k, v := range res.BytesByEndpointPID {
		merged.BytesByEndpointPID[k] = v
	}
	merged.BytesByPID = make(map[int]uint64, len(res.BytesByPID)+len(sticky))
	for k, v := range res.BytesByPID {
		merged.BytesByPID[k] = v
	}
	// Copy FirstFrame / FirstPacket maps so we can patch entries for
	// sticky-only or PID-rotated candidates without mutating the
	// shared IngestResult. The renderer's ID and TIME columns read
	// from these via the candidate's CURRENT synthetic PID — without
	// patching, both columns blank out whenever a cluster's PID
	// doesn't match the original allocation.
	merged.FirstFrameByPID = make(map[int]uint64, len(res.FirstFrameByPID)+len(sticky))
	for k, v := range res.FirstFrameByPID {
		merged.FirstFrameByPID[k] = v
	}
	merged.FirstPacketByPID = make(map[int]time.Time, len(res.FirstPacketByPID)+len(sticky))
	for k, v := range res.FirstPacketByPID {
		merged.FirstPacketByPID[k] = v
	}
	merged.LastPacketByPID = make(map[int]time.Time, len(res.LastPacketByPID)+len(sticky))
	for k, v := range res.LastPacketByPID {
		merged.LastPacketByPID[k] = v
	}
	seen := make(map[string]struct{}, len(res.Candidates))
	for _, c := range res.Candidates {
		if c.Proc == nil || c.Proc.Name == "" {
			merged.Candidates = append(merged.Candidates, c)
			continue
		}
		name := c.Proc.Name
		if sc, ok := sticky[name]; ok {
			role := strings.ToLower(c.Role)
			if role != "beacon" && role != "pivot" && role != "smb-pipe" && role != "tunnel" {
				// Latest cycle demoted; keep the sticky role and
				// signal set so the row reads consistently.
				c.Role = sc.Role
				c.Signals = append([]string(nil), sc.Signals...)
				c.Reasons = append([]string(nil), sc.Reasons...)
			}
			// If current PID has zero recorded bytes (PID re-allocated
			// since the candidate was first stuck) but we have a saved
			// snapshot byte count, patch it in so the zero-byte filter
			// doesn't drop the row.
			if stickyBytes != nil {
				if existing := merged.BytesByEndpointPID[c.Proc.Pid]; existing == 0 {
					if saved, ok := stickyBytes[name]; ok && saved > 0 {
						merged.BytesByEndpointPID[c.Proc.Pid] = saved
					}
				}
			}
			// Patch first-frame / first-packet so the ID and TIME
			// columns stay stable even when this cycle's res didn't
			// re-record them under the current PID.
			if stickyFirstFrame != nil {
				if _, present := merged.FirstFrameByPID[c.Proc.Pid]; !present {
					if saved, ok := stickyFirstFrame[name]; ok && saved > 0 {
						merged.FirstFrameByPID[c.Proc.Pid] = saved
					}
				}
			}
			if stickyFirstPacket != nil {
				if t, present := merged.FirstPacketByPID[c.Proc.Pid]; !present || t.IsZero() {
					if saved, ok := stickyFirstPacket[name]; ok && !saved.IsZero() {
						merged.FirstPacketByPID[c.Proc.Pid] = saved
					}
				}
			}
			// Patch LastPacketByPID for tunneling recency check
			if stickyLastPacket != nil {
				if t, present := merged.LastPacketByPID[c.Proc.Pid]; !present || t.IsZero() {
					if saved, ok := stickyLastPacket[name]; ok && !saved.IsZero() {
						merged.LastPacketByPID[c.Proc.Pid] = saved
					}
				}
			}
		}
		merged.Candidates = append(merged.Candidates, c)
		seen[name] = struct{}{}
	}
	// Sticky candidates whose Name didn't show up in this cycle's
	// candidate slice (e.g. the cluster aged out) — keep them visible.
	for name, sc := range sticky {
		if _, ok := seen[name]; ok {
			continue
		}
		merged.Candidates = append(merged.Candidates, sc)
		// Patch saved bytes into merged so the zero-byte filter
		// preserves the sticky row even though the candidate is no
		// longer in res.
		if sc.Proc != nil {
			if stickyBytes != nil {
				if saved, ok := stickyBytes[name]; ok && saved > 0 {
					merged.BytesByEndpointPID[sc.Proc.Pid] = saved
				}
			}
			if stickyFirstFrame != nil {
				if saved, ok := stickyFirstFrame[name]; ok && saved > 0 {
					merged.FirstFrameByPID[sc.Proc.Pid] = saved
				}
			}
			if stickyFirstPacket != nil {
				if saved, ok := stickyFirstPacket[name]; ok && !saved.IsZero() {
					merged.FirstPacketByPID[sc.Proc.Pid] = saved
				}
			}
			// Patch LastPacketByPID for tunneling recency check
			if stickyLastPacket != nil {
				if saved, ok := stickyLastPacket[name]; ok && !saved.IsZero() {
					merged.LastPacketByPID[sc.Proc.Pid] = saved
				}
			}
		}
	}
	return buildFindings(&merged, showAll, sortMode, groupBy)
}

func buildFindings(res *pcap.IngestResult, showAll bool, sortMode string, groupBy string) ([]shared.Candidate, []bool) {
	if res == nil {
		return nil, nil
	}
	// Apply view-time projection if a non-default grouping is selected.
	// This DOES NOT change classification — it just expands or collapses
	// the candidate set into the chosen lens. Each projected row
	// inherits role/signals/reasons from the parent /16 cluster.
	if proj := projectGroupBy(res, groupBy); proj != nil {
		view := *res
		view.Candidates = proj
		res = &view
	}
	// Hard filters — applied regardless of showAll. Two operator
	// complaints made these unconditional:
	//   1. role=="analyzing" candidates pollute the table while the
	//      classifier is still gathering evidence; the user doesn't
	//      want them surfacing at all (the SETUP form's Action button
	//      already conveys "analysis in flight").
	//   2. Empty / placeholder candidates (no local-port, no remote,
	//      0 bytes) render as `—  ===>  —` rows that have no useful
	//      information — exclude them so the table stays tight.
	keepCandidate := func(c *shared.Candidate) bool {
		if c == nil || c.Proc == nil {
			return false
		}
		role := strings.ToLower(c.Role)
		if role == "analyzing" {
			return false
		}
		// Listen / listener candidates are host-context and don't
		// belong in the FINDINGS triage table. The user explicitly
		// said listen shouldn't appear here. Drop them outright,
		// independent of showAll mode.
		if role == "listen" || role == "listener" {
			return false
		}
		// Require usable LOCAL/REMOTE so the row has something to
		// show — checks against the same tuple-extraction logic the
		// renderer uses (pcapTupleFor) to avoid letting candidates
		// through that would render as blank `—  ===> —` rows.
		local, remote := pcapTupleFor(*c, res)
		if local == "—" && remote == "—" {
			return false
		}
		// Drop candidates with zero recorded connections AND zero
		// listeners — operator-confirmed FP 2026-05-04: a finding
		// was rendered with role=Pivot + TUNNEL=yes but the detail
		// pane said "No connections recorded for this finding."
		// A candidate with no observable network shape can't be
		// actioned and should never have made it to the findings
		// table. Listener candidates are already filtered above,
		// but a beacon-* candidate that lost all its connections
		// (e.g. transient flows with no carryover) shouldn't survive.
		if len(c.Conns) == 0 && len(c.Listeners) == 0 {
			return false
		}
		return true
	}

	// Build a set of hosts (local IPs) that have at least one
	// analyzer-level malicious candidate. The TUI's outbound→
	// beacon promotion only fires when the candidate's host
	// shows broader compromise indicators — without this guard, any
	// legitimate HTTPS download to a CDN ASN gets promoted via the
	// CDN-fronted-C2 signal alone (admin laptop downloading a tarball
	// is indistinguishable in pure network shape from a Sliver
	// beacon). Co-located pivot / beacon /
	// smb-pipe / tunnel candidates indicate the host itself is
	// compromised, which is what makes the suspicious outbound a
	// real C2 channel rather than coincidental CDN traffic.
	hostsWithMalice := pcapHostsWithMaliciousCandidates(res)

	// Pass 1: gather "primary" findings — anything that meets the
	// beacon-* / tunneling default-view criteria.
	primary := make(map[int]shared.Candidate, len(res.Candidates))
	for _, c := range res.Candidates {
		if !keepCandidate(&c) {
			continue
		}
		role := strings.ToLower(c.Role)
		isControl := role == "beacon" || role == "pivot" ||
			role == "smb-pipe" || role == "tunnel"
		isTun := isOfflineTunneling(c, res)
		// Outbound candidates that carry decisive beacon
		// signals (CDN-fronted C2, persistent control session, static
		// crypto + HTTP beaconing) are real beacons — the
		// analyzer leaves the role as "outbound" offline because the
		// final role assignment happens in the live ML/scoring layer
		// that needs process attribution. Promote them here so the
		// pcap dashboard surfaces them instead of dropping them.
		// Gate: the candidate's local-host must also have at least
		// one analyzer-level malicious candidate (pivot /
		// internal pivot / sshd-z relay listener, etc.) — that's
		// what distinguishes a real C2 beacon from an admin laptop's
		// legitimate HTTPS-to-CDN download.
		// UI-side outbound→beacon promotion is disabled in
		// pcap mode. The classifier + ApplyPcapModeRoleGuard +
		// demoteUnderEvidencedSyntheticPivots pipeline already promotes
		// candidates with packet-decisive evidence to beacon
		// offline; everything else is intentionally left as outbound
		// because pcap can't access vendor / signing / publisher
		// metadata to filter legitimate CDN traffic. Re-promoting here
		// based on cdn-fronted-c2-candidate (which fires on any CDN
		// destination on port 443) or session-persistent-channel
		// (which fires on long-lived HTTPS) generated wholesale FPs on
		// hosts that happened to have any one beacon-* candidate
		// (e.g. an sshd listener flagged as pivot on synthetic-
		// PID conflation poisoned every outbound flow on the host).
		// Live mode is unchanged: the live ML/scoring layer still
		// promotes via process attribution.
		isPromotedChannel := !isControl && !isTun &&
			!shared.IsPcapMode(&c) &&
			hasOutboundControlChannelEvidence(c) &&
			pcapCandidateHostHasMalice(c, hostsWithMalice)
		if !showAll {
			if !isControl && !isTun && !isPromotedChannel {
				continue
			}
			// High-precision gate for TUI-side promotions only. The
			// classifier's pcap rescue path (ApplyPcapModeRoleGuard +
			// CDN-rescue with byte-floor + push-exclude in roles.go)
			// already requires signal-corroborated high-confidence
			// promotion, so its beacon-* verdicts are trusted here.
			// This gate stays on for the TUI's own outbound→control
			// promotion path (currently disabled in pcap mode anyway,
			// but preserved as defence-in-depth).
			if isPromotedChannel && !hasDecisivePcapEvidence(c, isTun) {
				continue
			}
		}
		if isPromotedChannel {
			c.Role = "beacon"
		}
		primary[c.Proc.Pid] = c
	}

	// Pass 2 (default-view only): include the parent listener of any
	// primary finding, even if the listener didn't pass the decisive
	// evidence gate on its own. Sshd-as-parent-of-pivot is
	// the canonical case — the listener's role is just "listen" but
	// it's load-bearing context for understanding the child's pivot.
	keep := make([]shared.Candidate, 0, len(primary))
	parentSet := make(map[int]struct{})
	if !showAll {
		for _, c := range primary {
			if c.Proc == nil {
				continue
			}
			parentPID := c.Proc.ParentPid
			if parentPID == 0 {
				continue
			}
			if _, ok := primary[parentPID]; ok {
				continue
			}
			parentSet[parentPID] = struct{}{}
		}
		for _, c := range res.Candidates {
			if !keepCandidate(&c) {
				continue
			}
			if _, ok := parentSet[c.Proc.Pid]; ok {
				keep = append(keep, c)
			}
		}
	} else {
		// Show-all mode gathers everything from res.Candidates that
		// passes the analyzing/blank filter and isn't already in
		// `primary`. Without keepCandidate here, the show-all path
		// would re-introduce the analyzing rows + blank `— ===> —`
		// placeholder rows the user explicitly flagged.
		for _, c := range res.Candidates {
			if !keepCandidate(&c) {
				continue
			}
			if _, ok := primary[c.Proc.Pid]; !ok {
				keep = append(keep, c)
			}
		}
	}
	for _, c := range primary {
		keep = append(keep, c)
	}

	// Dedup pass — split into two cases by promotion source, since
	// per-cluster vs aggregate behaviour differs based on what fired:
	//
	//   Case 1: clusters with INDEPENDENT evidence (their own decisive
	//     signal — child-tunnel-relay, contour-egress-tunnel-port,
	//     pivot-listener-plus-outbound, etc). KEEP the per-cluster
	//     row, DROP the aggregate (the cluster IS the finding).
	//
	//   Case 2: clusters promoted ONLY via host-c2-active-pivot —
	//     the host had a confirmed C2 cluster, so every internal
	//     /16:port from that host got the same blanket promotion.
	//     Cheerful's SOCKS-tunneled nmap scan blows out 25-30
	//     individual /16:port rows like this even though it's all
	//     ONE pivot session — operator-reported 2026-05-03 as
	//     "tons of false positives" because PCAP had 29 beacon-
	//     pivot rows when LIVE only showed 1 process. KEEP the
	//     aggregate, DROP the per-cluster rows so the FINDINGS table
	//     surfaces one row per host's pivot activity, not one per
	//     scanned port.
	//
	// Detection coverage is preserved: the aggregate row still says
	// "pivot" with the host-c2-active-pivot signal — the
	// operator sees that 172.16.1.81 is doing implant-relay scanning,
	// the timeline lights up the pivot lane, and clicking the row
	// lists every individual scanned target in CONNECTIONS.
	{
		// Build per-host/per-role-family classification:
		//   independent_set[hostKey] = true   if any non-aggregate cluster
		//                                     on that host has independent
		//                                     decisive evidence
		//   blanket_set[hostKey]     = true   if any non-aggregate cluster
		//                                     on that host has only the
		//                                     blanket host-c2-active-pivot
		//                                     promotion
		independentSet := make(map[string]bool)
		blanketSet := make(map[string]bool)
		for _, c := range keep {
			if c.Proc == nil {
				continue
			}
			host := pcapCandidateHost(c)
			if host == "" {
				continue
			}
			if pcapIsAggregateName(c.Proc.Name) {
				continue
			}
			key := host + "|" + shared.RoleFamily(c.Role)
			if hasOnlyBlanketHostC2Promotion(c) {
				blanketSet[key] = true
			} else {
				independentSet[key] = true
			}
		}
		filtered := keep[:0]
		for _, c := range keep {
			if c.Proc == nil {
				filtered = append(filtered, c)
				continue
			}
			host := pcapCandidateHost(c)
			rf := shared.RoleFamily(c.Role)
			key := host + "|" + rf
			if pcapIsAggregateName(c.Proc.Name) {
				// Aggregate row: keep it ONLY when the host has
				// blanket-promoted clusters AND no independent-evidence
				// clusters. The aggregate becomes the canonical finding
				// for the host's blanket pivot activity.
				if blanketSet[key] && !independentSet[key] {
					filtered = append(filtered, c)
					continue
				}
				if !blanketSet[key] && !independentSet[key] {
					// Host has only the aggregate — keep so operator
					// sees the host listed (legacy behaviour).
					filtered = append(filtered, c)
					continue
				}
				// Host has independent-evidence clusters — they carry
				// the verdict at finer granularity, drop the aggregate.
				continue
			}
			// Non-aggregate cluster: drop if it's blanket-promoted AND
			// the host's aggregate is in `keep` (the aggregate will
			// represent it). Keep if it has independent evidence.
			if hasOnlyBlanketHostC2Promotion(c) {
				// Check whether the host's aggregate is in keep.
				aggregateInKeep := false
				for _, ac := range keep {
					if ac.Proc == nil || !pcapIsAggregateName(ac.Proc.Name) {
						continue
					}
					if pcapCandidateHost(ac) == host && shared.RoleFamily(ac.Role) == rf {
						aggregateInKeep = true
						break
					}
				}
				if aggregateInKeep {
					continue
				}
			}
			filtered = append(filtered, c)
		}
		keep = filtered
	}

	// Drop zero-byte findings unconditionally. The synthetic-PID
	// attribution occasionally wires a candidate to a flow that
	// never carried payload (e.g. a pivot built off
	// `child-tunnel-relay` with no observed bytes), or a parent
	// listener whose own endpoint never received traffic. These
	// rows clutter the dashboard without contributing observable
	// evidence — a finding the analyst can't substantiate from
	// the capture isn't a finding. Previously gated on !showAll
	// which let zero-byte rows leak through once "show all" became
	// the default; the user explicitly flagged this as nonsensical
	// so the filter now runs in both modes.
	{
		filtered := keep[:0]
		for _, c := range keep {
			if pcapTotalBytes(res, c) == 0 {
				continue
			}
			filtered = append(filtered, c)
		}
		keep = filtered
	}

	// Sort by the requested mode. All sorts are stable so ties
	// preserve insertion order (parent listeners stay grouped near
	// their children when severity sort doesn't separate them).
	// candName extracts a stable secondary sort key from the candidate
	// name. Used as a tiebreaker so two candidates with identical
	// primary sort values (same first-packet timestamp, same byte
	// count) end up in deterministic order across re-analyses of the
	// same pcap. Without this, sort.SliceStable preserves INSERTION
	// order — but res.Candidates is built from map iteration so the
	// insertion order itself is non-deterministic.
	candName := func(c shared.Candidate) string {
		if c.Proc == nil {
			return ""
		}
		return c.Proc.Name
	}
	switch sortMode {
	case "time":
		sort.SliceStable(keep, func(i, j int) bool {
			ti := pcapFirstSeen(res, keep[i])
			tj := pcapFirstSeen(res, keep[j])
			if !ti.Equal(tj) {
				return ti.Before(tj)
			}
			return candName(keep[i]) < candName(keep[j])
		})
	case "bytes":
		sort.SliceStable(keep, func(i, j int) bool {
			bi := pcapTotalBytes(res, keep[i])
			bj := pcapTotalBytes(res, keep[j])
			if bi != bj {
				return bi > bj
			}
			return candName(keep[i]) < candName(keep[j])
		})
	default: // severity
		sort.SliceStable(keep, func(i, j int) bool {
			if keep[i].Score != keep[j].Score {
				return keep[i].Score > keep[j].Score
			}
			ri, rj := strings.ToLower(keep[i].Role), strings.ToLower(keep[j].Role)
			ipri := pcapRolePriority(ri)
			jpri := pcapRolePriority(rj)
			if ipri != jpri {
				return ipri < jpri
			}
			ni, nj := "", ""
			if keep[i].Proc != nil {
				ni = keep[i].Proc.Name
			}
			if keep[j].Proc != nil {
				nj = keep[j].Proc.Name
			}
			return ni < nj
		})
	}

	// Tunneling flag is the candidate's own state — same source the
	// live dashboard uses. The strict isOfflineTunneling gate (which
	// requires listener + inbound + symmetric I/O bps) under-counts
	// in pcap mode because we can't see live I/O rates the same
	// way; CandidateState works directly off ActiveProxying + role
	// + connection topology which is all available offline.
	// Both checks are gated on recency: if the flow's last packet
	// was significantly before pcap end, the tunneling has finished.
	tunnel := make([]bool, len(keep))
	for i, c := range keep {
		tunnel[i] = isPcapTunnelingActive(c, res)
	}
	return keep, tunnel
}

// isPcapTunnelingActive returns true if the candidate shows active
// tunneling AND the flow is still recent (last packet within
// tunnelRecencyWindow of pcap end). This prevents stale tunneling
// states from persisting after the actual traffic ends.
func isPcapTunnelingActive(c shared.Candidate, res *pcap.IngestResult) bool {
	// First check if CandidateState or isOfflineTunneling would fire
	isTunneling := shared.CandidateState(c) == "tunneling" || isOfflineTunneling(c, res)
	if !isTunneling {
		return false
	}
	// Apply recency gate: if the last packet was significantly before
	// pcap end, the tunneling is no longer active.
	if res != nil && c.Proc != nil && !res.PcapEnd.IsZero() {
		if lastPkt, ok := res.LastPacketByPID[c.Proc.Pid]; ok {
			if res.PcapEnd.Sub(lastPkt) > tunnelRecencyWindow {
				return false
			}
		}
	}
	return true
}

// pcapFirstSeen returns the candidate's first-packet timestamp from
// the IngestResult, falling back to PcapStart when the candidate has
// no recorded packets (e.g. a parent-listener picked up via the
// parent_pid linkage that itself never accepted a flow in the pcap).
func pcapFirstSeen(res *pcap.IngestResult, c shared.Candidate) time.Time {
	if c.Proc == nil || res == nil {
		return time.Time{}
	}
	if t, ok := res.FirstPacketByPID[c.Proc.Pid]; ok {
		return t
	}
	return res.PcapStart
}

// pcapTotalBytes returns the candidate's full per-endpoint byte
// total (every flow attributed to this endpoint, both directions).
// Falls back to BytesByPID for legacy / no-attribution cases.
// Stable across re-analyses — no dependence on which subset of flows
// any particular renderer happens to enumerate.
func pcapTotalBytes(res *pcap.IngestResult, c shared.Candidate) uint64 {
	if c.Proc == nil || res == nil {
		return 0
	}
	if v, ok := res.BytesByEndpointPID[c.Proc.Pid]; ok {
		return v
	}
	return res.BytesByPID[c.Proc.Pid]
}

// hasDecisivePcapEvidence returns true when a candidate has at least
// one signal/condition that survives the loss of vendor-suppression in
// offline mode. Without it, "beacon" verdicts driven only by
// long-lived HTTPS or multi-peer outbound fire on every workstation —
// Slack, Teams, vendor update channels, browser sessions all look the
// same as C2 when no signature/ASN/publisher gates run.
//
// The list is split between TIMING / CMDLINE / HOST signals (always
// trustworthy) and DATA-SHAPE signals (trustworthy when we have
// enough observation to corroborate). All of these are hard to fake
// from normal HTTPS app traffic without process context:
//
//   - isOfflineTunneling==true: full relay topology observable
//     (listener receiving + outbound forwarding + active flow).
//   - beacon-interval-confirmed / beacon-syn-cycle-cadence: measured
//     periodic timing across multiple windows; can't be faked by
//     normal HTTPS bursts.
//   - beacon-endpoint-rotation: multiple destination IPs on the same
//     port, the C2 failover-list pattern. Real apps that use CDN
//     don't rotate IPs on a fixed port the way C2 frameworks do.
//   - beacon-static-crypto-likely: static crypto material in code,
//     specific to malware that can't reach a CDN for keys.
//   - session-persistent-channel: long-held single-peer
//     control channel, measured directly from connection lifetime.
//   - session-exfil-write-heavy: large asymmetric upload, hard to
//     mistake for normal request/response API traffic.
//   - pivot-reverse-tunnel-shape: reverse-tunnel topology (callback
//     → forward) — distinct from the synthetic-PID-conflation FPs.
//   - child-tunnel-relay: parent listener + child fork forwards
//     internal connections. SSH-SOCKS-style.
//   - raw-socket: bypasses the TCP stack — very rare in normal apps.
//   - pivot-ssh-tunnel-flags: SSH -L/-R/-D in command line.
//   - session-shell-spawn / session-covert-channel: host signals that
//     occasionally fire offline; precise enough to keep.
//
// Deliberately omitted: pivot-listener-plus-outbound,
// pivot-multiplex-relay, pivot-non-loopback-internal,
// pivot-throughput-symmetry, beacon-target-lock — those fire
// liberally on synthetic-PID conflation (one PID per host bundles a
// real server + an unrelated outbound client into one "process").
// pcapHostsWithMaliciousCandidates returns the set of local-host IPs
// that have at least one analyzer-level malicious candidate
// (pivot, beacon, smb-pipe, or tunnel role) attributed
// to them. Used by the outbound→beacon promotion gate to
// require host-level corroboration before treating a CDN-fronted
// outbound flow as a beacon.
func pcapHostsWithMaliciousCandidates(res *pcap.IngestResult) map[string]struct{} {
	out := make(map[string]struct{})
	if res == nil {
		return out
	}
	for _, c := range res.Candidates {
		if c.Proc == nil {
			continue
		}
		role := strings.ToLower(c.Role)
		switch role {
		case "beacon", "pivot", "smb-pipe", "tunnel":
		default:
			continue
		}
		host := pcapCandidateHost(c)
		if host != "" {
			out[host] = struct{}{}
		}
	}
	return out
}

// pcapCandidateHostHasMalice reports whether the candidate's host-IP
// is in the malicious-host set built by
// pcapHostsWithMaliciousCandidates.
func pcapCandidateHostHasMalice(c shared.Candidate, hosts map[string]struct{}) bool {
	host := pcapCandidateHost(c)
	if host == "" {
		return false
	}
	_, ok := hosts[host]
	return ok
}

// signalPrecisionBadge returns a small "[NN%]" badge styled by signal
// quality, used by the PCAP detail panel's SIGNALS list. The number
// comes from model.LookupSignalStat (TP/(TP+FP) accumulated by the
// experience-feedback loop). Color tiers:
//
//	≥ 75% → green   (high-precision: this signal usually means malice)
//	50-74% → yellow (corroborating: needs other signals to be reliable)
//	< 50% → red     (noisy: lots of FPs in production data)
//
// "[—]" means no feedback recorded yet (signal hasn't been graded).
// Empty Total means same condition.
func signalPrecisionBadge(signal string) string {
	stat := model.LookupSignalStat(signal)
	if stat == nil || stat.Total == 0 {
		return inspDim.Render("[ — ]")
	}
	pct := int(stat.Precision*100 + 0.5)
	label := fmt.Sprintf("[%2d%%]", pct)
	switch {
	case pct >= 75:
		return lipgloss.NewStyle().Foreground(colorCyan).Render(label)
	case pct >= 50:
		return lipgloss.NewStyle().Foreground(colorWarn).Render(label)
	default:
		return lipgloss.NewStyle().Foreground(colorAlert).Render(label)
	}
}

// uniqueSortedByPrecision dedupes the signal list and orders it by
// per-signal precision DESC. Signals with no feedback recorded
// (LookupSignalStat returns nil or Total==0) sort last in stable
// alphabetical order so the "[ — ]" rows cluster together at the bottom.
//
// Read side of the same SignalStats source signalPrecisionBadge uses,
// so the badge value the operator sees is the same value the row was
// sorted on.
func uniqueSortedByPrecision(signals []string) []string {
	if len(signals) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(signals))
	out := make([]string, 0, len(signals))
	for _, s := range signals {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool {
		si := model.LookupSignalStat(out[i])
		sj := model.LookupSignalStat(out[j])
		ti := si != nil && si.Total > 0
		tj := sj != nil && sj.Total > 0
		if ti != tj {
			return ti // graded signals before ungraded
		}
		if !ti {
			return out[i] < out[j] // both ungraded: alphabetical
		}
		if si.Precision != sj.Precision {
			return si.Precision > sj.Precision
		}
		return out[i] < out[j] // tiebreak deterministic
	})
	return out
}

// hasOnlyBlanketHostC2Promotion reports whether a candidate is being
// kept as beacon-* SOLELY because of the blanket host-c2-active-pivot
// rule — i.e., it has the host-c2-active-pivot signal but no other
// decisive evidence that would have promoted it on its own.
//
// Used by the FINDINGS dedup pass to decide whether the per-cluster
// row carries unique value (independent evidence → keep) or whether
// it's just one of many port-scan fan-out rows that should collapse
// into the host's outbound-int aggregate.
func hasOnlyBlanketHostC2Promotion(c shared.Candidate) bool {
	hasBlanket := false
	for _, s := range c.Signals {
		if s == "host-c2-active-pivot" {
			hasBlanket = true
			break
		}
	}
	if !hasBlanket {
		return false
	}
	// Any of these signals constitutes independent decisive evidence —
	// the cluster has its own reason to be beacon-* regardless of the
	// host-c2-active-pivot blanket. Mirrors the explicit-decisive set
	// in shared.HasPacketDecisiveSignal plus the same pcap-decisive
	// signal map.
	for _, s := range c.Signals {
		switch s {
		case "child-tunnel-relay",
			"pivot-ssh-tunnel-flags",
			"pivot-named-pipe-c2-pattern",
			"contour-egress-tunnel-port",
			"listener-egress-tunnel-shape",
			"pivot-listener-plus-outbound",
			"pivot-loopback-listener-external-out",
			"forward-tunnel-shape",
			"reverse-beacon-shape",
			"pivot-socks-candidate",
			"beacon-syn-cycle-cadence":
			return false
		}
	}
	return true
}

// pcapIsAggregateName reports whether a candidate's Name is the per-host
// outbound aggregate ("pcap:<ip> outbound-ext" / "outbound-int"). Used
// by the FINDINGS dedup pass to drop the aggregate row when at least one
// specific cluster row from the same host carries the same role-family
// — the cluster rows are finer-grained and more useful for triage.
func pcapIsAggregateName(name string) bool {
	return strings.HasSuffix(name, " outbound-ext") || strings.HasSuffix(name, " outbound-int")
}

// pcapCandidateHost extracts the local-host IP from a synthetic-PID
// candidate's name. Names follow two forms: `pcap:<ip> outbound-ext`,
// `pcap:<ip> outbound-int`, and `pcap:<ip>:<port>` (listener). Returns
// the empty string if neither pattern matches.
func pcapCandidateHost(c shared.Candidate) string {
	if c.Proc == nil {
		return ""
	}
	body := strings.TrimPrefix(c.Proc.Name, "pcap:")
	if !strings.HasPrefix(c.Proc.Name, "pcap:") {
		return ""
	}
	if idx := strings.Index(body, " "); idx >= 0 {
		return body[:idx]
	}
	if idx := strings.LastIndex(body, ":"); idx >= 0 {
		return body[:idx]
	}
	return ""
}

// hasOutboundControlChannelEvidence detects an outbound candidate that
// carries the high-precision C2-beacon signal mix (CDN-fronted C2,
// persistent control session, beacon-static-crypto, beacon-endpoint-
// rotation, beacon-http-channel + io-read-dominant). The pcap analyzer
// leaves these as role="outbound" because the live ML/scoring layer is
// what normally promotes them to beacon using process context;
// in offline mode that promotion never fires. This helper bridges the
// gap so the pcap dashboard surfaces beacons that would otherwise be
// hidden behind the role filter.
func hasOutboundControlChannelEvidence(c shared.Candidate) bool {
	hasSig := func(want string) bool {
		for _, s := range c.Signals {
			if s == want {
				return true
			}
		}
		return false
	}
	// CDN-fronted C2 alone is sufficient — that signal is precise and
	// rarely fires on real CDN traffic without other corroborating
	// shape evidence.
	if hasSig("cdn-fronted-c2-candidate") {
		return true
	}
	// Persistent single-peer control channel + a hard beacon shape
	// (rotation, static crypto, or HTTP beacon timing) is also
	// distinctive enough to call beacon offline.
	if hasSig("session-persistent-channel") {
		if hasSig("beacon-endpoint-rotation") || hasSig("beacon-static-crypto-likely") ||
			hasSig("beacon-http-channel") || hasSig("beacon-interval-confirmed") {
			return true
		}
	}
	return false
}

func hasDecisivePcapEvidence(c shared.Candidate, isTun bool) bool {
	if isTun {
		return true
	}
	decisive := map[string]struct{}{
		// Timing — measured periodicity, can't be faked
		"beacon-interval-confirmed":   {},
		"beacon-syn-cycle-cadence":    {},
		"beacon-endpoint-rotation":    {},
		"beacon-static-crypto-likely": {},
		// Long-lived control channel + exfil shape
		"session-persistent-channel": {},
		"session-exfil-write-heavy":  {},
		// Topology — specific shapes that survive offline
		"pivot-reverse-tunnel-shape": {},
		"child-tunnel-relay":         {},
		// CMDLINE / kernel — hard to fake from normal apps
		"raw-socket":             {},
		"pivot-ssh-tunnel-flags": {},
		// Host signals
		"session-shell-spawn":    {},
		"session-covert-channel": {},
	}
	for _, sig := range c.Signals {
		if _, ok := decisive[sig]; ok {
			return true
		}
	}
	return false
}

func pcapRolePriority(role string) int {
	switch role {
	case "pivot":
		return 0
	case "beacon":
		return 1
	case "listener", "listen":
		return 2
	case "outbound":
		return 3
	default:
		return 4
	}
}

// buildDetailContent renders the connections list for the
// currently-selected finding. Operator-facing intent: the side panel
// answers "what's this finding actually talking to?" without burying
// it under metadata — IDENTITY / ROLE / BYTES already live in the
// findings table, so the panel stays focused on the per-connection
// detail (local/remote/state/scope) only.
func (m *PcapAnalyzerModel) buildDetailContent() string {
	if m.result == nil {
		return inspValue.Render("No result.")
	}
	c, ok := m.selectedFinding()
	if !ok {
		return inspValue.Render("No row selected.")
	}

	// Merge current snapshot conns into the per-cluster sticky cache
	// keyed by cluster name (stable across cycles). Returns the union
	// of (current cycle's conns) ∪ (cached conns from previous cycles
	// within stickyDetailConnTTL). Closed connections stay visible
	// for the TTL window, deduplicated by (local, remote) tuple.
	stickyConns := m.refreshStickyDetailConns(&c)

	var lines []string

	// SIGNALS section — list every signal that fired on this finding,
	// each annotated with its measured TP/FP precision (read from
	// model.SignalStats which is populated by the experience-feedback
	// loop). Color-codes: green ≥75% (high signal), yellow 50-74%
	// (corroborating), red <50% (noisy). When precision is unset
	// (no feedback recorded yet) we render "—" instead of a number.
	// Operators can use the badge colour to see at a glance which
	// signals on a row carry weight vs which are noise.
	if len(c.Signals) > 0 {
		sigs := uniqueSortedByPrecision(c.Signals)
		lines = append(lines, inspValue.Render("  SIGNALS"))
		divider := lipgloss.NewStyle().Foreground(colorFrame)
		lines = append(lines, divider.Render("  "+strings.Repeat("─", 60)))
		for _, sig := range sigs {
			badge := signalPrecisionBadge(sig)
			lines = append(lines, "  "+badge+" "+inspDim.Render(sig))
		}
		lines = append(lines, "")
	}

	if len(stickyConns) == 0 && len(c.Listeners) == 0 {
		if len(lines) > 0 {
			lines = append(lines, inspDim.Render("  No connections recorded for this finding."))
			return strings.Join(lines, "\n")
		}
		return inspDim.Render("  No connections recorded for this finding.")
	}

	// CONNECTIONS section header.
	if len(lines) > 0 {
		lines = append(lines, inspValue.Render("  CONNECTIONS"))
	}
	divider := lipgloss.NewStyle().Foreground(colorFrame)
	lines = append(lines, inspValue.Render(fmt.Sprintf("  %-22s %-22s %-12s %-8s",
		"Local", "Remote", "State", "Scope")))
	lines = append(lines, divider.Render(fmt.Sprintf("  %-22s %-22s %-12s %-8s",
		strings.Repeat("─", 22), strings.Repeat("─", 22), strings.Repeat("─", 9), strings.Repeat("─", 7))))
	for _, l := range c.Listeners {
		local := fmt.Sprintf("%s:%d", l.LocalAddress, l.LocalPort)
		lines = append(lines,
			inspDim.Render(fmt.Sprintf(" %-22s", local))+
				bodyText.Render(fmt.Sprintf(" %-22s", "*"))+
				inspConnStateStyle("LISTEN").Render(fmt.Sprintf(" %-12s", "LISTEN"))+
				inspScopeStyle("").Render(fmt.Sprintf(" %-8s", "")))
	}
	shown := 0
	for _, cn := range stickyConns {
		if shown >= 50 {
			lines = append(lines, inspDim.Render(fmt.Sprintf("  … and %d more", len(stickyConns)-shown)))
			break
		}
		scope := ""
		if cn.RemoteAddress != "" && !shared.IsWildcardIP(cn.RemoteAddress) && !shared.IsLoopbackIP(cn.RemoteAddress) {
			if shared.IsInternalIP(cn.RemoteAddress) {
				scope = "internal"
			} else {
				scope = "external"
			}
		}
		local := fmt.Sprintf("%s:%d", cn.LocalAddress, cn.LocalPort)
		remote := fmt.Sprintf("→ %s:%d", cn.RemoteAddress, cn.RemotePort)
		lines = append(lines,
			inspDim.Render(fmt.Sprintf(" %-22s", local))+
				bodyText.Render(fmt.Sprintf(" %-22s", remote))+
				inspConnStateStyle(cn.State).Render(fmt.Sprintf(" %-12s", cn.State))+
				inspScopeStyle(scope).Render(fmt.Sprintf(" %-8s", scope)))
		shown++
	}
	return strings.Join(lines, "\n")
}

// renderFindingsPanel draws the top half of the results-stage DISPLAY
// area: a bordered panel hosting the findings (or destinations) table
// inside m.viewportFindings. Includes a scroll indicator so the
// operator can tell when there's more table off-screen.
func (m PcapAnalyzerModel) renderFindingsPanel(w, h int) string {
	if w <= 0 {
		w = 80
	}
	if h < 5 {
		h = 5
	}
	panelTitle := "FINDINGS"
	if m.app.PcapResultsTab == "destinations" {
		panelTitle = "DESTINATIONS"
	}
	// Append the current grouping mode so the operator can see which
	// lens they're viewing. Default mode (cluster /16) is shown as
	// blank — only non-default modes are flagged in the title.
	switch m.app.PcapGroupBy {
	case "flow":
		panelTitle += " [flow]"
	case "ja3":
		panelTitle += " [JA3]"
	case "asn":
		panelTitle += " [ASN]"
	case "beacon":
		panelTitle += " [session]"
	case "behavior":
		panelTitle += " [shape]"
	}
	// Sort mode indicator (default "time" stays blank)
	switch m.app.PcapSortMode {
	case "bytes":
		panelTitle += " ↓bytes"
	case "packets":
		panelTitle += " ↓pkts"
	}
	if m.tailing {
		panelTitle += " ● live"
	}
	opts := ReportPanelOpts{
		Title:  panelTitle,
		Width:  w,
		Height: h,
	}
	if m.ready {
		opts.Content = m.viewportFindings.View()
		total := m.viewportFindings.TotalLineCount()
		visible := m.viewportFindings.VisibleLineCount()
		opts.ScrollTotal = total
		opts.ScrollVisible = visible
		opts.ScrollTop = m.viewportFindings.YOffset + 1
		opts.ScrollBottom = m.viewportFindings.YOffset + visible
		if opts.ScrollBottom > total {
			opts.ScrollBottom = total
		}
	}
	return renderAccentReportPanel(opts)
}

// renderDetailsPanel draws the bottom half of the results-stage
// DISPLAY area: a bordered panel hosting the selected finding's
// details inside m.viewportDetail. Operator scrolls with PgUp/PgDn.
func (m PcapAnalyzerModel) renderDetailsPanel(w, h int) string {
	if w <= 0 {
		w = 80
	}
	if h < 5 {
		h = 5
	}
	opts := ReportPanelOpts{
		Title:  "CONNECTIONS",
		Width:  w,
		Height: h,
	}
	if m.ready {
		opts.Content = m.viewportDetail.View()
		total := m.viewportDetail.TotalLineCount()
		visible := m.viewportDetail.VisibleLineCount()
		opts.ScrollTotal = total
		opts.ScrollVisible = visible
		opts.ScrollTop = m.viewportDetail.YOffset + 1
		opts.ScrollBottom = m.viewportDetail.YOffset + visible
		if opts.ScrollBottom > total {
			opts.ScrollBottom = total
		}
	}
	return renderAccentReportPanel(opts)
}

// ── helpers ────────────────────────────────────────────────────────────

// selectedFinding returns the candidate currently under the cursor in
// the flat findings list, plus a bool indicating whether a valid row
// is selected (false when the list is empty).
func (m PcapAnalyzerModel) selectedFinding() (shared.Candidate, bool) {
	if len(m.findings) == 0 {
		return shared.Candidate{}, false
	}
	idx := m.app.PcapRowCursor
	if idx < 0 {
		idx = 0
	}
	if idx >= len(m.findings) {
		idx = len(m.findings) - 1
	}
	return m.findings[idx], true
}

// minTunnelObservation is the floor on how long we must have watched a
// candidate before we'll commit to "tunneling". Set high enough that a
// brief HTTPS exchange (browser fetch, app update poll) doesn't cross
// it, but low enough that a real SSH-SOCKS forwarder running for half
// a minute does. Same value applies to one-shot mode (where the
// duration is the pcap-time span the candidate was observed for) and
// tail mode (where it's how long the watch has been running).
const minTunnelObservation = 10 * time.Second

// minTunnelSymmetry is the lower bound on min(in,out)/max(in,out) for
// the lifetime byte counts. A real tunnel forwards: bytes received
// roughly equal bytes sent. A "server with unrelated outbound client"
// usually has highly asymmetric flow (e.g. lots of inbound API
// requests, occasional update download). 0.3 leaves headroom for
// protocol asymmetry while rejecting the common FP shape.
const minTunnelSymmetry = 0.3

// isOfflineTunneling reports whether a candidate looks like an active
// tunnel/relay in offline mode. Without process attribution, the live
// vendor-suppression layer can't help us — we have to rely on the
// flow shape alone. Synthetic-PID conflation (one PID per host) makes
// ActiveProxying / pivot-* signals fire spuriously: any host that
// both serves AND connects out gets the pivot topology. That means a
// web server that fetches updates trips the rule, even though it's
// not relaying anything.
//
// We require ALL of:
//  1. Role is pivot. beacon is a beacon shape (C2
//     callback to a single peer), not a tunnel; we don't accept it.
//  2. ActiveProxying flag set by the orchestrator.
//  3. Listener present AND has received inbound (InboundTotal > 0).
//  4. Outbound connection to a non-loopback peer.
//  5. BIDIRECTIONAL flow active right now: both IOReadBps and
//     IOWriteBps ≥ dataFlowOfflineThreshold. A tunnel forwards in
//     both directions concurrently.
//  6. THROUGHPUT SYMMETRY across the whole observation:
//     min(BytesIn, BytesOut) / max(BytesIn, BytesOut) ≥
//     minTunnelSymmetry. Rejects "100KB inbound API traffic + 5KB
//     occasional outbound" shapes.
//  7. OBSERVATION-TIME FLOOR: we must have watched the candidate for
//     ≥ minTunnelObservation. A 2-second blip can never commit to
//     tunneling — the operator asked for a deeper, longer inspection
//     before a verdict, and this is the gate that enforces it.
//
// All 7 must pass. False positives that previously survived (172.16.1.6
// type "server with outbound") fail at #6 / #7.
// tunnelRecencyWindow is how recently traffic must have flowed for a
// PCAP finding to show as "ACTIVE" tunneling. If the last packet was
// longer ago than this, the flow is considered ended.
const tunnelRecencyWindow = 30 * time.Second

func isOfflineTunneling(c shared.Candidate, res *pcap.IngestResult) bool {
	if strings.ToLower(c.Role) != "pivot" {
		return false
	}
	if !c.ActiveProxying || c.Proc == nil {
		return false
	}
	if len(c.Listeners) == 0 || c.InboundTotal == 0 {
		return false
	}
	hasOutbound := false
	for _, conn := range c.Conns {
		if conn.RemoteAddress == "" || conn.RemotePort == 0 {
			continue
		}
		if shared.IsLoopbackIP(conn.RemoteAddress) || shared.IsWildcardIP(conn.RemoteAddress) {
			continue
		}
		hasOutbound = true
		break
	}
	if !hasOutbound {
		return false
	}
	if c.Proc.IOReadBps < dataFlowOfflineThreshold || c.Proc.IOWriteBps < dataFlowOfflineThreshold {
		return false
	}
	if res == nil {
		// Without per-PID stats we can't enforce symmetry/observation.
		// Be conservative: require explicit IngestResult context.
		return false
	}
	pid := c.Proc.Pid
	// Check if the flow is still active: last packet must be recent
	// relative to the end of the analysis. If the last packet was
	// significantly before pcap end, the tunneling has finished.
	if lastPkt, ok := res.LastPacketByPID[pid]; ok && !res.PcapEnd.IsZero() {
		if res.PcapEnd.Sub(lastPkt) > tunnelRecencyWindow {
			return false
		}
	}
	bytesIn := res.BytesInByPID[pid]
	bytesOut := res.BytesOutByPID[pid]
	if bytesIn == 0 || bytesOut == 0 {
		return false
	}
	lo, hi := bytesIn, bytesOut
	if hi < lo {
		lo, hi = hi, lo
	}
	if float64(lo)/float64(hi) < minTunnelSymmetry {
		return false
	}
	if res.ObservationByPID[pid] < minTunnelObservation {
		return false
	}
	return true
}

func fnvHash(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return h.Sum64()
}

// keep tcell import alive — convertKeyMsg returns *tcell.EventKey and is
// called via the bridge, but the symbol itself is referenced indirectly.
var _ = tcell.KeyUp
