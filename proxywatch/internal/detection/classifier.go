package detection

import (
	"sort"
	"strings"
	"time"

	"proxywatch/internal/detection/features"
	"proxywatch/internal/detection/gbdt"
	"proxywatch/internal/detection/ml"
	"proxywatch/internal/detection/model"
	"proxywatch/internal/detection/output"
	"proxywatch/internal/detection/scoring"
	"proxywatch/internal/shared"
)

func hasReason(reasons []string, reason string) bool {
	for _, r := range reasons {
		if r == reason {
			return true
		}
	}
	return false
}

// confidenceToScore converts a model probability (0.0-1.0) to a display
// score (0-100). The mapping is non-linear: low confidence stays low,
// high confidence maps to high scores.
func confidenceToScore(prob float64) int {
	score := int(prob * 100)
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	return score
}

// TrainingExporter is set externally to enable ML telemetry export.
// When nil, no training data is emitted.
var TrainingExporter *gbdt.Exporter

// MLLearner is set externally when the continuous learning system is active.
// Provides the active predictor and training buffer.
var MLLearner *ml.ContinuousLearner

// MLPrimary controls whether the ML model is the primary role assigner.
var MLPrimary bool

// bufferAddLogged tracks whether we've logged the first buffer add (one-time diagnostic).
var bufferAddLogged bool

// Classify converts a telemetry snapshot into classified candidates.
func Classify(
	snap *shared.Snapshot,
	opts shared.ClassifyOptions,
	cache *shared.ClassifierCache,
) []shared.Candidate {
	// Protect global classifier state maps from concurrent access.
	// The background refresh goroutine runs Classify in parallel with the UI.
	shared.ClassifyMu.Lock()
	defer shared.ClassifyMu.Unlock()

	candidates := buildCandidates(snap)
	now := time.Now()
	refreshObservedExternalPortProfile(candidates)
	hostScope := strings.TrimSpace(opts.HostScope)
	if hostScope == "" {
		hostScope = "local"
	}

	var (
		nextCandidates map[int]shared.Candidate
		nextSignatures map[int]shared.CandidateSignature
	)
	if opts.Incremental && cache != nil {
		nextCandidates = make(map[int]shared.Candidate, len(candidates))
		nextSignatures = make(map[int]shared.CandidateSignature, len(candidates))
	}

	var interesting []shared.Candidate
	for i := range candidates {
		c := &candidates[i]
		var pendingTrainingRec *gbdt.TrainingRecord
		if c.Proc == nil {
			continue
		}
		if strings.TrimSpace(c.Host) == "" {
			c.Host = hostScope
		}
		if opts.Incremental && cache != nil {
			sig := candidateSignature(*c)
			prevCands := cache.Candidates
			prevSigs := cache.Signatures
			if prevCands != nil && prevSigs != nil {
				if prev, ok := prevCands[c.Proc.Pid]; ok {
					if prevSig, ok := prevSigs[c.Proc.Pid]; ok && prevSig == sig {
						if shouldRescoreUnchangedCandidate(c, &prev, now) {
							scoring.ScoreCandidate(c)
						} else {
							reuseCandidate(c, &prev)
							touchHistoryFromCandidate(c, now)
						}
					} else {
						scoring.ScoreCandidate(c)
					}
				} else {
					scoring.ScoreCandidate(c)
				}
			} else {
				scoring.ScoreCandidate(c)
			}

			nextSignatures[c.Proc.Pid] = sig
			// nextCandidates stored after model override + ActiveProxying (below).
		} else {
			scoring.ScoreCandidate(c)
		}

		// Record observation for maturity — ALWAYS, regardless of ML state.
		if c.Proc != nil {
			model.RecordObservationForMaturity()
		}

		// ── Model-first classification ──────────────────────────────────
		// The model is the primary role assigner. The rule engine's role
		// (SuggestedRole) is retained for training data and fallback only.
		// When no model is loaded, the rule engine's role stands.
		if c.Proc != nil {
			key := ProcessBehaviorKey(c)
			behavior := shared.ProcessBehaviorByKey[key]
			profile := model.ResolveProfile(key)

			// Signal-only inference used for override tiebreakers below.
			// NOTE: do NOT assign to c.SuggestedRole — that field stores
			// rank.go's topology decision (set at rank.go line 1627) and is
			// the authoritative "Rule engine decided X" value shown in the
			// inspector and used for ML training labels. Overwriting here
			// would replace rank.go's deep topology analysis with weak
			// signal counting (e.g. known beacons get suppressed to
			// "outbound" by outbound-baseline-verified).
			ruleRole := shared.InferRoleFromSignals(c.Signals, c.ControlSubtype, c.Role)

			// Check if ML predictor is available (model loaded and trained).
			hasPred := false
			if MLLearner != nil {
				fv := features.Extract(c, behavior, profile)
				if fv.Valid {
					pred := MLLearner.Predictor()
					if pred != nil {
						hasPred = true
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

						// Model is primary ONLY after it has qualified via shadow
						// agreement + prediction volume (see model.MLQualified()).
						// Before qualification, the predictor runs in shadow-only
						// mode: predictions are recorded for maturity computation
						// and signal-effectiveness tracking, but c.Role stays as
						// rank.go's topology decision. This prevents a half-baked
						// model (low shadow agreement or few predictions) from
						// flipping roles incorrectly. Once qualified, ML takes
						// over (subject to the Case 1/2/3 confidence gates below).
						scoreRole := c.Role // preserve ScoreCandidate's role (rank.go topology analysis)
						if model.MLQualified() {
							c.Role = result.TopRole
							c.Score = confidenceToScore(result.TopProb)
						}

						// Signal-based override: trust live signals/topology over the
						// model when they disagree — BUT ONLY when the model itself
						// is uncertain. A high-confidence ML prediction (>=0.80) has
						// learned patterns across thousands of observations; a single
						// topology heuristic should not override it. Gate every
						// override path on mlLowConfidence so msedgewebview2-style
						// cases (ML outbound 99%, topology control-channel) stop
						// flipping to the topology verdict.
						const mlTrustThreshold = 0.80
						mlLowConfidence := result.TopProb < mlTrustThreshold

						signalOverride := false
						// Case 1: ML says suspicious, signals say benign → trust signals
						// (prevent FP). Only override when ML is itself uncertain.
						if mlLowConfidence && scoring.IsMaliciousRole(c.Role) && (ruleRole == "outbound" || ruleRole == "listener") {
							c.Role = ruleRole
							c.Score = 0
							signalOverride = true
						}
						// Case 2: ML says benign, signals say suspicious → trust signals
						// (prevent FN). Also gated — a 99%-confident "this is outbound"
						// prediction outweighs signal-only inference.
						if mlLowConfidence && !scoring.IsMaliciousRole(c.Role) && scoring.IsMaliciousRole(ruleRole) {
							c.Role = ruleRole
							signalOverride = true
						}
						// Case 3: ML says benign, ScoreCandidate topology says
						// suspicious. Rank.go has deeper analysis than signal counting
						// (connection topology, multiplexed inbound, child aggregation)
						// so we still honor its verdict over ML — but only when ML
						// isn't high-confidence. A 99%-confident outbound prediction
						// wins here too.
						if !signalOverride && mlLowConfidence && !scoring.IsMaliciousRole(c.Role) && scoring.IsMaliciousRole(scoreRole) {
							c.Role = scoreRole
							signalOverride = true
						}

						// Operator overrides — training labels, kill/whitelist verdicts.
						decision := model.ApplyOperatorOverrides(
							key, c.Role, c.Score, c.Proc,
							c.OutExternal, c.OutInternal, len(c.Listeners) > 0,
						)
						if decision.Override {
							c.Role = decision.Role
							if !hasReason(c.Reasons, decision.Reason) {
								c.Reasons = append(c.Reasons, decision.Reason)
							}
						}

						// Role stability — prevent rapid flapping between callbacks.
						// Skip when signal override fired — the signal engine already
						// made the authoritative decision based on current telemetry.
						hist := scoring.GetHistory(c.Proc.Pid, now)
						if !signalOverride {
							if hist.LastRole != "" && c.Role != hist.LastRole {
								prevMal := scoring.IsMaliciousRole(hist.LastRole)
								newMal := scoring.IsMaliciousRole(c.Role)
								if prevMal && !newMal {
									if now.Sub(hist.LastRoleChange) < shared.MaliciousRoleDemoteCooldown {
										c.Role = hist.LastRole
									}
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

						// Maturity tracking.
						agree := result.TopRole == ruleRole
						model.RecordShadowComparison(agree)
						if !agree {
							// Capture the full disagreement context for the
							// /ml/disagreements debug endpoint so operators
							// can tune the model from the actual population
							// without tailing logs or waiting for retrain.
							entry := model.ShadowDisagreement{
								PID:          c.Proc.Pid,
								Host:         c.Host,
								Name:         c.Proc.Name,
								ExePath:      c.Proc.ExePath,
								SHA256:       c.Proc.SHA256,
								RuleRole:     ruleRole,
								MLRole:       result.TopRole,
								MLConfidence: result.TopProb,
							}
							model.RecordShadowDisagreement(entry)
						}
						committed := ""
						if profile != nil {
							committed = profile.ExperienceLastRole
						}
						model.RecordMLPrediction(result.TopProb, result.TopRole == committed)
					}

					// Buffer for continuous learning. Use SuggestedRole (rank.go's
					// topology decision) — not the local signal-only ruleRole —
					// so the model learns from the deeper rule-engine analysis,
					// not just signal counting.
					rec := gbdt.TrainingRecord{
						Timestamp:       now.UTC(),
						Host:            strings.TrimSpace(c.Host),
						ProcessKey:      key,
						ProcessName:     c.Proc.Name,
						ProcessPath:     c.Proc.ExePath,
						User:            c.Proc.UserName,
						Company:         c.Proc.Company,
						Features:        fv.ToMap(),
						Signals:         c.Signals,
						RuleRole:        c.SuggestedRole,
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
					// Defer buffer add until after ActiveProxying is computed
					// so the training record can reflect tunneling → pivot.
					pendingTrainingRec = &rec
				}
			}
			// Fallback: no ML predictor available (model not loaded or not trained).
			// Use signal-based role inference, BUT preserve rank.go's topology
			// decision (in c.SuggestedRole) when it found a suspicious pattern
			// that signal-only counting missed. ScoreCandidate has deeper
			// analysis (topology, multiplexed inbound, beacon-syn-cycle,
			// reverseControl) than InferRoleFromSignals (signal counting with
			// outbound suppression). Without this, sshd.exe with multiplexed
			// inbound would drop from "control-pivot" (rank.go) → "listener"
			// (signal-only) when ML is unavailable.
			if !hasPred {
				topologyRole := c.SuggestedRole // rank.go's pre-DecideRole role
				topologyIsSuspicious := scoring.IsMaliciousRole(topologyRole)
				ruleIsSuspicious := scoring.IsMaliciousRole(ruleRole)

				if topologyIsSuspicious && !ruleIsSuspicious {
					// Topology found a tunnel/pivot/control pattern that signal
					// counting suppressed (e.g. outbound-baseline-verified
					// suppression on a sshd with multiplexed SSH sessions).
					// Trust topology — that's what rank.go's deep analysis is for.
					c.Role = topologyRole
				} else {
					c.Role = ruleRole
				}

				// Role stability — prevent control-channel → outbound flapping
				// between beacon callbacks (zero connections = zero signals = outbound).
				tunnelActive := false
				if _, ok := shared.TunnelingSeen[c.Proc.Pid]; ok {
					tunnelActive = true
				}
				if _, ok := shared.TunnelingSeen[scoring.HistoryPIDForCandidate(c)]; ok {
					tunnelActive = true
				}
				hist := scoring.GetHistory(c.Proc.Pid, now)
				if hist.LastRole != "" && c.Role != hist.LastRole {
					prevMal := scoring.IsMaliciousRole(hist.LastRole)
					newMal := scoring.IsMaliciousRole(c.Role)
					if prevMal && !newMal && (ruleIsSuspicious || topologyIsSuspicious || tunnelActive) {
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
		}

		// Publisher → destination DNS alignment — live per-cycle check so
		// fresh connections get evaluated as soon as PTR cache populates.
		// Never blocks: DNS resolution is async-cached; miss returns false
		// and triggers a refresh for the next cycle. See
		// shared/verifier_publisher_dns.go.
		if c.Proc != nil {
			if aligned, tags := shared.EvaluatePublisherDNSAlignment(c); aligned {
				c.Proc.PublisherDNSAligned = true
				c.Proc.OnlineEvidence = append(c.Proc.OnlineEvidence, tags...)
			}
		}

		// Shape-only control-channel demotion — if rank.go assigned a
		// control role based purely on phone-home shape (persistent HTTPS
		// to a single destination, crypto-lib loaded, no children) AND
		// no distinguishing suspicion signal fired (raw socket, SSH
		// tunnel flags, suspicious path, lateral movement, confirmed
		// beacon cadence, etc.), demote to outbound. This is the
		// structural replacement for per-vendor name lists.
		if c.Proc != nil {
			shared.DemoteShapeOnlyControlRole(c)
			// Sleeping-beacon rescue: re-promote outbound candidates that
			// the per-host baseline incorrectly committed as "outbound"
			// because the beacon sleeps most of the time. Tight 5-fact
			// combo (beacon cadence + suspicious path + unsigned +
			// !pkg-owned + !known-vendor) so benign vendor polling is
			// unaffected. See shared/distinguishing.go.
			shared.UpgradeSleepingBeaconProfile(c)
		}

		// Vendor-FP suppression pass — runs after BOTH the ML-loaded and the
		// fallback role-assignment branches so behavior is identical with
		// or without a trained model. Both rules are no-ops when blockers
		// are present (decisive pivot/tunnel signals, ActiveProxying, etc.).
		// See shared/vendor_fp_shape.go for the blocker canonical list.
		if c.Proc != nil {
			shared.ApplyVendorUpdateSuppression(c)
			shared.ApplyVendorFPShape(c)
			// Narrow rescue for signed vendor desktop/Electron apps
			// (Zoom, Slack, CloudSync) whose helper-mesh IPC trips
			// ActiveProxying in rank.go and blocks the broader
			// demotion paths. Gated on rich-local-ipc-shape + multi-
			// source identity convergence. See vendor_fp_shape.go.
			shared.ApplyVendorIPCRescue(c)
		}

		// ActiveProxying is set by ScoreCandidate (rank.go) which has deep
		// understanding of connection topology, role context, and relay patterns.
		// The classifier does not override it — rank.go is authoritative.

		// Persist tunneling state when live topology evidence exists.
		// Only set TunnelingSeen from isActivelyProxying result (actual relay
		// connections visible), not from role alone. This ensures the 10-minute
		// expiry works — when connections stop, TunnelingSeen stops being refreshed
		// and eventually expires, transitioning state back to "watch".
		if c.Proc != nil && c.ActiveProxying {
			shared.TunnelingSeen[c.Proc.Pid] = now
			shared.TunnelingSeen[scoring.HistoryPIDForCandidate(c)] = now
		}

		// Flush deferred training record now that ActiveProxying is known.
		// When tunneling is active, promote the label to control-pivot so
		// the ML model learns that this behavior pattern is a pivot.
		if pendingTrainingRec != nil && MLLearner != nil {
			if c.ActiveProxying && pendingTrainingRec.RuleRole != "control-pivot" {
				pendingTrainingRec.RuleRole = "control-pivot"
			}
			MLLearner.Buffer().Add(*pendingTrainingRec)
			if !bufferAddLogged {
				bufferAddLogged = true
				shared.LogInfo("training", "buffer: first record added (key=%s, buffer=%d)", pendingTrainingRec.ProcessKey, MLLearner.Buffer().Len())
			}
		}

		// Store fully-corrected candidate in incremental cache.
		if opts.Incremental && nextCandidates != nil && c.Proc != nil {
			nextCandidates[c.Proc.Pid] = *c
		}

		if !shouldDisplayCandidate(c, now) {
			continue
		}

		// Role filter is applied AFTER linger in ApplyScoreAndRoleFilters.
		// Filtering here prevents processes from reaching the linger cache
		// where child tunnel evidence can be correlated with parents.

		interesting = append(interesting, *c)
	}

	if opts.Incremental && cache != nil {
		cache.Candidates = nextCandidates
		cache.Signatures = nextSignatures
	}

	// Aggregate child process tunnel evidence to parents with listeners.
	// SSH SOCKS proxy: parent sshd forks children that exit quickly.
	// Transfer children's internal connection evidence to the parent.
	scoring.AggregateChildTunnelEvidence(candidates)

	// Time-lingered control-pivot promotion. Any candidate observed forwarding
	// internal-only traffic in a relay context (own listener, parent listener,
	// or already a control role) gets stamped into shared.PivotUntil and held
	// at role=control-pivot for the linger window. Runs after
	// AggregateChildTunnelEvidence so parent-has-listener evidence is
	// up-to-date, and after per-candidate ScoreCandidate + model.DecideRole so
	// the ML model's committed role hold cannot un-promote the pivot.
	scoring.ApplyPivotLinger(candidates, snap.Processes)

	// Re-sync ActiveProxying from candidates→interesting after child aggregation.
	// AggregateChildTunnelEvidence updates the candidates slice but interesting
	// has copies from before the aggregation.
	candidateByPID := make(map[int]*shared.Candidate, len(candidates))
	for i := range candidates {
		if candidates[i].Proc != nil {
			candidateByPID[candidates[i].Proc.Pid] = &candidates[i]
		}
	}
	for i := range interesting {
		if interesting[i].Proc != nil {
			if src, ok := candidateByPID[interesting[i].Proc.Pid]; ok {
				interesting[i].ActiveProxying = src.ActiveProxying
				interesting[i].OutInternal = src.OutInternal
				interesting[i].OutTotal = src.OutTotal
				interesting[i].Role = src.Role
				interesting[i].Signals = src.Signals
				interesting[i].Reasons = src.Reasons
			}
		}
	}

	sort.Slice(interesting, func(i, j int) bool {
		return shared.CandidateLess(interesting[i], interesting[j])
	})
	output.EmitDetectionOutputs(now.UTC(), hostScope, candidates, interesting, opts)

	// Feed ALL scored candidates into the detection model as experience.
	// This ensures every process gets a profile, not just high-scoring ones.
	{
		expRecords := make([]model.ExperienceRecord, 0, len(candidates))
		for i := range candidates {
			c := &candidates[i]
			if c.Proc == nil {
				continue
			}
			// Use the FINAL assigned role (after ML prediction + operator overrides),
			// not the rule engine's signal inference. The model and operator labels
			// are the source of truth — experience must reflect their decisions.
			role := c.Role
			rec := model.ExperienceRecord{
				ProcessKey:   ProcessBehaviorKey(c),
				Name:         c.Proc.Name,
				Role:         role,
				Score:        c.Score,
				Signals:      c.Signals,
				IOReadBytes:  c.Proc.IOReadBytes,
				IOWriteBytes: c.Proc.IOWriteBytes,
			}
			// Track role stability for maturity — compare assigned role to
			// the committed/dominant role from experience profile.
			// Only record when we have a prior committed role to compare against.
			// Skip first-observation processes (no baseline = meaningless comparison).
			// Skip when ML already recorded (avoid 2x inflation).
			if !c.MLActive {
				if profile := model.ResolveProfile(rec.ProcessKey); profile != nil && profile.ExperienceLastRole != "" {
					model.RecordRoleAssignment(role == profile.ExperienceLastRole, c.Score)
				}
			}
			// Persist beacon interval even when role is blocked — the cadence
			// was confirmed regardless of whether the role promotion succeeded.
			if c.BeaconIntervalMs > 0 {
				rec.BeaconInterval = c.BeaconIntervalMs
				rec.BeaconJitter = c.BeaconJitter
			}
			expRecords = append(expRecords, rec)
		}
		if len(expRecords) > 0 {
			model.RecordExperience(expRecords)
		}
	}

	// Emit ML training telemetry if exporter is configured.
	if TrainingExporter != nil {
		for i := range candidates {
			c := &candidates[i]
			if c.Proc == nil {
				continue
			}
			key := ProcessBehaviorKey(c)
			behavior := shared.ProcessBehaviorByKey[key]
			profile := model.ResolveProfile(key)
			fv := features.Extract(c, behavior, profile)
			if !fv.Valid {
				continue
			}

			rec := gbdt.TrainingRecord{
				Timestamp:       now.UTC(),
				Host:            strings.TrimSpace(c.Host),
				ProcessKey:      key,
				ProcessName:     c.Proc.Name,
				ProcessPath:     c.Proc.ExePath,
				User:            c.Proc.UserName,
				Company:         c.Proc.Company,
				Features:        fv.ToMap(),
				Signals:         c.Signals,
				RuleRole:        c.SuggestedRole,
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
			_ = TrainingExporter.Emit(rec)
		}
	}

	shared.MaybeSaveClassifierMemory("", now.UTC())
	model.RefreshRuntimeProfiles()
	model.MaybeSave(now.UTC())

	// Update training dashboard state.
	if MLLearner != nil {
		shared.TrainingBufferSizeAtomic.Store(int64(MLLearner.Buffer().Len()))
	}

	return interesting
}

// inferRoleFromSignals is now shared.InferRoleFromSignals — single source of truth
// used by both standalone (classifier.go) and server (server.go).

func refreshObservedExternalPortProfile(candidates []shared.Candidate) {
	procPorts := make(map[int]map[int]struct{})
	portPrefixes := make(map[int]map[string]struct{})
	portConnCount := make(map[int]int)

	for _, c := range candidates {
		if c.Proc == nil {
			continue
		}
		seenForProc := make(map[int]struct{})
		for _, cn := range c.Conns {
			if !scoring.IsActiveConnState(cn.State) {
				continue
			}
			if cn.RemotePort <= 0 ||
				cn.RemoteAddress == "" ||
				shared.IsWildcardIP(cn.RemoteAddress) ||
				shared.IsLoopbackIP(cn.RemoteAddress) ||
				shared.IsInternalIP(cn.RemoteAddress) {
				continue
			}

			portConnCount[cn.RemotePort]++
			if _, ok := seenForProc[cn.RemotePort]; !ok {
				if procPorts[cn.RemotePort] == nil {
					procPorts[cn.RemotePort] = make(map[int]struct{})
				}
				procPorts[cn.RemotePort][c.Proc.Pid] = struct{}{}
				seenForProc[cn.RemotePort] = struct{}{}
			}
			if prefix := shared.TargetPrefix(cn.RemoteAddress); prefix != "" {
				if portPrefixes[cn.RemotePort] == nil {
					portPrefixes[cn.RemotePort] = make(map[string]struct{})
				}
				portPrefixes[cn.RemotePort][prefix] = struct{}{}
			}
		}
	}

	shared.ObservedExternalPortProcessCount = make(map[int]int, len(procPorts))
	for port, procs := range procPorts {
		shared.ObservedExternalPortProcessCount[port] = len(procs)
	}

	shared.ObservedExternalPortPrefixCount = make(map[int]int, len(portPrefixes))
	for port, prefixes := range portPrefixes {
		shared.ObservedExternalPortPrefixCount[port] = len(prefixes)
	}

	shared.ObservedExternalPortConnCount = make(map[int]int, len(portConnCount))
	for port, count := range portConnCount {
		shared.ObservedExternalPortConnCount[port] = count
	}
}

func buildCandidates(snap *shared.Snapshot) []shared.Candidate {
	now := snap.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}

	lmap := make(map[int][]shared.ListenerInfo)
	for _, l := range snap.Listeners {
		lmap[l.Pid] = append(lmap[l.Pid], l)
	}

	cmap := make(map[int][]shared.ConnectionInfo)
	for _, c := range snap.Connections {
		cmap[c.Pid] = append(cmap[c.Pid], c)
	}

	umap := make(map[int][]shared.UDPListenerInfo)
	for _, u := range snap.UDPListeners {
		umap[u.Pid] = append(umap[u.Pid], u)
	}

	rmap := make(map[int][]shared.RawSocketConn)
	for _, r := range snap.RawConns {
		rmap[r.Pid] = append(rmap[r.Pid], r)
	}

	pipemap := make(map[int][]string)
	for _, p := range snap.NamedPipes {
		pipemap[p.Pid] = append(pipemap[p.Pid], p.PipeName)
	}

	seen := make(map[int]bool)
	for pid := range lmap {
		seen[pid] = true
	}
	for pid := range cmap {
		seen[pid] = true
	}
	for pid := range umap {
		seen[pid] = true
	}
	for pid := range snap.RawSocketPIDs {
		seen[pid] = true
	}
	scoring.SeedConnHistoryFromSnapshot(cmap, now)
	delegated := scoring.CorrelateDelegatedEgress(snap, cmap, seen, now)

	for pid, t := range shared.BeaconSeen {
		if now.Sub(t) <= shared.SuspicionWindow {
			seen[pid] = true
		}
	}

	// Keep PIDs with recent connection history visible even when they
	// currently have no active connections. This catches beacons between
	// callback intervals and processes that briefly close connections.
	for key, t := range shared.ConnFirstSeen {
		if now.Sub(t) <= shared.SuspicionWindow {
			seen[key.Pid] = true
		}
	}

	// Also keep PIDs with short-lived burst history (beacon candidates).
	for pid, t := range shared.ShortLivedBurstLast {
		if now.Sub(t) <= shared.SlowScanWindow {
			seen[pid] = true
		}
	}

	// Keep processes from suspicious staging paths visible when they have
	// significant IO activity — these may be long-interval C2 beacons
	// (hours between callbacks) that have no current TCP connections.
	for pid, proc := range snap.Processes {
		if seen[pid] || proc == nil {
			continue
		}
		if !isSuspiciousStagingPathForVisibility(proc.ExePath) {
			continue
		}
		if shared.IsLikelyBenignControlClient(proc) {
			continue
		}
		ioTotal := proc.IOReadBytes + proc.IOWriteBytes + proc.IOOtherBytes
		if ioTotal >= 500*1024 {
			seen[pid] = true
		}
	}

	var out []shared.Candidate
	for pid := range seen {
		proc := snap.Processes[pid]
		if proc == nil {
			continue
		}
		if shared.IsProxywatchProcess(proc) {
			continue
		}

		out = append(out, shared.Candidate{
			Proc:              proc,
			Listeners:         lmap[pid],
			Conns:             cmap[pid],
			UDPListeners:      umap[pid],
			RawConns:          rmap[pid],
			DelegatedEgress:   delegated[pid].OwnerPID > 0,
			DelegatedStrong:   delegated[pid].Strong,
			DelegatedOwnerPID: delegated[pid].OwnerPID,
			DelegatedOwner:    delegated[pid].OwnerName,
			RawSocket:         snap.RawSocketPIDs[pid],
			NamedPipes:        pipemap[pid],
		})
	}

	return out
}

// isSuspiciousStagingPathForVisibility returns true for user-writable staging
// locations where implants are commonly dropped. Used to keep long-interval
// beacons visible even when they have no current TCP connections.
func isSuspiciousStagingPathForVisibility(exePath string) bool {
	p := shared.NormalizeExePath(exePath)
	if p == "" {
		return false
	}
	markers := []string{
		"/downloads/",
		"/desktop/",
		"/tmp/",
		"/var/tmp/",
		"/appdata/local/temp/",
		"/public/",
	}
	for _, m := range markers {
		if strings.Contains(p, m) {
			return true
		}
	}
	return false
}
