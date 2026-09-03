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

// trainingSignalDeweightThresholds gate when a signal gets stripped
// from training records. The point is NOT to silence the signal at
// runtime (it still contributes to scoring / display) — only to keep
// it out of the per-record Signals slice the ML buffer sees. Without
// this filter, a handful of always-firing benign signals (listener-
// open-port-awaiting on every listener, beacon-http-channel on every
// long-held HTTPS) dominate the training corpus to the point that
// maturity / shadow-agreement metrics drop into DEGRADED — operator
// reported 2026-05-03 the model went 40% maturity / 18% shadow with
// 60K+ FP records on these signals overwhelming the buffer.
//
// Two-stage gate so brand-new signals (no stats yet) aren't silently
// stripped: require BOTH a precision floor AND a minimum sample size.
const (
	trainingSignalMinSamples        = 500  // need this many observations before pruning
	trainingSignalPrecisionFloor    = 0.05 // < 5% precision = noise
	trainingSignalDecisivePrecision = 0.30 // ≥ 30% precision = always keep
)

// filterLowPrecisionTrainingSignals returns a copy of `signals` with
// signals that are PROVEN noise (precision < 5% over ≥500 samples)
// removed. Preserves order and never strips signals that lack stats
// yet — the model needs to see new signals to learn anything from
// them. Decisive signals (≥30% precision) bypass the cap so a recent
// FP burst can't silently strip a strong signal.
func filterLowPrecisionTrainingSignals(signals []string) []string {
	if len(signals) == 0 {
		return signals
	}
	out := signals[:0:len(signals)]
	for _, s := range signals {
		stat := model.LookupSignalStat(s)
		if stat != nil && stat.Total >= trainingSignalMinSamples &&
			stat.Precision < trainingSignalPrecisionFloor &&
			stat.Precision < trainingSignalDecisivePrecision {
			continue
		}
		out = append(out, s)
	}
	// Defensive copy so we never alias the caller's slice when nothing was stripped.
	if len(out) == len(signals) {
		dup := make([]string, len(signals))
		copy(dup, signals)
		return dup
	}
	dup := make([]string, len(out))
	copy(dup, out)
	return dup
}

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

// finalizeRoleStreaks commits each candidate's role-stability state
// (hist.LastRole, hist.RoleStableStreak, hist.LastRoleChange) using the
// TRULY-final role for this Classify cycle — i.e. the role after every
// post-pass mutation has run (DemoteShapeOnlyControlRole, vendor FP
// gates, capture-tool suppression, AggregateChildTunnelEvidence,
// ApplyPivotLinger, ApplyBenignClientHostMaliceGate). Updating in the
// per-candidate loop before those passes captures rank.go's pre-demote
// verdict, which flips cycle-to-cycle on shape-driven candidates
// (chrome / code / electron loopback IPC) and resets the streak every
// cycle, trapping the candidate in `analyzing` forever.
//
// CandidateState (shared/candidate.go) reads RoleStableStreak directly
// to decide when to exit the analyzing display state — gating the
// streak on the real final role makes that exit work correctly.
func finalizeRoleStreaks(candidates []shared.Candidate, now time.Time) {
	for i := range candidates {
		c := &candidates[i]
		if c.Proc == nil {
			continue
		}
		hist := scoring.GetHistory(c.Proc.Pid, now)
		if hist == nil {
			continue
		}
		// Compare by role FAMILY, not exact role. listen ↔ listener and
		// other intra-family transitions (session ↔
		// beacon → "beacon" family) are equivalent
		// from an operator perspective and shouldn't trap the
		// candidate in `analyzing` forever. Cross-family transitions
		// (outbound → pivot, listener → beacon)
		// still reset the streak because those represent a real role
		// change worth re-evaluating.
		sameFamily := hist.LastRole != "" &&
			shared.RoleFamily(hist.LastRole) == shared.RoleFamily(c.Role)
		if sameFamily {
			hist.RoleStableStreak++
		} else {
			hist.RoleStableStreak = 1
			hist.LastRoleChange = now
		}
		hist.LastRole = c.Role
	}
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
	now := snap.Timestamp
	if now.IsZero() {
		now = shared.PcapNow()
	}
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
							scoring.ScoreCandidate(c, now)
						} else {
							reuseCandidate(c, &prev)
							touchHistoryFromCandidate(c, now)
						}
					} else {
						scoring.ScoreCandidate(c, now)
					}
				} else {
					scoring.ScoreCandidate(c, now)
				}
			} else {
				scoring.ScoreCandidate(c, now)
			}

			nextSignatures[c.Proc.Pid] = sig
			// nextCandidates stored after model override + ActiveProxying (below).
		} else {
			scoring.ScoreCandidate(c, now)
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

						// Listener-state OS-truth override: if the kernel
						// reports a bound port for this PID, the rule
						// engine's listen / beacon-* verdict is observable
						// ground truth and MUST NOT be overridden by an ML
						// prediction — no matter how confident. The
						// classic FP this prevents: `nc -lnvp 666` (or any
						// service that begins listening mid-run) where the
						// ML model's training data carried 200+ historical
						// "outbound" observations of the same PID/identity
						// before the listener appeared, so the predictor
						// becomes 100%-confident outbound and overrides the
						// rule engine's correct listen verdict. The reverse
						// case (ML says listen but no listener present)
						// also surrenders to the rule engine — listener
						// removal is equally observable.
						//
						// Coverage extended beyond outbound: ML may also
						// predict beacon / pivot for a
						// process that the OS clearly reports as a passive
						// listener (e.g. sshd handling an inbound SSH
						// session got tagged pivot/1.0 in live
						// telemetry on 2026-04-28). Any ML-promoted role
						// that contradicts a "listen" verdict from rank.go
						// while the OS confirms a bound port surrenders.
						hasListenerNow := len(c.Listeners) > 0 || len(c.UDPListeners) > 0
						if hasListenerNow && (scoreRole == "listen" || scoreRole == "listener") &&
							c.Role != scoreRole {
							c.Role = scoreRole
							c.Score = 50
						}
						if !hasListenerNow && (c.Role == "listen" || c.Role == "listener") &&
							(scoreRole == "outbound") {
							c.Role = scoreRole
						}

						// ML-cannot-relax-suspicious gate. When rank.go's
						// topology analysis classified this candidate as a
						// suspicious beacon-* role and ML wants to demote
						// it to a benign role (outbound/listen/listener),
						// rank.go wins — irrespective of ML confidence.
						// This prevents the ML-hides-malware path observed
						// in live telemetry on 2026-04-28: a CS-style
						// payload in C:\Users\Public\ was correctly tagged
						// beacon by rank.go but ML overrode to
						// outbound/1.0, hiding the detection. ML may
						// REFINE between suspicious roles (beacon
						// ↔ pivot) but may NOT escape the
						// suspicious bucket entirely.
						if scoring.IsMaliciousRole(scoreRole) && !scoring.IsMaliciousRole(c.Role) {
							c.Role = scoreRole
							c.Score = confidenceToScore(0.85)
						}

						// Signal-based override: trust live signals/topology over the
						// model when they disagree — BUT ONLY when the model itself
						// is uncertain. A high-confidence ML prediction (>=0.80) has
						// learned patterns across thousands of observations; a single
						// topology heuristic should not override it. Gate every
						// override path on mlLowConfidence so msedgewebview2-style
						// cases (ML outbound 99%, topology beacon) stop
						// flipping to the topology verdict.
						const mlTrustThreshold = 0.80
						mlLowConfidence := result.TopProb < mlTrustThreshold

						signalOverride := false

						// High-specificity signals override ML regardless of confidence.
						// beacon-port-rotation (3+ connections to same IP on different ports)
						// is a strong tunneling/C2 indicator that should never be ignored
						// by ML — legitimate processes don't exhibit this pattern.
						for _, sig := range c.Signals {
							if sig == "beacon-port-rotation" {
								ruleRole = shared.InferRoleFromSignals(c.Signals, "", c.Role)
								if scoring.IsMaliciousRole(ruleRole) {
									c.Role = ruleRole
									signalOverride = true
									if !hasReason(c.Reasons, "High-specificity signal (beacon-port-rotation) overrides ML") {
										c.Reasons = append(c.Reasons, "High-specificity signal (beacon-port-rotation) overrides ML")
									}
								}
								break
							}
						}

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
						// hist.LastRole / RoleStableStreak are committed at the
						// END of Classify (post-pass demotions / gates may still
						// mutate c.Role). See finalizeRoleStreaks() below.
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
						// Maturity stability comparison uses the profile's
						// DominantRole (statistical mode over the full
						// experience window) once enough observations have
						// accumulated. ExperienceLastRole flips with every
						// rule-engine cycle, so on hosts where the rule
						// engine flaps a candidate's role between
						// equivalent verdicts (suppressed-beacon ↔
						// outbound, listener ↔ pivot, etc.) the
						// stability ratio collapses even when the ML model
						// is consistently correct. DominantRole is robust
						// to those transient flips and gives the maturity
						// score a meaningful signal.
						//
						// Detection paths still consult ExperienceLastRole
						// directly (model/decide.go's role-commitment gate
						// + the OS-truth contradiction checks); only the
						// maturity counter changes.
						committed := ""
						if profile != nil {
							if profile.ExperienceObservations >= 30 && profile.DominantRole != "" {
								committed = profile.DominantRole
							} else {
								committed = profile.ExperienceLastRole
							}
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
					// PCAP cluster operator label — stamps the training
					// record's OperatorLabel field (highest training
					// trust tier) so the model gets ground-truth
					// feedback every time a labeled cluster is observed.
					// Stable cluster name = stable training signal across
					// re-analyses.
					if c.Proc != nil && c.Proc.Name != "" && shared.IsPcapMode(c) {
						if pl := shared.LookupPcapOperatorLabel(c.Proc.Name); pl != nil {
							verdict := pl.Verdict
							rec.OperatorLabel = &verdict
						}
					}
					// Filter out persistently-low-precision signals before
					// they enter the training record. These are noise that
					// dilutes the buffer — listener-open-port-awaiting,
					// listener-service-context, listener-wildcard-bind, etc.
					// fire on EVERY listener regardless of role and at 0%
					// precision over 60K+ observations they're indistinguishable
					// from random noise to the model. Keeping them in the
					// training data costs the model nothing; removing them
					// prevents the maturity / shadow-agreement metrics from
					// getting dragged down by buffer-fill from a handful of
					// noisy signals dominating the corpus. Operator confirmation
					// 2026-05-03: model went DEGRADED with 21K observations
					// because 60K+ FP records on these signals overwhelmed
					// the discriminative ones.
					rec.Signals = filterLowPrecisionTrainingSignals(rec.Signals)
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
			// inbound would drop from "pivot" (rank.go) → "listener"
			// (signal-only) when ML is unavailable.
			if !hasPred {
				topologyRole := c.SuggestedRole // rank.go's pre-DecideRole role
				topologyIsSuspicious := scoring.IsMaliciousRole(topologyRole)
				ruleIsSuspicious := scoring.IsMaliciousRole(ruleRole)
				hasListenerNow := len(c.Listeners) > 0 || len(c.UDPListeners) > 0

				switch {
				case topologyIsSuspicious && !ruleIsSuspicious:
					// Topology found a tunnel/pivot/control pattern that signal
					// counting suppressed (e.g. outbound-baseline-verified
					// suppression on a sshd with multiplexed SSH sessions).
					// Trust topology — that's what rank.go's deep analysis is for.
					c.Role = topologyRole
				case hasListenerNow && (topologyRole == "listen" || topologyRole == "listener"):
					// OS-truth gate: kernel reports a bound port AND rank.go
					// classified as a listener. InferRoleFromSignals's outbound-
					// suppression-vs-listener-signal arithmetic must NOT
					// override observable listener state. Without this, system
					// services (services.exe / lsass.exe / svchost) with
					// outbound-known-vendor + outbound-system-path + outbound-
					// baseline-verified collapse to "outbound" even when their
					// listening port is plainly visible to netstat — exactly
					// the false negative observed on 2026-04-28.
					c.Role = topologyRole
				default:
					c.Role = ruleRole
				}

				// Role stability — prevent beacon → outbound flapping
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
				// hist.LastRole / RoleStableStreak are committed at the END
				// of Classify (post-pass demotions may still mutate c.Role).
				// See finalizeRoleStreaks() below.
				_ = hist
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

		// Shape-only beacon demotion — if rank.go assigned a
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
			// Capture-tool override runs first because the standard
			// vendor-FP gates are blocked by the `raw-socket` signal,
			// which is exactly the signal these tools (tcpdump, tshark,
			// dumpcap, wireshark) carry by design. Bypassing the
			// blocker is safe for this small named allowlist — see
			// shared/fp_post_classify.go for the full rationale.
			shared.ApplyCaptureToolSuppression(c)
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
		// When tunneling is active, promote the label to pivot so
		// the ML model learns that this behavior pattern is a pivot.
		if pendingTrainingRec != nil && MLLearner != nil {
			if c.ActiveProxying && pendingTrainingRec.RuleRole != "pivot" {
				pendingTrainingRec.RuleRole = "pivot"
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
	scoring.AggregateChildTunnelEvidence(candidates, snap.Processes, now)

	// Time-lingered pivot promotion. Any candidate observed forwarding
	// internal-only traffic in a relay context (own listener, parent listener,
	// or already a control role) gets stamped into shared.PivotUntil and held
	// at role=pivot for the linger window. Runs after
	// AggregateChildTunnelEvidence so parent-has-listener evidence is
	// up-to-date, and after per-candidate ScoreCandidate + model.DecideRole so
	// the ML model's committed role hold cannot un-promote the pivot.
	scoring.ApplyPivotLinger(candidates, snap.Processes, now)

	// Browser / IDE / API-CLI host-malice gate — runs LAST among the
	// per-host post-passes so the maliciousHosts set reflects every
	// other suppression / promotion that's already fired this cycle.
	// Demotes browsers/IDEs/CLI clients tagged beacon-* back to
	// outbound when no other malicious candidate exists on the same
	// host (i.e. their long-lived CDN/API beacon shape is almost
	// certainly vendor telemetry, not C2). Co-located malice keeps
	// the tag — a browser participating in a real attack chain
	// stays surfaced. See shared/fp_post_classify.go.
	shared.ApplyBenignClientHostMaliceGate(candidates)

	// Pcap-mode role guard — see shared/roles.go's
	// ApplyPcapModeRoleGuard. Runs LAST among the per-host gates so it
	// undoes any beacon-* promotion (rank.go topology, signal
	// counting, ApplyPivotLinger, AggregateChildTunnelEvidence) that
	// happened upstream when the candidate's signal evidence is not
	// packet-decisive. No-op on live candidates (IsPcapMode returns
	// false). Required because pcap synthesises ProcessInfo with no
	// vendor / signing / IPC metadata, so the FP-suppression signals
	// that normally balance beacon-shape signals never fire — every
	// external-talking pcap candidate would otherwise end up
	// beacon.
	shared.ApplyPcapModeRoleGuard(candidates)

	// Final role-streak commit. Captures the TRULY-final role for the
	// cycle (post DemoteShapeOnlyControlRole / vendor FP gates / capture-
	// tool suppression / AggregateChildTunnelEvidence / ApplyPivotLinger /
	// ApplyBenignClientHostMaliceGate). Updating before these passes
	// caused chrome / code / browser-style processes to flap between
	// rank.go's pre-demote verdict (e.g. "beacon" via persistent-
	// session signal) and the post-demote benign role,
	// resetting RoleStableStreak every cycle and trapping the candidate
	// in `analyzing` state forever. See CandidateState in
	// shared/candidate.go for the streak threshold.
	finalizeRoleStreaks(candidates, now)

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
				if profile := model.ResolveProfile(rec.ProcessKey); profile != nil {
					// Same DominantRole-vs-LastRole rationale as the ML
					// path above: comparing against the dominant historical
					// role keeps the maturity stability ratio honest even
					// when the rule engine flaps between equivalent
					// verdicts cycle-to-cycle.
					committed := ""
					if profile.ExperienceObservations >= 30 && profile.DominantRole != "" {
						committed = profile.DominantRole
					} else {
						committed = profile.ExperienceLastRole
					}
					if committed != "" {
						model.RecordRoleAssignment(role == committed, c.Score)
					}
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
				Signals:         filterLowPrecisionTrainingSignals(c.Signals),
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
		now = shared.PcapNow().UTC()
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
