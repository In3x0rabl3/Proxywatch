package views

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/gdamore/tcell/v2"

	"proxywatch/internal/detection"
	"proxywatch/internal/detection/ml"
	"proxywatch/internal/detection/model"
	"proxywatch/internal/shared"
	"proxywatch/internal/ui/platform"
)

// TrainingModel is the bubbletea model for the model lifecycle dashboard.
type TrainingModel struct {
	app        *shared.AppState
	viewport   viewport.Model
	width      int
	height     int
	ready      bool
	contentKey uint64
}

func NewTrainingModel(app *shared.AppState) TrainingModel {
	return TrainingModel{app: app}
}

func (m TrainingModel) Init() tea.Cmd { return nil }

func (m TrainingModel) Update(msg tea.Msg) (TrainingModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.InitViewport()
		m.RefreshContent()

	case tea.KeyMsg:
		tev := convertKeyMsg(msg)

		handled, shouldQuit := handleQuitConfirmKey(m.app, tev)
		if handled {
			if shouldQuit {
				return m, tea.Quit
			}
			return m, nil
		}

		if !m.app.TrainingShowHelp && m.ready {
			switch tev.Key() {
			case tcell.KeyPgUp:
				m.viewport.ViewUp()
				return m, nil
			case tcell.KeyPgDn:
				m.viewport.ViewDown()
				return m, nil
			case tcell.KeyHome:
				m.viewport.GotoTop()
				return m, nil
			case tcell.KeyEnd:
				m.viewport.GotoBottom()
				return m, nil
			}
			switch tev.Rune() {
			case '[':
				m.viewport.LineUp(3)
				return m, nil
			case ']':
				m.viewport.LineDown(3)
				return m, nil
			}
		}

		if handleTrainingKey(m.app, tev) {
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m *TrainingModel) InitViewport() {
	if m.width <= 0 || m.height <= 0 {
		return
	}
	vpH := m.height - m.headerHeight() - m.controlsHeight()
	if vpH < 4 {
		vpH = 4
	}
	if !m.ready {
		m.viewport = viewport.New(m.width-4, vpH-2)
		m.viewport.Style = lipgloss.NewStyle()
		m.ready = true
	} else {
		m.viewport.Width = m.width - 4
		m.viewport.Height = vpH - 2
	}
}

func (m TrainingModel) headerHeight() int   { return 3 }
func (m TrainingModel) controlsHeight() int { return 5 } // 3 rows + border

func (m *TrainingModel) RefreshContent() {
	if !m.ready || m.app == nil {
		return
	}
	content := m.buildContent()
	h := quickHash(content)
	if h != m.contentKey {
		m.contentKey = h
		m.viewport.SetContent(content)
	}
}

func (m TrainingModel) View() string {
	w := m.width
	h := m.height
	if w <= 0 || h <= 0 {
		return ""
	}

	var sections []string
	sections = append(sections, m.renderHeader())
	sections = append(sections, m.renderControls())

	if m.ready {
		vpStyle := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorFrame).
			Width(w - 2).
			Height(m.viewport.Height)
		sections = append(sections, vpStyle.Render(m.viewport.View()))
	}

	view := lipgloss.JoinVertical(lipgloss.Left, sections...)

	if m.app.TrainingShowHelp {
		help := trainingHelpOptions()
		view = overlayCenter(view, renderHelpPanel("Model", help, w), w, h)
	}
	if m.app.ShowQuitConfirm && m.app.QuitConfirmDeadline.After(time.Now()) {
		quitPanel := renderQuitConfirm(m.app.QuitConfirmDeadline, w)
		view = overlayCenter(view, quitPanel, w, h)
	}
	return view
}

func trainingHelpOptions() []string {
	return []string{
		"[Navigation]",
		"UP/DOWN      Select control",
		"ENTER        Execute selected action",
		"PgUp/PgDn    Scroll report",
		"[  /  ]      Scroll (3 lines)",
		"Home/End     Top / bottom",
		"ESC          Return to dashboard",
		"LEFT/RIGHT   Cycle workflows",
		"1-6          Jump to workflow",
		"",
		"[Controls]",
		"Auto-Learn     Toggle continuous learning on/off",
		"Retrain        Trigger a retrain cycle now",
		"Reset          Reset to baseline (double-confirm)",
		"",
		"[Role labeling]",
		"Press t in Inspector to cycle training labels",
		"Kill (k) and whitelist (w) also feed the model",
		"",
		"?            Toggle this help",
		"q            Quit",
	}
}

// ── Header ──────────────────────────────────────────────────────────────────

func (m TrainingModel) renderHeader() string {
	w := m.width
	if w <= 0 {
		w = 80
	}
	contentW := w - 2
	helpPlain := "? help   esc dashboard"
	utcPlain := "UTC: " + time.Now().UTC().Format(UTCTimeFormat)
	gap := max(1, contentW-len(helpPlain)-len(utcPlain))
	line := dimText.Render(helpPlain) + bgSp(gap) +
		rightLabelStyle.Render("UTC: ") + dimText.Render(time.Now().UTC().Format(UTCTimeFormat))
	return renderPanel(w, 3, "Model", "proxywatch", "", line)
}

// ── Controls ────────────────────────────────────────────────────────────────

func (m TrainingModel) renderControls() string {
	w := m.width
	if w <= 0 {
		w = 80
	}

	autoVal := "Enabled"
	if !m.app.TrainingAutoRetrain {
		autoVal = "Paused"
	}

	retrainVal := "Trigger training cycle"
	trainingActive := shared.TrainingActiveAtomic.Load() || m.app.TrainingRetraining
	if trainingActive {
		elapsed := spinnerElapsed(m.app.TrainingRetrainStart)
		retrainVal = dotSpinFrame() + " Training... " + elapsed + " (ENTER to stop)"
	}

	resetVal := "Reset to baseline"
	if m.app.TrainingResetConfirm && time.Now().Before(m.app.TrainingResetDeadline) {
		remaining := time.Until(m.app.TrainingResetDeadline).Truncate(time.Second)
		resetVal = fmt.Sprintf("CONFIRM reset (%ds)", int(remaining.Seconds()))
	}

	rows := []FormRow{
		{Field: trainingFieldAutoLearn, Label: "Auto-Learn", Value: autoVal},
		{Field: trainingFieldRetrain, Label: "Train", Value: retrainVal},
		{Field: trainingFieldReset, Label: "Reset", Value: resetVal},
	}
	return renderSetupPanel("CONTROLS", rows, m.app.TrainingField, false, w)
}

// ── Scrollable Content ──────────────────────────────────────────────────────

func (m TrainingModel) buildContent() string {
	sectionHead := lipgloss.NewStyle().Foreground(colorAccent).Bold(true)
	dividerStyle := lipgloss.NewStyle().Foreground(colorFrame)
	w := m.width - 8
	if w < 40 {
		w = 40
	}

	bar := func(title string) string {
		label := " " + title + " "
		fill := w - len(label) - 1
		if fill < 0 {
			fill = 0
		}
		return sectionHead.Render(label) + dividerStyle.Render(strings.Repeat("─", fill))
	}

	var b strings.Builder

	maturity := model.GetMaturity()
	det := model.Get()
	// Read buffer size directly from the learner — the atomic can be stale.
	bufSize := 0
	if learner, ok := m.app.TrainingLearner.(*ml.ContinuousLearner); ok && learner != nil {
		bufSize = learner.Buffer().Len()
	}
	labels := int(model.GetOperatorLabelCount())

	// ── Shared progress bar renderer ───────────────────────────────────
	progressBar := func(label string, pct float64, fg lipgloss.Color) string {
		if pct < 0 {
			pct = 0
		}
		if pct > 100 {
			pct = 100
		}
		barW := 20
		filled := int(pct * float64(barW) / 100)
		empty := barW - filled
		gauge := dimText.Render(platform.BarLeft) +
			lipgloss.NewStyle().Foreground(fg).Render(strings.Repeat(platform.BarFilled, filled)) +
			lipgloss.NewStyle().Foreground(colorDim).Render(strings.Repeat(platform.BarEmpty, empty)) +
			dimText.Render(platform.BarRight)
		padded := label + ":"
		for len(padded) < 16 {
			padded += " "
		}
		return "  " + dimText.Render(padded) +
			bodyText.Render(fmt.Sprintf("%3.0f%%", pct)) + "  " + gauge + "\n"
	}

	// ── 1. MODEL STATUS (unified) ──────────────────────────────────────
	b.WriteString(bar("MODEL STATUS"))
	b.WriteByte('\n')
	bline := model.GetBaselineInfo()
	{
		cyclePhase := shared.GetCyclePhase()
		cycleError := shared.GetCycleError()

		mlModelLoaded := false
		if learner, ok := m.app.TrainingLearner.(*ml.ContinuousLearner); ok && learner != nil {
			mlModelLoaded = learner.Predictor() != nil
		}
		lastTrainVersion := ""
		if orch, ok := m.app.TrainingOrchestrator.(*detection.Orchestrator); ok && orch != nil {
			for _, run := range orch.History() {
				if run.Promoted && !run.RolledBack && run.Error == "" {
					lastTrainVersion = run.Version
				}
			}
		}

		// ── State headline driven by cycle phase ──
		matStyle := maturityColor(maturity.State)
		stateLabel := maturity.State
		detail := ""
		isTrainingPhase := false

		switch cyclePhase {
		case shared.CycleTrainingIngest:
			stateLabel = "TRAINING"
			detail = " — preparing data"
			matStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#56B6C2"))
			isTrainingPhase = true
		case shared.CycleTrainingFit:
			stateLabel = "TRAINING"
			detail = " — fitting model"
			matStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#56B6C2"))
			isTrainingPhase = true
		case shared.CycleTrainingEval:
			stateLabel = "TRAINING"
			detail = " — validating"
			matStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#56B6C2"))
			isTrainingPhase = true
		case shared.CycleTrainingExport:
			stateLabel = "TRAINING"
			detail = " — publishing model"
			matStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#56B6C2"))
			isTrainingPhase = true
		case shared.CycleTrainingDone:
			if mlModelLoaded && lastTrainVersion != "" {
				stateLabel = "TRAINED"
				detail = " " + lastTrainVersion
				matStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#98C379"))
			} else if lastTrainVersion != "" {
				stateLabel = "TRAINED"
				detail = " " + lastTrainVersion + " — loading"
				matStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#56B6C2"))
			}
		case shared.CycleTrainingFailed:
			stateLabel = "TRAIN FAILED"
			matStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#E06C75"))
		case shared.CycleWaitingBuffer:
			stateLabel = "WAITING"
			detail = fmt.Sprintf(" — buffer %d/200 records", bufSize)
			matStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#D19A66"))
		case shared.CycleThresholdMet:
			stateLabel = "THRESHOLD MET"
			detail = " — starting training"
			matStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#56B6C2"))
		default: // CycleCollecting
			// Use baseline/maturity state.
			switch {
			case bline.State == "ready":
				stateLabel = "READY"
				matStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#98C379"))
			case bline.State == "degraded":
				stateLabel = "DEGRADED"
				matStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#D19A66"))
			case mlModelLoaded && lastTrainVersion != "":
				stateLabel = "TRAINED"
				detail = " " + lastTrainVersion
				matStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#98C379"))
			}
		}

		baselineLabel := "shipped"
		if bline.Type == "user" {
			baselineLabel = "user-created"
		}
		b.WriteString("  " + matStyle.Render(stateLabel+detail) +
			dimText.Render("  baseline: "+baselineLabel) +
			dimText.Render(fmt.Sprintf("  (%d observations)", model.LiveObservationCount())) + "\n")

		// Show training error if failed.
		if cyclePhase == shared.CycleTrainingFailed && cycleError != "" {
			errMsg := cycleError
			if len(errMsg) > 60 {
				errMsg = errMsg[:60] + "…"
			}
			b.WriteString("  " + lipgloss.NewStyle().Foreground(lipgloss.Color("#E06C75")).Render(errMsg) + "\n")
		}

		if isTrainingPhase {
			b.WriteString(trainingLine(m.app.TrainingRetrainStart))
		}
		b.WriteByte('\n')

		// Progress bars — always amber. No state-dependent color changes
		// that could be confused with training/collecting states.
		barColor := lipgloss.Color("#D19A66")

		b.WriteString(progressBar("Maturity", float64(maturity.Score), barColor))
		// Stability (cross-time consistency) and Confidence (per-prediction
		// certainty) tracked ~identically on well-calibrated models and
		// were confusing as two separate bars. Collapsed into a single
		// "Decisiveness" bar that averages both, mirroring how the
		// maturity score internally weights them (~equal weight). The
		// individual metrics are still exposed via ModelMaturity fields
		// for callers that want them.
		decisiveness := (maturity.StabilityRatio + maturity.MeanConfidence) / 2 * 100
		b.WriteString(progressBar("Decisiveness", decisiveness, barColor))

		// Collection bar: buffer fills up → 100% → train → reset to 0% → repeat.
		collectionPct := clampPct(float64(bufSize), 200)
		collectionColor := barColor
		if isTrainingPhase {
			collectionPct = 100
			collectionColor = lipgloss.Color("#56B6C2")
		}
		b.WriteString(progressBar("Collection", collectionPct, collectionColor))
		b.WriteByte('\n')

		// Counters.
		autoLabel := "on"
		if !m.app.TrainingAutoRetrain {
			autoLabel = "PAUSED"
		}
		b.WriteString(kvLine("Observations", fmt.Sprintf("%d total, %d in buffer", model.LiveObservationCount(), bufSize)))
		b.WriteString(kvLine("Labels", fmt.Sprintf("%d operator", labels)))
		b.WriteString(kvLine("Auto-Learn", autoLabel))

		// ML model status.
		shadowRate := model.ShadowAgreementRate()
		agree, disagree := model.ShadowCounts()
		qualified := model.MLQualified()
		totalShadow := agree + disagree

		b.WriteByte('\n')
		if !mlModelLoaded {
			if lastTrainVersion != "" {
				b.WriteString(kvLine("ML Model", lastTrainVersion+" trained — awaiting hot-swap"))
			} else {
				b.WriteString(kvLine("ML Model", "not loaded — train to enable"))
			}
		} else {
			modelColor := lipgloss.Color("#56B6C2")
			statusLabel := "shadowing"
			if qualified {
				modelColor = lipgloss.Color("#98C379")
				statusLabel = "active"
			}
			modelStatusStyle := lipgloss.NewStyle().Foreground(modelColor)
			b.WriteString("  " + dimText.Render("ML Model:       ") +
				modelStatusStyle.Render(statusLabel) +
				dimText.Render(fmt.Sprintf("  (%d predictions)", totalShadow)) + "\n")
			// Shadow = disagreement rate (complement of Agreement). Shows
			// how often the ML prediction DIVERGED from the rule engine's
			// verdict — the part of the traffic where the model is still
			// "shadowing" the rules rather than matching them. Colored
			// redder as disagreement rises so high values draw the eye.
			// Previous version capped cumulative prediction count at 100
			// and pinned the bar at 100% forever; that was meaningless for
			// long-running instances.
			shadowRatePct := (1.0 - shadowRate) * 100
			shadowColor := lipgloss.Color("#98C379") // green — low divergence
			switch {
			case shadowRatePct >= 40:
				shadowColor = lipgloss.Color("#E06C75") // red
			case shadowRatePct >= 20:
				shadowColor = lipgloss.Color("#D19A66") // orange
			}
			b.WriteString(progressBar("Shadow", shadowRatePct, shadowColor))
			b.WriteString(progressBar("Agreement", shadowRate*100, modelColor))

			// Operator feedback.
			if det != nil {
				q := det.Quality
				if q.TotalFeedback > 0 {
					b.WriteString(kvLine("Feedback", fmt.Sprintf("%d confirmed, %d contradictions", q.ConfirmedCorrect, q.Contradictions)))
				}
				if q.SelfConfirmed > 0 {
					b.WriteString(kvLine("Self-Learned", fmt.Sprintf("%d", q.SelfConfirmed)))
				}
				labelCounts := countTrainingLabels(det)
				if len(labelCounts) > 0 {
					parts := make([]string, 0, len(labelCounts))
					for _, lc := range labelCounts {
						parts = append(parts, fmt.Sprintf("%s:%d", lc.label, lc.count))
					}
					b.WriteString(kvLine("Labels", strings.Join(parts, "  ")))
				}
			}

			// Summary line.
			if qualified {
				summary := fmt.Sprintf("  Qualified — %d agree, %d disagree (%.0f%% match)", agree, disagree, shadowRate*100)
				b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#98C379")).Render(summary) + "\n")
			} else if model.MLDemoted() {
				// Previously qualified but rolling agreement dropped below the
				// degrade floor — model is running in shadow again while it
				// either re-earns trust or gets replaced by the next retrain.
				summary := fmt.Sprintf("  DEGRADED — dropped below %.0f%% agreement, reverting to shadow (retrain pending)", model.ShadowDegradeFloor*100)
				b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#E06C75")).Render(summary) + "\n")
			} else {
				var summary string
				needThreshold := model.ShadowQualifyAgreement
				needPreds := model.ShadowQualifyPredictions
				if shadowRate < needThreshold {
					summary = fmt.Sprintf("  Shadowing — %.0f%% agreement (need %.0f%% to qualify)", shadowRate*100, needThreshold*100)
				} else {
					needed := needPreds - totalShadow
					if needed > 0 {
						summary = fmt.Sprintf("  Shadowing — %d more predictions to qualify", needed)
					} else {
						summary = fmt.Sprintf("  Shadowing — %.0f%% agreement, building confidence", shadowRate*100)
					}
				}
				b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#D19A66")).Render(summary) + "\n")
			}
		}
	}
	b.WriteByte('\n')

	// ── 6. SIGNAL EFFECTIVENESS ─────────────────────────────────────────
	b.WriteString(bar("SIGNAL EFFECTIVENESS"))
	b.WriteByte('\n')
	if det != nil && len(det.SignalStats) > 0 {
		type sigEntry struct {
			name string
			prec float64
			tp   int
			fp   int
		}
		var entries []sigEntry
		for name, st := range det.SignalStats {
			entries = append(entries, sigEntry{name: name, prec: st.Precision, tp: st.TruePositive, fp: st.FalsePositive})
		}
		// Sort: signals with FP first (noisiest), then by total volume.
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].fp != entries[j].fp {
				return entries[i].fp > entries[j].fp // noisiest first
			}
			return entries[i].tp+entries[i].fp > entries[j].tp+entries[j].fp // then by volume
		})
		top := 8
		if len(entries) < top {
			top = len(entries)
		}
		for _, e := range entries[:top] {
			b.WriteString(fmt.Sprintf("    %-28s  %.0f%%  TP=%d FP=%d\n",
				e.name, e.prec*100, e.tp, e.fp))
		}
	} else {
		b.WriteString(dimText.Render("  Signal stats build from observations and operator feedback.") + "\n")
	}
	b.WriteByte('\n')

	// ── 7. TRAINING HISTORY ─────────────────────────────────────────────
	b.WriteString(bar("TRAINING HISTORY"))
	b.WriteByte('\n')
	if orch, ok := m.app.TrainingOrchestrator.(*detection.Orchestrator); ok && orch != nil {
		history := orch.History()
		if len(history) == 0 {
			b.WriteString(dimText.Render("  No training runs yet. The system will retrain automatically") + "\n")
			b.WriteString(dimText.Render("  when enough observations and labels have been collected.") + "\n")
		} else {
			start := 0
			if len(history) > 8 {
				start = len(history) - 8
			}
			b.WriteString(dimText.Render("  Version   Started              Dataset  Promoted  Error") + "\n")
			for i := len(history) - 1; i >= start; i-- {
				run := history[i]
				started := run.StartedAt.Format("2006-01-02 15:04")
				ds := fmt.Sprintf("%-7d", run.DatasetSize)
				prom := "  -"
				if run.Promoted && !run.RolledBack {
					prom = "  active"
				} else if run.RolledBack {
					prom = "  rolled back"
				}
				errStr := ""
				if run.Error != "" {
					errStr = run.Error
					if len(errStr) > 25 {
						errStr = errStr[:25] + "…"
					}
				}
				line := fmt.Sprintf("  %-9s %-20s %s  %-13s %s",
					run.Version, started, ds, prom, errStr)
				if run.Error != "" {
					b.WriteString(lipgloss.NewStyle().Foreground(colorAlert).Render(line) + "\n")
				} else if run.Promoted && !run.RolledBack {
					b.WriteString(lipgloss.NewStyle().Foreground(colorCyan).Render(line) + "\n")
				} else {
					b.WriteString(dimText.Render(line) + "\n")
				}
			}
		}
	}
	b.WriteByte('\n')

	// ── 8. EVENT LOG ────────────────────────────────────────────────────
	b.WriteString(bar("EVENT LOG"))
	b.WriteByte('\n')
	events := shared.EventLogSnapshot()
	maxEvents := 12
	if len(events) > maxEvents {
		events = events[len(events)-maxEvents:]
	}
	if len(events) == 0 {
		b.WriteString(dimText.Render("  No events yet.") + "\n")
	} else {
		for _, ev := range events {
			ts := ev.Time.Format("15:04:05")
			style := dimText
			switch ev.Severity {
			case shared.EventWarn:
				style = lipgloss.NewStyle().Foreground(lipgloss.Color("#D19A66"))
			case shared.EventError:
				style = lipgloss.NewStyle().Foreground(lipgloss.Color("#E06C75"))
			}
			line := dimText.Render("  "+ts+" ") +
				style.Render("["+ev.Source+"] ") +
				bodyText.Render(ev.Message)
			b.WriteString(line + "\n")
		}
	}

	return b.String()
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func kvLine(label, value string) string {
	padded := label + ":"
	for len(padded) < 16 {
		padded += " "
	}
	return "  " + dimText.Render(padded) + bodyText.Render(value) + "\n"
}

func clampPct(value, max float64) float64 {
	if max <= 0 {
		return 0
	}
	pct := value / max * 100
	if pct > 100 {
		return 100
	}
	return pct
}

func trainingLine(_ time.Time) string {
	trainStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#D19A66"))
	// Use the shared start time set by the orchestrator — works for both
	// manual and auto-triggered detection.
	startNano := shared.TrainingStartTime.Load()
	elapsed := ""
	if startNano > 0 {
		elapsed = spinnerElapsed(time.Unix(0, startNano))
	}
	return "  " + dimText.Render("Collection:     ") + trainStyle.Render(dotSpinFrame()+" Training... "+elapsed) + "\n"
}

func maturityColor(state string) lipgloss.Style {
	switch state {
	case "LEARNING":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#D19A66"))
	case "STABLE":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#56B6C2"))
	case "CALIBRATED":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#98C379"))
	default:
		return dimText
	}
}

type labelCount struct {
	label string
	count int
}

func countTrainingLabels(det *model.DetectionModel) []labelCount {
	if det == nil {
		return nil
	}
	counts := make(map[string]int)
	for _, p := range det.Processes {
		if p.TrainingLabel != "" {
			counts[p.TrainingLabel]++
		}
	}
	if len(counts) == 0 {
		return nil
	}
	var result []labelCount
	for label, count := range counts {
		result = append(result, labelCount{label: label, count: count})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].count > result[j].count })
	return result
}

// refreshBaselineListView updates the cached baseline list in AppState
