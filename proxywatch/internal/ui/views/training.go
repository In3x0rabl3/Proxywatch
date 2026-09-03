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
	vpH := m.height - m.headerHeight() - m.controlsHeight() - 1 // -1 for bottom bar
	if vpH < 4 {
		vpH = 4
	}
	if !m.ready {
		m.viewport = viewport.New(m.width, vpH)
		m.viewport.Style = lipgloss.NewStyle()
		m.ready = true
	} else {
		m.viewport.Width = m.width
		m.viewport.Height = vpH
	}
}

func (m TrainingModel) headerHeight() int   { return shellBannerHeight(m.width) }
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
		sections = append(sections, m.viewport.View())
	}
	sections = append(sections, m.renderBottomBar(w))

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
		"PGUP/PGDN    Scroll report",
		"[ / ]        Scroll line",
		"HOME/END     Top / bottom",
		"",
		"[Workflows]",
		"LEFT/RIGHT   Cycle workflows",
		"0-7          Jump to workflow",
		"",
		"[Actions]",
		"ENTER        Execute selected control",
		"",
		"[Controls]",
		"Auto-Learn   Toggle continuous learning on/off",
		"Retrain      Trigger a retrain cycle now",
		"Reset        Reset to baseline (double-confirm)",
		"",
		"[Role labeling]",
		"Press t in Inspector to cycle training labels",
		"Kill (k) and whitelist (w) also feed the model",
		"",
		"[General]",
		"?            Close this menu",
		"ESC          Back to dashboard",
		"q            Quit",
	}
}

// ── Header ──────────────────────────────────────────────────────────────────

func (m TrainingModel) renderHeader() string {
	w := m.width
	if w <= 0 {
		w = 80
	}
	return shellBanner(w)
}

// renderBottomBar draws the model dash bottom nav bar (mirrors the dashboard).
func (m TrainingModel) renderBottomBar(w int) string {
	line := bgSp(1) + dimText.Render("esc dashboard    ↑↓ select    [ ] scroll page    enter execute    ? menu")
	if pad := w - lipgloss.Width(line); pad > 0 {
		line += bgSp(pad)
	}
	return line
}

// ── Controls ────────────────────────────────────────────────────────────────

func (m TrainingModel) renderControls() string {
	w := m.width
	if w <= 0 {
		w = 80
	}

	autoVal := "ENABLED"
	if !m.app.TrainingAutoRetrain {
		autoVal = "PAUSED"
	}

	retrainVal := "INITIATE CYCLE"
	trainingActive := shared.TrainingActiveAtomic.Load() || m.app.TrainingRetraining
	if trainingActive {
		d := time.Since(m.app.TrainingRetrainStart)
		elapsed := formatTacticalElapsed(d)
		retrainVal = dotSpinFrame() + " ACQUIRING " + elapsed + " (ENTER TO ABORT)"
	}

	resetVal := "RTB (RETURN TO BASELINE)"
	if m.app.TrainingResetConfirm && time.Now().Before(m.app.TrainingResetDeadline) {
		remaining := time.Until(m.app.TrainingResetDeadline).Truncate(time.Second)
		resetVal = fmt.Sprintf("CONFIRM RTB (%02ds)", int(remaining.Seconds()))
	}

	forceMLVal := "TRUST ML (OVERRIDE RULES)"
	if model.MLForceQualified() {
		forceMLVal = "ML TRUSTED — PRESS TO REVERT"
	}

	rows := []FormRow{
		{Field: trainingFieldAutoLearn, Label: "AUTO-ACQUIRE", Value: autoVal},
		{Field: trainingFieldRetrain, Label: "TRAIN", Value: retrainVal},
		{Field: trainingFieldReset, Label: "RTB", Value: resetVal},
		{Field: trainingFieldForceML, Label: "FORCE", Value: forceMLVal},
	}
	return renderSetupPanel("CONTROLS", rows, m.app.TrainingField, false, w)
}

// ── Scrollable Content ──────────────────────────────────────────────────────

func (m TrainingModel) buildContent() string {
	w := m.width // full-width boxes
	if w < 40 {
		w = 40
	}

	// Section sentinels — bar(title) emits an unstyled marker that the
	// post-pass below splits on to wrap each section in its own
	// accent-bordered box (matching the Inspector format / color the
	// operator asked for). Using a unique non-printing sentinel keeps
	// every existing b.WriteString call inside the section's content
	// without renaming them.
	const sectionSentinel = "\x1c__PROXYWATCH_TRAINING_SECTION__\x1c"
	bar := func(title string) string {
		return sectionSentinel + title + sectionSentinel
	}
	_ = bar // keep referenced for the immediate-mode fallback below

	var b strings.Builder

	maturity := model.GetMaturity()
	det := model.Get()
	// Read buffer size directly from the learner — the atomic can be stale.
	bufSize := 0
	if learner, ok := m.app.TrainingLearner.(*ml.ContinuousLearner); ok && learner != nil {
		bufSize = learner.Buffer().Len()
	}

	// ── Shared progress bar renderer (square blocks style) ────────────
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
		// Square blocks: ■ for filled, □ for empty
		gauge := lipgloss.NewStyle().Foreground(fg).Render(strings.Repeat("■", filled)) +
			lipgloss.NewStyle().Foreground(colorDim).Render(strings.Repeat("□", empty))
		label = strings.ToUpper(label)
		const totalWidth = 24
		dotsNeeded := totalWidth - len(label) - 1
		if dotsNeeded < 2 {
			dotsNeeded = 2
		}
		dots := " " + strings.Repeat(".", dotsNeeded) + " "
		// Zero-padded percentage (015%)
		return "  " + inspLabel.Render(label) + dimText.Render(dots) +
			bodyText.Render(fmt.Sprintf("%03.0f%%", pct)) + "  " + gauge + "\n"
	}

	// ── STATUS (state + maturity) ──────────────────────────────────────
	b.WriteString(bar("STATUS"))
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
			stateLabel = "ACQUIRING"
			detail = " — PREP DATA"
			matStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#B39A63"))
			isTrainingPhase = true
		case shared.CycleTrainingFit:
			stateLabel = "ACQUIRING"
			detail = " — FIT MODEL"
			matStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#B39A63"))
			isTrainingPhase = true
		case shared.CycleTrainingEval:
			stateLabel = "ACQUIRING"
			detail = " — VALIDATE"
			matStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#B39A63"))
			isTrainingPhase = true
		case shared.CycleTrainingExport:
			stateLabel = "ACQUIRING"
			detail = " — PUBLISH"
			matStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#B39A63"))
			isTrainingPhase = true
		case shared.CycleTrainingDone:
			if mlModelLoaded && lastTrainVersion != "" {
				stateLabel = "OPERATIONAL"
				detail = " REV-" + strings.TrimPrefix(lastTrainVersion, "v")
				matStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#6F9B78"))
			} else if lastTrainVersion != "" {
				stateLabel = "LOADING"
				detail = " REV-" + strings.TrimPrefix(lastTrainVersion, "v")
				matStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#B39A63"))
			}
		case shared.CycleTrainingFailed:
			stateLabel = "CYCLE FAILED"
			matStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#B4696A"))
		case shared.CycleWaitingBuffer:
			stateLabel = "STANDBY"
			detail = fmt.Sprintf(" — BUFFER %04d/0200", bufSize)
			matStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#B39A63"))
		case shared.CycleThresholdMet:
			stateLabel = "THRESHOLD MET"
			detail = " — INITIATING"
			matStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#B39A63"))
		default: // CycleCollecting
			switch {
			case bline.State == "ready":
				stateLabel = "OPERATIONAL"
				matStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#6F9B78"))
			case bline.State == "degraded":
				stateLabel = "DEGRADED"
				matStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#B39A63"))
			case mlModelLoaded && lastTrainVersion != "":
				stateLabel = "OPERATIONAL"
				detail = " REV-" + strings.TrimPrefix(lastTrainVersion, "v")
				matStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#6F9B78"))
			}
		}

		baselineLabel := "SHIPPED"
		if bline.Type == "user" {
			baselineLabel = "USER"
		}

		// Show training error if failed.
		if cyclePhase == shared.CycleTrainingFailed && cycleError != "" {
			errMsg := cycleError
			if len(errMsg) > 60 {
				errMsg = errMsg[:60] + "…"
			}
			b.WriteString("  " + lipgloss.NewStyle().Foreground(lipgloss.Color("#B4696A")).Render(errMsg) + "\n")
		}

		if isTrainingPhase {
			b.WriteString(trainingLine(m.app.TrainingRetrainStart))
		}

		// Status line with dot leaders (like maturity)
		b.WriteString("  " + inspLabel.Render("STATUS") + dimText.Render(" .............. ") + matStyle.Render(stateLabel+detail) + "\n")
		b.WriteString("  " + inspLabel.Render("BASELINE") + dimText.Render(" ............ ") + bodyText.Render(baselineLabel) + "\n")

		// Progress bars — always amber
		barColor := lipgloss.Color("#B39A63")
		b.WriteString(progressBar("Maturity", float64(maturity.Score), barColor))

		// ── ML MODEL ──
		shadowRate := model.ShadowAgreementRate()
		agree, disagree := model.ShadowCounts()
		qualified := model.MLQualified()
		totalShadow := agree + disagree

		b.WriteString(bar("ML MODEL"))
		b.WriteByte('\n')
		if !mlModelLoaded {
			if lastTrainVersion != "" {
				b.WriteString(kvLine("Status", "REV-"+strings.TrimPrefix(lastTrainVersion, "v")+" — AWAITING SWAP"))
			} else {
				b.WriteString(kvLine("Status", "NOT LOADED — TRAIN TO ENABLE"))
			}
		} else {
			modelColor := lipgloss.Color("#B39A63")
			statusLabel := "SHADOWING"
			if qualified {
				modelColor = lipgloss.Color("#6F9B78")
				statusLabel = "ACTIVE"
			}
			modelStatusStyle := lipgloss.NewStyle().Foreground(modelColor)
			b.WriteString("  " + inspLabel.Render("STATUS") + dimText.Render(" .............. ") +
				modelStatusStyle.Render(statusLabel) +
				dimText.Render(fmt.Sprintf("  (%04d PREDICTIONS)", totalShadow)) + "\n")
			shadowRatePct := (1.0 - shadowRate) * 100
			shadowColor := lipgloss.Color("#6F9B78")
			switch {
			case shadowRatePct >= 40:
				shadowColor = lipgloss.Color("#B4696A")
			case shadowRatePct >= 20:
				shadowColor = lipgloss.Color("#B39A63")
			}
			b.WriteString(progressBar("Divergence", shadowRatePct, shadowColor))
			b.WriteString(progressBar("Sync Rate", shadowRate*100, modelColor))

			if det != nil {
				q := det.Quality
				if q.TotalFeedback > 0 {
					b.WriteString(kvLine("Feedback", fmt.Sprintf("%04d CONFIRMED, %04d CONTRADICTIONS", q.ConfirmedCorrect, q.Contradictions)))
				}
				if q.SelfConfirmed > 0 {
					b.WriteString(kvLine("Self-Learned", fmt.Sprintf("%04d", q.SelfConfirmed)))
				}
				labelCounts := countTrainingLabels(det)
				if len(labelCounts) > 0 {
					parts := make([]string, 0, len(labelCounts))
					for _, lc := range labelCounts {
						parts = append(parts, fmt.Sprintf("%s:%04d", strings.ToUpper(lc.label), lc.count))
					}
					b.WriteString(kvLine("Labels", strings.Join(parts, "  ")))
				}
			}

			if qualified {
				summary := fmt.Sprintf("  QUALIFIED — %04d AGREE, %04d DISAGREE (%03.0f%% SYNC)", agree, disagree, shadowRate*100)
				b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#6F9B78")).Render(summary) + "\n")
			} else if model.MLDemoted() {
				summary := fmt.Sprintf("  DEGRADED — BELOW %03.0f%% SYNC, REVERTING TO SHADOW", model.ShadowDegradeFloor*100)
				b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#B4696A")).Render(summary) + "\n")
			} else {
				var summary string
				needThreshold := model.ShadowQualifyAgreement
				needPreds := model.ShadowQualifyPredictions
				if shadowRate < needThreshold {
					summary = fmt.Sprintf("  SHADOWING — %03.0f%% SYNC (NEED %03.0f%% TO QUALIFY)", shadowRate*100, needThreshold*100)
				} else {
					needed := needPreds - totalShadow
					if needed > 0 {
						summary = fmt.Sprintf("  SHADOWING — %04d MORE PREDICTIONS TO QUALIFY", needed)
					} else {
						summary = fmt.Sprintf("  SHADOWING — %03.0f%% SYNC, BUILDING CONFIDENCE", shadowRate*100)
					}
				}
				b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#B39A63")).Render(summary) + "\n")
			}
		}
	}
	b.WriteByte('\n')

	// ── Fetch orchestrator data once for all ML sections ──
	var latestRun *detection.TrainRun
	var shadowMetrics *detection.ShadowMetrics
	if orch, ok := m.app.TrainingOrchestrator.(*detection.Orchestrator); ok && orch != nil {
		latestRun = orch.LatestPromotedRun()
		shadowMetrics = orch.GetShadowMetrics()
	}

	// ── DRIFT MONITOR ───────────────────────────────────────────────────
	b.WriteString(bar("DRIFT MONITOR"))
	b.WriteByte('\n')
	if shadowMetrics != nil && shadowMetrics.Predictions > 0 {
		// A/B testing a new candidate model
		b.WriteString(kvLine("Shadow Model", shadowMetrics.ModelVersion))
		b.WriteString(kvLine("Predictions", fmt.Sprintf("%d", shadowMetrics.Predictions)))
		agreement := shadowMetrics.AgreementRate() * 100
		agreeStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#6F9B78"))
		if agreement < 80 {
			agreeStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#B39A63"))
		}
		if agreement < 60 {
			agreeStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#B4696A"))
		}
		b.WriteString("  " + inspLabel.Render("AGREEMENT") + dimText.Render(" .......... ") +
			agreeStyle.Render(fmt.Sprintf("%.1f%%", agreement)) + "\n")
		confirmed := shadowMetrics.ConfirmedRight + shadowMetrics.ConfirmedWrong
		if confirmed > 0 {
			accuracy := float64(shadowMetrics.ConfirmedRight) / float64(confirmed) * 100
			b.WriteString(kvLine("Confirmed", fmt.Sprintf("%d right / %d wrong (%.1f%%)", shadowMetrics.ConfirmedRight, shadowMetrics.ConfirmedWrong, accuracy)))
		}
	} else {
		// Show ML vs rules drift when no A/B test is active
		mlAgree, mlDisagree := model.ShadowCounts()
		totalPreds := mlAgree + mlDisagree
		if totalPreds > 0 {
			syncRate := model.ShadowAgreementRate() * 100
			driftRate := 100 - syncRate
			driftStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#6F9B78"))
			if driftRate > 20 {
				driftStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#B39A63"))
			}
			if driftRate > 40 {
				driftStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#B4696A"))
			}
			b.WriteString(kvLine("ML vs Rules", fmt.Sprintf("%d predictions", totalPreds)))
			b.WriteString("  " + inspLabel.Render("DRIFT RATE") + dimText.Render(" ........ ") +
				driftStyle.Render(fmt.Sprintf("%.1f%%", driftRate)) +
				dimText.Render(fmt.Sprintf("  (%d disagree)", mlDisagree)) + "\n")
		} else {
			b.WriteString(dimText.Render("  Collecting predictions...") + "\n")
		}
	}
	b.WriteByte('\n')

	// ── FEATURE IMPORTANCE ──────────────────────────────────────────────
	b.WriteString(bar("FEATURE IMPORTANCE"))
	b.WriteByte('\n')
	if latestRun != nil && len(latestRun.FeatureImportance) > 0 {
		// Pre-sorted slice (sorted once, stored in run)
		type featImp struct {
			name string
			imp  float64
		}
		var features []featImp
		for name, imp := range latestRun.FeatureImportance {
			features = append(features, featImp{name, imp})
		}
		// Quick sort - only 117 features max
		sort.Slice(features, func(i, j int) bool {
			return features[i].imp > features[j].imp
		})
		top := 8
		if len(features) < top {
			top = len(features)
		}
		if top > 0 {
			maxImp := features[0].imp
			if maxImp == 0 {
				maxImp = 1 // avoid division by zero
			}
			for _, f := range features[:top] {
				pct := f.imp / maxImp * 100
				barW := 20
				filled := int(pct * float64(barW) / 100)
				if filled > barW {
					filled = barW
				}
				// Square blocks style matching other bars: ■ filled, □ empty
				gauge := lipgloss.NewStyle().Foreground(colorCyan).Render(strings.Repeat("■", filled)) +
					lipgloss.NewStyle().Foreground(colorDim).Render(strings.Repeat("□", barW-filled))
				name := f.name
				if len(name) > 20 {
					name = name[:18] + "…"
				}
				// Dot leader style matching other rows
				const labelW = 20
				dotsNeeded := labelW - len(name)
				if dotsNeeded < 2 {
					dotsNeeded = 2
				}
				dots := " " + strings.Repeat(".", dotsNeeded) + " "
				b.WriteString("  " + inspLabel.Render(strings.ToUpper(name)) + dimText.Render(dots) +
					bodyText.Render(fmt.Sprintf("%03.0f%%", pct)) + "  " + gauge + "\n")
			}
		}
	} else {
		b.WriteString(dimText.Render("  Feature importance computed after first training cycle.") + "\n")
	}
	b.WriteByte('\n')

	// ── 6. SIGNAL EFFECTIVENESS ─────────────────────────────────────────
	// Same row structure as EVENT LOG: leading dim margin → bracketed
	// [tag] in a severity-coloured style (high / mid / low precision
	// bucket) → bodyText for the signal name + numeric columns. Header
	// and row use the same column widths via the sigEffCol* constants
	// below so labels sit directly above their values.
	b.WriteString(bar("SIGNAL EFFECTIVENESS"))
	b.WriteByte('\n')
	if det != nil && len(det.SignalStats) > 0 {
		const (
			sigEffTagW  = 10 // "[CHARLIE] "
			sigEffNameW = 36 // signal name column (longest: pivot-loopback-listener-external-out)
			sigEffPrecW = 6  // "100% "
			sigEffTPW   = 10 // "TP=12719 "
			sigEffFPW   = 10 // "FP=0336 "
		)
		header := dimText.Render(fmt.Sprintf("  %-*s%-*s%-*s%-*s%-*s",
			sigEffTagW, "CLASS",
			sigEffNameW, "SIGNAL",
			sigEffPrecW, "PREC",
			sigEffTPW, "TP",
			sigEffFPW, "FP",
		))
		b.WriteString(header + "\n")
		// Separator line
		b.WriteString(dimText.Render("  "+strings.Repeat("─", sigEffTagW+sigEffNameW+sigEffPrecW+sigEffTPW+sigEffFPW)) + "\n")

		type sigEntry struct {
			name string
			prec float64
			tp   int
			fp   int
		}
		var entries []sigEntry
		for name, st := range det.SignalStats {
			if st.Total == 0 {
				continue
			}
			entries = append(entries, sigEntry{name: name, prec: st.Precision, tp: st.TruePositive, fp: st.FalsePositive})
		}
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].prec != entries[j].prec {
				return entries[i].prec > entries[j].prec
			}
			vi := entries[i].tp + entries[i].fp
			vj := entries[j].tp + entries[j].fp
			if vi != vj {
				return vi > vj
			}
			return entries[i].name < entries[j].name
		})
		top := 12
		if len(entries) < top {
			top = len(entries)
		}
		alertStyle := lipgloss.NewStyle().Foreground(colorAlert)
		warnStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#B39A63"))
		okStyle := lipgloss.NewStyle().Foreground(colorCyan)
		tpStyle := lipgloss.NewStyle().Foreground(colorCyan)
		fpStyle := alertStyle
		for _, e := range entries[:top] {
			tag := "[CHARLIE]"
			tagStyle := alertStyle
			switch {
			case e.prec >= 0.50:
				tag = "[ALPHA]"
				tagStyle = okStyle
			case e.prec >= 0.20:
				tag = "[BRAVO]"
				tagStyle = warnStyle
			}
			// Truncate long signal names to fit column
			sigName := e.name
			if len(sigName) > sigEffNameW-1 {
				sigName = sigName[:sigEffNameW-2] + "…"
			}
			line := dimText.Render("  ") +
				tagStyle.Render(fmt.Sprintf("%-*s", sigEffTagW, tag)) +
				bodyText.Render(fmt.Sprintf("%-*s", sigEffNameW, sigName)) +
				bodyText.Render(fmt.Sprintf("%-*s", sigEffPrecW, fmt.Sprintf("%03d%%", int(e.prec*100+0.5)))) +
				tpStyle.Render(fmt.Sprintf("%-*s", sigEffTPW, fmt.Sprintf("TP=%d", e.tp))) +
				fpStyle.Render(fmt.Sprintf("%-*s", sigEffFPW, fmt.Sprintf("FP=%d", e.fp)))
			b.WriteString(line + "\n")
		}
		if len(entries) == 0 {
			b.WriteString(dimText.Render("  No graded signals yet — feedback accumulates after first labels.") + "\n")
		}
	} else {
		b.WriteString(dimText.Render("  Signal stats build from observations and operator feedback.") + "\n")
	}
	b.WriteByte('\n')

	// ── 7. TRAINING HISTORY ─────────────────────────────────────────────
	// Same row structure as EVENT LOG: leading dim margin → bracketed
	// version tag in a status-coloured style (cyan=active, warn=rolled
	// back, alert=error, dim=other) → bodyText for the date / dataset
	// columns. Status word at end retains its own colour so the line
	// still reads at a glance.
	b.WriteString(bar("TRAINING HISTORY"))
	b.WriteByte('\n')
	if orch, ok := m.app.TrainingOrchestrator.(*detection.Orchestrator); ok && orch != nil {
		// Show cumulative stats summary
		cumObs := orch.CumulativeObservations()
		if cumObs > 0 {
			b.WriteString(dimText.Render(fmt.Sprintf("  Total observations: %d", cumObs)) + "\n")
		}

		history := orch.History()
		if len(history) == 0 {
			b.WriteString(dimText.Render("  No training runs yet. The system will retrain automatically") + "\n")
			b.WriteString(dimText.Render("  when enough observations and labels have been collected.") + "\n")
		} else {
			// Shared column widths for military format
			const (
				histVerW    = 10 // "[REV-033] "
				histStartW  = 20 // "01MAY26 J121 0146Z"
				histDataW   = 8  // "0200   "
				histCumW    = 10 // "1234567  "
				histStatusW = 14 // "● rolled back"
			)
			b.WriteString(dimText.Render(fmt.Sprintf("  %-*s%-*s%-*s%-*s%s",
				histVerW, "REV",
				histStartW, "DTG",
				histDataW, "BATCH",
				histCumW, "CUMUL",
				"STATUS",
			)) + "\n")
			// Separator line
			b.WriteString(dimText.Render("  "+strings.Repeat("─", histVerW+histStartW+histDataW+histCumW+histStatusW)) + "\n")
			alertStyle := lipgloss.NewStyle().Foreground(colorAlert)
			warnStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#B39A63"))
			okStyle := lipgloss.NewStyle().Foreground(colorCyan)
			start := 0
			if len(history) > 8 {
				start = len(history) - 8
			}
			for i := len(history) - 1; i >= start; i-- {
				run := history[i]
				started := formatMilDateTime(run.StartedAt)
				ds := fmt.Sprintf("%04d", run.DatasetSize)
				cumul := fmt.Sprintf("%d", run.CumulativeObservations)
				if run.CumulativeObservations == 0 {
					cumul = "—" // legacy runs without cumulative tracking
				}
				statusLabel := "—"
				statusStyle := dimText
				switch {
				case run.Error != "":
					statusLabel = "ERROR"
					statusStyle = alertStyle
				case run.RolledBack:
					statusLabel = "ROLLED BACK"
					statusStyle = warnStyle
				case run.Promoted:
					statusLabel = "ACTIVE"
					statusStyle = okStyle
				}
				tagStyle := okStyle
				if run.Error != "" {
					tagStyle = alertStyle
				} else if run.RolledBack {
					tagStyle = warnStyle
				} else if !run.Promoted {
					tagStyle = dimText
				}
				errSuffix := ""
				if run.Error != "" {
					errStr := run.Error
					if len(errStr) > 25 {
						errStr = errStr[:25] + "…"
					}
					errSuffix = "  " + alertStyle.Render(errStr)
				}
				tag := fmt.Sprintf("[REV-%s]", strings.TrimPrefix(run.Version, "v"))
				line := dimText.Render("  ") +
					tagStyle.Render(fmt.Sprintf("%-*s", histVerW, tag)) +
					bodyText.Render(fmt.Sprintf("%-*s", histStartW, started)) +
					bodyText.Render(fmt.Sprintf("%-*s", histDataW, ds)) +
					bodyText.Render(fmt.Sprintf("%-*s", histCumW, cumul)) +
					statusStyle.Render(fmt.Sprintf("%-*s", histStatusW, statusLabel)) +
					errSuffix
				b.WriteString(line + "\n")
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
			ts := formatZuluTimeSec(ev.Time)
			style := dimText
			switch ev.Severity {
			case shared.EventWarn:
				style = lipgloss.NewStyle().Foreground(lipgloss.Color("#B39A63"))
			case shared.EventError:
				style = lipgloss.NewStyle().Foreground(lipgloss.Color("#B4696A"))
			}
			line := dimText.Render("  "+ts+" ") +
				style.Render("["+ev.Source+"] ") +
				bodyText.Render(ev.Message)
			b.WriteString(line + "\n")
		}
	}

	// Post-process: split the buffered content on the section sentinels
	// emitted by bar(...), then wrap each section body in an
	// accent-bordered panel with the section title in the top-left.
	// Leading content before the first sentinel (none in current
	// layout, but kept for safety) flows through unchanged.
	raw := b.String()
	parts := strings.Split(raw, sectionSentinel)
	if len(parts) < 3 {
		return raw
	}
	var out strings.Builder
	if strings.TrimSpace(parts[0]) != "" {
		out.WriteString(parts[0])
	}
	for i := 1; i+1 < len(parts); i += 2 {
		title := parts[i]
		body := strings.TrimPrefix(parts[i+1], "\n")
		body = strings.TrimRight(body, "\n")
		h := strings.Count(body, "\n") + 3
		out.WriteString(renderAccentPanel(w, h, title, body))
		out.WriteByte('\n')
	}
	return out.String()
}

// ── Helpers ─────────────────────────────────────────────────────────────────

// kvLineMil renders a key-value line with dot leaders for military-style alignment
func kvLineMil(label, value string) string {
	label = strings.ToUpper(label)
	const totalWidth = 24
	dotsNeeded := totalWidth - len(label) - 1
	if dotsNeeded < 2 {
		dotsNeeded = 2
	}
	dots := " " + strings.Repeat(".", dotsNeeded) + " "
	return "  " + inspLabel.Render(label) + dimText.Render(dots) + bodyText.Render(value) + "\n"
}

// kvLine kept for compatibility but now uses dot leaders
func kvLine(label, value string) string {
	return kvLineMil(label, value)
}

// formatMilDateTime formats time as military: 01MAY26 J121 0146Z
func formatMilDateTime(t time.Time) string {
	t = t.UTC()
	day := t.Day()
	month := strings.ToUpper(t.Format("Jan"))
	year := t.Format("06")
	julian := t.YearDay()
	hour := t.Hour()
	minute := t.Minute()
	return fmt.Sprintf("%02d%s%s J%03d %02d%02dZ", day, month, year, julian, hour, minute)
}

// formatZuluTimeSec formats time as Zulu with seconds: 014632Z
func formatZuluTimeSec(t time.Time) string {
	t = t.UTC()
	return fmt.Sprintf("%02d%02d%02dZ", t.Hour(), t.Minute(), t.Second())
}

// formatTacticalElapsed formats duration as T+MM:SS
func formatTacticalElapsed(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	totalSec := int(d.Seconds())
	min := totalSec / 60
	sec := totalSec % 60
	return fmt.Sprintf("T+%02d:%02d", min, sec)
}

func trainingLine(_ time.Time) string {
	trainStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#B39A63"))
	startNano := shared.TrainingStartTime.Load()
	elapsed := "T+00:00"
	if startNano > 0 {
		d := time.Since(time.Unix(0, startNano))
		elapsed = formatTacticalElapsed(d)
	}
	return "  " + inspLabel.Render("ACQUISITION") + dimText.Render(" ............ ") +
		trainStyle.Render(dotSpinFrame()+" TRAINING "+elapsed) + "\n"
}

func maturityColor(state string) lipgloss.Style {
	switch state {
	case "LEARNING":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#B39A63"))
	case "STABLE":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#B39A63"))
	case "CALIBRATED":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#6F9B78"))
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
