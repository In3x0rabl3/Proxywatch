package common

import (
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// Sparkline glyphs: three CP437 half-blocks that give us actual
// vertical position variation per cell, like a real ECG trace
// instead of a dim → bright color bar. All three glyphs (▄ ▀ █) are
// in CP437 — same code-page neighborhood as `█`, which already
// renders for the operator — so we know they'll show up.
//
//   - sparkGlyphLow  '▄' (U+2584): line sits at the BOTTOM of the
//     cell (baseline / quiet)
//   - sparkGlyphMid  '█' (U+2588): line passes through the MIDDLE
//     (rising or falling through this cell)
//   - sparkGlyphHigh '▀' (U+2580): line sits at the TOP of the cell
//     (peak)
//
// A spike now visibly RISES (`▄` → `█` → `▀`) and FALLS (`▀` → `█`
// → `▄`) instead of just brightening in place. Color is still used
// inside each level to convey finer magnitude.
const (
	sparkGlyphLow  = "▄"
	sparkGlyphMid  = "█"
	sparkGlyphHigh = "▀"
)

// sparkColors is the foreground-color gradient used to encode the
// finer-grained magnitude WITHIN whichever vertical position the
// glyph is at. Six stops; baselineColor (sparkColors[0]) is the
// barely-visible "ECG idle line" tint.
var sparkColors = []lipgloss.Color{
	"#2a3a2f", // 0 — baseline (idle line tint)
	"#436659", // 1 — dim teal
	"#52806e", // 2
	"#74b69d", // 3
	"#8ad2b5", // 4
	"#a4eecf", // 5 — bright teal (peak)
}

// Sparkline renders a slice of values as a Unicode-block sparkline of
// exactly `width` runes. Auto-scales to the max value in the series.
//
// Behavior:
//   - width <= 0 returns empty string.
//   - empty series returns a string of `width` spaces.
//   - all-zero series returns a string of `width` spaces.
//   - any series with non-zero data: empty buckets render as the
//     baseline glyph (▁) so the bar always shows a visible "this row
//     exists" baseline that rises and falls with traffic. Without a
//     baseline, gaps between bursts looked like the row was broken.
//   - len(values) == width: one rune per value.
//   - len(values) >  width: bucketed (mean-pool) and lightly smoothed
//     with a 3-cell rolling average so adjacent buckets transition
//     smoothly instead of stepping in hard rectangles.
//   - len(values) <  width: stretched (left-aligned), tail padded with
//     spaces so callers always get a stable column width.
//
// The TUI uses this for the per-finding ACTIVITY column in the pcap
// dashboard, the live dashboard process view, and the in-detail
// TIMELINE section.
func Sparkline(values []uint64, width int) string {
	return SparklineWithBg(values, width, "")
}

// SparklineWithBg is the same as Sparkline but with a caller-supplied
// background color baked into every cell. Use this when the bar is
// rendered inside a row that has its own background (e.g. the
// dashboard's selection highlight) — the per-cell ANSI escape
// sequences emitted for the foreground gradient include resets that
// would otherwise wipe the outer background between cells. Empty bg
// means no background (transparent / terminal default).
//
// When bg is set, baseline-tinted cells (the idle ECG line) are
// auto-promoted to a brighter color stop so they stay visible on
// top of the selection background — the default dim baseline blends
// into ColorSelect and disappears.
func SparklineWithBg(values []uint64, width int, bg lipgloss.Color) string {
	if width <= 0 {
		return ""
	}
	// Resolve the baseline color: when no bg, the standard dim teal
	// is fine; when bg is set, bump to a brighter stop so the
	// baseline glyph reads against the selection background.
	baselineFg := sparkColors[0]
	if bg != "" {
		baselineFg = sparkColors[2]
	}
	style := func(fg lipgloss.Color) lipgloss.Style {
		// Substitute the brighter baseline color for the dim default
		// whenever the cell would render as baseline AND a bg is set.
		if bg != "" && fg == sparkColors[0] {
			fg = baselineFg
		}
		s := lipgloss.NewStyle().Foreground(fg)
		if bg != "" {
			s = s.Background(bg)
		}
		return s
	}
	// Render a full-width baseline glyph for every cell when there's
	// no data or when all samples are zero. Like an ECG monitor's
	// flat trace: the row is always visibly alive, even for idle
	// processes that haven't pushed any bytes — peaks rise out of
	// this baseline and decay back into it. Baseline = ▄ at the
	// bottom of the cell, dim-tinted.
	baselineRow := func() string {
		baseline := style(sparkColors[0]).Render(sparkGlyphLow)
		var b strings.Builder
		b.Grow(width * len(baseline))
		for i := 0; i < width; i++ {
			b.WriteString(baseline)
		}
		return b.String()
	}
	if len(values) == 0 {
		return baselineRow()
	}
	// Apply an exponential moving average over the input series before
	// bucketing. EMA gives a single-sample burst temporal persistence —
	// the spike's contribution decays gracefully across subsequent
	// samples instead of vanishing on the next tick — which is what
	// turns a row of bursty 250ms I/O readings into a fluid wave that
	// rises smoothly into a peak and tails back down to baseline.
	persisted := emaPersist(values, 0.55)
	bucketed := bucketize(persisted, width)
	smoothed := smooth3(bucketed)
	var maxVal uint64
	for _, v := range smoothed {
		if v > maxVal {
			maxVal = v
		}
	}
	if maxVal == 0 {
		return baselineRow()
	}
	var b strings.Builder
	b.Grow(width * 16)
	// Map each sample's relative magnitude into one of three vertical
	// positions (low ▄, mid █, high ▀) so the wave actually rises and
	// falls across the bar — like a real heart-rate trace, not a
	// dim → bright color gradient. Color brightness within each
	// position adds finer-grained intensity gradation.
	const (
		lowCutoff = 33 // <33% of max stays at the bottom (▄)
		midCutoff = 66 // 33-66% passes through the middle (█)
		// >66% sits at the top (▀)
	)
	colorStops := uint64(len(sparkColors))
	for i := 0; i < width; i++ {
		var v uint64
		if i < len(smoothed) {
			v = smoothed[i]
		}
		if v == 0 {
			// Quiet cell — render baseline glyph so the wave never
			// "drops out" mid-trace.
			b.WriteString(style(sparkColors[0]).Render(sparkGlyphLow))
			continue
		}
		// Vertical position based on relative magnitude (0..100%).
		pct := (v * 100) / maxVal
		var glyph string
		switch {
		case pct < lowCutoff:
			glyph = sparkGlyphLow
		case pct < midCutoff:
			glyph = sparkGlyphMid
		default:
			glyph = sparkGlyphHigh
		}
		// Color brightness based on the same relative magnitude.
		colorIdx := (v*colorStops - 1) / maxVal
		if colorIdx >= colorStops {
			colorIdx = colorStops - 1
		}
		b.WriteString(style(sparkColors[colorIdx]).Render(glyph))
	}
	return b.String()
}

// bouncePos returns the head position for a given frame number,
// ping-ponging between 0 and width-1. Used by BouncingBar to drive
// the Knight-Rider/Cylon scanner motion.
func bouncePos(frame, width int) int {
	period := 2 * (width - 1)
	if period <= 0 {
		return 0
	}
	p := frame % period
	if p < 0 {
		p += period
	}
	if p < width {
		return p
	}
	return period - p
}

// bounceFrameInterval is how often the bouncing-bar head advances by
// one cell. Independent of the data sampling rate — animation is a
// pure time function so it stays smooth even when no new samples are
// arriving.
const bounceFrameInterval = 80 * time.Millisecond

// BouncingBar renders a Knight-Rider / Cylon-style scanner: a single
// "head" cell glides back and forth across the column, leaving a
// 3-cell fading trail behind it in the direction of motion. The
// background of the column shows the dim baseline (`▄` in baseline
// tint), the head is the brightest, the trail fades from bright →
// mid → dim.
//
// Inputs:
//   - intensity (0..4): activity level — 0 = idle (head/trail use
//     dim colors so the row reads as quiet), 4 = peak (head is at
//     brightest stop, trail fades down through the brighter palette).
//   - phaseOffset: per-row phase offset so different rows aren't
//     synchronized into one big stripe. Pass the PID (or any stable
//     int unique to the row) — the function takes it modulo the
//     bounce period.
//   - width: total column width in cells.
//   - bg: optional background color for selection-highlight cells.
//
// The frame number is derived from time.Now() / bounceFrameInterval
// so callers don't need to thread a frame counter through — the
// motion happens purely as a function of wall-clock time, and the
// caller just needs to re-render at >= 25 fps for the motion to
// appear smooth.
func BouncingBar(intensity int, phaseOffset, width int, bg lipgloss.Color) string {
	if width <= 0 {
		return ""
	}
	if intensity < 0 {
		intensity = 0
	}
	if intensity > 4 {
		intensity = 4
	}
	style := func(fg lipgloss.Color) lipgloss.Style {
		s := lipgloss.NewStyle().Foreground(fg)
		if bg != "" {
			s = s.Background(bg)
		}
		return s
	}
	// Brightness palette: dim teal → bright teal. Use the same
	// sparkColors gradient as the rest of the dashboard so the bar
	// matches the visual language. Index 0 = baseline (faint).
	colorAt := func(level int) lipgloss.Color {
		if level < 0 {
			level = 0
		}
		if level >= len(sparkColors) {
			level = len(sparkColors) - 1
		}
		c := sparkColors[level]
		// Promote the dim baseline to a brighter stop when a bg is
		// set, so it reads against the selection background.
		if bg != "" && c == sparkColors[0] {
			c = sparkColors[2]
		}
		return c
	}
	baselineColor := colorAt(0)
	headColor := colorAt(1 + intensity) // 1..5 in the sparkColors palette

	frame := int(time.Now().UnixMilli()/int64(bounceFrameInterval/time.Millisecond)) + phaseOffset
	pos := bouncePos(frame, width)
	prev := bouncePos(frame-1, width)
	dir := 1
	if prev > pos {
		dir = -1
	}

	var b strings.Builder
	b.Grow(width * 16)
	for i := 0; i < width; i++ {
		var glyph string
		var color lipgloss.Color
		switch {
		case i == pos:
			glyph = "█"
			color = headColor
		case i == pos-dir:
			glyph = "▆"
			color = colorAt(intensity)
		case i == pos-2*dir:
			glyph = "▄"
			color = colorAt(intensity - 1)
		default:
			glyph = "▄"
			color = baselineColor
		}
		b.WriteString(style(color).Render(glyph))
	}
	return b.String()
}

// ProgressBar renders a fixed-width left-to-right filled gauge of
// the form `[██████░░░░░░]` showing the CURRENT (last-sample) rate
// as a fraction of the recent peak observed across the supplied
// series. Width includes the surrounding brackets — pass the same
// width you'd pass to Sparkline. An optional bg color is baked into
// each cell so the selection highlight reads correctly when this is
// rendered inside a selected row (per-cell ANSI resets in lipgloss
// would otherwise wipe the outer background).
//
// Empty/all-zero series render as a fully-empty bracketed bar
// (`[░░░░░░░░░░░░]`) rather than blank space — the column always
// shows that the row exists, just at zero intensity.
func ProgressBar(values []uint64, width int, bg lipgloss.Color) string {
	if width < 3 {
		return strings.Repeat(" ", width)
	}
	style := func(fg lipgloss.Color) lipgloss.Style {
		s := lipgloss.NewStyle().Foreground(fg)
		if bg != "" {
			s = s.Background(bg)
		}
		return s
	}
	// Baseline color resolves like SparklineWithBg: when bg is set,
	// promote to a brighter stop so empty-bar `░` cells are visible
	// against the selection background instead of blending into it.
	baseColor := sparkColors[0]
	if bg != "" {
		baseColor = sparkColors[2]
	}
	bracketStyle := style(baseColor)

	inner := width - 2
	// Square blocks: ■ for filled, □ for empty (matches ML dashboard)
	emptyBar := bracketStyle.Render("[") +
		style(baseColor).Render(strings.Repeat("□", inner)) +
		bracketStyle.Render("]")

	if len(values) == 0 {
		return emptyBar
	}
	current := values[len(values)-1]
	var maxV uint64
	for _, v := range values {
		if v > maxV {
			maxV = v
		}
	}
	if maxV == 0 {
		return emptyBar
	}

	fill := int((current * uint64(inner)) / maxV)
	if fill > inner {
		fill = inner
	}

	// Pick a color stop based on the current sample's relative
	// magnitude: dim when traffic is light, bright when traffic
	// is at recent peak. Both filled and empty halves use the same
	// color so the bar reads as one coherent block — only the glyph
	// (█ vs ░) distinguishes filled from empty.
	stops := uint64(len(sparkColors))
	idx := uint64(0)
	if current > 0 {
		idx = (current*stops - 1) / maxV
		if idx >= stops {
			idx = stops - 1
		}
	}
	fillColor := sparkColors[idx]
	if bg != "" && fillColor == sparkColors[0] {
		fillColor = baseColor
	}
	filledStyle := style(fillColor)

	// Square blocks: ■ for filled, □ for empty (matches ML dashboard)
	return bracketStyle.Render("[") +
		filledStyle.Render(strings.Repeat("■", fill)) +
		filledStyle.Render(strings.Repeat("□", inner-fill)) +
		bracketStyle.Render("]")
}

// emaPersist runs a one-sided exponential moving average over the
// series so a one-tick burst's influence persists into subsequent
// ticks instead of vanishing on the next sample. alpha is the weight
// of the current sample (0..1); the rest carries forward from the
// running EMA. With alpha=0.55, a single peak decays to ~0.45 of its
// height one tick later, ~0.20 two ticks later — visually that's
// the smooth tail-off the ECG-monitor look needs.
func emaPersist(values []uint64, alpha float64) []uint64 {
	if alpha <= 0 || alpha >= 1 || len(values) == 0 {
		out := make([]uint64, len(values))
		copy(out, values)
		return out
	}
	out := make([]uint64, len(values))
	ema := float64(values[0])
	out[0] = values[0]
	for i := 1; i < len(values); i++ {
		ema = alpha*float64(values[i]) + (1-alpha)*ema
		out[i] = uint64(ema)
	}
	return out
}

// bucketize compresses a value series into exactly `width` buckets by
// mean-pooling — each output bucket holds the mean of the input values
// that fall within its range. Mean-pool gives smoother wave transitions
// than max-pool; a brief burst still raises the bucket but doesn't
// dominate it as a sharp rectangular spike.
func bucketize(values []uint64, width int) []uint64 {
	if len(values) <= width {
		// Stretch by repeating each value so visual position roughly
		// tracks time. Caller pads remaining slots with spaces.
		if len(values) == width {
			out := make([]uint64, width)
			copy(out, values)
			return out
		}
		out := make([]uint64, width)
		for i := 0; i < width; i++ {
			srcIdx := (i * len(values)) / width
			if srcIdx >= len(values) {
				srcIdx = len(values) - 1
			}
			out[i] = values[srcIdx]
		}
		return out
	}
	sums := make([]uint64, width)
	counts := make([]uint64, width)
	for i, v := range values {
		bucket := (i * width) / len(values)
		if bucket >= width {
			bucket = width - 1
		}
		sums[bucket] += v
		counts[bucket]++
	}
	out := make([]uint64, width)
	for i := range out {
		if counts[i] > 0 {
			out[i] = sums[i] / counts[i]
		}
	}
	return out
}

// smooth3 applies a width-5 rolling-average over the bucketed values
// (the function name is historic — kept to avoid renaming all callers).
// Edges clamp the kernel to the available cells so the first/last
// buckets don't artificially attenuate. A wider kernel turns the
// raw bursty per-refresh samples (250ms) into a fluid wave: a peak
// in any one sample influences four neighbors, so adjacent cells
// glide into and out of the peak instead of stepping into it.
func smooth3(in []uint64) []uint64 {
	if len(in) < 2 {
		out := make([]uint64, len(in))
		copy(out, in)
		return out
	}
	out := make([]uint64, len(in))
	for i := range in {
		var sum, count uint64
		for k := -2; k <= 2; k++ {
			j := i + k
			if j < 0 || j >= len(in) {
				continue
			}
			sum += in[j]
			count++
		}
		if count > 0 {
			out[i] = sum / count
		}
	}
	return out
}

// HourHeatmap renders a 24-cell heatmap row of packet density per hour
// using the same glyph palette as Sparkline. Output format:
//
//	" 00 ▁▁▁▃▇█▇▃▁▁▁▁▁▃▇▇▃▁▁▁▁▁▁▁ 23"
//
// Hour labels frame the row so the analyst can see at a glance which
// time-of-day the activity clusters in. Caller should suppress this
// section for short pcaps (< ~4 hours) where every cell either lights
// up or stays empty regardless of attacker behavior.
func HourHeatmap(hourCounts [24]uint64) string {
	var maxVal uint64
	for _, v := range hourCounts {
		if v > maxVal {
			maxVal = v
		}
	}
	var b strings.Builder
	b.WriteString(" 00 ")
	if maxVal == 0 {
		b.WriteString(strings.Repeat(" ", 24))
	} else {
		peakStop := uint64(len(sparkColors))
		for _, v := range hourCounts {
			if v == 0 {
				b.WriteByte(' ')
				continue
			}
			idx := (v*peakStop - 1) / maxVal
			if idx >= peakStop {
				idx = peakStop - 1
			}
			b.WriteString(lipgloss.NewStyle().Foreground(sparkColors[idx]).Render(sparkGlyphLow))
		}
	}
	b.WriteString(" 23")
	return b.String()
}
