package views

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/gdamore/tcell/v2"

	"proxywatch/internal/shared"
)

// LegacyModel wraps the existing tcell-based views so they render inside
// bubbletea. It uses a VirtualScreen as a fake tcell.Screen, calls the
// original Draw functions, then converts the cell grid to an ANSI string.

type LegacyModel struct {
	app     *shared.AppState
	vscreen *VirtualScreen
	width   int
	height  int
}

func NewLegacyModel(app *shared.AppState) LegacyModel {
	vs := NewVirtualScreen(80, 24)
	return LegacyModel{app: app, vscreen: vs, width: 80, height: 24}
}

func (m LegacyModel) Init() tea.Cmd { return nil }

func (m LegacyModel) Update(msg tea.Msg) (LegacyModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		tev := convertKeyMsg(msg)
		handled, shouldQuit := handleQuitConfirmKey(m.app, tev)
		if handled {
			if shouldQuit {
				return m, tea.Quit
			}
			return m, nil
		}
		if handleKeyEvent(m.app, tev) {
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.vscreen.ResizeTo(m.width, m.height)
	}
	return m, nil
}

func (m LegacyModel) View() string {
	if m.width <= 0 || m.height <= 0 {
		return ""
	}
	m.vscreen.ResizeTo(m.width, m.height)
	m.vscreen.Clear()
	prev := m.app.Screen
	m.app.Screen = m.vscreen
	drawCurrentMode(m.app)
	drawQuitConfirmOverlay(m.app)
	m.app.Screen = prev
	return m.vscreen.Render()
}

// ── Virtual Screen ──────────────────────────────────────────────────────────

type VirtualScreen struct {
	width, height int
	cells         []vcell
	defaultStyle  tcell.Style
	cursorX       int
	cursorY       int
	cursorVisible bool
}

type vcell struct {
	ch    rune
	style tcell.Style
}

func NewVirtualScreen(w, h int) *VirtualScreen {
	if w <= 0 {
		w = 80
	}
	if h <= 0 {
		h = 24
	}
	vs := &VirtualScreen{width: w, height: h, cells: make([]vcell, w*h)}
	vs.Clear()
	return vs
}

func (vs *VirtualScreen) ResizeTo(w, h int) {
	if w <= 0 || h <= 0 || (w == vs.width && h == vs.height) {
		return
	}
	vs.width = w
	vs.height = h
	vs.cells = make([]vcell, w*h)
	vs.fill(' ', vs.defaultStyle)
}

func (vs *VirtualScreen) fill(ch rune, st tcell.Style) {
	for i := range vs.cells {
		vs.cells[i] = vcell{ch: ch, style: st}
	}
}

// tcell.Screen interface stubs.
func (vs *VirtualScreen) Init() error                                          { return nil }
func (vs *VirtualScreen) Fini()                                                {}
func (vs *VirtualScreen) Show()                                                {}
func (vs *VirtualScreen) Sync()                                                {}
func (vs *VirtualScreen) CharacterSet() string                                 { return "UTF-8" }
func (vs *VirtualScreen) CanDisplay(rune, bool) bool                           { return true }
func (vs *VirtualScreen) HasMouse() bool                                       { return false }
func (vs *VirtualScreen) EnableMouse(...tcell.MouseFlags)                      {}
func (vs *VirtualScreen) DisableMouse()                                        {}
func (vs *VirtualScreen) EnablePaste()                                         {}
func (vs *VirtualScreen) DisablePaste()                                        {}
func (vs *VirtualScreen) HasKey(tcell.Key) bool                                { return true }
func (vs *VirtualScreen) Beep() error                                          { return nil }
func (vs *VirtualScreen) SetSize(int, int)                                     {}
func (vs *VirtualScreen) EnableFocus()                                         {}
func (vs *VirtualScreen) DisableFocus()                                        {}
func (vs *VirtualScreen) Suspend() error                                       { return nil }
func (vs *VirtualScreen) Resume() error                                        { return nil }
func (vs *VirtualScreen) Colors() int                                          { return 1 << 24 }
func (vs *VirtualScreen) RegisterRuneFallback(rune, string)                    {}
func (vs *VirtualScreen) UnregisterRuneFallback(rune)                          {}
func (vs *VirtualScreen) SetTitle(string)                                      {}
func (vs *VirtualScreen) SetClipboard([]byte)                                  {}
func (vs *VirtualScreen) GetClipboard()                                        {}
func (vs *VirtualScreen) SetCursorStyle(tcell.CursorStyle, ...tcell.Color)     {}
func (vs *VirtualScreen) SetCursor(tcell.CursorStyle, tcell.Color)             {}
func (vs *VirtualScreen) LockRegion(int, int, int, int, bool)                  {}
func (vs *VirtualScreen) Tty() (tcell.Tty, bool)                               { return nil, false }
func (vs *VirtualScreen) GetCells() *tcell.CellBuffer                          { return nil }
func (vs *VirtualScreen) EventQ() chan tcell.Event                             { return nil }
func (vs *VirtualScreen) StopQ() <-chan struct{}                               { return nil }
func (vs *VirtualScreen) Resize(int, int, int, int)                            {}
func (vs *VirtualScreen) PutStr(int, int, string)                              {}
func (vs *VirtualScreen) PutStrStyled(int, int, string, tcell.Style)           {}
func (vs *VirtualScreen) Put(x, y int, s string, st tcell.Style) (string, int) { return "", 0 }

func (vs *VirtualScreen) Size() (int, int) { return vs.width, vs.height }

func (vs *VirtualScreen) PollEvent() tcell.Event { select {} }

func (vs *VirtualScreen) HasPendingEvent() bool                                     { return false }
func (vs *VirtualScreen) PostEvent(ev tcell.Event) error                            { return nil }
func (vs *VirtualScreen) PostEventWait(ev tcell.Event)                              {}
func (vs *VirtualScreen) ChannelEvents(ch chan<- tcell.Event, quit <-chan struct{}) {}

func (vs *VirtualScreen) Clear() {
	vs.fill(' ', vs.defaultStyle)
	vs.cursorVisible = false
}

func (vs *VirtualScreen) Fill(ch rune, style tcell.Style) { vs.fill(ch, style) }
func (vs *VirtualScreen) SetStyle(style tcell.Style)      { vs.defaultStyle = style }

func (vs *VirtualScreen) SetContent(x, y int, primary rune, combining []rune, style tcell.Style) {
	if x < 0 || x >= vs.width || y < 0 || y >= vs.height {
		return
	}
	vs.cells[y*vs.width+x] = vcell{ch: primary, style: style}
}

func (vs *VirtualScreen) Get(x, y int) (string, tcell.Style, int) {
	if x < 0 || x >= vs.width || y < 0 || y >= vs.height {
		return " ", vs.defaultStyle, 1
	}
	c := vs.cells[y*vs.width+x]
	ch := c.ch
	if ch == 0 {
		ch = ' '
	}
	return string(ch), c.style, 1
}

func (vs *VirtualScreen) GetContent(x, y int) (rune, []rune, tcell.Style, int) {
	if x < 0 || x >= vs.width || y < 0 || y >= vs.height {
		return ' ', nil, vs.defaultStyle, 1
	}
	c := vs.cells[y*vs.width+x]
	return c.ch, nil, c.style, 1
}

func (vs *VirtualScreen) SetCell(x, y int, style tcell.Style, ch ...rune) {
	if len(ch) > 0 {
		vs.SetContent(x, y, ch[0], ch[1:], style)
	}
}

func (vs *VirtualScreen) ShowCursor(x, y int) {
	vs.cursorX = x
	vs.cursorY = y
	vs.cursorVisible = true
}

func (vs *VirtualScreen) HideCursor() { vs.cursorVisible = false }

func (vs *VirtualScreen) Render() string {
	var sb strings.Builder
	sb.Grow(vs.width * vs.height * 4)

	var prevFg, prevBg [3]int32
	prevFg = [3]int32{-1, -1, -1}
	prevBg = [3]int32{-1, -1, -1}
	prevBold := false
	ansiActive := false

	for y := 0; y < vs.height; y++ {
		if y > 0 {
			if ansiActive {
				sb.WriteString("\x1b[0m")
				ansiActive = false
				prevFg = [3]int32{-1, -1, -1}
				prevBg = [3]int32{-1, -1, -1}
				prevBold = false
			}
			sb.WriteByte('\n')
		}
		for x := 0; x < vs.width; x++ {
			c := vs.cells[y*vs.width+x]
			fg, bg, attr := c.style.Decompose()
			bold := attr&tcell.AttrBold != 0

			fgR, fgG, fgB := fg.RGB()
			bgR, bgG, bgB := bg.RGB()
			curFg := [3]int32{fgR, fgG, fgB}
			curBg := [3]int32{bgR, bgG, bgB}

			if bold != prevBold && !bold {
				sb.WriteString("\x1b[0m")
				ansiActive = false
				prevFg = [3]int32{-1, -1, -1}
				prevBg = [3]int32{-1, -1, -1}
				prevBold = false
			}

			var parts []string
			if bold && !prevBold {
				parts = append(parts, "1")
			}
			if curFg != prevFg {
				parts = append(parts, fmt.Sprintf("38;2;%d;%d;%d", fgR, fgG, fgB))
			}
			if curBg != prevBg && !(bgR == 0 && bgG == 0 && bgB == 0) {
				parts = append(parts, fmt.Sprintf("48;2;%d;%d;%d", bgR, bgG, bgB))
			}
			if len(parts) > 0 {
				sb.WriteString("\x1b[")
				sb.WriteString(strings.Join(parts, ";"))
				sb.WriteByte('m')
				ansiActive = true
			}

			prevFg = curFg
			prevBg = curBg
			prevBold = bold

			ch := c.ch
			if ch == 0 {
				ch = ' '
			}
			sb.WriteRune(ch)
		}
	}
	if ansiActive {
		sb.WriteString("\x1b[0m")
	}
	return sb.String()
}
