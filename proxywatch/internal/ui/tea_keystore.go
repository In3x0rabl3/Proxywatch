package ui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/gdamore/tcell/v2"

	"proxywatch/internal/keystore"
	"proxywatch/internal/shared"
)

const (
	keystorePanelSetup  = 0
	keystorePanelList   = 1
	keystorePanelFields = 2
)

type KeystoreModel struct {
	app    *shared.AppState
	width  int
	height int
}

func NewKeystoreModel(app *shared.AppState) KeystoreModel {
	return KeystoreModel{app: app}
}

func (m KeystoreModel) Init() tea.Cmd { return nil }

func (m KeystoreModel) Update(msg tea.Msg) (KeystoreModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		// Handle paste: when editing, append all runes from a paste event.
		if m.app.KeystoreEditing && msg.Type == tea.KeyRunes && len(msg.Runes) > 1 {
			key, ok := keystoreFieldEnvKey(m.app.KeystoreField)
			if ok {
				ensureKeystoreValues(m.app)
				for _, r := range msg.Runes {
					if r >= 32 && r <= 126 {
						m.app.KeystoreValues[key] += string(r)
					}
				}
				// Auto-apply to runtime so other dashboards see the value.
				keystore.ApplyToRuntime(m.app.KeystoreValues)
			}
			return m, nil
		}

		tev := convertKeyMsg(msg)

		handled, shouldQuit := handleQuitConfirmKey(m.app, tev)
		if handled {
			if shouldQuit {
				return m, tea.Quit
			}
			return m, nil
		}

		if m.app.KeystoreEditing {
			switch tev.Key() {
			case tcell.KeyLeft, tcell.KeyRight:
				return m, nil
			}
		} else {
			switch tev.Key() {
			case tcell.KeyLeft:
				if stepWorkflowMenu(m.app, -1) {
					return m, nil
				}
			case tcell.KeyRight:
				if stepWorkflowMenu(m.app, 1) {
					return m, nil
				}
			}
		}

		if handleKeystoreKey(m.app, tev) {
			return m, tea.Quit
		}
	}

	return m, nil
}

func (m KeystoreModel) View() string {
	w := m.width
	h := m.height
	if w <= 0 || h <= 0 {
		return ""
	}

	// Refresh keystore list.
	m.refreshKeystoreList()

	var sections []string
	sections = append(sections, m.renderHeader())
	sections = append(sections, m.renderSecurity())
	if m.app.KeystoreUnlocked && m.app.KeystoreActiveEntry != "" {
		sections = append(sections, m.renderFields())
	}
	sections = append(sections, m.renderSetup())
	sections = append(sections, m.renderKeystoreList())

	view := lipgloss.JoinVertical(lipgloss.Left, sections...)

	if m.app.KeystoreWizardOpen {
		view = overlayCenter(view, m.renderWizard(), w, h)
	} else if m.app.KeystoreShowHelp {
		view = overlayCenter(view, renderHelpPanel("Keystore Menu", keystoreMenuHelpOptions(), w), w, h)
	}
	if m.app.ShowQuitConfirm && m.app.QuitConfirmDeadline.After(time.Now()) {
		view += "\n" + renderQuitConfirm(m.app.QuitConfirmDeadline, w)
	}
	return view
}

func (m KeystoreModel) refreshKeystoreList() {
	entries := keystore.ListKeystores()
	names := make([]string, len(entries))
	for i, e := range entries {
		label := e.Name
		if e.Secure {
			label += " [secure]"
		}
		names[i] = label
	}
	m.app.KeystoreEntries = names
}

// ── Header ───────────────────────────────────────────────────────────────────

func (m KeystoreModel) renderHeader() string {
	w := m.width
	if w <= 0 {
		w = 80
	}
	contentW := w - 2
	helpPlain := "? help"
	utcPlain := "UTC: " + time.Now().UTC().Format(utcTimeFormat)
	gap := max(1, contentW-len(helpPlain)-len(utcPlain))
	line := dimText.Render(helpPlain) + bgSp(gap) +
		rightLabelStyle.Render("UTC: ") + sectionLabel.Render(time.Now().UTC().Format(utcTimeFormat))
	return renderPanel(w, 3, "Keystore", "proxywatch", "", line)
}

// ── Security panel ───────────────────────────────────────────────────────────

func (m KeystoreModel) renderSecurity() string {
	w := m.width
	if w <= 0 {
		w = 80
	}

	hwAvail, hwDetail := keystore.HardwareKeyAvailable()
	slots := keystore.DetectKeySlotsCached()

	var badges []string
	if hwAvail {
		activeCount := 0
		for _, s := range slots {
			if s.InUse {
				activeCount++
			}
		}
		slotInfo := "no active slots"
		if activeCount == 1 {
			slotInfo = "1 slot active"
		} else if activeCount > 1 {
			slotInfo = fmt.Sprintf("%d slots active", activeCount)
		}
		badges = append(badges, statusPass.Render("✓ YubiKey")+bgSp(2)+dimText.Render("("+slotInfo+")"))
	} else {
		badges = append(badges, dimText.Render("✗ Hardware Key")+bgSp(2)+dimText.Render("("+hwDetail+")"))
	}

	// Lock state on right.
	lockLabel := "[LOCKED]"
	lockStyle := lipgloss.NewStyle().Foreground(colorAlert).Bold(true).Background(colorBg)
	if m.app.KeystoreUnlocked {
		lockLabel = "[UNLOCKED]"
		lockStyle = lipgloss.NewStyle().Foreground(colorCyan).Bold(true).Background(colorBg)
	}

	left := "  " + strings.Join(badges, "")
	right := lockStyle.Render(lockLabel)
	contentW := w - 2
	gap := max(1, contentW-lipgloss.Width(left)-len(lockLabel))

	line := left + bgSp(gap) + right
	return renderPanel(w, 3, "SECURITY", "", "", line)
}

// ── Setup panel (always visible) ─────────────────────────────────────────────

func (m KeystoreModel) renderSetup() string {
	w := m.width
	if w <= 0 {
		w = 80
	}

	rows := []FormRow{
		{Field: keystoreFieldLoad, Label: "Create", Value: "▶ New keystore (ENTER to select type)"},
	}
	return renderSetupPanel("SETUP", rows, m.app.KeystoreField, false, w)
}

func (m KeystoreModel) renderFields() string {
	w := m.width
	if w <= 0 {
		w = 80
	}

	vals := m.app.KeystoreValues
	if vals == nil {
		vals = map[string]string{}
	}

	type ksField struct {
		field int
		label string
		value string
	}

	allFields := []ksField{
		{keystoreFieldOpenAIKey, "OpenAI key   ", keystore.MaskValue("OPENAI_API_KEY", vals["OPENAI_API_KEY"])},
		{keystoreFieldOpenAIBaseURL, "OpenAI URL   ", keystore.MaskValue("OPENAI_BASE_URL", vals["OPENAI_BASE_URL"])},
		{keystoreFieldAnthropicKey, "Anthropic key", keystore.MaskValue("ANTHROPIC_API_KEY", vals["ANTHROPIC_API_KEY"])},
		{keystoreFieldAnthropicBaseURL, "Anthropic URL", keystore.MaskValue("ANTHROPIC_BASE_URL", vals["ANTHROPIC_BASE_URL"])},
		{keystoreFieldLocalLLMURL, "Local LLM URL", keystore.MaskValue("LOCAL_LLM_URL", vals["LOCAL_LLM_URL"])},
		{keystoreFieldLocalLLMAPIKey, "Local LLM key", keystore.MaskValue("LOCAL_LLM_API_KEY", vals["LOCAL_LLM_API_KEY"])},
		{keystoreFieldCalibrationTimeout, "Cal timeout  ", keystore.MaskValue("CALIBRATION_HTTP_TIMEOUT", vals["CALIBRATION_HTTP_TIMEOUT"])},
		{keystoreFieldBloodhoundURL, "BH URL       ", keystore.MaskValue("BLOODHOUND_API_URL", vals["BLOODHOUND_API_URL"])},
		{keystoreFieldBloodhoundToken, "BH token     ", keystore.MaskValue("BLOODHOUND_API_TOKEN", vals["BLOODHOUND_API_TOKEN"])},
		{keystoreFieldBloodhoundTokenID, "BH token ID  ", keystore.MaskValue("BLOODHOUND_API_TOKEN_ID", vals["BLOODHOUND_API_TOKEN_ID"])},
		{keystoreFieldTLSDir, "TLS dir      ", keystore.MaskValue("PROXYWATCH_TLS_DIR", vals["PROXYWATCH_TLS_DIR"])},
		{keystoreFieldAgentToken, "Agent token  ", keystore.MaskValue("PROXYWATCH_AGENT_TOKEN", vals["PROXYWATCH_AGENT_TOKEN"])},
		{keystoreFieldDisableClientCert, "No client crt", keystore.MaskValue("PROXYWATCH_DISABLE_CLIENT_CERT", vals["PROXYWATCH_DISABLE_CLIENT_CERT"])},
		{keystoreFieldTrustOnFirstUse, "Trust TOFU   ", keystore.MaskValue("PROXYWATCH_TRUST_ON_FIRST_USE", vals["PROXYWATCH_TRUST_ON_FIRST_USE"])},
		{keystoreFieldSave, "Save         ", "Save keystore"},
		{keystoreFieldApply, "Apply        ", "Apply to runtime"},
		{keystoreFieldLock, "Lock         ", "Lock (encrypt & clear)"},
	}

	var rows []FormRow
	for _, f := range allFields {
		if !keystoreFieldVisible(f.field) {
			continue
		}
		_, editable := keystoreFieldEnvKey(f.field)
		rows = append(rows, FormRow{
			Field:    f.field,
			Label:    f.label,
			Value:    f.value,
			Editable: editable,
		})
	}

	title := "FIELDS · " + m.app.KeystoreActiveEntry
	if m.app.KeystoreSecure {
		title = "FIELDS · " + m.app.KeystoreActiveEntry + " [secure]"
	}
	return renderSetupPanel(title, rows, m.app.KeystoreField, m.app.KeystoreEditing, w)
}

// ── Keystores list panel ─────────────────────────────────────────────────────

func (m KeystoreModel) renderKeystoreList() string {
	w := m.width
	if w <= 0 {
		w = 80
	}

	entries := keystore.ListKeystores()

	listH := m.height - 3 - 3 - m.setupHeight() - 1
	if m.app.KeystoreStatusText != "" && time.Now().Before(m.app.KeystoreStatusUntil) {
		listH--
	}
	if listH < 4 {
		listH = 4
	}
	counter := fmt.Sprintf("%d/%d", max(0, m.app.KeystoreSelected+1), len(entries))

	if len(entries) == 0 {
		body := bodyText.Render("  No keystores created yet.") + "\n" +
			dimText.Render("  Use Setup above to create one.")

		// Status.
		if m.app.KeystoreStatusText != "" && time.Now().Before(m.app.KeystoreStatusUntil) {
			st := bodyText
			if m.app.KeystoreStatusError {
				st = statusFail
			}
			body += "\n\n  " + st.Render(m.app.KeystoreStatusText)
		}
		return renderPanel(w, listH, "DISPLAY", counter, "", body)
	}

	// Clamp selection.
	if m.app.KeystoreSelected < 0 {
		m.app.KeystoreSelected = 0
	}
	if m.app.KeystoreSelected >= len(entries) {
		m.app.KeystoreSelected = len(entries) - 1
	}

	focused := m.app.KeystorePanel == 1

	var lines []string
	for i, entry := range entries {
		sel := focused && i == m.app.KeystoreSelected
		gap := applySelectBg(bg(), sel)

		encLabel := "plain"
		if entry.Secure {
			encLabel = "encrypted"
		}
		if entry.Name == m.app.KeystoreActiveEntry {
			encLabel += " (active)"
		}

		prefix := bg().Render(" ")
		if sel {
			prefix = lipgloss.NewStyle().Foreground(colorCyan).Bold(true).Background(colorSelect).Render(">")
		}

		encStyle := applySelectBg(dimText, sel)
		if entry.Name == m.app.KeystoreActiveEntry {
			encStyle = applySelectBg(statusPass, sel)
		}

		row := prefix + gap.Render(" ") +
			applySelectBg(bodyText, sel).Render(entry.Name) +
			gap.Render("  ") +
			encStyle.Render(encLabel) +
			gap.Render("  ") +
			applySelectBg(dimText, sel).Render(entry.CreatedAt)

		if sel {
			row = lgSelectBg.Width(w - 2).Render(row)
		}
		lines = append(lines, row)
	}

	body := strings.Join(lines, "\n")

	// Status.
	if m.app.KeystoreStatusText != "" && time.Now().Before(m.app.KeystoreStatusUntil) {
		st := bodyText
		if m.app.KeystoreStatusError {
			st = statusFail
		}
		body += "\n\n  " + st.Render(m.app.KeystoreStatusText)
	}

	titleLabel := "DISPLAY"
	return renderPanel(w, listH, titleLabel, counter, "", body)
}

func (m KeystoreModel) setupHeight() int {
	setupH := 3 // Setup panel always shown: 1 Create field + borders.
	if m.app.KeystoreUnlocked && m.app.KeystoreActiveEntry != "" {
		// Fields panel is also visible.
		count := 0
		for f := keystoreFieldOpenAIKey; f <= keystoreFieldMax; f++ {
			if keystoreFieldVisible(f) && f != keystoreFieldLoad {
				count++
			}
		}
		setupH += count + 2
	}
	return setupH
}

// ── Creation wizard ──────────────────────────────────────────────────────────

func (m KeystoreModel) renderWizard() string {
	w := m.width
	if w <= 0 {
		w = 80
	}

	wizW := min(60, w-10)
	if wizW < 30 {
		wizW = 30
	}

	sel := m.app.KeystoreWizardField
	editing := m.app.KeystoreWizardEditing

	selBgStyle := lipgloss.NewStyle().Background(colorSelect)
	curStyle := lipgloss.NewStyle().Foreground(colorCyan).Bold(true).Background(colorSelect)
	selLbl := lipgloss.NewStyle().Foreground(colorText).Bold(true).Background(colorSelect)
	selVal := lipgloss.NewStyle().Foreground(colorTextHi).Bold(true).Background(colorSelect)
	normLbl := lipgloss.NewStyle().Foreground(colorMuted).Background(colorBg)
	normVal := lipgloss.NewStyle().Foreground(colorText).Background(colorBg)

	contentW := wizW - 2

	renderRow := func(field int, label, value string) string {
		isSel := field == sel
		lbl := fmt.Sprintf("%-13s", label+":")
		if isSel {
			prefix := curStyle.Render("> ")
			if editing && field == 0 {
				// Show cursor on name field.
				cursor := lipgloss.NewStyle().Foreground(colorBg).Background(colorCyan).Render(" ")
				return selBgStyle.Width(contentW).Render(prefix + selLbl.Render(lbl) + selBgStyle.Render(" ") + selVal.Render(value) + cursor)
			}
			return selBgStyle.Width(contentW).Render(prefix + selLbl.Render(lbl) + selBgStyle.Render(" ") + selVal.Render(value))
		}
		return bg().Render("  ") + normLbl.Render(lbl) + bg().Render(" ") + normVal.Render(value)
	}

	// Name.
	nameVal := m.app.KeystoreWizardName
	if nameVal == "" {
		nameVal = "(auto-generated)"
	}

	// Encryption.
	encVal := "Standard (no encryption)"
	if m.app.KeystoreWizardSecure {
		encVal = "Hardware Key (YubiKey)"
	}

	// Slot — show selected active slot with ID and type.
	slotVal := ""
	if m.app.KeystoreWizardSecure {
		slots := keystore.DetectKeySlotsCached()
		// Only consider active (in-use) slots.
		var active []keystore.KeySlot
		for _, s := range slots {
			if s.InUse {
				active = append(active, s)
			}
		}
		// Find the currently selected slot.
		for _, s := range active {
			if s.ID == m.app.KeystoreWizardSlot {
				slotVal = fmt.Sprintf("Slot %s: Active / %s", s.ID, s.Type)
				break
			}
		}
		if slotVal == "" && len(active) > 0 {
			s := active[0]
			slotVal = fmt.Sprintf("Slot %s: Active / %s", s.ID, s.Type)
		}
		if slotVal == "" {
			slotVal = "(no active slots found)"
		}
		if len(active) > 1 {
			slotVal += " (ENTER to cycle)"
		}
	}

	var lines []string
	lines = append(lines, renderRow(0, "Name", nameVal))
	lines = append(lines, renderRow(1, "Encryption", encVal))
	if m.app.KeystoreWizardSecure {
		lines = append(lines, renderRow(2, "Slot", slotVal))
		lines = append(lines, renderRow(3, "Action", "▶ Create keystore"))
	} else {
		lines = append(lines, renderRow(2, "Action", "▶ Create keystore"))
	}
	lines = append(lines, "")
	lines = append(lines, dimText.Render("  ENTER edit/toggle/cycle   Esc cancel"))

	content := strings.Join(lines, "\n")
	h := len(lines) + 2
	return renderPanel(wizW, h, "NEW KEYSTORE", "", "", content)
}

// Ensure imports used.
var _ = tcell.KeyUp
