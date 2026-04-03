package render

import (
	"fmt"
	"time"

	"proxywatch/internal/keystore"
	"proxywatch/internal/shared"
	"proxywatch/internal/ui/common"
)

func DrawKeystore(app *shared.AppState) {
	s := app.Screen
	common.ClearScreen(s)
	cursorVisible := false
	cursorX, cursorY := 0, 0

	w, h := s.Size()
	common.DrawPanel(s, 0, 0, w, 4, "Keystore", "proxywatch")
	common.PutStringStyle(s, 2, 1, "? help", common.StyleDim)
	utcLabel := "UTC: "
	utcValue := time.Now().UTC().Format(common.UTCTimeFormat)
	stateLabel := "State: "
	stateValue := "locked"
	if app.KeystoreUnlocked {
		stateValue = "unlocked"
	}
	blockWidth := max(len(utcLabel)+len(utcValue), len(stateLabel)+len(stateValue))
	blockX := max(2, w-2-blockWidth)
	common.PutStringStyle(s, blockX, 1, utcLabel, common.StyleCyanB)
	common.PutStringStyle(s, blockX+len(utcLabel), 1, utcValue, common.StyleTextB)
	common.PutStringStyle(s, blockX, 2, stateLabel, common.StyleCyanB)
	common.PutStringStyle(s, blockX+len(stateLabel), 2, stateValue, common.StyleTextB)

	allRows := map[int]struct{ label, value string }{
		keystoreFieldOpenAIKey:          {"OpenAI key", keystore.MaskValue("OPENAI_API_KEY", app.KeystoreValues["OPENAI_API_KEY"])},
		keystoreFieldOpenAIBaseURL:      {"OpenAI base URL", keystore.MaskValue("OPENAI_BASE_URL", app.KeystoreValues["OPENAI_BASE_URL"])},
		keystoreFieldAnthropicKey:       {"Anthropic key", keystore.MaskValue("ANTHROPIC_API_KEY", app.KeystoreValues["ANTHROPIC_API_KEY"])},
		keystoreFieldAnthropicBaseURL:   {"Anthropic base URL", keystore.MaskValue("ANTHROPIC_BASE_URL", app.KeystoreValues["ANTHROPIC_BASE_URL"])},
		keystoreFieldLocalLLMURL:        {"Local LLM URL", keystore.MaskValue("LOCAL_LLM_URL", app.KeystoreValues["LOCAL_LLM_URL"])},
		keystoreFieldLocalLLMAPIKey:     {"Local LLM key", keystore.MaskValue("LOCAL_LLM_API_KEY", app.KeystoreValues["LOCAL_LLM_API_KEY"])},
		keystoreFieldCalibrationTimeout: {"Calibration timeout", keystore.MaskValue("CALIBRATION_HTTP_TIMEOUT", app.KeystoreValues["CALIBRATION_HTTP_TIMEOUT"])},
		keystoreFieldProxyhoundURL:      {"PH URL", keystore.MaskValue("BLOODHOUND_API_URL", app.KeystoreValues["BLOODHOUND_API_URL"])},
		keystoreFieldProxyhoundToken:    {"PH token", keystore.MaskValue("BLOODHOUND_API_TOKEN", app.KeystoreValues["BLOODHOUND_API_TOKEN"])},
		keystoreFieldProxyhoundTokenID:  {"PH token ID", keystore.MaskValue("BLOODHOUND_API_TOKEN_ID", app.KeystoreValues["BLOODHOUND_API_TOKEN_ID"])},
		keystoreFieldTLSDir:             {"TLS dir", keystore.MaskValue("PROXYWATCH_TLS_DIR", app.KeystoreValues["PROXYWATCH_TLS_DIR"])},
		keystoreFieldAgentToken:         {"Agent token", keystore.MaskValue("PROXYWATCH_AGENT_TOKEN", app.KeystoreValues["PROXYWATCH_AGENT_TOKEN"])},
		keystoreFieldDisableClientCert:  {"Disable client cert", keystore.MaskValue("PROXYWATCH_DISABLE_CLIENT_CERT", app.KeystoreValues["PROXYWATCH_DISABLE_CLIENT_CERT"])},
		keystoreFieldTrustOnFirstUse:    {"Trust on first use", keystore.MaskValue("PROXYWATCH_TRUST_ON_FIRST_USE", app.KeystoreValues["PROXYWATCH_TRUST_ON_FIRST_USE"])},
		keystoreFieldGitHubToken:        {"GitHub token", keystore.MaskValue("GITHUB_TOKEN", app.KeystoreValues["GITHUB_TOKEN"])},
		keystoreFieldLoad:               {"Load", "Load encrypted keystore"},
		keystoreFieldSave:               {"Save", "Save encrypted keystore"},
		keystoreFieldApply:              {"Apply", "Apply values to runtime"},
	}

	type ksRow struct {
		field int
		label string
		value string
	}
	rows := make([]ksRow, 0, 16)
	fieldOrder := []int{
		keystoreFieldOpenAIKey, keystoreFieldOpenAIBaseURL,
		keystoreFieldAnthropicKey, keystoreFieldAnthropicBaseURL,
		keystoreFieldLocalLLMURL, keystoreFieldLocalLLMAPIKey,
		keystoreFieldCalibrationTimeout,
		keystoreFieldProxyhoundURL, keystoreFieldProxyhoundToken, keystoreFieldProxyhoundTokenID,
		keystoreFieldTLSDir, keystoreFieldAgentToken,
		keystoreFieldDisableClientCert, keystoreFieldTrustOnFirstUse,
		keystoreFieldGitHubToken,
		keystoreFieldLoad, keystoreFieldSave, keystoreFieldApply,
	}
	for _, f := range fieldOrder {
		if !keystoreFieldVisible(f) {
			continue
		}
		r := allRows[f]
		rows = append(rows, ksRow{field: f, label: r.label, value: r.value})
	}

	setupY := 4
	setupH := len(rows) + 4
	if setupY+setupH >= h {
		setupH = max(10, h-setupY-1)
	}
	if setupY+setupH > h {
		setupH = max(3, h-setupY)
	}
	common.DrawPanel(s, 0, setupY, w, setupH, "KEYSTORE", "")
	fileLabel := fmt.Sprintf(" %-20s", "File:")
	fileLabel = common.TruncateToWidth(fileLabel, w-4)
	common.PutStringStyle(s, 2, setupY+1, fileLabel, common.StyleMuted)
	fileValueX := 2 + len(fileLabel) + 2
	if fileValueX < w-2 {
		common.PutStringStyle(s, fileValueX, setupY+1, common.TruncateToWidth(keystore.NormalizePath(app.KeystorePath), w-fileValueX-2), common.StyleText)
	}
	keyLabel := fmt.Sprintf(" %-20s", "Key:")
	keyLabel = common.TruncateToWidth(keyLabel, w-4)
	common.PutStringStyle(s, 2, setupY+2, keyLabel, common.StyleMuted)
	keyValueX := 2 + len(keyLabel) + 2
	if keyValueX < w-2 {
		common.PutStringStyle(s, keyValueX, setupY+2, common.TruncateToWidth(keystore.KeyPath(app.KeystorePath), w-keyValueX-2), common.StyleText)
	}
	maxVisibleRows := max(0, setupH-4)
	selectedDisplayIdx := 0
	for i, row := range rows {
		if row.field == app.KeystoreField {
			selectedDisplayIdx = i
			break
		}
	}
	rowStart := 0
	if maxVisibleRows > 0 && len(rows) > maxVisibleRows {
		rowStart = selectedDisplayIdx - maxVisibleRows + 1
		if rowStart < 0 {
			rowStart = 0
		}
		maxStart := len(rows) - maxVisibleRows
		if rowStart > maxStart {
			rowStart = maxStart
		}
	}
	for i := rowStart; i < len(rows) && i < rowStart+maxVisibleRows; i++ {
		row := rows[i]
		y := setupY + 3 + (i - rowStart)
		rowSelected := row.field == app.KeystoreField
		prefix := " "
		labelStyle := common.StyleMuted
		valueStyle := common.StyleText
		prefixStyle := common.StyleText
		if rowSelected {
			prefix = ">"
			valueStyle = common.StyleTextB
			prefixStyle = common.StyleTextB
		}
		value := row.value
		common.FillSelectedRowBar(s, y, 2, w-3, rowSelected)
		labelText := fmt.Sprintf("%s %-15s", prefix, row.label+":")
		labelText = common.TruncateToWidth(labelText, w-4)
		common.PutStringStyle(s, 2, y, labelText, common.ApplySelectedRowStyle(labelStyle, rowSelected))
		valueX := 2 + len(labelText) + 2
		if valueX < w-2 {
			valueW := max(0, w-valueX-2)
			common.PutStringStyle(s, valueX, y, common.TruncateToWidth(value, valueW), common.ApplySelectedRowStyle(valueStyle, rowSelected))
			if rowSelected && app.KeystoreEditing && !app.KeystoreShowHelp {
				if _, editable := keystoreFieldEnvKey(row.field); editable {
					cursorVisible = true
					cursorX = common.TextCursorX(valueX, value, valueW)
					cursorY = y
				}
			}
		}
		common.PutStringStyle(s, 2, y, string(prefix), common.ApplySelectedRowStyle(prefixStyle, rowSelected))
		_, keystoreEditable := keystoreFieldEnvKey(row.field)
		common.DrawEditingTag(s, y, w, rowSelected && app.KeystoreEditing && keystoreEditable)
	}

	notesY := setupY + setupH
	notesH := max(4, h-notesY)
	if notesY+notesH > h {
		notesH = h - notesY
	}
	if notesH >= 3 {
		common.DrawPanel(s, 0, notesY, w, notesH, "", "Keystore")
		noteRow := notesY + 1
		notes := []string{
			"Values are encrypted on disk with AES-GCM using a machine key.",
			"Load reads the encrypted keystore. Save writes it. Apply pushes values to runtime.",
			"Keys are used by Calibration (AI providers), SIEM, ProxyHound, and agent transport.",
		}
		for _, note := range notes {
			if noteRow >= notesY+notesH-1 {
				break
			}
			common.PutStringStyle(s, 2, noteRow, common.TruncateToWidth(note, w-4), common.StyleMuted)
			noteRow++
		}
	}

	now := time.Now()
	if app.KeystoreStatusText != "" && now.Before(app.KeystoreStatusUntil) && h >= 2 {
		st := common.StyleText
		if app.KeystoreStatusError {
			st = common.StyleAlert
		}
		common.PutStringStyle(s, 2, h-2, common.TruncateToWidth(app.KeystoreStatusText, w-4), st)
	}
	if cursorVisible {
		common.ShowInputCursor(s, cursorX, cursorY)
	}

	drawKeystoreOverlays(app, w, h)
}

func drawKeystoreOverlays(app *shared.AppState, w, h int) {
	if !app.KeystoreShowHelp {
		return
	}
	opts := common.KeystoreMenuHelpOptions()
	common.DrawMenuPanel(app.Screen, w, h, "Keystore Menu", opts, common.ClampIndex(app.KeystoreHelpIndex, len(opts)), "")
}
