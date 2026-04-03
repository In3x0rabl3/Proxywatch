package keys

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	classifier "proxywatch/internal/detection"
	"proxywatch/internal/keystore"
	"proxywatch/internal/shared"

	"github.com/gdamore/tcell/v2"
)

// ApplyDetectionOutputRuntimeConfig configures detection outputs from runtime keystore values.
func ApplyDetectionOutputRuntimeConfig() error {
	debugOutputPath := keystore.RuntimeValue("PROXYWATCH_DETECT_DEBUG_LOG")
	defenderOutputPath := keystore.RuntimeValue("PROXYWATCH_DETECT_RULES_JSON")
	return classifier.ConfigureDetectionOutputs(debugOutputPath, defenderOutputPath)
}

func HandleKeystoreKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if app.KeystoreShowHelp {
		return handleKeystoreOverlayKey(app, tev)
	}

	if app.KeystoreWizardOpen {
		return HandleKeystoreWizardKey(app, tev)
	}

	if app.KeystorePasswordPrompt {
		switch tev.Key() {
		case tcell.KeyEscape:
			app.KeystorePasswordPrompt = false
			app.KeystorePasswordInput = ""
			app.KeystoreActiveEntry = ""
			setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
				"unlock cancelled", false)
		case tcell.KeyEnter:
			password := app.KeystorePasswordInput
			path := app.KeystorePath
			isSave := app.KeystorePasswordSave
			app.KeystorePasswordPrompt = false
			app.KeystorePasswordInput = ""
			app.KeystorePasswordSave = false

			if isSave {
				if err := keystore.SavePassword(path, password, app.KeystoreValues); err != nil {
					setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
						"save failed: "+err.Error(), true)
					return false
				}
				keystore.ApplyToRuntime(app.KeystoreValues)
				_ = ApplyDetectionOutputRuntimeConfig()
				app.KeystoreEditing = false
				setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
					"password keystore saved", false)
			} else {
				values, err := keystore.LoadPassword(path, password)
				if err != nil {
					setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
						"unlock failed: "+err.Error(), true)
					app.KeystoreActiveEntry = ""
					return false
				}
				app.KeystoreValues = values
				app.KeystoreUnlocked = true
				app.KeystoreMethod = "password"
				InitMissingKeystoreKeys(app)
				keystore.ApplyToRuntime(app.KeystoreValues)
				keystore.SetActiveKeystore(&app.KeystoreValues)
				app.KeystoreField = KeystoreFieldOpenAIKey
				app.KeystorePanel = 0
				setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
					"password keystore unlocked: "+app.KeystoreActiveEntry, false)
			}
		case tcell.KeyBackspace, tcell.KeyBackspace2:
			if len(app.KeystorePasswordInput) > 0 {
				app.KeystorePasswordInput = app.KeystorePasswordInput[:len(app.KeystorePasswordInput)-1]
			}
		default:
			r := tev.Rune()
			if r >= 32 && r <= 126 {
				app.KeystorePasswordInput += string(r)
			}
		}
		return false
	}

	inFieldsMode := app.KeystoreUnlocked && app.KeystoreActiveEntry != ""
	inListPanel := app.KeystorePanel == 1

	switch tev.Key() {
	case tcell.KeyUp:
		if inListPanel {
			if app.KeystoreSelected > 0 {
				app.KeystoreSelected--
			}
		} else if inFieldsMode {
			CycleKeystoreField(&app.KeystoreField, true)
		}
	case tcell.KeyDown:
		if inListPanel {
			entries := keystore.ListKeystores()
			if app.KeystoreSelected < len(entries)-1 {
				app.KeystoreSelected++
			}
		} else if inFieldsMode {
			CycleKeystoreField(&app.KeystoreField, false)
		}
	case tcell.KeyTab:
		if app.KeystoreEditing {
			app.KeystoreEditing = false
			keystore.ApplyToRuntime(app.KeystoreValues)
		}
		if app.KeystorePanel == 1 {
			app.KeystorePanel = 0
		} else {
			app.KeystorePanel = 1
		}
	case tcell.KeyBacktab:
		if app.KeystoreEditing {
			app.KeystoreEditing = false
			keystore.ApplyToRuntime(app.KeystoreValues)
		}
		if app.KeystorePanel == 0 {
			app.KeystorePanel = 1
		} else {
			app.KeystorePanel = 0
		}
	case tcell.KeyPgUp:
		app.KeystorePanel = 0
	case tcell.KeyPgDn:
		app.KeystorePanel = 1
	case tcell.KeyBackspace, tcell.KeyBackspace2:
		handleKeystoreBackspace(app)
	case tcell.KeyEnter:
		if inListPanel {
			SelectKeystoreEntry(app)
		} else {
			handleKeystoreEnter(app)
		}
	case tcell.KeyEscape:
		if app.KeystoreEditing {
			app.KeystoreEditing = false
			keystore.ApplyToRuntime(app.KeystoreValues)
		} else if inListPanel && inFieldsMode {
			app.KeystorePanel = 0
		} else if inFieldsMode {
			keystore.ApplyToRuntime(app.KeystoreValues)
			app.Mode = shared.ModeDashboard
		} else {
			app.Mode = shared.ModeDashboard
		}
	}

	if inListPanel {
		if tev.Rune() == 'a' {
			ActivateSelectedKeystore(app)
			return false
		}
		if tev.Rune() == 'd' {
			DeleteSelectedKeystore(app)
			return false
		}
		if tev.Rune() == 'n' {
			app.KeystoreWizardOpen = true
			app.KeystoreWizardField = 0
			app.KeystoreWizardName = ""
			app.KeystoreWizardSecure = false
			app.KeystoreWizardSlot = ""
			app.KeystoreWizardEditing = false
			return false
		}
	}

	if tev.Key() == tcell.KeyRune && tev.Rune() != 0 {
		if tev.Rune() == '?' && !app.KeystoreEditing {
			app.KeystoreShowHelp = true
			app.KeystoreHelpIndex = 0
			return false
		}
		handleKeystoreRuneInput(app, tev.Rune())
		if tev.Rune() == 'q' && app.KeystoreEditing {
			return false
		}
	}
	if tev.Rune() == 'q' && !app.KeystoreEditing {
		return requestQuit(app)
	}
	return false
}

func handleKeystoreOverlayKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if tev.Rune() == 'q' {
		return requestQuit(app)
	}
	if tev.Rune() == '?' || tev.Key() == tcell.KeyEscape {
		app.KeystoreShowHelp = false
		return false
	}
	maxIdx := len(keystoreMenuHelpOptions()) - 1
	switch tev.Key() {
	case tcell.KeyUp:
		if app.KeystoreHelpIndex > 0 {
			app.KeystoreHelpIndex--
		}
	case tcell.KeyDown:
		if app.KeystoreHelpIndex < max(0, maxIdx) {
			app.KeystoreHelpIndex++
		}
	}
	return false
}

func keystoreMenuHelpOptions() []string {
	return []string{
		"[Navigation]",
		"UP/DOWN      Move field / select keystore",
		"PGUP         Jump to Setup",
		"PGDN         Jump to Keystores list",
		"TAB          Toggle fields / keystores list",
		"LEFT/RIGHT   Cycle workflows",
		"",
		"[Editing]",
		"ENTER        Edit / open / switch keystore",
		"BACKSPACE    Delete while editing",
		"",
		"[Actions]",
		"a            Activate selected keystore",
		"n            Create new keystore",
		"d            Delete selected keystore",
		"?            Close this menu",
		"ESC          Back / lock keystore",
		"q            Quit",
	}
}

func handleKeystoreBackspace(app *shared.AppState) {
	if !app.KeystoreEditing {
		return
	}
	key, ok := KeystoreFieldEnvKey(app.KeystoreField)
	if !ok {
		return
	}
	EnsureKeystoreValues(app)
	app.KeystoreValues[key] = trimLastRune(app.KeystoreValues[key])
	keystore.ApplyToRuntime(app.KeystoreValues)
}

func handleKeystoreEnter(app *shared.AppState) {
	if app.KeystoreField == KeystoreFieldLoad {
		app.KeystoreWizardOpen = true
		app.KeystoreWizardField = 0
		app.KeystoreWizardName = ""
		app.KeystoreWizardSecure = false
		app.KeystoreWizardSlot = ""
		app.KeystoreWizardEditing = false
		return
	}

	if !app.KeystoreUnlocked || app.KeystoreActiveEntry == "" {
		return
	}

	switch app.KeystoreField {
	case KeystoreFieldMethod:
		methods := keystore.DetectSecurityMethods()
		currentMethod := strings.TrimSpace(app.KeystoreMethod)
		if currentMethod == "" {
			currentMethod = "local"
		}
		switch currentMethod {
		case "local":
			for _, m := range methods {
				if m.ID == "gpg" && m.Available {
					app.KeystoreMethod = "gpg"
					setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil, "security method changed to GPG Key", false)
					return
				}
			}
			for _, m := range methods {
				if m.ID == "yubikey" && m.Available {
					app.KeystoreMethod = "yubikey"
					setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil, "security method changed to Hardware Key", false)
					return
				}
			}
			setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil, "no other security methods available", true)
		case "gpg":
			for _, m := range methods {
				if m.ID == "yubikey" && m.Available {
					app.KeystoreMethod = "yubikey"
					setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil, "security method changed to Hardware Key", false)
					return
				}
			}
			app.KeystoreMethod = "local"
			setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil, "security method changed to Local Key", false)
		default:
			app.KeystoreMethod = "local"
			setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil, "security method changed to Local Key", false)
		}
	case KeystoreFieldLoad:
		LoadKeystore(app)
	case KeystoreFieldSave:
		SaveKeystore(app)
	case KeystoreFieldApply:
		ApplyKeystore(app)
	case KeystoreFieldLock:
		LockKeystore(app)
	default:
		wasEditing := app.KeystoreEditing
		app.KeystoreEditing = !app.KeystoreEditing
		if wasEditing {
			ApplyKeystore(app)
		}
	}
}

func handleKeystoreRuneInput(app *shared.AppState, r rune) {
	if !app.KeystoreEditing || r < 32 || r > 126 {
		return
	}
	key, ok := KeystoreFieldEnvKey(app.KeystoreField)
	if !ok {
		return
	}
	EnsureKeystoreValues(app)
	app.KeystoreValues[key] += string(r)
	keystore.ApplyToRuntime(app.KeystoreValues)
}

func LoadKeystore(app *shared.AppState) {
	values, err := keystore.Load(app.KeystorePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil, "keystore not found; save to create "+keystore.NormalizePath(app.KeystorePath), true)
			return
		}
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil, "load failed: "+err.Error(), true)
		return
	}
	app.KeystoreValues = values
	InitMissingKeystoreKeys(app)
	keystore.ApplyToRuntime(app.KeystoreValues)
	if err := ApplyDetectionOutputRuntimeConfig(); err != nil {
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil, "load failed: "+err.Error(), true)
		return
	}
	app.KeystoreUnlocked = true
	keystore.SetActiveKeystore(&app.KeystoreValues)
	app.KeystoreEditing = false
	setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil, "keystore loaded and applied to runtime config", false)
}

func SaveKeystore(app *shared.AppState) {
	EnsureKeystoreValues(app)

	if app.KeystoreMethod == "password" || keystore.IsPasswordKeystore(app.KeystorePath) {
		app.KeystorePasswordPrompt = true
		app.KeystorePasswordSave = true
		app.KeystorePasswordInput = ""
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
			"enter password to save...", false)
		return
	}

	if app.KeystoreSecure {
		values := make(map[string]string)
		for k, v := range app.KeystoreValues {
			values[k] = v
		}
		path := app.KeystorePath
		entries := keystore.ListKeystores()
		slot := "2"
		for _, e := range entries {
			if e.Name == app.KeystoreActiveEntry && e.Slot != "" {
				slot = e.Slot
			}
		}
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil, "saving — touch YubiKey...", false)
		go func() {
			if err := keystore.SaveSecure(path, slot, values); err != nil {
				setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil, "save failed: "+err.Error(), true)
				return
			}
			keystore.ApplyToRuntime(values)
			setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil, "secure keystore saved (YubiKey)", false)
		}()
		return
	}

	if err := keystore.SaveNonSecure(app.KeystorePath, app.KeystoreValues); err != nil {
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil, "save failed: "+err.Error(), true)
		return
	}
	keystore.ApplyToRuntime(app.KeystoreValues)
	_ = ApplyDetectionOutputRuntimeConfig()
	app.KeystoreEditing = false
	setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil, "keystore saved (encrypted) and applied to runtime config", false)
}

func HandleKeystoreWizardKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if tev.Key() == tcell.KeyEscape {
		app.KeystoreWizardOpen = false
		app.KeystoreWizardEditing = false
		return false
	}

	method := app.KeystoreWizardMethod
	if method == "" {
		method = "local"
	}
	maxField := 2
	switch method {
	case "password":
		maxField = 4
	case "yubikey":
		maxField = 3
	}

	switch tev.Key() {
	case tcell.KeyUp:
		if app.KeystoreWizardField > 0 {
			app.KeystoreWizardField--
		}
	case tcell.KeyDown:
		if app.KeystoreWizardField < maxField {
			app.KeystoreWizardField++
		}
	case tcell.KeyBackspace, tcell.KeyBackspace2:
		if app.KeystoreWizardEditing && app.KeystoreWizardField == 0 {
			if len(app.KeystoreWizardName) > 0 {
				app.KeystoreWizardName = app.KeystoreWizardName[:len(app.KeystoreWizardName)-1]
			}
		}
		if app.KeystoreWizardEditing && method == "password" {
			if app.KeystoreWizardField == 2 && len(app.KeystoreWizardPassword) > 0 {
				app.KeystoreWizardPassword = app.KeystoreWizardPassword[:len(app.KeystoreWizardPassword)-1]
			}
			if app.KeystoreWizardField == 3 && len(app.KeystoreWizardConfirm) > 0 {
				app.KeystoreWizardConfirm = app.KeystoreWizardConfirm[:len(app.KeystoreWizardConfirm)-1]
			}
		}
	case tcell.KeyEnter:
		switch app.KeystoreWizardField {
		case 0:
			app.KeystoreWizardEditing = !app.KeystoreWizardEditing
		case 1:
			hwAvail, _ := keystore.HardwareKeyAvailable()
			switch method {
			case "local":
				app.KeystoreWizardMethod = "password"
				app.KeystoreWizardSecure = true
				app.KeystoreWizardSlot = ""
				app.KeystoreWizardPassword = ""
				app.KeystoreWizardConfirm = ""
			case "password":
				if hwAvail {
					app.KeystoreWizardMethod = "yubikey"
					app.KeystoreWizardSecure = true
					app.KeystoreWizardPassword = ""
					app.KeystoreWizardConfirm = ""
					slots := keystore.DetectKeySlotsCached()
					for _, s := range slots {
						if s.InUse {
							app.KeystoreWizardSlot = s.ID
							break
						}
					}
				} else {
					app.KeystoreWizardMethod = "local"
					app.KeystoreWizardSecure = false
					app.KeystoreWizardSlot = ""
					app.KeystoreWizardPassword = ""
					app.KeystoreWizardConfirm = ""
				}
			default:
				app.KeystoreWizardMethod = "local"
				app.KeystoreWizardSecure = false
				app.KeystoreWizardSlot = ""
				app.KeystoreWizardPassword = ""
				app.KeystoreWizardConfirm = ""
			}
			if app.KeystoreWizardField > 1 {
				app.KeystoreWizardField = 1
			}
		case 2:
			switch method {
			case "password":
				app.KeystoreWizardEditing = !app.KeystoreWizardEditing
			case "yubikey":
				slots := keystore.DetectKeySlotsCached()
				var inUse []keystore.KeySlot
				for _, s := range slots {
					if s.InUse {
						inUse = append(inUse, s)
					}
				}
				if len(inUse) > 0 {
					found := false
					for i, s := range inUse {
						if s.ID == app.KeystoreWizardSlot {
							app.KeystoreWizardSlot = inUse[(i+1)%len(inUse)].ID
							found = true
							break
						}
					}
					if !found {
						app.KeystoreWizardSlot = inUse[0].ID
					}
				}
			default:
				ExecuteKeystoreWizardCreate(app)
			}
		case 3:
			if method == "password" {
				app.KeystoreWizardEditing = !app.KeystoreWizardEditing
			} else {
				ExecuteKeystoreWizardCreate(app)
			}
		case 4:
			if method == "password" {
				if app.KeystoreWizardPassword == "" {
					setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
						"password cannot be empty", true)
				} else if app.KeystoreWizardPassword != app.KeystoreWizardConfirm {
					setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
						"passwords do not match", true)
				} else {
					ExecuteKeystoreWizardCreate(app)
				}
			}
		}
	}

	if app.KeystoreWizardEditing {
		r := tev.Rune()
		if r >= 32 && r <= 126 {
			switch app.KeystoreWizardField {
			case 0:
				app.KeystoreWizardName += string(r)
			case 2:
				if method == "password" {
					app.KeystoreWizardPassword += string(r)
				}
			case 3:
				if method == "password" {
					app.KeystoreWizardConfirm += string(r)
				}
			}
		}
	}

	if tev.Rune() == 'q' && !app.KeystoreWizardEditing {
		return requestQuit(app)
	}
	return false
}

func ExecuteKeystoreWizardCreate(app *shared.AppState) {
	name := strings.TrimSpace(app.KeystoreWizardName)
	if name == "" {
		name = fmt.Sprintf("keystore-%s", time.Now().Format("20060102-150405"))
	}
	wizMethod := app.KeystoreWizardMethod
	if wizMethod == "" {
		wizMethod = "local"
	}
	slot := app.KeystoreWizardSlot

	if wizMethod == "password" {
		password := app.KeystoreWizardPassword
		app.KeystoreWizardOpen = false
		app.KeystoreWizardPassword = ""
		app.KeystoreWizardConfirm = ""
		entry, err := keystore.CreatePasswordKeystore(name, password)
		if err != nil {
			setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
				"create failed: "+err.Error(), true)
			return
		}
		app.KeystoreActiveEntry = entry.Name
		app.KeystoreSecure = true
		app.KeystoreMethod = "password"
		app.KeystorePath = entry.Path
		app.KeystoreValues = keystore.EmptyValues()
		app.KeystoreUnlocked = true
		keystore.ApplyToRuntime(app.KeystoreValues)
		keystore.SetActiveKeystore(&app.KeystoreValues)
		app.KeystoreField = KeystoreFieldOpenAIKey
		app.KeystorePanel = 0
		app.KeystoreEditing = false
		app.KeystoreWizardEditing = false
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
			"password keystore created: "+entry.Name, false)
		return
	}

	if wizMethod == "yubikey" {
		app.KeystoreWizardOpen = false
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
			"creating secure keystore — touch YubiKey...", false)
		go func() {
			entry, err := keystore.CreateKeystore(name, true, slot)
			if err != nil {
				setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
					"create failed: "+err.Error(), true)
				return
			}
			app.KeystoreActiveEntry = entry.Name
			app.KeystoreSecure = true
			app.KeystorePath = entry.Path
			app.KeystoreValues = keystore.EmptyValues()
			app.KeystoreUnlocked = true
			keystore.SetActiveKeystore(&app.KeystoreValues)
			app.KeystoreField = KeystoreFieldOpenAIKey
			app.KeystorePanel = 0
			app.KeystoreEditing = false
			app.KeystoreWizardEditing = false
			setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
				"secure keystore created (slot "+slot+"): "+entry.Name, false)
		}()
		return
	}

	entry, err := keystore.CreateKeystore(name, false)
	if err != nil {
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
			"create failed: "+err.Error(), true)
		return
	}

	app.KeystoreWizardOpen = false
	app.KeystoreWizardEditing = false
	app.KeystoreActiveEntry = entry.Name
	app.KeystoreSecure = false
	app.KeystorePath = entry.Path
	app.KeystoreValues = keystore.EmptyValues()
	app.KeystoreUnlocked = true
	keystore.SetActiveKeystore(&app.KeystoreValues)
	app.KeystoreField = KeystoreFieldOpenAIKey
	app.KeystorePanel = 0
	app.KeystoreEditing = false

	label := "keystore created: " + entry.Name
	setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil, label, false)
}

func DeleteSelectedKeystore(app *shared.AppState) {
	entries := keystore.ListKeystores()
	if app.KeystoreSelected < 0 || app.KeystoreSelected >= len(entries) {
		return
	}
	entry := entries[app.KeystoreSelected]

	if !app.KeystoreDeleteConfirm || app.KeystoreDeleteTarget != entry.Name {
		app.KeystoreDeleteConfirm = true
		app.KeystoreDeleteTarget = entry.Name
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
			"press d again to confirm delete: "+entry.Name, true)
		return
	}

	app.KeystoreDeleteConfirm = false
	app.KeystoreDeleteTarget = ""

	if entry.Secure {
		hwAvail, _ := keystore.HardwareKeyAvailable()
		if !hwAvail {
			setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
				"cannot delete secure keystore — hardware key not connected", true)
			return
		}
	}

	if err := keystore.DeleteKeystore(entry.Name); err != nil {
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
			"delete failed: "+err.Error(), true)
		return
	}

	if entry.Name == app.KeystoreActiveEntry {
		app.KeystoreValues = make(map[string]string)
		app.KeystoreUnlocked = false
		keystore.SetActiveKeystore(nil)
		app.KeystoreActiveEntry = ""
		app.KeystoreSecure = false
		app.KeystoreEditing = false
		app.KeystoreField = KeystoreFieldLoad
		app.KeystorePanel = 0
	}

	remaining := keystore.ListKeystores()
	if len(remaining) == 0 {
		app.KeystoreSelected = 0
		app.KeystorePanel = 0
	} else if app.KeystoreSelected >= len(remaining) {
		app.KeystoreSelected = len(remaining) - 1
	}
	setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
		"keystore deleted: "+entry.Name, false)
}

func ActivateSelectedKeystore(app *shared.AppState) {
	entries := keystore.ListKeystores()
	if app.KeystoreSelected < 0 || app.KeystoreSelected >= len(entries) {
		return
	}
	entry := entries[app.KeystoreSelected]

	if entry.Name == app.KeystoreActiveEntry {
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
			"already active: "+entry.Name, false)
		return
	}

	keystore.ClearSensitiveRuntime()

	app.KeystoreSecure = entry.Secure
	app.KeystoreMethod = entry.Method
	app.KeystorePath = entry.Path

	if entry.Method == "password" || keystore.IsPasswordKeystore(entry.Path) {
		app.KeystoreActiveEntry = entry.Name
		app.KeystorePasswordPrompt = true
		app.KeystorePasswordInput = ""
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
			"enter password to unlock...", false)
		return
	}

	if entry.Secure {
		path := entry.Path
		entryName := entry.Name
		app.KeystoreActiveEntry = entryName
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
			"touch YubiKey to activate...", false)
		go func() {
			values, err := keystore.LoadSecure(path)
			if err != nil {
				setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
					"activate failed: "+err.Error(), true)
				app.KeystoreActiveEntry = ""
				return
			}
			keystore.ApplyToRuntime(values)
			keystore.SetActiveKeystore(nil)
			setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
				"activated and relocked: "+entryName, false)
		}()
	} else {
		values, err := keystore.LoadNonSecure(entry.Path)
		if err != nil {
			setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
				"activate failed: "+err.Error(), true)
			return
		}
		app.KeystoreActiveEntry = entry.Name
		keystore.ApplyToRuntime(values)
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
			"activated: "+entry.Name, false)
	}
}

func SelectKeystoreEntry(app *shared.AppState) {
	entries := keystore.ListKeystores()
	if app.KeystoreSelected < 0 || app.KeystoreSelected >= len(entries) {
		return
	}
	entry := entries[app.KeystoreSelected]
	app.KeystoreActiveEntry = entry.Name
	app.KeystoreSecure = entry.Secure
	app.KeystorePath = entry.Path

	if entry.Secure {
		path := entry.Path
		entryName := entry.Name
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
			"touch YubiKey to decrypt...", false)
		go func() {
			values, err := keystore.LoadSecure(path)
			if err != nil {
				values, err = keystore.Load(path)
			}
			if err != nil {
				setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
					"decrypt failed: "+err.Error(), true)
				app.KeystoreActiveEntry = ""
				return
			}
			app.KeystoreValues = values
			keystore.ApplyToRuntime(values)
			app.KeystoreUnlocked = true
			keystore.SetActiveKeystore(&app.KeystoreValues)
			app.KeystoreField = KeystoreFieldOpenAIKey
			app.KeystorePanel = 0
			app.KeystoreEditing = false
			setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
				"secure keystore decrypted and loaded: "+entryName, false)
		}()
	} else {
		values, err := keystore.LoadNonSecure(entry.Path)
		if err != nil {
			setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
				"load failed: "+err.Error(), true)
			return
		}
		app.KeystoreValues = values
		keystore.ApplyToRuntime(values)
		app.KeystoreUnlocked = true
		keystore.SetActiveKeystore(&app.KeystoreValues)
		app.KeystoreField = KeystoreFieldOpenAIKey
		app.KeystorePanel = 0
		app.KeystoreEditing = false
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
			"keystore loaded", false)
	}
}

func LockKeystore(app *shared.AppState) {
	method := app.KeystoreMethod
	path := app.KeystorePath
	valuesToSave := app.KeystoreValues
	activeName := app.KeystoreActiveEntry

	app.KeystoreValues = make(map[string]string)
	keystore.ApplyToRuntime(make(map[string]string))
	app.KeystoreUnlocked = false
	keystore.SetActiveKeystore(nil)
	app.KeystoreEditing = false
	app.KeystoreActiveEntry = ""
	app.KeystorePanel = 0
	app.KeystoreField = KeystoreFieldLoad

	if activeName == "" || path == "" || valuesToSave == nil {
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
			"keystore locked — values cleared from memory", false)
		return
	}

	switch method {
	case "password":
		app.KeystorePasswordPrompt = true
		app.KeystorePasswordSave = true
		app.KeystorePasswordInput = ""
		app.KeystoreValues = valuesToSave
		app.KeystorePath = path
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
			"enter password to lock and encrypt...", false)
	case "yubikey":
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
			"encrypting — touch YubiKey...", false)
		go func() {
			entries := keystore.ListKeystores()
			slot := "2"
			for _, e := range entries {
				if e.Name == activeName && e.Slot != "" {
					slot = e.Slot
				}
			}
			if err := keystore.SaveSecure(path, slot, valuesToSave); err != nil {
				setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
					"encrypt failed: "+err.Error(), true)
			} else {
				setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
					"secure keystore encrypted and locked — runtime cleared", false)
			}
		}()
	default:
		_ = keystore.SaveNonSecure(path, valuesToSave)
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil,
			"keystore saved and locked", false)
	}
}

func ApplyKeystore(app *shared.AppState) {
	EnsureKeystoreValues(app)
	keystore.ApplyToRuntime(app.KeystoreValues)
	if err := ApplyDetectionOutputRuntimeConfig(); err != nil {
		setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil, "apply failed: "+err.Error(), true)
		return
	}
	setWorkflowStatus(app, &app.KeystoreStatusText, &app.KeystoreStatusError, &app.KeystoreStatusUntil, "runtime config updated from keystore values", false)
}
