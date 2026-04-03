package keys

import (
	"strings"
	"time"

	"proxywatch/internal/shared"

	"github.com/gdamore/tcell/v2"
)

func HandleCollectKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if app.CollectShowHelp || app.CollectShowMenu {
		return handleCollectOverlayKey(app, tev)
	}
	minField := CollectFieldSource
	if strings.TrimSpace(app.LocalHost) != "" {
		minField = CollectFieldOutput
	}
	switch tev.Key() {
	case tcell.KeyUp:
		cycleField(&app.CollectField, minField, CollectFieldMax, true)
	case tcell.KeyDown:
		cycleField(&app.CollectField, minField, CollectFieldMax, false)
	case tcell.KeyBackspace, tcell.KeyBackspace2:
		handleCollectBackspace(app)
	case tcell.KeyEnter:
		handleCollectEnter(app)
	case tcell.KeyEscape:
		if app.CollectEditing {
			app.CollectEditing = false
		} else {
			app.Mode = shared.ModeDashboard
		}
	}

	if tev.Key() == tcell.KeyRune && tev.Rune() != 0 {
		if tev.Rune() == '?' && !app.CollectEditing {
			app.CollectShowHelp = true
			app.CollectHelpIndex = 0
			return false
		}
		handleCollectRuneInput(app, tev.Rune())
	}
	if tev.Rune() == 'q' && !app.CollectEditing {
		return requestQuit(app)
	}

	return false
}

func handleCollectOverlayKey(app *shared.AppState, tev *tcell.EventKey) bool {
	return handleOverlayKey(app, tev, overlayState{
		showHelp: &app.CollectShowHelp, showMenu: &app.CollectShowMenu,
		helpIndex: &app.CollectHelpIndex, menuIndex: &app.CollectMenuIndex,
		menuOptions: &app.CollectMenuOptions, menuKind: &app.CollectMenuKind,
		menuTitle: &app.CollectMenuTitle, helpOptions: collectMenuHelpOptions,
		applyMenu: func(a *shared.AppState) { applyCollectMenuSelection(a) },
	})
}

func collectMenuHelpOptions() []string {
	return []string{
		"[Navigation]",
		"UP/DOWN      Move field",
		"LEFT/RIGHT   Cycle workflows",
		"",
		"[Editing]",
		"ENTER        Edit / open / start",
		"BACKSPACE    Delete while editing",
		"",
		"?            Close this menu",
		"ESC          Back to dashboard",
		"q            Quit",
	}
}

func handleCollectBackspace(app *shared.AppState) {
	if !app.CollectEditing {
		return
	}
	switch app.CollectField {
	case CollectFieldOutput:
		app.CollectOutput = trimLastRune(app.CollectOutput)
	}
}

func handleCollectEnter(app *shared.AppState) {
	switch app.CollectField {
	case CollectFieldSource:
		if app.CollectActive {
			setWorkflowStatus(app, &app.CollectStatusText, &app.CollectStatusError, &app.CollectStatusUntil,
				"cannot change source while collection is running", false)
			return
		}
		RefreshCollectSources(app)
		openCollectMenu(app, "source", "Select Source", app.CollectSourceOpts, findIndex(app.CollectSourceOpts, app.CollectSource))
	case CollectFieldOutput:
		if app.CollectActive {
			setWorkflowStatus(app, &app.CollectStatusText, &app.CollectStatusError, &app.CollectStatusUntil,
				"cannot change output while collection is running", false)
			return
		}
		app.CollectEditing = !app.CollectEditing
	case CollectFieldDuration:
		if app.CollectActive {
			setWorkflowStatus(app, &app.CollectStatusText, &app.CollectStatusError, &app.CollectStatusUntil,
				"cannot change duration while collection is running", false)
			return
		}
		openCollectMenu(app, "duration", "Select Duration", CollectDurations, findIndex(CollectDurations, app.CollectDurationStr))

	case CollectFieldAction:
		if app.CollectActive {
			FinalizeCollection(app)
			return
		}

		dur, err := time.ParseDuration(app.CollectDurationStr)
		if err != nil || dur <= 0 {
			setWorkflowStatus(app, &app.CollectStatusText, &app.CollectStatusError, &app.CollectStatusUntil, "collection failed: invalid duration", true)
			return
		}
		if strings.TrimSpace(app.CollectSource) == "" {
			setWorkflowStatus(app, &app.CollectStatusText, &app.CollectStatusError, &app.CollectStatusUntil, "collection failed: no source selected", true)
			return
		}
		if strings.TrimSpace(app.CollectOutput) == "" {
			setWorkflowStatus(app, &app.CollectStatusText, &app.CollectStatusError, &app.CollectStatusUntil, "collection failed: output path is required", true)
			return
		}

		app.CollectData = nil
		app.CollectActive = true
		app.CollectStartedAt = time.Now()
		app.CollectUntil = time.Now().Add(dur)
		app.CollectEditing = false
		setWorkflowStatus(app, &app.CollectStatusText, &app.CollectStatusError, &app.CollectStatusUntil,
			"collection started ("+dur.String()+", source: "+app.CollectSource+")", false)
	}
}

func openCollectMenu(app *shared.AppState, kind, title string, options []string, selected int) {
	openWorkflowMenu(kind, title, options, selected, &app.CollectShowHelp, &app.CollectShowMenu, &app.CollectMenuKind, &app.CollectMenuTitle, &app.CollectMenuOptions, &app.CollectMenuIndex)
}

func applyCollectMenuSelection(app *shared.AppState) {
	if len(app.CollectMenuOptions) == 0 {
		return
	}
	choice := app.CollectMenuOptions[clampChoice(app.CollectMenuIndex, len(app.CollectMenuOptions))]
	switch app.CollectMenuKind {
	case "source":
		app.CollectSource = choice
		app.CollectSourceIndex = findIndex(app.CollectSourceOpts, choice)
	case "duration":
		app.CollectDurationStr = choice
	}
}

func handleCollectRuneInput(app *shared.AppState, r rune) {
	if !app.CollectEditing || r < 32 || r > 126 {
		return
	}
	switch app.CollectField {
	case CollectFieldOutput:
		app.CollectOutput += string(r)
	}
}
