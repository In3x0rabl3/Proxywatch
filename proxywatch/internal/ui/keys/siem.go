package keys

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"

	"proxywatch/internal/detection/output"
	"proxywatch/internal/shared"
)

// SIEM setup — two fields, visual order matches Output above Action so
// UP/DOWN navigation feels natural.
const (
	siemFieldOutput = iota
	siemFieldAction
)

const siemFieldMax = siemFieldAction

func HandleSIEMKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if app == nil || tev == nil {
		return false
	}
	if app.SiemShowHelp {
		switch tev.Key() {
		case tcell.KeyEscape:
			app.SiemShowHelp = false
			return false
		}
		if tev.Rune() == '?' {
			app.SiemShowHelp = false
		}
		return false
	}

	switch tev.Key() {
	case tcell.KeyUp:
		if app.SiemField > 0 {
			app.SiemField--
		}
	case tcell.KeyDown:
		if app.SiemField < siemFieldMax {
			app.SiemField++
		}
	case tcell.KeyTab:
		app.SiemField = (app.SiemField + 1) % (siemFieldMax + 1)
	case tcell.KeyBacktab:
		app.SiemField = (app.SiemField - 1 + siemFieldMax + 1) % (siemFieldMax + 1)
	case tcell.KeyLeft:
		StepWorkflowMenu(app, -1)
		return false
	case tcell.KeyRight:
		StepWorkflowMenu(app, 1)
		return false
	case tcell.KeyEnter:
		activateSIEMField(app)
	}

	switch tev.Rune() {
	case '?':
		app.SiemShowHelp = true
	case 'g', 'G':
		runSIEMGenerateAndExport(app)
	case 'q':
		return requestQuit(app)
	case '<':
		StepWorkflowMenu(app, -1)
	case '>':
		StepWorkflowMenu(app, 1)
	}
	return false
}

// activateSIEMField runs the single SIEM workflow: snapshot all control-*
// candidates and write the JSON bundle in one step. Both rows trigger the
// same action — there's no separate "generate" vs "export" phase.
func activateSIEMField(app *shared.AppState) {
	runSIEMGenerateAndExport(app)
}

func runSIEMGenerateAndExport(app *shared.AppState) {
	generateSIEMSnapshot(app)
	if !app.SiemGenerated || len(app.SiemGeneratedSet) == 0 {
		return
	}
	if err := exportSIEMJSON(app); err != nil {
		setSiemStatus(app, err.Error(), true)
	}
}

// generateSIEMSnapshot freezes the current control-* candidates as the
// set to be exported. Clears any prior export marker so the Output row
// re-advertises the pending write.
func generateSIEMSnapshot(app *shared.AppState) {
	if app == nil {
		return
	}
	cands := siemControlCandidates(app)
	// Deep-copy what we need so future scanner refreshes don't mutate the
	// snapshot (ProcessInfo and ControlChannel are *-typed on Candidate).
	frozen := make([]shared.Candidate, len(cands))
	for i, c := range cands {
		frozen[i] = c // shallow — rank.go immutable for our reads
	}
	app.SiemGeneratedSet = frozen
	app.SiemGenerated = true
	app.SiemGeneratedAt = time.Now().UTC()
	app.SiemLastExportPath = ""
	if len(frozen) == 0 {
		setSiemStatus(app, "no control-* processes to generate", true)
		return
	}
	setSiemStatus(app, fmt.Sprintf("generated %d detection%s",
		len(frozen), plural(len(frozen))), false)
}

// exportSIEMJSON writes the generated snapshot to the Output path. All
// five platforms are included. Refuses when Generate hasn't been run.
func exportSIEMJSON(app *shared.AppState) error {
	if !app.SiemGenerated {
		return fmt.Errorf("press [g] to generate detections first")
	}
	if len(app.SiemGeneratedSet) == 0 {
		return fmt.Errorf("snapshot is empty — nothing to export")
	}
	mask := [5]bool{true, true, true, true, true}
	hostScope := shared.DisplayHost(app.LocalHost)
	if hostScope == "" || hostScope == "local" {
		hostScope = shared.DefaultHostID("local")
	}
	doc := output.BuildSIEMExport(app.SiemGeneratedSet, mask, hostScope,
		app.SiemGeneratedAt)
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	path := defaultSIEMOutputPath(app)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	app.SiemLastExportPath = path
	setSiemStatus(app, fmt.Sprintf("wrote %d detection%s → %s",
		doc.Count, plural(doc.Count), shortenSIEMHome(path)), false)
	return nil
}

func siemControlCandidates(app *shared.AppState) []shared.Candidate {
	if app == nil {
		return nil
	}
	out := make([]shared.Candidate, 0, len(app.Candidates))
	for _, c := range app.Candidates {
		if c.Proc == nil {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(c.Role), "control-") {
			continue
		}
		out = append(out, c)
	}
	return out
}

func defaultSIEMOutputPath(app *shared.AppState) string {
	if p := strings.TrimSpace(app.SiemOutputPath); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "."
	}
	host := shared.DisplayHost(app.LocalHost)
	if host == "" || host == "local" {
		host = shared.DefaultHostID("local")
	}
	return filepath.Join(home, ".proxywatch", "siem",
		fmt.Sprintf("siem-%s.json", sanitizeSIEMPathComponent(host)))
}

func sanitizeSIEMPathComponent(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "local"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "local"
	}
	return b.String()
}

func shortenSIEMHome(p string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return p
	}
	if strings.HasPrefix(p, home) {
		return "~" + strings.TrimPrefix(p, home)
	}
	return p
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func setSiemStatus(app *shared.AppState, text string, isErr bool) {
	if app == nil {
		return
	}
	app.SiemStatusText = text
	app.SiemStatusError = isErr
	app.SiemStatusUntil = time.Now().Add(6 * time.Second)
}
