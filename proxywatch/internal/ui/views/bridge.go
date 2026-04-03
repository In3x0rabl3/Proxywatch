// Package views contains the bubbletea view models for each workflow.
// They were extracted from package ui to separate rendering from key handling.
//
// Function variables in this file are wired up by the parent ui package
// at init time so that views can call back into ui-private key handlers.
package views

import (
	"fmt"
	"strings"
	"time"

	"proxywatch/internal/shared"
	"proxywatch/internal/ui/common"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/gdamore/tcell/v2"
)

// ── Constants duplicated from tea_loop.go ───────────────────────────────────

const (
	CollectFieldSource = iota
	CollectFieldOutput
	CollectFieldDuration
	CollectFieldAction
)

const CollectFieldMax = CollectFieldAction

const (
	WhitelistFieldProcess = iota
	WhitelistFieldEntry
	WhitelistFieldAdd
	WhitelistFieldRemove
)

const WhitelistFieldMax = WhitelistFieldRemove

const (
	CalibrateFieldProvider = iota
	CalibrateFieldHostScope
	CalibrateFieldModel
	CalibrateFieldProfile
	CalibrateFieldOutput
	CalibrateFieldDuration
	CalibrateFieldAction
	CalibrateFieldApply
	CalibrateFieldReset
)

const CalibrateFieldMax = CalibrateFieldReset

const (
	ContourFieldSource = iota
	ContourFieldEndpoint
	ContourFieldOutput
	ContourFieldDuration
	ContourFieldProbeMode
	ContourFieldProbeRole
	ContourFieldAction
)

const ContourFieldMax = ContourFieldAction

const (
	ContourNewFieldRole = iota
	ContourNewFieldMethod
	ContourNewFieldPort
	ContourNewFieldMode
)

const (
	ContourDashScan     = 0
	ContourDashContour  = 1
	ContourDashServices = 2
)

const (
	SiemFieldProvider = iota
	SiemFieldModel
	SiemFieldSourceReport
	SiemFieldJSONOutput
	SiemFieldGenerate
	SiemFieldCalibrate
	SiemFieldReportOutput
	SiemFieldSaveGeneration
	SiemFieldDebugLog
	SiemFieldRulesJSON
	SiemFieldApply
	SiemFieldSave
	SiemFieldDisable
)

const SiemFieldMax = SiemFieldCalibrate

const (
	KeystoreFieldOpenAIKey = iota
	KeystoreFieldOpenAIBaseURL
	KeystoreFieldAnthropicKey
	KeystoreFieldAnthropicBaseURL
	KeystoreFieldLocalLLMURL
	KeystoreFieldLocalLLMAPIKey
	KeystoreFieldCalibrationTimeout
	KeystoreFieldProxyhoundURL
	KeystoreFieldProxyhoundToken
	KeystoreFieldProxyhoundTokenID
	KeystoreFieldTLSDir
	KeystoreFieldAgentToken
	KeystoreFieldDisableClientCert
	KeystoreFieldTrustOnFirstUse
	KeystoreFieldMethod
	KeystoreFieldGitHubToken
	KeystoreFieldBuildkiteToken
	KeystoreFieldAWSAccessKey
	KeystoreFieldAWSSecretKey
	KeystoreFieldAzureClientID
	KeystoreFieldAzureClientSecret
	KeystoreFieldGCPServiceKey
	KeystoreFieldSlackBotToken
	KeystoreFieldDiscordBotToken
	KeystoreFieldTelegramBotKey
	KeystoreFieldFirebaseKey
	KeystoreFieldTeamsAuth
	KeystoreFieldGitLabToken
	KeystoreFieldSave
	KeystoreFieldApply
	KeystoreFieldLock
	KeystoreFieldLoad
	KeystoreFieldNew
)

const KeystoreFieldMax = KeystoreFieldNew

const (
	KeystorePanelSetup  = 0
	KeystorePanelList   = 1
	KeystorePanelFields = 2
)

// Lowercase aliases for internal use by view files — matching old package-private names.
const (
	collectFieldSource   = CollectFieldSource
	collectFieldOutput   = CollectFieldOutput
	collectFieldDuration = CollectFieldDuration
	collectFieldAction   = CollectFieldAction
	collectFieldMax      = CollectFieldMax
)

const (
	whitelistFieldProcess = WhitelistFieldProcess
	whitelistFieldEntry   = WhitelistFieldEntry
	whitelistFieldAdd     = WhitelistFieldAdd
	whitelistFieldRemove  = WhitelistFieldRemove
	whitelistFieldMax     = WhitelistFieldMax
)

const (
	calibrateFieldProvider  = CalibrateFieldProvider
	calibrateFieldHostScope = CalibrateFieldHostScope
	calibrateFieldModel     = CalibrateFieldModel
	calibrateFieldProfile   = CalibrateFieldProfile
	calibrateFieldOutput    = CalibrateFieldOutput
	calibrateFieldDuration  = CalibrateFieldDuration
	calibrateFieldAction    = CalibrateFieldAction
	calibrateFieldApply     = CalibrateFieldApply
	calibrateFieldReset     = CalibrateFieldReset
	calibrateFieldMax       = CalibrateFieldMax
)

const (
	contourFieldSource   = ContourFieldSource
	contourFieldEndpoint = ContourFieldEndpoint
	contourFieldOutput   = ContourFieldOutput
	contourFieldAction   = ContourFieldAction
)

const (
	contourDashScan     = ContourDashScan
	contourDashContour  = ContourDashContour
	contourDashServices = ContourDashServices
)

const (
	siemFieldProvider     = SiemFieldProvider
	siemFieldModel        = SiemFieldModel
	siemFieldSourceReport = SiemFieldSourceReport
	siemFieldJSONOutput   = SiemFieldJSONOutput
	siemFieldGenerate     = SiemFieldGenerate
	siemFieldCalibrate    = SiemFieldCalibrate
)

const (
	keystoreFieldOpenAIKey          = KeystoreFieldOpenAIKey
	keystoreFieldOpenAIBaseURL      = KeystoreFieldOpenAIBaseURL
	keystoreFieldAnthropicKey       = KeystoreFieldAnthropicKey
	keystoreFieldAnthropicBaseURL   = KeystoreFieldAnthropicBaseURL
	keystoreFieldLocalLLMURL        = KeystoreFieldLocalLLMURL
	keystoreFieldLocalLLMAPIKey     = KeystoreFieldLocalLLMAPIKey
	keystoreFieldCalibrationTimeout = KeystoreFieldCalibrationTimeout
	keystoreFieldProxyhoundURL      = KeystoreFieldProxyhoundURL
	keystoreFieldProxyhoundToken    = KeystoreFieldProxyhoundToken
	keystoreFieldProxyhoundTokenID  = KeystoreFieldProxyhoundTokenID
	keystoreFieldTLSDir             = KeystoreFieldTLSDir
	keystoreFieldAgentToken         = KeystoreFieldAgentToken
	keystoreFieldDisableClientCert  = KeystoreFieldDisableClientCert
	keystoreFieldTrustOnFirstUse    = KeystoreFieldTrustOnFirstUse
	keystoreFieldGitHubToken        = KeystoreFieldGitHubToken
	keystoreFieldBuildkiteToken     = KeystoreFieldBuildkiteToken
	keystoreFieldAWSAccessKey       = KeystoreFieldAWSAccessKey
	keystoreFieldAWSSecretKey       = KeystoreFieldAWSSecretKey
	keystoreFieldAzureClientID      = KeystoreFieldAzureClientID
	keystoreFieldAzureClientSecret  = KeystoreFieldAzureClientSecret
	keystoreFieldGCPServiceKey      = KeystoreFieldGCPServiceKey
	keystoreFieldSlackBotToken      = KeystoreFieldSlackBotToken
	keystoreFieldDiscordBotToken    = KeystoreFieldDiscordBotToken
	keystoreFieldTelegramBotKey     = KeystoreFieldTelegramBotKey
	keystoreFieldFirebaseKey        = KeystoreFieldFirebaseKey
	keystoreFieldTeamsAuth          = KeystoreFieldTeamsAuth
	keystoreFieldGitLabToken        = KeystoreFieldGitLabToken
	keystoreFieldSave               = KeystoreFieldSave
	keystoreFieldApply              = KeystoreFieldApply
	keystoreFieldLock               = KeystoreFieldLock
	keystoreFieldLoad               = KeystoreFieldLoad
	keystoreFieldMax                = KeystoreFieldMax
)

// ── Time format ─────────────────────────────────────────────────────────────

const UTCTimeFormat = "2006-01-02 15:04:05"

// ── Style aliases ───────────────────────────────────────────────────────────
// These give view files short names identical to the old package-private vars.

var (
	colorBg     = common.ColorBg
	colorText   = common.ColorText
	colorTextHi = common.ColorTextHi
	colorFrame  = common.ColorFrame
	colorAccent = common.ColorAccent
	colorCyan   = common.ColorCyan
	colorDim    = common.ColorDim
	colorMuted  = common.ColorMuted
	colorAlert  = common.ColorAlert
	colorWarn   = common.ColorWarn
	colorSelect = common.ColorSelect
)

func bg() lipgloss.Style { return common.Bg() }
func bgSp(n int) string  { return common.BgSp(n) }

var (
	rightLabelStyle = common.RightLabelStyle
	sectionLabel    = common.SectionLabel
	bodyText        = common.BodyText
	mutedText       = common.MutedText
	dimText         = common.DimText
)

var (
	sevWatch = common.SevWatch
)

var (
	statusPass = common.StatusPass
	statusFail = common.StatusFail
)

var matrixFailStyle = common.MatrixFailStyle

var (
	dotSpinFrames  = common.DotSpinFrames
	dialSpinFrames = common.DialSpinFrames
)

func dotSpinFrame() string  { return common.DotSpinFrame() }
func dialSpinFrame() string { return common.DialSpinFrame() }

// Re-export common types under their old names.
type FormRow = common.FormRow
type ReportPanelOpts = common.ReportPanelOpts

// Layout functions.
func renderSetupPanel(title string, rows []FormRow, selectedField int, editing bool, w int) string {
	return common.RenderSetupPanel(title, rows, selectedField, editing, w)
}
func renderReportPanel(opts ReportPanelOpts) string {
	return common.RenderReportPanel(opts)
}
func renderPanel(w, h int, title, rightTitle, bottomRight, content string) string {
	return common.RenderPanel(w, h, title, rightTitle, bottomRight, content)
}
func overlayCenter(base, overlay string, screenW, screenH int) string {
	return common.OverlayCenter(base, overlay, screenW, screenH)
}
func renderAccentPanel(w, h int, title, content string) string {
	return common.RenderAccentPanel(w, h, title, content)
}
func renderQuitConfirm(deadline time.Time, w int) string {
	remaining := time.Until(deadline).Truncate(time.Second)
	if remaining < 0 {
		remaining = 0
	}
	msg := fmt.Sprintf("  Press q again to quit (%ds)", int(remaining.Seconds()))
	return statusFail.Render(msg)
}
func renderMenuPanel(title string, options []string, selected int, footer string, screenW int) string {
	return common.RenderMenuPanel(title, options, selected, footer, screenW)
}
func renderHelpPanel(title string, options []string, w int) string {
	return common.RenderHelpPanel(title, options, w)
}

// Helper functions from common.
func TruncateToWidth(s string, w int) string { return common.TruncateToWidth(s, w) }
func ClipToWidth(s string, w int) string     { return common.ClipToWidth(s, w) }
func FormatBytes(n uint64) string            { return common.FormatBytes(n) }
func FormatBytesPerSec(n uint64) string      { return common.FormatBytesPerSec(n) }
func FormatIOBytes(r, w, o uint64) string    { return common.FormatIOBytes(r, w, o) }
func FormatIORate(r, w, o uint64) string     { return common.FormatIORate(r, w, o) }
func spinnerElapsed(start time.Time) string {
	return common.SpinnerElapsed(start).String()
}

// Help option functions from common.
func calibrationMenuHelpOptions() []string { return common.CalibrationMenuHelpOptions() }
func contourMenuHelpOptions() []string     { return common.ContourMenuHelpOptions() }
func siemMenuHelpOptions() []string        { return common.SiemMenuHelpOptions() }
func collectMenuHelpOptions() []string     { return common.CollectMenuHelpOptions() }
func keystoreMenuHelpOptions() []string    { return common.KeystoreMenuHelpOptions() }
func whitelistMenuHelpOptions() []string   { return common.WhitelistMenuHelpOptions() }
func inspectorMenuOptions() []string       { return common.InspectorMenuOptions() }
func dashboardMenuHelpOptions() []string   { return common.DashboardMenuHelpOptions() }
func refreshPresetOptions() []string       { return common.RefreshPresetOptions() }

// ── Function variables wired by ui package ──────────────────────────────────
// These are set by ui.init() or ui.Run() to point at the real implementations.

var (
	ConvertKeyMsg                   func(tea.KeyMsg) *tcell.EventKey
	HandleQuitConfirmKey            func(*shared.AppState, *tcell.EventKey) (bool, bool)
	StepWorkflowMenu                func(*shared.AppState, int) bool
	JumpToWorkflow                  func(*shared.AppState, rune) bool
	RequestQuit                     func(*shared.AppState) bool
	HandleCalibrationKey            func(*shared.AppState, *tcell.EventKey) bool
	HandleContourKey                func(*shared.AppState, *tcell.EventKey) bool
	HandleContourModeKey            func(*shared.AppState, *tcell.EventKey) bool
	HandleDashboardKey              func(*shared.AppState, *tcell.EventKey) bool
	HandleSIEMKey                   func(*shared.AppState, *tcell.EventKey) bool
	HandleKeystoreKey               func(*shared.AppState, *tcell.EventKey) bool
	HandleWhitelistKey              func(*shared.AppState, *tcell.EventKey) bool
	HandleInspectKey                func(*shared.AppState, *tcell.EventKey) bool
	HandleCollectKey                func(*shared.AppState, *tcell.EventKey) bool
	HandleKeyEvent                  func(*shared.AppState, *tcell.EventKey) bool
	DrawCurrentMode                 func(*shared.AppState)
	DrawQuitConfirmOverlay          func(*shared.AppState)
	CalibrateEditValue              func(*shared.AppState) string
	CalibrationActionLabel          func(*shared.AppState) string
	CalibrationCollectionLines      func(*shared.AppState) []string
	NormalizeCalibrationReportLines func([]string, int) []string
	DashboardHostListMode           func(*shared.AppState) bool
	DashboardProcessCandidates      func(*shared.AppState) []shared.Candidate
	SelectedDashboardProcessIndex   func(*shared.AppState, []shared.Candidate) int
	BuildMultiHostSummary           func(*shared.AppState) string
	SafeRolePreset                  func(*shared.AppState) string
	FormatDashboardAge              func(int) string
	NormalizeDashboardRole          func(string) string
	DashboardCandidateAgeSeconds    func(shared.Candidate) int
	CycleInspectProcess             func(*shared.AppState, int)
	InspectorExternalOrgs           func(*shared.Candidate) ([]string, int, int)
	EnsureKeystoreValues            func(*shared.AppState)
	KeystoreFieldEnvKey             func(int) (string, bool)
	KeystoreFieldVisible            func(int) bool
	RefreshCollectSources           func(*shared.AppState)
	CollectActionLabel              func(*shared.AppState) string
	CollectLiveLines                func(*shared.AppState) []string
	WhitelistProcessCandidates      func(*shared.AppState) []shared.Candidate
	FormatWhitelistEntry            func(string, int) string
	NonEmptySIEMValue               func(string, string) string
	RoleSortMenuLabels              func() []string
	ClampIndex                      func(int, int) int
	CalibrateHostScopeLabel         func(*shared.AppState) string
	CalibrateResetLabel             func(*shared.AppState) string
	SiemFieldMaxFor                 func(*shared.AppState) int
)

// ── Convenience wrappers ────────────────────────────────────────────────────
// These let view code call the function variables with the old lowercase names.

func convertKeyMsg(msg tea.KeyMsg) *tcell.EventKey {
	if ConvertKeyMsg != nil {
		return ConvertKeyMsg(msg)
	}
	return tcell.NewEventKey(tcell.KeyRune, 0, tcell.ModNone)
}

func handleQuitConfirmKey(app *shared.AppState, tev *tcell.EventKey) (bool, bool) {
	if HandleQuitConfirmKey != nil {
		return HandleQuitConfirmKey(app, tev)
	}
	return false, false
}

func stepWorkflowMenu(app *shared.AppState, dir int) bool {
	if StepWorkflowMenu != nil {
		return StepWorkflowMenu(app, dir)
	}
	return false
}

func jumpToWorkflow(app *shared.AppState, r rune) bool {
	if JumpToWorkflow != nil {
		return JumpToWorkflow(app, r)
	}
	return false
}

func requestQuit(app *shared.AppState) bool {
	if RequestQuit != nil {
		return RequestQuit(app)
	}
	return false
}

func handleCalibrationKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if HandleCalibrationKey != nil {
		return HandleCalibrationKey(app, tev)
	}
	return false
}

func handleContourKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if HandleContourKey != nil {
		return HandleContourKey(app, tev)
	}
	return false
}

func handleContourModeKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if HandleContourModeKey != nil {
		return HandleContourModeKey(app, tev)
	}
	return false
}

func handleDashboardKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if HandleDashboardKey != nil {
		return HandleDashboardKey(app, tev)
	}
	return false
}

func handleSIEMKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if HandleSIEMKey != nil {
		return HandleSIEMKey(app, tev)
	}
	return false
}

func handleKeystoreKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if HandleKeystoreKey != nil {
		return HandleKeystoreKey(app, tev)
	}
	return false
}

func handleWhitelistKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if HandleWhitelistKey != nil {
		return HandleWhitelistKey(app, tev)
	}
	return false
}

func handleInspectKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if HandleInspectKey != nil {
		return HandleInspectKey(app, tev)
	}
	return false
}

func handleCollectKey(app *shared.AppState, tev *tcell.EventKey) bool {
	if HandleCollectKey != nil {
		return HandleCollectKey(app, tev)
	}
	return false
}

func handleKeyEvent(app *shared.AppState, tev *tcell.EventKey) bool {
	if HandleKeyEvent != nil {
		return HandleKeyEvent(app, tev)
	}
	return false
}

func drawCurrentMode(app *shared.AppState) {
	if DrawCurrentMode != nil {
		DrawCurrentMode(app)
	}
}

func drawQuitConfirmOverlay(app *shared.AppState) {
	if DrawQuitConfirmOverlay != nil {
		DrawQuitConfirmOverlay(app)
	}
}

func calibrateEditValue(app *shared.AppState) string {
	if CalibrateEditValue != nil {
		return CalibrateEditValue(app)
	}
	return ""
}

func calibrationActionLabel(app *shared.AppState) string {
	if CalibrationActionLabel != nil {
		return CalibrationActionLabel(app)
	}
	return "Start"
}

func calibrationCollectionLines(app *shared.AppState) []string {
	if CalibrationCollectionLines != nil {
		return CalibrationCollectionLines(app)
	}
	return nil
}

func normalizeCalibrationReportLines(lines []string, width int) []string {
	if NormalizeCalibrationReportLines != nil {
		return NormalizeCalibrationReportLines(lines, width)
	}
	return lines
}

func dashboardHostListMode(app *shared.AppState) bool {
	if DashboardHostListMode != nil {
		return DashboardHostListMode(app)
	}
	return false
}

func dashboardProcessCandidates(app *shared.AppState) []shared.Candidate {
	if DashboardProcessCandidates != nil {
		return DashboardProcessCandidates(app)
	}
	return nil
}

func selectedDashboardProcessIndex(app *shared.AppState, view []shared.Candidate) int {
	if SelectedDashboardProcessIndex != nil {
		return SelectedDashboardProcessIndex(app, view)
	}
	return 0
}

func buildMultiHostSummary(app *shared.AppState) string {
	if BuildMultiHostSummary != nil {
		return BuildMultiHostSummary(app)
	}
	return ""
}

func safeRolePreset(app *shared.AppState) string {
	if SafeRolePreset != nil {
		return SafeRolePreset(app)
	}
	return "recommended"
}

func formatDashboardAge(seconds int) string {
	if FormatDashboardAge != nil {
		return FormatDashboardAge(seconds)
	}
	return "0s"
}

func normalizeDashboardRole(role string) string {
	if NormalizeDashboardRole != nil {
		return NormalizeDashboardRole(role)
	}
	return role
}

func dashboardCandidateAgeSeconds(c shared.Candidate) int {
	if DashboardCandidateAgeSeconds != nil {
		return DashboardCandidateAgeSeconds(c)
	}
	return 0
}

func cycleInspectProcess(app *shared.AppState, dir int) {
	if CycleInspectProcess != nil {
		CycleInspectProcess(app, dir)
	}
}

func inspectorExternalOrgs(cand *shared.Candidate) ([]string, int, int) {
	if InspectorExternalOrgs != nil {
		return InspectorExternalOrgs(cand)
	}
	return nil, 0, 0
}

func ensureKeystoreValues(app *shared.AppState) {
	if EnsureKeystoreValues != nil {
		EnsureKeystoreValues(app)
	}
}

func keystoreFieldEnvKey(field int) (string, bool) {
	if KeystoreFieldEnvKey != nil {
		return KeystoreFieldEnvKey(field)
	}
	return "", false
}

func keystoreFieldVisible(field int) bool {
	if KeystoreFieldVisible != nil {
		return KeystoreFieldVisible(field)
	}
	return true
}

func refreshCollectSources(app *shared.AppState) {
	if RefreshCollectSources != nil {
		RefreshCollectSources(app)
	}
}

func collectActionLabel(app *shared.AppState) string {
	if CollectActionLabel != nil {
		return CollectActionLabel(app)
	}
	return "Start collection"
}

func collectLiveLines(app *shared.AppState) []string {
	if CollectLiveLines != nil {
		return CollectLiveLines(app)
	}
	return nil
}

func whitelistProcessCandidates(app *shared.AppState) []shared.Candidate {
	if WhitelistProcessCandidates != nil {
		return WhitelistProcessCandidates(app)
	}
	return nil
}

func formatWhitelistEntry(entry string, width int) string {
	if FormatWhitelistEntry != nil {
		return FormatWhitelistEntry(entry, width)
	}
	return entry
}

func nonEmptySIEMValue(value, fallback string) string {
	if NonEmptySIEMValue != nil {
		return NonEmptySIEMValue(value, fallback)
	}
	if value != "" {
		return value
	}
	return fallback
}

func roleSortMenuLabels() []string {
	if RoleSortMenuLabels != nil {
		return RoleSortMenuLabels()
	}
	return nil
}

func clampIndex(idx, n int) int {
	if ClampIndex != nil {
		return ClampIndex(idx, n)
	}
	if n <= 0 {
		return -1
	}
	if idx < 0 {
		return 0
	}
	if idx >= n {
		return n - 1
	}
	return idx
}

func calibrateHostScopeLabel(app *shared.AppState) string {
	if CalibrateHostScopeLabel != nil {
		return CalibrateHostScopeLabel(app)
	}
	return ""
}

func calibrateResetLabel(app *shared.AppState) string {
	if CalibrateResetLabel != nil {
		return CalibrateResetLabel(app)
	}
	return "Reset baseline model"
}

// ── Inspector-specific styles (shared across multiple views) ────────────────

var (
	inspLabel   = lipgloss.NewStyle().Foreground(common.ColorMuted).Background(common.ColorBg)
	inspValue   = lipgloss.NewStyle().Foreground(common.ColorText).Bold(true).Background(common.ColorBg)
	inspDim     = lipgloss.NewStyle().Foreground(common.ColorDim).Background(common.ColorBg)
	inspWarn    = lipgloss.NewStyle().Foreground(common.ColorWarn).Bold(true).Background(common.ColorBg)
	inspAlert   = lipgloss.NewStyle().Foreground(common.ColorAlert).Bold(true).Background(common.ColorBg)
	inspCyan    = lipgloss.NewStyle().Foreground(common.ColorCyan).Background(common.ColorBg)
	inspSession = lipgloss.NewStyle().Foreground(common.ColorSession).Bold(true).Background(common.ColorBg)
	inspPivot   = lipgloss.NewStyle().Foreground(common.ColorWarn).Bold(true).Background(common.ColorBg)
	inspTunnel  = lipgloss.NewStyle().Foreground(common.ColorOrange).Bold(true).Background(common.ColorBg)
)

// ── sparkGauge renders a simple percentage gauge ────────────────────────────

func sparkGauge(pct float64, w int, fg lipgloss.Color) string {
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	filled := int(pct * float64(w) / 100)
	empty := w - filled
	bar := lipgloss.NewStyle().Foreground(fg).Render(strings.Repeat("█", filled)) +
		lipgloss.NewStyle().Foreground(common.ColorDim).Render(strings.Repeat("░", empty))
	return bar
}

// ── quickHash is a simple string hash for content dedup ─────────────────────

func quickHash(s string) uint64 {
	var h uint64 = 5381
	for _, c := range s {
		h = h*33 + uint64(c)
	}
	return h
}

// ── Dashboard lipgloss styles ───────────────────────────────────────────────

var (
	lgText    = lipgloss.NewStyle().Foreground(common.ColorText).Background(common.ColorBg)
	lgTextB   = lipgloss.NewStyle().Foreground(common.ColorText).Bold(true).Background(common.ColorBg)
	lgCyanB   = lipgloss.NewStyle().Foreground(common.ColorCyan).Bold(true).Background(common.ColorBg)
	lgDim     = lipgloss.NewStyle().Foreground(common.ColorDim).Background(common.ColorBg)
	lgDimB    = lipgloss.NewStyle().Foreground(common.ColorDim).Bold(true).Background(common.ColorBg)
	lgWatch   = lipgloss.NewStyle().Foreground(common.ColorCyan).Bold(true).Background(common.ColorBg)
	lgWarn    = lipgloss.NewStyle().Foreground(common.ColorWarn).Bold(true).Background(common.ColorBg)
	lgAlert   = lipgloss.NewStyle().Foreground(common.ColorAlert).Bold(true).Background(common.ColorBg)
	lgMuted   = lipgloss.NewStyle().Foreground(common.ColorMuted).Background(common.ColorBg)
	lgSession = lipgloss.NewStyle().Foreground(common.ColorSession).Bold(true).Background(common.ColorBg)
	lgPivot   = lipgloss.NewStyle().Foreground(common.ColorWarn).Bold(true).Background(common.ColorBg)
	lgTunnel  = lipgloss.NewStyle().Foreground(common.ColorOrange).Bold(true).Background(common.ColorBg)

	lgSelectBg = lipgloss.NewStyle().Background(common.ColorSelect)
)

func lgRoleStyle(role string) lipgloss.Style {
	switch role {
	case "control-session", "control-beacon":
		return lgSession
	case "analyzing":
		return lgDim
	case "control-pivot":
		return lgPivot
	case "control-tunnel":
		return lgTunnel
	default:
		return lgTextB
	}
}

func lgStateStyle(state string) lipgloss.Style {
	switch state {
	case "active":
		return lgAlert
	case "strong":
		return lgWarn
	default:
		return lgWatch
	}
}

func applySelectBg(s lipgloss.Style, selected bool) lipgloss.Style {
	if !selected {
		return s
	}
	return s.Background(common.ColorSelect)
}

// Ensure imports are used.
var (
	_ = tea.KeyMsg{}
	_ = tcell.KeyUp
)
