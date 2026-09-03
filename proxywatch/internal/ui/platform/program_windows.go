//go:build windows

package platform

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

func RunTeaProgram(root tea.Model) error {
	// Force true color on Windows too.
	lipgloss.SetColorProfile(termenv.TrueColor)

	p := tea.NewProgram(root, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
