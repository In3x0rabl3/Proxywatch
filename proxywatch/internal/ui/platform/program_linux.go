//go:build linux

package platform

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

func RunTeaProgram(root tea.Model) error {
	// Force true color output so our RGB colors render correctly
	// on all terminals, even if COLORTERM is not set.
	lipgloss.SetColorProfile(termenv.TrueColor)

	// Set terminal default background to match the app theme.
	fmt.Fprint(os.Stdout, "\033]11;rgb:1e/1e/1e\007")

	p := tea.NewProgram(root, tea.WithAltScreen(), tea.WithInputTTY(), tea.WithMouseCellMotion())
	fmt.Fprintf(os.Stderr, "[ui] starting TUI...\n")
	_, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ui] TUI error: %v\n", err)
	}

	// Restore terminal default background.
	fmt.Fprint(os.Stdout, "\033]111\007")
	return err
}
