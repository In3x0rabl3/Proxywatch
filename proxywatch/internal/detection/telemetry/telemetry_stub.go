//go:build !windows && !linux && !darwin
// +build !windows,!linux,!darwin

package telemetry

import (
	"errors"

	"proxywatch/internal/shared"
)

func Collect() (*shared.Snapshot, error) {
	return nil, errors.New("telemetry collection is only supported on Windows, Linux, and macOS")
}

func KillProcess(pid int) error {
	return errors.New("process termination is only supported on Windows, Linux, and macOS")
}
