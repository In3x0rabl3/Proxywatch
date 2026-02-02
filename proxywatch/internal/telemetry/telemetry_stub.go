//go:build !windows && !linux
// +build !windows,!linux

package telemetry

import (
	"errors"

	"proxywatch/internal/shared"
)

func Collect() (*shared.Snapshot, error) {
	return nil, errors.New("telemetry collection is only supported on Windows")
}

func KillProcess(pid int) error {
	return errors.New("process termination is only supported on Windows")
}
