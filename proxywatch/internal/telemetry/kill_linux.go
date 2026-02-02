//go:build linux

package telemetry

import "syscall"

func killPID(pid int) error {
	return syscall.Kill(pid, syscall.SIGKILL)
}
