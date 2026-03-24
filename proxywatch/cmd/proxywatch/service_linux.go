//go:build linux

package main

import (
	"fmt"
)

func installService(exePath string, args []string) error {
	return fmt.Errorf("service install not supported on linux")
}

func startService() error {
	return fmt.Errorf("service start not supported on linux")
}

func stopService() error {
	return fmt.Errorf("service stop not supported on linux")
}

func removeService() error {
	return fmt.Errorf("service uninstall not supported on linux")
}

func runService(serverAddr, hostID, token string) error {
	return fmt.Errorf("service mode not supported on linux")
}
