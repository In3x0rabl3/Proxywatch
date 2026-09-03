package main

import "fmt"

const darwinServiceUnsupported = "service mode is not yet supported on macOS; run with -connect directly or wrap in a LaunchAgent plist manually"

func installService(exePath string, args []string) error {
	_ = exePath
	_ = args
	return fmt.Errorf(darwinServiceUnsupported)
}

func startService() error {
	return fmt.Errorf(darwinServiceUnsupported)
}

func stopService() error {
	return fmt.Errorf(darwinServiceUnsupported)
}

func removeService() error {
	return fmt.Errorf(darwinServiceUnsupported)
}

func runService(serverAddr, hostID, token string) error {
	_ = serverAddr
	_ = hostID
	_ = token
	return fmt.Errorf(darwinServiceUnsupported)
}
