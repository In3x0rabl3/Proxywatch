//go:build darwin

package main

import "fmt"

// macOS does not yet have a launchctl-integrated service mode. These
// stubs let the darwin binary link + run — foreground execution via
// -connect / -listen remains fully supported. If an operator needs
// persistent background execution, wrap the binary in a user
// LaunchAgent plist under ~/Library/LaunchAgents/ manually.
//
// Wiring launchctl properly would require: emit a plist template,
// bootstrap into the current session via `launchctl bootstrap
// gui/<uid> <plist>`, and unload cleanly on removal. Not yet in
// scope — see the darwin-arm64 plan and Track 11c.

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
