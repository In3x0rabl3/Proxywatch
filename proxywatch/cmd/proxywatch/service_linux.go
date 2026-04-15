//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const unitPath = "/etc/systemd/system/proxywatch.service"

func installService(exePath string, args []string) error {
	unit := fmt.Sprintf(`[Unit]
Description=ProxyWatch Agent
After=network.target

[Service]
Type=simple
ExecStart=%s %s
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`, exePath, strings.Join(args, " "))

	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("write unit file: %w", err)
	}
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("daemon-reload: %w", err)
	}
	if err := exec.Command("systemctl", "enable", "proxywatch").Run(); err != nil {
		return fmt.Errorf("enable service: %w", err)
	}
	fmt.Printf("Service installed: %s\nStart with: sudo systemctl start proxywatch\n", unitPath)
	return nil
}

func startService() error {
	return exec.Command("systemctl", "start", "proxywatch").Run()
}

func stopService() error {
	return exec.Command("systemctl", "stop", "proxywatch").Run()
}

func removeService() error {
	_ = exec.Command("systemctl", "stop", "proxywatch").Run()
	_ = exec.Command("systemctl", "disable", "proxywatch").Run()
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove unit file: %w", err)
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	fmt.Println("Service uninstalled.")
	return nil
}

func runService(serverAddr, hostID, token string) error {
	return fmt.Errorf("use -connect flag directly; systemd manages the process lifecycle via the unit file")
}
