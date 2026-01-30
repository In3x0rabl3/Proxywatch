//go:build windows
// +build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"proxywatch/internal/shared"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	serviceName        = "BeaconHunterAgent"
	serviceDisplayName = "BeaconHunter Agent"
	serviceDescription = "BeaconHunter endpoint agent for ProxyWatch"
)

type serviceConfig struct {
	serverAddr  string
	hostID      string
	interval    time.Duration
	incremental bool
}

type serviceHandler struct {
	cfg serviceConfig
}

func (h *serviceHandler) Execute(args []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	s <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		cache := shared.ClassifierCache{}
		lastIO := map[int]shared.IOSample{}
		runAgentLoop(ctx, h.cfg.serverAddr, h.cfg.hostID, h.cfg.interval, h.cfg.incremental, &cache, &lastIO)
		close(done)
	}()

	s <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for {
		select {
		case <-done:
			s <- svc.Status{State: svc.StopPending}
			return false, 0
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				s <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}
		}
	}
}

func runService(serverAddr, hostID string, interval time.Duration, incremental bool) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !isService {
		return errors.New("not running as a Windows service (use --install/--start)")
	}
	cfg := serviceConfig{
		serverAddr:  serverAddr,
		hostID:      hostID,
		interval:    interval,
		incremental: incremental,
	}
	return svc.Run(serviceName, &serviceHandler{cfg: cfg})
}

func installService(exePath string, args []string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", serviceName)
	}

	s, err = m.CreateService(serviceName, exePath, mgr.Config{
		DisplayName: serviceDisplayName,
		StartType:   mgr.StartAutomatic,
		Description: serviceDescription,
	}, args...)
	if err != nil {
		return err
	}
	defer s.Close()
	return nil
}

func removeService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Delete()
}

func startService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Start()
}

func stopService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()
	_, err = s.Control(svc.Stop)
	return err
}
