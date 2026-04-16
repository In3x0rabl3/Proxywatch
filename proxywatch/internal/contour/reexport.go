package contour

// This file re-exports symbols from the probe and tunnel subpackages so that
// external callers can continue to use them via the contour package without
// changing their import paths.

import (
	"context"

	"proxywatch/internal/contour/probe"
	"proxywatch/internal/contour/tunnel"
)

// ═══════════════════════════════════════════════════════════════════════════
// Probe type aliases
// ═══════════════════════════════════════════════════════════════════════════

type ProbeSummary = probe.ProbeSummary
type ProbeEndpoint = probe.ProbeEndpoint
type ProbeMethodResult = probe.ProbeMethodResult
type ProbePortResult = probe.ProbePortResult
type ProbeCheck = probe.ProbeCheck
type ServiceProbeResult = probe.ServiceProbeResult
type ListenerProbeResult = probe.ListenerProbeResult

// ═══════════════════════════════════════════════════════════════════════════
// Probe constants
// ═══════════════════════════════════════════════════════════════════════════

const (
	ProbeModeOff    = probe.ProbeModeOff
	ProbeModeSweep  = probe.ProbeModeSweep
	ProbeModeChecks = probe.ProbeModeChecks
	ProbeRoleClient = probe.ProbeRoleClient
	ProbeRoleListen = probe.ProbeRoleListen
	ProbeRoleScan   = probe.ProbeRoleScan

	SvcCatCloudStorage = probe.SvcCatCloudStorage
	SvcCatMessaging    = probe.SvcCatMessaging
	SvcCatCodeHosting  = probe.SvcCatCodeHosting
	SvcCatCDN          = probe.SvcCatCDN
	SvcCatDNSProvider  = probe.SvcCatDNSProvider
	SvcCatPasteShare   = probe.SvcCatPasteShare
	SvcCatCICD         = probe.SvcCatCICD
	SvcCatAPICloud     = probe.SvcCatAPICloud
	SvcCatTunnelVPN    = probe.SvcCatTunnelVPN
	SvcCatContainerReg = probe.SvcCatContainerReg
	SvcCatUnknown      = probe.SvcCatUnknown
)

// ═══════════════════════════════════════════════════════════════════════════
// Probe function re-exports
// ═══════════════════════════════════════════════════════════════════════════

func NormalizeProbeMode(v string) string       { return probe.NormalizeProbeMode(v) }
func ProbeModeLabel(v string) string           { return probe.ProbeModeLabel(v) }
func DefaultProbeMode() string                 { return probe.DefaultProbeMode() }
func DefaultProbeRole() string                 { return probe.DefaultProbeRole() }
func NormalizeProbeRole(v string) string       { return probe.NormalizeProbeRole(v) }
func DefaultProbePorts() []int                 { return probe.DefaultProbePorts() }
func DefaultProtocolNames() []string           { return probe.DefaultProtocolNames() }
func ClassifyProtoKind(proto string) string    { return probe.ClassifyProtoKind(proto) }
func ServiceTargetNames() []string             { return probe.ServiceTargetNames() }
func IsCarrierTunnelMethod(method string) bool { return probe.IsCarrierTunnelMethod(method) }

func RunListenerProbe(ctx context.Context, ports []int, onUpdate func(ListenerProbeResult)) ListenerProbeResult {
	return probe.RunListenerProbe(ctx, ports, onUpdate)
}

// ═══════════════════════════════════════════════════════════════════════════
// Tunnel type aliases
// ═══════════════════════════════════════════════════════════════════════════

type TunnelInput = tunnel.TunnelInput

// ═══════════════════════════════════════════════════════════════════════════
// Tunnel function and variable re-exports
// ═══════════════════════════════════════════════════════════════════════════

func RunTunnel(ctx context.Context, input TunnelInput) tunnel.TunnelResult {
	return tunnel.RunTunnel(ctx, input)
}

func ServiceMethodToProto(service string) string { return tunnel.ServiceMethodToProto(service) }
func ServiceMethodToProtoDeadDrop(service string) string {
	return tunnel.ServiceMethodToProtoDeadDrop(service)
}
func GetServiceKeyExported(service string) string { return tunnel.GetServiceKeyExported(service) }

var UsableServices = tunnel.UsableServices
var DeadDropServices = tunnel.DeadDropServices
