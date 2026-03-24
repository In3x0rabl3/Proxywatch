//go:build windows
// +build windows

package platform

import "golang.org/x/sys/windows"

var (
	ModKernel32              = windows.NewLazySystemDLL("kernel32.dll")
	ProcGetProcessTimes      = ModKernel32.NewProc("GetProcessTimes")
	ProcGetProcessIoCounters = ModKernel32.NewProc("GetProcessIoCounters")
	ProcProcessIdToSessionId = ModKernel32.NewProc("ProcessIdToSessionId")
	ModPsapi                 = windows.NewLazySystemDLL("psapi.dll")
	ProcGetProcessMemoryInfo = ModPsapi.NewProc("GetProcessMemoryInfo")

	IPHlpapi           = windows.NewLazySystemDLL("iphlpapi.dll")
	ProcGetExtendedTcp = IPHlpapi.NewProc("GetExtendedTcpTable")
	ProcGetExtendedUdp = IPHlpapi.NewProc("GetExtendedUdpTable")

	ModVersion                 = windows.NewLazySystemDLL("version.dll")
	ProcGetFileVersionInfoSize = ModVersion.NewProc("GetFileVersionInfoSizeW")
	ProcGetFileVersionInfo     = ModVersion.NewProc("GetFileVersionInfoW")
	ProcVerQueryValue          = ModVersion.NewProc("VerQueryValueW")
)

const (
	AF_INET                 = 2
	AF_INET6                = 23
	TCP_TABLE_OWNER_PID_ALL = 5
	UDP_TABLE_OWNER_PID     = 1
)

type ProcessMemoryCounters struct {
	Cb             uint32
	WorkingSetSize uintptr
}

type MIBTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

type MIBTCP6RowOwnerPID struct {
	State         uint32
	LocalAddr     [16]byte
	LocalScopeId  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeId uint32
	RemotePort    uint32
	OwningPID     uint32
}

type MIBUDPROwnerPID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPID uint32
}

type MIBUDP6OwnerPID struct {
	LocalAddr    [16]byte
	LocalScopeId uint32
	LocalPort    uint32
	OwningPID    uint32
}
