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
	ProcEnumProcessModules   = ModPsapi.NewProc("EnumProcessModules")
	ProcGetModuleFileNameExW = ModPsapi.NewProc("GetModuleFileNameExW")

	IPHlpapi           = windows.NewLazySystemDLL("iphlpapi.dll")
	ProcGetExtendedTcp = IPHlpapi.NewProc("GetExtendedTcpTable")
	ProcGetExtendedUdp = IPHlpapi.NewProc("GetExtendedUdpTable")

	ModNtdll                      = windows.NewLazySystemDLL("ntdll.dll")
	ProcNtQueryInformationProcess = ModNtdll.NewProc("NtQueryInformationProcess")
	ProcNtQuerySystemInformation  = ModNtdll.NewProc("NtQuerySystemInformation")
	ProcNtQueryObject             = ModNtdll.NewProc("NtQueryObject")

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

	// NtQueryInformationProcess info classes
	ProcessBasicInformation = 0
	ProcessCommandLineInfo  = 60

	// NtQuerySystemInformation classes
	SystemHandleInformation = 16

	// NtQueryObject classes
	ObjectTypeInformation = 2

	// TCP states for SYN_SENT detection
	MIB_TCP_STATE_SYN_SENT = 3
)

// UnicodeString matches the Windows UNICODE_STRING structure.
type UnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}

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

// SystemHandleEntry is a single handle row from NtQuerySystemInformation.
type SystemHandleEntry struct {
	OwnerPID       uint16
	CreatorBackRef uint16
	HandleType     uint8
	Flags          uint8
	Handle         uint16
	Object         uintptr
	GrantedAccess  uint32
}
