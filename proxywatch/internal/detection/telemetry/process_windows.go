//go:build windows
// +build windows

package telemetry

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"proxywatch/internal/shared"

	"golang.org/x/sys/windows"
)

func GetProcessInfoMap() (map[int]*shared.ProcessInfo, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := windows.Process32First(snap, &entry); err != nil {
		return nil, err
	}

	procs := make(map[int]*shared.ProcessInfo)

	now := time.Now().UTC()
	for {
		pid := int(entry.ProcessID)
		if pid != 0 {
			name := strings.ToLower(strings.TrimSpace(windows.UTF16ToString(entry.ExeFile[:])))

			pi := &shared.ProcessInfo{
				Pid:         pid,
				ParentPid:   int(entry.ParentProcessID),
				Name:        name,
				Status:      "Running",
				ThreadCount: int(entry.Threads),
			}

			meta, metaOK := getCachedMeta(pid, now)
			if metaOK {
				applyCachedMeta(pi, meta)
			}

			const fullAccess = windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_READ
			h, err := windows.OpenProcess(fullAccess, false, uint32(pid))
			fullHandle := err == nil
			if !fullHandle {
				h, err = windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
			}
			if err == nil {
				fillTimes(h, pi)
				fillMemory(h, pi)
				fillIOCounters(h, pi)
				fillCmdLine(h, pi)
				fillHandleCount(h, pi)
				if !metaOK {
					fillExePath(h, pi)
					// fillLoadedLibs is DISABLED on Windows: EnumProcessModulesEx
					// hangs indefinitely on protected service hosts (svchost)
					// in certain Windows states. The naive timeout-goroutine
					// approach is unsafe because the main path closes the
					// handle the goroutine is mid-syscall on. Until we land a
					// safe handle-duplicating wrapper, skip loaded-libs
					// enumeration; we lose the beacon-crypto-lib-loaded signal
					// but gain a responsive scanner. Other role detection
					// (tunnel flags, named pipes, ASN, traffic patterns) is
					// unaffected.
					fillUser(h, pi)
					fillIntegrity(h, pi)
					fillTokenDetails(h, pi)
					fillCompany(pi)
					// fillSignatureTrust is safe in cache-only posture
					// (default): it only consults the in-memory verdict
					// cache and enqueues lookups. The hang we saw earlier
					// was exclusively in fillLoadedLibs's
					// EnumProcessModulesEx call on protected service
					// hosts — unrelated to signature verification.
					fillSignatureTrust(pi)
					// SHA256 — async-cached, same flow as Linux. Feeds
					// operator-label lookup (Phase 9). First observation
					// returns ""; next cycle picks up the computed hash.
					pi.SHA256 = shared.LookupExeSHA256(pi.ExePath)
				}
				windows.CloseHandle(h)
			}

			if !metaOK {
				fillSession(pi)
				cacheMeta(pid, pi, now)
			}
			procs[pid] = pi
		}

		if err := windows.Process32Next(snap, &entry); err != nil {
			break
		}
	}

	// Build child process map from PPIDs.
	childrenByPPID := make(map[int][]int)
	for pid, proc := range procs {
		if proc.ParentPid > 0 {
			childrenByPPID[proc.ParentPid] = append(childrenByPPID[proc.ParentPid], pid)
		}
	}
	for pid, proc := range procs {
		children := childrenByPPID[pid]
		proc.ChildCount = len(children)
		if len(children) > 50 {
			children = children[:50]
		}
		proc.ChildPids = children
		procs[pid] = proc
	}

	return procs, nil
}

/* --- helpers --- */

func fillHandleCount(h windows.Handle, pi *shared.ProcessInfo) {
	var count uint32
	r, _, _ := ProcGetProcessHandleCount.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&count)),
	)
	if r != 0 {
		pi.HandleCount = int(count)
	}
}

func fillTokenDetails(h windows.Handle, pi *shared.ProcessInfo) {
	var token windows.Token
	if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token) != nil {
		return
	}
	defer token.Close()

	// Token type: Primary vs Impersonation
	var tokenType uint32
	var returnLen uint32
	err := windows.GetTokenInformation(token, windows.TokenType, (*byte)(unsafe.Pointer(&tokenType)), 4, &returnLen)
	if err == nil {
		switch tokenType {
		case 1:
			pi.TokenType = "Primary"
		case 2:
			pi.TokenType = "Impersonation"
		}
	}

	// Elevation type: Full, Limited, Default
	var elevType uint32
	err = windows.GetTokenInformation(token, windows.TokenElevationType, (*byte)(unsafe.Pointer(&elevType)), 4, &returnLen)
	if err == nil {
		switch elevType {
		case 2:
			pi.ElevationType = "Full"
		case 3:
			pi.ElevationType = "Limited"
		}
	}
}

func fillTimes(h windows.Handle, pi *shared.ProcessInfo) {
	var c, e, k, u windows.Filetime
	if r, _, _ := ProcGetProcessTimes.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&c)),
		uintptr(unsafe.Pointer(&e)),
		uintptr(unsafe.Pointer(&k)),
		uintptr(unsafe.Pointer(&u)),
	); r == 0 {
		return
	}

	pi.CpuTime = filetimeToDuration(k) + filetimeToDuration(u)
	// Extract process creation time from the creation filetime.
	pi.StartTime = time.Unix(0, c.Nanoseconds())
}

func fillMemory(h windows.Handle, pi *shared.ProcessInfo) {
	var pmc ProcessMemoryCounters
	pmc.Cb = uint32(unsafe.Sizeof(pmc))

	if r, _, _ := ProcGetProcessMemoryInfo.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&pmc)),
		uintptr(pmc.Cb),
	); r != 0 {
		pi.MemUsage = uint64(pmc.WorkingSetSize)
	}
}

func fillIOCounters(h windows.Handle, pi *shared.ProcessInfo) {
	var io windows.IO_COUNTERS
	if r, _, _ := ProcGetProcessIoCounters.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&io)),
	); r != 0 {
		pi.IOReadBytes = io.ReadTransferCount
		pi.IOWriteBytes = io.WriteTransferCount
		pi.IOOtherBytes = io.OtherTransferCount
	}
}

func fillSession(pi *shared.ProcessInfo) {
	var sid uint32
	if r, _, _ := ProcProcessIdToSessionId.Call(
		uintptr(uint32(pi.Pid)),
		uintptr(unsafe.Pointer(&sid)),
	); r != 0 {
		pi.SessionID = sid
		if sid == 0 {
			pi.SessionName = "Console"
		} else {
			pi.SessionName = fmt.Sprintf("Session-%d", sid)
		}
	}
}

func fillUser(h windows.Handle, pi *shared.ProcessInfo) {
	var token windows.Token
	if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token) != nil {
		return
	}
	defer token.Close()

	tu, err := token.GetTokenUser()
	if err != nil || tu.User.Sid == nil {
		return
	}

	name, domain, _, err := tu.User.Sid.LookupAccount("")
	if err != nil {
		return
	}

	if domain != "" {
		pi.UserName = domain + `\` + name
	} else {
		pi.UserName = name
	}
}

func fillExePath(h windows.Handle, pi *shared.ProcessInfo) {
	if pi.ExePath != "" {
		return
	}

	size := uint32(260)
	for i := 0; i < 4; i++ {
		buf := make([]uint16, size)
		sz := size
		err := windows.QueryFullProcessImageName(h, 0, &buf[0], &sz)
		if err == nil {
			if sz > 0 {
				pi.ExePath = windows.UTF16ToString(buf[:sz])
			}
			return
		}
		if size < 32768 && err == windows.ERROR_INSUFFICIENT_BUFFER {
			size *= 2
			continue
		}
		return
	}
}

func fillIntegrity(h windows.Handle, pi *shared.ProcessInfo) {
	var token windows.Token
	if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token) != nil {
		return
	}
	defer token.Close()

	ilevel := tokenIntegrity(token)
	if ilevel != "" {
		pi.Integrity = ilevel
	}
}

func getCachedMeta(pid int, now time.Time) (shared.ProcessMeta, bool) {
	return shared.ProcMetaCache.Get(pid, now)
}

func applyCachedMeta(pi *shared.ProcessInfo, meta shared.ProcessMeta) {
	pi.UserName = meta.UserName
	pi.ExePath = meta.ExePath
	pi.Company = meta.Company
	pi.Integrity = meta.Integrity
	pi.SessionID = meta.SessionID
	pi.SessionName = meta.SessionName
}

func cacheMeta(pid int, pi *shared.ProcessInfo, now time.Time) {
	shared.ProcMetaCache.Set(pid, shared.ProcessMeta{
		UserName:    pi.UserName,
		ExePath:     pi.ExePath,
		Company:     pi.Company,
		Integrity:   pi.Integrity,
		SessionID:   pi.SessionID,
		SessionName: pi.SessionName,
		FetchedAt:   now,
	})
}

func fillCompany(pi *shared.ProcessInfo) {
	if pi.ExePath == "" {
		return
	}

	company, err := queryCompanyName(pi.ExePath)
	if err != nil || company == "" {
		return
	}
	pi.Company = company
}

// fillSignatureTrust calls the shared cross-platform verifier. The Windows
// implementation is currently a stub returning Unknown — see
// shared/signature_windows.go for the WinVerifyTrust TODO.
func fillSignatureTrust(pi *shared.ProcessInfo) {
	if pi == nil || pi.ExePath == "" {
		return
	}
	trust, _ := shared.VerifyBinaryTrust(pi.ExePath)
	pi.SignatureTrust = trust
	pi.Signed = trust == shared.SignatureTrustTrusted
}

func queryCompanyName(path string) (string, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}

	var handle uint32
	size, _, _ := ProcGetFileVersionInfoSize.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&handle)),
	)
	if size == 0 {
		return "", fmt.Errorf("version info size is 0")
	}

	buf := make([]byte, int(size))
	r1, _, _ := ProcGetFileVersionInfo.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		0,
		uintptr(size),
		uintptr(unsafe.Pointer(&buf[0])),
	)
	if r1 == 0 {
		return "", fmt.Errorf("GetFileVersionInfo failed")
	}

	lang, codepage, err := queryVersionTranslation(buf)
	if err != nil {
		return "", err
	}

	query := fmt.Sprintf("\\StringFileInfo\\%04x%04x\\CompanyName", lang, codepage)
	return queryVersionString(buf, query)
}

func queryVersionTranslation(buf []byte) (uint16, uint16, error) {
	subBlock, err := windows.UTF16PtrFromString(`\VarFileInfo\Translation`)
	if err != nil {
		return 0, 0, err
	}

	var valuePtr uintptr
	var valueLen uint32
	r0, _, _ := ProcVerQueryValue.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(subBlock)),
		uintptr(unsafe.Pointer(&valuePtr)),
		uintptr(unsafe.Pointer(&valueLen)),
	)
	if r0 == 0 || valueLen < 4 {
		return 0, 0, fmt.Errorf("no translation")
	}

	lang := *(*uint16)(unsafe.Pointer(valuePtr))
	codepage := *(*uint16)(unsafe.Pointer(valuePtr + unsafe.Sizeof(lang)))
	return lang, codepage, nil
}

func queryVersionString(buf []byte, query string) (string, error) {
	queryPtr, err := windows.UTF16PtrFromString(query)
	if err != nil {
		return "", err
	}

	var valuePtr uintptr
	var valueLen uint32
	r0, _, _ := ProcVerQueryValue.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(queryPtr)),
		uintptr(unsafe.Pointer(&valuePtr)),
		uintptr(unsafe.Pointer(&valueLen)),
	)
	if r0 == 0 || valueLen == 0 {
		return "", fmt.Errorf("no value")
	}

	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(valuePtr))), nil
}

func tokenIntegrity(token windows.Token) string {
	var outLen uint32
	buf := make([]byte, 256)

	for {
		err := windows.GetTokenInformation(token, windows.TokenIntegrityLevel, &buf[0], uint32(len(buf)), &outLen)
		if err == nil {
			break
		}
		if err != windows.ERROR_INSUFFICIENT_BUFFER || outLen == 0 {
			return ""
		}
		buf = make([]byte, outLen)
	}

	tml := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0]))
	if tml.Label.Sid == nil {
		return ""
	}

	sidStr := tml.Label.Sid.String()
	if sidStr == "" {
		return ""
	}
	parts := strings.Split(sidStr, "-")
	if len(parts) == 0 {
		return ""
	}
	rid, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		return ""
	}

	switch rid {
	case 0x0000:
		return "Untrusted"
	case 0x1000:
		return "Low"
	case 0x2000:
		return "Medium"
	case 0x2100:
		return "MediumPlus"
	case 0x3000:
		return "High"
	case 0x4000:
		return "System"
	case 0x5000:
		return "Protected"
	default:
		return fmt.Sprintf("0x%X", rid)
	}
}

func filetimeToDuration(ft windows.Filetime) time.Duration {
	v := (uint64(ft.HighDateTime) << 32) | uint64(ft.LowDateTime)
	return time.Duration(v * 100)
}

func fillCmdLine(h windows.Handle, pi *shared.ProcessInfo) {
	// ProcessCommandLineInformation (class 60) available on Windows 10+.
	// Returns UNICODE_STRING with the full command line.
	buf := make([]byte, 2048)
	var retLen uint32
	r, _, _ := ProcNtQueryInformationProcess.Call(
		uintptr(h),
		uintptr(ProcessCommandLineInfo),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if r != 0 || retLen < 4 {
		return
	}
	us := (*UnicodeString)(unsafe.Pointer(&buf[0]))
	if us.Length == 0 || us.Buffer == 0 {
		return
	}
	charCount := int(us.Length) / 2
	if charCount > 512 {
		charCount = 512
	}
	chars := unsafe.Slice((*uint16)(unsafe.Pointer(us.Buffer)), charCount)
	pi.CmdLine = strings.TrimSpace(windows.UTF16ToString(chars))
}

