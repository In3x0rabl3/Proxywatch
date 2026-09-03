//go:build windows

package pcap

import (
	"os"
	"syscall"
)

// openSharedRead opens path for reading on Windows with the file
// sharing flags set so other processes can keep WRITING and DELETING
// the file while we hold the handle.
//
// Plain os.Open on Windows uses FILE_SHARE_READ only — that is
// enough for two readers but blocks any writer from extending the
// file. WinDump's per-packet append fails silently and the pcap
// stays at its initial size (24-byte header only). Setting
// FILE_SHARE_WRITE lets WinDump grow the file while pcapgo's
// tail reader follows along.
//
// FILE_SHARE_DELETE is included so the operator can stop windump
// (which closes its handle, sometimes via deletion of a temp file
// during rotation) without our handle blocking the cleanup.
func openSharedRead(path string) (*os.File, error) {
	pathp, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	const shareMode = syscall.FILE_SHARE_READ |
		syscall.FILE_SHARE_WRITE |
		syscall.FILE_SHARE_DELETE
	h, err := syscall.CreateFile(
		pathp,
		syscall.GENERIC_READ,
		shareMode,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}
