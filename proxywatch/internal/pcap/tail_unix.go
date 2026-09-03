//go:build !windows

package pcap

import "os"

// openSharedRead opens path read-only. POSIX file sharing has no
// concept of an exclusive-by-default lock, so plain os.Open already
// allows other processes to keep writing — no platform shim needed.
func openSharedRead(path string) (*os.File, error) {
	return os.Open(path)
}
