//go:build linux || darwin

package shared

import (
	"os"
	"strings"
	"syscall"
)

// performAuthenticodeVerify has no Authenticode analogue on unix — we
// delegate to the existing path+ownership heuristic so the shared worker
// path is uniform. Returns no chain subjects and ocspSeen=false.
func performAuthenticodeVerify(exePath string) (trust, publisher string, chain []string, ocspSeen bool, err error) {
	t, p := verifyBinaryTrust(exePath)
	return t, p, nil, false, nil
}

// trustedUnixPrefixes are absolute paths whose contents are delivered by the
// OS vendor or a distro package manager on a typical install. Binaries here,
// when root-owned and non-world-writable, are treated as signed-trusted
// pending a proper dpkg/rpm/codesign integration.
var trustedUnixPrefixes = []string{
	"/usr/bin/", "/usr/sbin/", "/usr/libexec/",
	"/usr/lib/", "/usr/lib32/", "/usr/lib64/",
	"/bin/", "/sbin/",
	"/lib/", "/lib32/", "/lib64/",
	"/opt/",
	"/snap/",
	"/nix/store/",
	// macOS:
	"/System/", "/Applications/",
	"/Library/Apple/",
}

func verifyBinaryTrust(exePath string) (string, string) {
	for _, pref := range trustedUnixPrefixes {
		if strings.HasPrefix(exePath, pref) {
			st, err := os.Stat(exePath)
			if err != nil {
				return SignatureTrustUnknown, ""
			}
			sys, ok := st.Sys().(*syscall.Stat_t)
			if !ok {
				return SignatureTrustUnknown, ""
			}
			if sys.Uid != 0 {
				return SignatureTrustUntrusted, ""
			}
			if st.Mode().Perm()&0o002 != 0 {
				return SignatureTrustUntrusted, ""
			}
			return SignatureTrustTrusted, ""
		}
	}
	return SignatureTrustUnknown, ""
}
