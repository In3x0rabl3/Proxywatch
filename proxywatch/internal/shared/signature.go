package shared

import (
	"strings"
	"sync"
)

// Signature trust levels returned by VerifyBinaryTrust.
const (
	SignatureTrustTrusted   = "trusted"
	SignatureTrustUntrusted = "untrusted"
	SignatureTrustUnsigned  = "unsigned"
	SignatureTrustUnknown   = "unknown"
)

// SignatureTrustedReason is the sentinel string appended to c.Reasons when
// the signature-trust path contributes to a suppression decision. Exported
// for /fp-report and tests.
const SignatureTrustedReason = "vendor-signed-trusted"

type signatureVerdict struct {
	Trust     string
	Publisher string
}

var (
	sigCacheMu sync.RWMutex
	sigCache   = map[string]signatureVerdict{}
)

// VerifyBinaryTrust returns a best-effort signature-trust level plus the
// publisher string for an executable path. Results are cached keyed by
// path for the lifetime of the process — binary contents at a given path
// are assumed stable for the scan window.
//
// Platform specifics:
//   - Linux: verifyBinaryTrustUnix — path under a distro-owned prefix AND
//     root-owned AND not world-writable. Cheap, no shell-outs. Does NOT
//     yet consult dpkg/rpm; that is deferred to a follow-up.
//   - macOS: verifyBinaryTrustUnix — same heuristic as Linux, plus
//     /Applications and /System recognized as trusted prefixes. Does NOT
//     yet consult codesign/spctl; deferred to a follow-up.
//   - Windows: verifyBinaryTrustWindows — stub returning SignatureTrustUnknown
//     until WinVerifyTrust / WinTrust is wired. Path+owner checks on NTFS
//     are not a safe substitute for authenticode.
//
// Callers (telemetry readers) should populate Proc.SignatureTrust + Proc.Signed
// from the returned verdict; Publisher is returned separately so callers can
// prefer an existing Company field when populated.
func VerifyBinaryTrust(exePath string) (trust string, publisher string) {
	exePath = strings.TrimSpace(exePath)
	if exePath == "" {
		return SignatureTrustUnknown, ""
	}
	sigCacheMu.RLock()
	if v, ok := sigCache[exePath]; ok {
		sigCacheMu.RUnlock()
		return v.Trust, v.Publisher
	}
	sigCacheMu.RUnlock()

	t, p := verifyBinaryTrust(exePath)
	if t == "" {
		t = SignatureTrustUnknown
	}

	sigCacheMu.Lock()
	sigCache[exePath] = signatureVerdict{Trust: t, Publisher: p}
	sigCacheMu.Unlock()
	return t, p
}
