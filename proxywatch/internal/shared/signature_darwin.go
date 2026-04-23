//go:build darwin

package shared

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// performAuthenticodeVerify on darwin runs `codesign -dv --verbose=4`
// against the binary and extracts the Team Identifier + primary
// Authority (Developer ID Application: ...) as the Publisher. An
// intact signature chain plus a Developer ID or Apple-signed Authority
// lands the binary in SignatureTrustTrusted; an explicitly broken
// signature is SignatureTrustUntrusted; anything unverifiable falls
// back to the trusted-path + uid heuristic.
//
// Pure-Go: codesign ships with the base macOS install (/usr/bin/
// codesign). Bounded via context timeout so a hung codesign call
// (network-connected OCSP resolution on a restricted host) can't stall
// the signature-verification worker.
//
// Returned chain is the list of Authority entries in order, suitable
// for the chain UI. ocspSeen remains false because codesign doesn't
// expose OCSP-response-seen state; online-verify evidence on darwin
// comes from the Team Identifier match, not OCSP.
func performAuthenticodeVerify(exePath string) (trust, publisher string, chain []string, ocspSeen bool, err error) {
	exePath = strings.TrimSpace(exePath)
	if exePath == "" {
		return SignatureTrustUnknown, "", nil, false, nil
	}

	trust, publisher, chain = runCodesignDarwin(exePath)
	if trust == SignatureTrustUnknown {
		// Fall back to path + ownership heuristic when codesign has no
		// verdict (binary unsigned, not a recognized bundle, or the
		// subprocess failed). Keeps parity with the Linux fallback so a
		// binary in /usr/bin without a signed bundle still registers as
		// trusted.
		trust, publisher = verifyBinaryTrustDarwin(exePath, publisher)
	}
	return trust, publisher, chain, false, nil
}

// runCodesignDarwin shells out to `codesign -dv --verbose=4 <path>`
// and parses key=value pairs from its stderr output. codesign writes
// signature info to stderr (stdout only carries --display output when
// additional flags are passed). A 3s timeout is enough for cached
// verdicts; uncached / OCSP-resolving codesign can take longer but
// will re-try on the next cycle.
func runCodesignDarwin(exePath string) (trust string, publisher string, chain []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "codesign", "-dv", "--verbose=4", exePath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// codesign writes its verbose output to stderr; CombinedOutput
	// keeps us agnostic to which stream carries the details.
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Exit code 1 on "not signed" is the normal case; exit code 2
		// is broken signature; other errors are transient.
		if exitErr, ok := err.(*exec.ExitError); ok {
			switch exitErr.ExitCode() {
			case 1:
				// "not signed at all" or similar — return unknown so the
				// caller falls through to the heuristic.
				return SignatureTrustUnknown, "", nil
			case 2:
				// Invalid signature.
				return SignatureTrustUntrusted, parseCodesignPublisher(out), parseCodesignAuthorities(out)
			}
		}
		return SignatureTrustUnknown, "", nil
	}

	authorities := parseCodesignAuthorities(out)
	pub := parseCodesignPublisher(out)

	// A successful codesign -dv with at least one Authority line is
	// trusted. Apple's own binaries carry "Authority=Software Signing",
	// third-party binaries carry "Authority=Developer ID Application:
	// <publisher> (<team>)". Either path grants SignatureTrustTrusted.
	if len(authorities) > 0 {
		return SignatureTrustTrusted, pub, authorities
	}
	return SignatureTrustUnknown, pub, authorities
}

// parseCodesignAuthorities returns the Authority chain in output
// order. Example lines:
//
//	Authority=Developer ID Application: Zoom Communications, Inc. (BJ4HAAB9B3)
//	Authority=Developer ID Certification Authority
//	Authority=Apple Root CA
func parseCodesignAuthorities(out []byte) []string {
	var chain []string
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Authority=") {
			chain = append(chain, strings.TrimSpace(strings.TrimPrefix(line, "Authority=")))
		}
	}
	return chain
}

// parseCodesignPublisher extracts the publisher (company) from the
// first "Developer ID Application" Authority line. Falls back to
// TeamIdentifier when the Authority form is missing or when the
// binary is signed with a non-Developer-ID cert (e.g., ad-hoc signed
// or Apple internal).
func parseCodesignPublisher(out []byte) string {
	var teamID string
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Authority=Developer ID Application: ") {
			rest := strings.TrimPrefix(line, "Authority=Developer ID Application: ")
			// Strip trailing " (TEAMID)".
			if i := strings.LastIndex(rest, " ("); i >= 0 {
				rest = rest[:i]
			}
			return strings.TrimSpace(rest)
		}
		if strings.HasPrefix(line, "TeamIdentifier=") {
			teamID = strings.TrimSpace(strings.TrimPrefix(line, "TeamIdentifier="))
		}
	}
	if teamID != "" && teamID != "not set" {
		return "TeamID:" + teamID
	}
	return ""
}

// trustedDarwinPrefixes are absolute paths whose contents are delivered
// by Apple or a common third-party install convention. Used as the
// fallback trust heuristic when codesign has no verdict (unsigned,
// ad-hoc signed, or subprocess failure).
var trustedDarwinPrefixes = []string{
	"/System/", "/Library/Apple/", "/usr/libexec/",
	"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
	"/Applications/",
	"/opt/homebrew/", "/opt/local/",
}

// verifyBinaryTrust is the cheap, cache-friendly sync path called by
// signature.go. Runs only the path + ownership heuristic — no codesign
// subprocess — because the hot path can't afford a shell-out per PID.
// The worker thread (performAuthenticodeVerify above) calls codesign
// asynchronously and updates the richer verdict cache.
func verifyBinaryTrust(exePath string) (string, string) {
	return verifyBinaryTrustDarwin(exePath, "")
}

func verifyBinaryTrustDarwin(exePath, publisherHint string) (string, string) {
	for _, pref := range trustedDarwinPrefixes {
		if strings.HasPrefix(exePath, pref) {
			st, err := os.Stat(exePath)
			if err != nil {
				return SignatureTrustUnknown, publisherHint
			}
			sys, ok := st.Sys().(*syscall.Stat_t)
			if !ok {
				return SignatureTrustUnknown, publisherHint
			}
			// /Applications/ and /opt/homebrew/ are normally user-owned.
			// Elsewhere (system dirs) require root (uid 0).
			if strings.HasPrefix(exePath, "/Applications/") ||
				strings.HasPrefix(exePath, "/opt/homebrew/") ||
				strings.HasPrefix(exePath, "/opt/local/") {
				// Permit any owner; the install-path convention is the
				// trust signal here. Still reject world-writable.
			} else if sys.Uid != 0 {
				return SignatureTrustUntrusted, publisherHint
			}
			if st.Mode().Perm()&0o002 != 0 {
				return SignatureTrustUntrusted, publisherHint
			}
			return SignatureTrustTrusted, publisherHint
		}
	}
	return SignatureTrustUnknown, publisherHint
}
