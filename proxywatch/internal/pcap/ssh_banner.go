package pcap

import (
	"bytes"
	"strings"
)

// SSHBanner captures the SSH protocol banner from one side of an SSH
// flow. The banner is the first line each peer sends per RFC 4253:
//
//	SSH-protoversion-softwareversion SP comments CR LF
//
// We extract the software-version token (e.g. "OpenSSH_8.9p1") and the
// raw banner string. The banner is sent before any TLS-like handshake,
// so it sits in the clear at flow head — making it the simplest passive
// fingerprint signal SSH offers.
type SSHBanner struct {
	Raw      string
	Software string // software-version token, e.g. "OpenSSH_8.9p1"
}

// parseSSHBanner extracts the SSH banner from a TCP payload that begins
// with the bytes "SSH-". Returns nil for non-SSH payloads or banners
// that don't terminate within the first 256 bytes (RFC 4253 caps the
// banner line at 255 bytes, anything longer is not a real SSH peer).
func parseSSHBanner(data []byte) *SSHBanner {
	if len(data) < 4 || !bytes.HasPrefix(data, []byte("SSH-")) {
		return nil
	}
	limit := len(data)
	if limit > 256 {
		limit = 256
	}
	idx := bytes.IndexByte(data[:limit], '\n')
	if idx < 0 {
		return nil
	}
	line := string(data[:idx])
	line = strings.TrimRight(line, "\r")
	// RFC 4253 §4.2: SSH-protoversion-softwareversion SP comments
	// We split off the comments after the first space.
	primary := line
	if sp := strings.IndexByte(line, ' '); sp >= 0 {
		primary = line[:sp]
	}
	parts := strings.SplitN(primary, "-", 3)
	if len(parts) < 3 {
		return &SSHBanner{Raw: line}
	}
	return &SSHBanner{
		Raw:      line,
		Software: parts[2],
	}
}

// shouldAttemptSSHParse gates the parser cheaply on the magic prefix.
// Port-agnostic — Sliver / custom C2 frameworks frequently expose SSH
// listeners on non-22 ports, so we accept any flow whose first bytes
// look like an SSH banner.
func shouldAttemptSSHParse(payload []byte) bool {
	return len(payload) >= 4 && bytes.HasPrefix(payload, []byte("SSH-"))
}
