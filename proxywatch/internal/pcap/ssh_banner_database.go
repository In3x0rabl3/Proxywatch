package pcap

import "strings"

// sshBannerC2Patterns lists software-version substrings that strongly
// indicate a C2 framework or implant-style SSH endpoint rather than a
// stock OS / vendor SSH server.
//
// Matching is case-INsensitive substring against the software-version
// token (everything after "SSH-2.0-" / "SSH-1.99-" / etc.). Substring
// is the right granularity because frameworks append version + build
// suffixes that change per release, but the framework name stays.
//
// FP-safety: these are framework defaults that operators rarely change.
// The match is reported as a soft signal (`ssh-banner-c2-shape`) UNLESS
// it matches one of the high-confidence framework names below — those
// upgrade to a decisive signal via the gate in ssh_enrich.go.
//
// References:
//   - Sliver default Go SSH: "Go" build banner with Sliver agent token
//   - Cobalt Strike default SSH listener: "CobaltStrike" or "BeaconCS"
//   - Mythic Apollo / Athena agents over SSH: "Apollo" / "Athena"
//   - Brute Ratel C4 SSH: "BruteRatel"
//   - Havoc demon SSH: "Havoc" or "HavocDemon"
//   - Dropbear on a Windows host = strong pivot signal (it's an
//     embedded-device server, never legitimate on Windows)
var sshBannerC2Patterns = map[string]string{
	"sliver":       "Sliver agent",
	"cobaltstrike": "Cobalt Strike",
	"beaconcs":     "Cobalt Strike beacon",
	"mythic":       "Mythic agent",
	"apollo":       "Mythic Apollo agent",
	"athena":       "Mythic Athena agent",
	"bruteratel":   "Brute Ratel C4",
	"havoc":        "Havoc framework",
	"havocdemon":   "Havoc demon",
	"meterpreter":  "Metasploit Meterpreter",
	// Additional C2 and tunneling tools
	"chisel":    "Chisel tunnel",
	"ligolo":    "Ligolo-ng agent",
	"poshc2":    "PoshC2 implant",
	"covenant":  "Covenant Grunt",
	"empire":    "Empire agent",
	"merlin":    "Merlin C2 agent",
	"nighthawk": "Nighthawk agent",
	"gost":      "GOST tunnel",
	"frp":       "FRP reverse proxy",
	"ngrok":     "Ngrok tunnel",
	"rathole":   "Rathole tunnel",
}

// sshBannerBenignPatterns lists software-version substrings that mark
// the banner as definitively a stock OS / vendor SSH server. Used as a
// soft suppressor: even if other heuristics raise the cluster, a banner
// match here keeps the role at "outbound" / "listen" by emitting
// `ssh-banner-known-benign` (informational; non-promoting).
var sshBannerBenignPatterns = map[string]string{
	"openssh":             "OpenSSH (stock)",
	"libssh":              "libssh client",
	"paramiko":            "Paramiko (Python)",
	"jschssh":             "JSch (Java)",
	"go-ssh":              "golang.org/x/crypto/ssh client",
	"putty":               "PuTTY (Windows client)",
	"winscp":              "WinSCP",
	"filezilla":           "FileZilla",
	"openssh_for_windows": "OpenSSH for Windows",
}

// LookupSSHBanner returns the C2 framework label, benign vendor label,
// and verdict for a banner's software-version token. Verdict values:
//   - "c2"     — known-bad framework default
//   - "benign" — stock OS / vendor SSH client/server
//   - ""       — unknown banner; emit only the soft observed signal
//
// Note: Dropbear is NOT in either map by default because Dropbear on a
// Linux router/IoT device is benign, but Dropbear on a Windows host is
// a strong pivot signal. The host-side context lives in the enrich
// pass, not the lookup table.
func LookupSSHBanner(software string) (label, verdict string) {
	if software == "" {
		return "", ""
	}
	low := strings.ToLower(software)
	for needle, name := range sshBannerC2Patterns {
		if strings.Contains(low, needle) {
			return name, "c2"
		}
	}
	for needle, name := range sshBannerBenignPatterns {
		if strings.Contains(low, needle) {
			return name, "benign"
		}
	}
	return "", ""
}
