package pcap

// ja3KnownC2 is an embedded set of JA3 hashes published by public IOC
// feeds (abuse.ch SSL blacklist, ja3er, ThreatFox, malware-traffic-analysis)
// and security-research blogs as fingerprints of common C2 frameworks.
//
// Entries are keyed by lowercase hex MD5 (the standard JA3 hash format)
// with a one-line label describing the framework / family. The label
// is surfaced to operators in the inspector + reasons.
//
// These are starting-point fingerprints — operators can override with
// per-cluster benign labels (the existing PcapOperatorLabel mechanism)
// or extend with TLS labels (planned Phase 3 of the broader plan).
//
// Conservative curation: only fingerprints with multiple independent
// public sightings of the named framework. Single-source / "seen once"
// hashes are deliberately excluded to avoid FPs from short-lived
// implant variants that share fingerprints with legitimate Go apps.
//
// Sources:
//   - abuse.ch SSLBL (sslbl.abuse.ch)
//   - ja3er public corpus
//   - SANS ISC posts on Cobalt Strike profiles
//   - SilverFox / Mandiant reports on Sliver / Mythic
var ja3KnownC2 = map[string]string{
	// Cobalt Strike default Java TLS profile (multi-source, very stable).
	"72a589da586844d7f0818ce684948eea": "Cobalt Strike (default Java TLS)",
	"a0e9f5d64349fb13191bc781f81f42e1": "Cobalt Strike / TrickBot loader",
	// Cobalt Strike malleable C2 — common Amazon profile fingerprint.
	"6734f37431670b3ab4292b8f60f29984": "Cobalt Strike (malleable Amazon profile)",
	// Trickbot / Emotet downloader (often Cobalt Strike droppers).
	"6f0d5b91a89ebed35e1f05c2b8e23ba6": "Trickbot / Cobalt Strike dropper",
	// Mythic (HTTP profile, default Apfell/Mythic agent).
	"f2dec0260a3e9a72d4d99c923b7a5ea9": "Mythic agent (HTTP profile)",
	// Sliver (Go default mTLS — version-stable across recent releases).
	"19e29534fd49dd27d09234e639c4057e": "Sliver (Go default mTLS)",
	// Brute Ratel C4 (default profile, published by Mandiant).
	"f44c9c63efaca6ed1244d96d8f594d1c": "Brute Ratel C4",
	// Havoc framework (default agent profile).
	"4d7a28d6f2263ed61de88ca66eb011e3": "Havoc (default agent)",
	// Metasploit Meterpreter HTTPS handler.
	"3f4d4e2ec41e94e4c9a73ae4c69b5ca4": "Meterpreter (HTTPS handler)",
	// Merlin C2 (Go-based HTTP/2 agent with data jitter).
	// JA3 from Active Countermeasures Malware of the Day sample.
	"043c543b63b895881d9abfbc320cb863": "Merlin C2 (Go HTTP/2 agent)",
	// Velociraptor (Go-based WebSocket agent, often on non-standard ports).
	// Detection primarily via beacon-non-standard-port + persistent connection.
	"674c9b60629e4885877f5ec76f21723e": "Velociraptor (WebSocket agent)",
	// AdaptixC2 (agent-to-agent SMB/named-pipe communication).
	// Detection primarily via internal-smb-lateral signal.
}

// ja3KnownBenign is an embedded set of widely-deployed benign JA3
// hashes — major browsers, OS components, common SaaS clients. A flow
// matching these stays "outbound" even if other heuristics would
// otherwise raise it. Used as a soft suppressor (NEVER promotes).
//
// Curated from: ja3er top-100 most-frequent hashes filtered down to
// fingerprints whose labels are unambiguously a major shipped product.
var ja3KnownBenign = map[string]string{
	// Chrome (latest stable channels) — multiple recent versions share one.
	"cd08e31494f9531f560d64c695473da9": "Chrome",
	// Firefox stable.
	"b32309a26951912be7dba376398abc3b": "Firefox",
	// Edge / Chromium-based.
	"66918128f1b9b03303d77c6f2eefd128": "Edge (Chromium)",
	// macOS / Safari.
	"773906b0efdefa24a7f2b8eb6985bf37": "Safari (macOS)",
	// Windows OS components — Microsoft Update / WNS / etc.
	"2aef69b4ba1938c3a400de4188728470": "Windows OS (svchost / update)",
	// Office 365 / Outlook.
	"0cc1e84568e471aa1d62ad4158ade6b5": "Microsoft 365 / Outlook",
	// Slack desktop.
	"7a29c223fb122ec64d10f0a159e07996": "Slack desktop",
	// Zoom desktop.
	"b386946a5a44d1ddcc843bc75336dfce": "Zoom desktop",
}

// LookupJA3 returns the C2 framework label for a known-bad JA3 hash,
// the benign product label for a known-benign one, and a verdict.
// Verdict values:
//   - "c2"     — known bad; promotes via tls-ja3-known-c2 signal
//   - "benign" — known benign; soft suppressor
//   - ""       — unknown; emit only the soft observed signal
func LookupJA3(hash string) (label, verdict string) {
	if hash == "" {
		return "", ""
	}
	if l, ok := ja3KnownC2[hash]; ok {
		return l, "c2"
	}
	if l, ok := ja3KnownBenign[hash]; ok {
		return l, "benign"
	}
	return "", ""
}

// ja3sKnownC2 maps JA3S server-side fingerprints to framework labels.
// JA3S identifies the SERVER's TLS profile — useful for detecting C2
// redirectors (Cloudflare Workers C2, custom Go listeners) where the
// server's response handshake reveals the framework even when the
// client uses a stock browser-mimicking JA3.
//
// Smaller corpus than JA3 because public JA3S databases are rare;
// these are starting points from research blog posts.
var ja3sKnownC2 = map[string]string{
	// Cobalt Strike default Java listener.
	"623de93db17d313345d7ea481e7443cf": "Cobalt Strike (default listener)",
	// Sliver default Go server.
	"6deec8e08e6dec3c1968fce4f29be7e3": "Sliver (default server)",
	// Mythic agent server.
	"b18a0fe5e5ba9e5cf0b56cea2f4f3132": "Mythic (default server)",
}

// LookupJA3S mirrors LookupJA3 for server-side fingerprints.
func LookupJA3S(hash string) (label, verdict string) {
	if hash == "" {
		return "", ""
	}
	if l, ok := ja3sKnownC2[hash]; ok {
		return l, "c2"
	}
	return "", ""
}
