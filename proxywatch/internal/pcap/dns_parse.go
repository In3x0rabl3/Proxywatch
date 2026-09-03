package pcap

import (
	"encoding/binary"
	"math"
	"strings"
)

// DNSPacket captures the operator-relevant fields from a single DNS
// query or response packet. Only fields needed for DGA / tunneling
// detection are extracted — full RR parsing is intentionally avoided
// to keep the per-packet cost low.
type DNSPacket struct {
	IsResponse  bool
	QueryName   string
	QueryType   uint16
	PayloadSize int // total UDP payload length, used for query/response byte volume tracking
}

// parseDNSPacket parses a UDP payload as a DNS message. Returns nil
// when the bytes don't look like a DNS message (header too short,
// malformed, or not a query/response). Defensive against truncation:
// any parse failure mid-name simply returns whatever was extracted.
func parseDNSPacket(payload []byte) *DNSPacket {
	if len(payload) < 12 {
		return nil
	}
	flags := binary.BigEndian.Uint16(payload[2:4])
	qdcount := binary.BigEndian.Uint16(payload[4:6])
	if qdcount == 0 {
		return &DNSPacket{
			IsResponse:  flags&0x8000 != 0,
			PayloadSize: len(payload),
		}
	}
	// Parse the FIRST question's name — that's the operator-relevant
	// part for DGA / tunneling detection. Compression pointers (the
	// 0xC0 prefix at the start of a label length byte) are NOT followed
	// here because question-section names aren't compressed per RFC 1035.
	pos := 12
	var labels []string
	for pos < len(payload) {
		if pos >= len(payload) {
			break
		}
		l := int(payload[pos])
		pos++
		if l == 0 {
			break
		}
		// Compression pointer (top two bits set) in a question name =
		// malformed per RFC 1035 §4.1.4. Bail. Note: the check is
		// `== 0xC0` (BOTH high bits set), not `!= 0`. The reserved
		// patterns 01 and 10 are also illegal but extremely rare; we
		// treat them as compression-pointer-equivalent to be safe.
		if l&0xC0 == 0xC0 {
			return &DNSPacket{
				IsResponse:  flags&0x8000 != 0,
				PayloadSize: len(payload),
			}
		}
		// RFC 1035 caps label length at 63. Anything bigger is malformed
		// or a non-DNS UDP packet; abort.
		if l > 63 {
			return &DNSPacket{
				IsResponse:  flags&0x8000 != 0,
				PayloadSize: len(payload),
			}
		}
		if pos+l > len(payload) {
			return &DNSPacket{
				IsResponse:  flags&0x8000 != 0,
				QueryName:   strings.Join(labels, "."),
				PayloadSize: len(payload),
			}
		}
		labels = append(labels, string(payload[pos:pos+l]))
		pos += l
	}
	var qtype uint16
	if pos+2 <= len(payload) {
		qtype = binary.BigEndian.Uint16(payload[pos : pos+2])
	}
	return &DNSPacket{
		IsResponse:  flags&0x8000 != 0,
		QueryName:   strings.Join(labels, "."),
		QueryType:   qtype,
		PayloadSize: len(payload),
	}
}

// shannonEntropy returns the bit-entropy of a string, computed over
// its byte distribution. DGA names like "g7q2v9p1aklm.example.com"
// score >= 4.0 bits because they sample uniformly across the alphabet;
// English-language names like "shop.example.com" score < 3.5.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[byte]int, 16)
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	total := float64(len(s))
	var h float64
	for _, c := range freq {
		p := float64(c) / total
		h -= p * math.Log2(p)
	}
	return h
}

// extract2LD returns the registrable second-level domain from a query
// name (e.g. "a.b.c.example.com" -> "example.com"). The classic
// public-suffix list isn't available offline, so we fall back to the
// last two labels — sufficient for DGA bucketing where we want to
// group queries that target the same parent zone.
func extract2LD(name string) string {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return ""
	}
	parts := strings.Split(name, ".")
	if len(parts) < 2 {
		return name
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

// extractSubdomainAboveTLD returns the part of `name` above the 2LD —
// for "g7q2v9p1aklm.example.com" the 2LD is "example.com" and the
// subdomain is "g7q2v9p1aklm". For DGA / tunneling detection we want
// the entropy of the SUBDOMAIN, not the whole name (the 2LD is fixed
// for any given attacker; randomness lives in the subdomain).
func extractSubdomainAboveTLD(name string) string {
	name = strings.TrimSuffix(name, ".")
	parts := strings.Split(name, ".")
	if len(parts) <= 2 {
		return ""
	}
	return strings.Join(parts[:len(parts)-2], ".")
}
