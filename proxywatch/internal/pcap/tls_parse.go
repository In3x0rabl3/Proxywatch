package pcap

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
)

// TLSClientHelloFingerprint captures the TLS-handshake-derived data
// pcap mode uses for passive role assignment: JA3 hash, SNI, ALPN.
// All fields are best-effort — partial fingerprints are still useful
// (e.g. SNI alone resolves CDN-fronted destinations to a hostname even
// when the cipher list is malformed).
type TLSClientHelloFingerprint struct {
	Version        uint16
	Ciphers        []uint16
	Extensions     []uint16
	EllipticCurves []uint16
	PointFormats   []uint8
	SNI            string
	ALPN           []string
}

// JA3 returns the canonical JA3 string and lower-case MD5 hash per the
// salesforce/ja3 spec: `Version,Ciphers,Extensions,EllipticCurves,
// PointFormats` (decimal, dash-separated, GREASE excluded). Empty
// strings when the fingerprint is too sparse to hash meaningfully.
func (f *TLSClientHelloFingerprint) JA3() (raw, hash string) {
	if f == nil || f.Version == 0 || len(f.Ciphers) == 0 {
		return "", ""
	}
	var sb strings.Builder
	sb.WriteString(strconv.FormatUint(uint64(f.Version), 10))
	sb.WriteByte(',')
	sb.WriteString(joinUint16Decimal(f.Ciphers))
	sb.WriteByte(',')
	sb.WriteString(joinUint16Decimal(f.Extensions))
	sb.WriteByte(',')
	sb.WriteString(joinUint16Decimal(f.EllipticCurves))
	sb.WriteByte(',')
	sb.WriteString(joinUint8Decimal(f.PointFormats))
	raw = sb.String()
	sum := md5.Sum([]byte(raw))
	hash = hex.EncodeToString(sum[:])
	return raw, hash
}

// isGREASE reports whether v is a GREASE value per RFC 8701. GREASE
// values are 0x0A0A, 0x1A1A, ... 0xFAFA — high byte == low byte AND
// the low nibble is 0xA.
func isGREASE(v uint16) bool {
	high := byte(v >> 8)
	low := byte(v)
	return high == low && (low&0x0F) == 0x0A
}

func joinUint16Decimal(xs []uint16) string {
	if len(xs) == 0 {
		return ""
	}
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = strconv.FormatUint(uint64(x), 10)
	}
	return strings.Join(parts, "-")
}

func joinUint8Decimal(xs []uint8) string {
	if len(xs) == 0 {
		return ""
	}
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = strconv.FormatUint(uint64(x), 10)
	}
	return strings.Join(parts, "-")
}

// parseTLSClientHello parses a single TCP payload that begins at the
// TLS record layer. Returns nil for non-handshake or non-ClientHello
// payloads. Defensive against truncation: malformed/short input simply
// stops parsing and returns whatever was extracted up to the failure
// point — JA3() will return "" if the result is unhashable.
//
// First-packet only — TCP segment reassembly is Tier 3 work. Most
// ClientHellos fit comfortably in 512 bytes (cipher-list bloat from
// Chrome/Firefox is ~300 bytes; Go-default is much smaller). Flows
// that happen to fragment ClientHello get skipped silently.
func parseTLSClientHello(data []byte) *TLSClientHelloFingerprint {
	if len(data) < 5 {
		return nil
	}
	// TLS record layer: content_type(1) + version(2) + length(2)
	// Handshake type 22 (0x16) is required; SSL 2.0 ClientHellos are skipped.
	if data[0] != 0x16 {
		return nil
	}
	if data[1] != 0x03 {
		return nil
	}
	recLen := int(binary.BigEndian.Uint16(data[3:5]))
	if 5+recLen > len(data) {
		recLen = len(data) - 5
	}
	if recLen < 4 {
		return nil
	}
	body := data[5 : 5+recLen]
	// Handshake header: msg_type(1) + length(3)
	if body[0] != 0x01 { // ClientHello
		return nil
	}
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if 4+hsLen > len(body) {
		hsLen = len(body) - 4
	}
	if hsLen < 34 {
		return nil
	}
	ch := body[4 : 4+hsLen]

	fp := &TLSClientHelloFingerprint{}
	fp.Version = binary.BigEndian.Uint16(ch[0:2])
	// skip 32-byte random
	pos := 34
	// Session ID
	if pos >= len(ch) {
		return fp
	}
	sidLen := int(ch[pos])
	pos++
	if pos+sidLen > len(ch) {
		return fp
	}
	pos += sidLen
	// Cipher suites
	if pos+2 > len(ch) {
		return fp
	}
	csLen := int(binary.BigEndian.Uint16(ch[pos : pos+2]))
	pos += 2
	if pos+csLen > len(ch) || csLen < 2 {
		return fp
	}
	for i := 0; i+1 < csLen; i += 2 {
		c := binary.BigEndian.Uint16(ch[pos+i : pos+i+2])
		if !isGREASE(c) {
			fp.Ciphers = append(fp.Ciphers, c)
		}
	}
	pos += csLen
	// Compression methods
	if pos >= len(ch) {
		return fp
	}
	cmLen := int(ch[pos])
	pos++
	if pos+cmLen > len(ch) {
		return fp
	}
	pos += cmLen
	// Extensions
	if pos+2 > len(ch) {
		return fp
	}
	extLen := int(binary.BigEndian.Uint16(ch[pos : pos+2]))
	pos += 2
	extEnd := pos + extLen
	if extEnd > len(ch) {
		extEnd = len(ch)
	}
	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(ch[pos : pos+2])
		extDataLen := int(binary.BigEndian.Uint16(ch[pos+2 : pos+4]))
		pos += 4
		if pos+extDataLen > extEnd {
			break
		}
		if !isGREASE(extType) {
			fp.Extensions = append(fp.Extensions, extType)
		}
		extData := ch[pos : pos+extDataLen]
		switch extType {
		case 0x0000: // server_name (SNI)
			parseSNI(extData, fp)
		case 0x000a: // supported_groups (elliptic curves)
			parseSupportedGroups(extData, fp)
		case 0x000b: // ec_point_formats
			parsePointFormats(extData, fp)
		case 0x0010: // ALPN
			parseALPN(extData, fp)
		}
		pos += extDataLen
	}
	return fp
}

func parseSNI(data []byte, fp *TLSClientHelloFingerprint) {
	if len(data) < 2 {
		return
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	end := 2 + listLen
	if end > len(data) {
		end = len(data)
	}
	p := 2
	for p+3 <= end {
		nameType := data[p]
		p++
		nameLen := int(binary.BigEndian.Uint16(data[p : p+2]))
		p += 2
		if p+nameLen > end {
			break
		}
		if nameType == 0 && fp.SNI == "" {
			fp.SNI = string(data[p : p+nameLen])
		}
		p += nameLen
	}
}

func parseSupportedGroups(data []byte, fp *TLSClientHelloFingerprint) {
	if len(data) < 2 {
		return
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if 2+listLen > len(data) {
		listLen = len(data) - 2
	}
	for i := 0; i+1 < listLen; i += 2 {
		g := binary.BigEndian.Uint16(data[2+i : 2+i+2])
		if !isGREASE(g) {
			fp.EllipticCurves = append(fp.EllipticCurves, g)
		}
	}
}

func parsePointFormats(data []byte, fp *TLSClientHelloFingerprint) {
	if len(data) < 1 {
		return
	}
	listLen := int(data[0])
	if 1+listLen > len(data) {
		listLen = len(data) - 1
	}
	fp.PointFormats = append(fp.PointFormats, data[1:1+listLen]...)
}

func parseALPN(data []byte, fp *TLSClientHelloFingerprint) {
	if len(data) < 2 {
		return
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	end := 2 + listLen
	if end > len(data) {
		end = len(data)
	}
	p := 2
	for p < end {
		al := int(data[p])
		p++
		if p+al > end {
			break
		}
		fp.ALPN = append(fp.ALPN, string(data[p:p+al]))
		p += al
	}
}

// shouldAttemptTLSParse gates the parser on the first byte of any flow
// payload — TLS handshake records start with 0x16 (handshake) followed
// by 0x03 (SSL 3.x / TLS 1.x). Cheap pre-filter that also catches C2
// frameworks running TLS on non-443 ports (Sliver on 8443, custom
// redirectors on 80, etc.).
func shouldAttemptTLSParse(payload []byte) bool {
	return len(payload) >= 5 && payload[0] == 0x16 && payload[1] == 0x03
}

// TLSServerHelloFingerprint captures the JA3S-relevant fields from a
// ServerHello: the server's selected version, single chosen cipher,
// and selected extensions. JA3S = MD5("Version,Cipher,Extensions").
type TLSServerHelloFingerprint struct {
	Version    uint16
	Cipher     uint16
	Extensions []uint16
}

// JA3S returns the canonical JA3S string and lower-case MD5 hash.
// Empty strings when the fingerprint is unparseable.
func (f *TLSServerHelloFingerprint) JA3S() (raw, hash string) {
	if f == nil || f.Version == 0 {
		return "", ""
	}
	var sb strings.Builder
	sb.WriteString(strconv.FormatUint(uint64(f.Version), 10))
	sb.WriteByte(',')
	sb.WriteString(strconv.FormatUint(uint64(f.Cipher), 10))
	sb.WriteByte(',')
	sb.WriteString(joinUint16Decimal(f.Extensions))
	raw = sb.String()
	sum := md5.Sum([]byte(raw))
	hash = hex.EncodeToString(sum[:])
	return raw, hash
}

// parseTLSServerHello parses a single TCP payload that begins at the
// TLS record layer and contains a ServerHello (handshake type 0x02).
// Returns nil for non-handshake or non-ServerHello payloads.
func parseTLSServerHello(data []byte) *TLSServerHelloFingerprint {
	if len(data) < 5 {
		return nil
	}
	if data[0] != 0x16 || data[1] != 0x03 {
		return nil
	}
	recLen := int(binary.BigEndian.Uint16(data[3:5]))
	if 5+recLen > len(data) {
		recLen = len(data) - 5
	}
	if recLen < 4 {
		return nil
	}
	body := data[5 : 5+recLen]
	if body[0] != 0x02 { // ServerHello
		return nil
	}
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if 4+hsLen > len(body) {
		hsLen = len(body) - 4
	}
	if hsLen < 38 { // version(2) + random(32) + sid_len(1) + cipher(2) + cm(1) = 38 minimum
		return nil
	}
	sh := body[4 : 4+hsLen]

	fp := &TLSServerHelloFingerprint{}
	fp.Version = binary.BigEndian.Uint16(sh[0:2])
	pos := 34 // skip version (2) + random (32)
	if pos >= len(sh) {
		return fp
	}
	sidLen := int(sh[pos])
	pos++
	if pos+sidLen > len(sh) {
		return fp
	}
	pos += sidLen
	if pos+2 > len(sh) {
		return fp
	}
	fp.Cipher = binary.BigEndian.Uint16(sh[pos : pos+2])
	pos += 2
	// compression method (1)
	if pos >= len(sh) {
		return fp
	}
	pos++
	// extensions length (2) — optional in older TLS, may be absent
	if pos+2 > len(sh) {
		return fp
	}
	extLen := int(binary.BigEndian.Uint16(sh[pos : pos+2]))
	pos += 2
	extEnd := pos + extLen
	if extEnd > len(sh) {
		extEnd = len(sh)
	}
	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(sh[pos : pos+2])
		extDataLen := int(binary.BigEndian.Uint16(sh[pos+2 : pos+4]))
		pos += 4
		if pos+extDataLen > extEnd {
			break
		}
		if !isGREASE(extType) {
			fp.Extensions = append(fp.Extensions, extType)
		}
		pos += extDataLen
	}
	return fp
}

// shouldAttemptTLSServerParse mirrors shouldAttemptTLSParse but is
// distinct conceptually — caller must already know this is a
// responder-side payload, since both ClientHello and ServerHello start
// with the same record header.
func shouldAttemptTLSServerParse(payload []byte) bool {
	return len(payload) >= 5 && payload[0] == 0x16 && payload[1] == 0x03
}
