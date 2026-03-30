package contour

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"strconv"
	"strings"
	"time"
)

func buildProbeResponsePacket(raw []byte) ([]byte, bool) {
	packet, ok := decodeProbePacket(raw, false)
	if !ok {
		return nil, false
	}
	if !validateProbeMethodRequest(packet.Method, packet.Body, packet.Exfil) {
		return nil, false
	}
	methodID, ok := probeMethodIDs[packet.Method]
	if !ok {
		return nil, false
	}
	respBody := buildProbeMethodResponseBody(packet.Method, packet.Body)
	if len(respBody) == 0 || len(respBody) > 0xffff {
		return nil, false
	}
	resp := encodeProbePacket(true, packet.Kind, methodID, packet.Port, packet.Exfil, packet.Nonce, respBody)
	return resp, len(resp) > 0
}

func detectProbeRawMethod(body []byte) (string, bool, bool) {
	lower := bytes.ToLower(body)
	exfil := bytes.Contains(body, probeExfilMarker) ||
		bytes.Contains(lower, []byte("x-contour-check: exfil")) ||
		bytes.HasPrefix(body, []byte("SSH-2.0-ContourProbe-EXFIL"))
	for _, proto := range defaultProtocols {
		method := strings.ToLower(strings.TrimSpace(proto.Name))
		if validateProbeMethodRequest(method, body, exfil) {
			return method, exfil, true
		}
	}
	return "", false, false
}

func buildProbeListenerResponsePacket(raw []byte) ([]byte, bool) {
	// Backward compatibility for legacy wrapped probe packets.
	if packet, ok := decodeProbePacket(raw, false); ok {
		if !validateProbeMethodRequest(packet.Method, packet.Body, packet.Exfil) {
			return nil, false
		}
		methodID, ok := probeMethodIDs[packet.Method]
		if !ok {
			return nil, false
		}
		respBody := buildProbeMethodResponseBody(packet.Method, packet.Body)
		if len(respBody) == 0 || len(respBody) > 0xffff {
			return nil, false
		}
		resp := encodeProbePacket(true, packet.Kind, methodID, packet.Port, packet.Exfil, packet.Nonce, respBody)
		return resp, len(resp) > 0
	}
	method, _, ok := detectProbeRawMethod(raw)
	if !ok {
		return nil, false
	}
	resp := buildProbeMethodResponseBody(method, raw)
	if len(resp) == 0 {
		return nil, false
	}
	return resp, true
}

func validateProbeWireResponse(method string, request, response []byte) bool {
	method = strings.ToLower(strings.TrimSpace(method))
	expectedBody := buildProbeMethodResponseBody(method, request)
	if bytes.Equal(response, expectedBody) {
		return true
	}
	// Accept legacy wrapped responses from older listeners.
	packet, ok := decodeProbePacket(response, true)
	if !ok {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(packet.Method), method) && bytes.Equal(packet.Body, expectedBody)
}

func encodeProbePacket(response bool, kind string, methodID byte, port int, exfil bool, nonce uint64, body []byte) []byte {
	if len(body) > 0xffff {
		return nil
	}
	if port < 0 || port > 65535 {
		return nil
	}
	out := make([]byte, probePacketHeaderLen+len(body))
	magic := probePacketReqMagic
	if response {
		magic = probePacketRespMagic
	}
	copy(out[:4], []byte(magic))
	out[4] = probePacketVersion
	out[5] = encodeProbeKind(kind)
	out[6] = methodID
	if exfil {
		out[7] = probeFlagExfil
	}
	binary.BigEndian.PutUint16(out[8:10], uint16(port))
	binary.BigEndian.PutUint16(out[10:12], uint16(len(body)))
	binary.BigEndian.PutUint64(out[12:20], nonce)
	copy(out[20:], body)
	return out
}

func decodeProbePacket(raw []byte, expectResponse bool) (probePacket, bool) {
	if len(raw) < probePacketHeaderLen {
		return probePacket{}, false
	}
	magic := string(raw[:4])
	if expectResponse {
		if magic != probePacketRespMagic {
			return probePacket{}, false
		}
	} else if magic != probePacketReqMagic {
		return probePacket{}, false
	}
	if raw[4] != probePacketVersion {
		return probePacket{}, false
	}
	kind, ok := decodeProbeKind(raw[5])
	if !ok {
		return probePacket{}, false
	}
	method, ok := probeMethodNames[raw[6]]
	if !ok {
		return probePacket{}, false
	}
	flags := raw[7]
	port := int(binary.BigEndian.Uint16(raw[8:10]))
	bodyLen := int(binary.BigEndian.Uint16(raw[10:12]))
	if len(raw) != probePacketHeaderLen+bodyLen {
		return probePacket{}, false
	}
	nonce := binary.BigEndian.Uint64(raw[12:20])
	body := make([]byte, bodyLen)
	copy(body, raw[20:])
	return probePacket{
		Kind:   kind,
		Method: method,
		Port:   port,
		Exfil:  flags&probeFlagExfil != 0,
		Nonce:  nonce,
		Body:   body,
	}, true
}

func encodeProbeKind(kind string) byte {
	if strings.EqualFold(strings.TrimSpace(kind), "exfil") {
		return probeKindExfil
	}
	return probeKindTunnel
}

func decodeProbeKind(v byte) (string, bool) {
	switch v {
	case probeKindTunnel:
		return "tunnel", true
	case probeKindExfil:
		return "exfil", true
	default:
		return "", false
	}
}

func buildProbeMethodBaseRequestBody(method string, port int) []byte {
	var base []byte
	switch method {
	case "http":
		base = []byte("GET /contour-probe HTTP/1.1\r\nHost: contour.local\r\nUser-Agent: contour/http\r\n\r\n")
	case "https":
		base = []byte("CONNECT contour.local:" + strconv.Itoa(port) + " HTTP/1.1\r\nHost: contour.local\r\n\r\n")
	case "ws", "wss":
		base = []byte("GET /contour-probe/ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	case "ssh":
		base = []byte("SSH-2.0-ContourProbe\r\n")
	case "smtp", "smtps":
		base = []byte("EHLO contour.local\r\n")
	case "imap", "imaps":
		base = []byte("a1 CAPABILITY\r\n")
	case "pop3", "pop3s":
		base = []byte("CAPA\r\n")
	case "ftp", "ftps":
		base = []byte("FEAT\r\n")
	case "smb":
		base = buildProbeSMB2NegotiateRequestBody()
	case "rdp":
		base = []byte{0x03, 0x00, 0x00, 0x0b, 0x06, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00}
	case "ldap", "ldaps":
		base = []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00}
	case "socks4":
		base = []byte{0x04, 0x01, 0x00, 0x50, 0x7f, 0x00, 0x00, 0x01, 0x00}
	case "socks5":
		base = []byte{0x05, 0x01, 0x00}
	case "mqtt":
		base = []byte{0x10, 0x10, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3c, 0x00, 0x04, 'p', 'r', 'o', 'b'}
	case "amqp":
		base = buildProbeAMQPProtocolHeader()
	case "postgres":
		base = []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}
	case "dns":
		base = []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 'c', 'o', 'n', 't', 'o', 'u', 'r', 0x00, 0x00, 0x01, 0x00, 0x01}
	case "ntp":
		base = buildProbeNTPRequestBody(nil)
	case "quic":
		base = buildProbeQUICInitialPacket([]byte{0x06, 0x00, 0x00}, 1)
	case "webrtc":
		base = buildProbeSTUNBindingRequestBody()
	case "sip":
		base = []byte("OPTIONS sip:contour.local SIP/2.0\r\nVia: SIP/2.0/UDP contour.local;branch=z9hG4bK-contour\r\nFrom: <sip:probe@contour.local>;tag=contour\r\nTo: <sip:contour.local>\r\nCall-ID: contour-probe@contour.local\r\nCSeq: 1 OPTIONS\r\nContact: <sip:probe@contour.local>\r\nContent-Length: 0\r\n\r\n")
	case "rtsp":
		base = []byte("OPTIONS rtsp://contour.local/probe RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: contour/rtsp\r\n\r\n")
	case "snmp":
		base = buildProbeSNMPGetRequestBody()
	case "coap":
		base = buildProbeCoAPGetRequestBody()
	case "redis":
		base = []byte("*1\r\n$4\r\nPING\r\n")
	default:
		base = []byte("CONTOUR-PROBE-" + method)
	}
	return base
}

func buildProbeAMQPProtocolHeader() []byte {
	return []byte{'A', 'M', 'Q', 'P', 0x00, 0x00, 0x09, 0x01}
}

func buildProbeNTPRequestBody(extPayload []byte) []byte {
	base := make([]byte, 48)
	// LI=0, VN=4, Mode=3 (client).
	base[0] = 0x23
	base[2] = 0x04 // Poll interval
	base[3] = 0xec // Precision (-20)
	ts := ntpTimestampNow()
	binary.BigEndian.PutUint64(base[40:48], ts) // Transmit timestamp
	if len(extPayload) == 0 {
		return base
	}
	padLen := (4 - (len(extPayload) % 4)) % 4
	fieldLen := 4 + len(extPayload) + padLen
	out := make([]byte, 0, 48+fieldLen)
	out = append(out, base...)
	// Private-use extension field type (0x0100) with explicit length.
	out = append(out, 0x01, 0x00, byte(fieldLen>>8), byte(fieldLen))
	out = append(out, extPayload...)
	if padLen > 0 {
		out = append(out, make([]byte, padLen)...)
	}
	return out
}

func ntpTimestampNow() uint64 {
	now := time.Now().UTC()
	// NTP epoch starts 1900-01-01.
	secs := uint64(now.Unix() + 2208988800)
	frac := uint64(now.Nanosecond()) * (1 << 32) / 1_000_000_000
	return (secs << 32) | frac
}

func buildProbeQUICInitialPacket(payload []byte, pn uint16) []byte {
	_ = payload
	_ = pn
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x11}
	scid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x22}
	out := make([]byte, 0, 32)
	// A minimal Version Negotiation packet keeps dissectors stable and avoids
	// generating malformed Initial packets without AEAD/header protection.
	out = append(out, 0x80, 0x00, 0x00, 0x00, 0x00)
	out = append(out, byte(len(dcid)))
	out = append(out, dcid...)
	out = append(out, byte(len(scid)))
	out = append(out, scid...)
	// Supported version list: QUIC v1.
	out = append(out, 0x00, 0x00, 0x00, 0x01)
	return out
}

func buildProbeSTUNBindingRequestBody() []byte {
	out := make([]byte, 20)
	// STUN Binding Request.
	binary.BigEndian.PutUint16(out[0:2], 0x0001)
	binary.BigEndian.PutUint16(out[2:4], 0x0000)
	binary.BigEndian.PutUint32(out[4:8], 0x2112a442)
	copy(out[8:20], []byte("contourprobe"))
	return out
}

func buildProbeSTUNBindingSuccessResponseBody(request []byte) []byte {
	out := make([]byte, 20)
	// STUN Binding Success Response.
	binary.BigEndian.PutUint16(out[0:2], 0x0101)
	binary.BigEndian.PutUint16(out[2:4], 0x0000)
	binary.BigEndian.PutUint32(out[4:8], 0x2112a442)
	if len(request) >= 20 {
		copy(out[8:20], request[8:20])
	} else {
		copy(out[8:20], []byte("contourprobe"))
	}
	return out
}

func buildProbeSNMPGetRequestBody() []byte {
	return []byte{
		0x30, 0x26,
		0x02, 0x01, 0x00,
		0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c',
		0xa0, 0x19,
		0x02, 0x04, 0x70, 0x71, 0x72, 0x73,
		0x02, 0x01, 0x00,
		0x02, 0x01, 0x00,
		0x30, 0x0b,
		0x30, 0x09,
		0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01,
		0x05, 0x00,
	}
}

func buildProbeSNMPGetResponseBody(request []byte) []byte {
	if len(request) == 0 {
		request = buildProbeSNMPGetRequestBody()
	}
	resp := append([]byte(nil), request...)
	for i := 2; i < len(resp); i++ {
		if resp[i] == 0xa0 {
			resp[i] = 0xa2
			break
		}
	}
	return resp
}

func buildProbeCoAPGetRequestBody() []byte {
	return []byte{0x40, 0x01, 0x12, 0x34, 0xb5, 'p', 'r', 'o', 'b', 'e'}
}

func buildProbeCoAPContentResponseBody(request []byte) []byte {
	midHi := byte(0x12)
	midLo := byte(0x34)
	if len(request) >= 4 {
		midHi = request[2]
		midLo = request[3]
	}
	return []byte{0x60, 0x45, midHi, midLo, 0xff, 'o', 'k'}
}

func buildProbeSMB2NegotiateRequestBody() []byte {
	header := make([]byte, 64)
	copy(header[0:4], []byte{0xFE, 'S', 'M', 'B'})
	header[4] = 0x40 // StructureSize = 64
	header[5] = 0x00
	header[12] = 0x00 // Command = NEGOTIATE
	header[13] = 0x00
	header[14] = 0x01 // Credit request
	header[15] = 0x00
	header[24] = 0x01 // MessageID = 1
	// Remaining header bytes are zero.
	body := []byte{
		0x24, 0x00, // StructureSize = 36
		0x01, 0x00, // DialectCount = 1
		0x01, 0x00, // SecurityMode = signing enabled
		0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, // Capabilities
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, // ClientGuid
		0x00, 0x00, 0x00, 0x00, // NegotiateContextOffset
		0x00, 0x00, // NegotiateContextCount
		0x00, 0x00, // Reserved2
		0x02, 0x02, // Dialect: SMB 2.0.2
	}
	wire := append(header, body...)
	out := make([]byte, 0, len(wire)+4)
	length := len(wire)
	out = append(out, 0x00, byte(length>>16), byte(length>>8), byte(length))
	out = append(out, wire...)
	return out
}

// IsCarrierTunnelMethod reports whether the given protocol method is a SOCKS5
// carrier tunnel method (http, https, ws, wss, ssh).
func IsCarrierTunnelMethod(method string) bool {
	return methodUsesSocksCarrierTunnel(method)
}

func methodUsesSocksCarrierTunnel(method string) bool {
	_, ok := probeSocksCarrierMethods[strings.ToLower(strings.TrimSpace(method))]
	return ok
}

func buildProbeSocks5TunnelPayload(port int) []byte {
	if port <= 0 {
		port = 1080
	}
	host := []byte("contour.local")
	out := make([]byte, 0, 3+4+1+len(host)+2)
	// SOCKS5 greeting: version 5, one method, no-auth.
	out = append(out, 0x05, 0x01, 0x00)
	// SOCKS5 connect request to contour.local:<port>.
	out = append(out, 0x05, 0x01, 0x00, 0x03, byte(len(host)))
	out = append(out, host...)
	out = append(out, byte(port>>8), byte(port))
	return out
}

func buildProbeMethodRequestBody(method string, port int, exfil bool) []byte {
	base := buildProbeMethodBaseRequestBody(method, port)
	if !exfil && methodUsesSocksCarrierTunnel(method) {
		// Carrier tunnel checks are verified with a real SOCKS5 handshake over the
		// same TCP flow after carrier negotiation, so the initial request is base
		// protocol bytes only.
		return base
	}
	if !exfil {
		return base
	}
	switch method {
	case "http":
		return []byte("GET /contour-probe HTTP/1.1\r\nHost: contour.local\r\nUser-Agent: contour/http\r\nX-Contour-Check: exfil\r\n\r\n")
	case "https":
		return []byte("CONNECT contour.local:" + strconv.Itoa(port) + " HTTP/1.1\r\nHost: contour.local\r\nX-Contour-Check: exfil\r\n\r\n")
	case "ws", "wss":
		return []byte("GET /contour-probe/ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nX-Contour-Check: exfil\r\n\r\n")
	case "ssh":
		return []byte("SSH-2.0-ContourProbe-EXFIL\r\n")
	default:
		// Exfil checks use protocol-valid request/response exchanges only.
		return base
	}
}

func splitProbeTunnelBody(body []byte) (base []byte, payload []byte) {
	idx := bytes.Index(body, probeTunnelMarker)
	if idx < 0 {
		return body, nil
	}
	base = body[:idx]
	payload = body[idx+len(probeTunnelMarker):]
	return base, payload
}

func splitProbeExfilBody(body []byte) (base []byte, payload []byte) {
	idx := bytes.Index(body, probeExfilMarker)
	if idx < 0 {
		return body, nil
	}
	base = body[:idx]
	payload = body[idx+len(probeExfilMarker):]
	return base, payload
}

func buildProbeExfilReceipt(body []byte) []byte {
	_, payload := splitProbeExfilBody(body)
	if len(payload) == 0 {
		return nil
	}
	sum := crc32.ChecksumIEEE(payload)
	return []byte(fmt.Sprintf("|EXFIL-ACK:%d:%08x|", len(payload), sum))
}

func validateProbeSocks5TunnelPayload(payload []byte) bool {
	// Greeting: 0x05 0x01 0x00
	if len(payload) < 3+4+2 {
		return false
	}
	if payload[0] != 0x05 || payload[1] != 0x01 || payload[2] != 0x00 {
		return false
	}
	// CONNECT request starts immediately after greeting.
	req := payload[3:]
	if len(req) < 6 {
		return false
	}
	if req[0] != 0x05 || req[1] != 0x01 || req[2] != 0x00 {
		return false
	}
	atyp := req[3]
	offset := 4
	switch atyp {
	case 0x01: // IPv4
		offset += 4
	case 0x03: // Domain
		if len(req) < offset+1 {
			return false
		}
		dlen := int(req[offset])
		offset++
		if dlen <= 0 {
			return false
		}
		offset += dlen
	case 0x04: // IPv6
		offset += 16
	default:
		return false
	}
	if len(req) < offset+2 {
		return false
	}
	port := int(req[offset])<<8 | int(req[offset+1])
	return port > 0
}

func validateSocks5ConnectRequest(payload []byte) bool {
	full := make([]byte, 0, 3+len(payload))
	full = append(full, 0x05, 0x01, 0x00)
	full = append(full, payload...)
	return validateProbeSocks5TunnelPayload(full)
}

func validateSocks5ConnectReply(payload []byte) bool {
	if len(payload) < 7 {
		return false
	}
	if payload[0] != 0x05 || payload[1] != 0x00 || payload[2] != 0x00 {
		return false
	}
	offset := 4
	switch payload[3] {
	case 0x01:
		offset += 4
	case 0x03:
		if len(payload) < offset+1 {
			return false
		}
		dlen := int(payload[offset])
		offset++
		if dlen <= 0 {
			return false
		}
		offset += dlen
	case 0x04:
		offset += 16
	default:
		return false
	}
	return len(payload) >= offset+2
}

func buildProbeTunnelReceipt(body []byte) []byte {
	base, _ := splitProbeExfilBody(body)
	_, tunnelPayload := splitProbeTunnelBody(base)
	if len(tunnelPayload) == 0 || !validateProbeSocks5TunnelPayload(tunnelPayload) {
		return nil
	}
	sum := crc32.ChecksumIEEE(tunnelPayload)
	return []byte(fmt.Sprintf("|TUNNEL-ACK:socks5:%d:%08x|", len(tunnelPayload), sum))
}

func validateProbeMethodRequest(method string, body []byte, exfil bool) bool {
	base, exfilPayload := splitProbeExfilBody(body)
	base, tunnelPayload := splitProbeTunnelBody(base)
	if !exfil && len(exfilPayload) > 0 {
		return false
	}
	if exfil && len(exfilPayload) > 0 && len(exfilPayload) < 16 {
		return false
	}
	if exfil && len(tunnelPayload) > 0 {
		return false
	}
	if methodUsesSocksCarrierTunnel(method) {
		if exfil {
			// Exfil check is direct payload transfer, not a tunnel assertion.
			if len(tunnelPayload) > 0 {
				return false
			}
		} else if len(tunnelPayload) > 0 && !validateProbeSocks5TunnelPayload(tunnelPayload) {
			return false
		}
	} else if len(tunnelPayload) > 0 {
		return false
	}
	switch method {
	case "http":
		return bytes.HasPrefix(base, []byte("GET /contour-probe HTTP/1.1\r\n"))
	case "https":
		return bytes.HasPrefix(base, []byte("CONNECT contour.local:"))
	case "ws", "wss":
		return bytes.Contains(base, []byte("Upgrade: websocket"))
	case "ssh":
		return bytes.HasPrefix(base, []byte("SSH-2.0-"))
	case "smtp", "smtps":
		return bytes.HasPrefix(base, []byte("EHLO "))
	case "imap", "imaps":
		return bytes.HasPrefix(base, []byte("a1 CAPABILITY"))
	case "pop3", "pop3s":
		return bytes.HasPrefix(base, []byte("CAPA"))
	case "ftp", "ftps":
		return bytes.HasPrefix(base, []byte("FEAT"))
	case "smb":
		return len(base) >= 12 && ((base[4] == 0xFE && bytes.Equal(base[5:8], []byte("SMB"))) || (base[4] == 0xFF && bytes.Equal(base[5:8], []byte("SMB"))))
	case "rdp":
		return len(base) >= 7 && base[0] == 0x03 && base[1] == 0x00
	case "ldap", "ldaps":
		return len(base) >= 8 && base[0] == 0x30
	case "socks4":
		return len(base) >= 2 && base[0] == 0x04
	case "socks5":
		return len(base) >= 3 && base[0] == 0x05 && base[1] >= 0x01
	case "mqtt":
		return len(base) >= 8 && base[0] == 0x10 && bytes.Contains(base, []byte("MQTT"))
	case "amqp":
		return len(base) >= 4 && bytes.Equal(base[:4], []byte("AMQP"))
	case "postgres":
		return len(base) >= 8 && bytes.Equal(base[:8], []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f})
	case "dns":
		return len(base) >= 12 && base[2]&0x80 == 0
	case "ntp":
		return len(base) >= 48 && base[0]&0x7 == 3
	case "quic":
		return len(base) >= 8 && base[0]&0x80 != 0
	case "webrtc":
		return len(base) >= 20 &&
			binary.BigEndian.Uint16(base[0:2]) == 0x0001 &&
			binary.BigEndian.Uint32(base[4:8]) == 0x2112a442
	case "sip":
		return bytes.HasPrefix(base, []byte("OPTIONS sip:")) &&
			bytes.Contains(base, []byte("SIP/2.0"))
	case "rtsp":
		return bytes.HasPrefix(base, []byte("OPTIONS rtsp://")) &&
			bytes.Contains(base, []byte("RTSP/1.0"))
	case "snmp":
		return len(base) >= 16 &&
			base[0] == 0x30 &&
			bytes.Contains(base, []byte("public")) &&
			bytes.Contains(base, []byte{0xa0})
	case "coap":
		return len(base) >= 4 &&
			(base[0]&0xc0) == 0x40 &&
			base[1] == 0x01
	case "redis":
		return bytes.HasPrefix(base, []byte("*1\r\n$4\r\nPING\r\n"))
	default:
		return len(base) > 0
	}
}

func buildProbeMethodResponseBody(method string, requestBody []byte) []byte {
	acks := make([]byte, 0, 64)
	acks = append(acks, buildProbeTunnelReceipt(requestBody)...)
	acks = append(acks, buildProbeExfilReceipt(requestBody)...)
	switch method {
	case "http", "https":
		return append([]byte("HTTP/1.1 200 OK\r\nX-Contour-Ack: 1\r\nContent-Length: 2\r\n\r\nOK"), acks...)
	case "ws", "wss":
		return append([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"), acks...)
	case "ssh":
		return append([]byte("SSH-2.0-ContourListener\r\n"), acks...)
	case "smtp", "smtps":
		return append([]byte("250 contour.local\r\n"), acks...)
	case "imap", "imaps":
		return append([]byte("* CAPABILITY IMAP4rev1\r\na1 OK CAPABILITY completed\r\n"), acks...)
	case "pop3", "pop3s":
		return append([]byte("+OK Capability list follows\r\n.\r\n"), acks...)
	case "ftp", "ftps":
		return append([]byte("211-Features\r\n211 End\r\n"), acks...)
	case "smb":
		return buildProbeSMB2NegotiateRequestBody()
	case "rdp":
		return append([]byte{0x03, 0x00, 0x00, 0x0b, 0x02, 0xf0, 0x80, 0x00, 0x00, 0x00, 0x00}, acks...)
	case "ldap", "ldaps":
		return append([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}, acks...)
	case "socks4":
		return append([]byte{0x00, 0x5a, 0x00, 0x50, 0x7f, 0x00, 0x00, 0x01}, acks...)
	case "socks5":
		return append([]byte{0x05, 0x00}, acks...)
	case "mqtt":
		return append([]byte{0x20, 0x02, 0x00, 0x00}, acks...)
	case "amqp":
		return buildProbeAMQPProtocolHeader()
	case "postgres":
		return append([]byte{'N'}, acks...)
	case "dns":
		if len(requestBody) >= 2 {
			return append([]byte{requestBody[0], requestBody[1], 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, acks...)
		}
		return append([]byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, acks...)
	case "ntp":
		resp := make([]byte, 48)
		// LI=0, VN=4, Mode=4 (server)
		resp[0] = 0x24
		resp[1] = 0x01 // Stratum
		resp[2] = 0x04 // Poll interval
		resp[3] = 0xec // Precision (-20)
		if len(requestBody) >= 48 {
			copy(resp[24:32], requestBody[40:48]) // Originate Timestamp
		}
		nowTS := ntpTimestampNow()
		binary.BigEndian.PutUint64(resp[32:40], nowTS) // Receive Timestamp
		binary.BigEndian.PutUint64(resp[40:48], nowTS) // Transmit Timestamp
		return resp
	case "quic":
		resp := buildProbeQUICInitialPacket(nil, 0)
		if len(resp) > 0 {
			return resp
		}
		return []byte{0xc1, 0x00}
	case "webrtc":
		return buildProbeSTUNBindingSuccessResponseBody(requestBody)
	case "sip":
		return []byte("SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n")
	case "rtsp":
		return []byte("RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n")
	case "snmp":
		return buildProbeSNMPGetResponseBody(requestBody)
	case "coap":
		return buildProbeCoAPContentResponseBody(requestBody)
	case "redis":
		return []byte("+PONG\r\n")
	default:
		return append([]byte("ACK"), acks...)
	}
}

func validateProbeMethodResponse(method string, requestBody, responseBody []byte) bool {
	expected := buildProbeMethodResponseBody(method, requestBody)
	return bytes.Equal(responseBody, expected)
}
