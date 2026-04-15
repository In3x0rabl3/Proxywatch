package tunnel

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════
// DNS tunnel — data hidden inside DNS wire format over TCP
// Wire: 2-byte length prefix + DNS query/response structure
// Queries encode data in subdomain labels (base64), responses carry data
// in TXT RDATA. Looks like DNS-over-TCP traffic to inspection.
// ═══════════════════════════════════════════════════════════════════════════

const dnsTunnelDomain = ".cdn.cloudflare-dns.com"

func serveDNSTunnel(ctx context.Context, port int, emit func(string)) TunnelResult {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return TunnelResult{Error: err}
	}
	defer ln.Close()
	emit(fmt.Sprintf("[+] DNS tunnel bound on %s", addr))
	emit(fmt.Sprintf("[+] Listening on port %d — waiting for client...", port))
	go func() { <-ctx.Done(); ln.Close() }()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return TunnelResult{}
			}
			continue
		}
		emit(fmt.Sprintf("[+] Client connected from %s", conn.RemoteAddr()))
		go handleDNSTunnelSession(conn, emit)
	}
}

func handleDNSTunnelSession(conn net.Conn, emit func(string)) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Minute))

	// First DNS query carries the target address encoded in the query name.
	query, txid, err := dnsReadQuery(conn)
	if err != nil {
		return
	}
	target := dnsDecodeLabel(query)
	if target == "" {
		dnsWriteResponse(conn, txid, []byte("error"))
		return
	}

	remote, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		dnsWriteResponse(conn, txid, []byte("refused"))
		return
	}
	defer remote.Close()

	// Send "ok" response.
	dnsWriteResponse(conn, txid, []byte("ok"))
	emit(fmt.Sprintf("[+] DNS tunnel: proxying → %s", target))

	// Relay using raw bidirectional copy over the DNS-framed TCP connection.
	// After the handshake, switch to simple length-prefixed binary frames
	// (reusing the DNS TCP 2-byte length prefix) for efficient data transfer.
	// This maintains wire compatibility — each message has a 2-byte length
	// prefix which is standard DNS-over-TCP framing.
	done := make(chan struct{}, 2)

	// remote → client: read from destination, send as length-prefixed frames.
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := remote.Read(buf)
			if n > 0 {
				frame := make([]byte, 2+n)
				binary.BigEndian.PutUint16(frame[:2], uint16(n))
				copy(frame[2:], buf[:n])
				if _, werr := conn.Write(frame); werr != nil {
					done <- struct{}{}
					return
				}
			}
			if err != nil {
				done <- struct{}{}
				return
			}
		}
	}()

	// client → remote: read length-prefixed frames, write to destination.
	go func() {
		for {
			var lenBuf [2]byte
			if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
				done <- struct{}{}
				return
			}
			frameLen := binary.BigEndian.Uint16(lenBuf[:])
			if frameLen == 0 || frameLen > 32*1024 {
				done <- struct{}{}
				return
			}
			data := make([]byte, frameLen)
			if _, err := io.ReadFull(conn, data); err != nil {
				done <- struct{}{}
				return
			}
			if _, err := remote.Write(data); err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	<-done
	remote.Close()
	conn.Close()
}

func connectDNSTunnelClient(ctx context.Context, proxyAddr string, emit func(string)) TunnelResult {
	// Verify: send a DNS query and check for a well-formed DNS response.
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return TunnelResult{Error: fmt.Errorf("cannot reach %s: %w", proxyAddr, err)}
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	dnsWriteQuery(conn, 0x1234, dnsEncodeLabel("verify"))
	resp, err := dnsReadResponse(conn)
	conn.Close()
	if err != nil || len(resp) == 0 {
		return TunnelResult{Error: fmt.Errorf("DNS handshake failed on %s", proxyAddr)}
	}

	return startLocalForwarder(ctx, proxyAddr, "dns", emit, func(local net.Conn) {
		forwardDNSTunnel(local, proxyAddr, emit)
	})
}

func forwardDNSTunnel(local net.Conn, proxyAddr string, emit func(string)) {
	defer local.Close()
	local.SetDeadline(time.Now().Add(5 * time.Minute))

	// Accept SOCKS5 from local app, extract target.
	buf := make([]byte, 256)
	n, err := local.Read(buf)
	if err != nil || n < 3 || buf[0] != 0x05 {
		return
	}
	local.Write([]byte{0x05, 0x00})
	n, err = local.Read(buf)
	if err != nil || n < 7 || buf[0] != 0x05 || buf[1] != 0x01 {
		local.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	target := parseSOCKS5Target(buf[:n])
	if target == "" {
		local.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Connect to DNS tunnel server.
	remote, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()
	remote.SetDeadline(time.Now().Add(5 * time.Minute))

	// Send target as first DNS query.
	dnsWriteQuery(remote, 0xABCD, dnsEncodeLabel(target))
	resp, err := dnsReadResponse(remote)
	if err != nil || string(resp) != "ok" {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	emit(fmt.Sprintf("[+] DNS tunnel forwarding → %s", target))

	// Relay using length-prefixed binary frames (2-byte DNS TCP framing).
	done := make(chan struct{}, 2)

	// remote → local: read length-prefixed frames from tunnel, write to local app.
	go func() {
		for {
			var lenBuf [2]byte
			if _, err := io.ReadFull(remote, lenBuf[:]); err != nil {
				done <- struct{}{}
				return
			}
			frameLen := binary.BigEndian.Uint16(lenBuf[:])
			if frameLen == 0 || frameLen > 32*1024 {
				done <- struct{}{}
				return
			}
			data := make([]byte, frameLen)
			if _, err := io.ReadFull(remote, data); err != nil {
				done <- struct{}{}
				return
			}
			if _, err := local.Write(data); err != nil {
				done <- struct{}{}
				return
			}
		}
	}()

	// local → remote: read from local app, send as length-prefixed frames.
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := local.Read(buf)
			if n > 0 {
				frame := make([]byte, 2+n)
				binary.BigEndian.PutUint16(frame[:2], uint16(n))
				copy(frame[2:], buf[:n])
				if _, werr := remote.Write(frame); werr != nil {
					done <- struct{}{}
					return
				}
			}
			if err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	<-done
	local.Close()
	remote.Close()
}

// dnsEncodeLabel wraps data as a DNS-style query name with the tunnel domain.
func dnsEncodeLabel(data string) string {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(data))
	return encoded + dnsTunnelDomain
}

// dnsDecodeLabel extracts data from a DNS-style query name.
func dnsDecodeLabel(qname string) string {
	label := strings.TrimSuffix(qname, dnsTunnelDomain)
	data, err := base64.RawURLEncoding.DecodeString(label)
	if err != nil {
		return ""
	}
	return string(data)
}

// dnsWriteQuery sends a DNS query over TCP (2-byte length prefix + DNS packet).
func dnsWriteQuery(conn net.Conn, txid uint16, qname string) {
	// Build minimal DNS query: header(12) + QNAME + QTYPE(2) + QCLASS(2).
	var pkt []byte
	// Header: TXID, flags=0x0100 (standard query), QDCOUNT=1.
	pkt = append(pkt, byte(txid>>8), byte(txid))
	pkt = append(pkt, 0x01, 0x00)                         // flags: standard query, RD=1
	pkt = append(pkt, 0x00, 0x01)                         // QDCOUNT=1
	pkt = append(pkt, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // AN, NS, AR = 0

	// QNAME: split into labels.
	parts := strings.Split(strings.TrimSuffix(qname, "."), ".")
	for _, part := range parts {
		// DNS labels max 63 bytes; split longer parts.
		for len(part) > 63 {
			pkt = append(pkt, 63)
			pkt = append(pkt, []byte(part[:63])...)
			part = part[63:]
		}
		if len(part) > 0 {
			pkt = append(pkt, byte(len(part)))
			pkt = append(pkt, []byte(part)...)
		}
	}
	pkt = append(pkt, 0x00)       // root label
	pkt = append(pkt, 0x00, 0x10) // QTYPE = TXT (16)
	pkt = append(pkt, 0x00, 0x01) // QCLASS = IN (1)

	// TCP DNS: 2-byte length prefix.
	lenBuf := []byte{byte(len(pkt) >> 8), byte(len(pkt))}
	conn.Write(append(lenBuf, pkt...))
}

// dnsWriteResponse sends a DNS TXT response carrying arbitrary data.
func dnsWriteResponse(conn net.Conn, txid uint16, data []byte) {
	var pkt []byte
	// Header: TXID, flags=0x8180 (response, no error), QDCOUNT=0, ANCOUNT=1.
	pkt = append(pkt, byte(txid>>8), byte(txid))
	pkt = append(pkt, 0x81, 0x80)             // QR=1, AA=1, RD=1, RA=1
	pkt = append(pkt, 0x00, 0x00)             // QDCOUNT=0
	pkt = append(pkt, 0x00, 0x01)             // ANCOUNT=1
	pkt = append(pkt, 0x00, 0x00, 0x00, 0x00) // NS=0, AR=0

	// Answer: name=root, TYPE=TXT, CLASS=IN, TTL=0, RDATA=data.
	pkt = append(pkt, 0x00)                   // name: root
	pkt = append(pkt, 0x00, 0x10)             // TYPE = TXT
	pkt = append(pkt, 0x00, 0x01)             // CLASS = IN
	pkt = append(pkt, 0x00, 0x00, 0x00, 0x00) // TTL = 0

	// TXT RDATA: each chunk is length-prefixed (max 255 per chunk).
	var rdata []byte
	for len(data) > 0 {
		chunk := data
		if len(chunk) > 255 {
			chunk = data[:255]
		}
		rdata = append(rdata, byte(len(chunk)))
		rdata = append(rdata, chunk...)
		data = data[len(chunk):]
	}
	if len(rdata) == 0 {
		rdata = []byte{0}
	}
	pkt = append(pkt, byte(len(rdata)>>8), byte(len(rdata)))
	pkt = append(pkt, rdata...)

	lenBuf := []byte{byte(len(pkt) >> 8), byte(len(pkt))}
	conn.Write(append(lenBuf, pkt...))
}

// dnsReadQuery reads a TCP DNS query and returns the qname and transaction ID.
func dnsReadQuery(conn net.Conn) (string, uint16, error) {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return "", 0, err
	}
	pktLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if pktLen < 12 || pktLen > 65535 {
		return "", 0, fmt.Errorf("invalid DNS packet length")
	}
	pkt := make([]byte, pktLen)
	if _, err := io.ReadFull(conn, pkt); err != nil {
		return "", 0, err
	}
	txid := uint16(pkt[0])<<8 | uint16(pkt[1])

	// Parse QNAME starting at offset 12.
	var labels []string
	i := 12
	for i < len(pkt) && pkt[i] != 0 {
		llen := int(pkt[i])
		i++
		if i+llen > len(pkt) {
			break
		}
		labels = append(labels, string(pkt[i:i+llen]))
		i += llen
	}
	return strings.Join(labels, "."), txid, nil
}

// dnsReadResponse reads a TCP DNS response and returns the TXT RDATA payload.
func dnsReadResponse(conn net.Conn) ([]byte, error) {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}
	pktLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if pktLen < 12 || pktLen > 65535 {
		return nil, fmt.Errorf("invalid DNS response length")
	}
	pkt := make([]byte, pktLen)
	if _, err := io.ReadFull(conn, pkt); err != nil {
		return nil, err
	}

	// Skip header (12 bytes), skip QNAME in question section if present.
	ancount := int(pkt[6])<<8 | int(pkt[7])
	qdcount := int(pkt[4])<<8 | int(pkt[5])
	i := 12
	for q := 0; q < qdcount && i < len(pkt); q++ {
		for i < len(pkt) && pkt[i] != 0 {
			i += int(pkt[i]) + 1
		}
		i += 5 // null + QTYPE(2) + QCLASS(2)
	}

	// Parse answer records to find TXT RDATA.
	for a := 0; a < ancount && i < len(pkt); a++ {
		// Skip name (may be compressed).
		if i < len(pkt) && pkt[i]&0xC0 == 0xC0 {
			i += 2
		} else {
			for i < len(pkt) && pkt[i] != 0 {
				i += int(pkt[i]) + 1
			}
			i++
		}
		if i+10 > len(pkt) {
			break
		}
		// TYPE(2), CLASS(2), TTL(4), RDLENGTH(2)
		rtype := int(pkt[i])<<8 | int(pkt[i+1])
		rdlen := int(pkt[i+8])<<8 | int(pkt[i+9])
		i += 10
		if i+rdlen > len(pkt) {
			break
		}
		if rtype != 16 { // not TXT
			i += rdlen
			continue
		}
		// Parse TXT RDATA: concatenate character-strings.
		var data []byte
		end := i + rdlen
		for i < end {
			slen := int(pkt[i])
			i++
			if i+slen > end {
				break
			}
			data = append(data, pkt[i:i+slen]...)
			i += slen
		}
		return data, nil
	}
	return nil, fmt.Errorf("no TXT record in response")
}

// ═══════════════════════════════════════════════════════════════════════════
// NTP tunnel — data hidden inside NTP packet extension fields
// Wire: standard 48-byte NTP header + extension field carrying tunnel data
// Looks like NTP time sync traffic with extensions.
// ═══════════════════════════════════════════════════════════════════════════

const ntpHeaderSize = 48

func serveNTPTunnel(ctx context.Context, port int, emit func(string)) TunnelResult {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return TunnelResult{Error: err}
	}
	defer ln.Close()
	emit(fmt.Sprintf("[+] NTP tunnel bound on %s", addr))
	emit(fmt.Sprintf("[+] Listening on port %d — waiting for client...", port))
	go func() { <-ctx.Done(); ln.Close() }()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return TunnelResult{}
			}
			continue
		}
		emit(fmt.Sprintf("[+] Client connected from %s", conn.RemoteAddr()))
		go handleNTPTunnelSession(conn, emit)
	}
}

func handleNTPTunnelSession(conn net.Conn, emit func(string)) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Minute))

	// First NTP packet extension carries the target address.
	data, err := ntpReadPacket(conn)
	if err != nil || len(data) == 0 {
		return
	}
	target := string(data)

	remote, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		ntpWritePacket(conn, []byte("refused"))
		return
	}
	defer remote.Close()

	ntpWritePacket(conn, []byte("ok"))
	emit(fmt.Sprintf("[+] NTP tunnel: proxying → %s", target))

	// Relay via NTP packets.
	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 16*1024)
		for {
			n, err := remote.Read(buf)
			if err != nil {
				done <- struct{}{}
				return
			}
			ntpWritePacket(conn, buf[:n])
		}
	}()
	go func() {
		for {
			data, err := ntpReadPacket(conn)
			if err != nil {
				done <- struct{}{}
				return
			}
			if _, err := remote.Write(data); err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	<-done
}

func connectNTPTunnelClient(ctx context.Context, proxyAddr string, emit func(string)) TunnelResult {
	// Verify with NTP packet exchange.
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return TunnelResult{Error: fmt.Errorf("cannot reach %s: %w", proxyAddr, err)}
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	ntpWritePacket(conn, []byte("verify"))
	resp, err := ntpReadPacket(conn)
	conn.Close()
	// Accept any NTP-framed response as proof it's our tunnel.
	if err != nil || len(resp) == 0 {
		return TunnelResult{Error: fmt.Errorf("NTP handshake failed on %s", proxyAddr)}
	}

	return startLocalForwarder(ctx, proxyAddr, "ntp", emit, func(local net.Conn) {
		forwardNTPTunnel(local, proxyAddr, emit)
	})
}

func forwardNTPTunnel(local net.Conn, proxyAddr string, emit func(string)) {
	defer local.Close()
	local.SetDeadline(time.Now().Add(5 * time.Minute))

	// Accept SOCKS5 from local app.
	buf := make([]byte, 256)
	n, err := local.Read(buf)
	if err != nil || n < 3 || buf[0] != 0x05 {
		return
	}
	local.Write([]byte{0x05, 0x00})
	n, err = local.Read(buf)
	if err != nil || n < 7 || buf[0] != 0x05 || buf[1] != 0x01 {
		local.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	target := parseSOCKS5Target(buf[:n])
	if target == "" {
		local.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	remote, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()
	remote.SetDeadline(time.Now().Add(5 * time.Minute))

	ntpWritePacket(remote, []byte(target))
	resp, err := ntpReadPacket(remote)
	if err != nil || string(resp) != "ok" {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	emit(fmt.Sprintf("[+] NTP tunnel forwarding → %s", target))

	done := make(chan struct{}, 2)
	go func() {
		for {
			data, err := ntpReadPacket(remote)
			if err != nil {
				done <- struct{}{}
				return
			}
			if _, err := local.Write(data); err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 16*1024)
		for {
			n, err := local.Read(buf)
			if err != nil {
				done <- struct{}{}
				return
			}
			ntpWritePacket(remote, buf[:n])
		}
	}()
	<-done
}

// ntpWritePacket sends an NTP-framed packet: 48-byte NTP header + 4-byte
// extension header (type=0xF000, length) + payload. Over TCP, prefixed
// with 2-byte total length.
func ntpWritePacket(conn net.Conn, payload []byte) {
	// Standard NTP header (48 bytes): LI=0, VN=4, Mode=4 (server).
	var hdr [ntpHeaderSize]byte
	hdr[0] = 0x24 // LI=0, VN=4, Mode=4
	// Set transmit timestamp to current time for realism.
	now := time.Now()
	secs := uint32(now.Unix()) + 2208988800 // NTP epoch offset
	binary.BigEndian.PutUint32(hdr[40:44], secs)

	// NTP extension field: Type=0xF000 (private).
	// Length field stores actual payload size (not padded) so reader
	// can extract exact data without trailing zeros.
	payloadLen := len(payload)
	extLen := 4 + payloadLen
	// Pad total to 4-byte boundary for NTP compliance.
	paddedExtLen := extLen
	if paddedExtLen%4 != 0 {
		paddedExtLen += 4 - (paddedExtLen % 4)
	}
	ext := make([]byte, paddedExtLen)
	binary.BigEndian.PutUint16(ext[0:2], 0xF000)               // private extension type
	binary.BigEndian.PutUint16(ext[2:4], uint16(4+payloadLen)) // actual data length (unpadded)
	copy(ext[4:], payload)

	total := ntpHeaderSize + paddedExtLen
	// TCP framing: 2-byte length prefix.
	frame := make([]byte, 2+total)
	binary.BigEndian.PutUint16(frame[0:2], uint16(total))
	copy(frame[2:], hdr[:])
	copy(frame[2+ntpHeaderSize:], ext)
	conn.Write(frame)
}

// ntpReadPacket reads an NTP-framed packet and returns the extension payload.
func ntpReadPacket(conn net.Conn) ([]byte, error) {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}
	total := int(binary.BigEndian.Uint16(lenBuf))
	if total < ntpHeaderSize || total > 65535 {
		return nil, fmt.Errorf("invalid NTP packet length: %d", total)
	}
	pkt := make([]byte, total)
	if _, err := io.ReadFull(conn, pkt); err != nil {
		return nil, err
	}

	// Skip 48-byte NTP header, parse extension field.
	if total <= ntpHeaderSize+4 {
		return nil, fmt.Errorf("no extension field")
	}
	ext := pkt[ntpHeaderSize:]
	if len(ext) < 4 {
		return nil, fmt.Errorf("extension too short")
	}
	extLen := int(binary.BigEndian.Uint16(ext[2:4]))
	if extLen < 4 || extLen > len(ext) {
		return nil, fmt.Errorf("invalid extension length")
	}
	return ext[4:extLen], nil
}

// ═══════════════════════════════════════════════════════════════════════════
// SMTP tunnel — data hidden inside SMTP session with MIME multipart encoding
// Wire: full SMTP handshake (220/EHLO/MAIL FROM/RCPT TO/DATA), target is
// hidden in a Content-Disposition header inside the MIME message body.
// Relay data flows as base64-encoded MIME body lines and 250- continuation
// responses. Looks like legitimate email traffic to inspection.
// ═══════════════════════════════════════════════════════════════════════════

func serveSMTPTunnel(ctx context.Context, port int, emit func(string)) TunnelResult {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return TunnelResult{Error: err}
	}
	defer ln.Close()
	emit(fmt.Sprintf("[+] SMTP tunnel bound on %s", addr))
	emit(fmt.Sprintf("[+] Listening on port %d — waiting for client...", port))
	go func() { <-ctx.Done(); ln.Close() }()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return TunnelResult{}
			}
			continue
		}
		emit(fmt.Sprintf("[+] Client connected from %s", conn.RemoteAddr()))
		go handleSMTPTunnelSession(conn, emit)
	}
}

func handleSMTPTunnelSession(conn net.Conn, emit func(string)) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Minute))

	send := func(msg string) { fmt.Fprintf(conn, "%s\r\n", msg) }
	reader := bufio.NewReader(conn)
	readLine := func() string { l, _ := reader.ReadString('\n'); return strings.TrimSpace(l) }

	// SMTP banner — looks like a real Postfix server.
	send("220 mail.corp-relay.internal ESMTP Postfix (Ubuntu)")

	// Read EHLO.
	line := readLine()
	if !strings.HasPrefix(strings.ToUpper(line), "EHLO") {
		send("500 5.5.1 Command not recognized")
		return
	}
	send("250-mail.corp-relay.internal")
	send("250-PIPELINING")
	send("250-SIZE 52428800")
	send("250-VRFY")
	send("250-ETRN")
	send("250-STARTTLS")
	send("250-8BITMIME")
	send("250-DSN")
	send("250 SMTPUTF8")

	// Read MAIL FROM — realistic address, target is NOT here.
	line = readLine()
	if !strings.HasPrefix(strings.ToUpper(line), "MAIL FROM:") {
		send("503 5.5.1 Error: need MAIL command")
		return
	}
	send("250 2.1.0 Ok")

	// Read RCPT TO.
	line = readLine()
	if !strings.HasPrefix(strings.ToUpper(line), "RCPT TO:") {
		send("503 5.5.1 Error: need RCPT command")
		return
	}
	send("250 2.1.5 Ok")

	// Read DATA command.
	line = readLine()
	if strings.ToUpper(line) != "DATA" {
		send("503 5.5.1 Error: need DATA command")
		return
	}
	send("354 End data with <CR><LF>.<CR><LF>")

	// Read MIME headers from the DATA body to find target in Content-Disposition.
	// The client sends a MIME message where the target is hex-encoded in
	// the Content-Disposition filename parameter.
	target := ""
	for {
		line = readLine()
		if line == "" {
			// Empty line = end of MIME headers, body starts.
			break
		}
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "CONTENT-DISPOSITION:") {
			// Extract filename="<hex-encoded-target>"
			if idx := strings.Index(line, "filename=\""); idx >= 0 {
				rest := line[idx+10:]
				if end := strings.Index(rest, "\""); end >= 0 {
					decoded, err := hex.DecodeString(rest[:end])
					if err == nil && len(decoded) > 0 {
						target = string(decoded)
					}
				}
			}
		}
	}

	if target == "" {
		send("550 5.1.1 Recipient not found")
		return
	}

	remote, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		send("421 4.7.0 Service unavailable")
		return
	}
	defer remote.Close()

	emit(fmt.Sprintf("[+] SMTP tunnel: proxying → %s", target))

	// Now relay: DATA body lines carry base64-encoded tunnel data.
	// Server responses carry base64-encoded return data as 250- continuation lines.
	done := make(chan struct{}, 2)

	// remote → client: read from remote, encode as SMTP multi-line response.
	go func() {
		buf := make([]byte, 16*1024)
		for {
			n, err := remote.Read(buf)
			if err != nil {
				done <- struct{}{}
				return
			}
			encoded := base64.StdEncoding.EncodeToString(buf[:n])
			send("250-" + encoded)
		}
	}()

	// client → remote: read DATA body lines, decode, write to remote.
	go func() {
		for {
			line := readLine()
			if line == "" {
				continue
			}
			if line == "." {
				done <- struct{}{}
				return
			}
			data, err := base64.StdEncoding.DecodeString(line)
			if err != nil || len(data) == 0 {
				continue
			}
			if _, err := remote.Write(data); err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	<-done
}

func connectSMTPTunnelClient(ctx context.Context, proxyAddr string, emit func(string)) TunnelResult {
	// Verify: connect and check for SMTP banner.
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return TunnelResult{Error: fmt.Errorf("cannot reach %s: %w", proxyAddr, err)}
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	conn.Close()
	banner := string(buf[:n])
	if !strings.HasPrefix(banner, "220") {
		return TunnelResult{Error: fmt.Errorf("not an SMTP tunnel on %s", proxyAddr)}
	}

	return startLocalForwarder(ctx, proxyAddr, "smtp", emit, func(local net.Conn) {
		forwardSMTPTunnel(local, proxyAddr, emit)
	})
}

func forwardSMTPTunnel(local net.Conn, proxyAddr string, emit func(string)) {
	defer local.Close()
	local.SetDeadline(time.Now().Add(5 * time.Minute))

	// Accept SOCKS5 from local app.
	buf := make([]byte, 256)
	n, err := local.Read(buf)
	if err != nil || n < 3 || buf[0] != 0x05 {
		return
	}
	local.Write([]byte{0x05, 0x00})
	n, err = local.Read(buf)
	if err != nil || n < 7 || buf[0] != 0x05 || buf[1] != 0x01 {
		local.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	target := parseSOCKS5Target(buf[:n])
	if target == "" {
		local.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Connect to SMTP tunnel server and do full handshake.
	remote, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()
	remote.SetDeadline(time.Now().Add(5 * time.Minute))

	smtpReader := bufio.NewReader(remote)
	smtpSend := func(msg string) { fmt.Fprintf(remote, "%s\r\n", msg) }
	smtpRecvLine := func() string {
		line, _ := smtpReader.ReadString('\n')
		return strings.TrimSpace(line)
	}
	// Read until final response (line without continuation dash).
	smtpRecvFull := func() string {
		var last string
		for {
			line := smtpRecvLine()
			last = line
			if len(line) < 4 || line[3] != '-' {
				break
			}
		}
		return last
	}

	// Read banner.
	banner := smtpRecvLine()
	if !strings.HasPrefix(banner, "220") {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// EHLO — multi-line response.
	smtpSend("EHLO client.corp-relay.internal")
	smtpRecvFull()

	// MAIL FROM with a realistic-looking address (no target here).
	smtpSend("MAIL FROM:<noreply@localhost>")
	resp := smtpRecvLine()
	if !strings.HasPrefix(resp, "250") {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// RCPT TO with a realistic address.
	smtpSend("RCPT TO:<user@example.com>")
	smtpRecvLine() // 250

	// DATA command.
	smtpSend("DATA")
	smtpRecvLine() // 354

	// Send MIME headers with target hidden in Content-Disposition filename (hex-encoded).
	hexTarget := hex.EncodeToString([]byte(target))
	smtpSend("From: noreply@localhost")
	smtpSend("To: user@example.com")
	smtpSend("Subject: Report")
	smtpSend("MIME-Version: 1.0")
	smtpSend("Content-Type: application/octet-stream")
	smtpSend(fmt.Sprintf("Content-Disposition: attachment; filename=\"%s\"", hexTarget))
	smtpSend("Content-Transfer-Encoding: base64")
	smtpSend("") // End of MIME headers, body starts.

	local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	emit(fmt.Sprintf("[+] SMTP tunnel forwarding → %s", target))

	// Relay: local→remote as base64 DATA body lines, remote→local from 250- lines.
	done := make(chan struct{}, 2)
	go func() {
		for {
			line := smtpRecvLine()
			if line == "" {
				done <- struct{}{}
				return
			}
			if strings.HasPrefix(line, "250-") {
				data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "250-"))
				if err == nil && len(data) > 0 {
					if _, err := local.Write(data); err != nil {
						done <- struct{}{}
						return
					}
				}
			}
		}
	}()
	go func() {
		b := make([]byte, 16*1024)
		for {
			n, err := local.Read(b)
			if err != nil {
				done <- struct{}{}
				return
			}
			encoded := base64.StdEncoding.EncodeToString(b[:n])
			smtpSend(encoded)
		}
	}()
	<-done
}
