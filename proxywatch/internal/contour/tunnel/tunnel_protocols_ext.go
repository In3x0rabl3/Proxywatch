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
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════
// Shared protocol-framed relay helpers
// These replace raw relay() so every byte stays in protocol wire format.
// ═══════════════════════════════════════════════════════════════════════════

// binRelayDefault relays data between a raw connection and a framed connection.
// rawConn=first arg, framedConn=second arg.
// framedConn uses 4-byte length-prefixed frames: [LEN:4][DATA:LEN]
func binRelayDefault(rawConn, framedConn net.Conn) {
	done := make(chan struct{}, 2)
	// framedConn → rawConn: read frames, write raw
	go func() {
		for {
			data, err := binRecvFrame(framedConn)
			if err != nil {
				done <- struct{}{}
				return
			}
			if _, err := rawConn.Write(data); err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	// rawConn → framedConn: read raw, write frames
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := rawConn.Read(buf)
			if err != nil || n == 0 {
				done <- struct{}{}
				return
			}
			if binSendFrame(framedConn, buf[:n]) != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	<-done
}

func binSendFrame(dst net.Conn, data []byte) error {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(data)))
	if _, err := dst.Write(hdr); err != nil {
		return err
	}
	_, err := dst.Write(data)
	return err
}

func binRecvFrame(src net.Conn) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(src, hdr); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(hdr)
	if length == 0 || length > 1<<20 {
		return nil, fmt.Errorf("invalid frame length: %d", length)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(src, data); err != nil {
		return nil, err
	}
	return data, nil
}

// lineRelay relays data between a raw connection and a framed connection.
// framedConn sends/receives base64 lines with protocol prefixes.
// rawConn sends/receives raw bytes.
// toRawPrefix: prefix on lines FROM framedConn (to decode)
// toFramedPrefix: prefix for lines TO framedConn (to encode)
func lineRelay(rawConn, framedConn net.Conn, toRawPrefix, toFramedPrefix string) {
	done := make(chan struct{}, 2)
	framedReader := bufio.NewReader(framedConn)
	// framedConn → rawConn: read framed lines, decode, write raw
	go func() {
		for {
			line, err := framedReader.ReadString('\n')
			if err != nil {
				done <- struct{}{}
				return
			}
			line = strings.TrimSpace(line)
			payload := strings.TrimPrefix(line, toRawPrefix)
			data, err := base64.StdEncoding.DecodeString(payload)
			if err != nil || len(data) == 0 {
				continue
			}
			if _, err := rawConn.Write(data); err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	// rawConn → framedConn: read raw, encode as framed lines
	go func() {
		buf := make([]byte, 16*1024)
		for {
			n, err := rawConn.Read(buf)
			if err != nil || n == 0 {
				done <- struct{}{}
				return
			}
			encoded := base64.StdEncoding.EncodeToString(buf[:n])
			line := toFramedPrefix + encoded + "\r\n"
			if _, err := framedConn.Write([]byte(line)); err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	<-done
}

// respRelay wraps data in Redis RESP bulk strings.
// Server→Client: $<len>\r\n<data>\r\n
// Client→Server: $<len>\r\n<data>\r\n
// respRelay: rawConn=first, framedConn=second. Uses Redis RESP bulk strings.
func respRelay(rawConn, framedConn net.Conn) {
	done := make(chan struct{}, 2)
	framedReader := bufio.NewReader(framedConn)
	// framedConn → rawConn: read RESP frames, write raw
	go func() {
		for {
			line, err := framedReader.ReadString('\n')
			if err != nil {
				done <- struct{}{}
				return
			}
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "$") {
				continue
			}
			var length int
			fmt.Sscanf(line, "$%d", &length)
			if length <= 0 || length > 1<<20 {
				continue
			}
			data := make([]byte, length)
			if _, err := io.ReadFull(framedReader, data); err != nil {
				done <- struct{}{}
				return
			}
			framedReader.ReadString('\n') // trailing \r\n
			if _, err := rawConn.Write(data); err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	// rawConn → framedConn: read raw, write RESP frames
	go func() {
		buf := make([]byte, 16*1024)
		for {
			n, err := rawConn.Read(buf)
			if err != nil || n == 0 {
				done <- struct{}{}
				return
			}
			frame := fmt.Sprintf("$%d\r\n", n)
			framedConn.Write([]byte(frame))
			framedConn.Write(buf[:n])
			framedConn.Write([]byte("\r\n"))
		}
	}()
	<-done
}

// mqttRelay wraps data in MQTT PUBLISH packets.
// Wire: 0x30 (PUBLISH QoS0) + remaining length + topic + payload
// mqttRelay: rawConn=first, framedConn=second. Uses MQTT PUBLISH packets.
func mqttRelay(rawConn, framedConn net.Conn) {
	topic := []byte("pw")
	done := make(chan struct{}, 2)
	writeMQTT := func(dst net.Conn, payload []byte) error {
		topicLen := len(topic)
		remaining := 2 + topicLen + len(payload)
		var hdr []byte
		hdr = append(hdr, 0x30) // PUBLISH, QoS 0
		// Encode remaining length (MQTT variable-length encoding)
		for {
			b := byte(remaining % 128)
			remaining /= 128
			if remaining > 0 {
				b |= 0x80
			}
			hdr = append(hdr, b)
			if remaining == 0 {
				break
			}
		}
		hdr = append(hdr, byte(topicLen>>8), byte(topicLen))
		hdr = append(hdr, topic...)
		dst.Write(hdr)
		_, err := dst.Write(payload)
		return err
	}
	readMQTT := func(src net.Conn) ([]byte, error) {
		hdr := make([]byte, 1)
		if _, err := io.ReadFull(src, hdr); err != nil {
			return nil, err
		}
		// Decode remaining length
		remaining := 0
		multiplier := 1
		for {
			b := make([]byte, 1)
			if _, err := io.ReadFull(src, b); err != nil {
				return nil, err
			}
			remaining += int(b[0]&0x7F) * multiplier
			multiplier *= 128
			if b[0]&0x80 == 0 {
				break
			}
		}
		data := make([]byte, remaining)
		if _, err := io.ReadFull(src, data); err != nil {
			return nil, err
		}
		// Skip topic (2-byte length + topic bytes)
		if len(data) < 2 {
			return nil, fmt.Errorf("short MQTT packet")
		}
		topicLen := int(data[0])<<8 | int(data[1])
		if 2+topicLen > len(data) {
			return nil, fmt.Errorf("invalid topic length")
		}
		return data[2+topicLen:], nil
	}

	// framedConn → rawConn: read MQTT frames, write raw
	go func() {
		for {
			data, err := readMQTT(framedConn)
			if err != nil {
				done <- struct{}{}
				return
			}
			if _, err := rawConn.Write(data); err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	// rawConn → framedConn: read raw, write MQTT frames
	go func() {
		buf := make([]byte, 16*1024)
		for {
			n, err := rawConn.Read(buf)
			if err != nil {
				done <- struct{}{}
				return
			}
			if writeMQTT(framedConn, buf[:n]) != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	<-done
}

// pgRelay: rawConn=first, framedConn=second. Uses PostgreSQL messages.
func pgRelay(rawConn, framedConn net.Conn) {
	done := make(chan struct{}, 2)
	writePG := func(dst net.Conn, msgType byte, payload []byte) error {
		hdr := make([]byte, 5)
		hdr[0] = msgType
		binary.BigEndian.PutUint32(hdr[1:5], uint32(4+len(payload)))
		dst.Write(hdr)
		_, err := dst.Write(payload)
		return err
	}
	readPG := func(src net.Conn) (byte, []byte, error) {
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(src, hdr); err != nil {
			return 0, nil, err
		}
		length := binary.BigEndian.Uint32(hdr[1:5])
		if length < 4 || length > 1<<20 {
			return 0, nil, fmt.Errorf("invalid PG message length")
		}
		data := make([]byte, length-4)
		if _, err := io.ReadFull(src, data); err != nil {
			return 0, nil, err
		}
		return hdr[0], data, nil
	}

	// framedConn → rawConn: read PG frames, write raw
	go func() {
		for {
			_, data, err := readPG(framedConn)
			if err != nil {
				done <- struct{}{}
				return
			}
			if _, err := rawConn.Write(data); err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	// rawConn → framedConn: read raw, write PG DataRow ('D')
	go func() {
		buf := make([]byte, 16*1024)
		for {
			n, err := rawConn.Read(buf)
			if err != nil {
				done <- struct{}{}
				return
			}
			if writePG(framedConn, 'D', buf[:n]) != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	<-done
}

// sshRelay: rawConn=first, framedConn=second. Uses SSH channel data messages.
// SSH message types (RFC 4254)
const (
	sshMsgChannelData byte = 94
)

// sshWritePacket wraps payload in proper SSH binary packet format (RFC 4253).
// Format: uint32 packet_length + byte padding_length + payload + padding
func sshWritePacket(dst net.Conn, payload []byte) error {
	// Padding to 8-byte boundary (minimum 4 bytes)
	paddingLen := 8 - ((len(payload) + 5) % 8)
	if paddingLen < 4 {
		paddingLen += 8
	}
	packetLen := 1 + len(payload) + paddingLen
	pkt := make([]byte, 4+packetLen)
	binary.BigEndian.PutUint32(pkt[0:4], uint32(packetLen))
	pkt[4] = byte(paddingLen)
	copy(pkt[5:], payload)
	// Padding bytes (zeros for simplicity)
	_, err := dst.Write(pkt)
	return err
}

// sshReadPacket reads an SSH binary packet and returns the payload.
func sshReadPacket(src io.Reader) ([]byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(src, hdr); err != nil {
		return nil, err
	}
	packetLen := binary.BigEndian.Uint32(hdr[0:4])
	if packetLen < 2 || packetLen > 1<<20 {
		return nil, fmt.Errorf("invalid SSH packet length: %d", packetLen)
	}
	paddingLen := int(hdr[4])
	payloadLen := int(packetLen) - 1 - paddingLen
	if payloadLen < 0 || payloadLen > 1<<20 {
		return nil, fmt.Errorf("invalid SSH payload length")
	}
	rest := make([]byte, packetLen-1)
	if _, err := io.ReadFull(src, rest); err != nil {
		return nil, err
	}
	return rest[:payloadLen], nil
}

// sshBuildChannelData builds SSH_MSG_CHANNEL_DATA payload (RFC 4254).
// Format: byte msg_type + uint32 recipient_channel + string data
func sshBuildChannelData(channel uint32, data []byte) []byte {
	payload := make([]byte, 1+4+4+len(data))
	payload[0] = sshMsgChannelData
	binary.BigEndian.PutUint32(payload[1:5], channel)
	binary.BigEndian.PutUint32(payload[5:9], uint32(len(data)))
	copy(payload[9:], data)
	return payload
}

// sshParseChannelData extracts data from SSH_MSG_CHANNEL_DATA payload.
func sshParseChannelData(payload []byte) ([]byte, error) {
	if len(payload) < 9 {
		return nil, fmt.Errorf("SSH channel data too short")
	}
	if payload[0] != sshMsgChannelData {
		return nil, fmt.Errorf("expected SSH_MSG_CHANNEL_DATA (94), got %d", payload[0])
	}
	dataLen := binary.BigEndian.Uint32(payload[5:9])
	if int(dataLen) > len(payload)-9 {
		return nil, fmt.Errorf("SSH channel data length mismatch")
	}
	return payload[9 : 9+dataLen], nil
}

func sshRelay(rawConn, framedConn net.Conn) {
	done := make(chan struct{}, 2)
	framedReader := bufio.NewReader(framedConn)

	// framedConn → rawConn: read SSH packets, extract channel data, write raw
	go func() {
		for {
			payload, err := sshReadPacket(framedReader)
			if err != nil {
				done <- struct{}{}
				return
			}
			data, err := sshParseChannelData(payload)
			if err != nil {
				continue
			}
			if _, err := rawConn.Write(data); err != nil {
				done <- struct{}{}
				return
			}
		}
	}()

	// rawConn → framedConn: read raw, wrap in SSH channel data packets
	go func() {
		buf := make([]byte, 16*1024)
		for {
			n, err := rawConn.Read(buf)
			if err != nil {
				done <- struct{}{}
				return
			}
			payload := sshBuildChannelData(0, buf[:n])
			if sshWritePacket(framedConn, payload) != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	<-done
}

// ═══════════════════════════════════════════════════════════════════════════
// FTP tunnel — tunnel data carried in FTP data transfer
// Wire: 220 banner, USER/PASS/CWD(hex target)/PASV/RETR exchange
// Target is hex-encoded as directory path in CWD command.
// ═══════════════════════════════════════════════════════════════════════════

func serveFTPTunnel(ctx context.Context, port int, emit func(string)) TunnelResult {
	return serveTCPTunnel(ctx, "FTP", port, emit, func(conn net.Conn) (string, net.Conn, error) {
		send := func(code int, msg string) { fmt.Fprintf(conn, "%d %s\r\n", code, msg) }
		reader := bufio.NewReader(conn)
		readLine := func() string { l, _ := reader.ReadString('\n'); return strings.TrimSpace(l) }

		send(220, "ProFTPD 1.3.6 Server (Debian)")

		// USER anonymous
		line := readLine()
		if !strings.HasPrefix(strings.ToUpper(line), "USER ") {
			send(530, "Login incorrect")
			return "", nil, fmt.Errorf("expected USER")
		}
		send(331, "Password required for anonymous")

		// PASS
		readLine()
		send(230, "Anonymous access granted, restrictions apply")

		// CWD carries the target hex-encoded as a directory path.
		line = readLine()
		target := ""
		if strings.HasPrefix(strings.ToUpper(line), "CWD ") {
			path := strings.TrimSpace(line[4:])
			path = strings.TrimPrefix(path, "/")
			decoded, err := hex.DecodeString(path)
			if err == nil && len(decoded) > 0 {
				target = string(decoded)
			}
		}
		if target == "" {
			send(550, "Failed to change directory")
			return "", nil, fmt.Errorf("no target in CWD")
		}
		send(250, "Directory successfully changed")

		// PASV
		line = readLine()
		if strings.HasPrefix(strings.ToUpper(line), "PASV") {
			send(227, "Entering Passive Mode (127,0,0,1,0,0)")
		}

		// TYPE I
		line = readLine()
		if strings.HasPrefix(strings.ToUpper(line), "TYPE ") {
			send(200, "Switching to Binary mode")
		}

		// RETR data.bin
		line = readLine()
		if !strings.HasPrefix(strings.ToUpper(line), "RETR ") {
			send(550, "Failed to open file")
			return "", nil, fmt.Errorf("expected RETR")
		}

		remote, err := net.DialTimeout("tcp", target, 10*time.Second)
		if err != nil {
			send(550, "Connection refused")
			return "", nil, err
		}
		send(150, "Opening BINARY mode data connection for data.bin")
		return target, remote, nil
	}, func(rawConn, framedConn net.Conn) {
		lineRelay(rawConn, framedConn, "STOR ", "226-")
	})
}

func connectFTPTunnelClient(ctx context.Context, proxyAddr string, emit func(string)) TunnelResult {
	// Verify: check for FTP banner.
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return TunnelResult{Error: fmt.Errorf("cannot reach %s: %w", proxyAddr, err)}
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	conn.Close()
	if !strings.HasPrefix(string(buf[:n]), "220") {
		return TunnelResult{Error: fmt.Errorf("not an FTP tunnel on %s", proxyAddr)}
	}

	return startLocalForwarder(ctx, proxyAddr, "ftp", emit, func(local net.Conn) {
		forwardGenericTextTunnel(local, proxyAddr, "ftp", emit, func(remote net.Conn, target string) bool {
			reader := bufio.NewReader(remote)
			readLine := func() string { l, _ := reader.ReadString('\n'); return strings.TrimSpace(l) }
			sendCmd := func(cmd string) string { fmt.Fprintf(remote, "%s\r\n", cmd); return readLine() }

			readLine()                 // 220 banner
			sendCmd("USER anonymous")  // 331
			sendCmd("PASS anonymous@") // 230
			hexTarget := hex.EncodeToString([]byte(target))
			sendCmd("CWD /" + hexTarget)     // 250
			sendCmd("PASV")                  // 227
			sendCmd("TYPE I")                // 200
			resp := sendCmd("RETR data.bin") // 150 or 550
			return strings.HasPrefix(resp, "150")
		}, func(client, remote net.Conn) {
			lineRelay(client, remote, "226-", "STOR ")
		})
	})
}

// ═══════════════════════════════════════════════════════════════════════════
// IMAP tunnel — tunnel data in IMAP FETCH responses and APPEND commands
// Wire: * OK banner, LOGIN, SELECT <hex-target>, FETCH with IMAP literals
// Target is hex-encoded in SELECT mailbox name (looks like a UUID mailbox).
// ═══════════════════════════════════════════════════════════════════════════

func serveIMAPTunnel(ctx context.Context, port int, emit func(string)) TunnelResult {
	return serveTCPTunnel(ctx, "IMAP", port, emit, func(conn net.Conn) (string, net.Conn, error) {
		send := func(tag, msg string) { fmt.Fprintf(conn, "%s %s\r\n", tag, msg) }
		reader := bufio.NewReader(conn)
		readLine := func() string { l, _ := reader.ReadString('\n'); return strings.TrimSpace(l) }

		send("*", "OK Dovecot (Ubuntu) IMAP4rev1 ready")

		// A1 LOGIN user pass
		line := readLine()
		if !strings.HasPrefix(strings.ToUpper(line), "A1 LOGIN") {
			send("A1", "BAD Command not recognized")
			return "", nil, fmt.Errorf("expected LOGIN")
		}
		send("A1", "OK Logged in")

		// A2 SELECT <hex-encoded-target> — target hidden as mailbox name.
		line = readLine()
		target := ""
		parts := strings.Fields(line)
		if len(parts) >= 3 && strings.ToUpper(parts[1]) == "SELECT" {
			mailbox := parts[2]
			decoded, err := hex.DecodeString(mailbox)
			if err == nil && len(decoded) > 0 {
				target = string(decoded)
			}
		}
		if target == "" {
			send("A2", "NO Mailbox not found")
			return "", nil, fmt.Errorf("no target in SELECT")
		}
		send("*", "FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)")
		send("*", "OK [PERMANENTFLAGS (\\Deleted \\Seen \\*)] Flags permitted")
		send("*", "1 EXISTS")
		send("*", "0 RECENT")
		send("*", "OK [UIDVALIDITY 1585295langley] UIDs valid")
		send("A2", "OK [READ-WRITE] Select completed")

		// A3 FETCH 1 BODY[]
		line = readLine()
		if !strings.HasPrefix(strings.ToUpper(line), "A3 FETCH") {
			send("A3", "BAD Command not recognized")
			return "", nil, fmt.Errorf("expected FETCH")
		}

		remote, err := net.DialTimeout("tcp", target, 10*time.Second)
		if err != nil {
			send("A3", "NO Connection refused")
			return "", nil, err
		}
		send("A3", "OK FETCH completed")
		return target, remote, nil
	}, func(rawConn, framedConn net.Conn) {
		lineRelay(rawConn, framedConn, "A4 APPEND ", "* DATA ")
	})
}

func connectIMAPTunnelClient(ctx context.Context, proxyAddr string, emit func(string)) TunnelResult {
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return TunnelResult{Error: fmt.Errorf("cannot reach %s: %w", proxyAddr, err)}
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	conn.Close()
	if !strings.Contains(string(buf[:n]), "IMAP") {
		return TunnelResult{Error: fmt.Errorf("not an IMAP tunnel on %s", proxyAddr)}
	}

	return startLocalForwarder(ctx, proxyAddr, "imap", emit, func(local net.Conn) {
		forwardGenericTextTunnel(local, proxyAddr, "imap", emit, func(remote net.Conn, target string) bool {
			reader := bufio.NewReader(remote)
			readLine := func() string { l, _ := reader.ReadString('\n'); return strings.TrimSpace(l) }
			sendCmd := func(tag, cmd string) string { fmt.Fprintf(remote, "%s %s\r\n", tag, cmd); return readLine() }

			readLine() // * OK banner
			sendCmd("A1", "LOGIN user pass")
			hexTarget := hex.EncodeToString([]byte(target))
			resp := sendCmd("A2", "SELECT "+hexTarget)
			// Drain multi-line SELECT response.
			for !strings.HasPrefix(resp, "A2 ") {
				resp = readLine()
			}
			if !strings.Contains(resp, "OK") {
				return false
			}
			resp = sendCmd("A3", "FETCH 1 BODY[]")
			return strings.Contains(resp, "OK")
		}, func(client, remote net.Conn) {
			lineRelay(client, remote, "* DATA ", "A4 APPEND ")
		})
	})
}

// ═══════════════════════════════════════════════════════════════════════════
// POP3 tunnel — tunnel data in POP3 RETR responses
// Wire: +OK banner, USER <hex-target>/PASS/RETR 1 exchange
// Target is hex-encoded in USER value (looks like an email/account ID).
// ═══════════════════════════════════════════════════════════════════════════

func servePOP3Tunnel(ctx context.Context, port int, emit func(string)) TunnelResult {
	return serveTCPTunnel(ctx, "POP3", port, emit, func(conn net.Conn) (string, net.Conn, error) {
		send := func(msg string) { fmt.Fprintf(conn, "%s\r\n", msg) }
		reader := bufio.NewReader(conn)
		readLine := func() string { l, _ := reader.ReadString('\n'); return strings.TrimSpace(l) }

		send("+OK Dovecot (Ubuntu) ready.")

		// USER carries the hex-encoded target.
		line := readLine()
		target := ""
		if strings.HasPrefix(strings.ToUpper(line), "USER ") {
			userVal := strings.TrimSpace(line[5:])
			decoded, err := hex.DecodeString(userVal)
			if err == nil && len(decoded) > 0 {
				target = string(decoded)
			}
		}
		if target == "" {
			send("-ERR [AUTH] Authentication failed")
			return "", nil, fmt.Errorf("no target in USER")
		}
		send("+OK")

		// PASS
		readLine()
		send("+OK Logged in")

		// STAT (optional, some clients send it)
		line = readLine()
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "STAT") {
			send("+OK 1 4096")
			line = readLine()
			upper = strings.ToUpper(line)
		}

		// RETR 1
		if !strings.HasPrefix(upper, "RETR ") {
			send("-ERR Unknown command")
			return "", nil, fmt.Errorf("expected RETR")
		}

		remote, err := net.DialTimeout("tcp", target, 10*time.Second)
		if err != nil {
			send("-ERR Connection refused")
			return "", nil, err
		}
		send("+OK 4096 octets")
		return target, remote, nil
	}, func(rawConn, framedConn net.Conn) {
		lineRelay(rawConn, framedConn, "RETR ", "+OK ")
	})
}

func connectPOP3TunnelClient(ctx context.Context, proxyAddr string, emit func(string)) TunnelResult {
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return TunnelResult{Error: fmt.Errorf("cannot reach %s: %w", proxyAddr, err)}
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	conn.Close()
	if !strings.HasPrefix(string(buf[:n]), "+OK") {
		return TunnelResult{Error: fmt.Errorf("not a POP3 tunnel on %s", proxyAddr)}
	}

	return startLocalForwarder(ctx, proxyAddr, "pop3", emit, func(local net.Conn) {
		forwardGenericTextTunnel(local, proxyAddr, "pop3", emit, func(remote net.Conn, target string) bool {
			reader := bufio.NewReader(remote)
			readLine := func() string { l, _ := reader.ReadString('\n'); return strings.TrimSpace(l) }
			sendCmd := func(cmd string) string { fmt.Fprintf(remote, "%s\r\n", cmd); return readLine() }

			readLine() // +OK banner
			hexTarget := hex.EncodeToString([]byte(target))
			sendCmd("USER " + hexTarget)
			sendCmd("PASS anonymous")
			resp := sendCmd("RETR 1")
			return strings.HasPrefix(resp, "+OK")
		}, func(client, remote net.Conn) {
			lineRelay(client, remote, "+OK ", "RETR ")
		})
	})
}

// ═══════════════════════════════════════════════════════════════════════════
// Redis tunnel — tunnel data in Redis RESP bulk strings
// Wire: PING/PONG, SET/GET with realistic session keys (hex-encoded target)
// Target is hex-encoded as a session-like key: "sess:<hex>"
// ═══════════════════════════════════════════════════════════════════════════

func serveRedisTunnel(ctx context.Context, port int, emit func(string)) TunnelResult {
	return serveTCPTunnel(ctx, "Redis", port, emit, func(conn net.Conn) (string, net.Conn, error) {
		reader := bufio.NewReader(conn)
		readLine := func() string { l, _ := reader.ReadString('\n'); return strings.TrimSpace(l) }

		// Read RESP commands until we get a GET with the target.
		for {
			line := readLine()
			if line == "" {
				return "", nil, fmt.Errorf("connection closed")
			}
			if !strings.HasPrefix(line, "*") {
				fmt.Fprintf(conn, "-ERR invalid\r\n")
				continue
			}
			var argc int
			fmt.Sscanf(line, "*%d", &argc)
			// Read argc bulk strings.
			args := make([]string, 0, argc)
			for i := 0; i < argc; i++ {
				readLine() // $<len>
				args = append(args, readLine())
			}
			if len(args) == 0 {
				continue
			}
			cmd := strings.ToUpper(args[0])
			if cmd == "PING" {
				fmt.Fprintf(conn, "+PONG\r\n")
				continue
			}
			if cmd == "GET" && len(args) >= 2 {
				// Key format: "sess:<hex-encoded-target>"
				key := args[1]
				hexPart := strings.TrimPrefix(key, "sess:")
				if hexPart == key {
					// No "sess:" prefix — try raw hex.
					hexPart = key
				}
				decoded, err := hex.DecodeString(hexPart)
				if err != nil || len(decoded) == 0 {
					fmt.Fprintf(conn, "$-1\r\n")
					continue
				}
				target := string(decoded)
				remote, err := net.DialTimeout("tcp", target, 10*time.Second)
				if err != nil {
					fmt.Fprintf(conn, "-ERR connection refused\r\n")
					return "", nil, err
				}
				fmt.Fprintf(conn, "+OK\r\n")
				return target, remote, nil
			}
			if cmd == "SET" && len(args) >= 3 {
				fmt.Fprintf(conn, "+OK\r\n")
				continue
			}
			fmt.Fprintf(conn, "-ERR unknown command '%s'\r\n", cmd)
		}
	}, respRelay)
}

func connectRedisTunnelClient(ctx context.Context, proxyAddr string, emit func(string)) TunnelResult {
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return TunnelResult{Error: fmt.Errorf("cannot reach %s: %w", proxyAddr, err)}
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	// Send a PING, expect +PONG.
	fmt.Fprintf(conn, "*1\r\n$4\r\nPING\r\n")
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	conn.Close()
	if n == 0 {
		return TunnelResult{Error: fmt.Errorf("no response from %s", proxyAddr)}
	}

	return startLocalForwarder(ctx, proxyAddr, "redis", emit, func(local net.Conn) {
		forwardGenericTextTunnel(local, proxyAddr, "redis", emit, func(remote net.Conn, target string) bool {
			hexTarget := hex.EncodeToString([]byte(target))
			key := "sess:" + hexTarget
			// Send as RESP: *2\r\n$3\r\nGET\r\n$<len>\r\n<key>\r\n
			fmt.Fprintf(remote, "*2\r\n$3\r\nGET\r\n$%d\r\n%s\r\n", len(key), key)
			reader := bufio.NewReader(remote)
			line, _ := reader.ReadString('\n')
			return strings.HasPrefix(strings.TrimSpace(line), "+OK")
		}, respRelay)
	})
}

// ═══════════════════════════════════════════════════════════════════════════
// PostgreSQL tunnel — tunnel data in PostgreSQL query/row messages
// Wire: real PostgreSQL startup with protocol 3.0, AuthenticationOk,
// ReadyForQuery. Target is hex-encoded in database field of startup message.
// ═══════════════════════════════════════════════════════════════════════════

func servePostgresTunnel(ctx context.Context, port int, emit func(string)) TunnelResult {
	return serveTCPTunnel(ctx, "PostgreSQL", port, emit, func(conn net.Conn) (string, net.Conn, error) {
		// Read StartupMessage: 4-byte length + 4-byte protocol + key=value\0 pairs + \0
		lenBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", nil, err
		}
		msgLen := int(binary.BigEndian.Uint32(lenBuf))
		if msgLen < 8 || msgLen > 8192 {
			return "", nil, fmt.Errorf("invalid startup message length")
		}
		body := make([]byte, msgLen-4)
		if _, err := io.ReadFull(conn, body); err != nil {
			return "", nil, err
		}

		// Parse protocol version (should be 3.0 = 0x00030000).
		if len(body) < 4 {
			return "", nil, fmt.Errorf("startup message too short")
		}

		// Parse key-value pairs to find "database" field.
		target := ""
		params := body[4:] // skip protocol version
		for len(params) > 1 {
			// Find key.
			idx := 0
			for idx < len(params) && params[idx] != 0 {
				idx++
			}
			if idx >= len(params) {
				break
			}
			key := string(params[:idx])
			params = params[idx+1:]
			// Find value.
			idx = 0
			for idx < len(params) && params[idx] != 0 {
				idx++
			}
			if idx >= len(params) {
				break
			}
			val := string(params[:idx])
			params = params[idx+1:]

			if key == "database" {
				decoded, err := hex.DecodeString(val)
				if err == nil && len(decoded) > 0 {
					target = string(decoded)
				}
			}
		}

		if target == "" {
			// Send ErrorResponse.
			errMsg := []byte("SFATAL\x00MVFATAL: database does not exist\x00\x00")
			hdr := make([]byte, 5)
			hdr[0] = 'E'
			binary.BigEndian.PutUint32(hdr[1:5], uint32(4+len(errMsg)))
			conn.Write(hdr)
			conn.Write(errMsg)
			return "", nil, fmt.Errorf("no target in startup database field")
		}

		remote, err := net.DialTimeout("tcp", target, 10*time.Second)
		if err != nil {
			errMsg := []byte("SFATAL\x00Mcould not connect\x00\x00")
			hdr := make([]byte, 5)
			hdr[0] = 'E'
			binary.BigEndian.PutUint32(hdr[1:5], uint32(4+len(errMsg)))
			conn.Write(hdr)
			conn.Write(errMsg)
			return "", nil, err
		}

		// Send AuthenticationOk: R\x00\x00\x00\x08\x00\x00\x00\x00
		conn.Write([]byte{'R', 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00})
		// Send ReadyForQuery: Z\x00\x00\x00\x05I
		conn.Write([]byte{'Z', 0x00, 0x00, 0x00, 0x05, 'I'})

		return target, remote, nil
	}, pgRelay)
}

func connectPostgresTunnelClient(ctx context.Context, proxyAddr string, emit func(string)) TunnelResult {
	// Verify: send StartupMessage with a test database, expect AuthenticationOk or Error.
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return TunnelResult{Error: fmt.Errorf("cannot reach %s: %w", proxyAddr, err)}
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	// Send a minimal StartupMessage with protocol 3.0.
	startup := pgBuildStartupMessage("user", "verify", "database", "verify")
	conn.Write(startup)
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	conn.Close()
	// Expect an 'R' (AuthenticationOk) or 'E' (Error) response — either proves it's PG.
	if n == 0 || (buf[0] != 'R' && buf[0] != 'E') {
		return TunnelResult{Error: fmt.Errorf("not a PostgreSQL tunnel on %s", proxyAddr)}
	}

	return startLocalForwarder(ctx, proxyAddr, "postgresql", emit, func(local net.Conn) {
		forwardGenericTextTunnel(local, proxyAddr, "postgresql", emit, func(remote net.Conn, target string) bool {
			hexTarget := hex.EncodeToString([]byte(target))
			startup := pgBuildStartupMessage("user", "postgres", "database", hexTarget)
			remote.Write(startup)

			// Read response — expect 'R' (AuthenticationOk).
			hdr := make([]byte, 1)
			if _, err := io.ReadFull(remote, hdr); err != nil {
				return false
			}
			if hdr[0] != 'R' {
				return false
			}
			// Read rest of AuthenticationOk (8 bytes: length 4 + auth type 4).
			rest := make([]byte, 4)
			io.ReadFull(remote, rest)
			authLen := int(binary.BigEndian.Uint32(rest))
			if authLen > 4 {
				discard := make([]byte, authLen-4)
				io.ReadFull(remote, discard)
			}
			// Read ReadyForQuery.
			rdy := make([]byte, 6)
			io.ReadFull(remote, rdy) // Z + 4-byte len + status
			return rdy[0] == 'Z'
		}, pgRelay)
	})
}

// pgBuildStartupMessage constructs a PostgreSQL StartupMessage (protocol 3.0).
func pgBuildStartupMessage(kvPairs ...string) []byte {
	var body []byte
	// Protocol version 3.0.
	body = append(body, 0x00, 0x03, 0x00, 0x00)
	for i := 0; i+1 < len(kvPairs); i += 2 {
		body = append(body, []byte(kvPairs[i])...)
		body = append(body, 0x00)
		body = append(body, []byte(kvPairs[i+1])...)
		body = append(body, 0x00)
	}
	body = append(body, 0x00) // terminator

	length := uint32(4 + len(body))
	msg := make([]byte, 4)
	binary.BigEndian.PutUint32(msg, length)
	msg = append(msg, body...)
	return msg
}

// ═══════════════════════════════════════════════════════════════════════════
// BER-TLV helpers for LDAP wire format
// ═══════════════════════════════════════════════════════════════════════════

func berLength(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	var buf [4]byte
	i := 3
	v := n
	for v > 0 {
		buf[i] = byte(v & 0xff)
		v >>= 8
		i--
	}
	numBytes := 3 - i
	out := make([]byte, 1+numBytes)
	out[0] = byte(0x80 | numBytes)
	copy(out[1:], buf[4-numBytes:])
	return out
}

func berSequence(tag byte, payload []byte) []byte {
	l := berLength(len(payload))
	out := make([]byte, 0, 1+len(l)+len(payload))
	out = append(out, tag)
	out = append(out, l...)
	out = append(out, payload...)
	return out
}

func berReadElement(r io.Reader) (byte, []byte, error) {
	tagBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, tagBuf); err != nil {
		return 0, nil, err
	}
	tag := tagBuf[0]
	lenBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return 0, nil, err
	}
	var length int
	if lenBuf[0] < 128 {
		length = int(lenBuf[0])
	} else {
		numBytes := int(lenBuf[0] & 0x7f)
		if numBytes > 4 {
			return 0, nil, fmt.Errorf("BER length too large")
		}
		lb := make([]byte, numBytes)
		if _, err := io.ReadFull(r, lb); err != nil {
			return 0, nil, err
		}
		for _, b := range lb {
			length = (length << 8) | int(b)
		}
	}
	if length < 0 || length > 1<<20 {
		return 0, nil, fmt.Errorf("BER invalid length: %d", length)
	}
	data := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, data); err != nil {
			return 0, nil, err
		}
	}
	return tag, data, nil
}

// ═══════════════════════════════════════════════════════════════════════════
// LDAP tunnel — real LDAP BER-TLV wire format
// Wire: BindRequest(0x60)/BindResponse(0x61), SearchRequest(0x63) for
// target, ExtendedResponse(0x78) for data relay
// ═══════════════════════════════════════════════════════════════════════════

func ldapBuildBindRequest(msgID int) []byte {
	idBytes := berSequence(0x02, []byte{byte(msgID)})
	version := berSequence(0x02, []byte{3})
	name := berSequence(0x04, nil)
	auth := berSequence(0x80, nil)
	bindReq := berSequence(0x60, append(append(version, name...), auth...))
	return berSequence(0x30, append(idBytes, bindReq...))
}

func ldapBuildBindResponse(msgID int) []byte {
	idBytes := berSequence(0x02, []byte{byte(msgID)})
	resultCode := berSequence(0x0a, []byte{0})
	matchedDN := berSequence(0x04, nil)
	diagMsg := berSequence(0x04, nil)
	bindResp := berSequence(0x61, append(append(resultCode, matchedDN...), diagMsg...))
	return berSequence(0x30, append(idBytes, bindResp...))
}

func ldapBuildSearchRequest(msgID int, baseDN string) []byte {
	idBytes := berSequence(0x02, []byte{byte(msgID)})
	base := berSequence(0x04, []byte(baseDN))
	scope := berSequence(0x0a, []byte{0})
	deref := berSequence(0x0a, []byte{0})
	sizeLimit := berSequence(0x02, []byte{0})
	timeLimit := berSequence(0x02, []byte{0})
	typesOnly := berSequence(0x01, []byte{0})
	filter := berSequence(0x87, []byte("objectClass"))
	attrs := berSequence(0x30, nil)
	searchBody := append(append(append(append(append(append(append(base, scope...), deref...), sizeLimit...), timeLimit...), typesOnly...), filter...), attrs...)
	searchReq := berSequence(0x63, searchBody)
	return berSequence(0x30, append(idBytes, searchReq...))
}

func ldapBuildSearchResDone(msgID int) []byte {
	idBytes := berSequence(0x02, []byte{byte(msgID)})
	resultCode := berSequence(0x0a, []byte{0})
	matchedDN := berSequence(0x04, nil)
	diagMsg := berSequence(0x04, nil)
	resDone := berSequence(0x65, append(append(resultCode, matchedDN...), diagMsg...))
	return berSequence(0x30, append(idBytes, resDone...))
}

func ldapBuildExtendedResponse(msgID int, payload []byte) []byte {
	idBytes := berSequence(0x02, []byte{byte(msgID)})
	resultCode := berSequence(0x0a, []byte{0})
	matchedDN := berSequence(0x04, nil)
	diagMsg := berSequence(0x04, nil)
	respValue := berSequence(0x8b, payload)
	extResp := berSequence(0x78, append(append(append(resultCode, matchedDN...), diagMsg...), respValue...))
	return berSequence(0x30, append(idBytes, extResp...))
}

func ldapRelay(rawConn, framedConn net.Conn) {
	done := make(chan struct{}, 2)
	framedReader := bufio.NewReader(framedConn)
	go func() {
		for {
			tag, data, err := berReadElement(framedReader)
			if err != nil {
				done <- struct{}{}
				return
			}
			_ = tag
			inner := bufio.NewReader(strings.NewReader(string(data)))
			if _, _, err = berReadElement(inner); err != nil {
				done <- struct{}{}
				return
			}
			opTag, opData, err := berReadElement(inner)
			if err != nil {
				done <- struct{}{}
				return
			}
			if opTag != 0x78 {
				continue
			}
			opInner := bufio.NewReader(strings.NewReader(string(opData)))
			berReadElement(opInner) // resultCode
			berReadElement(opInner) // matchedDN
			berReadElement(opInner) // diagMsg
			respTag, respPayload, err := berReadElement(opInner)
			if err != nil || respTag != 0x8b {
				continue
			}
			if _, err := rawConn.Write(respPayload); err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 16*1024)
		msgID := 10
		for {
			n, err := rawConn.Read(buf)
			if err != nil || n == 0 {
				done <- struct{}{}
				return
			}
			msg := ldapBuildExtendedResponse(msgID, buf[:n])
			msgID++
			if msgID > 127 {
				msgID = 10
			}
			if _, err := framedConn.Write(msg); err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	<-done
}

func serveLDAPTunnel(ctx context.Context, port int, emit func(string)) TunnelResult {
	return serveTCPTunnel(ctx, "LDAP", port, emit, func(conn net.Conn) (string, net.Conn, error) {
		reader := bufio.NewReader(conn)
		tag, data, err := berReadElement(reader)
		if err != nil || tag != 0x30 {
			return "", nil, fmt.Errorf("LDAP: expected SEQUENCE, got 0x%02x", tag)
		}
		inner := bufio.NewReader(strings.NewReader(string(data)))
		_, _, _ = berReadElement(inner)
		opTag, _, err := berReadElement(inner)
		if err != nil || opTag != 0x60 {
			return "", nil, fmt.Errorf("LDAP: expected BindRequest(0x60), got 0x%02x", opTag)
		}
		conn.Write(ldapBuildBindResponse(1))

		tag, data, err = berReadElement(reader)
		if err != nil || tag != 0x30 {
			return "", nil, fmt.Errorf("LDAP: expected SEQUENCE for search")
		}
		inner = bufio.NewReader(strings.NewReader(string(data)))
		_, _, _ = berReadElement(inner)
		opTag, opData, err := berReadElement(inner)
		if err != nil || opTag != 0x63 {
			return "", nil, fmt.Errorf("LDAP: expected SearchRequest(0x63), got 0x%02x", opTag)
		}
		searchInner := bufio.NewReader(strings.NewReader(string(opData)))
		_, baseDN, err := berReadElement(searchInner)
		if err != nil {
			return "", nil, fmt.Errorf("LDAP: cannot read baseDN")
		}
		target := string(baseDN)
		if target == "" {
			conn.Write(ldapBuildSearchResDone(2))
			return "", nil, fmt.Errorf("LDAP: empty target")
		}

		remote, err := net.DialTimeout("tcp", target, 10*time.Second)
		if err != nil {
			conn.Write(ldapBuildSearchResDone(2))
			return "", nil, err
		}
		conn.Write(ldapBuildSearchResDone(2))
		return target, remote, nil
	}, ldapRelay)
}

func connectLDAPTunnelClient(ctx context.Context, proxyAddr string, emit func(string)) TunnelResult {
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return TunnelResult{Error: fmt.Errorf("cannot reach %s: %w", proxyAddr, err)}
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write(ldapBuildBindRequest(1))
	reader := bufio.NewReader(conn)
	tag, data, err := berReadElement(reader)
	conn.Close()
	if err != nil || tag != 0x30 {
		return TunnelResult{Error: fmt.Errorf("not an LDAP tunnel on %s", proxyAddr)}
	}
	inner := bufio.NewReader(strings.NewReader(string(data)))
	_, _, _ = berReadElement(inner)
	opTag, _, _ := berReadElement(inner)
	if opTag != 0x61 {
		return TunnelResult{Error: fmt.Errorf("not an LDAP tunnel on %s (no BindResponse)", proxyAddr)}
	}

	return startLocalForwarder(ctx, proxyAddr, "ldap", emit, func(local net.Conn) {
		forwardGenericTextTunnel(local, proxyAddr, "ldap", emit, func(remote net.Conn, target string) bool {
			remoteReader := bufio.NewReader(remote)
			remote.Write(ldapBuildBindRequest(1))
			tag, _, err := berReadElement(remoteReader)
			if err != nil || tag != 0x30 {
				return false
			}
			remote.Write(ldapBuildSearchRequest(2, target))
			tag, _, err = berReadElement(remoteReader)
			if err != nil || tag != 0x30 {
				return false
			}
			return true
		}, ldapRelay)
	})
}

// ═══════════════════════════════════════════════════════════════════════════
// SMB tunnel — real SMB2 wire format
// Wire: \xfeSMB magic + 64-byte header, NegotiateRequest/Response,
// SessionSetup for target, Read/Write commands for data relay
// ═══════════════════════════════════════════════════════════════════════════

func smb2Header(command uint16, messageID uint64, flags uint32) []byte {
	hdr := make([]byte, 64)
	hdr[0] = 0xfe
	hdr[1] = 'S'
	hdr[2] = 'M'
	hdr[3] = 'B'
	binary.LittleEndian.PutUint16(hdr[4:6], 64)
	binary.LittleEndian.PutUint16(hdr[6:8], 1)
	binary.LittleEndian.PutUint32(hdr[8:12], 0)
	binary.LittleEndian.PutUint16(hdr[12:14], command)
	binary.LittleEndian.PutUint16(hdr[14:16], 1)
	binary.LittleEndian.PutUint32(hdr[16:20], flags)
	binary.LittleEndian.PutUint64(hdr[24:32], messageID)
	binary.LittleEndian.PutUint32(hdr[32:36], 0xfeff)
	binary.LittleEndian.PutUint32(hdr[36:40], 1)
	binary.LittleEndian.PutUint64(hdr[40:48], 0x0001000000000001)
	return hdr
}

func smb2NetBIOSWrap(msg []byte) []byte {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(msg)))
	hdr[0] = 0
	return append(hdr, msg...)
}

func smb2ReadMessage(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(hdr) & 0x00ffffff
	if length == 0 || length > 1<<20 {
		return nil, fmt.Errorf("SMB2: invalid message length: %d", length)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	return data, nil
}

const (
	smb2CmdNegotiate    uint16 = 0x0000
	smb2CmdSessionSetup uint16 = 0x0001
	smb2CmdWrite        uint16 = 0x0009
	smb2FlagResponse    uint32 = 0x00000001
)

func smb2BuildNegotiateRequest() []byte {
	hdr := smb2Header(smb2CmdNegotiate, 0, 0)
	body := make([]byte, 36)
	binary.LittleEndian.PutUint16(body[0:2], 36)
	binary.LittleEndian.PutUint16(body[2:4], 1)
	binary.LittleEndian.PutUint16(body[4:6], 1)
	binary.LittleEndian.PutUint16(body[34:36], 0x0311)
	return smb2NetBIOSWrap(append(hdr, body...))
}

func smb2BuildNegotiateResponse() []byte {
	hdr := smb2Header(smb2CmdNegotiate, 0, smb2FlagResponse)
	body := make([]byte, 65)
	binary.LittleEndian.PutUint16(body[0:2], 65)
	binary.LittleEndian.PutUint16(body[2:4], 1)
	binary.LittleEndian.PutUint16(body[4:6], 0x0311)
	binary.LittleEndian.PutUint32(body[12:16], 65536)
	binary.LittleEndian.PutUint32(body[16:20], 65536)
	binary.LittleEndian.PutUint32(body[20:24], 65536)
	return smb2NetBIOSWrap(append(hdr, body...))
}

func smb2BuildSessionSetup(target string, flags uint32) []byte {
	hdr := smb2Header(smb2CmdSessionSetup, 1, flags)
	secBuf := []byte(target)
	body := make([]byte, 25)
	binary.LittleEndian.PutUint16(body[0:2], 25)
	binary.LittleEndian.PutUint16(body[4:6], 1)
	binary.LittleEndian.PutUint16(body[12:14], uint16(64+25))
	binary.LittleEndian.PutUint16(body[14:16], uint16(len(secBuf)))
	return smb2NetBIOSWrap(append(append(hdr, body...), secBuf...))
}

func smb2BuildSessionSetupResponse(status uint32) []byte {
	hdr := smb2Header(smb2CmdSessionSetup, 1, smb2FlagResponse)
	binary.LittleEndian.PutUint32(hdr[8:12], status)
	body := make([]byte, 9)
	binary.LittleEndian.PutUint16(body[0:2], 9)
	return smb2NetBIOSWrap(append(hdr, body...))
}

func smb2Relay(rawConn, framedConn net.Conn) {
	done := make(chan struct{}, 2)
	framedReader := bufio.NewReader(framedConn)
	go func() {
		for {
			msg, err := smb2ReadMessage(framedReader)
			if err != nil {
				done <- struct{}{}
				return
			}
			if len(msg) < 68 {
				continue
			}
			payload := msg[68:]
			if len(payload) == 0 {
				continue
			}
			if _, err := rawConn.Write(payload); err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 16*1024)
		var msgID uint64 = 2
		for {
			n, err := rawConn.Read(buf)
			if err != nil || n == 0 {
				done <- struct{}{}
				return
			}
			hdr := smb2Header(smb2CmdWrite, msgID, 0)
			msgID++
			body := make([]byte, 4)
			binary.LittleEndian.PutUint16(body[0:2], 49)
			msg := smb2NetBIOSWrap(append(append(hdr, body...), buf[:n]...))
			if _, err := framedConn.Write(msg); err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	<-done
}

func serveSMBTunnel(ctx context.Context, port int, emit func(string)) TunnelResult {
	return serveTCPTunnel(ctx, "SMB", port, emit, func(conn net.Conn) (string, net.Conn, error) {
		reader := bufio.NewReader(conn)
		msg, err := smb2ReadMessage(reader)
		if err != nil || len(msg) < 64 {
			return "", nil, fmt.Errorf("SMB: failed to read negotiate request")
		}
		if msg[0] != 0xfe || msg[1] != 'S' || msg[2] != 'M' || msg[3] != 'B' {
			return "", nil, fmt.Errorf("SMB: invalid magic")
		}
		conn.Write(smb2BuildNegotiateResponse())

		msg, err = smb2ReadMessage(reader)
		if err != nil || len(msg) < 89 {
			return "", nil, fmt.Errorf("SMB: failed to read session setup")
		}
		body := msg[64:]
		if len(body) < 16 {
			return "", nil, fmt.Errorf("SMB: session setup body too short")
		}
		bufOffset := int(binary.LittleEndian.Uint16(body[12:14]))
		bufLen := int(binary.LittleEndian.Uint16(body[14:16]))
		if bufOffset+bufLen > len(msg) || bufLen == 0 {
			return "", nil, fmt.Errorf("SMB: invalid security buffer")
		}
		target := string(msg[bufOffset : bufOffset+bufLen])
		if target == "" {
			conn.Write(smb2BuildSessionSetupResponse(0xC000006D))
			return "", nil, fmt.Errorf("SMB: empty target")
		}

		remote, err := net.DialTimeout("tcp", target, 10*time.Second)
		if err != nil {
			conn.Write(smb2BuildSessionSetupResponse(0xC000006D))
			return "", nil, err
		}
		conn.Write(smb2BuildSessionSetupResponse(0))
		return target, remote, nil
	}, smb2Relay)
}

func connectSMBTunnelClient(ctx context.Context, proxyAddr string, emit func(string)) TunnelResult {
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return TunnelResult{Error: fmt.Errorf("cannot reach %s: %w", proxyAddr, err)}
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write(smb2BuildNegotiateRequest())
	reader := bufio.NewReader(conn)
	msg, err := smb2ReadMessage(reader)
	conn.Close()
	if err != nil || len(msg) < 64 || msg[0] != 0xfe || msg[1] != 'S' || msg[2] != 'M' || msg[3] != 'B' {
		return TunnelResult{Error: fmt.Errorf("not an SMB tunnel on %s", proxyAddr)}
	}

	return startLocalForwarder(ctx, proxyAddr, "smb", emit, func(local net.Conn) {
		forwardGenericTextTunnel(local, proxyAddr, "smb", emit, func(remote net.Conn, target string) bool {
			remoteReader := bufio.NewReader(remote)
			remote.Write(smb2BuildNegotiateRequest())
			msg, err := smb2ReadMessage(remoteReader)
			if err != nil || len(msg) < 64 {
				return false
			}
			remote.Write(smb2BuildSessionSetup(target, 0))
			msg, err = smb2ReadMessage(remoteReader)
			if err != nil || len(msg) < 64 {
				return false
			}
			status := binary.LittleEndian.Uint32(msg[8:12])
			return status == 0
		}, smb2Relay)
	})
}

// ═══════════════════════════════════════════════════════════════════════════
// MQTT tunnel — real MQTT CONNECT/CONNACK handshake
// Wire: client sends CONNECT (0x10) with ClientID containing hex-encoded
// target, server responds CONNACK (0x20 0x02 0x00 0x00). Then mqttRelay
// handles data as MQTT PUBLISH packets.
// ═══════════════════════════════════════════════════════════════════════════

func serveMQTTTunnel(ctx context.Context, port int, emit func(string)) TunnelResult {
	return serveTCPTunnel(ctx, "MQTT", port, emit, func(conn net.Conn) (string, net.Conn, error) {
		// Read MQTT CONNECT packet.
		hdr := make([]byte, 1)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return "", nil, err
		}
		if hdr[0] != 0x10 {
			return "", nil, fmt.Errorf("expected MQTT CONNECT, got 0x%02x", hdr[0])
		}
		// Read remaining length (variable-length encoding).
		remaining := 0
		multiplier := 1
		for {
			b := make([]byte, 1)
			if _, err := io.ReadFull(conn, b); err != nil {
				return "", nil, err
			}
			remaining += int(b[0]&0x7F) * multiplier
			multiplier *= 128
			if b[0]&0x80 == 0 {
				break
			}
		}
		if remaining < 10 || remaining > 65535 {
			return "", nil, fmt.Errorf("invalid CONNECT remaining length")
		}
		payload := make([]byte, remaining)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return "", nil, err
		}

		// Parse CONNECT: variable header (protocol name + level + flags + keepalive) + payload.
		// Protocol Name: 2-byte length + "MQTT" (or "MQIsdp").
		if len(payload) < 10 {
			return "", nil, fmt.Errorf("CONNECT payload too short")
		}
		protoLen := int(payload[0])<<8 | int(payload[1])
		offset := 2 + protoLen + 1 + 1 + 2 // name + level + flags + keepalive
		if offset >= len(payload) {
			return "", nil, fmt.Errorf("CONNECT missing client ID")
		}

		// Client ID: 2-byte length + string.
		if offset+2 > len(payload) {
			return "", nil, fmt.Errorf("CONNECT client ID length missing")
		}
		clientIDLen := int(payload[offset])<<8 | int(payload[offset+1])
		offset += 2
		if offset+clientIDLen > len(payload) {
			return "", nil, fmt.Errorf("CONNECT client ID truncated")
		}
		clientID := string(payload[offset : offset+clientIDLen])

		// Decode hex-encoded target from ClientID.
		decoded, err := hex.DecodeString(clientID)
		if err != nil || len(decoded) == 0 {
			// Send CONNACK with "refused" (0x05 = not authorized).
			conn.Write([]byte{0x20, 0x02, 0x00, 0x05})
			return "", nil, fmt.Errorf("invalid target in ClientID")
		}
		target := string(decoded)

		remote, dialErr := net.DialTimeout("tcp", target, 10*time.Second)
		if dialErr != nil {
			conn.Write([]byte{0x20, 0x02, 0x00, 0x03}) // Server unavailable
			return "", nil, dialErr
		}

		// Send CONNACK: accepted (0x20, remaining=2, flags=0, rc=0).
		conn.Write([]byte{0x20, 0x02, 0x00, 0x00})
		return target, remote, nil
	}, mqttRelay)
}

func connectMQTTTunnelClient(ctx context.Context, proxyAddr string, emit func(string)) TunnelResult {
	// Verify: send MQTT CONNECT, expect CONNACK.
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return TunnelResult{Error: fmt.Errorf("cannot reach %s: %w", proxyAddr, err)}
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write(mqttBuildConnect("verify"))
	buf := make([]byte, 4)
	n, _ := conn.Read(buf)
	conn.Close()
	if n < 2 || buf[0] != 0x20 {
		return TunnelResult{Error: fmt.Errorf("not an MQTT tunnel on %s", proxyAddr)}
	}

	return startLocalForwarder(ctx, proxyAddr, "mqtt", emit, func(local net.Conn) {
		forwardGenericTextTunnel(local, proxyAddr, "mqtt", emit, func(remote net.Conn, target string) bool {
			hexTarget := hex.EncodeToString([]byte(target))
			remote.Write(mqttBuildConnect(hexTarget))
			ack := make([]byte, 4)
			n, err := io.ReadFull(remote, ack)
			if err != nil || n < 4 {
				return false
			}
			// CONNACK: 0x20, remaining=2, flags, rc=0 means accepted.
			return ack[0] == 0x20 && ack[3] == 0x00
		}, mqttRelay)
	})
}

// mqttBuildConnect builds an MQTT CONNECT packet with the given ClientID.
func mqttBuildConnect(clientID string) []byte {
	// Variable header: protocol name "MQTT", level 4, flags 0x02 (clean session), keepalive 60.
	var varHeader []byte
	varHeader = append(varHeader, 0x00, 0x04) // Protocol name length
	varHeader = append(varHeader, "MQTT"...)  // Protocol name
	varHeader = append(varHeader, 0x04)       // Protocol level (4 = MQTT 3.1.1)
	varHeader = append(varHeader, 0x02)       // Connect flags: clean session
	varHeader = append(varHeader, 0x00, 0x3C) // Keep alive: 60 seconds

	// Payload: Client ID.
	var payload []byte
	payload = append(payload, byte(len(clientID)>>8), byte(len(clientID)))
	payload = append(payload, []byte(clientID)...)

	remaining := len(varHeader) + len(payload)
	// Build packet.
	var pkt []byte
	pkt = append(pkt, 0x10) // CONNECT packet type
	// Encode remaining length.
	for {
		b := byte(remaining % 128)
		remaining /= 128
		if remaining > 0 {
			b |= 0x80
		}
		pkt = append(pkt, b)
		if remaining == 0 {
			break
		}
	}
	pkt = append(pkt, varHeader...)
	pkt = append(pkt, payload...)
	return pkt
}

// ═══════════════════════════════════════════════════════════════════════════
// AMQP tunnel — real AMQP 0-9-1 wire format
// Wire: protocol header, Connection.Start/Start-OK, Body frames for relay
// Frame: type(1) + channel(2) + size(4) + payload + frame-end(0xCE)
// ═══════════════════════════════════════════════════════════════════════════

var amqpProtocolHeader = []byte{'A', 'M', 'Q', 'P', 0x00, 0x00, 0x09, 0x01}

const (
	amqpFrameMethod   byte   = 1
	amqpFrameBody     byte   = 3
	amqpFrameEnd      byte   = 0xCE
	amqpClassConn     uint16 = 10
	amqpMethodStart   uint16 = 10
	amqpMethodStartOK uint16 = 11
)

func amqpWriteFrame(dst net.Conn, frameType byte, channel uint16, payload []byte) error {
	hdr := make([]byte, 7)
	hdr[0] = frameType
	binary.BigEndian.PutUint16(hdr[1:3], channel)
	binary.BigEndian.PutUint32(hdr[3:7], uint32(len(payload)))
	if _, err := dst.Write(hdr); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := dst.Write(payload); err != nil {
			return err
		}
	}
	_, err := dst.Write([]byte{amqpFrameEnd})
	return err
}

func amqpReadFrame(r io.Reader) (byte, uint16, []byte, error) {
	hdr := make([]byte, 7)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, 0, nil, err
	}
	frameType := hdr[0]
	channel := binary.BigEndian.Uint16(hdr[1:3])
	size := binary.BigEndian.Uint32(hdr[3:7])
	if size > 1<<20 {
		return 0, 0, nil, fmt.Errorf("AMQP: frame too large: %d", size)
	}
	payload := make([]byte, size)
	if size > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, 0, nil, err
		}
	}
	end := make([]byte, 1)
	if _, err := io.ReadFull(r, end); err != nil {
		return 0, 0, nil, err
	}
	if end[0] != amqpFrameEnd {
		return 0, 0, nil, fmt.Errorf("AMQP: invalid frame-end: 0x%02x", end[0])
	}
	return frameType, channel, payload, nil
}

func amqpBuildMethodPayload(class, method uint16, args []byte) []byte {
	p := make([]byte, 4+len(args))
	binary.BigEndian.PutUint16(p[0:2], class)
	binary.BigEndian.PutUint16(p[2:4], method)
	if len(args) > 0 {
		copy(p[4:], args)
	}
	return p
}

func amqpBuildConnectionStart() []byte {
	var args []byte
	args = append(args, 0, 9)
	args = append(args, 0, 0, 0, 0) // empty server-properties
	mech := []byte("PLAIN")
	mechLen := make([]byte, 4)
	binary.BigEndian.PutUint32(mechLen, uint32(len(mech)))
	args = append(args, mechLen...)
	args = append(args, mech...)
	loc := []byte("en_US")
	locLen := make([]byte, 4)
	binary.BigEndian.PutUint32(locLen, uint32(len(loc)))
	args = append(args, locLen...)
	args = append(args, loc...)
	return amqpBuildMethodPayload(amqpClassConn, amqpMethodStart, args)
}

func amqpBuildConnectionStartOK(target string) []byte {
	var table []byte
	key := []byte("target")
	table = append(table, byte(len(key)))
	table = append(table, key...)
	table = append(table, 'S')
	valLen := make([]byte, 4)
	binary.BigEndian.PutUint32(valLen, uint32(len(target)))
	table = append(table, valLen...)
	table = append(table, []byte(target)...)
	tableHdr := make([]byte, 4)
	binary.BigEndian.PutUint32(tableHdr, uint32(len(table)))

	var args []byte
	args = append(args, tableHdr...)
	args = append(args, table...)
	mech := []byte("PLAIN")
	args = append(args, byte(len(mech)))
	args = append(args, mech...)
	args = append(args, 0, 0, 0, 0) // response
	loc := []byte("en_US")
	args = append(args, byte(len(loc)))
	args = append(args, loc...)
	return amqpBuildMethodPayload(amqpClassConn, amqpMethodStartOK, args)
}

func amqpExtractTarget(args []byte) string {
	if len(args) < 4 {
		return ""
	}
	tableLen := int(binary.BigEndian.Uint32(args[0:4]))
	if tableLen <= 0 || 4+tableLen > len(args) {
		return ""
	}
	table := args[4 : 4+tableLen]
	pos := 0
	for pos < len(table) {
		keyLen := int(table[pos])
		pos++
		if pos+keyLen > len(table) {
			break
		}
		key := string(table[pos : pos+keyLen])
		pos += keyLen
		if pos >= len(table) {
			break
		}
		fieldType := table[pos]
		pos++
		if fieldType == 'S' {
			if pos+4 > len(table) {
				break
			}
			valLen := int(binary.BigEndian.Uint32(table[pos : pos+4]))
			pos += 4
			if pos+valLen > len(table) {
				break
			}
			val := string(table[pos : pos+valLen])
			pos += valLen
			if key == "target" {
				return val
			}
		} else {
			break
		}
	}
	return ""
}

func amqpRelay(rawConn, framedConn net.Conn) {
	done := make(chan struct{}, 2)
	framedReader := bufio.NewReader(framedConn)
	go func() {
		for {
			frameType, _, payload, err := amqpReadFrame(framedReader)
			if err != nil {
				done <- struct{}{}
				return
			}
			if frameType == amqpFrameBody && len(payload) > 0 {
				if _, err := rawConn.Write(payload); err != nil {
					done <- struct{}{}
					return
				}
			}
		}
	}()
	go func() {
		buf := make([]byte, 16*1024)
		for {
			n, err := rawConn.Read(buf)
			if err != nil || n == 0 {
				done <- struct{}{}
				return
			}
			if amqpWriteFrame(framedConn, amqpFrameBody, 1, buf[:n]) != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	<-done
}

func serveAMQPTunnel(ctx context.Context, port int, emit func(string)) TunnelResult {
	return serveTCPTunnel(ctx, "AMQP", port, emit, func(conn net.Conn) (string, net.Conn, error) {
		hdr := make([]byte, 8)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return "", nil, fmt.Errorf("AMQP: failed to read protocol header")
		}
		if string(hdr[:4]) != "AMQP" {
			return "", nil, fmt.Errorf("AMQP: invalid protocol header")
		}

		startPayload := amqpBuildConnectionStart()
		amqpWriteFrame(conn, amqpFrameMethod, 0, startPayload)

		frameType, _, payload, err := amqpReadFrame(conn)
		if err != nil || frameType != amqpFrameMethod {
			return "", nil, fmt.Errorf("AMQP: expected method frame")
		}
		if len(payload) < 4 {
			return "", nil, fmt.Errorf("AMQP: Start-OK too short")
		}
		class := binary.BigEndian.Uint16(payload[0:2])
		method := binary.BigEndian.Uint16(payload[2:4])
		if class != amqpClassConn || method != amqpMethodStartOK {
			return "", nil, fmt.Errorf("AMQP: expected Connection.Start-OK, got %d.%d", class, method)
		}
		target := amqpExtractTarget(payload[4:])
		if target == "" {
			return "", nil, fmt.Errorf("AMQP: no target in client-properties")
		}

		remote, err := net.DialTimeout("tcp", target, 10*time.Second)
		if err != nil {
			return "", nil, err
		}

		tunePayload := amqpBuildMethodPayload(amqpClassConn, 30, []byte{
			0x00, 0x00,
			0x00, 0x01, 0x00, 0x00,
			0x00, 0x00,
		})
		amqpWriteFrame(conn, amqpFrameMethod, 0, tunePayload)
		return target, remote, nil
	}, amqpRelay)
}

func connectAMQPTunnelClient(ctx context.Context, proxyAddr string, emit func(string)) TunnelResult {
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return TunnelResult{Error: fmt.Errorf("cannot reach %s: %w", proxyAddr, err)}
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write(amqpProtocolHeader)
	frameType, _, payload, err := amqpReadFrame(conn)
	conn.Close()
	if err != nil || frameType != amqpFrameMethod || len(payload) < 4 {
		return TunnelResult{Error: fmt.Errorf("not an AMQP tunnel on %s", proxyAddr)}
	}
	class := binary.BigEndian.Uint16(payload[0:2])
	method := binary.BigEndian.Uint16(payload[2:4])
	if class != amqpClassConn || method != amqpMethodStart {
		return TunnelResult{Error: fmt.Errorf("not an AMQP tunnel on %s (unexpected method)", proxyAddr)}
	}

	return startLocalForwarder(ctx, proxyAddr, "amqp", emit, func(local net.Conn) {
		forwardGenericTextTunnel(local, proxyAddr, "amqp", emit, func(remote net.Conn, target string) bool {
			remote.Write(amqpProtocolHeader)
			frameType, _, _, err := amqpReadFrame(remote)
			if err != nil || frameType != amqpFrameMethod {
				return false
			}
			startOK := amqpBuildConnectionStartOK(target)
			amqpWriteFrame(remote, amqpFrameMethod, 0, startOK)
			frameType, _, _, err = amqpReadFrame(remote)
			return err == nil && frameType == amqpFrameMethod
		}, amqpRelay)
	})
}

// ═══════════════════════════════════════════════════════════════════════════
// SSH tunnel — real SSH version exchange handshake
// Wire: server sends "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n", client sends
// "SSH-2.0-OpenSSH_8.9p1\r\n". Target is sent in a custom SSH_MSG (0x5A)
// with target as channel type. Then sshRelay handles data framing.
// ═══════════════════════════════════════════════════════════════════════════

// SSH message types for channel operations (RFC 4254)
const (
	sshMsgChannelOpen        byte = 90
	sshMsgChannelOpenConfirm byte = 91
	sshMsgChannelOpenFailure byte = 92
)

// sshBuildChannelOpen builds SSH_MSG_CHANNEL_OPEN for direct-tcpip (RFC 4254 §7.2).
func sshBuildChannelOpen(host string, port uint32) []byte {
	chanType := "direct-tcpip"
	origIP := "127.0.0.1"
	var origPort uint32 = 0

	// Calculate total size
	size := 1 + 4 + len(chanType) + 4 + 4 + 4 + 4 + len(host) + 4 + 4 + len(origIP) + 4
	payload := make([]byte, size)
	off := 0

	payload[off] = sshMsgChannelOpen
	off++

	// channel type string
	binary.BigEndian.PutUint32(payload[off:], uint32(len(chanType)))
	off += 4
	copy(payload[off:], chanType)
	off += len(chanType)

	// sender channel, initial window size, max packet size
	binary.BigEndian.PutUint32(payload[off:], 0) // sender channel
	off += 4
	binary.BigEndian.PutUint32(payload[off:], 0x200000) // 2MB window
	off += 4
	binary.BigEndian.PutUint32(payload[off:], 0x8000) // 32KB max packet
	off += 4

	// host to connect + port
	binary.BigEndian.PutUint32(payload[off:], uint32(len(host)))
	off += 4
	copy(payload[off:], host)
	off += len(host)
	binary.BigEndian.PutUint32(payload[off:], port)
	off += 4

	// originator IP + port
	binary.BigEndian.PutUint32(payload[off:], uint32(len(origIP)))
	off += 4
	copy(payload[off:], origIP)
	off += len(origIP)
	binary.BigEndian.PutUint32(payload[off:], origPort)

	return payload
}

// sshParseChannelOpen extracts host:port from SSH_MSG_CHANNEL_OPEN direct-tcpip.
func sshParseChannelOpen(payload []byte) (string, error) {
	if len(payload) < 1 || payload[0] != sshMsgChannelOpen {
		return "", fmt.Errorf("not SSH_MSG_CHANNEL_OPEN")
	}
	off := 1

	// channel type string
	if off+4 > len(payload) {
		return "", fmt.Errorf("truncated channel type length")
	}
	chanTypeLen := int(binary.BigEndian.Uint32(payload[off:]))
	off += 4
	if off+chanTypeLen > len(payload) {
		return "", fmt.Errorf("truncated channel type")
	}
	off += chanTypeLen

	// skip sender channel, window, max packet (12 bytes)
	off += 12
	if off > len(payload) {
		return "", fmt.Errorf("truncated channel params")
	}

	// host string
	if off+4 > len(payload) {
		return "", fmt.Errorf("truncated host length")
	}
	hostLen := int(binary.BigEndian.Uint32(payload[off:]))
	off += 4
	if off+hostLen > len(payload) {
		return "", fmt.Errorf("truncated host")
	}
	host := string(payload[off : off+hostLen])
	off += hostLen

	// port
	if off+4 > len(payload) {
		return "", fmt.Errorf("truncated port")
	}
	port := binary.BigEndian.Uint32(payload[off:])

	return fmt.Sprintf("%s:%d", host, port), nil
}

// sshBuildChannelOpenConfirm builds SSH_MSG_CHANNEL_OPEN_CONFIRMATION (RFC 4254).
func sshBuildChannelOpenConfirm() []byte {
	payload := make([]byte, 17)
	payload[0] = sshMsgChannelOpenConfirm
	binary.BigEndian.PutUint32(payload[1:], 0)        // recipient channel
	binary.BigEndian.PutUint32(payload[5:], 0)        // sender channel
	binary.BigEndian.PutUint32(payload[9:], 0x200000) // initial window size
	binary.BigEndian.PutUint32(payload[13:], 0x8000)  // max packet size
	return payload
}

// sshBuildChannelOpenFailure builds SSH_MSG_CHANNEL_OPEN_FAILURE (RFC 4254).
func sshBuildChannelOpenFailure(reason uint32) []byte {
	desc := "Connection refused"
	lang := ""
	payload := make([]byte, 1+4+4+4+len(desc)+4+len(lang))
	off := 0
	payload[off] = sshMsgChannelOpenFailure
	off++
	binary.BigEndian.PutUint32(payload[off:], 0) // recipient channel
	off += 4
	binary.BigEndian.PutUint32(payload[off:], reason)
	off += 4
	binary.BigEndian.PutUint32(payload[off:], uint32(len(desc)))
	off += 4
	copy(payload[off:], desc)
	off += len(desc)
	binary.BigEndian.PutUint32(payload[off:], uint32(len(lang)))
	return payload
}

func serveSSHTunnel(ctx context.Context, port int, emit func(string)) TunnelResult {
	return serveTCPTunnel(ctx, "SSH", port, emit, func(conn net.Conn) (string, net.Conn, error) {
		// Send SSH server version string.
		fmt.Fprintf(conn, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n")

		// Read client version string.
		reader := bufio.NewReader(conn)
		clientVersion, err := reader.ReadString('\n')
		if err != nil {
			return "", nil, err
		}
		clientVersion = strings.TrimSpace(clientVersion)
		if !strings.HasPrefix(clientVersion, "SSH-2.0-") {
			return "", nil, fmt.Errorf("invalid SSH version: %s", clientVersion)
		}

		// Read SSH_MSG_CHANNEL_OPEN packet (RFC 4253/4254 format)
		payload, err := sshReadPacket(reader)
		if err != nil {
			return "", nil, fmt.Errorf("failed to read channel open: %w", err)
		}

		target, err := sshParseChannelOpen(payload)
		if err != nil {
			return "", nil, fmt.Errorf("invalid channel open: %w", err)
		}

		remote, err := net.DialTimeout("tcp", target, 10*time.Second)
		if err != nil {
			// Send SSH_MSG_CHANNEL_OPEN_FAILURE
			failPayload := sshBuildChannelOpenFailure(2) // SSH_OPEN_CONNECT_FAILED
			sshWritePacket(conn, failPayload)
			return "", nil, err
		}

		// Send SSH_MSG_CHANNEL_OPEN_CONFIRMATION
		confirmPayload := sshBuildChannelOpenConfirm()
		sshWritePacket(conn, confirmPayload)
		return target, remote, nil
	}, sshRelay)
}

func connectSSHTunnelClient(ctx context.Context, proxyAddr string, emit func(string)) TunnelResult {
	// Verify: check for SSH version banner.
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return TunnelResult{Error: fmt.Errorf("cannot reach %s: %w", proxyAddr, err)}
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	conn.Close()
	if !strings.HasPrefix(string(buf[:n]), "SSH-2.0-") {
		return TunnelResult{Error: fmt.Errorf("not an SSH tunnel on %s", proxyAddr)}
	}

	return startLocalForwarder(ctx, proxyAddr, "ssh", emit, func(local net.Conn) {
		forwardGenericTextTunnel(local, proxyAddr, "ssh", emit, func(remote net.Conn, target string) bool {
			// Read server version.
			reader := bufio.NewReader(remote)
			serverVersion, err := reader.ReadString('\n')
			if err != nil || !strings.HasPrefix(strings.TrimSpace(serverVersion), "SSH-2.0-") {
				return false
			}
			// Send client version.
			fmt.Fprintf(remote, "SSH-2.0-OpenSSH_8.9p1\r\n")

			// Parse target into host:port
			host, portStr, err := net.SplitHostPort(target)
			if err != nil {
				return false
			}
			var port uint32
			fmt.Sscanf(portStr, "%d", &port)

			// Send SSH_MSG_CHANNEL_OPEN direct-tcpip (RFC 4254)
			openPayload := sshBuildChannelOpen(host, port)
			if sshWritePacket(remote, openPayload) != nil {
				return false
			}

			// Read confirmation packet
			respPayload, err := sshReadPacket(reader)
			if err != nil || len(respPayload) < 1 {
				return false
			}
			return respPayload[0] == sshMsgChannelOpenConfirm
		}, sshRelay)
	})
}

// ═══════════════════════════════════════════════════════════════════════════
// RDP tunnel — real RDP over TPKT/X.224 wire format
// Wire: TPKT(03 00 LL LL) + X.224 CR(0xE0)/CC(0xD0), target in cookie,
// data relay via TPKT + X.224 DT(0xF0)
// ═══════════════════════════════════════════════════════════════════════════

func tpktWrap(payload []byte) []byte {
	totalLen := 4 + len(payload)
	hdr := make([]byte, 4)
	hdr[0] = 0x03
	hdr[1] = 0x00
	binary.BigEndian.PutUint16(hdr[2:4], uint16(totalLen))
	return append(hdr, payload...)
}

func tpktRead(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != 0x03 {
		return nil, fmt.Errorf("TPKT: invalid version: 0x%02x", hdr[0])
	}
	totalLen := int(binary.BigEndian.Uint16(hdr[2:4]))
	if totalLen < 4 || totalLen > 1<<20 {
		return nil, fmt.Errorf("TPKT: invalid length: %d", totalLen)
	}
	payloadLen := totalLen - 4
	if payloadLen == 0 {
		return nil, nil
	}
	data := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	return data, nil
}

func x224ConnectionRequest(cookie string) []byte {
	cookieData := []byte("Cookie: mstshash=" + cookie + "\r\n")
	tpduLen := 6 + len(cookieData)
	var pdu []byte
	pdu = append(pdu, byte(tpduLen))
	pdu = append(pdu, 0xE0)
	pdu = append(pdu, 0, 0) // dst-ref
	pdu = append(pdu, 0, 0) // src-ref
	pdu = append(pdu, 0)    // class
	pdu = append(pdu, cookieData...)
	return tpktWrap(pdu)
}

func x224ConnectionConfirm() []byte {
	var pdu []byte
	pdu = append(pdu, 6)
	pdu = append(pdu, 0xD0)
	pdu = append(pdu, 0, 0) // dst-ref
	pdu = append(pdu, 0, 0) // src-ref
	pdu = append(pdu, 0)    // class
	return tpktWrap(pdu)
}

func x224DataWrap(data []byte) []byte {
	var pdu []byte
	pdu = append(pdu, 2)
	pdu = append(pdu, 0xF0)
	pdu = append(pdu, 0x80)
	pdu = append(pdu, data...)
	return tpktWrap(pdu)
}

func rdpRelay(rawConn, framedConn net.Conn) {
	done := make(chan struct{}, 2)
	framedReader := bufio.NewReader(framedConn)
	go func() {
		for {
			payload, err := tpktRead(framedReader)
			if err != nil {
				done <- struct{}{}
				return
			}
			if len(payload) < 3 || payload[1] != 0xF0 {
				continue
			}
			data := payload[3:]
			if len(data) == 0 {
				continue
			}
			if _, err := rawConn.Write(data); err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 16*1024)
		for {
			n, err := rawConn.Read(buf)
			if err != nil || n == 0 {
				done <- struct{}{}
				return
			}
			msg := x224DataWrap(buf[:n])
			if _, err := framedConn.Write(msg); err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	<-done
}

func serveRDPTunnel(ctx context.Context, port int, emit func(string)) TunnelResult {
	return serveTCPTunnel(ctx, "RDP", port, emit, func(conn net.Conn) (string, net.Conn, error) {
		reader := bufio.NewReader(conn)
		payload, err := tpktRead(reader)
		if err != nil || len(payload) < 7 {
			return "", nil, fmt.Errorf("RDP: failed to read connection request")
		}
		if payload[1] != 0xE0 {
			return "", nil, fmt.Errorf("RDP: expected CR (0xE0), got 0x%02x", payload[1])
		}
		crData := string(payload[7:])
		target := ""
		if strings.HasPrefix(crData, "Cookie: mstshash=") {
			cookie := strings.TrimPrefix(crData, "Cookie: mstshash=")
			cookie = strings.TrimSuffix(cookie, "\r\n")
			decoded, err := hex.DecodeString(cookie)
			if err == nil && len(decoded) > 0 {
				target = string(decoded)
			}
		}
		if target == "" {
			return "", nil, fmt.Errorf("RDP: no target in cookie")
		}

		conn.Write(x224ConnectionConfirm())
		remote, err := net.DialTimeout("tcp", target, 10*time.Second)
		if err != nil {
			return "", nil, err
		}
		return target, remote, nil
	}, rdpRelay)
}

func connectRDPTunnelClient(ctx context.Context, proxyAddr string, emit func(string)) TunnelResult {
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return TunnelResult{Error: fmt.Errorf("cannot reach %s: %w", proxyAddr, err)}
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write(x224ConnectionRequest(hex.EncodeToString([]byte("verify"))))
	reader := bufio.NewReader(conn)
	payload, err := tpktRead(reader)
	conn.Close()
	if err != nil || len(payload) < 2 || payload[1] != 0xD0 {
		return TunnelResult{Error: fmt.Errorf("not an RDP tunnel on %s", proxyAddr)}
	}

	return startLocalForwarder(ctx, proxyAddr, "rdp", emit, func(local net.Conn) {
		forwardGenericTextTunnel(local, proxyAddr, "rdp", emit, func(remote net.Conn, target string) bool {
			remoteReader := bufio.NewReader(remote)
			hexTarget := hex.EncodeToString([]byte(target))
			remote.Write(x224ConnectionRequest(hexTarget))
			payload, err := tpktRead(remoteReader)
			if err != nil || len(payload) < 2 {
				return false
			}
			return payload[1] == 0xD0
		}, rdpRelay)
	})
}

// ═══════════════════════════════════════════════════════════════════════════
// QUIC tunnel — real UDP-based QUIC wire format
// Wire: QUIC Initial (0xC0) for handshake with target in DCID,
// Handshake (0xE0) for server response, Short Header (0x40) for data.
// Each UDP datagram is one QUIC packet (no TCP length prefix).
// Wireshark identifies these as QUIC by the form bit + version 0x00000001.
// ═══════════════════════════════════════════════════════════════════════════

var quicVersion = []byte{0x00, 0x00, 0x00, 0x01}
var quicConnID = []byte{0xAA, 0xBB, 0xCC, 0xDD}

// quicBuildInitialUDP builds a QUIC Initial packet (RFC 9000 compliant).
// First byte: 0xC0 (long header, Initial type, 00 reserved, 00 pkt num len → 1 byte)
// Bytes 1-4: version 0x00000001
// DCID length + DCID (carries the tunnel target)
// SCID length + SCID
// Token length (varint 0 = no token)
// Length (2-byte varint of packet number + payload length)
// Packet number (1 byte: 0x00)
// Payload
func quicBuildInitialUDP(dcid []byte) []byte {
	scid := []byte{0x01, 0x02, 0x03, 0x04}
	payload := []byte("INIT")
	pnLen := 1 // packet number is 1 byte
	// Length field = pnLen + len(payload), encoded as 2-byte varint
	innerLen := pnLen + len(payload)

	var pkt []byte
	pkt = append(pkt, 0xC0) // long header, Initial type, pkt num len = 1 byte (00)
	pkt = append(pkt, quicVersion...)
	pkt = append(pkt, byte(len(dcid)))
	pkt = append(pkt, dcid...)
	pkt = append(pkt, byte(len(scid)))
	pkt = append(pkt, scid...)
	pkt = append(pkt, 0x00) // token length = 0 (varint)
	// Length as 2-byte varint (0x40 prefix means 2-byte encoding in QUIC varint)
	pkt = append(pkt, byte(0x40|((innerLen>>8)&0x3F)), byte(innerLen&0xFF))
	pkt = append(pkt, 0x00) // packet number = 0
	pkt = append(pkt, payload...)

	// Pad to at least 1200 bytes (QUIC Initial minimum) so Wireshark is happy.
	if len(pkt) < 1200 {
		pkt = append(pkt, make([]byte, 1200-len(pkt))...)
	}
	return pkt
}

// quicBuildHandshakeUDP builds a QUIC Handshake packet.
// First byte: 0xE0 (long header, Handshake type)
func quicBuildHandshakeUDP() []byte {
	dcid := []byte{0x01, 0x02, 0x03, 0x04}
	scid := []byte{0x05, 0x06, 0x07, 0x08}
	payload := []byte("HSOK")
	pnLen := 1
	innerLen := pnLen + len(payload)

	var pkt []byte
	pkt = append(pkt, 0xE0) // long header, Handshake type
	pkt = append(pkt, quicVersion...)
	pkt = append(pkt, byte(len(dcid)))
	pkt = append(pkt, dcid...)
	pkt = append(pkt, byte(len(scid)))
	pkt = append(pkt, scid...)
	// Length as 2-byte varint
	pkt = append(pkt, byte(0x40|((innerLen>>8)&0x3F)), byte(innerLen&0xFF))
	pkt = append(pkt, 0x00) // packet number = 0
	pkt = append(pkt, payload...)
	return pkt
}

// quicBuildShortHeaderUDP builds a QUIC 1-RTT (short header) data packet.
// First byte: 0x40 (short header, fixed bit set)
// DCID (4 bytes, known from handshake)
// Packet number (4 bytes, big-endian sequence number)
// Payload (tunnel data)
func quicBuildShortHeaderUDP(connID []byte, seq uint32, payload []byte) []byte {
	pkt := make([]byte, 0, 1+len(connID)+4+len(payload))
	pkt = append(pkt, 0x43) // short header, fixed bit, pkt num len = 4 bytes (11)
	pkt = append(pkt, connID...)
	seqBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(seqBuf, seq)
	pkt = append(pkt, seqBuf...)
	pkt = append(pkt, payload...)
	return pkt
}

// quicParseShortHeaderUDP extracts the payload from a QUIC short header packet.
// Returns the sequence number and payload, or error.
func quicParseShortHeaderUDP(pkt []byte, connIDLen int) (seq uint32, payload []byte, err error) {
	minLen := 1 + connIDLen + 4 // header byte + connID + 4-byte pkt num
	if len(pkt) < minLen {
		return 0, nil, fmt.Errorf("QUIC short: packet too short (%d < %d)", len(pkt), minLen)
	}
	if pkt[0]&0x80 != 0 {
		return 0, nil, fmt.Errorf("QUIC short: long header form bit set")
	}
	seq = binary.BigEndian.Uint32(pkt[1+connIDLen : 1+connIDLen+4])
	payload = pkt[1+connIDLen+4:]
	return seq, payload, nil
}

// quicReadLongHeader parses a QUIC long header packet (Initial or Handshake).
// Returns the packet type (first byte with form bit cleared), DCID, SCID, and payload.
func quicReadLongHeader(pkt []byte) (pktType byte, dcid, scid, payload []byte, err error) {
	if len(pkt) < 7 {
		return 0, nil, nil, nil, fmt.Errorf("QUIC: packet too short")
	}
	if pkt[0]&0x80 == 0 {
		return 0, nil, nil, nil, fmt.Errorf("QUIC: not a long header")
	}
	pktType = pkt[0] & 0x30 // extract type bits (bits 4-5)
	pos := 5                // skip first byte + 4-byte version
	if pos >= len(pkt) {
		return 0, nil, nil, nil, fmt.Errorf("QUIC: truncated")
	}
	dcidLen := int(pkt[pos])
	pos++
	if pos+dcidLen > len(pkt) {
		return 0, nil, nil, nil, fmt.Errorf("QUIC: truncated DCID")
	}
	dcid = pkt[pos : pos+dcidLen]
	pos += dcidLen
	if pos >= len(pkt) {
		return 0, nil, nil, nil, fmt.Errorf("QUIC: truncated")
	}
	scidLen := int(pkt[pos])
	pos++
	if pos+scidLen > len(pkt) {
		return 0, nil, nil, nil, fmt.Errorf("QUIC: truncated SCID")
	}
	scid = pkt[pos : pos+scidLen]
	pos += scidLen

	// For Initial packets (type 0x00), read token length + token
	if pktType == 0x00 {
		if pos >= len(pkt) {
			return 0, nil, nil, nil, fmt.Errorf("QUIC: truncated token length")
		}
		tokenLen, tokenLenSize := quicDecodeVarint(pkt[pos:])
		pos += tokenLenSize
		pos += int(tokenLen) // skip token bytes
		if pos > len(pkt) {
			return 0, nil, nil, nil, fmt.Errorf("QUIC: truncated token")
		}
	}

	// Read Length field (varint) then packet number (1 byte) then payload
	if pos >= len(pkt) {
		return 0, nil, nil, nil, fmt.Errorf("QUIC: truncated length field")
	}
	innerLen, lenSize := quicDecodeVarint(pkt[pos:])
	pos += lenSize
	if pos+int(innerLen) > len(pkt) {
		// Allow truncation (padding may be stripped)
		innerLen = uint64(len(pkt) - pos)
	}
	// Skip 1-byte packet number, rest is payload
	if innerLen < 1 {
		return pktType, dcid, scid, nil, nil
	}
	pos++ // skip packet number
	innerLen--
	payload = pkt[pos : pos+int(innerLen)]
	return pktType, dcid, scid, payload, nil
}

// quicDecodeVarint decodes a QUIC variable-length integer.
// Returns the value and the number of bytes consumed.
func quicDecodeVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	prefix := b[0] >> 6
	switch prefix {
	case 0: // 1-byte
		return uint64(b[0] & 0x3F), 1
	case 1: // 2-byte
		if len(b) < 2 {
			return 0, 1
		}
		return uint64(b[0]&0x3F)<<8 | uint64(b[1]), 2
	case 2: // 4-byte
		if len(b) < 4 {
			return 0, 1
		}
		return uint64(b[0]&0x3F)<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3]), 4
	default: // 8-byte
		if len(b) < 8 {
			return 0, 1
		}
		return uint64(b[0]&0x3F)<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
			uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7]), 8
	}
}

// quicUDPMaxPayload is the maximum tunnel data per UDP datagram.
// 1 (header) + 4 (connID) + 4 (seq) + payload ≤ 1400.
const quicUDPMaxPayload = 1387

// ── QUIC UDP server ─────────────────────────────────────────────────────────

func serveQUICTunnel(ctx context.Context, port int, emit func(string)) TunnelResult {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return TunnelResult{Error: err}
	}
	defer pc.Close()
	emit(fmt.Sprintf("[+] QUIC tunnel bound on %s (UDP)", addr))
	emit(fmt.Sprintf("[+] Listening on port %d — waiting for client...", port))
	go func() { <-ctx.Done(); pc.Close() }()

	type udpSession struct {
		remote     net.Conn // TCP connection to destination
		clientAddr net.Addr // client's UDP address
		seq        uint32   // outbound sequence counter
		cancel     context.CancelFunc
	}

	var mu sync.Mutex
	sessions := make(map[string]*udpSession) // key = client addr string

	buf := make([]byte, 2000)
	for {
		n, clientAddr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return TunnelResult{}
			}
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		// Long header (Initial) = new session request
		if n > 0 && pkt[0]&0x80 != 0 {
			_, dcid, _, _, perr := quicReadLongHeader(pkt)
			if perr != nil {
				continue
			}
			target := string(dcid)
			if target == "" {
				continue
			}

			// Send Handshake response
			hsPkt := quicBuildHandshakeUDP()
			pc.WriteTo(hsPkt, clientAddr)

			if target == "verify" {
				emit(fmt.Sprintf("[+] Client verified from %s", clientAddr))
				continue
			}

			// Dial TCP destination
			remote, derr := net.DialTimeout("tcp", target, 10*time.Second)
			if derr != nil {
				emit(fmt.Sprintf("[-] QUIC tunnel: cannot reach %s: %s", target, derr))
				continue
			}

			sessCtx, sessCancel := context.WithCancel(ctx)
			sess := &udpSession{
				remote:     remote,
				clientAddr: clientAddr,
				seq:        0,
				cancel:     sessCancel,
			}
			key := clientAddr.String()
			mu.Lock()
			// Clean up any old session from the same address.
			if old, ok := sessions[key]; ok {
				old.cancel()
				old.remote.Close()
			}
			sessions[key] = sess
			mu.Unlock()

			emit(fmt.Sprintf("[+] QUIC tunnel: proxying %s → %s", clientAddr, target))

			// Goroutine: read from TCP destination, send as QUIC short header via UDP.
			go func(s *udpSession, sctx context.Context, caddr net.Addr) {
				defer func() {
					mu.Lock()
					if sessions[caddr.String()] == s {
						delete(sessions, caddr.String())
					}
					mu.Unlock()
					s.remote.Close()
				}()
				readBuf := make([]byte, quicUDPMaxPayload)
				for {
					if sctx.Err() != nil {
						return
					}
					s.remote.SetReadDeadline(time.Now().Add(5 * time.Minute))
					rn, rerr := s.remote.Read(readBuf)
					if rerr != nil {
						return
					}
					mu.Lock()
					s.seq++
					seq := s.seq
					mu.Unlock()
					outPkt := quicBuildShortHeaderUDP(quicConnID, seq, readBuf[:rn])
					pc.WriteTo(outPkt, caddr)
				}
			}(sess, sessCtx, clientAddr)
			continue
		}

		// Short header = data for existing session
		if n > 0 && pkt[0]&0x80 == 0 {
			_, payload, perr := quicParseShortHeaderUDP(pkt, len(quicConnID))
			if perr != nil || len(payload) == 0 {
				continue
			}
			key := clientAddr.String()
			mu.Lock()
			sess := sessions[key]
			mu.Unlock()
			if sess == nil {
				continue
			}
			sess.remote.SetWriteDeadline(time.Now().Add(30 * time.Second))
			sess.remote.Write(payload)
		}
	}
}

// ── QUIC UDP client ─────────────────────────────────────────────────────────

func connectQUICTunnelClient(ctx context.Context, proxyAddr string, emit func(string)) TunnelResult {
	// Probe: send Initial with "verify" target, expect Handshake back.
	probeConn, err := net.DialTimeout("udp", proxyAddr, 3*time.Second)
	if err != nil {
		return TunnelResult{Error: fmt.Errorf("cannot reach %s (udp): %w", proxyAddr, err)}
	}
	probeConn.SetDeadline(time.Now().Add(3 * time.Second))
	probeConn.Write(quicBuildInitialUDP([]byte("verify")))

	probeBuf := make([]byte, 2000)
	pn, perr := probeConn.Read(probeBuf)
	probeConn.Close()
	if perr != nil {
		return TunnelResult{Error: fmt.Errorf("not a QUIC tunnel on %s", proxyAddr)}
	}
	pktType, _, _, _, perr := quicReadLongHeader(probeBuf[:pn])
	if perr != nil || pktType != 0x20 { // 0xE0 & 0x30 = 0x20 (Handshake type bits)
		return TunnelResult{Error: fmt.Errorf("not a QUIC tunnel on %s (no handshake)", proxyAddr)}
	}

	// Start local SOCKS5 TCP forwarder.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return TunnelResult{Error: fmt.Errorf("local SOCKS listener: %w", err)}
	}
	defer ln.Close()
	localAddr := ln.Addr().String()
	emit(fmt.Sprintf("[+] Remote QUIC tunnel verified at %s", proxyAddr))
	emit(fmt.Sprintf("[+] Local SOCKS5 forwarder on %s", localAddr))
	emit(fmt.Sprintf("[+] Tunnel active — socks5://%s → quic://%s", localAddr, proxyAddr))
	emit(fmt.Sprintf("[*] Point applications at socks5://%s", localAddr))
	go func() { <-ctx.Done(); ln.Close() }()

	for {
		local, lerr := ln.Accept()
		if lerr != nil {
			if ctx.Err() != nil {
				return TunnelResult{}
			}
			continue
		}
		go quicForwardSOCKS(ctx, local, proxyAddr, emit)
	}
}

// quicForwardSOCKS handles one SOCKS5 connection through the QUIC UDP tunnel.
func quicForwardSOCKS(ctx context.Context, local net.Conn, proxyAddr string, emit func(string)) {
	defer local.Close()
	local.SetDeadline(time.Now().Add(5 * time.Minute))

	// SOCKS5 greeting
	buf := make([]byte, 256)
	n, err := local.Read(buf)
	if err != nil || n < 3 || buf[0] != 0x05 {
		return
	}
	local.Write([]byte{0x05, 0x00})

	// SOCKS5 CONNECT
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

	// Open a dedicated UDP connection to the tunnel server.
	udpConn, err := net.DialTimeout("udp", proxyAddr, 5*time.Second)
	if err != nil {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer udpConn.Close()

	// Send QUIC Initial with real target in DCID.
	udpConn.SetDeadline(time.Now().Add(5 * time.Second))
	udpConn.Write(quicBuildInitialUDP([]byte(target)))

	// Read Handshake response.
	hsBuf := make([]byte, 2000)
	hn, herr := udpConn.Read(hsBuf)
	if herr != nil {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	pktType, _, _, _, herr := quicReadLongHeader(hsBuf[:hn])
	if herr != nil || pktType != 0x20 {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// SOCKS5 success
	local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	emit(fmt.Sprintf("[+] QUIC tunnel forwarding → %s", target))

	// Reset deadline for relay phase.
	udpConn.SetDeadline(time.Time{})
	local.SetDeadline(time.Now().Add(5 * time.Minute))

	// Bidirectional relay: local TCP <-> UDP QUIC tunnel
	done := make(chan struct{}, 2)
	var seq uint32
	var seqMu sync.Mutex

	// UDP → local TCP: read QUIC short header, extract payload, write to local.
	go func() {
		defer func() { done <- struct{}{} }()
		readBuf := make([]byte, 2000)
		for {
			udpConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
			rn, rerr := udpConn.Read(readBuf)
			if rerr != nil {
				return
			}
			pkt := readBuf[:rn]
			if len(pkt) == 0 {
				continue
			}
			// Skip long header packets (shouldn't happen in relay phase)
			if pkt[0]&0x80 != 0 {
				continue
			}
			_, payload, perr := quicParseShortHeaderUDP(pkt, len(quicConnID))
			if perr != nil || len(payload) == 0 {
				continue
			}
			if _, werr := local.Write(payload); werr != nil {
				return
			}
		}
	}()

	// Local TCP → UDP: read from local, wrap in QUIC short header, send.
	go func() {
		defer func() { done <- struct{}{} }()
		sendBuf := make([]byte, quicUDPMaxPayload)
		for {
			rn, rerr := local.Read(sendBuf)
			if rerr != nil || rn == 0 {
				return
			}
			seqMu.Lock()
			seq++
			s := seq
			seqMu.Unlock()
			outPkt := quicBuildShortHeaderUDP(quicConnID, s, sendBuf[:rn])
			if _, werr := udpConn.Write(outPkt); werr != nil {
				return
			}
		}
	}()
	<-done
}

// ═══════════════════════════════════════════════════════════════════════════
// WebRTC tunnel — real UDP-based STUN/TURN
// Wire: STUN Binding Request (0x0001) for handshake with target in USERNAME,
// Binding Success Response (0x0101), then TURN ChannelData for data relay.
// Each UDP datagram is one STUN/TURN message.
// Wireshark identifies these as STUN/TURN by the magic cookie 0x2112A442.
// ═══════════════════════════════════════════════════════════════════════════

const (
	stunBindingRequest  uint16 = 0x0001
	stunBindingSuccess  uint16 = 0x0101
	stunMagicCookie     uint32 = 0x2112A442
	stunAttrUsername    uint16 = 0x0006
	turnChannelDataBase uint16 = 0x4000
)

var stunTxnID = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}

// stunBuildMessage builds a STUN message (RFC 5389) for UDP.
// Format: type(2) + length(2) + magic cookie(4) + transaction ID(12) + attrs
func stunBuildMessage(msgType uint16, txnID []byte, attrs []byte) []byte {
	if len(txnID) < 12 {
		padded := make([]byte, 12)
		copy(padded, txnID)
		txnID = padded
	}
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], msgType)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(attrs)))
	binary.BigEndian.PutUint32(hdr[4:8], stunMagicCookie)
	copy(hdr[8:20], txnID[:12])
	return append(hdr, attrs...)
}

// stunBuildUsernameAttr encodes a target address in a STUN USERNAME attribute.
func stunBuildUsernameAttr(target string) []byte {
	val := []byte(target)
	attr := make([]byte, 4)
	binary.BigEndian.PutUint16(attr[0:2], stunAttrUsername)
	binary.BigEndian.PutUint16(attr[2:4], uint16(len(val)))
	attr = append(attr, val...)
	if pad := len(val) % 4; pad != 0 {
		attr = append(attr, make([]byte, 4-pad)...)
	}
	return attr
}

// stunExtractUsername extracts the USERNAME attribute value from STUN attrs.
func stunExtractUsername(attrs []byte) string {
	pos := 0
	for pos+4 <= len(attrs) {
		attrType := binary.BigEndian.Uint16(attrs[pos : pos+2])
		attrLen := int(binary.BigEndian.Uint16(attrs[pos+2 : pos+4]))
		pos += 4
		if pos+attrLen > len(attrs) {
			break
		}
		if attrType == stunAttrUsername {
			return string(attrs[pos : pos+attrLen])
		}
		pos += attrLen
		if pad := attrLen % 4; pad != 0 {
			pos += 4 - pad
		}
	}
	return ""
}

// stunParseMessage parses a STUN message from a UDP datagram.
// Returns message type, transaction ID, and attribute bytes.
func stunParseMessage(pkt []byte) (uint16, []byte, []byte, error) {
	if len(pkt) < 20 {
		return 0, nil, nil, fmt.Errorf("STUN: packet too short (%d)", len(pkt))
	}
	msgType := binary.BigEndian.Uint16(pkt[0:2])
	msgLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	cookie := binary.BigEndian.Uint32(pkt[4:8])
	if cookie != stunMagicCookie {
		return 0, nil, nil, fmt.Errorf("STUN: bad magic cookie 0x%08x", cookie)
	}
	txnID := make([]byte, 12)
	copy(txnID, pkt[8:20])
	if 20+msgLen > len(pkt) {
		msgLen = len(pkt) - 20
	}
	var attrs []byte
	if msgLen > 0 {
		attrs = pkt[20 : 20+msgLen]
	}
	return msgType, txnID, attrs, nil
}

// turnBuildChannelData builds a TURN ChannelData message for UDP.
// Format: channel number(2) + length(2) + data (padded to 4-byte boundary).
func turnBuildChannelData(channel uint16, data []byte) []byte {
	dataLen := len(data)
	padded := dataLen
	if rem := dataLen % 4; rem != 0 {
		padded += 4 - rem
	}
	msg := make([]byte, 4+padded)
	binary.BigEndian.PutUint16(msg[0:2], channel)
	binary.BigEndian.PutUint16(msg[2:4], uint16(dataLen))
	copy(msg[4:], data)
	return msg
}

// turnParseChannelData parses a TURN ChannelData message from a UDP datagram.
// Returns channel number and data payload.
func turnParseChannelData(pkt []byte) (uint16, []byte, error) {
	if len(pkt) < 4 {
		return 0, nil, fmt.Errorf("TURN ChannelData: too short (%d)", len(pkt))
	}
	channel := binary.BigEndian.Uint16(pkt[0:2])
	dataLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if 4+dataLen > len(pkt) {
		dataLen = len(pkt) - 4
	}
	if dataLen <= 0 {
		return channel, nil, nil
	}
	return channel, pkt[4 : 4+dataLen], nil
}

// webrtcUDPMaxPayload is the maximum tunnel data per UDP datagram.
// 4 (ChannelData header) + payload ≤ 1400.
const webrtcUDPMaxPayload = 1396

// ── WebRTC UDP server ───────────────────────────────────────────────────────

func serveWebRTCTunnel(ctx context.Context, port int, emit func(string)) TunnelResult {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return TunnelResult{Error: err}
	}
	defer pc.Close()
	emit(fmt.Sprintf("[+] WebRTC tunnel bound on %s (UDP)", addr))
	emit(fmt.Sprintf("[+] Listening on port %d — waiting for client...", port))
	go func() { <-ctx.Done(); pc.Close() }()

	type udpSession struct {
		remote     net.Conn
		clientAddr net.Addr
		cancel     context.CancelFunc
	}

	var mu sync.Mutex
	sessions := make(map[string]*udpSession)

	buf := make([]byte, 2000)
	for {
		n, clientAddr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return TunnelResult{}
			}
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		// STUN message: first two bits are 0 (type < 0x4000) and has magic cookie.
		if n >= 20 && pkt[0]&0xC0 == 0 {
			msgType, txnID, attrs, perr := stunParseMessage(pkt)
			if perr != nil {
				continue
			}
			if msgType != stunBindingRequest {
				continue
			}
			target := stunExtractUsername(attrs)
			if target == "" {
				continue
			}

			// Send Binding Success Response.
			resp := stunBuildMessage(stunBindingSuccess, txnID, nil)
			pc.WriteTo(resp, clientAddr)

			if target == "verify" {
				emit(fmt.Sprintf("[+] Client verified from %s", clientAddr))
				continue
			}

			// Dial TCP destination.
			remote, derr := net.DialTimeout("tcp", target, 10*time.Second)
			if derr != nil {
				emit(fmt.Sprintf("[-] WebRTC tunnel: cannot reach %s: %s", target, derr))
				continue
			}

			sessCtx, sessCancel := context.WithCancel(ctx)
			sess := &udpSession{
				remote:     remote,
				clientAddr: clientAddr,
				cancel:     sessCancel,
			}
			key := clientAddr.String()
			mu.Lock()
			if old, ok := sessions[key]; ok {
				old.cancel()
				old.remote.Close()
			}
			sessions[key] = sess
			mu.Unlock()

			emit(fmt.Sprintf("[+] WebRTC tunnel: proxying %s → %s", clientAddr, target))

			// Goroutine: read from TCP destination, send as TURN ChannelData via UDP.
			go func(s *udpSession, sctx context.Context, caddr net.Addr) {
				defer func() {
					mu.Lock()
					if sessions[caddr.String()] == s {
						delete(sessions, caddr.String())
					}
					mu.Unlock()
					s.remote.Close()
				}()
				readBuf := make([]byte, webrtcUDPMaxPayload)
				for {
					if sctx.Err() != nil {
						return
					}
					s.remote.SetReadDeadline(time.Now().Add(5 * time.Minute))
					rn, rerr := s.remote.Read(readBuf)
					if rerr != nil {
						return
					}
					outPkt := turnBuildChannelData(turnChannelDataBase, readBuf[:rn])
					pc.WriteTo(outPkt, caddr)
				}
			}(sess, sessCtx, clientAddr)
			continue
		}

		// TURN ChannelData: first two bits indicate channel (>= 0x4000).
		if n >= 4 && pkt[0]&0xC0 != 0 {
			ch, payload, perr := turnParseChannelData(pkt)
			if perr != nil || len(payload) == 0 {
				continue
			}
			if ch < 0x4000 || ch > 0x7FFF {
				continue
			}
			key := clientAddr.String()
			mu.Lock()
			sess := sessions[key]
			mu.Unlock()
			if sess == nil {
				continue
			}
			sess.remote.SetWriteDeadline(time.Now().Add(30 * time.Second))
			sess.remote.Write(payload)
		}
	}
}

// ── WebRTC UDP client ───────────────────────────────────────────────────────

func connectWebRTCTunnelClient(ctx context.Context, proxyAddr string, emit func(string)) TunnelResult {
	// Probe: send STUN Binding Request with "verify" target, expect Success back.
	probeConn, err := net.DialTimeout("udp", proxyAddr, 3*time.Second)
	if err != nil {
		return TunnelResult{Error: fmt.Errorf("cannot reach %s (udp): %w", proxyAddr, err)}
	}
	probeConn.SetDeadline(time.Now().Add(3 * time.Second))
	attrs := stunBuildUsernameAttr("verify")
	probeConn.Write(stunBuildMessage(stunBindingRequest, stunTxnID, attrs))

	probeBuf := make([]byte, 2000)
	pn, perr := probeConn.Read(probeBuf)
	probeConn.Close()
	if perr != nil {
		return TunnelResult{Error: fmt.Errorf("not a WebRTC tunnel on %s", proxyAddr)}
	}
	msgType, _, _, perr := stunParseMessage(probeBuf[:pn])
	if perr != nil || msgType != stunBindingSuccess {
		return TunnelResult{Error: fmt.Errorf("not a WebRTC tunnel on %s (no binding response)", proxyAddr)}
	}

	// Start local SOCKS5 TCP forwarder.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return TunnelResult{Error: fmt.Errorf("local SOCKS listener: %w", err)}
	}
	defer ln.Close()
	localAddr := ln.Addr().String()
	emit(fmt.Sprintf("[+] Remote WebRTC tunnel verified at %s", proxyAddr))
	emit(fmt.Sprintf("[+] Local SOCKS5 forwarder on %s", localAddr))
	emit(fmt.Sprintf("[+] Tunnel active — socks5://%s → webrtc://%s", localAddr, proxyAddr))
	emit(fmt.Sprintf("[*] Point applications at socks5://%s", localAddr))
	go func() { <-ctx.Done(); ln.Close() }()

	for {
		local, lerr := ln.Accept()
		if lerr != nil {
			if ctx.Err() != nil {
				return TunnelResult{}
			}
			continue
		}
		go webrtcForwardSOCKS(ctx, local, proxyAddr, emit)
	}
}

// webrtcForwardSOCKS handles one SOCKS5 connection through the WebRTC UDP tunnel.
func webrtcForwardSOCKS(ctx context.Context, local net.Conn, proxyAddr string, emit func(string)) {
	defer local.Close()
	local.SetDeadline(time.Now().Add(5 * time.Minute))

	// SOCKS5 greeting.
	buf := make([]byte, 256)
	n, err := local.Read(buf)
	if err != nil || n < 3 || buf[0] != 0x05 {
		return
	}
	local.Write([]byte{0x05, 0x00})

	// SOCKS5 CONNECT.
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

	// Open a dedicated UDP connection to the tunnel server.
	udpConn, err := net.DialTimeout("udp", proxyAddr, 5*time.Second)
	if err != nil {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer udpConn.Close()

	// Send STUN Binding Request with real target in USERNAME.
	udpConn.SetDeadline(time.Now().Add(5 * time.Second))
	attrs := stunBuildUsernameAttr(target)
	udpConn.Write(stunBuildMessage(stunBindingRequest, stunTxnID, attrs))

	// Read Binding Success Response.
	hsBuf := make([]byte, 2000)
	hn, herr := udpConn.Read(hsBuf)
	if herr != nil {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	msgType, _, _, herr := stunParseMessage(hsBuf[:hn])
	if herr != nil || msgType != stunBindingSuccess {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// SOCKS5 success.
	local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	emit(fmt.Sprintf("[+] WebRTC tunnel forwarding → %s", target))

	// Reset deadline for relay phase.
	udpConn.SetDeadline(time.Time{})
	local.SetDeadline(time.Now().Add(5 * time.Minute))

	// Bidirectional relay: local TCP <-> UDP TURN ChannelData tunnel.
	done := make(chan struct{}, 2)

	// UDP → local TCP: read TURN ChannelData, extract payload, write to local.
	go func() {
		defer func() { done <- struct{}{} }()
		readBuf := make([]byte, 2000)
		for {
			udpConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
			rn, rerr := udpConn.Read(readBuf)
			if rerr != nil {
				return
			}
			pkt := readBuf[:rn]
			if len(pkt) < 4 {
				continue
			}
			// Skip STUN messages (shouldn't happen in relay phase).
			if pkt[0]&0xC0 == 0 {
				continue
			}
			ch, payload, perr := turnParseChannelData(pkt)
			if perr != nil || len(payload) == 0 {
				continue
			}
			if ch < 0x4000 || ch > 0x7FFF {
				continue
			}
			if _, werr := local.Write(payload); werr != nil {
				return
			}
		}
	}()

	// Local TCP → UDP: read from local, wrap in TURN ChannelData, send.
	go func() {
		defer func() { done <- struct{}{} }()
		sendBuf := make([]byte, webrtcUDPMaxPayload)
		for {
			rn, rerr := local.Read(sendBuf)
			if rerr != nil || rn == 0 {
				return
			}
			outPkt := turnBuildChannelData(turnChannelDataBase, sendBuf[:rn])
			if _, werr := udpConn.Write(outPkt); werr != nil {
				return
			}
		}
	}()
	<-done
}

// ═══════════════════════════════════════════════════════════════════════════
// Shared tunnel helpers
// ═══════════════════════════════════════════════════════════════════════════

// serveTCPTunnel provides a generic TCP tunnel server framework.
// The handshake function reads the target from the client using
// protocol-specific messages and returns the target and remote connection.
// relayOverride replaces the default raw relay; if nil, uses binRelay.
func serveTCPTunnel(ctx context.Context, proto string, port int, emit func(string),
	handshake func(conn net.Conn) (target string, remote net.Conn, err error),
	relayOverride ...func(client, remote net.Conn)) TunnelResult {

	addr := fmt.Sprintf("0.0.0.0:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return TunnelResult{Error: err}
	}
	defer ln.Close()
	emit(fmt.Sprintf("[+] %s tunnel bound on %s", proto, addr))
	emit(fmt.Sprintf("[+] Listening on port %d — waiting for client...", port))
	go func() { <-ctx.Done(); ln.Close() }()

	doRelay := binRelayDefault
	if len(relayOverride) > 0 && relayOverride[0] != nil {
		doRelay = relayOverride[0]
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return TunnelResult{}
			}
			continue
		}
		conn.SetDeadline(time.Now().Add(5 * time.Minute))
		emit(fmt.Sprintf("[+] Client connected from %s", conn.RemoteAddr()))

		go func(c net.Conn) {
			defer c.Close()
			target, remote, err := handshake(c)
			if err != nil || remote == nil {
				return
			}
			defer remote.Close()
			emit(fmt.Sprintf("[+] %s tunnel: proxying → %s", proto, target))
			// doRelay(rawConn, framedConn): remote=raw(destination), c=framed(tunnel)
			doRelay(remote, c)
		}(conn)
	}
}

// forwardGenericTextTunnel is a shared forwarder for text-based tunnel
// protocols. It accepts SOCKS5 from local apps, extracts the target,
// then calls the protocol-specific handshake to set up the remote
// tunnel connection. After handshake, bidirectional relay begins.
func forwardGenericTextTunnel(local net.Conn, proxyAddr, proto string, emit func(string),
	handshake func(remote net.Conn, target string) bool,
	relayOverride ...func(client, remote net.Conn)) {

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

	// Connect to tunnel server.
	remote, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()
	remote.SetDeadline(time.Now().Add(5 * time.Minute))

	// Protocol-specific handshake with target.
	if !handshake(remote, target) {
		local.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// SOCKS5 success.
	local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	emit(fmt.Sprintf("[+] %s tunnel forwarding → %s", proto, target))

	doRelay := binRelayDefault
	if len(relayOverride) > 0 && relayOverride[0] != nil {
		doRelay = relayOverride[0]
	}
	doRelay(local, remote)
}
