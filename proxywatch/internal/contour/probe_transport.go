package contour

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func runProbeListenerSocks5Handshake(conn net.Conn, timeout time.Duration) bool {
	if conn == nil {
		return false
	}
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	greeting, err := readSocks5Greeting(conn, timeout)
	if err != nil || len(greeting) < 3 {
		return false
	}
	supportsNoAuth := false
	for _, m := range greeting[2:] {
		if m == 0x00 {
			supportsNoAuth = true
			break
		}
	}
	if !supportsNoAuth {
		_, _ = conn.Write([]byte{0x05, 0xff})
		return false
	}
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return false
	}
	connectReq, err := readSocks5ConnectMessage(conn, timeout)
	if err != nil || len(connectReq) == 0 {
		return false
	}
	if !validateSocks5ConnectRequest(connectReq) {
		return false
	}
	reply := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90}
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(reply); err != nil {
		return false
	}
	return true
}

func startTCPEchoServerOn(bindHost string, port int, exchangeCounter *uint64, recorder *probeListenerRecorder) (net.Listener, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort(bindHost, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				request, err := readProbeTCPRequest(c, 64*1024, 4*time.Second)
				if err != nil || len(request) == 0 {
					return
				}
				if _, ok := decodeProbePacket(request, false); ok {
					response, ok := buildProbeResponsePacket(request)
					if !ok {
						return
					}
					if _, err := c.Write(response); err != nil {
						return
					}
					if exchangeCounter != nil {
						atomic.AddUint64(exchangeCounter, 1)
					}
					recordProbeListenerCheck(recorder, request, "tcp", port, c.RemoteAddr())
					return
				}
				method, exfil, ok := detectProbeRawMethod(request)
				if !ok {
					return
				}
				response := buildProbeMethodResponseBody(method, request)
				if len(response) == 0 {
					return
				}
				if _, err := c.Write(response); err != nil {
					return
				}
				kind := "tunnel"
				if exfil {
					kind = "exfil"
				}
				if !exfil && methodUsesSocksCarrierTunnel(method) {
					if !runProbeListenerSocks5Handshake(c, 4*time.Second) {
						return
					}
				}
				if exchangeCounter != nil {
					atomic.AddUint64(exchangeCounter, 1)
				}
				recordProbeListenerCheckWithKind(recorder, kind, method, "tcp", port, c.RemoteAddr())
			}(conn)
		}
	}()
	return ln, nil
}

type udpEchoServer struct {
	pc      net.PacketConn
	done    chan struct{}
	once    sync.Once
	counter *uint64
}

func startUDPEchoServerOn(bindHost string, port int, exchangeCounter *uint64, recorder *probeListenerRecorder) (*udpEchoServer, error) {
	pc, err := net.ListenPacket("udp", net.JoinHostPort(bindHost, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	srv := &udpEchoServer{pc: pc, done: make(chan struct{}), counter: exchangeCounter}
	go func() {
		buf := make([]byte, 4096)
		for {
			_ = pc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					select {
					case <-srv.done:
						return
					default:
						continue
					}
				}
				return
			}
			if n == 0 {
				continue
			}
			response, ok := buildProbeListenerResponsePacket(buf[:n])
			if !ok {
				continue
			}
			_, _ = pc.WriteTo(response, addr)
			if srv.counter != nil {
				atomic.AddUint64(srv.counter, 1)
			}
			recordProbeListenerCheck(recorder, buf[:n], "udp", port, addr)
		}
	}()
	return srv, nil
}

func (u *udpEchoServer) Close() {
	if u == nil {
		return
	}
	u.once.Do(func() {
		close(u.done)
		_ = u.pc.Close()
	})
}

func recordProbeListenerCheck(recorder *probeListenerRecorder, raw []byte, transport string, port int, peer net.Addr) {
	if recorder == nil {
		return
	}
	kind := "tunnel"
	method := ""
	if packet, ok := decodeProbePacket(raw, false); ok {
		kind = strings.ToLower(strings.TrimSpace(packet.Kind))
		method = strings.ToLower(strings.TrimSpace(packet.Method))
	} else {
		rawMethod, exfil, ok := detectProbeRawMethod(raw)
		if !ok {
			return
		}
		method = strings.ToLower(strings.TrimSpace(rawMethod))
		if exfil {
			kind = "exfil"
		}
	}
	peerLabel := ""
	if peer != nil {
		peerLabel = strings.TrimSpace(peer.String())
	}
	recorder.record(ProbeCheck{
		Kind:      kind,
		Method:    method,
		Transport: strings.ToLower(strings.TrimSpace(transport)),
		Port:      port,
		Success:   true,
		Peer:      peerLabel,
	})
}

func recordProbeListenerCheckWithKind(recorder *probeListenerRecorder, kind, method, transport string, port int, peer net.Addr) {
	if recorder == nil {
		return
	}
	peerLabel := ""
	if peer != nil {
		peerLabel = strings.TrimSpace(peer.String())
	}
	recorder.record(ProbeCheck{
		Kind:      strings.ToLower(strings.TrimSpace(nonEmpty(kind, "tunnel"))),
		Method:    strings.ToLower(strings.TrimSpace(method)),
		Transport: strings.ToLower(strings.TrimSpace(transport)),
		Port:      port,
		Success:   true,
		Peer:      peerLabel,
	})
}

func readTCPWithIdleTimeout(conn net.Conn, maxBytes int, idle time.Duration) ([]byte, error) {
	if conn == nil {
		return nil, io.EOF
	}
	if maxBytes <= 0 {
		maxBytes = 64 * 1024
	}
	if idle <= 0 {
		idle = 120 * time.Millisecond
	}
	tmp := make([]byte, 4096)
	out := make([]byte, 0, 4096)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(idle))
		n, err := conn.Read(tmp)
		if n > 0 {
			if len(out)+n > maxBytes {
				n = maxBytes - len(out)
			}
			out = append(out, tmp[:n]...)
			if len(out) >= maxBytes {
				return out, nil
			}
			continue
		}
		if err != nil {
			if (isNetTimeout(err) || errors.Is(err, io.EOF)) && len(out) > 0 {
				return out, nil
			}
			return nil, err
		}
		if len(out) > 0 {
			return out, nil
		}
	}
}

func readTCPExact(conn net.Conn, n int, timeout time.Duration) ([]byte, error) {
	if conn == nil {
		return nil, io.EOF
	}
	if n <= 0 {
		return nil, nil
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	buf := make([]byte, n)
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func readProbeTCPRequest(conn net.Conn, maxBytes int, timeout time.Duration) ([]byte, error) {
	if conn == nil {
		return nil, io.EOF
	}
	if maxBytes <= 0 {
		maxBytes = 64 * 1024
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	tmp := make([]byte, 4096)
	out := make([]byte, 0, 4096)
	deadline := time.Now().Add(timeout)
	for len(out) < maxBytes {
		remain := time.Until(deadline)
		if remain <= 0 {
			break
		}
		wait := min(remain, 200*time.Millisecond)
		_ = conn.SetReadDeadline(time.Now().Add(wait))
		n, err := conn.Read(tmp)
		if n > 0 {
			if len(out)+n > maxBytes {
				n = maxBytes - len(out)
			}
			out = append(out, tmp[:n]...)
			// Fast boundary checks for protocol-style requests.
			if bytes.Contains(out, []byte("\r\n\r\n")) ||
				bytes.HasSuffix(out, []byte("\n")) ||
				len(out) >= probePacketHeaderLen {
				if packet, ok := decodeProbePacket(out, false); ok && len(packet.Body) > 0 {
					return out, nil
				}
				if bytes.Contains(out, []byte("\r\n\r\n")) || bytes.HasSuffix(out, []byte("\n")) {
					return out, nil
				}
			}
			continue
		}
		if err != nil {
			if isNetTimeout(err) && len(out) > 0 {
				return out, nil
			}
			if errors.Is(err, io.EOF) && len(out) > 0 {
				return out, nil
			}
			return nil, err
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	if len(out) == 0 {
		return nil, io.EOF
	}
	return out, nil
}

func readSocks5Greeting(conn net.Conn, timeout time.Duration) ([]byte, error) {
	head, err := readTCPExact(conn, 2, timeout)
	if err != nil {
		return nil, err
	}
	if head[0] != 0x05 {
		return nil, errors.New("invalid socks5 greeting version")
	}
	methodsLen := int(head[1])
	if methodsLen <= 0 || methodsLen > 255 {
		return nil, errors.New("invalid socks5 method list length")
	}
	methods, err := readTCPExact(conn, methodsLen, timeout)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 2+len(methods))
	out = append(out, head...)
	out = append(out, methods...)
	return out, nil
}

func readSocks5MethodSelection(conn net.Conn, timeout time.Duration) ([]byte, error) {
	return readTCPExact(conn, 2, timeout)
}

func readSocks5ConnectMessage(conn net.Conn, timeout time.Duration) ([]byte, error) {
	head, err := readTCPExact(conn, 4, timeout)
	if err != nil {
		return nil, err
	}
	atyp := head[3]
	out := make([]byte, 0, 32)
	out = append(out, head...)
	switch atyp {
	case 0x01:
		rest, err := readTCPExact(conn, 4+2, timeout)
		if err != nil {
			return nil, err
		}
		out = append(out, rest...)
	case 0x03:
		dlenRaw, err := readTCPExact(conn, 1, timeout)
		if err != nil {
			return nil, err
		}
		dlen := int(dlenRaw[0])
		if dlen <= 0 {
			return nil, errors.New("invalid socks5 domain length")
		}
		out = append(out, dlenRaw...)
		rest, err := readTCPExact(conn, dlen+2, timeout)
		if err != nil {
			return nil, err
		}
		out = append(out, rest...)
	case 0x04:
		rest, err := readTCPExact(conn, 16+2, timeout)
		if err != nil {
			return nil, err
		}
		out = append(out, rest...)
	default:
		return nil, errors.New("unsupported socks5 atyp")
	}
	return out, nil
}

func probeSocksCarrierTunnelRoundTrip(ctx context.Context, host string, port int, method string, timeout time.Duration) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return false
	}
	carrierRequest := buildProbeMethodBaseRequestBody(method, port)
	if len(carrierRequest) == 0 {
		return false
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	defer conn.Close()
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	setDeadline := func() {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}
	setDeadline()
	if _, err := conn.Write(carrierRequest); err != nil {
		return false
	}
	setDeadline()
	carrierResponse, err := readTCPWithIdleTimeout(conn, 64*1024, min(timeout/2, 600*time.Millisecond))
	if err != nil || len(carrierResponse) == 0 {
		return false
	}
	if !validateProbeWireResponse(method, carrierRequest, carrierResponse) {
		return false
	}
	greeting := []byte{0x05, 0x01, 0x00}
	setDeadline()
	if _, err := conn.Write(greeting); err != nil {
		return false
	}
	setDeadline()
	methodSelection, err := readSocks5MethodSelection(conn, timeout)
	if err != nil || len(methodSelection) < 2 {
		return false
	}
	if methodSelection[0] != 0x05 || methodSelection[1] != 0x00 {
		return false
	}
	tunnelPayload := buildProbeSocks5TunnelPayload(port)
	if len(tunnelPayload) < 4 {
		return false
	}
	connectRequest := tunnelPayload[3:]
	setDeadline()
	if _, err := conn.Write(connectRequest); err != nil {
		return false
	}
	setDeadline()
	connectReply, err := readSocks5ConnectMessage(conn, timeout)
	if err != nil || len(connectReply) == 0 {
		return false
	}
	return validateSocks5ConnectReply(connectReply)
}

func probeTCPRoundTrip(ctx context.Context, host string, port int, method string, payload []byte, timeout time.Duration) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return false
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(payload); err != nil {
		return false
	}
	response, err := readTCPWithIdleTimeout(conn, 64*1024, min(timeout/2, 500*time.Millisecond))
	if err != nil || len(response) == 0 {
		return false
	}
	return validateProbeWireResponse(method, payload, response)
}

func probeUDPRoundTrip(ctx context.Context, host string, port int, method string, payload []byte, timeout time.Duration) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return false
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(payload); err != nil {
		return false
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return false
	}
	if n <= 0 {
		return false
	}
	return validateProbeWireResponse(method, payload, buf[:n])
}
