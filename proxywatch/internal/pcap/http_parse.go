package pcap

import (
	"bytes"
	"strings"
)

// parseHTTPRequestIntoFlow attempts to parse `payload` as the start of
// an HTTP request and records the URI / Host / User-Agent on the flow.
// Sets st.httpParseAttempted regardless of outcome so the parser only
// runs once per flow (we want the FIRST request's headers — beacons
// typically open a new connection per callback so the first request
// IS the diagnostic one).
//
// Lenient parser by design: it doesn't validate the full RFC 7230 grammar,
// just looks for the first request line ("METHOD path HTTP/1.\r") and
// then walks header lines for Host / User-Agent. Returns no error on
// malformed input — the flow simply doesn't get HTTP fields populated.
//
// Performance: called once per flow on its first non-empty initiator-
// side payload. Bounded work (capped at httpParseMaxBytes ≈ 8 KiB).
const httpParseMaxBytes = 8 * 1024

func parseHTTPRequestIntoFlow(payload []byte, st *flowState) {
	if st == nil || st.httpParseAttempted {
		return
	}
	st.httpParseAttempted = true

	// Cap the buffer we examine — HTTP request headers are virtually
	// always under 8 KiB.
	if len(payload) > httpParseMaxBytes {
		payload = payload[:httpParseMaxBytes]
	}

	// Find the first \r\n.
	i := bytes.Index(payload, []byte("\r\n"))
	if i < 0 {
		return
	}
	requestLine := string(payload[:i])

	// Method validation — bail if it doesn't start with one of the
	// HTTP methods we care about. Cheaper than a regex match.
	method, rest, ok := strings.Cut(requestLine, " ")
	if !ok {
		return
	}
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
	default:
		return
	}
	uri, version, ok := strings.Cut(rest, " ")
	if !ok || !strings.HasPrefix(version, "HTTP/1.") {
		return
	}
	st.httpURI = uri

	// Walk header lines until empty line (end of headers).
	headers := payload[i+2:]
	for len(headers) > 0 {
		next := bytes.Index(headers, []byte("\r\n"))
		if next < 0 {
			break
		}
		line := headers[:next]
		headers = headers[next+2:]
		if len(line) == 0 {
			break // end of headers
		}
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(string(line[:colon])))
		value := strings.TrimSpace(string(line[colon+1:]))
		switch name {
		case "host":
			if st.httpHost == "" {
				st.httpHost = value
			}
		case "user-agent":
			if st.httpUserAgent == "" {
				st.httpUserAgent = value
			}
		}
		if st.httpHost != "" && st.httpUserAgent != "" {
			break
		}
	}
}

// shouldAttemptHTTPParse gates parser invocation to ports that
// commonly carry cleartext HTTP. Avoids attempting to parse encrypted
// TLS bytes or bursts on weird ports.
func shouldAttemptHTTPParse(dstPort int) bool {
	switch dstPort {
	case 80, 81, 8000, 8008, 8080, 8081, 8443, 8888, 9000:
		return true
	}
	return false
}
