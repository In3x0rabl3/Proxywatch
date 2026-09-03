package pcap

import (
	"bytes"
	"strconv"
	"strings"
)

// parseHTTPResponseIntoFlow attempts to parse `payload` as the start of
// an HTTP response and records the status code, Content-Type,
// Content-Length, and Server header on the flow. Sets
// st.httpRespParseAttempted so the parser only runs once per flow on
// the FIRST response — that's the most diagnostic one (beacons reopen
// connections per callback, so the first response carries the
// framework signature).
//
// Lenient parser: doesn't validate full RFC 7230 grammar, just walks
// the status line + key headers. Malformed payloads simply leave the
// fields blank (no error path).
//
// Bounded work (capped at httpParseMaxBytes ≈ 8 KiB) so a malformed
// "HTTP/1." prefix on a long stream can't burn parse budget.
func parseHTTPResponseIntoFlow(payload []byte, st *flowState) {
	if st == nil || st.httpRespParseAttempted {
		return
	}
	st.httpRespParseAttempted = true

	if len(payload) > httpParseMaxBytes {
		payload = payload[:httpParseMaxBytes]
	}

	// Status line: "HTTP/1.X SSS reason\r\n"
	i := bytes.Index(payload, []byte("\r\n"))
	if i < 0 {
		return
	}
	statusLine := string(payload[:i])
	if !strings.HasPrefix(statusLine, "HTTP/1.") {
		return
	}
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 {
		return
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil || code < 100 || code > 599 {
		return
	}
	st.httpRespStatus = code

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
		case "content-type":
			if st.httpRespContentType == "" {
				st.httpRespContentType = value
			}
		case "content-length":
			if st.httpRespContentLength == 0 {
				if n, err := strconv.Atoi(value); err == nil && n >= 0 {
					st.httpRespContentLength = n
				}
			}
		case "server":
			if st.httpRespServer == "" {
				st.httpRespServer = value
			}
		}
	}
}

// shouldAttemptHTTPResponseParse gates response parsing on the magic
// prefix — cheap pre-filter that catches the responder-side payload.
// Same port-set as the request gate isn't needed because we pre-check
// the prefix, but we keep the helper for symmetry with the TLS path.
func shouldAttemptHTTPResponseParse(payload []byte) bool {
	return len(payload) >= 7 && bytes.HasPrefix(payload, []byte("HTTP/1."))
}
