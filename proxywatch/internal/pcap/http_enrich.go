package pcap

import (
	"strings"

	"proxywatch/internal/shared"
)

// enrichPcapWithHTTPSignals scans flow-level HTTP fields populated
// by parseHTTPRequestIntoFlow and stamps signals on the matching
// cluster candidates. Runs as a post-pass (after candidate build,
// before role guard) so the new signals participate in the existing
// `pcapDecisiveSignals` evaluation.
//
// Two signal classes:
//   - `http-c2-known-ua`        — DECISIVE: User-Agent matched a
//     framework-default UA in the curated
//     corpus (operators leave UA defaults
//     unchanged surprisingly often).
//   - `http-c2-uri-pattern`     — DECISIVE: URI matched a framework-
//     default Malleable-C2 / agent-message
//     path.
//
// Live mode is unchanged — this pass runs only on synthetic-PID
// candidates emitted by pcap ingest. The signal names are added to
// the pcap decisive set so role-guard preserves them.
//
// FP-safety: the matchers are extremely high-precision by
// construction. A Cobalt Strike default UA literally cannot match a
// real Microsoft Edge / Chrome / curl UA. A Mythic agent_message URI
// won't appear in any benign service. If an operator ever
// encounters an FP, they can add a benign cluster label via the
// existing operator-label store and that vetoes promotion.
func enrichPcapWithHTTPSignals(flows []*flowState, attr *pcapAttribution, candidates []shared.Candidate) {
	if len(flows) == 0 || attr == nil || len(candidates) == 0 {
		return
	}

	// Build the per-PID signal set we want to add. We aggregate first
	// across all flows that route to a given cluster PID, then apply
	// to the candidate slice in a single pass.
	type matchSet struct {
		hasKnownUA      bool
		hasC2URI        bool
		hasC2RespShape  bool
		hasMIMEMismatch bool
		uaFramework     string
		uaName          string
		uaValue         string
		uriPattern      string
		respShapeReason string
		mismatchReason  string
	}
	pidMatches := make(map[int]*matchSet)

	add := func(pid int, build func(*matchSet)) {
		ms, ok := pidMatches[pid]
		if !ok {
			ms = &matchSet{}
			pidMatches[pid] = ms
		}
		build(ms)
	}

	for _, st := range flows {
		if st == nil {
			continue
		}
		if !st.httpParseAttempted && !st.httpRespParseAttempted {
			continue
		}
		// Resolve the cluster PIDs this flow contributes to. A flow
		// usually maps to TWO candidates: the per-host outbound rollup
		// and the per-/16 destination cluster. We stamp the signal on
		// both so whichever candidate the FINDINGS table promotes
		// surfaces the evidence.
		var pids []int
		if rollupPID, ok := attr.outboundPIDFor(st.key.InitIP, st.key.RespIP); ok {
			pids = append(pids, rollupPID)
		}
		if flowPID, ok := attr.outboundFlowPIDFor(st.key.InitIP, st.key.RespIP, st.key.RespPort); ok {
			pids = append(pids, flowPID)
		}
		if len(pids) == 0 {
			continue
		}

		if uaSig := matchHTTPUserAgent(st.httpUserAgent); uaSig != nil {
			for _, pid := range pids {
				add(pid, func(ms *matchSet) {
					ms.hasKnownUA = true
					ms.uaFramework = uaSig.Framework
					ms.uaName = uaSig.Name
					ms.uaValue = st.httpUserAgent
				})
			}
		}
		if uriSig := matchHTTPURI(st.httpURI); uriSig != nil {
			for _, pid := range pids {
				add(pid, func(ms *matchSet) {
					ms.hasC2URI = true
					ms.uriPattern = uriSig.Name
				})
			}
		}
		if reason := matchHTTPResponseShape(st); reason != "" {
			for _, pid := range pids {
				add(pid, func(ms *matchSet) {
					ms.hasC2RespShape = true
					ms.respShapeReason = reason
				})
			}
		}
		// MIME / URI mismatch: when a request URI claims a static-asset
		// extension (.jpg, .css, .pdf...) but the response Content-Type
		// doesn't match, it's a strong tell for HTTP-cover-channel C2
		// (Cobalt Strike Malleable profiles download "image" URIs that
		// are actually base64 task blobs).
		if reason := matchMIMETypeMismatch(st.httpURI, st.httpRespContentType); reason != "" {
			for _, pid := range pids {
				add(pid, func(ms *matchSet) {
					ms.hasMIMEMismatch = true
					ms.mismatchReason = reason
				})
			}
		}
	}

	if len(pidMatches) == 0 {
		return
	}

	for i := range candidates {
		c := &candidates[i]
		if c.Proc == nil {
			continue
		}
		ms := pidMatches[c.Proc.Pid]
		if ms == nil {
			continue
		}
		if ms.hasKnownUA {
			c.Signals = appendUniqueSignal(c.Signals, "http-c2-known-ua")
			c.Reasons = appendUniqueSignal(c.Reasons,
				"HTTP User-Agent matches "+ms.uaFramework+" default ("+ms.uaName+")")
		}
		if ms.hasC2URI {
			c.Signals = appendUniqueSignal(c.Signals, "http-c2-uri-pattern")
			c.Reasons = appendUniqueSignal(c.Reasons,
				"HTTP request URI matches C2 pattern ("+ms.uriPattern+")")
		}
		if ms.hasC2RespShape {
			c.Signals = appendUniqueSignal(c.Signals, "http-response-c2-shape")
			c.Reasons = appendUniqueSignal(c.Reasons,
				"HTTP response shape matches C2 pattern ("+ms.respShapeReason+")")
		}
		if ms.hasMIMEMismatch {
			c.Signals = appendUniqueSignal(c.Signals, "http-mime-uri-mismatch")
			c.Reasons = appendUniqueSignal(c.Reasons,
				"HTTP response MIME doesn't match URI extension ("+ms.mismatchReason+")")
		}
	}
}

// matchMIMETypeMismatch returns a non-empty reason string when the
// request URI's file extension implies a content-type class (image,
// stylesheet, font, document) that doesn't match the response's
// actual Content-Type header. The canonical Cobalt Strike Malleable-C2
// tell where a "GET /banner.jpg" returns text/plain or
// application/octet-stream because the body is actually a task-blob.
//
// Returns "" when:
//   - URI has no extension we recognise (most API paths)
//   - URI is empty or Content-Type missing (incomplete capture)
//   - Extension and Content-Type agree
//
// FP guards:
//   - We only flag KNOWN static-asset extensions. Random/unknown
//     extensions don't trigger because they could legitimately serve
//     anything.
//   - We accept generic types (application/octet-stream is treated as
//     "no opinion" rather than "definitely wrong") only when they
//     coexist with a static asset URI — that combo IS suspicious.
func matchMIMETypeMismatch(uri, contentType string) string {
	uri = strings.TrimSpace(uri)
	contentType = strings.TrimSpace(contentType)
	if uri == "" || contentType == "" {
		return ""
	}
	// Strip query string + fragment so .jpg?v=2 still matches.
	if i := strings.IndexAny(uri, "?#"); i >= 0 {
		uri = uri[:i]
	}
	// Lowercase comparisons throughout — the wire is case-insensitive
	// for extensions and (per RFC 9110) for Content-Type values.
	lowerURI := strings.ToLower(uri)
	lowerCT := strings.ToLower(contentType)
	// Take just the type/subtype, drop ; charset=... parameter.
	if i := strings.Index(lowerCT, ";"); i >= 0 {
		lowerCT = strings.TrimSpace(lowerCT[:i])
	}

	// Find the LAST '.' after the last '/' so /assets/v1.2/img.jpg
	// resolves to ".jpg" not ".2/img" etc.
	slash := strings.LastIndex(lowerURI, "/")
	tail := lowerURI
	if slash >= 0 {
		tail = lowerURI[slash+1:]
	}
	dot := strings.LastIndex(tail, ".")
	if dot < 0 || dot == len(tail)-1 {
		return ""
	}
	ext := tail[dot:]

	// Map extension → expected content-type prefix. Static asset
	// extensions only — APIs and dynamic endpoints don't end in these.
	var expected string
	switch ext {
	case ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".ico", ".svg":
		expected = "image/"
	case ".css":
		expected = "text/css"
	case ".js", ".mjs":
		// JS can be served as application/javascript or text/javascript
		// — both are fine. Mismatch is anything else.
		expected = "javascript"
	case ".woff", ".woff2", ".ttf", ".otf", ".eot":
		expected = "font/"
	case ".pdf":
		expected = "application/pdf"
	case ".mp4", ".webm", ".mov":
		expected = "video/"
	case ".mp3", ".wav", ".ogg":
		expected = "audio/"
	case ".html", ".htm":
		expected = "text/html"
	default:
		return ""
	}

	// Special case for js: extension implies a class of types, not a
	// fixed prefix.
	if expected == "javascript" {
		if strings.Contains(lowerCT, "javascript") || strings.Contains(lowerCT, "ecmascript") {
			return ""
		}
		return "URI " + ext + " expected JavaScript, got " + lowerCT
	}

	if strings.HasPrefix(lowerCT, expected) {
		return ""
	}
	return "URI " + ext + " expected " + expected + ", got " + lowerCT
}

// matchHTTPResponseShape returns a non-empty reason string when the
// flow's parsed response headers look like a known C2 framework's
// agent-message reply. Used as a DECISIVE signal — only fires on
// tight pattern matches that are very unlikely to occur in benign
// HTTP services:
//
//   - Mythic agent_message: 200 OK + application/octet-stream + small
//     body length (< 4 KiB) + no Server header (or unspecific Server).
//     Mythic returns binary blobs to the agent; legit APIs in this
//     shape almost always identify themselves via a Server header.
//   - Cobalt Strike default profile: 200 OK + text/plain or
//     application/octet-stream + Server header missing/`nginx`-spoofed
//   - content-length <= 1 byte (Cobalt's "ack" response).
//
// Returns "" when no pattern matches; the soft `http-response-observed`
// case is intentionally NOT emitted because the response side already
// has many benign permutations.
func matchHTTPResponseShape(st *flowState) string {
	if st == nil || !st.httpRespParseAttempted {
		return ""
	}
	if st.httpRespStatus != 200 {
		return ""
	}
	ct := st.httpRespContentType
	cl := st.httpRespContentLength
	server := st.httpRespServer

	// Mythic agent_message shape: octet-stream, small body, no useful Server header.
	if ct == "application/octet-stream" && cl > 0 && cl < 4096 {
		if server == "" || server == "nginx" {
			return "Mythic-style agent_message (200 OK + application/octet-stream + small body)"
		}
	}
	// Cobalt Strike default-profile ack: 1-byte body + text/plain.
	if ct == "text/plain" && cl == 1 {
		return "Cobalt-Strike-style ack (200 OK + text/plain + 1-byte body)"
	}
	return ""
}
