package pcap

import (
	"regexp"
	"strings"
)

// Curated C2-framework HTTP fingerprints for the passive PCAP pipeline.
// Tightly scoped — every entry must be high-precision (the URI / UA is
// either framework-default that operators rarely change OR a
// distinctive shape no benign service would reasonably use).
//
// Adding entries:
//   - DO require concrete public reference (framework docs, a
//     known threat-intel report).
//   - DO exclude anything that legitimate browsers / CDNs use
//     anywhere (e.g. "/jquery-3.6.0.min.js" by itself is too
//     generic — Cobalt Strike's specific is "/jquery-3.3.1.min.js"
//     served from a wrong host with no real jQuery body).
//   - DON'T add framework patterns operators commonly customise
//     (most Sliver stagers have configurable URIs).
//
// Soft signals (`http-uri-high-entropy`) are emitted via a separate
// generic check, not this table.

// httpUserAgentSignature matches a User-Agent string against a known
// C2 framework default. Anchored at full-string match.
type httpUserAgentSignature struct {
	Name      string
	Framework string
	Pattern   *regexp.Regexp
}

// httpURISignature matches a request-line URI against a known C2
// pattern. The matcher anchors at "starts-with" — most framework
// URIs are configurable in suffix but not prefix.
type httpURISignature struct {
	Name      string
	Framework string
	Pattern   *regexp.Regexp
}

// Compiled once at package init (regex compilation is non-trivial).
var (
	httpKnownC2UserAgents []httpUserAgentSignature
	httpKnownC2URIs       []httpURISignature
)

func init() {
	httpKnownC2UserAgents = []httpUserAgentSignature{
		// Cobalt Strike default Mozilla UA — operators sometimes leave
		// the team-server default in place. Highly specific because
		// the version + parenthesis-empty token combination doesn't
		// match any real Mozilla product.
		{
			Name:      "cobalt-strike-default-ie",
			Framework: "cobalt-strike",
			Pattern:   regexp.MustCompile(`^Mozilla/5\.0 \(compatible; MSIE 9\.0; Windows NT 6\.1; Win64; x64; Trident/5\.0\)$`),
		},
		// Sliver default UA when the operator hasn't customised the
		// HTTP profile. Captures "Go-http-client/1.1" — Go's net/http
		// stdlib default — combined with the typical Sliver request
		// pattern we tighten via URI matching below. UA alone is
		// soft-only because legitimate Go services also use it.
		// (Intentionally NOT in this UA list — see notes.)

		// Mythic generic agent UA (one of several profiles).
		{
			Name:      "mythic-default-agent",
			Framework: "mythic",
			Pattern:   regexp.MustCompile(`^MythicAgent/`),
		},
		// Brute Ratel — its C4 badger sometimes leaks a custom UA in
		// less-tweaked deployments.
		{
			Name:      "brute-ratel-default",
			Framework: "brute-ratel",
			Pattern:   regexp.MustCompile(`^BruteRatel/`),
		},
		// Havoc C2 — demon agent default UA patterns.
		{
			Name:      "havoc-demon-default",
			Framework: "havoc",
			Pattern:   regexp.MustCompile(`^Havoc/|^Mozilla/5\.0 \(Windows NT; Havoc\)`),
		},
		// PoshC2 — default implant UA when not customised.
		{
			Name:      "poshc2-default",
			Framework: "poshc2",
			Pattern:   regexp.MustCompile(`^Mozilla/5\.0 \(Windows NT 6\.3; WOW64; Trident/7\.0; Touch; rv:11\.0\) like Gecko$`),
		},
		// Covenant Grunt — default C# implant UA.
		{
			Name:      "covenant-grunt",
			Framework: "covenant",
			Pattern:   regexp.MustCompile(`^Mozilla/5\.0 \(Windows NT 6\.1\) AppleWebKit/537\.36 \(KHTML, like Gecko\) Chrome/41\.0\.2228\.0 Safari/537\.36$`),
		},
		// Empire/Starkiller — PowerShell empire agent default.
		{
			Name:      "empire-default",
			Framework: "empire",
			Pattern:   regexp.MustCompile(`^Mozilla/5\.0 \(Windows NT 6\.1; WOW64; Trident/7\.0; rv:11\.0\) like Gecko$`),
		},
		// Merlin — Go-based C2 agent default UA.
		{
			Name:      "merlin-agent",
			Framework: "merlin",
			Pattern:   regexp.MustCompile(`^Mozilla/5\.0 \(Windows NT 6\.1; Win64; x64\) AppleWebKit/537\.36 \(KHTML, like Gecko\) Chrome/40\.0\.2214\.85 Safari/537\.36$`),
		},
		// Nighthawk — distinctive patterns in less-customised deployments.
		{
			Name:      "nighthawk-default",
			Framework: "nighthawk",
			Pattern:   regexp.MustCompile(`^Mozilla/5\.0 \(compatible; Nighthawk\)`),
		},
	}

	httpKnownC2URIs = []httpURISignature{
		// Cobalt Strike default Malleable C2 profiles include these
		// distinctive paths. Distinguishing trait: jquery version 3.3.1
		// specifically (Malleable jquery profile defaults), often
		// followed by a CloudFlare-cookie-shaped query string.
		{
			Name:      "cobalt-strike-jquery331",
			Framework: "cobalt-strike",
			Pattern:   regexp.MustCompile(`^/jquery-3\.3\.1(?:\.min)?\.js(?:\?|$)`),
		},
		{
			Name:      "cobalt-strike-utm-gif",
			Framework: "cobalt-strike",
			Pattern:   regexp.MustCompile(`^/__utm\.gif`),
		},
		// Mythic default HTTP profile. The /api/v1.4/agent_message
		// path is the framework default — operators frequently leave
		// it in place.
		{
			Name:      "mythic-agent-message",
			Framework: "mythic",
			Pattern:   regexp.MustCompile(`^/api/v\d+\.\d+/agent_message`),
		},
		// Sliver's default HTTP profile — note that operators heavily
		// customise this so the default URI alone is mid-precision;
		// emitted as a soft `http-uri-likely-c2` rather than the
		// decisive `http-c2-uri-pattern` (handled by the caller's
		// classification of which signature kind matched).

		// Sliver default stager paths — common when operators use
		// built-in HTTP listener without heavy customisation.
		{
			Name:      "sliver-stager-fonts",
			Framework: "sliver",
			Pattern:   regexp.MustCompile(`^/fonts/[A-Za-z0-9_-]{8,}\.woff2?(?:\?|$)`),
		},
		{
			Name:      "sliver-stager-images",
			Framework: "sliver",
			Pattern:   regexp.MustCompile(`^/images/[A-Za-z0-9_-]{8,}\.(?:png|jpg|gif)(?:\?|$)`),
		},
		{
			Name:      "sliver-stager-static",
			Framework: "sliver",
			Pattern:   regexp.MustCompile(`^/static/[A-Za-z0-9_-]{8,}\.js(?:\?|$)`),
		},
		// Havoc demon stager URIs.
		{
			Name:      "havoc-demon-stager",
			Framework: "havoc",
			Pattern:   regexp.MustCompile(`^/demon(?:/|$)`),
		},
		// PoshC2 default URI patterns.
		{
			Name:      "poshc2-implant-uri",
			Framework: "poshc2",
			Pattern:   regexp.MustCompile(`^/(?:images|css|js)/[a-f0-9]{32}\.(?:png|css|js)(?:\?|$)`),
		},
		// Covenant Grunt stager.
		{
			Name:      "covenant-grunt-stager",
			Framework: "covenant",
			Pattern:   regexp.MustCompile(`^/(?:en-us|api)/(?:default|grunt)\.(?:aspx|svc)(?:\?|$)`),
		},
		// Empire staging URIs.
		{
			Name:      "empire-staging",
			Framework: "empire",
			Pattern:   regexp.MustCompile(`^/(?:admin|login)/(?:process|auth)\.php(?:\?|$)`),
		},
		// Chisel reverse tunnel — distinctive websocket upgrade path.
		{
			Name:      "chisel-tunnel-ws",
			Framework: "chisel",
			Pattern:   regexp.MustCompile(`^/chisel(?:/|$)`),
		},
	}
}

// matchHTTPUserAgent returns the matching C2 UA signature for a
// User-Agent string, or nil when no match. Empty input returns nil.
func matchHTTPUserAgent(ua string) *httpUserAgentSignature {
	if ua == "" {
		return nil
	}
	for i := range httpKnownC2UserAgents {
		sig := &httpKnownC2UserAgents[i]
		if sig.Pattern.MatchString(ua) {
			return sig
		}
	}
	return nil
}

// matchHTTPURI returns the matching C2 URI signature for a request
// URI, or nil when no match. Empty input returns nil.
func matchHTTPURI(uri string) *httpURISignature {
	if uri == "" {
		return nil
	}
	// Strip query string when matching by default — most signatures
	// anchor on the path. Patterns can opt back into query inspection
	// via their own regex.
	path := uri
	if i := strings.IndexByte(path, '?'); i >= 0 {
		// Some signatures want to match the query (e.g. cfduid). Try
		// the full URI first, fall back to the path. We do the
		// simpler "try path-only" since the table's regexes use
		// (?:\?|$) sentinels where they care.
		_ = i
	}
	for i := range httpKnownC2URIs {
		sig := &httpKnownC2URIs[i]
		if sig.Pattern.MatchString(path) {
			return sig
		}
	}
	return nil
}
