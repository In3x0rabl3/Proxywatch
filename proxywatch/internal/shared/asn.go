package shared

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type asnLookupStatus int

const (
	asnLookupPending asnLookupStatus = iota
	asnLookupResolved
	asnLookupFailed
)

type asnLookupRecord struct {
	orgs      []string
	err       string
	updatedAt time.Time
}

var (
	asnCacheMu      sync.RWMutex
	asnCache        = make(map[string]asnLookupRecord)
	asnLookupActive = make(map[string]bool)
	asnCacheTTL     = 6 * time.Hour
	asnDNSTimeout   = 2 * time.Second
	asnLookupSem    = make(chan struct{}, 20) // max 20 concurrent DNS lookups
)

// ResolveExternalASNOrgs resolves ASN org names for external remote IPs observed in conns.
// Lookups are async and cached; unresolved entries are reported as pending.
func ResolveExternalASNOrgs(conns []ConnectionInfo) (orgs []string, pending int, failed int) {
	unique := make(map[string]struct{})
	for _, cn := range conns {
		ip := strings.TrimSpace(cn.RemoteAddress)
		if ip == "" || IsWildcardIP(ip) || IsLoopbackIP(ip) || IsInternalIP(ip) {
			continue
		}
		unique[ip] = struct{}{}
	}
	if len(unique) == 0 {
		return nil, 0, 0
	}

	orgSet := make(map[string]struct{})
	for ip := range unique {
		rec, status := getOrQueueASNRecord(ip)
		switch status {
		case asnLookupPending:
			pending++
		case asnLookupFailed:
			failed++
		case asnLookupResolved:
			for _, org := range rec.orgs {
				org = strings.TrimSpace(org)
				if org == "" {
					continue
				}
				orgSet[org] = struct{}{}
			}
		}
	}

	if len(orgSet) == 0 {
		return nil, pending, failed
	}

	out := make([]string, 0, len(orgSet))
	for org := range orgSet {
		out = append(out, org)
	}
	sort.Strings(out)
	return out, pending, failed
}

// LookupCachedASNOrgsForIP returns the cached ASN orgs for a single IP
// without scheduling a new lookup when missing. Used by the offline-C2
// disambiguator where we don't want the pure FP-gate check to incur a
// DNS round-trip on every cycle — if the cache is empty the caller
// should treat the target as "unknown" and fall back to the default
// promotion path.
func LookupCachedASNOrgsForIP(ip string) []string {
	ip = strings.TrimSpace(ip)
	if ip == "" || IsWildcardIP(ip) || IsLoopbackIP(ip) || IsInternalIP(ip) {
		return nil
	}
	asnCacheMu.RLock()
	rec, ok := asnCache[ip]
	asnCacheMu.RUnlock()
	if !ok || rec.err != "" || len(rec.orgs) == 0 {
		return nil
	}
	if time.Since(rec.updatedAt) > asnCacheTTL {
		return nil
	}
	out := make([]string, 0, len(rec.orgs))
	for _, o := range rec.orgs {
		if o = strings.TrimSpace(o); o != "" {
			out = append(out, o)
		}
	}
	return out
}

// IsLikelyBenignOfflineTarget returns true when a callback-retry
// target's IP resolves (from ASN cache) to a CDN / major cloud org,
// or its PTR / forward-cache host matches a well-known vendor
// domain. The intent is to distinguish "benign service temporarily
// offline" (Teams, Slack, vendor telemetry endpoint) from a C2
// server the operator has taken down. target must be "ip:port" or
// "ip".
func IsLikelyBenignOfflineTarget(target string) bool {
	ip := target
	if i := strings.LastIndex(target, ":"); i > 0 {
		ip = target[:i]
	}
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return false
	}
	orgs := LookupCachedASNOrgsForIP(ip)
	for _, org := range orgs {
		if IsCDNOrg(org) {
			return true
		}
		low := strings.ToLower(org)
		// Major vendor backbones commonly host benign offline
		// services — they're legit destinations that happen to be
		// unreachable now. A C2 would more typically sit behind a
		// redirector or fresh VPS.
		for _, vendor := range []string{
			"microsoft", "google", "amazon", "apple", "facebook",
			"meta platforms", "netflix", "github", "atlassian",
			"zoom", "slack", "discord", "dropbox", "spotify",
		} {
			if strings.Contains(low, vendor) {
				return true
			}
		}
	}
	// Hostname-based check — if the PTR/fwd cache has a vendor
	// suffix, it's a benign destination.
	host := PTRLookupCached(ip)
	if host == "" {
		return false
	}
	low := strings.ToLower(host)
	for _, suf := range []string{
		".microsoft.com", ".azureedge.net", ".msedge.net",
		".googleapis.com", ".google.com", ".gstatic.com",
		".googleusercontent.com", ".amazonaws.com", ".cloudfront.net",
		".apple.com", ".icloud.com", ".github.com",
		".githubusercontent.com", ".atlassian.com", ".slack.com",
		".discord.com", ".zoom.us", ".dropboxapi.com",
	} {
		if strings.HasSuffix(low, suf) {
			return true
		}
	}
	return false
}

// ASNOrgAlignedWithProcess returns true when any resolved ASN org token overlaps
// with publisher/path context tokens for the process.
func ASNOrgAlignedWithProcess(p *ProcessInfo, orgs []string) bool {
	if p == nil || len(orgs) == 0 {
		return false
	}

	ctxTokens := processContextTokens(p)
	if len(ctxTokens) == 0 {
		return false
	}
	orgTokens := orgContextTokens(orgs)
	if len(orgTokens) == 0 {
		return false
	}

	for tok := range ctxTokens {
		if len(tok) < 4 {
			continue
		}
		if _, ok := orgTokens[tok]; ok {
			return true
		}
	}
	return false
}

func processContextTokens(p *ProcessInfo) map[string]struct{} {
	out := make(map[string]struct{})

	for _, tok := range tokenizeContextField(p.Company) {
		out[tok] = struct{}{}
	}

	path := NormalizeExePath(p.ExePath)
	if path != "" {
		for _, part := range strings.Split(path, "/") {
			for _, tok := range tokenizeContextField(part) {
				out[tok] = struct{}{}
			}
		}
		base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		for _, tok := range tokenizeContextField(base) {
			out[tok] = struct{}{}
		}
	}

	return out
}

func orgContextTokens(orgs []string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, org := range orgs {
		for _, tok := range tokenizeContextField(org) {
			out[tok] = struct{}{}
		}
	}
	return out
}

func tokenizeContextField(s string) []string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return nil
	}

	var parts []string
	var buf strings.Builder
	flush := func() {
		if buf.Len() == 0 {
			return
		}
		tok := buf.String()
		buf.Reset()
		if len(tok) < 3 {
			return
		}
		if _, skip := contextTokenStopwords[tok]; skip {
			return
		}
		parts = append(parts, tok)
	}

	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			buf.WriteRune(r)
			continue
		}
		flush()
	}
	flush()

	if len(parts) == 0 {
		return nil
	}
	return parts
}

var contextTokenStopwords = map[string]struct{}{
	"asn":            {},
	"block":          {},
	"corp":           {},
	"corporation":    {},
	"inc":            {},
	"llc":            {},
	"ltd":            {},
	"limited":        {},
	"co":             {},
	"company":        {},
	"group":          {},
	"holding":        {},
	"holdings":       {},
	"service":        {},
	"services":       {},
	"system":         {},
	"systems":        {},
	"software":       {},
	"technology":     {},
	"technologies":   {},
	"network":        {},
	"networks":       {},
	"communication":  {},
	"communications": {},
	"global":         {},
	"international":  {},
	"public":         {},
	"plc":            {},
	"gmbh":           {},
	"program":        {},
	"files":          {},
	"windows":        {},
	"users":          {},
	"user":           {},
	"desktop":        {},
	"downloads":      {},
	"tmp":            {},
	"temp":           {},
	"local":          {},
	"appdata":        {},
	"bin":            {},
	"lib":            {},
	"lib64":          {},
	"libexec":        {},
	"opt":            {},
	"usr":            {},
	"and":            {},
	"the":            {},
	"com":            {},
	"net":            {},
	"org":            {},
	"us":             {},
}

func getOrQueueASNRecord(ip string) (asnLookupRecord, asnLookupStatus) {
	now := time.Now()

	asnCacheMu.RLock()
	rec, ok := asnCache[ip]
	if ok && now.Sub(rec.updatedAt) <= asnCacheTTL {
		asnCacheMu.RUnlock()
		if rec.err != "" || len(rec.orgs) == 0 {
			return rec, asnLookupFailed
		}
		return rec, asnLookupResolved
	}
	asnCacheMu.RUnlock()

	asnCacheMu.Lock()
	if rec, ok = asnCache[ip]; ok && now.Sub(rec.updatedAt) <= asnCacheTTL {
		asnCacheMu.Unlock()
		if rec.err != "" || len(rec.orgs) == 0 {
			return rec, asnLookupFailed
		}
		return rec, asnLookupResolved
	}
	if !asnLookupActive[ip] {
		asnLookupActive[ip] = true
		select {
		case asnLookupSem <- struct{}{}:
			go func() {
				defer func() { <-asnLookupSem }()
				resolveASNInBackground(ip)
			}()
		default:
			// Too many concurrent lookups, skip this one
			delete(asnLookupActive, ip)
		}
	}
	asnCacheMu.Unlock()

	return asnLookupRecord{}, asnLookupPending
}

func resolveASNInBackground(ip string) {
	orgs, err := lookupASNOrgs(ip)

	rec := asnLookupRecord{
		orgs:      orgs,
		updatedAt: time.Now(),
	}
	if err != nil {
		rec.err = err.Error()
	}

	asnCacheMu.Lock()
	asnCache[ip] = rec
	delete(asnLookupActive, ip)
	asnCacheMu.Unlock()
}

func lookupASNOrgs(ipStr string) ([]string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, errors.New("invalid ip")
	}

	asns, err := lookupOriginASNs(ip)
	if err != nil {
		return nil, err
	}
	if len(asns) == 0 {
		return nil, errors.New("asn not found")
	}

	orgSet := make(map[string]struct{})
	for _, asn := range asns {
		org, orgErr := lookupASNOrg(asn)
		if orgErr != nil {
			org = "AS" + asn
		}
		org = strings.TrimSpace(org)
		if org != "" {
			orgSet[org] = struct{}{}
		}
	}
	if len(orgSet) == 0 {
		return nil, errors.New("org not found")
	}

	orgs := make([]string, 0, len(orgSet))
	for org := range orgSet {
		orgs = append(orgs, org)
	}
	sort.Strings(orgs)
	return orgs, nil
}

func lookupOriginASNs(ip net.IP) ([]string, error) {
	query := originQueryName(ip)
	if query == "" {
		return nil, errors.New("unsupported ip")
	}

	txts, err := lookupTXT(query)
	if err != nil {
		return nil, err
	}
	if len(txts) == 0 {
		return nil, errors.New("no origin txt")
	}

	seen := make(map[string]struct{})
	out := make([]string, 0, 2)
	for _, txt := range txts {
		parts := splitPipeFields(txt)
		if len(parts) == 0 {
			continue
		}
		for _, asn := range parseASNs(parts[0]) {
			if _, ok := seen[asn]; ok {
				continue
			}
			seen[asn] = struct{}{}
			out = append(out, asn)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("asn parse failed")
	}
	return out, nil
}

func lookupASNOrg(asn string) (string, error) {
	txts, err := lookupTXT("AS" + asn + ".asn.cymru.com")
	if err != nil {
		return "", err
	}
	for _, txt := range txts {
		parts := splitPipeFields(txt)
		if len(parts) >= 5 && strings.TrimSpace(parts[4]) != "" {
			return strings.TrimSpace(parts[4]), nil
		}
	}
	return "", errors.New("org parse failed")
}

func lookupTXT(name string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), asnDNSTimeout)
	defer cancel()

	r := net.Resolver{}
	return r.LookupTXT(ctx, name)
}

func originQueryName(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", v4[3], v4[2], v4[1], v4[0])
	}

	v6 := ip.To16()
	if v6 == nil {
		return ""
	}

	hex := fmt.Sprintf("%032x", v6)
	var b strings.Builder
	for i := len(hex) - 1; i >= 0; i-- {
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.WriteByte(hex[i])
	}
	b.WriteString(".origin6.asn.cymru.com")
	return b.String()
}

func splitPipeFields(s string) []string {
	raw := strings.Split(s, "|")
	out := make([]string, 0, len(raw))
	for _, part := range raw {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// IsCDNOrg returns true if the ASN organization name matches a known CDN provider.
func IsCDNOrg(org string) bool {
	org = strings.ToLower(strings.TrimSpace(org))
	cdnKeywords := []string{
		"cloudflare", "cloudfront", "fastly", "akamai", "edgecast",
		"limelight", "stackpath", "keycdn", "bunny", "cdn77",
		"azure front door", "azureedge", "google cloud cdn",
		"amazon cloudfront",
	}
	for _, kw := range cdnKeywords {
		if strings.Contains(org, kw) {
			return true
		}
	}
	return false
}

func parseASNs(field string) []string {
	field = strings.TrimSpace(field)
	if field == "" {
		return nil
	}

	seen := make(map[string]struct{})
	out := make([]string, 0, 2)
	for _, token := range strings.Fields(field) {
		token = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(token)), "AS")
		if token == "" {
			continue
		}
		valid := true
		for _, r := range token {
			if r < '0' || r > '9' {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		if _, ok := seen[token]; ok {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, token)
	}
	return out
}
