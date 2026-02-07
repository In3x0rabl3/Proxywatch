package ui

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"proxywatch/internal/shared"
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
)

func inspectorExternalOrgs(cand *shared.Candidate) (orgs []string, pending int, failed int) {
	if cand == nil {
		return nil, 0, 0
	}

	unique := make(map[string]struct{})
	for _, cn := range cand.Conns {
		ip := strings.TrimSpace(cn.RemoteAddress)
		if ip == "" || shared.IsWildcardIP(ip) || shared.IsLoopbackIP(ip) || shared.IsInternalIP(ip) {
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
		go resolveASNInBackground(ip)
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
			// Fallback keeps display useful even if org TXT lookup fails.
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

	return net.DefaultResolver.LookupTXT(ctx, name)
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
		b.WriteByte(hex[i])
		b.WriteByte('.')
	}
	b.WriteString("origin6.asn.cymru.com")
	return b.String()
}

func splitPipeFields(txt string) []string {
	raw := strings.Split(txt, "|")
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

func parseASNs(field string) []string {
	field = strings.TrimSpace(field)
	if field == "" {
		return nil
	}
	parts := strings.FieldsFunc(field, func(r rune) bool {
		return r == ' ' || r == ',' || r == ';' || r == '|'
	})

	seen := make(map[string]struct{})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(strings.TrimPrefix(strings.ToUpper(p), "AS"))
		if p == "" || p == "NA" {
			continue
		}
		valid := true
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}
