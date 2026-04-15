package shared

import "strings"

// PublisherDomains maps normalized publisher CN / Company strings to one or
// more canonical domain suffixes the vendor controls. Used by the
// publisher-DNS-alignment verifier to check whether a process's outbound
// destinations actually resolve inside the publisher's domain.
//
// Normalization (LookupPublisherDomains) lowercases, trims, and strips
// punctuation so "Microsoft Corporation", "Microsoft Corporation.", and
// "microsoft corporation" all match the same entry. Suffix match on the
// resolved PTR means an entry "microsoft.com" also matches
// "download.microsoft.com", "www.microsoft.com", etc.
//
// Curation policy:
//   - Prefer the organization's primary domain + any well-known product
//     domains that the signed binary is likely to talk to.
//   - Do NOT include generic CDN hostnames (cloudfront.net, akamai.net,
//     googleusercontent.com) — those are destination-hosting providers, not
//     publisher domains, and would lose the signal-vs-noise split.
//   - Keep it small. The goal is "top ~100 vendors we see" — grow by PR
//     when operators hit a gap.
var publisherDomainsRaw = map[string][]string{
	// Big platform vendors.
	"microsoft corporation":       {"microsoft.com", "windows.com", "office.com", "azure.com", "live.com", "msftncsi.com", "msftconnecttest.com"},
	"microsoft":                   {"microsoft.com", "windows.com", "office.com", "azure.com"},
	"microsoft windows":           {"microsoft.com", "windows.com"},
	"google llc":                  {"google.com", "googleapis.com", "gvt1.com", "gvt2.com", "googleusercontent.com", "youtube.com", "chrome.com"},
	"google inc":                  {"google.com", "googleapis.com"},
	"apple inc":                   {"apple.com", "icloud.com", "itunes.com", "mzstatic.com"},
	"apple":                       {"apple.com", "icloud.com"},
	"mozilla":                     {"mozilla.org", "mozilla.com", "mozilla.net", "firefox.com"},
	"mozilla corporation":         {"mozilla.org", "mozilla.com", "mozilla.net", "firefox.com"},

	// Browsers + browser-adjacent.
	"brave software inc":          {"brave.com"},
	"opera norway as":             {"opera.com"},
	"the chromium authors":        {"chromium.org", "google.com"},

	// Developer tooling + SaaS dev platforms.
	"github inc":                  {"github.com", "githubusercontent.com", "githubassets.com"},
	"gitlab inc":                  {"gitlab.com"},
	"jetbrains sro":               {"jetbrains.com"},
	"jetbrains":                   {"jetbrains.com"},
	"docker inc":                  {"docker.com", "docker.io"},
	"hashicorp inc":               {"hashicorp.com", "terraform.io", "consul.io", "vault.io"},
	"hashicorp":                   {"hashicorp.com"},
	"anthropic pbc":               {"anthropic.com", "claude.ai"},
	"anthropic":                   {"anthropic.com", "claude.ai"},
	"openai":                      {"openai.com", "chatgpt.com"},
	"openai inc":                  {"openai.com"},

	// Collaboration + productivity.
	"slack technologies llc":      {"slack.com"},
	"slack technologies inc":      {"slack.com"},
	"atlassian pty ltd":           {"atlassian.com", "jira.com"},
	"notion labs inc":              {"notion.so", "notion.site"},
	"linear orbit inc":            {"linear.app"},
	"figma inc":                    {"figma.com"},
	"zoom video communications":   {"zoom.us"},
	"microsoft teams":              {"microsoft.com", "office.com", "teams.microsoft.com"},
	"slack":                       {"slack.com"},

	// Security + compliance.
	"crowdstrike inc":             {"crowdstrike.com"},
	"sentinelone inc":             {"sentinelone.com"},
	"drata inc":                   {"drata.com"},
	"vanta inc":                   {"vanta.com"},
	"tanium inc":                  {"tanium.com"},
	"rapid7 inc":                  {"rapid7.com"},
	"tenable network security":   {"tenable.com"},
	"okta inc":                    {"okta.com"},
	"duo security":                {"duosecurity.com", "duo.com"},
	"1password":                   {"1password.com", "1passwordservices.com"},
	"agilebits inc":               {"1password.com"},
	"bitwarden inc":               {"bitwarden.com"},

	// Cloud + infra.
	"cloudflare inc":              {"cloudflare.com"},
	"cloudflare":                  {"cloudflare.com"},
	"amazon web services inc":    {"amazon.com", "amazonaws.com", "aws.amazon.com"},
	"amazoncom inc":               {"amazon.com", "amazonaws.com"},
	"datadog inc":                 {"datadoghq.com", "datadog.com"},
	"splunk inc":                  {"splunk.com"},
	"newrelic inc":                {"newrelic.com"},
	"elasticsearch bv":            {"elastic.co"},
	"elastic":                     {"elastic.co"},
	"mongodb inc":                 {"mongodb.com"},
	"hashi":                       {"hashicorp.com"},

	// VPN + network clients.
	"tailscale inc":               {"tailscale.com"},
	"wireguard llc":               {"wireguard.com"},
	"mullvad vpn ab":              {"mullvad.net"},
	"nordvpn sa":                  {"nordvpn.com"},
	"private internet access inc": {"privateinternetaccess.com"},
	"expressvpn":                  {"expressvpn.com"},

	// Communication + social.
	"discord inc":                 {"discord.com", "discordapp.com"},
	"signal messenger llc":        {"signal.org"},
	"telegram fz-llc":             {"telegram.org", "t.me"},
	"spotify ab":                  {"spotify.com"},

	// Payments + commerce SaaS.
	"stripe inc":                  {"stripe.com"},
	"twilio inc":                  {"twilio.com"},
	"vercel inc":                  {"vercel.com", "vercel-dns.com"},
	"netlify inc":                 {"netlify.com", "netlifyapp.com"},

	// Cloud sync + backup.
	"dropbox inc":                 {"dropbox.com", "dropboxusercontent.com"},
	"syncthing":                   {"syncthing.net"},
	"backblaze inc":               {"backblaze.com"},

	// Electron / Squirrel + auto-updaters rarely carry their own CN; covered
	// by the upstream app's publisher. Intentionally omitted here.

	// ── Linux-packaged vendor binaries ────────────────────────────────────
	// Keys here are BINARY NAMES (the dpkg/rpm package name as returned by
	// shared.LookupPackageOwner, which process_linux.go now writes into
	// Proc.Company). Windows PE metadata gives us "Microsoft Corporation";
	// Linux gives us "openssh-client", "gnome-software" — different shape,
	// same purpose: a stable identity the publisher-DNS-alignment verifier
	// can key off.
	"gnome-software":       {"flathub.org", "fedoraproject.org", "gnome.org", "fastly.net", "fastlylb.net"},
	"flatpak":              {"flathub.org", "fedoraproject.org"},
	"gnome-shell":          {"gnome.org", "mozilla.org"},
	"gjs":                  {"gnome.org"},
	"tracker-miner-fs":     {"gnome.org"},
	"tracker3":             {"gnome.org"},
	"evolution":            {"gnome.org"},
	"packagekit":           {"packagekit.org", "fedoraproject.org", "ubuntu.com", "debian.org"},
	"packagekitd":          {"packagekit.org", "fedoraproject.org", "ubuntu.com", "debian.org"},
	"snapd":                {"snapcraft.io", "ubuntu.com", "canonical.com"},
	"ubuntu-advantage-tools": {"ubuntu.com", "canonical.com"},
	"unattended-upgrades":  {"debian.org", "ubuntu.com"},
	"apt":                  {"debian.org", "ubuntu.com"},
	"fwupd":                {"fwupd.org", "lvfs.org"},
	"chrony":               {"ntp.org"},
	"systemd":              {"systemd.io", "freedesktop.org"},
	"networkmanager":       {"freedesktop.org", "gnome.org"},
	"avahi-daemon":         {"avahi.org"},

	// Cloud / SaaS daemons commonly showing up as long-lived control
	// sessions. Keys are the binary name from /usr/bin or equivalent.
	"docker.io":            {"docker.com", "docker.io"},
	"dockerd":              {"docker.com", "docker.io"},
	"containerd":           {"docker.com", "cncf.io"},
	"kubelet":              {"kubernetes.io", "k8s.io", "googleapis.com"},
	"kube-proxy":           {"kubernetes.io", "k8s.io"},
	"datadog-agent":        {"datadoghq.com", "datadog.com"},
	"dd-agent":             {"datadoghq.com"},
	"cloudflared":          {"cloudflare.com", "argotunnel.com"},
	"tailscaled":           {"tailscale.com"},
	"warp-svc":             {"cloudflare.com"},
	"osqueryd":             {"osquery.io"},
	"falcon-sensor":        {"crowdstrike.com"},
	"sentinelone":          {"sentinelone.com"},

	// Dev tools with background phone-home services.
	"code":                 {"visualstudio.com", "microsoft.com", "github.com", "vscode-unpkg.net", "gallerycdn.vsassets.io"},
	"code-insiders":        {"visualstudio.com", "microsoft.com"},
	"cursor":               {"cursor.com", "openai.com", "anthropic.com"},
	"firefox":              {"mozilla.org", "mozilla.net", "firefox.com"},
	"chromium":             {"chromium.org", "google.com", "gvt1.com", "gvt2.com"},
	"thunderbird":          {"mozilla.org", "mozilla.net"},

	// Windows Defender install tree — matches when Proc.Publisher =
	// "Microsoft Corporation" (which the Authenticode verifier extracts
	// for MpDefenderCoreService). Covered by the "microsoft corporation"
	// entry above but we also register the binary basename here so the
	// name-based fallback works in case Publisher lookup fails.
	"mpdefendercoreservice": {"microsoft.com", "windows.com"},
	"msmpeng":              {"microsoft.com", "windows.com"},
}

// LookupPublisherDomains returns the canonical domain suffixes for a
// publisher string, or nil if the publisher is unknown. Matching is
// lowercase + punctuation-insensitive so "Drata, Inc." and "Drata Inc."
// hit the same row.
func LookupPublisherDomains(publisher string) []string {
	key := normalizePublisher(publisher)
	if key == "" {
		return nil
	}
	if v, ok := publisherDomainsRaw[key]; ok {
		return v
	}
	// Fallback: try trimming a trailing "inc"/"llc"/"corporation" that the
	// raw map doesn't include explicitly.
	trimmed := trimLegalSuffixes(key)
	if trimmed != "" && trimmed != key {
		if v, ok := publisherDomainsRaw[trimmed]; ok {
			return v
		}
	}
	return nil
}

func normalizePublisher(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	// Drop punctuation that varies between "Drata, Inc." vs "Drata Inc.".
	s = strings.NewReplacer(",", "", ".", "", "(", "", ")", "").Replace(s)
	s = strings.Join(strings.Fields(s), " ")
	return s
}

func trimLegalSuffixes(s string) string {
	for _, suf := range []string{" corporation", " limited", " ltd", " inc", " llc", " sro", " pbc", " gmbh", " bv", " ag"} {
		if strings.HasSuffix(s, suf) {
			return strings.TrimSpace(strings.TrimSuffix(s, suf))
		}
	}
	return s
}
