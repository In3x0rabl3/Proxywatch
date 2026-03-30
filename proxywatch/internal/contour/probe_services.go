package contour

import (
	"context"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Service categories for egress channel classification.
const (
	SvcCatCloudStorage = "cloud-storage"
	SvcCatMessaging    = "messaging"
	SvcCatCodeHosting  = "code-hosting"
	SvcCatCDN          = "cdn"
	SvcCatDNSProvider  = "dns-provider"
	SvcCatPasteShare   = "paste-share"
	SvcCatCICD         = "ci-cd"
	SvcCatAPICloud     = "api-cloud"
	SvcCatTunnelVPN    = "tunnel-vpn"
	SvcCatContainerReg = "container-registry"
	SvcCatUnknown      = "unknown"
)

type serviceEntry struct {
	Name     string
	Category string
	Risk     string // "high", "medium", "low"
	Domains  []string
}

// knownServices maps domain suffixes to cloud/SaaS services. Reverse DNS
// results are matched against these entries to classify external traffic.
var knownServices = []serviceEntry{
	// Cloud storage — high exfil risk
	{Name: "Dropbox", Category: SvcCatCloudStorage, Risk: "high", Domains: []string{
		".dropbox.com", ".dropboxapi.com", ".dropbox-dns.com",
	}},
	{Name: "Google Drive", Category: SvcCatCloudStorage, Risk: "high", Domains: []string{
		".drive.google.com", ".docs.google.com", ".storage.googleapis.com",
	}},
	{Name: "OneDrive", Category: SvcCatCloudStorage, Risk: "high", Domains: []string{
		".onedrive.live.com", ".1drv.ms", ".sharepoint.com", ".storage.live.com",
	}},
	{Name: "AWS S3", Category: SvcCatCloudStorage, Risk: "high", Domains: []string{
		".s3.amazonaws.com", ".s3.us-east", ".s3.us-west", ".s3.eu-west",
		".s3.eu-central", ".s3.ap-southeast", ".s3.ap-northeast",
	}},
	{Name: "Azure Blob", Category: SvcCatCloudStorage, Risk: "high", Domains: []string{
		".blob.core.windows.net", ".file.core.windows.net",
	}},
	{Name: "GCS", Category: SvcCatCloudStorage, Risk: "high", Domains: []string{
		".storage.cloud.google.com",
	}},
	{Name: "Box", Category: SvcCatCloudStorage, Risk: "high", Domains: []string{
		".box.com", ".boxcloud.com",
	}},
	{Name: "Mega", Category: SvcCatCloudStorage, Risk: "high", Domains: []string{
		".mega.nz", ".mega.co.nz", ".mega.io",
	}},
	{Name: "WeTransfer", Category: SvcCatCloudStorage, Risk: "high", Domains: []string{
		".wetransfer.com",
	}},
	{Name: "pCloud", Category: SvcCatCloudStorage, Risk: "high", Domains: []string{
		".pcloud.com",
	}},
	{Name: "iCloud", Category: SvcCatCloudStorage, Risk: "medium", Domains: []string{
		".icloud.com", ".icloud-content.com",
	}},

	// Messaging — high exfil risk via file upload and webhooks
	{Name: "Slack", Category: SvcCatMessaging, Risk: "high", Domains: []string{
		".slack.com", ".slack-msgs.com", ".slack-edge.com", ".slack-imgs.com",
	}},
	{Name: "Discord", Category: SvcCatMessaging, Risk: "high", Domains: []string{
		".discord.com", ".discordapp.com", ".discord.gg", ".discord.media",
	}},
	{Name: "Telegram", Category: SvcCatMessaging, Risk: "high", Domains: []string{
		".telegram.org", ".t.me", ".telegra.ph", ".core.telegram.org",
	}},
	{Name: "Teams", Category: SvcCatMessaging, Risk: "medium", Domains: []string{
		".teams.microsoft.com", ".teams.cdn.office.net",
	}},
	{Name: "Signal", Category: SvcCatMessaging, Risk: "medium", Domains: []string{
		".signal.org", ".whispersystems.org",
	}},
	{Name: "WhatsApp", Category: SvcCatMessaging, Risk: "medium", Domains: []string{
		".whatsapp.com", ".whatsapp.net",
	}},
	{Name: "Keybase", Category: SvcCatMessaging, Risk: "medium", Domains: []string{
		".keybase.io", ".keybase.pub",
	}},
	{Name: "Matrix", Category: SvcCatMessaging, Risk: "medium", Domains: []string{
		".matrix.org", ".element.io",
	}},
	{Name: "Mattermost", Category: SvcCatMessaging, Risk: "medium", Domains: []string{
		".mattermost.com",
	}},
	{Name: "Zulip", Category: SvcCatMessaging, Risk: "medium", Domains: []string{
		".zulipchat.com", ".zulip.com",
	}},

	// Code hosting — high exfil risk via gists, repos, releases, APIs
	{Name: "GitHub", Category: SvcCatCodeHosting, Risk: "high", Domains: []string{
		".github.com", ".githubusercontent.com", ".github.io", ".githubassets.com", ".ghcr.io",
	}},
	{Name: "GitLab", Category: SvcCatCodeHosting, Risk: "high", Domains: []string{
		".gitlab.com", ".gitlab.io",
	}},
	{Name: "Bitbucket", Category: SvcCatCodeHosting, Risk: "high", Domains: []string{
		".bitbucket.org", ".bitbucket.io",
	}},
	{Name: "Codeberg", Category: SvcCatCodeHosting, Risk: "medium", Domains: []string{
		".codeberg.org",
	}},
	{Name: "SourceForge", Category: SvcCatCodeHosting, Risk: "medium", Domains: []string{
		".sourceforge.net",
	}},

	// Paste/file sharing — high exfil risk
	{Name: "Pastebin", Category: SvcCatPasteShare, Risk: "high", Domains: []string{
		".pastebin.com",
	}},
	{Name: "transfer.sh", Category: SvcCatPasteShare, Risk: "high", Domains: []string{
		"transfer.sh",
	}},
	{Name: "file.io", Category: SvcCatPasteShare, Risk: "high", Domains: []string{
		"file.io",
	}},
	{Name: "0x0.st", Category: SvcCatPasteShare, Risk: "high", Domains: []string{
		"0x0.st",
	}},
	{Name: "Hastebin", Category: SvcCatPasteShare, Risk: "high", Domains: []string{
		".hastebin.com", ".toptal.com",
	}},
	{Name: "dpaste", Category: SvcCatPasteShare, Risk: "medium", Domains: []string{
		".dpaste.com", ".dpaste.org",
	}},
	{Name: "Rentry", Category: SvcCatPasteShare, Risk: "medium", Domains: []string{
		"rentry.co", "rentry.org",
	}},

	// CDN — domain fronting risk
	{Name: "Cloudflare", Category: SvcCatCDN, Risk: "medium", Domains: []string{
		".cloudflare.com", ".cloudflare-dns.com", ".cloudflareclient.com",
	}},
	{Name: "Fastly", Category: SvcCatCDN, Risk: "medium", Domains: []string{
		".fastly.com", ".fastly.net", ".fastlylb.net",
	}},
	{Name: "Akamai", Category: SvcCatCDN, Risk: "medium", Domains: []string{
		".akamai.com", ".akamai.net", ".akamaized.net", ".akamaiedge.net",
	}},
	{Name: "CloudFront", Category: SvcCatCDN, Risk: "medium", Domains: []string{
		".cloudfront.net",
	}},
	{Name: "Azure CDN", Category: SvcCatCDN, Risk: "medium", Domains: []string{
		".azureedge.net", ".azurefd.net",
	}},
	{Name: "Google CDN", Category: SvcCatCDN, Risk: "medium", Domains: []string{
		".googlevideo.com", ".gstatic.com", ".googleusercontent.com",
	}},

	// DNS providers — DNS tunnel risk
	{Name: "Google DNS", Category: SvcCatDNSProvider, Risk: "low", Domains: []string{
		".dns.google", ".dns.google.com",
	}},
	{Name: "Cloudflare DNS", Category: SvcCatDNSProvider, Risk: "low", Domains: []string{
		".cloudflare-dns.com", ".one.one.one.one",
	}},
	{Name: "Quad9", Category: SvcCatDNSProvider, Risk: "low", Domains: []string{
		".quad9.net",
	}},
	{Name: "NextDNS", Category: SvcCatDNSProvider, Risk: "low", Domains: []string{
		".nextdns.io",
	}},

	// CI/CD — exfil via build artifacts and webhook triggers
	{Name: "CircleCI", Category: SvcCatCICD, Risk: "medium", Domains: []string{
		".circleci.com",
	}},
	{Name: "Travis CI", Category: SvcCatCICD, Risk: "medium", Domains: []string{
		".travis-ci.org", ".travis-ci.com",
	}},
	{Name: "GitHub Actions", Category: SvcCatCICD, Risk: "medium", Domains: []string{
		".actions.githubusercontent.com",
	}},
	{Name: "Buildkite", Category: SvcCatCICD, Risk: "medium", Domains: []string{
		".buildkite.com",
	}},

	// Tunnel/VPN services — high escape risk
	{Name: "ngrok", Category: SvcCatTunnelVPN, Risk: "high", Domains: []string{
		".ngrok.com", ".ngrok.io", ".ngrok-free.app",
	}},
	{Name: "Cloudflare Tunnel", Category: SvcCatTunnelVPN, Risk: "high", Domains: []string{
		".trycloudflare.com",
	}},
	{Name: "Tailscale", Category: SvcCatTunnelVPN, Risk: "medium", Domains: []string{
		".tailscale.com", ".ts.net",
	}},
	{Name: "ZeroTier", Category: SvcCatTunnelVPN, Risk: "medium", Domains: []string{
		".zerotier.com",
	}},
	{Name: "Bore", Category: SvcCatTunnelVPN, Risk: "high", Domains: []string{
		".bore.pub",
	}},
	{Name: "localhost.run", Category: SvcCatTunnelVPN, Risk: "high", Domains: []string{
		"localhost.run",
	}},
	{Name: "Serveo", Category: SvcCatTunnelVPN, Risk: "high", Domains: []string{
		"serveo.net",
	}},
	{Name: "Pagekite", Category: SvcCatTunnelVPN, Risk: "high", Domains: []string{
		".pagekite.me",
	}},

	// Container registries
	{Name: "Docker Hub", Category: SvcCatContainerReg, Risk: "medium", Domains: []string{
		".docker.com", ".docker.io",
	}},
	{Name: "Quay", Category: SvcCatContainerReg, Risk: "medium", Domains: []string{
		".quay.io",
	}},
	{Name: "GHCR", Category: SvcCatContainerReg, Risk: "medium", Domains: []string{
		".ghcr.io",
	}},

	// API/Cloud platforms
	{Name: "AWS", Category: SvcCatAPICloud, Risk: "medium", Domains: []string{
		".amazonaws.com", ".aws.amazon.com",
	}},
	{Name: "Azure", Category: SvcCatAPICloud, Risk: "medium", Domains: []string{
		".azure.com", ".windows.net", ".azure-api.net",
	}},
	{Name: "GCP", Category: SvcCatAPICloud, Risk: "medium", Domains: []string{
		".googleapis.com", ".cloud.google.com", ".run.app", ".appspot.com",
	}},
	{Name: "Heroku", Category: SvcCatAPICloud, Risk: "medium", Domains: []string{
		".herokuapp.com", ".heroku.com",
	}},
	{Name: "Vercel", Category: SvcCatAPICloud, Risk: "medium", Domains: []string{
		".vercel.app", ".vercel.com",
	}},
	{Name: "Netlify", Category: SvcCatAPICloud, Risk: "medium", Domains: []string{
		".netlify.app", ".netlify.com",
	}},
	{Name: "Render", Category: SvcCatAPICloud, Risk: "medium", Domains: []string{
		".render.com", ".onrender.com",
	}},
	{Name: "Railway", Category: SvcCatAPICloud, Risk: "medium", Domains: []string{
		".railway.app",
	}},
	{Name: "Fly.io", Category: SvcCatAPICloud, Risk: "medium", Domains: []string{
		".fly.dev", ".fly.io",
	}},
	{Name: "DigitalOcean", Category: SvcCatAPICloud, Risk: "medium", Domains: []string{
		".digitalocean.com", ".digitaloceanspaces.com",
	}},
	{Name: "Linode", Category: SvcCatAPICloud, Risk: "medium", Domains: []string{
		".linode.com", ".linodelb.com",
	}},
	{Name: "Vultr", Category: SvcCatAPICloud, Risk: "medium", Domains: []string{
		".vultr.com",
	}},
	{Name: "Oracle Cloud", Category: SvcCatAPICloud, Risk: "medium", Domains: []string{
		".oraclecloud.com", ".oraclecloudapps.com",
	}},
}

// Well-known DNS provider IPs — matched directly without reverse DNS.
var knownDNSProviderIPs = map[string]string{
	"8.8.8.8":         "Google DNS",
	"8.8.4.4":         "Google DNS",
	"1.1.1.1":         "Cloudflare DNS",
	"1.0.0.1":         "Cloudflare DNS",
	"9.9.9.9":         "Quad9",
	"149.112.112.112": "Quad9",
	"208.67.222.222":  "OpenDNS",
	"208.67.220.220":  "OpenDNS",
	"94.140.14.14":    "AdGuard DNS",
	"94.140.15.15":    "AdGuard DNS",
	"76.76.2.0":       "Control D",
	"76.76.10.0":      "Control D",
}

// ServiceMatch represents a classified external service.
type ServiceMatch struct {
	Name     string
	Category string
	Risk     string
}

// classifyServiceByDomain matches a hostname (typically from reverse DNS)
// against the known service database.
func classifyServiceByDomain(hostname string) (ServiceMatch, bool) {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	if hostname == "" {
		return ServiceMatch{}, false
	}
	for _, svc := range knownServices {
		for _, domain := range svc.Domains {
			domain = strings.ToLower(strings.TrimSpace(domain))
			if domain == "" {
				continue
			}
			if strings.HasPrefix(domain, ".") {
				if strings.HasSuffix(hostname, domain) || hostname == domain[1:] {
					return ServiceMatch{Name: svc.Name, Category: svc.Category, Risk: svc.Risk}, true
				}
			} else {
				if hostname == domain || strings.HasSuffix(hostname, "."+domain) {
					return ServiceMatch{Name: svc.Name, Category: svc.Category, Risk: svc.Risk}, true
				}
			}
		}
	}
	return ServiceMatch{}, false
}

// classifyServiceByIP checks well-known static IPs (e.g. public DNS resolvers).
func classifyServiceByIP(ip string) (ServiceMatch, bool) {
	ip = strings.TrimSpace(ip)
	if name, ok := knownDNSProviderIPs[ip]; ok {
		return ServiceMatch{Name: name, Category: SvcCatDNSProvider, Risk: "low"}, true
	}
	return ServiceMatch{}, false
}

// serviceResolution pairs an IP with its resolved service classification.
type serviceResolution struct {
	IP       string
	Hostname string
	Match    ServiceMatch
	Matched  bool
}

// resolveExternalServices performs reverse DNS lookups on external IPs and
// classifies them against the known service database. Runs concurrently with
// a per-lookup timeout and a global concurrency limit.
func resolveExternalServices(ctx context.Context, ips []string, perLookupTimeout time.Duration, maxLookups int) []serviceResolution {
	if ctx == nil {
		ctx = context.Background()
	}
	if perLookupTimeout <= 0 {
		perLookupTimeout = 400 * time.Millisecond
	}
	if maxLookups <= 0 {
		maxLookups = 80
	}

	unique := make([]string, 0, len(ips))
	seen := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		unique = append(unique, ip)
		if len(unique) >= maxLookups {
			break
		}
	}
	if len(unique) == 0 {
		return nil
	}

	results := make([]serviceResolution, len(unique))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20) // concurrency limiter

	for i, ip := range unique {
		results[i] = serviceResolution{IP: ip}

		// Direct IP match (e.g. 8.8.8.8 -> Google DNS).
		if match, ok := classifyServiceByIP(ip); ok {
			results[i].Match = match
			results[i].Matched = true
			continue
		}

		wg.Add(1)
		go func(idx int, addr string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			lookupCtx, cancel := context.WithTimeout(ctx, perLookupTimeout)
			defer cancel()

			resolver := &net.Resolver{}
			names, err := resolver.LookupAddr(lookupCtx, addr)
			if err != nil || len(names) == 0 {
				return
			}
			for _, name := range names {
				name = strings.TrimSuffix(strings.TrimSpace(name), ".")
				if name == "" {
					continue
				}
				results[idx].Hostname = name
				if match, ok := classifyServiceByDomain(name); ok {
					results[idx].Match = match
					results[idx].Matched = true
					return
				}
			}
		}(i, ip)
	}

	wg.Wait()
	return results
}

// serviceHit tracks connections to a particular cloud/SaaS service.
type serviceHit struct {
	Name     string
	Category string
	Risk     string
	Count    int
	IPs      map[string]struct{}
	Ports    map[int]struct{}
}

// serviceProfile aggregates service classification data for a candidate.
type serviceProfile struct {
	hits       map[string]*serviceHit // keyed by service name
	categories map[string]int         // category -> total connection count
	total      int                    // total classified connections
	highRisk   int                    // connections to high-risk services
}

func newServiceProfile() *serviceProfile {
	return &serviceProfile{
		hits:       make(map[string]*serviceHit),
		categories: make(map[string]int),
	}
}

func (sp *serviceProfile) add(ip string, port int, match ServiceMatch) {
	if sp == nil || match.Name == "" {
		return
	}
	hit, ok := sp.hits[match.Name]
	if !ok {
		hit = &serviceHit{
			Name:     match.Name,
			Category: match.Category,
			Risk:     match.Risk,
			IPs:      make(map[string]struct{}),
			Ports:    make(map[int]struct{}),
		}
		sp.hits[match.Name] = hit
	}
	hit.Count++
	hit.IPs[ip] = struct{}{}
	if port > 0 {
		hit.Ports[port] = struct{}{}
	}
	sp.categories[match.Category]++
	sp.total++
	if match.Risk == "high" {
		sp.highRisk++
	}
}

// sortedHits returns service hits sorted by count descending.
func (sp *serviceProfile) sortedHits() []*serviceHit {
	if sp == nil || len(sp.hits) == 0 {
		return nil
	}
	out := make([]*serviceHit, 0, len(sp.hits))
	for _, hit := range sp.hits {
		out = append(out, hit)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if riskRank(out[i].Risk) != riskRank(out[j].Risk) {
			return riskRank(out[i].Risk) > riskRank(out[j].Risk)
		}
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func riskRank(risk string) int {
	switch strings.ToLower(strings.TrimSpace(risk)) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// serviceCategoryLabel returns a human-readable label for a service category.
func serviceCategoryLabel(category string) string {
	switch category {
	case SvcCatCloudStorage:
		return "Cloud Storage"
	case SvcCatMessaging:
		return "Messaging"
	case SvcCatCodeHosting:
		return "Code Hosting"
	case SvcCatCDN:
		return "CDN"
	case SvcCatDNSProvider:
		return "DNS Provider"
	case SvcCatPasteShare:
		return "Paste/File Share"
	case SvcCatCICD:
		return "CI/CD"
	case SvcCatAPICloud:
		return "API/Cloud"
	case SvcCatTunnelVPN:
		return "Tunnel/VPN"
	case SvcCatContainerReg:
		return "Container Registry"
	default:
		return "Unknown"
	}
}

// exfilCapableCategory returns true for service categories that are commonly
// used as exfiltration channels.
func exfilCapableCategory(category string) bool {
	switch category {
	case SvcCatCloudStorage, SvcCatMessaging, SvcCatCodeHosting,
		SvcCatPasteShare, SvcCatContainerReg:
		return true
	default:
		return false
	}
}

// escapeCapableCategory returns true for service categories that facilitate
// network escape or tunneling.
func escapeCapableCategory(category string) bool {
	switch category {
	case SvcCatTunnelVPN, SvcCatCDN:
		return true
	default:
		return false
	}
}
