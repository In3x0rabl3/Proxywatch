package shared

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

// ServiceForPort returns the IANA service name registered for the
// given (port, proto) — or "" if none is known. Reads /etc/services
// on Linux/macOS once on first call and caches the result. Windows
// has no /etc/services, so a small embedded subset of common ports
// is used as the fallback.
//
// Used by the dashboard PROTO column to translate ports outside the
// hardcoded well-known set into a service name (e.g. 8009→ajp13,
// 9092→kafka, 11211→memcache). proto must be "tcp" or "udp"; case-
// insensitive on input.
//
// Thread-safe; may be called from any goroutine.
func ServiceForPort(port int, proto string) string {
	if port <= 0 {
		return ""
	}
	proto = strings.ToLower(strings.TrimSpace(proto))
	if proto != "tcp" && proto != "udp" {
		return ""
	}
	servicesOnce.Do(loadServices)
	servicesMu.RLock()
	defer servicesMu.RUnlock()
	if proto == "tcp" {
		return servicesTCP[port]
	}
	return servicesUDP[port]
}

var (
	servicesOnce sync.Once
	servicesMu   sync.RWMutex
	servicesTCP  = make(map[int]string)
	servicesUDP  = make(map[int]string)
)

// loadServices populates the servicesTCP / servicesUDP maps. Called
// once; subsequent ServiceForPort calls hit the cache directly.
func loadServices() {
	if runtime.GOOS == "windows" {
		loadServicesEmbedded()
		return
	}
	path := "/etc/services"
	f, err := os.Open(path)
	if err != nil {
		// File missing (rare on Linux/macOS, but possible in stripped
		// containers) — fall back to the embedded subset.
		loadServicesEmbedded()
		return
	}
	defer f.Close()

	servicesMu.Lock()
	defer servicesMu.Unlock()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		// fields[1] format: "port/proto" e.g. "443/tcp" or "53/udp"
		slash := strings.IndexByte(fields[1], '/')
		if slash <= 0 {
			continue
		}
		port, err := strconv.Atoi(fields[1][:slash])
		if err != nil || port <= 0 {
			continue
		}
		proto := strings.ToLower(fields[1][slash+1:])
		switch proto {
		case "tcp":
			if _, ok := servicesTCP[port]; !ok {
				servicesTCP[port] = name
			}
		case "udp":
			if _, ok := servicesUDP[port]; !ok {
				servicesUDP[port] = name
			}
		}
	}
}

// loadServicesEmbedded is the Windows / stripped-image fallback. Only
// covers ports that don't already overlap with the hardcoded
// wellKnownProtoName list in the dashboard — that list wins for its
// entries; this one fills in the gaps.
func loadServicesEmbedded() {
	servicesMu.Lock()
	defer servicesMu.Unlock()
	tcp := map[int]string{
		7:     "echo",
		9:     "discard",
		13:    "daytime",
		17:    "qotd",
		19:    "chargen",
		37:    "time",
		43:    "whois",
		49:    "tacacs",
		70:    "gopher",
		79:    "finger",
		88:    "kerberos",
		101:   "hostname",
		102:   "iso-tsap",
		107:   "rtelnet",
		109:   "pop2",
		113:   "ident",
		115:   "sftp",
		117:   "uucp-path",
		135:   "msrpc",
		220:   "imap3",
		264:   "bgmp",
		318:   "tsp",
		381:   "hp-collector",
		383:   "hp-managed-node",
		411:   "directconnect",
		427:   "svrloc",
		444:   "snpp",
		464:   "kpasswd",
		497:   "retrospect",
		500:   "isakmp",
		512:   "exec",
		513:   "login",
		515:   "printer",
		520:   "efs",
		524:   "ncp",
		540:   "uucp",
		543:   "klogin",
		544:   "kshell",
		546:   "dhcpv6-client",
		547:   "dhcpv6-server",
		554:   "rtsp",
		563:   "nntps",
		593:   "http-rpc-epmap",
		631:   "ipp",
		646:   "ldp",
		648:   "rrp",
		666:   "doom",
		674:   "acap",
		691:   "msexch-routing",
		860:   "iscsi",
		901:   "samba-swat",
		989:   "ftps-data",
		990:   "ftps",
		1025:  "blackjack",
		1026:  "calendar",
		1029:  "ms-lsa",
		1080:  "socks",
		1112:  "msql",
		1119:  "battlenet",
		1194:  "openvpn",
		1234:  "search-agent",
		1241:  "nessus",
		1311:  "rxmon",
		1337:  "menandmice-dns",
		1352:  "lotusnote",
		1387:  "cadsi-lm",
		1414:  "ibm-mq",
		1417:  "timbuktu-srv",
		1433:  "mssql-server",
		1434:  "mssql-monitor",
		1494:  "citrix-ica",
		1500:  "vlsi-lm",
		1503:  "netmeeting",
		1512:  "wins",
		1521:  "oracle",
		1524:  "ingres",
		1533:  "sametime",
		1547:  "laplink",
		1581:  "mil-2045-47001",
		1718:  "h225gatedisc",
		1720:  "h323hostcall",
		1731:  "msiccp",
		1741:  "ciscomgmt",
		1755:  "wms",
		1812:  "radius",
		1813:  "radius-acct",
		1863:  "msnp",
		1900:  "ssdp",
		1985:  "hsrp",
		2000:  "callbook",
		2002:  "globe",
		2049:  "nfs",
		2082:  "cpanel",
		2083:  "cpanel-ssl",
		2086:  "whm",
		2087:  "whm-ssl",
		2095:  "webmail",
		2096:  "webmail-ssl",
		2100:  "amiganetfs",
		2222:  "ssh-alt",
		2483:  "oracle-tns",
		2484:  "oracle-tns-ssl",
		2745:  "urbisnet",
		2967:  "symantec-av",
		3050:  "interbase",
		3074:  "xbox",
		3128:  "squid-http",
		3260:  "iscsi-target",
		3268:  "msft-gc",
		3269:  "msft-gc-ssl",
		3306:  "mysql",
		3389:  "rdp",
		3535:  "ms-la",
		3689:  "daap",
		3690:  "svn",
		3724:  "blizwow",
		3784:  "bfd-control",
		3785:  "bfd-echo",
		3868:  "diameter",
		3899:  "remote-admin",
		4333:  "msql",
		4444:  "krb524",
		4500:  "ipsec-nat",
		4664:  "google-desktop",
		4672:  "edonkey",
		4894:  "lyskom",
		5000:  "upnp",
		5001:  "iperf",
		5004:  "rtp",
		5005:  "rtcp",
		5050:  "yahoo-msg",
		5060:  "sip",
		5061:  "sip-tls",
		5093:  "sentinel",
		5104:  "ibm-app",
		5121:  "neverwinter",
		5190:  "icq-aim",
		5222:  "xmpp-client",
		5269:  "xmpp-server",
		5298:  "presence",
		5353:  "mdns",
		5355:  "llmnr",
		5432:  "postgresql",
		5500:  "vnc-srv",
		5631:  "pcanywhere",
		5632:  "pcanywhere-disc",
		5800:  "vnc-http",
		5900:  "vnc",
		5984:  "couchdb",
		5985:  "winrm",
		5986:  "winrm-ssl",
		6000:  "x11",
		6112:  "battlenet",
		6129:  "dameware",
		6257:  "winmx",
		6346:  "gnutella",
		6379:  "redis",
		6443:  "kubernetes-api",
		6500:  "boks",
		6660:  "irc",
		6661:  "irc",
		6662:  "irc",
		6663:  "irc",
		6664:  "irc",
		6665:  "irc",
		6666:  "irc",
		6667:  "irc",
		6668:  "irc",
		6669:  "irc",
		6679:  "irc-ssl",
		6697:  "irc-ssl",
		6881:  "bittorrent",
		6969:  "tracker",
		7001:  "weblogic",
		7212:  "ghostsurf",
		7474:  "neo4j",
		7777:  "cbt",
		8000:  "http-alt",
		8009:  "ajp13",
		8074:  "gadu-gadu",
		8080:  "http-proxy",
		8086:  "influxdb",
		8087:  "influxdb-admin",
		8181:  "intermapper",
		8222:  "vmware-mgmt",
		8443:  "https-alt",
		8500:  "consul",
		8888:  "http-alt",
		9000:  "cslistener",
		9043:  "websphere",
		9080:  "websphere-http",
		9090:  "websm",
		9092:  "kafka",
		9100:  "jetdirect",
		9101:  "bacula-dir",
		9102:  "bacula-fd",
		9103:  "bacula-sd",
		9119:  "mxit",
		9200:  "elasticsearch",
		9300:  "elastic-cluster",
		9418:  "git",
		9535:  "mansrv",
		9876:  "sd",
		9999:  "abyss",
		10000: "webmin",
		10050: "zabbix-agent",
		10051: "zabbix-server",
		11211: "memcache",
		11371: "openpgp-keyserver",
		12345: "netbus",
		13720: "bprd",
		13721: "bpdbm",
		13724: "vnetd",
		13782: "bpcd",
		13783: "vopied",
		15118: "dipnetlf",
		15672: "rabbitmq-mgmt",
		17500: "dropbox-lan",
		18091: "couchbase-mc",
		18092: "couchbase-mccouch",
		20000: "dnp",
		22136: "skype",
		24800: "synergy",
		25565: "minecraft",
		27015: "halflife",
		27017: "mongodb",
		28960: "callofduty",
		31337: "elite",
		32400: "plex",
		35357: "openstack-keystone",
		47808: "bacnet",
		49152: "dynamic",
		50000: "ibm-db2",
		51820: "wireguard",
		54321: "bo2k",
		60179: "battlenet",
	}
	udp := map[int]string{
		7:     "echo",
		9:     "discard",
		13:    "daytime",
		19:    "chargen",
		37:    "time",
		42:    "nameserver",
		43:    "whois",
		53:    "dns",
		67:    "dhcps",
		68:    "dhcpc",
		69:    "tftp",
		88:    "kerberos",
		111:   "rpcbind",
		123:   "ntp",
		137:   "netbios-ns",
		138:   "netbios-dgm",
		161:   "snmp",
		162:   "snmptrap",
		177:   "xdmcp",
		389:   "ldap",
		427:   "svrloc",
		443:   "https",
		445:   "smb",
		464:   "kpasswd",
		500:   "isakmp",
		514:   "syslog",
		520:   "rip",
		546:   "dhcpv6-client",
		547:   "dhcpv6-server",
		623:   "ipmi",
		1194:  "openvpn",
		1434:  "mssql-monitor",
		1645:  "radius",
		1646:  "radius-acct",
		1701:  "l2tp",
		1812:  "radius",
		1813:  "radius-acct",
		1900:  "ssdp",
		1985:  "hsrp",
		2049:  "nfs",
		3478:  "stun",
		3479:  "stun",
		3702:  "ws-discovery",
		4500:  "ipsec-nat",
		5060:  "sip",
		5061:  "sip-tls",
		5353:  "mdns",
		5355:  "llmnr",
		5683:  "coap",
		6343:  "sflow",
		6481:  "servicetags",
		33434: "traceroute",
		47808: "bacnet",
		51820: "wireguard",
	}
	servicesTCP = tcp
	servicesUDP = udp
}
