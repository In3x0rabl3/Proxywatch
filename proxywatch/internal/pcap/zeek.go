package pcap

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"proxywatch/internal/detection"
	"proxywatch/internal/shared"
)

// ZeekConn represents a single entry from Zeek's conn.log.
type ZeekConn struct {
	TS          time.Time
	UID         string
	OrigH       string
	OrigP       int
	RespH       string
	RespP       int
	Proto       string
	Service     string
	Duration    float64
	OrigBytes   int64
	RespBytes   int64
	ConnState   string
	LocalOrig   bool
	LocalResp   bool
	History     string
	OrigPkts    int64
	OrigIPBytes int64
	RespPkts    int64
	RespIPBytes int64
	TunnelP     string
	Label       string
	LineNum     uint64 // Line number in conn.log (used as synthetic frame ID)
}

// ZeekDNS represents a single entry from Zeek's dns.log.
type ZeekDNS struct {
	TS       time.Time
	UID      string
	OrigH    string
	OrigP    int
	RespH    string
	RespP    int
	Proto    string
	TransID  int
	RTT      float64
	Query    string
	QClass   int
	QType    string
	RCode    int
	AA       bool
	TC       bool
	RD       bool
	RA       bool
	Z        int
	Answers  []string
	TTLs     []float64
	Rejected bool
}

// ZeekSSL represents a single entry from Zeek's ssl.log.
type ZeekSSL struct {
	TS              time.Time
	UID             string
	OrigH           string
	OrigP           int
	RespH           string
	RespP           int
	Version         string
	Cipher          string
	Curve           string
	ServerName      string
	Resumed         bool
	NextProto       string
	Established     bool
	Subject         string
	Issuer          string
	NotValidBefore  time.Time
	NotValidAfter   time.Time
	JA3             string
	JA3S            string
	CertChainFUIDs  []string
	ClientCertChain []string
}

// ZeekHTTP represents a single entry from Zeek's http.log.
type ZeekHTTP struct {
	TS          time.Time
	UID         string
	OrigH       string
	OrigP       int
	RespH       string
	RespP       int
	TransDepth  int
	Method      string
	Host        string
	URI         string
	Referrer    string
	Version     string
	UserAgent   string
	Origin      string
	ReqBodyLen  int64
	RespBodyLen int64
	StatusCode  int
	StatusMsg   string
	InfoCode    int
	InfoMsg     string
	Tags        []string
	Username    string
	Password    string
	MIMETypes   []string
	Filename    string
	RespFUIDs   []string
}

// ZeekX509 represents a single entry from Zeek's x509.log.
type ZeekX509 struct {
	TS               time.Time
	ID               string
	CertVersion      int
	Serial           string
	Subject          string
	Issuer           string
	NotValidBefore   time.Time
	NotValidAfter    time.Time
	KeyAlg           string
	SigAlg           string
	KeyType          string
	KeyLength        int
	ExponentStr      string
	Curve            string
	SAN_DNS          []string
	SAN_URI          []string
	SAN_Email        []string
	SAN_IP           []string
	BasicConstraints bool
	CAFlag           bool
}

// ZeekLogs holds parsed Zeek log data from a directory.
type ZeekLogs struct {
	Conns     []ZeekConn
	DNS       []ZeekDNS
	SSL       []ZeekSSL
	HTTP      []ZeekHTTP
	X509      []ZeekX509
	LocalIPs  []string
	StartTime time.Time
	EndTime   time.Time
}

// ParseZeekPath parses Zeek logs from a file or directory.
// Accepts:
// - A directory containing conn.log
// - A conn.log file directly
// - Any .log file (uses parent directory to find conn.log)
func ParseZeekPath(ctx context.Context, path string) (*ZeekLogs, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot access %s: %w", path, err)
	}

	if info.IsDir() {
		return ParseZeekDir(ctx, path)
	}

	// It's a file - use its parent directory
	dir := filepath.Dir(path)
	return ParseZeekDir(ctx, dir)
}

// ParseZeekDir parses all Zeek logs in a directory.
func ParseZeekDir(ctx context.Context, dir string) (*ZeekLogs, error) {
	logs := &ZeekLogs{}

	// Parse conn.log (required)
	connPath := filepath.Join(dir, "conn.log")
	if _, err := os.Stat(connPath); err != nil {
		// Try gzipped version
		connPath = filepath.Join(dir, "conn.log.gz")
		if _, err := os.Stat(connPath); err != nil {
			return nil, fmt.Errorf("conn.log not found in %s (required for Zeek analysis)", dir)
		}
	}

	conns, err := parseConnLog(ctx, connPath)
	if err != nil {
		return nil, fmt.Errorf("parsing conn.log: %w", err)
	}
	logs.Conns = conns

	// Parse optional logs
	if dnsPath := findZeekLog(dir, "dns.log"); dnsPath != "" {
		dns, err := parseDNSLog(ctx, dnsPath)
		if err == nil {
			logs.DNS = dns
		}
	}

	if sslPath := findZeekLog(dir, "ssl.log"); sslPath != "" {
		ssl, err := parseSSLLog(ctx, sslPath)
		if err == nil {
			logs.SSL = ssl
		}
	}

	if httpPath := findZeekLog(dir, "http.log"); httpPath != "" {
		http, err := parseHTTPLog(ctx, httpPath)
		if err == nil {
			logs.HTTP = http
		}
	}

	if x509Path := findZeekLog(dir, "x509.log"); x509Path != "" {
		x509, err := parseX509Log(ctx, x509Path)
		if err == nil {
			logs.X509 = x509
		}
	}

	// Derive local IPs and time range from conn.log
	logs.LocalIPs, logs.StartTime, logs.EndTime = analyzeConns(conns)

	return logs, nil
}

func findZeekLog(dir, name string) string {
	path := filepath.Join(dir, name)
	if _, err := os.Stat(path); err == nil {
		return path
	}
	gzPath := path + ".gz"
	if _, err := os.Stat(gzPath); err == nil {
		return gzPath
	}
	return ""
}

// parseConnLog parses Zeek's conn.log file.
func parseConnLog(ctx context.Context, path string) ([]ZeekConn, error) {
	f, err := openZeekLog(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var conns []ZeekConn
	fields, scanner := zeekScanner(f)
	if fields == nil {
		return nil, fmt.Errorf("no fields header in conn.log")
	}

	fieldIdx := makeFieldIndex(fields)
	var lineNum uint64
	for scanner.Scan() {
		lineNum++
		if ctx != nil {
			if err := ctx.Err(); err != nil {
				return conns, err
			}
		}

		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, "\t")
		conn := ZeekConn{LineNum: lineNum}

		if idx, ok := fieldIdx["ts"]; ok && idx < len(parts) {
			conn.TS = parseZeekTime(parts[idx])
		}
		if idx, ok := fieldIdx["uid"]; ok && idx < len(parts) {
			conn.UID = parts[idx]
		}
		if idx, ok := fieldIdx["id.orig_h"]; ok && idx < len(parts) {
			conn.OrigH = parts[idx]
		}
		if idx, ok := fieldIdx["id.orig_p"]; ok && idx < len(parts) {
			conn.OrigP = parseInt(parts[idx])
		}
		if idx, ok := fieldIdx["id.resp_h"]; ok && idx < len(parts) {
			conn.RespH = parts[idx]
		}
		if idx, ok := fieldIdx["id.resp_p"]; ok && idx < len(parts) {
			conn.RespP = parseInt(parts[idx])
		}
		if idx, ok := fieldIdx["proto"]; ok && idx < len(parts) {
			conn.Proto = parts[idx]
		}
		if idx, ok := fieldIdx["service"]; ok && idx < len(parts) {
			conn.Service = parts[idx]
		}
		if idx, ok := fieldIdx["duration"]; ok && idx < len(parts) {
			conn.Duration = parseFloat(parts[idx])
		}
		if idx, ok := fieldIdx["orig_bytes"]; ok && idx < len(parts) {
			conn.OrigBytes = parseInt64(parts[idx])
		}
		if idx, ok := fieldIdx["resp_bytes"]; ok && idx < len(parts) {
			conn.RespBytes = parseInt64(parts[idx])
		}
		if idx, ok := fieldIdx["conn_state"]; ok && idx < len(parts) {
			conn.ConnState = parts[idx]
		}
		if idx, ok := fieldIdx["local_orig"]; ok && idx < len(parts) {
			conn.LocalOrig = parts[idx] == "T"
		}
		if idx, ok := fieldIdx["local_resp"]; ok && idx < len(parts) {
			conn.LocalResp = parts[idx] == "T"
		}
		if idx, ok := fieldIdx["history"]; ok && idx < len(parts) {
			conn.History = parts[idx]
		}
		if idx, ok := fieldIdx["orig_pkts"]; ok && idx < len(parts) {
			conn.OrigPkts = parseInt64(parts[idx])
		}
		if idx, ok := fieldIdx["orig_ip_bytes"]; ok && idx < len(parts) {
			conn.OrigIPBytes = parseInt64(parts[idx])
		}
		if idx, ok := fieldIdx["resp_pkts"]; ok && idx < len(parts) {
			conn.RespPkts = parseInt64(parts[idx])
		}
		if idx, ok := fieldIdx["resp_ip_bytes"]; ok && idx < len(parts) {
			conn.RespIPBytes = parseInt64(parts[idx])
		}

		if conn.OrigH != "" && conn.RespH != "" {
			conns = append(conns, conn)
		}
	}

	return conns, scanner.Err()
}

// parseDNSLog parses Zeek's dns.log file.
func parseDNSLog(ctx context.Context, path string) ([]ZeekDNS, error) {
	f, err := openZeekLog(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var records []ZeekDNS
	fields, scanner := zeekScanner(f)
	if fields == nil {
		return nil, fmt.Errorf("no fields header in dns.log")
	}

	fieldIdx := makeFieldIndex(fields)
	for scanner.Scan() {
		if ctx != nil {
			if err := ctx.Err(); err != nil {
				return records, err
			}
		}

		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, "\t")
		rec := ZeekDNS{}

		if idx, ok := fieldIdx["ts"]; ok && idx < len(parts) {
			rec.TS = parseZeekTime(parts[idx])
		}
		if idx, ok := fieldIdx["uid"]; ok && idx < len(parts) {
			rec.UID = parts[idx]
		}
		if idx, ok := fieldIdx["id.orig_h"]; ok && idx < len(parts) {
			rec.OrigH = parts[idx]
		}
		if idx, ok := fieldIdx["id.orig_p"]; ok && idx < len(parts) {
			rec.OrigP = parseInt(parts[idx])
		}
		if idx, ok := fieldIdx["id.resp_h"]; ok && idx < len(parts) {
			rec.RespH = parts[idx]
		}
		if idx, ok := fieldIdx["id.resp_p"]; ok && idx < len(parts) {
			rec.RespP = parseInt(parts[idx])
		}
		if idx, ok := fieldIdx["proto"]; ok && idx < len(parts) {
			rec.Proto = parts[idx]
		}
		if idx, ok := fieldIdx["query"]; ok && idx < len(parts) {
			rec.Query = parts[idx]
		}
		if idx, ok := fieldIdx["qtype_name"]; ok && idx < len(parts) {
			rec.QType = parts[idx]
		}
		if idx, ok := fieldIdx["rcode"]; ok && idx < len(parts) {
			rec.RCode = parseInt(parts[idx])
		}
		if idx, ok := fieldIdx["answers"]; ok && idx < len(parts) {
			rec.Answers = parseZeekSet(parts[idx])
		}
		if idx, ok := fieldIdx["TTLs"]; ok && idx < len(parts) {
			for _, ttl := range parseZeekSet(parts[idx]) {
				rec.TTLs = append(rec.TTLs, parseFloat(ttl))
			}
		}

		records = append(records, rec)
	}

	return records, scanner.Err()
}

// parseSSLLog parses Zeek's ssl.log file.
func parseSSLLog(ctx context.Context, path string) ([]ZeekSSL, error) {
	f, err := openZeekLog(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var records []ZeekSSL
	fields, scanner := zeekScanner(f)
	if fields == nil {
		return nil, fmt.Errorf("no fields header in ssl.log")
	}

	fieldIdx := makeFieldIndex(fields)
	for scanner.Scan() {
		if ctx != nil {
			if err := ctx.Err(); err != nil {
				return records, err
			}
		}

		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, "\t")
		rec := ZeekSSL{}

		if idx, ok := fieldIdx["ts"]; ok && idx < len(parts) {
			rec.TS = parseZeekTime(parts[idx])
		}
		if idx, ok := fieldIdx["uid"]; ok && idx < len(parts) {
			rec.UID = parts[idx]
		}
		if idx, ok := fieldIdx["id.orig_h"]; ok && idx < len(parts) {
			rec.OrigH = parts[idx]
		}
		if idx, ok := fieldIdx["id.orig_p"]; ok && idx < len(parts) {
			rec.OrigP = parseInt(parts[idx])
		}
		if idx, ok := fieldIdx["id.resp_h"]; ok && idx < len(parts) {
			rec.RespH = parts[idx]
		}
		if idx, ok := fieldIdx["id.resp_p"]; ok && idx < len(parts) {
			rec.RespP = parseInt(parts[idx])
		}
		if idx, ok := fieldIdx["version"]; ok && idx < len(parts) {
			rec.Version = parts[idx]
		}
		if idx, ok := fieldIdx["cipher"]; ok && idx < len(parts) {
			rec.Cipher = parts[idx]
		}
		if idx, ok := fieldIdx["server_name"]; ok && idx < len(parts) {
			rec.ServerName = parts[idx]
		}
		if idx, ok := fieldIdx["established"]; ok && idx < len(parts) {
			rec.Established = parts[idx] == "T"
		}
		if idx, ok := fieldIdx["subject"]; ok && idx < len(parts) {
			rec.Subject = parts[idx]
		}
		if idx, ok := fieldIdx["issuer"]; ok && idx < len(parts) {
			rec.Issuer = parts[idx]
		}
		if idx, ok := fieldIdx["ja3"]; ok && idx < len(parts) {
			rec.JA3 = parts[idx]
		}
		if idx, ok := fieldIdx["ja3s"]; ok && idx < len(parts) {
			rec.JA3S = parts[idx]
		}

		records = append(records, rec)
	}

	return records, scanner.Err()
}

// parseHTTPLog parses Zeek's http.log file.
func parseHTTPLog(ctx context.Context, path string) ([]ZeekHTTP, error) {
	f, err := openZeekLog(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var records []ZeekHTTP
	fields, scanner := zeekScanner(f)
	if fields == nil {
		return nil, fmt.Errorf("no fields header in http.log")
	}

	fieldIdx := makeFieldIndex(fields)
	for scanner.Scan() {
		if ctx != nil {
			if err := ctx.Err(); err != nil {
				return records, err
			}
		}

		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, "\t")
		rec := ZeekHTTP{}

		if idx, ok := fieldIdx["ts"]; ok && idx < len(parts) {
			rec.TS = parseZeekTime(parts[idx])
		}
		if idx, ok := fieldIdx["uid"]; ok && idx < len(parts) {
			rec.UID = parts[idx]
		}
		if idx, ok := fieldIdx["id.orig_h"]; ok && idx < len(parts) {
			rec.OrigH = parts[idx]
		}
		if idx, ok := fieldIdx["id.orig_p"]; ok && idx < len(parts) {
			rec.OrigP = parseInt(parts[idx])
		}
		if idx, ok := fieldIdx["id.resp_h"]; ok && idx < len(parts) {
			rec.RespH = parts[idx]
		}
		if idx, ok := fieldIdx["id.resp_p"]; ok && idx < len(parts) {
			rec.RespP = parseInt(parts[idx])
		}
		if idx, ok := fieldIdx["method"]; ok && idx < len(parts) {
			rec.Method = parts[idx]
		}
		if idx, ok := fieldIdx["host"]; ok && idx < len(parts) {
			rec.Host = parts[idx]
		}
		if idx, ok := fieldIdx["uri"]; ok && idx < len(parts) {
			rec.URI = parts[idx]
		}
		if idx, ok := fieldIdx["user_agent"]; ok && idx < len(parts) {
			rec.UserAgent = parts[idx]
		}
		if idx, ok := fieldIdx["status_code"]; ok && idx < len(parts) {
			rec.StatusCode = parseInt(parts[idx])
		}
		if idx, ok := fieldIdx["status_msg"]; ok && idx < len(parts) {
			rec.StatusMsg = parts[idx]
		}
		if idx, ok := fieldIdx["request_body_len"]; ok && idx < len(parts) {
			rec.ReqBodyLen = parseInt64(parts[idx])
		}
		if idx, ok := fieldIdx["response_body_len"]; ok && idx < len(parts) {
			rec.RespBodyLen = parseInt64(parts[idx])
		}
		if idx, ok := fieldIdx["mime_types"]; ok && idx < len(parts) {
			rec.MIMETypes = parseZeekSet(parts[idx])
		}

		records = append(records, rec)
	}

	return records, scanner.Err()
}

// parseX509Log parses Zeek's x509.log file.
func parseX509Log(ctx context.Context, path string) ([]ZeekX509, error) {
	f, err := openZeekLog(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var records []ZeekX509
	fields, scanner := zeekScanner(f)
	if fields == nil {
		return nil, fmt.Errorf("no fields header in x509.log")
	}

	fieldIdx := makeFieldIndex(fields)
	for scanner.Scan() {
		if ctx != nil {
			if err := ctx.Err(); err != nil {
				return records, err
			}
		}

		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, "\t")
		rec := ZeekX509{}

		if idx, ok := fieldIdx["ts"]; ok && idx < len(parts) {
			rec.TS = parseZeekTime(parts[idx])
		}
		if idx, ok := fieldIdx["id"]; ok && idx < len(parts) {
			rec.ID = parts[idx]
		}
		if idx, ok := fieldIdx["certificate.subject"]; ok && idx < len(parts) {
			rec.Subject = parts[idx]
		}
		if idx, ok := fieldIdx["certificate.issuer"]; ok && idx < len(parts) {
			rec.Issuer = parts[idx]
		}
		if idx, ok := fieldIdx["certificate.key_alg"]; ok && idx < len(parts) {
			rec.KeyAlg = parts[idx]
		}
		if idx, ok := fieldIdx["certificate.sig_alg"]; ok && idx < len(parts) {
			rec.SigAlg = parts[idx]
		}
		if idx, ok := fieldIdx["san.dns"]; ok && idx < len(parts) {
			rec.SAN_DNS = parseZeekSet(parts[idx])
		}
		if idx, ok := fieldIdx["san.ip"]; ok && idx < len(parts) {
			rec.SAN_IP = parseZeekSet(parts[idx])
		}

		records = append(records, rec)
	}

	return records, scanner.Err()
}

// Helper functions for parsing Zeek logs.

func openZeekLog(path string) (io.ReadCloser, error) {
	if strings.HasSuffix(path, ".gz") {
		return openGzipFile(path)
	}
	return os.Open(path)
}

func openGzipFile(path string) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	// Note: For real implementation, use compress/gzip
	// For now, return the file as-is and handle gzip elsewhere
	return f, nil
}

func zeekScanner(r io.Reader) ([]string, *bufio.Scanner) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024)

	var fields []string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#fields") {
			fields = strings.Split(strings.TrimPrefix(line, "#fields\t"), "\t")
			break
		}
	}

	return fields, scanner
}

func makeFieldIndex(fields []string) map[string]int {
	idx := make(map[string]int, len(fields))
	for i, f := range fields {
		idx[f] = i
	}
	return idx
}

func parseZeekTime(s string) time.Time {
	if s == "-" || s == "" {
		return time.Time{}
	}
	// Zeek uses epoch seconds with decimal microseconds
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return time.Time{}
	}
	sec := int64(f)
	nsec := int64((f - float64(sec)) * 1e9)
	return time.Unix(sec, nsec)
}

func parseInt(s string) int {
	if s == "-" || s == "" {
		return 0
	}
	v, _ := strconv.Atoi(s)
	return v
}

func parseInt64(s string) int64 {
	if s == "-" || s == "" {
		return 0
	}
	v, _ := strconv.ParseInt(s, 10, 64)
	return v
}

func parseFloat(s string) float64 {
	if s == "-" || s == "" {
		return 0
	}
	v, _ := strconv.ParseFloat(s, 64)
	return v
}

func parseZeekSet(s string) []string {
	if s == "-" || s == "(empty)" || s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// analyzeConns extracts local IPs and time range from connections.
func analyzeConns(conns []ZeekConn) ([]string, time.Time, time.Time) {
	localSet := make(map[string]struct{})
	var minTime, maxTime time.Time

	for _, c := range conns {
		if !c.TS.IsZero() {
			if minTime.IsZero() || c.TS.Before(minTime) {
				minTime = c.TS
			}
			if maxTime.IsZero() || c.TS.After(maxTime) {
				maxTime = c.TS
			}
		}

		// Use Zeek's local_orig/local_resp flags if available
		if c.LocalOrig {
			localSet[c.OrigH] = struct{}{}
		}
		if c.LocalResp {
			localSet[c.RespH] = struct{}{}
		}

		// Fallback: use RFC1918 detection
		if len(localSet) == 0 {
			if shared.IsInternalIP(c.OrigH) && !shared.IsInternalIP(c.RespH) {
				localSet[c.OrigH] = struct{}{}
			} else if shared.IsInternalIP(c.RespH) && !shared.IsInternalIP(c.OrigH) {
				localSet[c.RespH] = struct{}{}
			}
		}
	}

	// Convert set to sorted slice
	localIPs := make([]string, 0, len(localSet))
	for ip := range localSet {
		localIPs = append(localIPs, ip)
	}
	sort.Strings(localIPs)

	return localIPs, minTime, maxTime
}

// ConvertToFlows converts Zeek logs to the internal flow representation
// compatible with the existing PCAP analysis pipeline.
func (z *ZeekLogs) ConvertToFlows() (map[flowKey]*flowState, map[string][]string) {
	flows := make(map[flowKey]*flowState, len(z.Conns))
	dnsByHost := make(map[string][]string)

	// Build UID to SSL/HTTP lookup maps
	sslByUID := make(map[string]*ZeekSSL, len(z.SSL))
	for i := range z.SSL {
		sslByUID[z.SSL[i].UID] = &z.SSL[i]
	}

	httpByUID := make(map[string]*ZeekHTTP, len(z.HTTP))
	for i := range z.HTTP {
		httpByUID[z.HTTP[i].UID] = &z.HTTP[i]
	}

	// Build DNS response map (query -> IPs)
	for _, d := range z.DNS {
		if len(d.Answers) > 0 {
			for _, ans := range d.Answers {
				if net.ParseIP(ans) != nil {
					dnsByHost[d.Query] = append(dnsByHost[d.Query], ans)
				}
			}
		}
	}

	// Convert connections
	for _, c := range z.Conns {
		if c.Proto != "tcp" && c.Proto != "udp" {
			continue
		}

		key := flowKey{
			InitIP:   c.OrigH,
			InitPort: c.OrigP,
			RespIP:   c.RespH,
			RespPort: c.RespP,
		}

		endTime := c.TS
		if c.Duration > 0 {
			endTime = c.TS.Add(time.Duration(c.Duration * float64(time.Second)))
		}

		st := &flowState{
			key:             key,
			firstPacket:     c.TS,
			lastPacket:      endTime,
			firstFrameNum:   c.LineNum, // Use conn.log line number as synthetic frame ID
			synSeen:         strings.Contains(c.History, "S"),
			synAckSeen:      strings.Contains(c.History, "s"),
			finSeen:         strings.Contains(c.History, "F") || strings.Contains(c.History, "f"),
			rstSeen:         strings.Contains(c.History, "R") || strings.Contains(c.History, "r"),
			bytesInitToResp: uint64(c.OrigBytes),
			bytesRespToInit: uint64(c.RespBytes),
			packetsTotal:    int(c.OrigPkts + c.RespPkts),
		}

		// Enrich with SSL data
		if ssl, ok := sslByUID[c.UID]; ok {
			st.tlsJA3 = ssl.JA3
			st.tlsJA3S = ssl.JA3S
			st.tlsSNI = ssl.ServerName
		}

		// Enrich with HTTP data
		if http, ok := httpByUID[c.UID]; ok {
			st.httpURI = http.URI
			st.httpHost = http.Host
			st.httpUserAgent = http.UserAgent
			if http.StatusCode > 0 {
				st.httpRespStatus = http.StatusCode
			}
		}

		flows[key] = st
	}

	return flows, dnsByHost
}

// IngestZeek processes Zeek logs and returns results compatible with PCAP analysis.
// Accepts a directory containing conn.log, a conn.log file, or any .log file
// (uses the parent directory to find conn.log).
func IngestZeek(ctx context.Context, path string) IngestResult {
	return IngestZeekWithProgress(ctx, path, nil)
}

// IngestZeekWithProgress is the channel-aware variant for UI progress updates.
// Accepts a directory containing conn.log, a conn.log file, or any .log file
// (uses the parent directory to find conn.log).
func IngestZeekWithProgress(ctx context.Context, path string, progressCh chan<- IngestProgress) IngestResult {
	shared.PcapModeActive.Store(true)
	defer shared.PcapModeActive.Store(false)

	result := IngestResult{Path: path}

	send := func(p IngestProgress) {
		if progressCh == nil {
			return
		}
		select {
		case progressCh <- p:
		default:
		}
	}
	send(IngestProgress{Stage: "parsing"})

	logs, err := ParseZeekPath(ctx, path)
	if err != nil {
		result.Err = err
		send(IngestProgress{Stage: "error"})
		return result
	}

	result.PcapStart = logs.StartTime
	result.PcapEnd = logs.EndTime
	result.LocalIPs = logs.LocalIPs
	result.FlowsTotal = len(logs.Conns)

	if len(logs.Conns) == 0 {
		send(IngestProgress{Stage: "done"})
		return result
	}

	// Convert to internal flow format
	flows, dnsByHost := logs.ConvertToFlows()
	_ = dnsByHost // DNS enrichment available for later use

	// Apply the same time shift as PCAP ingestion
	shift := time.Now().Sub(logs.StartTime)
	for _, st := range flows {
		st.firstPacket = st.firstPacket.Add(shift)
		st.lastPacket = st.lastPacket.Add(shift)
	}

	shiftedStart := logs.StartTime.Add(shift)
	shiftedEnd := logs.EndTime.Add(shift)
	shared.PcapClockNanos.Store(shiftedEnd.UnixNano())
	defer shared.PcapClockNanos.Store(0)

	// Assign synthetic PIDs
	pidByIP := assignSyntheticPIDs(logs.LocalIPs)
	attr := buildPcapAttribution(sortFlowsForReplay(flows), logs.LocalIPs)
	for _, pid := range attr.allPIDs {
		result.SyntheticPIDs = append(result.SyntheticPIDs, pid)
	}
	sort.Ints(result.SyntheticPIDs)

	// Reset and cleanup synthetic PID state
	resetSyntheticPIDState(result.SyntheticPIDs)
	defer cleanupSyntheticPIDState(result.SyntheticPIDs)

	// Prime ProxywatchStartedAt
	prevStartedAt := shared.ProxywatchStartedAt
	shared.ProxywatchStartedAt = shiftedStart.Add(-10 * shared.StartupGracePeriod)
	defer func() { shared.ProxywatchStartedAt = prevStartedAt }()

	// Initialize result maps
	result.PacketsByPID = make(map[int]uint64, len(pidByIP))
	result.FlowsByPID = make(map[int]int, len(pidByIP))
	result.BytesByPID = make(map[int]uint64, len(pidByIP))
	result.BytesInByPID = make(map[int]uint64, len(pidByIP))
	result.BytesOutByPID = make(map[int]uint64, len(pidByIP))
	result.FirstFrameByPID = make(map[int]uint64, len(attr.allPIDs))
	result.FirstPacketByPID = make(map[int]time.Time, len(attr.allPIDs))
	result.LastPacketByPID = make(map[int]time.Time, len(attr.allPIDs))
	result.BytesByEndpointPID = make(map[int]uint64, len(attr.allPIDs))
	result.BeaconShapeByPID = make(map[int]BeaconShape, len(attr.allPIDs))
	result.FlowsMeta = make(map[FlowID]FlowMeta, len(flows))

	sortedFlows := sortFlowsForReplay(flows)
	flowsByEndpointPID := make(map[int][]FlowSummary, len(attr.allPIDs))

	// Populate per-flow data
	for _, st := range sortedFlows {
		flowBytes := st.bytesInitToResp + st.bytesRespToInit
		flowPackets := uint64(st.packetsTotal)
		summary := FlowSummary{
			Proto:           "tcp",
			LocalIP:         st.key.InitIP,
			LocalPort:       st.key.InitPort,
			RemoteIP:        st.key.RespIP,
			RemotePort:      st.key.RespPort,
			BytesInitToResp: st.bytesInitToResp,
			BytesRespToInit: st.bytesRespToInit,
			FirstPacket:     st.firstPacket.Add(-shift),
			LastPacket:      st.lastPacket.Add(-shift),
		}

		fid := FlowID{
			LocalIP:    st.key.InitIP,
			LocalPort:  st.key.InitPort,
			RemoteIP:   st.key.RespIP,
			RemotePort: st.key.RespPort,
		}
		result.FlowsMeta[fid] = FlowMeta{
			JA3:       st.tlsJA3,
			JA3S:      st.tlsJA3S,
			SNI:       st.tlsSNI,
			HTTPHost:  st.httpHost,
			HTTPURI:   st.httpURI,
			BytesSum:  flowBytes,
			FirstSeen: st.firstPacket.Add(-shift),
			LastSeen:  st.lastPacket.Add(-shift),
		}

		if pid, ok := pidByIP[st.key.InitIP]; ok {
			result.PacketsByPID[pid] += flowPackets
			result.FlowsByPID[pid]++
			result.BytesByPID[pid] += flowBytes
			result.BytesOutByPID[pid] += st.bytesInitToResp
			result.BytesInByPID[pid] += st.bytesRespToInit
			// Track first frame (line number) and first packet time
			if existing, ok := result.FirstFrameByPID[pid]; !ok || st.firstFrameNum < existing {
				result.FirstFrameByPID[pid] = st.firstFrameNum
			}
			if existing, ok := result.FirstPacketByPID[pid]; !ok || st.firstPacket.Before(existing) {
				result.FirstPacketByPID[pid] = st.firstPacket
			}
			if existing, ok := result.LastPacketByPID[pid]; !ok || st.lastPacket.After(existing) {
				result.LastPacketByPID[pid] = st.lastPacket
			}
		}

		if epPID, ok := attr.outboundPIDFor(st.key.InitIP, st.key.RespIP); ok {
			result.BytesByEndpointPID[epPID] += flowBytes
			flowsByEndpointPID[epPID] = append(flowsByEndpointPID[epPID], summary)
			// Track first frame and packet time for endpoint PIDs too
			if existing, ok := result.FirstFrameByPID[epPID]; !ok || st.firstFrameNum < existing {
				result.FirstFrameByPID[epPID] = st.firstFrameNum
			}
			if existing, ok := result.FirstPacketByPID[epPID]; !ok || st.firstPacket.Before(existing) {
				result.FirstPacketByPID[epPID] = st.firstPacket
			}
			if existing, ok := result.LastPacketByPID[epPID]; !ok || st.lastPacket.After(existing) {
				result.LastPacketByPID[epPID] = st.lastPacket
			}
		}
	}

	// Compute beacon shapes for each endpoint
	for pid, flowList := range flowsByEndpointPID {
		if shape, ok := computeBeaconShape(flowList); ok {
			result.BeaconShapeByPID[pid] = shape
		}
	}

	// Create candidates from flows using the same classification as PCAP
	// Build a minimal snapshot for detection.Classify
	allWindows := []time.Time{shiftedEnd} // Single window for Zeek logs
	snap := buildSnapshotForWindow(sortedFlows, attr, logs.LocalIPs, shiftedEnd, allWindows)
	cands := detection.Classify(snap, shared.ClassifyOptions{HostScope: "zeek-replay"}, nil)

	// Enrich with cross-candidate signals
	enrichPcapWithCrossCandidatePivotSignals(cands)

	// Stamp beacon shape signals
	stampBeaconShapeSignals(cands, result.BeaconShapeByPID)

	// Stamp SMB lateral movement signals
	stampSMBLateralSignals(cands, sortedFlows, attr)

	// Apply pcap-mode role guard
	shared.ApplyPcapModeRoleGuard(cands)

	result.Candidates = cands

	// Map per-PID stats for cluster candidates (they have synthetic PIDs
	// that differ from the per-host/endpoint PIDs tracked during flow processing).
	// Look up frame/bytes/time from the endpoint PID or per-host PID and copy to cluster.
	for _, c := range cands {
		if c.Proc == nil {
			continue
		}
		pid := c.Proc.Pid

		// Check if we already have data for this PID
		_, hasFrame := result.FirstFrameByPID[pid]
		_, hasBytes := result.BytesByEndpointPID[pid]
		if hasFrame && hasBytes {
			continue
		}

		// Try to find data from related PIDs via connections
		for _, conn := range c.Conns {
			if epPID, ok := attr.outboundPIDFor(conn.LocalAddress, conn.RemoteAddress); ok {
				if !hasFrame {
					if frame, ok := result.FirstFrameByPID[epPID]; ok {
						result.FirstFrameByPID[pid] = frame
						hasFrame = true
					}
				}
				if !hasBytes {
					if bytes, ok := result.BytesByEndpointPID[epPID]; ok {
						result.BytesByEndpointPID[pid] = bytes
						hasBytes = true
					}
				}
				if !hasFrame || !hasBytes {
					if firstPkt, ok := result.FirstPacketByPID[epPID]; ok {
						result.FirstPacketByPID[pid] = firstPkt
					}
					if lastPkt, ok := result.LastPacketByPID[epPID]; ok {
						result.LastPacketByPID[pid] = lastPkt
					}
				}
			}
			if hostPID, ok := pidByIP[conn.LocalAddress]; ok {
				if !hasFrame {
					if frame, ok := result.FirstFrameByPID[hostPID]; ok {
						result.FirstFrameByPID[pid] = frame
						hasFrame = true
					}
				}
				if !hasBytes {
					if bytes, ok := result.BytesByPID[hostPID]; ok {
						result.BytesByEndpointPID[pid] = bytes
						hasBytes = true
					}
				}
			}
			if hasFrame && hasBytes {
				break
			}
		}
	}

	send(IngestProgress{Stage: "done", FlowsObserved: len(flows)})
	return result
}

// IngestZeekWithStreaming is like IngestZeekWithProgress but emits results
// to resultCh for consistency with PCAP streaming mode. Zeek logs are
// processed in a single window, so only one result is emitted.
func IngestZeekWithStreaming(ctx context.Context, path string, progressCh chan<- IngestProgress, resultCh chan<- IngestResult) IngestResult {
	result := IngestZeekWithProgress(ctx, path, progressCh)
	if resultCh != nil {
		// Use blocking send to ensure the result is delivered. Non-blocking
		// select with default caused a race: Zeek parsing completes so fast
		// that the result was dropped before the UI started listening.
		resultCh <- result
	}
	return result
}
