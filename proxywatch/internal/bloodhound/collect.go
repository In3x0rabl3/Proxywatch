package bloodhound

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"proxywatch/internal/safeio"
	"proxywatch/internal/shared"
)

type Payload struct {
	Metadata map[string]any `json:"metadata,omitempty"`
	Graph    Graph          `json:"graph"`
}

type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

type Node struct {
	ID         string         `json:"id"`
	Kinds      []string       `json:"kinds"`
	Properties map[string]any `json:"properties,omitempty"`
}

type Edge struct {
	Kind       string         `json:"kind"`
	Start      Ref            `json:"start"`
	End        Ref            `json:"end"`
	Properties map[string]any `json:"properties,omitempty"`
}

type Ref struct {
	Value   string `json:"value"`
	MatchBy string `json:"match_by"`
}

func BuildGraph(cands []shared.Candidate) Payload {
	hostIPs := make(map[string]map[string]struct{})
	addHostIP := func(host, ip string) {
		if ip == "" || shared.IsWildcardIP(ip) || shared.IsLoopbackIP(ip) {
			return
		}
		host = shared.DisplayHost(host)
		ips := hostIPs[host]
		if ips == nil {
			ips = make(map[string]struct{})
			hostIPs[host] = ips
		}
		ips[ip] = struct{}{}
	}

	for _, c := range cands {
		if c.Proc == nil {
			continue
		}
		host := shared.DisplayHost(c.Host)
		for _, l := range c.Listeners {
			addHostIP(host, l.LocalAddress)
		}
		for _, cn := range c.Conns {
			addHostIP(host, cn.LocalAddress)
		}
		for _, ul := range c.UDPListeners {
			addHostIP(host, ul.LocalAddress)
		}
	}

	nodes := make(map[string]Node)
	edges := make(map[string]Edge)

	addNode := func(n Node) {
		if _, ok := nodes[n.ID]; ok {
			return
		}
		nodes[n.ID] = n
	}

	ipToHost := make(map[string]string)
	for host, ips := range hostIPs {
		hostID := "host:" + host
		for ip := range ips {
			if cur, ok := ipToHost[ip]; ok && cur != hostID {
				ipToHost[ip] = ""
				continue
			}
			if _, ok := ipToHost[ip]; !ok {
				ipToHost[ip] = hostID
			}
		}
	}

	addEdge := func(e Edge, key string) {
		if _, ok := edges[key]; ok {
			return
		}
		e = addEdgeDescription(e)
		edges[key] = e
	}

	scopeForIP := func(ip string) string {
		switch {
		case shared.IsLoopbackIP(ip):
			return "loopback"
		case shared.IsInternalIP(ip):
			return "internal"
		default:
			return "external"
		}
	}

	hostProps := func(host string) map[string]any {
		props := map[string]any{
			"name": host,
		}
		ips := hostIPs[host]
		if len(ips) == 0 {
			return props
		}
		list := make([]string, 0, len(ips))
		for ip := range ips {
			list = append(list, ip)
		}
		sort.Strings(list)
		props["ip"] = list[0]
		props["ips"] = list
		return props
	}

	addHostIPNode := func(ip string) string {
		hostIPID := "hostip:" + ip
		addNode(Node{
			ID:    hostIPID,
			Kinds: []string{"Host"},
			Properties: map[string]any{
				"name":  ip,
				"ip":    ip,
				"scope": scopeForIP(ip),
			},
		})
		return hostIPID
	}

	resolveKnownHostID := func(ip string) (string, bool) {
		if hostID, ok := ipToHost[ip]; ok && hostID != "" {
			return hostID, true
		}
		return "", false
	}

	for _, c := range cands {
		if c.Proc == nil {
			continue
		}
		host := shared.DisplayHost(c.Host)

		hostID := "host:" + host
		addNode(Node{
			ID:         hostID,
			Kinds:      []string{"Host"},
			Properties: hostProps(host),
		})

		if ips := hostIPs[host]; len(ips) > 0 {
			for ip := range ips {
				hostIPID := addHostIPNode(ip)
				addEdge(Edge{
					Kind: "HostHasIP",
					Start: Ref{
						Value:   hostID,
						MatchBy: "id",
					},
					End: Ref{
						Value:   hostIPID,
						MatchBy: "id",
					},
					Properties: map[string]any{
						"host":  host,
						"ip":    ip,
						"scope": scopeForIP(ip),
					},
				}, "HostHasIP|"+hostID+"|"+hostIPID)
			}
		}

		procID := fmt.Sprintf("proc:%s:%d", host, c.Proc.Pid)
		rolePrefix := roleKindPrefix(c.Role)
		addNode(Node{
			ID:    procID,
			Kinds: []string{"Process"},
			Properties: map[string]any{
				"pid":          c.Proc.Pid,
				"name":         c.Proc.Name,
				"path":         c.Proc.ExePath,
				"user":         c.Proc.UserName,
				"host":         host,
				"integrity":    c.Proc.Integrity,
				"score":        c.Score,
				"confidence":   c.Confidence,
				"active_proxy": c.ActiveProxying,
				"signals":      append([]string(nil), c.Signals...),
				"reasons":      append([]string(nil), c.Reasons...),
			},
		})

		hostProcessKind := rolePrefix + "ProcessOnHost"
		addEdge(Edge{
			Kind: hostProcessKind,
			Start: Ref{
				Value:   hostID,
				MatchBy: "id",
			},
			End: Ref{
				Value:   procID,
				MatchBy: "id",
			},
			Properties: map[string]any{
				"host":       host,
				"process":    c.Proc.Name,
				"pid":        c.Proc.Pid,
				"score":      c.Score,
				"confidence": c.Confidence,
			},
		}, hostProcessKind+"|"+hostID+"|"+procID)

		userName := strings.TrimSpace(c.Proc.UserName)
		if userID, ok := userNodeID(userName); ok {
			addNode(Node{
				ID:    userID,
				Kinds: []string{"User"},
				Properties: map[string]any{
					"name": userName,
				},
			})

			userProcessKind := "User" + rolePrefix + "Process"
			addEdge(Edge{
				Kind: userProcessKind,
				Start: Ref{
					Value:   userID,
					MatchBy: "id",
				},
				End: Ref{
					Value:   procID,
					MatchBy: "id",
				},
				Properties: map[string]any{
					"user":       userName,
					"process":    c.Proc.Name,
					"pid":        c.Proc.Pid,
					"score":      c.Score,
					"confidence": c.Confidence,
				},
			}, userProcessKind+"|"+userID+"|"+procID)
		}

		for _, cn := range c.Conns {
			if cn.RemoteAddress == "" || shared.IsWildcardIP(cn.RemoteAddress) {
				continue
			}

			localEndpointID := fmt.Sprintf("endpoint:%s:%s:%d", host, cn.LocalAddress, cn.LocalPort)
			addNode(Node{
				ID:    localEndpointID,
				Kinds: []string{"Endpoint"},
				Properties: map[string]any{
					"ip":       cn.LocalAddress,
					"port":     cn.LocalPort,
					"protocol": "tcp",
					"scope":    "local",
					"host":     host,
				},
			})

			addEdge(Edge{
				Kind: "HostHasLocalEndpoint",
				Start: Ref{
					Value:   hostID,
					MatchBy: "id",
				},
				End: Ref{
					Value:   localEndpointID,
					MatchBy: "id",
				},
				Properties: map[string]any{
					"host":     host,
					"ip":       cn.LocalAddress,
					"port":     cn.LocalPort,
					"protocol": "tcp",
				},
			}, "HostHasLocalEndpoint|"+hostID+"|"+localEndpointID)

			usesLocalKind := rolePrefix + "UsesLocalEndpoint"
			addEdge(Edge{
				Kind: usesLocalKind,
				Start: Ref{
					Value:   procID,
					MatchBy: "id",
				},
				End: Ref{
					Value:   localEndpointID,
					MatchBy: "id",
				},
				Properties: localEndpointProcessProps(c, cn),
			}, usesLocalKind+"|"+procID+"|"+localEndpointID+"|"+cn.State)

			localUsedByKind := "LocalEndpointUsedBy" + rolePrefix
			addEdge(Edge{
				Kind: localUsedByKind,
				Start: Ref{
					Value:   localEndpointID,
					MatchBy: "id",
				},
				End: Ref{
					Value:   procID,
					MatchBy: "id",
				},
				Properties: localEndpointProcessProps(c, cn),
			}, localUsedByKind+"|"+localEndpointID+"|"+procID+"|"+cn.State)

			scope := "external"
			switch {
			case shared.IsLoopbackIP(cn.RemoteAddress):
				scope = "loopback"
			case shared.IsInternalIP(cn.RemoteAddress):
				scope = "internal"
			}

			hostEdgeKind := kindForScope(
				scope,
				rolePrefix+"ConnectsToHostExternal",
				rolePrefix+"ConnectsToHostInternal",
				rolePrefix+"ConnectsToHostLoopback",
			)
			hostIPID, knownHost := resolveKnownHostID(cn.RemoteAddress)
			remoteHostName := ""
			if knownHost {
				remoteHostName = strings.TrimPrefix(hostIPID, "host:")
			}

			endpointID := fmt.Sprintf("endpoint:%s:%d", cn.RemoteAddress, cn.RemotePort)
			if remoteHostName != "" {
				endpointID = fmt.Sprintf("endpoint:%s:%s:%d", remoteHostName, cn.RemoteAddress, cn.RemotePort)
			}

			endpointName := fmt.Sprintf("%s:%d", cn.RemoteAddress, cn.RemotePort)
			if remoteHostName != "" {
				endpointName = fmt.Sprintf("%s (%s)", remoteHostName, endpointName)
			}
			endpointProps := map[string]any{
				"name":     endpointName,
				"ip":       cn.RemoteAddress,
				"port":     cn.RemotePort,
				"protocol": "tcp",
				"scope":    scope,
			}
			if remoteHostName != "" {
				endpointProps["host"] = remoteHostName
			}
			addNode(Node{
				ID:         endpointID,
				Kinds:      []string{"Endpoint"},
				Properties: endpointProps,
			})

			edgeKind := kindForScope(
				scope,
				rolePrefix+"ConnectsToExternal",
				rolePrefix+"ConnectsToInternal",
				rolePrefix+"ConnectsToLoopback",
			)
			edgeKey := fmt.Sprintf("%s|%s|%s|%d|%d", edgeKind, procID, endpointID, cn.LocalPort, cn.RemotePort)
			edgeProps := processConnProps(c, cn, scope)
			if remoteHostName != "" {
				edgeProps["remote_host"] = remoteHostName
			}
			addEdge(Edge{
				Kind: edgeKind,
				Start: Ref{
					Value:   procID,
					MatchBy: "id",
				},
				End: Ref{
					Value:   endpointID,
					MatchBy: "id",
				},
				Properties: edgeProps,
			}, edgeKey)

			linkKind := kindForScope(
				scope,
				"LocalEndpointConnectsToExternal",
				"LocalEndpointConnectsToInternal",
				"LocalEndpointConnectsToLoopback",
			)
			linkKey := fmt.Sprintf("%s|%s|%s|%d|%d", linkKind, localEndpointID, endpointID, cn.LocalPort, cn.RemotePort)
			linkProps := endpointLinkProps(c, cn, scope)
			if remoteHostName != "" {
				linkProps["remote_host"] = remoteHostName
			}
			addEdge(Edge{
				Kind: linkKind,
				Start: Ref{
					Value:   localEndpointID,
					MatchBy: "id",
				},
				End: Ref{
					Value:   endpointID,
					MatchBy: "id",
				},
				Properties: linkProps,
			}, linkKey)

			if userID, ok := userNodeID(userName); ok {
				userEdgeKind := kindForScope(
					scope,
					"User"+rolePrefix+"TrafficExternal",
					"User"+rolePrefix+"TrafficInternal",
					"User"+rolePrefix+"TrafficLoopback",
				)
				userKey := fmt.Sprintf("%s|%s|%s|%d|%d", userEdgeKind, userID, endpointID, cn.LocalPort, cn.RemotePort)
				userProps := userConnProps(userName, c, cn, scope)
				if remoteHostName != "" {
					userProps["remote_host"] = remoteHostName
				}
				addEdge(Edge{
					Kind: userEdgeKind,
					Start: Ref{
						Value:   userID,
						MatchBy: "id",
					},
					End: Ref{
						Value:   endpointID,
						MatchBy: "id",
					},
					Properties: userProps,
				}, userKey)
			}

			if knownHost {
				hostKey := fmt.Sprintf("%s|%s|%s|%d|%d", hostEdgeKind, procID, hostIPID, cn.LocalPort, cn.RemotePort)
				addEdge(Edge{
					Kind: hostEdgeKind,
					Start: Ref{
						Value:   procID,
						MatchBy: "id",
					},
					End: Ref{
						Value:   hostIPID,
						MatchBy: "id",
					},
					Properties: map[string]any{
						"process":        c.Proc.Name,
						"pid":            c.Proc.Pid,
						"state":          cn.State,
						"local_address":  cn.LocalAddress,
						"local_port":     cn.LocalPort,
						"remote_address": cn.RemoteAddress,
						"remote_port":    cn.RemotePort,
						"active_proxy":   c.ActiveProxying,
						"scope":          scope,
					},
				}, hostKey)

				localHostKind := kindForScope(
					scope,
					"LocalEndpointConnectsToHostExternal",
					"LocalEndpointConnectsToHostInternal",
					"LocalEndpointConnectsToHostLoopback",
				)
				localHostKey := fmt.Sprintf("%s|%s|%s|%d|%d", localHostKind, localEndpointID, hostIPID, cn.LocalPort, cn.RemotePort)
				addEdge(Edge{
					Kind: localHostKind,
					Start: Ref{
						Value:   localEndpointID,
						MatchBy: "id",
					},
					End: Ref{
						Value:   hostIPID,
						MatchBy: "id",
					},
					Properties: map[string]any{
						"local_address":  cn.LocalAddress,
						"local_port":     cn.LocalPort,
						"remote_address": cn.RemoteAddress,
						"remote_port":    cn.RemotePort,
						"process":        c.Proc.Name,
						"pid":            c.Proc.Pid,
						"scope":          scope,
					},
				}, localHostKey)

				if userID, ok := userNodeID(userName); ok {
					userHostKind := kindForScope(
						scope,
						"User"+rolePrefix+"TrafficHostExternal",
						"User"+rolePrefix+"TrafficHostInternal",
						"User"+rolePrefix+"TrafficHostLoopback",
					)
					userHostKey := fmt.Sprintf("%s|%s|%s|%d|%d", userHostKind, userID, hostIPID, cn.LocalPort, cn.RemotePort)
					addEdge(Edge{
						Kind: userHostKind,
						Start: Ref{
							Value:   userID,
							MatchBy: "id",
						},
						End: Ref{
							Value:   hostIPID,
							MatchBy: "id",
						},
						Properties: userConnProps(userName, c, cn, scope),
					}, userHostKey)
				}
			}
		}
	}

	payload := Payload{
		Metadata: map[string]any{
			"source_kind": "ProxyWatch",
		},
		Graph: Graph{
			Nodes: mapToSlice(nodes),
			Edges: edgeMapToSlice(edges),
		},
	}
	return payload
}

func addEdgeDescription(e Edge) Edge {
	if e.Properties == nil {
		e.Properties = make(map[string]any)
	}
	if _, ok := e.Properties["description"]; !ok {
		e.Properties["description"] = edgeDescription(e.Kind, e.Properties)
	}
	return e
}

func edgeDescription(kind string, props map[string]any) string {
	process := propString(props, "process")
	pid := propString(props, "pid")
	user := propString(props, "user")
	host := propString(props, "host")
	ip := propString(props, "ip")
	localAddr := propString(props, "local_address")
	localPort := propString(props, "local_port")
	remoteAddr := propString(props, "remote_address")
	remotePort := propString(props, "remote_port")
	state := propString(props, "state")
	scope := propString(props, "scope")

	local := joinHostPort(localAddr, localPort)
	remote := joinHostPort(remoteAddr, remotePort)

	if role, ok := roleFromKindSuffix(kind, "ProcessOnHost"); ok {
		return fmt.Sprintf("Host %s owns %s process %s (pid %s).", hostOr(process, host), role, process, pid)
	}
	if role, ok := roleFromUserKindSuffix(kind, "Process"); ok {
		return fmt.Sprintf("User %s owns %s process %s (pid %s).", user, role, process, pid)
	}
	if role, ok := roleFromKindSuffix(kind, "UsesLocalEndpoint"); ok {
		return fmt.Sprintf("%s process %s (pid %s) uses local endpoint %s (%s).", role, process, pid, local, state)
	}
	if role, ok := roleFromKindPrefix(kind, "LocalEndpointUsedBy"); ok {
		return fmt.Sprintf("Local endpoint %s is used by %s process %s (pid %s).", local, role, process, pid)
	}
	if role, ok := roleFromKindAnySuffix(kind, "ConnectsToExternal", "ConnectsToInternal", "ConnectsToLoopback"); ok {
		return fmt.Sprintf("%s process %s (pid %s) connects to %s endpoint %s from %s (%s).", role, process, pid, scope, remote, local, state)
	}
	if role, ok := roleFromKindAnySuffix(kind, "ConnectsToHostExternal", "ConnectsToHostInternal", "ConnectsToHostLoopback"); ok {
		return fmt.Sprintf("%s process %s (pid %s) connects to %s host %s from %s (%s).", role, process, pid, scope, remoteAddr, local, state)
	}
	if role, ok := roleFromUserKindAnySuffix(kind, "TrafficHostExternal", "TrafficHostInternal", "TrafficHostLoopback"); ok {
		return fmt.Sprintf("User %s has %s %s traffic to host %s via %s (pid %s).", user, role, scope, remoteAddr, process, pid)
	}
	if role, ok := roleFromUserKindAnySuffix(kind, "TrafficExternal", "TrafficInternal", "TrafficLoopback"); ok {
		return fmt.Sprintf("User %s has %s %s traffic to %s via %s (pid %s).", user, role, scope, remote, process, pid)
	}

	switch kind {
	case "HostHasIP":
		return fmt.Sprintf("Host %s has IP %s.", host, ip)
	case "HostHasLocalEndpoint":
		return fmt.Sprintf("Host %s exposes local endpoint %s.", host, local)
	case "LocalEndpointConnectsToHostExternal", "LocalEndpointConnectsToHostInternal", "LocalEndpointConnectsToHostLoopback":
		return fmt.Sprintf("Local endpoint %s connects to %s host %s.", local, scope, remoteAddr)
	case "LocalEndpointConnectsToExternal", "LocalEndpointConnectsToInternal", "LocalEndpointConnectsToLoopback":
		return fmt.Sprintf("Local endpoint %s connects to %s endpoint %s.", local, scope, remote)
	default:
		return fmt.Sprintf("Relationship %s recorded by ProxyWatch.", kind)
	}
}

func propString(props map[string]any, key string) string {
	if props == nil {
		return ""
	}
	if v, ok := props[key]; ok {
		switch t := v.(type) {
		case string:
			return t
		default:
			return fmt.Sprint(t)
		}
	}
	return ""
}

func joinHostPort(host, port string) string {
	if host == "" && port == "" {
		return ""
	}
	if host == "" {
		return port
	}
	if port == "" {
		return host
	}
	return host + ":" + port
}

func hostOr(process, host string) string {
	if host != "" {
		return host
	}
	return process
}

func roleKindPrefix(role string) string {
	switch role {
	case "tunnel", "smb-pipe":
		return "Tunnel"
	case "session":
		return "Session"
	case "beacon":
		return "Beacon"
	case "listen":
		return "Listener"
	case "outbound":
		return "Outbound"
	default:
		return "Process"
	}
}

func roleLabelFromPrefix(prefix string) string {
	switch strings.TrimSpace(prefix) {
	case "Tunnel":
		return "tunnel"
	case "Session":
		return "session"
	case "Beacon":
		return "beacon"
	case "Listener":
		return "listener"
	case "Outbound":
		return "outbound"
	case "Process":
		return "process"
	default:
		if prefix == "" {
			return "process"
		}
		return strings.ToLower(prefix)
	}
}

func roleFromKindSuffix(kind, suffix string) (string, bool) {
	if !strings.HasSuffix(kind, suffix) {
		return "", false
	}
	prefix := strings.TrimSuffix(kind, suffix)
	if prefix == "" {
		return "", false
	}
	return roleLabelFromPrefix(prefix), true
}

func roleFromKindPrefix(kind, prefix string) (string, bool) {
	if !strings.HasPrefix(kind, prefix) {
		return "", false
	}
	rolePrefix := strings.TrimPrefix(kind, prefix)
	if rolePrefix == "" {
		return "", false
	}
	return roleLabelFromPrefix(rolePrefix), true
}

func roleFromUserKindSuffix(kind, suffix string) (string, bool) {
	if !strings.HasPrefix(kind, "User") || !strings.HasSuffix(kind, suffix) {
		return "", false
	}
	rolePrefix := strings.TrimPrefix(kind, "User")
	rolePrefix = strings.TrimSuffix(rolePrefix, suffix)
	if rolePrefix == "" {
		return "", false
	}
	return roleLabelFromPrefix(rolePrefix), true
}

func roleFromKindAnySuffix(kind string, suffixes ...string) (string, bool) {
	for _, suffix := range suffixes {
		if role, ok := roleFromKindSuffix(kind, suffix); ok {
			return role, true
		}
	}
	return "", false
}

func roleFromUserKindAnySuffix(kind string, suffixes ...string) (string, bool) {
	for _, suffix := range suffixes {
		if role, ok := roleFromUserKindSuffix(kind, suffix); ok {
			return role, true
		}
	}
	return "", false
}

func kindForScope(scope, externalKind, internalKind, loopbackKind string) string {
	switch scope {
	case "internal":
		return internalKind
	case "loopback":
		return loopbackKind
	default:
		return externalKind
	}
}

func userNodeID(userName string) (string, bool) {
	userName = strings.TrimSpace(userName)
	if userName == "" || userName == "(unknown)" {
		return "", false
	}
	return "user:" + strings.ToLower(userName), true
}

func localEndpointProcessProps(c shared.Candidate, cn shared.ConnectionInfo) map[string]any {
	return map[string]any{
		"process":       c.Proc.Name,
		"pid":           c.Proc.Pid,
		"local_address": cn.LocalAddress,
		"local_port":    cn.LocalPort,
		"state":         cn.State,
	}
}

func processConnProps(c shared.Candidate, cn shared.ConnectionInfo, scope string) map[string]any {
	return map[string]any{
		"process":        c.Proc.Name,
		"pid":            c.Proc.Pid,
		"state":          cn.State,
		"local_address":  cn.LocalAddress,
		"local_port":     cn.LocalPort,
		"remote_address": cn.RemoteAddress,
		"remote_port":    cn.RemotePort,
		"active_proxy":   c.ActiveProxying,
		"scope":          scope,
	}
}

func endpointLinkProps(c shared.Candidate, cn shared.ConnectionInfo, scope string) map[string]any {
	return map[string]any{
		"local_address":  cn.LocalAddress,
		"local_port":     cn.LocalPort,
		"remote_address": cn.RemoteAddress,
		"remote_port":    cn.RemotePort,
		"process":        c.Proc.Name,
		"pid":            c.Proc.Pid,
		"scope":          scope,
	}
}

func userConnProps(userName string, c shared.Candidate, cn shared.ConnectionInfo, scope string) map[string]any {
	return map[string]any{
		"user":           userName,
		"local_address":  cn.LocalAddress,
		"local_port":     cn.LocalPort,
		"remote_address": cn.RemoteAddress,
		"remote_port":    cn.RemotePort,
		"process":        c.Proc.Name,
		"pid":            c.Proc.Pid,
		"scope":          scope,
	}
}

func WriteJSON(path string, payload Payload) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("output path is required")
	}
	path = normalizeCollectionOutputPath(path)
	if !strings.HasSuffix(strings.ToLower(path), ".json") {
		path += ".json"
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	f, closeFile, err := safeio.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = closeFile() }()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func normalizeCollectionOutputPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return path
	}
	path = safeio.ExpandHomePath(path)
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	// Strip collections/ prefix before common sanitization.
	cleaned := filepath.Clean(strings.TrimSpace(path))
	if strings.HasPrefix(cleaned, "collections"+string(filepath.Separator)) {
		cleaned = strings.TrimPrefix(cleaned, "collections"+string(filepath.Separator))
	}
	rel := safeio.SanitizeRelativePath(cleaned, "proxywatch-collection.json")
	return filepath.Join(collectionsRootDir(), rel)
}

func collectionsRootDir() string {
	return filepath.Join(safeio.ProxywatchDataRoot(), "collections")
}

func proxywatchTempDir() string {
	return filepath.Join(safeio.ProxywatchDataRoot(), "tmp")
}

func mapToSlice(m map[string]Node) []Node {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	out := make([]Node, 0, len(ids))
	for _, id := range ids {
		out = append(out, m[id])
	}
	return out
}

func edgeMapToSlice(m map[string]Edge) []Edge {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := make([]Edge, 0, len(keys))
	for _, key := range keys {
		out = append(out, m[key])
	}
	return out
}
