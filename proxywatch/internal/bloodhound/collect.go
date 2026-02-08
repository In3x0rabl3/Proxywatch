package bloodhound

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

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

func BuildGraph(cands []shared.Candidate, roleFilter map[string]bool) Payload {
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
		if !shared.RoleMatchesFilter(c.Role, roleFilter) {
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
		if !shared.RoleMatchesFilter(c.Role, roleFilter) {
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
		roleFamily := shared.RoleFamily(c.Role)
		addNode(Node{
			ID:    procID,
			Kinds: []string{"Process"},
			Properties: map[string]any{
				"pid":          c.Proc.Pid,
				"name":         c.Proc.Name,
				"path":         c.Proc.ExePath,
				"user":         c.Proc.UserName,
				"role":         c.Role,
				"role_family":  roleFamily,
				"host":         host,
				"integrity":    c.Proc.Integrity,
				"score":        c.Score,
				"confidence":   c.Confidence,
				"active_proxy": c.ActiveProxying,
				"signals":      append([]string(nil), c.Signals...),
				"reasons":      append([]string(nil), c.Reasons...),
			},
		})

		addEdge(Edge{
			Kind: "HasSuspProcess",
			Start: Ref{
				Value:   hostID,
				MatchBy: "id",
			},
			End: Ref{
				Value:   procID,
				MatchBy: "id",
			},
			Properties: map[string]any{
				"host":        host,
				"process":     c.Proc.Name,
				"pid":         c.Proc.Pid,
				"role":        c.Role,
				"role_family": roleFamily,
				"score":       c.Score,
				"confidence":  c.Confidence,
			},
		}, "HasSuspProcess|"+hostID+"|"+procID)

		userName := strings.TrimSpace(c.Proc.UserName)
		if userID, ok := userNodeID(userName); ok {
			addNode(Node{
				ID:    userID,
				Kinds: []string{"User"},
				Properties: map[string]any{
					"name": userName,
				},
			})

			addEdge(Edge{
				Kind: "UserHasSuspProcess",
				Start: Ref{
					Value:   userID,
					MatchBy: "id",
				},
				End: Ref{
					Value:   procID,
					MatchBy: "id",
				},
				Properties: map[string]any{
					"user":        userName,
					"process":     c.Proc.Name,
					"pid":         c.Proc.Pid,
					"role":        c.Role,
					"role_family": roleFamily,
					"score":       c.Score,
					"confidence":  c.Confidence,
				},
			}, "UserHasSuspProcess|"+userID+"|"+procID)
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

			addEdge(Edge{
				Kind: "SuspUsesLocalEndpoint",
				Start: Ref{
					Value:   procID,
					MatchBy: "id",
				},
				End: Ref{
					Value:   localEndpointID,
					MatchBy: "id",
				},
				Properties: localEndpointProcessProps(c, roleFamily, cn),
			}, "SuspUsesLocalEndpoint|"+procID+"|"+localEndpointID+"|"+cn.State)

			addEdge(Edge{
				Kind: "LocalEndpointUsedBySuspProcess",
				Start: Ref{
					Value:   localEndpointID,
					MatchBy: "id",
				},
				End: Ref{
					Value:   procID,
					MatchBy: "id",
				},
				Properties: localEndpointProcessProps(c, roleFamily, cn),
			}, "LocalEndpointUsedBySuspProcess|"+localEndpointID+"|"+procID+"|"+cn.State)

			scope := "external"
			switch {
			case shared.IsLoopbackIP(cn.RemoteAddress):
				scope = "loopback"
			case shared.IsInternalIP(cn.RemoteAddress):
				scope = "internal"
			}

			hostEdgeKind := kindForScope(
				scope,
				"SuspConnectsToHostExternal",
				"SuspConnectsToHostInternal",
				"SuspConnectsToHostLoopback",
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
				"SuspConnectsToExternal",
				"SuspConnectsToInternal",
				"SuspConnectsToLoopback",
			)
			edgeKey := fmt.Sprintf("%s|%s|%s|%d|%d", edgeKind, procID, endpointID, cn.LocalPort, cn.RemotePort)
			edgeProps := processConnProps(c, roleFamily, cn, scope)
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
			linkProps := endpointLinkProps(c, roleFamily, cn, scope)
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
					"UserSuspTrafficExternal",
					"UserSuspTrafficInternal",
					"UserSuspTrafficLoopback",
				)
				userKey := fmt.Sprintf("%s|%s|%s|%d|%d", userEdgeKind, userID, endpointID, cn.LocalPort, cn.RemotePort)
				userProps := userConnProps(userName, c, roleFamily, cn, scope)
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
						"role":           c.Role,
						"role_family":    roleFamily,
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
						"role":           c.Role,
						"role_family":    roleFamily,
						"process":        c.Proc.Name,
						"pid":            c.Proc.Pid,
						"scope":          scope,
					},
				}, localHostKey)

				if userID, ok := userNodeID(userName); ok {
					userHostKind := kindForScope(
						scope,
						"UserSuspTrafficHostExternal",
						"UserSuspTrafficHostInternal",
						"UserSuspTrafficHostLoopback",
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
						Properties: userConnProps(userName, c, roleFamily, cn, scope),
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

	switch kind {
	case "HasSuspProcess":
		return fmt.Sprintf("Host %s owns suspicious process %s (pid %s).", hostOr(process, host), process, pid)
	case "UserHasSuspProcess":
		return fmt.Sprintf("User %s owns suspicious process %s (pid %s).", user, process, pid)
	case "HostHasIP":
		return fmt.Sprintf("Host %s has IP %s.", host, ip)
	case "HostHasLocalEndpoint":
		return fmt.Sprintf("Host %s exposes local endpoint %s.", host, local)
	case "SuspUsesLocalEndpoint":
		return fmt.Sprintf("Suspicious process %s (pid %s) uses local endpoint %s (%s).", process, pid, local, state)
	case "LocalEndpointUsedBySuspProcess":
		return fmt.Sprintf("Local endpoint %s is used by suspicious process %s (pid %s).", local, process, pid)
	case "SuspConnectsToExternal", "SuspConnectsToInternal", "SuspConnectsToLoopback":
		return fmt.Sprintf("Suspicious process %s (pid %s) connects to %s endpoint %s from %s (%s).", process, pid, scope, remote, local, state)
	case "SuspConnectsToHostExternal", "SuspConnectsToHostInternal", "SuspConnectsToHostLoopback":
		return fmt.Sprintf("Suspicious process %s (pid %s) connects to %s host %s from %s (%s).", process, pid, scope, remoteAddr, local, state)
	case "LocalEndpointConnectsToHostExternal", "LocalEndpointConnectsToHostInternal", "LocalEndpointConnectsToHostLoopback":
		return fmt.Sprintf("Local endpoint %s connects to %s host %s.", local, scope, remoteAddr)
	case "LocalEndpointConnectsToExternal", "LocalEndpointConnectsToInternal", "LocalEndpointConnectsToLoopback":
		return fmt.Sprintf("Local endpoint %s connects to %s endpoint %s.", local, scope, remote)
	case "UserSuspTrafficHostExternal", "UserSuspTrafficHostInternal", "UserSuspTrafficHostLoopback":
		return fmt.Sprintf("User %s has suspicious %s traffic to host %s via %s (pid %s).", user, scope, remoteAddr, process, pid)
	case "UserSuspTrafficExternal", "UserSuspTrafficInternal", "UserSuspTrafficLoopback":
		return fmt.Sprintf("User %s has suspicious %s traffic to %s via %s (pid %s).", user, scope, remote, process, pid)
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

func localEndpointProcessProps(c shared.Candidate, roleFamily string, cn shared.ConnectionInfo) map[string]any {
	return map[string]any{
		"process":       c.Proc.Name,
		"pid":           c.Proc.Pid,
		"local_address": cn.LocalAddress,
		"local_port":    cn.LocalPort,
		"state":         cn.State,
		"role":          c.Role,
		"role_family":   roleFamily,
	}
}

func processConnProps(c shared.Candidate, roleFamily string, cn shared.ConnectionInfo, scope string) map[string]any {
	return map[string]any{
		"process":        c.Proc.Name,
		"pid":            c.Proc.Pid,
		"state":          cn.State,
		"local_address":  cn.LocalAddress,
		"local_port":     cn.LocalPort,
		"remote_address": cn.RemoteAddress,
		"remote_port":    cn.RemotePort,
		"role":           c.Role,
		"role_family":    roleFamily,
		"active_proxy":   c.ActiveProxying,
		"scope":          scope,
	}
}

func endpointLinkProps(c shared.Candidate, roleFamily string, cn shared.ConnectionInfo, scope string) map[string]any {
	return map[string]any{
		"local_address":  cn.LocalAddress,
		"local_port":     cn.LocalPort,
		"remote_address": cn.RemoteAddress,
		"remote_port":    cn.RemotePort,
		"role":           c.Role,
		"role_family":    roleFamily,
		"process":        c.Proc.Name,
		"pid":            c.Proc.Pid,
		"scope":          scope,
	}
}

func userConnProps(userName string, c shared.Candidate, roleFamily string, cn shared.ConnectionInfo, scope string) map[string]any {
	return map[string]any{
		"user":           userName,
		"local_address":  cn.LocalAddress,
		"local_port":     cn.LocalPort,
		"remote_address": cn.RemoteAddress,
		"remote_port":    cn.RemotePort,
		"role":           c.Role,
		"role_family":    roleFamily,
		"process":        c.Proc.Name,
		"pid":            c.Proc.Pid,
		"scope":          scope,
	}
}

func WriteJSON(path string, payload Payload) error {
	if path == "" {
		return fmt.Errorf("output path is required")
	}
	if !strings.HasSuffix(strings.ToLower(path), ".json") {
		path += ".json"
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
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
