package bloodhound

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	nodes := make(map[string]Node)
	edges := make(map[string]Edge)

	addNode := func(n Node) {
		if _, ok := nodes[n.ID]; ok {
			return
		}
		nodes[n.ID] = n
	}

	addEdge := func(e Edge, key string) {
		if _, ok := edges[key]; ok {
			return
		}
		e = addEdgeDescription(e)
		edges[key] = e
	}

	for _, c := range cands {
		if c.Proc == nil {
			continue
		}
		if len(roleFilter) > 0 && !roleFilter[c.Role] {
			continue
		}

		host := c.Host
		if host == "" {
			host = "local"
		}

		hostID := "host:" + host
		addNode(Node{
			ID:    hostID,
			Kinds: []string{"Host"},
			Properties: map[string]any{
				"name": host,
			},
		})

		procID := fmt.Sprintf("proc:%s:%d", host, c.Proc.Pid)
		addNode(Node{
			ID:    procID,
			Kinds: []string{"Process"},
			Properties: map[string]any{
				"pid":       c.Proc.Pid,
				"name":      c.Proc.Name,
				"path":      c.Proc.ExePath,
				"user":      c.Proc.UserName,
				"role":      c.Role,
				"host":      host,
				"integrity": c.Proc.Integrity,
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
				"host":    host,
				"process": c.Proc.Name,
				"pid":     c.Proc.Pid,
				"role":    c.Role,
			},
		}, "HasSuspProcess|"+hostID+"|"+procID)

		userName := strings.TrimSpace(c.Proc.UserName)
		if userName != "" && userName != "(unknown)" {
			userID := "user:" + strings.ToLower(userName)
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
					"user":    userName,
					"process": c.Proc.Name,
					"pid":     c.Proc.Pid,
					"role":    c.Role,
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
				Properties: map[string]any{
					"process":       c.Proc.Name,
					"pid":           c.Proc.Pid,
					"local_address": cn.LocalAddress,
					"local_port":    cn.LocalPort,
					"state":         cn.State,
					"role":          c.Role,
				},
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
				Properties: map[string]any{
					"process":       c.Proc.Name,
					"pid":           c.Proc.Pid,
					"local_address": cn.LocalAddress,
					"local_port":    cn.LocalPort,
					"state":         cn.State,
					"role":          c.Role,
				},
			}, "LocalEndpointUsedBySuspProcess|"+localEndpointID+"|"+procID+"|"+cn.State)

			endpointID := fmt.Sprintf("endpoint:%s:%d", cn.RemoteAddress, cn.RemotePort)
			scope := "external"
			switch {
			case shared.IsLoopbackIP(cn.RemoteAddress):
				scope = "loopback"
			case shared.IsInternalIP(cn.RemoteAddress):
				scope = "internal"
			}

			addNode(Node{
				ID:    endpointID,
				Kinds: []string{"Endpoint"},
				Properties: map[string]any{
					"ip":       cn.RemoteAddress,
					"port":     cn.RemotePort,
					"protocol": "tcp",
					"scope":    scope,
				},
			})

			edgeKind := "SuspConnectsToExternal"
			if scope == "internal" {
				edgeKind = "SuspConnectsToInternal"
			} else if scope == "loopback" {
				edgeKind = "SuspConnectsToLoopback"
			}
			key := fmt.Sprintf("%s|%s|%s|%d|%d", edgeKind, procID, endpointID, cn.LocalPort, cn.RemotePort)
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
				Properties: map[string]any{
					"process":        c.Proc.Name,
					"pid":            c.Proc.Pid,
					"state":          cn.State,
					"local_address":  cn.LocalAddress,
					"local_port":     cn.LocalPort,
					"remote_address": cn.RemoteAddress,
					"remote_port":    cn.RemotePort,
					"role":           c.Role,
					"active_proxy":   c.ActiveProxying,
					"scope":          scope,
				},
			}, key)

			linkKind := "LocalEndpointConnectsToExternal"
			if scope == "internal" {
				linkKind = "LocalEndpointConnectsToInternal"
			} else if scope == "loopback" {
				linkKind = "LocalEndpointConnectsToLoopback"
			}
			linkKey := fmt.Sprintf("%s|%s|%s|%d|%d", linkKind, localEndpointID, endpointID, cn.LocalPort, cn.RemotePort)
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
				Properties: map[string]any{
					"local_address":  cn.LocalAddress,
					"local_port":     cn.LocalPort,
					"remote_address": cn.RemoteAddress,
					"remote_port":    cn.RemotePort,
					"role":           c.Role,
					"process":        c.Proc.Name,
					"pid":            c.Proc.Pid,
					"scope":          scope,
				},
			}, linkKey)

			if userName != "" && userName != "(unknown)" {
				userID := "user:" + strings.ToLower(userName)
				userEdgeKind := "UserSuspTrafficExternal"
				if scope == "internal" {
					userEdgeKind = "UserSuspTrafficInternal"
				} else if scope == "loopback" {
					userEdgeKind = "UserSuspTrafficLoopback"
				}
				userKey := fmt.Sprintf("%s|%s|%s|%d|%d", userEdgeKind, userID, endpointID, cn.LocalPort, cn.RemotePort)
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
					Properties: map[string]any{
						"user":           userName,
						"local_address":  cn.LocalAddress,
						"local_port":     cn.LocalPort,
						"remote_address": cn.RemoteAddress,
						"remote_port":    cn.RemotePort,
						"role":           c.Role,
						"process":        c.Proc.Name,
						"pid":            c.Proc.Pid,
						"scope":          scope,
					},
				}, userKey)
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
	case "HostHasLocalEndpoint":
		return fmt.Sprintf("Host %s exposes local endpoint %s.", host, local)
	case "SuspUsesLocalEndpoint":
		return fmt.Sprintf("Suspicious process %s (pid %s) uses local endpoint %s (%s).", process, pid, local, state)
	case "LocalEndpointUsedBySuspProcess":
		return fmt.Sprintf("Local endpoint %s is used by suspicious process %s (pid %s).", local, process, pid)
	case "SuspConnectsToExternal", "SuspConnectsToInternal", "SuspConnectsToLoopback":
		return fmt.Sprintf("Suspicious process %s (pid %s) connects to %s endpoint %s from %s (%s).", process, pid, scope, remote, local, state)
	case "LocalEndpointConnectsToExternal", "LocalEndpointConnectsToInternal", "LocalEndpointConnectsToLoopback":
		return fmt.Sprintf("Local endpoint %s connects to %s endpoint %s.", local, scope, remote)
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
	out := make([]Node, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

func edgeMapToSlice(m map[string]Edge) []Edge {
	out := make([]Edge, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}
