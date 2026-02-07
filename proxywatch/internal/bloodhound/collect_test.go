package bloodhound

import (
	"testing"

	"proxywatch/internal/shared"
)

func TestBuildGraph_EmitsHostAndEndpointEdgesForKnownHost(t *testing.T) {
	cands := []shared.Candidate{
		{
			Host: "DEMO",
			Proc: &shared.ProcessInfo{
				Pid:      3472,
				Name:     "sliver_session.exe",
				UserName: "DEMO\\ops",
			},
			Conns: []shared.ConnectionInfo{
				{
					LocalAddress:  "172.16.1.106",
					LocalPort:     62046,
					RemoteAddress: "172.16.1.130",
					RemotePort:    7777,
					State:         "ESTABLISHED",
				},
			},
			Role: "susp-session",
		},
		{
			Host: "lok",
			Proc: &shared.ProcessInfo{
				Pid:      128068,
				Name:     "ssh",
				UserName: "op",
			},
			Listeners: []shared.ListenerInfo{
				{
					LocalAddress: "172.16.1.130",
					LocalPort:    22,
					State:        "LISTEN",
				},
			},
			Role: "susp-tun",
		},
	}

	payload := BuildGraph(cands, nil)
	edgesByKind := make(map[string]int)
	for _, e := range payload.Graph.Edges {
		edgesByKind[e.Kind]++
	}

	requiredKinds := []string{
		"SuspConnectsToHostInternal",
		"SuspConnectsToInternal",
		"LocalEndpointConnectsToHostInternal",
		"LocalEndpointConnectsToInternal",
		"UserSuspTrafficHostInternal",
		"UserSuspTrafficInternal",
	}
	for _, kind := range requiredKinds {
		if edgesByKind[kind] == 0 {
			t.Fatalf("expected edge kind %q to be present, but it was missing", kind)
		}
	}

	wantEndpoint := "endpoint:172.16.1.130:7777"
	foundEndpoint := false
	for _, n := range payload.Graph.Nodes {
		if n.ID == wantEndpoint {
			foundEndpoint = true
			break
		}
	}
	if !foundEndpoint {
		t.Fatalf("expected remote endpoint node %q for compatibility queries", wantEndpoint)
	}
}

