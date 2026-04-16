package scoring

import (
	"testing"

	"proxywatch/internal/shared"
)

func TestHasSMBListenerPort(t *testing.T) {
	cases := []struct {
		name  string
		ports map[int]struct{}
		want  bool
	}{
		{"nil ports", nil, false},
		{"no SMB", map[int]struct{}{80: {}, 443: {}}, false},
		{"port 445", map[int]struct{}{445: {}}, true},
		{"port 139", map[int]struct{}{139: {}}, true},
		{"both SMB ports", map[int]struct{}{139: {}, 445: {}}, true},
	}
	for _, tc := range cases {
		if got := HasSMBListenerPort(tc.ports); got != tc.want {
			t.Errorf("%s: HasSMBListenerPort(%v) = %v, want %v", tc.name, tc.ports, got, tc.want)
		}
	}
}

func TestSocksListenerPorts(t *testing.T) {
	cases := []struct {
		name             string
		listeners        []shared.ListenerInfo
		wantPortCount    int
		wantLoopbackOnly bool
		wantAnyWildcard  bool
	}{
		{"empty", nil, 0, true, false},
		{
			"single loopback",
			[]shared.ListenerInfo{{LocalAddress: "127.0.0.1", LocalPort: 1080}},
			1, true, false,
		},
		{
			"single wildcard",
			[]shared.ListenerInfo{{LocalAddress: "0.0.0.0", LocalPort: 8080}},
			1, false, true,
		},
		{
			"loopback + wildcard",
			[]shared.ListenerInfo{
				{LocalAddress: "127.0.0.1", LocalPort: 1080},
				{LocalAddress: "0.0.0.0", LocalPort: 8080},
			},
			2, false, true,
		},
		{
			"external address",
			[]shared.ListenerInfo{{LocalAddress: "10.0.0.5", LocalPort: 22}},
			1, false, false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ports, loopbackOnly, anyWildcard := SocksListenerPorts(tc.listeners)
			if len(ports) != tc.wantPortCount {
				t.Errorf("port count = %d, want %d", len(ports), tc.wantPortCount)
			}
			if loopbackOnly != tc.wantLoopbackOnly {
				t.Errorf("loopbackOnly = %v, want %v", loopbackOnly, tc.wantLoopbackOnly)
			}
			if anyWildcard != tc.wantAnyWildcard {
				t.Errorf("anyWildcard = %v, want %v", anyWildcard, tc.wantAnyWildcard)
			}
		})
	}
}

func TestOutboundTargets(t *testing.T) {
	ports := map[int]struct{}{8080: {}} // we own this local port (listener)
	conns := []shared.ConnectionInfo{
		// External outbound (should count).
		{State: "ESTABLISHED", LocalPort: 54321, RemoteAddress: "1.2.3.4", RemotePort: 443},
		{State: "ESTABLISHED", LocalPort: 54322, RemoteAddress: "8.8.8.8", RemotePort: 53},
		// Internal outbound (should count).
		{State: "ESTABLISHED", LocalPort: 54323, RemoteAddress: "10.0.0.5", RemotePort: 445},
		{State: "ESTABLISHED", LocalPort: 54324, RemoteAddress: "192.168.1.5", RemotePort: 22},
		// Loopback — counted separately as loopback, not in internal/external.
		{State: "ESTABLISHED", LocalPort: 54325, RemoteAddress: "127.0.0.1", RemotePort: 3000},
		// Inbound to our listener — local port 8080 is in `ports`, so skipped.
		{State: "ESTABLISHED", LocalPort: 8080, RemoteAddress: "10.0.0.9", RemotePort: 49000},
		// Wildcard remote → skipped.
		{State: "ESTABLISHED", LocalPort: 54326, RemoteAddress: "0.0.0.0", RemotePort: 443},
		// Empty remote → skipped.
		{State: "ESTABLISHED", LocalPort: 54327, RemoteAddress: "", RemotePort: 0},
		// Inactive state → skipped.
		{State: "CLOSED", LocalPort: 54328, RemoteAddress: "1.2.3.4", RemotePort: 443},
	}
	total, external, internal, loopback := OutboundTargets(conns, ports)
	if total != 4 {
		t.Errorf("total = %d, want 4", total)
	}
	if external != 2 {
		t.Errorf("external = %d, want 2", external)
	}
	if internal != 2 {
		t.Errorf("internal = %d, want 2", internal)
	}
	if loopback != 1 {
		t.Errorf("loopback = %d, want 1", loopback)
	}
}

func TestCountActiveClientSessions(t *testing.T) {
	ports := map[int]struct{}{443: {}} // we listen on :443
	conns := []shared.ConnectionInfo{
		// Inbound client sessions on our listener (should count).
		{State: "ESTABLISHED", LocalPort: 443, RemoteAddress: "1.2.3.4", RemotePort: 54321},
		{State: "ESTABLISHED", LocalPort: 443, RemoteAddress: "1.2.3.4", RemotePort: 54322}, // same client
		{State: "ESTABLISHED", LocalPort: 443, RemoteAddress: "5.6.7.8", RemotePort: 54323},
		// Not our listener — skipped.
		{State: "ESTABLISHED", LocalPort: 8080, RemoteAddress: "9.9.9.9", RemotePort: 50000},
		// Wildcard remote → skipped.
		{State: "ESTABLISHED", LocalPort: 443, RemoteAddress: "0.0.0.0", RemotePort: 50001},
		// Empty remote → skipped.
		{State: "ESTABLISHED", LocalPort: 443, RemoteAddress: "", RemotePort: 50002},
		// Inactive → skipped.
		{State: "CLOSED", LocalPort: 443, RemoteAddress: "1.2.3.4", RemotePort: 54324},
	}
	count, ips := CountActiveClientSessions(conns, ports)
	if count != 3 {
		t.Errorf("count = %d, want 3", count)
	}
	if ips["1.2.3.4"] != 2 {
		t.Errorf("ips[1.2.3.4] = %d, want 2", ips["1.2.3.4"])
	}
	if ips["5.6.7.8"] != 1 {
		t.Errorf("ips[5.6.7.8] = %d, want 1", ips["5.6.7.8"])
	}
}

func TestOutboundActivity(t *testing.T) {
	ports := map[int]struct{}{8080: {}}
	conns := []shared.ConnectionInfo{
		// Two distinct external targets.
		{State: "ESTABLISHED", LocalPort: 50001, RemoteAddress: "1.2.3.4", RemotePort: 443},
		{State: "ESTABLISHED", LocalPort: 50002, RemoteAddress: "5.6.7.8", RemotePort: 443},
		// Duplicate target:port — shouldn't inflate distinct.
		{State: "ESTABLISHED", LocalPort: 50003, RemoteAddress: "1.2.3.4", RemotePort: 443},
		// Different port, same target.
		{State: "ESTABLISHED", LocalPort: 50004, RemoteAddress: "1.2.3.4", RemotePort: 80},
		// Skipped paths.
		{State: "ESTABLISHED", LocalPort: 8080, RemoteAddress: "9.9.9.9", RemotePort: 443},   // listener
		{State: "ESTABLISHED", LocalPort: 50005, RemoteAddress: "127.0.0.1", RemotePort: 80}, // loopback
		{State: "ESTABLISHED", LocalPort: 50006, RemoteAddress: "0.0.0.0", RemotePort: 443},  // wildcard
	}
	total, targets, distinctPorts, prefixes := OutboundActivity(conns, ports)
	if total != 4 {
		t.Errorf("total = %d, want 4", total)
	}
	if len(targets) != 3 { // 1.2.3.4:443, 5.6.7.8:443, 1.2.3.4:80
		t.Errorf("distinct targets = %d, want 3", len(targets))
	}
	if len(distinctPorts) != 2 { // 443, 80
		t.Errorf("distinct ports = %d, want 2", len(distinctPorts))
	}
	if len(prefixes) != 2 { // /24 prefixes of 1.2.3 and 5.6.7
		t.Errorf("prefixes = %d, want 2", len(prefixes))
	}
}
