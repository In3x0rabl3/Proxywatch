package behavior

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"proxywatch/internal/shared"
)

// SSHBaseline tracks normal SSH connection patterns per user.
// Used to detect first-time SSH to new destinations (potential lateral movement).
type SSHBaseline struct {
	mu       sync.RWMutex
	patterns map[string]*SSHUserPattern // key: "user@sourceHost"
}

// SSHUserPattern tracks SSH destinations for a specific user on a specific host.
type SSHUserPattern struct {
	User          string              `json:"user"`
	SourceHost    string              `json:"source_host"`
	Destinations  map[string]*SSHDest `json:"destinations"` // key: "ip:port"
	FirstSeen     time.Time           `json:"first_seen"`
	LastSeen      time.Time           `json:"last_seen"`
	TotalSessions int                 `json:"total_sessions"`
	BaselineReady bool                `json:"baseline_ready"` // true after MinObservations
}

// SSHDest tracks a single SSH destination.
type SSHDest struct {
	IP        string    `json:"ip"`
	Port      int       `json:"port"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int       `json:"count"`
}

const (
	// MinSSHObservations is the minimum observations before baseline is considered ready.
	MinSSHObservations = 5
	// SSHBaselineWindow is how long a destination stays in baseline without being seen.
	SSHBaselineWindow = 30 * 24 * time.Hour // 30 days
)

var (
	globalSSHBaseline     *SSHBaseline
	globalSSHBaselineOnce sync.Once
)

// GetSSHBaseline returns the global SSH baseline tracker.
func GetSSHBaseline() *SSHBaseline {
	globalSSHBaselineOnce.Do(func() {
		globalSSHBaseline = &SSHBaseline{
			patterns: make(map[string]*SSHUserPattern),
		}
	})
	return globalSSHBaseline
}

// RecordSSHConnection records an SSH connection for baseline learning.
// Returns signals indicating whether this is a known or new destination.
func (b *SSHBaseline) RecordSSHConnection(c *shared.Candidate) []string {
	if c == nil || c.Proc == nil {
		return nil
	}

	// Only process SSH clients
	if !isSSHClientProcess(c.Proc) {
		return nil
	}

	user := c.Proc.UserName
	if user == "" {
		user = "unknown"
	}
	sourceHost := c.Host
	if sourceHost == "" {
		sourceHost = "localhost"
	}

	// Find SSH destination
	var destIP string
	var destPort int
	if c.ControlChannel != nil {
		destIP = c.ControlChannel.RemoteAddress
		destPort = c.ControlChannel.RemotePort
	} else {
		// Check connections for SSH port
		for _, conn := range c.Conns {
			if conn.RemotePort == 22 {
				destIP = conn.RemoteAddress
				destPort = conn.RemotePort
				break
			}
		}
	}

	if destIP == "" || destPort == 0 {
		return nil
	}

	now := time.Now().UTC()
	key := fmt.Sprintf("%s@%s", user, sourceHost)
	destKey := fmt.Sprintf("%s:%d", destIP, destPort)

	b.mu.Lock()
	defer b.mu.Unlock()

	pattern, exists := b.patterns[key]
	if !exists {
		pattern = &SSHUserPattern{
			User:         user,
			SourceHost:   sourceHost,
			Destinations: make(map[string]*SSHDest),
			FirstSeen:    now,
		}
		b.patterns[key] = pattern
	}

	pattern.LastSeen = now
	pattern.TotalSessions++

	var signals []string

	dest, destExists := pattern.Destinations[destKey]
	if !destExists {
		// First time seeing this destination
		dest = &SSHDest{
			IP:        destIP,
			Port:      destPort,
			FirstSeen: now,
		}
		pattern.Destinations[destKey] = dest

		// If baseline is ready, this is a NEW destination
		if pattern.BaselineReady {
			signals = append(signals, "ssh-first-time-destination")
			// Add detail about what's new
			if shared.IsInternalIP(destIP) {
				signals = append(signals, "ssh-new-internal-target")
			} else {
				signals = append(signals, "ssh-new-external-target")
			}
		}
	}

	dest.LastSeen = now
	dest.Count++

	// Check if baseline is now ready
	if !pattern.BaselineReady && pattern.TotalSessions >= MinSSHObservations {
		pattern.BaselineReady = true
		signals = append(signals, "ssh-baseline-established")
	}

	// Add context signals
	if pattern.BaselineReady && destExists {
		signals = append(signals, "ssh-known-destination")
	}

	return signals
}

// isSSHClientProcess checks if a process is an SSH client.
func isSSHClientProcess(p *shared.ProcessInfo) bool {
	if p == nil {
		return false
	}
	name := strings.ToLower(p.Name)
	path := strings.ToLower(p.ExePath)

	sshClientNames := []string{"ssh", "ssh.exe", "putty", "putty.exe", "kitty", "kitty.exe"}
	for _, n := range sshClientNames {
		if name == n {
			return true
		}
	}

	if strings.HasSuffix(path, "/ssh") || strings.HasSuffix(path, "/usr/bin/ssh") ||
		strings.Contains(path, "openssh") || strings.Contains(path, "putty") {
		return true
	}

	return false
}
