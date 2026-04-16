// Package alerts provides outbound notification hooks — currently a
// generic HTTP POST webhook that fires when a candidate is promoted to
// a malicious role for the first time in its lifetime. Detect-only: no
// kill / isolate actions are taken. Configure with the
// PROXYWATCH_WEBHOOK_URL runtime value (keystore or environment).
package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"proxywatch/internal/keystore"
	"proxywatch/internal/shared"
)

// Payload is the JSON shape POSTed to the webhook endpoint.
type Payload struct {
	Schema     string    `json:"schema"`
	Event      string    `json:"event"`
	Host       string    `json:"host"`
	PID        int       `json:"pid"`
	Name       string    `json:"name"`
	ExePath    string    `json:"exe_path,omitempty"`
	Role       string    `json:"role"`
	RoleFamily string    `json:"role_family"`
	Score      int       `json:"score"`
	Confidence int       `json:"confidence"`
	Signals    []string  `json:"signals,omitempty"`
	Reasons    []string  `json:"reasons,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

var (
	// alertedMu guards alertedKeys. Entries are cleared lazily when
	// the PID disappears from the current candidate set.
	alertedMu   sync.Mutex
	alertedKeys = make(map[string]string) // host|pid → last-alerted-role

	// httpClient is reused across webhook POSTs. Short timeouts so
	// a slow webhook endpoint can't back up the classifier loop.
	httpClient = &http.Client{Timeout: 5 * time.Second}
)

const payloadSchema = "proxywatch.alert.v1"

// webhookURL returns the configured target or empty string if unset.
// Checked on each call so operators can reconfigure without a restart.
func webhookURL() string {
	if v := strings.TrimSpace(keystore.RuntimeValue("PROXYWATCH_WEBHOOK_URL")); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("PROXYWATCH_WEBHOOK_URL"))
}

// IsConfigured reports whether a webhook URL is available.
func IsConfigured() bool { return webhookURL() != "" }

// ScanAndFire diffs the new candidate set against the last-alerted map
// and fires a webhook for each candidate freshly promoted to a
// malicious role. Called once per classifier cycle from the debug-api
// snapshot-update path. host scopes the dedup key so a per-host agent
// gateway can re-alert on the same PID across different hosts.
//
// Safe to call when no webhook is configured — it exits early.
func ScanAndFire(host string, scored []shared.Candidate) {
	if !IsConfigured() {
		return
	}
	alertedMu.Lock()
	defer alertedMu.Unlock()

	// Track which keys we saw this cycle; purge stale entries so the
	// map doesn't grow unbounded across long deployments.
	seen := make(map[string]struct{}, len(scored))

	for i := range scored {
		c := &scored[i]
		if c.Proc == nil {
			continue
		}
		if !isMaliciousRole(c.Role) {
			continue
		}
		scope := host
		if c.Host != "" {
			scope = c.Host
		}
		key := scope + "|" + itoa(c.Proc.Pid)
		seen[key] = struct{}{}

		// Fire when the promoted role is new or has changed for this PID.
		// Covers outbound → control-channel and control-channel →
		// control-pivot graduations.
		if prev, ok := alertedKeys[key]; ok && prev == c.Role {
			continue
		}
		alertedKeys[key] = c.Role
		go sendAlert(scope, c)
	}

	// Drop entries for PIDs that have exited or dropped out of the
	// malicious-role set — freeing the key lets a future re-promotion
	// alert again.
	for k := range alertedKeys {
		if _, stillAlive := seen[k]; !stillAlive {
			delete(alertedKeys, k)
		}
	}
}

// sendAlert POSTs a Payload to the configured webhook URL. Errors are
// swallowed silently — alerting is best-effort and must never block
// the classifier loop.
func sendAlert(host string, c *shared.Candidate) {
	url := webhookURL()
	if url == "" {
		return
	}
	payload := Payload{
		Schema:     payloadSchema,
		Event:      "promotion",
		Host:       host,
		PID:        c.Proc.Pid,
		Name:       c.Proc.Name,
		ExePath:    c.Proc.ExePath,
		Role:       c.Role,
		RoleFamily: shared.RoleFamily(c.Role),
		Score:      c.Score,
		Confidence: c.Confidence,
		Signals:    append([]string(nil), c.Signals...),
		Reasons:    append([]string(nil), c.Reasons...),
		Timestamp:  time.Now().UTC(),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "proxywatch-webhook/1")
	resp, err := httpClient.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

// ResetAlertedForTest clears the dedup map. Exported only for tests.
func ResetAlertedForTest() {
	alertedMu.Lock()
	alertedKeys = make(map[string]string)
	alertedMu.Unlock()
}

// isMaliciousRole mirrors scoring.IsMaliciousRole without importing
// the detection package (keeps the alerts package at a leaf position
// in the dep graph so the classifier can import it cleanly).
func isMaliciousRole(role string) bool {
	switch role {
	case "control-channel", "control-pivot",
		"control-session", "control-beacon", "control-tunnel",
		"tunnel", "smb-pipe":
		return true
	}
	return false
}

// itoa avoids importing strconv just for Itoa — keeps this package's
// import graph tight.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
