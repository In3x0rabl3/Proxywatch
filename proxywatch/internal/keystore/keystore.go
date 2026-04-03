package keystore

import (
	"sync"
	"time"
)

const (
	defaultPath = "~/.proxywatch/keystore.enc"
	fileMode    = 0o600
	dirMode     = 0o700
)

var ManagedKeys = []string{
	"OPENAI_API_KEY",
	"OPENAI_BASE_URL",
	"ANTHROPIC_API_KEY",
	"ANTHROPIC_BASE_URL",
	"LOCAL_LLM_URL",
	"LOCAL_LLM_API_KEY",
	"CALIBRATION_HTTP_TIMEOUT",
	"BLOODHOUND_API_URL",
	"BLOODHOUND_API_TOKEN",
	"BLOODHOUND_API_TOKEN_ID",
	"PROXYWATCH_TLS_DIR",
	"PROXYWATCH_AGENT_TOKEN",
	"PROXYWATCH_DISABLE_CLIENT_CERT",
	"PROXYWATCH_TRUST_ON_FIRST_USE",
	"PROXYWATCH_DETECT_DEBUG_LOG",
	"PROXYWATCH_DETECT_RULES_JSON",
	"PROXYWATCH_SIEM_SOURCE_REPORT",
	"PROXYWATCH_SIEM_PROVIDER",
	"PROXYWATCH_SIEM_MODEL",
	"PROXYWATCH_SIEM_REPORT_OUTPUT",
	"PROXYWATCH_SIEM_JSON_OUTPUT",
	// Service tunnel API keys
	"GITHUB_TOKEN",
	"BUILDKITE_TOKEN",
	"AWS_ACCESS_KEY_ID",
	"AWS_SECRET_ACCESS_KEY",
	"AZURE_CLIENT_ID",
	"AZURE_CLIENT_SECRET",
	"GCP_SERVICE_KEY",
}

var (
	runtimeMu     sync.RWMutex
	runtimeValues = make(map[string]string, len(ManagedKeys))

	// activeKeystoreValues points to the currently active keystore's values map.
	// When set, RuntimeValue reads from here instead of the old runtimeValues map.
	activeKeystoreValues *map[string]string
	activeKeystoreMu     sync.RWMutex

	// vaultFiles holds encrypted file data in memory while the keystore is
	// unlocked. Keys are logical names (e.g., "calibration/latest"), values
	// are raw file content. Persisted as base64 in the keystore payload.
	vaultFiles   map[string][]byte
	vaultFilesMu sync.RWMutex
)

type envelope struct {
	Version    int    `json:"version"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type payload struct {
	UpdatedAt time.Time         `json:"updated_at"`
	Values    map[string]string `json:"values"`
	Files     map[string]string `json:"files,omitempty"` // name → base64(content)
}

// KeystoreEntry represents a keystore in the registry.
type KeystoreEntry struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	Secure    bool   `json:"secure"`           // true = encrypted (hardware or password)
	Method    string `json:"method,omitempty"` // "local", "password", "yubikey"
	Slot      string `json:"slot,omitempty"`   // HMAC slot used (e.g., "1" or "2")
	CreatedAt string `json:"created_at"`
}

// keystoreRegistry holds the list of known keystores.
type keystoreRegistry struct {
	Version   int             `json:"version"`
	Keystores []KeystoreEntry `json:"keystores"`
}
