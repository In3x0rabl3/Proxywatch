package keystore

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"proxywatch/internal/safeio"
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
}

var (
	runtimeMu     sync.RWMutex
	runtimeValues = make(map[string]string, len(ManagedKeys))

	// activeKeystoreValues points to the currently active keystore's values map.
	// When set, RuntimeValue reads from here instead of the old runtimeValues map.
	activeKeystoreValues *map[string]string
	activeKeystoreMu     sync.RWMutex
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
}

// KeystoreEntry represents a keystore in the registry.
type KeystoreEntry struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	Secure    bool   `json:"secure"`    // true = hardware-key encrypted
	Slot      string `json:"slot,omitempty"` // HMAC slot used (e.g., "1" or "2")
	CreatedAt string `json:"created_at"`
}

// keystoreRegistry holds the list of known keystores.
type keystoreRegistry struct {
	Version    int              `json:"version"`
	Keystores  []KeystoreEntry  `json:"keystores"`
}

// RegistryPath returns the path to the keystore registry file.
func RegistryPath() string {
	home := safeio.UserHomeDir()
	if home == "" {
		return filepath.Join(".proxywatch", "keystores.json")
	}
	return filepath.Join(home, ".proxywatch", "keystores.json")
}

// ListKeystores returns all registered keystores.
func ListKeystores() []KeystoreEntry {
	path := RegistryPath()
	raw, err := safeio.ReadFile(path)
	if err != nil {
		return nil
	}
	var reg keystoreRegistry
	if err := json.Unmarshal(raw, &reg); err != nil {
		return nil
	}
	return reg.Keystores
}

// CreateKeystore creates a new keystore entry and registers it.
// For secure keystores, slot specifies the HMAC slot (e.g., "hmac:slot1").
func CreateKeystore(name string, secure bool, slot ...string) (KeystoreEntry, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return KeystoreEntry{}, fmt.Errorf("keystore name is required")
	}

	home := safeio.UserHomeDir()
	dir := filepath.Join(home, ".proxywatch", "keystores")
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return KeystoreEntry{}, err
	}

	safeName := strings.ReplaceAll(strings.ToLower(name), " ", "-")
	ext := ".json"
	if secure {
		ext = ".enc"
	}
	path := filepath.Join(dir, safeName+ext)

	entry := KeystoreEntry{
		Name:      name,
		Path:      path,
		Secure:    secure,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	// Create empty keystore file.
	emptyValues := EmptyValues()
	if secure {
		slotID := "2"
		if len(slot) > 0 && strings.Contains(slot[0], "1") {
			slotID = "1"
		}
		entry.Slot = slotID
		if err := SaveSecure(path, slotID, emptyValues); err != nil {
			return KeystoreEntry{}, fmt.Errorf("create secure keystore (touch YubiKey): %w", err)
		}
	} else {
		data, err := json.MarshalIndent(payload{
			UpdatedAt: time.Now().UTC(),
			Values:    emptyValues,
		}, "", "  ")
		if err != nil {
			return KeystoreEntry{}, err
		}
		if err := os.WriteFile(path, data, fileMode); err != nil {
			return KeystoreEntry{}, err
		}
	}

	// Register.
	reg := keystoreRegistry{Version: 1}
	regPath := RegistryPath()
	if raw, err := safeio.ReadFile(regPath); err == nil {
		_ = json.Unmarshal(raw, &reg)
	}
	reg.Keystores = append(reg.Keystores, entry)
	regData, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return entry, nil // created but not registered
	}
	regDir := filepath.Dir(regPath)
	if regDir != "" && regDir != "." {
		_ = os.MkdirAll(regDir, dirMode)
	}
	_ = os.WriteFile(regPath, regData, fileMode)

	return entry, nil
}

// secureEnvelope wraps the encrypted data with the HMAC challenge.
type secureEnvelope struct {
	Version    int    `json:"version"`
	Secure     bool   `json:"secure"`
	Slot       string `json:"slot"`       // HMAC slot used (e.g., "1" or "2")
	Challenge  string `json:"challenge"`  // hex-encoded random challenge
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

// SaveSecure encrypts and saves a keystore using HMAC challenge-response.
// Requires YubiKey touch.
func SaveSecure(path, slot string, values map[string]string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("path required")
	}

	// Generate random challenge.
	challengeBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, challengeBytes); err != nil {
		return fmt.Errorf("generate challenge: %w", err)
	}
	challengeHex := fmt.Sprintf("%x", challengeBytes)

	// Try HMAC from YubiKey (requires touch).
	slotNum := "2"
	if strings.Contains(slot, "1") {
		slotNum = "1"
	}

	var keyBytes []byte
	response, err := execCommandWithTouch("ykchalresp", "-"+slotNum, "-H", challengeHex)
	if err == nil {
		response = strings.TrimSpace(response)
		if len(response) >= 40 {
			keyBytes = deriveKeyFromHMAC(response)
		}
	}

	// Fallback: use local machine key if HMAC failed.
	if keyBytes == nil {
		fallbackKey, fErr := loadMasterKey(path, true)
		if fErr != nil {
			return fmt.Errorf("HMAC failed and no local key: %w", fErr)
		}
		keyBytes = fallbackKey
	}

	// Encrypt.
	data, err := json.Marshal(payload{
		UpdatedAt: time.Now().UTC(),
		Values:    sanitizeValues(values),
	})
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	ciphertext := gcm.Seal(nil, nonce, data, nil)

	now := time.Now().UTC().Format(time.RFC3339)
	env := secureEnvelope{
		Version:    2,
		Secure:     true,
		Slot:       slotNum,
		Challenge:  challengeHex,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	encData, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, dirMode)
	}
	return os.WriteFile(path, encData, fileMode)
}

// LoadSecure decrypts a keystore using HMAC challenge-response.
// Falls back to local machine key if HMAC fails.
func LoadSecure(path string) (map[string]string, error) {
	raw, err := safeio.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var env secureEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	if !env.Secure || env.Challenge == "" {
		return nil, fmt.Errorf("not a secure keystore")
	}

	// Try HMAC first (requires YubiKey touch).
	slotNum := env.Slot
	if slotNum == "" {
		slotNum = "2"
	}

	var keyBytes []byte
	response, err := execCommandWithTouch("ykchalresp", "-"+slotNum, "-H", env.Challenge)
	if err == nil {
		response = strings.TrimSpace(response)
		if len(response) >= 40 {
			keyBytes = deriveKeyFromHMAC(response)
		}
	}

	// Fallback: try local machine key if HMAC failed.
	if keyBytes == nil {
		fallbackKey, fErr := loadMasterKey(path, false)
		if fErr != nil {
			return nil, fmt.Errorf("HMAC failed and no local key: %w (HMAC error: %v)", fErr, err)
		}
		keyBytes = fallbackKey
	}

	nonce, err := base64.StdEncoding.DecodeString(strings.TrimSpace(env.Nonce))
	if err != nil || len(nonce) == 0 {
		return nil, fmt.Errorf("invalid nonce")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(env.Ciphertext))
	if err != nil || len(ciphertext) == 0 {
		return nil, fmt.Errorf("invalid ciphertext")
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: wrong key or corrupted data")
	}

	var pl payload
	if err := json.Unmarshal(plain, &pl); err != nil {
		return nil, err
	}
	return sanitizeValues(pl.Values), nil
}

// deriveKeyFromHMAC turns the hex HMAC response into a 32-byte AES key
// using SHA-256.
func deriveKeyFromHMAC(hexResponse string) []byte {
	h := sha256.Sum256([]byte(hexResponse))
	return h[:]
}

// LoadNonSecure loads a non-encrypted keystore (plain JSON).
func LoadNonSecure(path string) (map[string]string, error) {
	raw, err := safeio.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pl payload
	if err := json.Unmarshal(raw, &pl); err != nil {
		return nil, err
	}
	return sanitizeValues(pl.Values), nil
}

// SaveNonSecure saves a non-encrypted keystore (plain JSON).
func SaveNonSecure(path string, values map[string]string) error {
	data, err := json.MarshalIndent(payload{
		UpdatedAt: time.Now().UTC(),
		Values:    sanitizeValues(values),
	}, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, dirMode)
	}
	return os.WriteFile(path, data, fileMode)
}

// Cached hardware key detection.
var (
	cachedHWAvail   bool
	cachedHWDetail  string
	cachedHWTime    time.Time
	cachedHWMu      sync.Mutex
)

// HardwareKeyAvailable returns true if a hardware key (YubiKey) is detected.
// Results are cached for 10 seconds.
func HardwareKeyAvailable() (bool, string) {
	cachedHWMu.Lock()
	defer cachedHWMu.Unlock()
	if time.Since(cachedHWTime) < 10*time.Second {
		return cachedHWAvail, cachedHWDetail
	}
	if yubikeyAvailable() {
		cachedHWAvail = true
		cachedHWDetail = "YubiKey detected"
	} else {
		cachedHWAvail = false
		cachedHWDetail = "no hardware key detected"
	}
	cachedHWTime = time.Now()
	return cachedHWAvail, cachedHWDetail
}

func DefaultPath() string {
	return defaultPath
}

func NormalizePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		path = defaultPath
	}
	path = safeio.ExpandHomePath(path)
	if filepath.IsAbs(path) {
		return path
	}
	rel := safeio.SanitizeRelativePath(path, "keystore.enc")
	home := safeio.UserHomeDir()
	if home == "" {
		return filepath.Join(".proxywatch", rel)
	}
	return filepath.Join(home, ".proxywatch", rel)
}

func KeyPath(path string) string {
	dataPath := NormalizePath(path)
	if strings.HasSuffix(strings.ToLower(dataPath), ".enc") {
		return dataPath[:len(dataPath)-4] + ".key"
	}
	return dataPath + ".key"
}

func ValuesFromRuntime() map[string]string {
	out := make(map[string]string, len(ManagedKeys))
	runtimeMu.RLock()
	defer runtimeMu.RUnlock()
	for _, key := range ManagedKeys {
		out[key] = strings.TrimSpace(runtimeValues[key])
	}
	return out
}

func ApplyToRuntime(values map[string]string) {
	if values == nil {
		values = map[string]string{}
	}
	runtimeMu.Lock()
	defer runtimeMu.Unlock()
	for _, key := range ManagedKeys {
		value := strings.TrimSpace(values[key])
		runtimeValues[key] = value
	}
}

// RuntimeSetValue sets a single key in the runtime values map.
func RuntimeSetValue(key, value string) {
	runtimeMu.Lock()
	defer runtimeMu.Unlock()
	runtimeValues[strings.TrimSpace(key)] = strings.TrimSpace(value)
}

// ClearSensitiveRuntime removes API keys and secrets from the runtime
// values map.  Non-sensitive config (URLs, paths, flags) is preserved.
func ClearSensitiveRuntime() {
	runtimeMu.Lock()
	defer runtimeMu.Unlock()
	for _, key := range ManagedKeys {
		if IsSecretKey(key) {
			runtimeValues[key] = ""
		}
	}
}

// SetActiveKeystore points RuntimeValue to read from the given values map.
// Pass nil to disconnect.
func SetActiveKeystore(values *map[string]string) {
	activeKeystoreMu.Lock()
	defer activeKeystoreMu.Unlock()
	activeKeystoreValues = values
}

func RuntimeValue(key string) string {
	key = strings.TrimSpace(key)

	// First check the active keystore values.
	activeKeystoreMu.RLock()
	if activeKeystoreValues != nil && *activeKeystoreValues != nil {
		v := strings.TrimSpace((*activeKeystoreValues)[key])
		activeKeystoreMu.RUnlock()
		if v != "" {
			return v
		}
	} else {
		activeKeystoreMu.RUnlock()
	}

	// Fall back to the old runtime values map.
	runtimeMu.RLock()
	v := strings.TrimSpace(runtimeValues[key])
	runtimeMu.RUnlock()
	if v != "" {
		return v
	}

	// Final fallback: check environment variables.
	return strings.TrimSpace(os.Getenv(key))
}

func RuntimeSet(key string) bool {
	return strings.TrimSpace(RuntimeValue(key)) != ""
}

func EmptyValues() map[string]string {
	out := make(map[string]string, len(ManagedKeys))
	for _, key := range ManagedKeys {
		out[key] = ""
	}
	return out
}

func Save(path string, values map[string]string) error {
	path = NormalizePath(path)
	key, err := loadMasterKey(path, true)
	if err != nil {
		return err
	}
	toStore := sanitizeValues(values)
	data, err := json.Marshal(payload{
		UpdatedAt: time.Now().UTC(),
		Values:    toStore,
	})
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	ciphertext := gcm.Seal(nil, nonce, data, nil)
	now := time.Now().UTC().Format(time.RFC3339)
	env := envelope{
		Version:    1,
		CreatedAt:  now,
		UpdatedAt:  now,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	encData, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, dirMode); err != nil {
			return err
		}
	}
	return os.WriteFile(path, encData, fileMode)
}

func Load(path string) (map[string]string, error) {
	path = NormalizePath(path)
	raw, err := safeio.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	if env.Version != 1 {
		return nil, fmt.Errorf("unsupported keystore version: %d", env.Version)
	}
	if strings.TrimSpace(env.Ciphertext) == "" {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	nonce, err := base64.StdEncoding.DecodeString(strings.TrimSpace(env.Nonce))
	if err != nil || len(nonce) == 0 {
		return nil, fmt.Errorf("invalid nonce")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(env.Ciphertext))
	if err != nil || len(ciphertext) == 0 {
		return nil, fmt.Errorf("invalid ciphertext")
	}

	key, err := loadMasterKey(path, false)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decrypt failed: invalid local keystore key")
	}

	var pl payload
	if err := json.Unmarshal(plain, &pl); err != nil {
		return nil, err
	}
	return sanitizeValues(pl.Values), nil
}

func IsSecretKey(key string) bool {
	switch strings.TrimSpace(key) {
	case "LOCAL_LLM_URL", "BLOODHOUND_API_URL", "OPENAI_BASE_URL", "ANTHROPIC_BASE_URL", "CALIBRATION_HTTP_TIMEOUT", "PROXYWATCH_TLS_DIR", "PROXYWATCH_DISABLE_CLIENT_CERT", "PROXYWATCH_TRUST_ON_FIRST_USE", "PROXYWATCH_DETECT_DEBUG_LOG", "PROXYWATCH_DETECT_RULES_JSON", "PROXYWATCH_SIEM_SOURCE_REPORT", "PROXYWATCH_SIEM_PROVIDER", "PROXYWATCH_SIEM_MODEL", "PROXYWATCH_SIEM_REPORT_OUTPUT", "PROXYWATCH_SIEM_JSON_OUTPUT":
		return false
	default:
		return true
	}
}

func MaskValue(key, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "(empty)"
	}
	if !IsSecretKey(key) {
		if len(value) > 40 {
			return value[:37] + "..."
		}
		return value
	}
	if len(value) <= 10 {
		return strings.Repeat("*", len(value))
	}
	// Show first 5 chars + 5 stars + "..."
	return value[:5] + "*****..."
}

// SecurityMethod describes the keystore protection method.
type SecurityMethod struct {
	ID        string // "local", "gpg", "yubikey"
	Label     string
	Available bool
	Detail    string // e.g., key ID or device serial
}

// DetectSecurityMethods returns available keystore protection methods.
func DetectSecurityMethods() []SecurityMethod {
	methods := []SecurityMethod{
		{ID: "local", Label: "Local Machine Key", Available: true, Detail: "AES-256-GCM with random key on disk"},
	}

	// Check for GPG.
	if gpgAvailable() {
		gpgID := gpgDefaultKeyID()
		methods = append(methods, SecurityMethod{
			ID: "gpg", Label: "GPG Key", Available: true,
			Detail: gpgID,
		})
	} else {
		methods = append(methods, SecurityMethod{
			ID: "gpg", Label: "GPG Key", Available: false,
			Detail: "gpg not found",
		})
	}

	// Check for YubiKey / hardware token.
	if yubikeyAvailable() {
		methods = append(methods, SecurityMethod{
			ID: "yubikey", Label: "Hardware Key (YubiKey)", Available: true,
			Detail: "FIDO2/PIV token detected",
		})
	} else {
		methods = append(methods, SecurityMethod{
			ID: "yubikey", Label: "Hardware Key (YubiKey)", Available: false,
			Detail: "no hardware token detected",
		})
	}

	return methods
}

// gpgAvailable checks if gpg is installed.
func gpgAvailable() bool {
	for _, name := range []string{"gpg2", "gpg"} {
		for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
			if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
				return true
			}
		}
	}
	return false
}

// gpgDefaultKeyID returns the default GPG key ID or "(none)" if unavailable.
func gpgDefaultKeyID() string {
	// In a full implementation this would exec gpg --list-secret-keys.
	// For now, return a placeholder.
	if gpgAvailable() {
		return "(run gpg --list-secret-keys to configure)"
	}
	return "(none)"
}

// yubikeyAvailable checks for FIDO2/PIV hardware tokens.
func yubikeyAvailable() bool {
	// Check for common YubiKey device paths and tools.
	for _, tool := range []string{"ykman", "yubico-piv-tool", "fido2-token"} {
		for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
			if _, err := os.Stat(filepath.Join(dir, tool)); err == nil {
				return true
			}
		}
	}
	return false
}

// KeySlot represents an available encryption slot on a hardware key.
type KeySlot struct {
	ID     string // e.g., "fido2:resident-1", "gpg:ABCD1234"
	Type   string // "fido2" or "gpg"
	Label  string // human-readable label
	InUse  bool   // true if this credential/key exists
	Detail string // extra info (e.g., relying party, key ID)
}

// DetectKeySlots returns available FIDO2 and GPG slots on the hardware key.
func DetectKeySlots() []KeySlot {
	var slots []KeySlot

	// Detect HMAC-SHA1 challenge-response slots.
	slots = append(slots, detectHMACSlots()...)

	// Detect GPG keys on the hardware key.
	slots = append(slots, detectGPGSlots()...)

	// If no existing keys found, show what's missing.
	if len(slots) == 0 {
		slots = append(slots, KeySlot{
			ID: "none", Type: "none", Label: "No keys detected",
			InUse: false, Detail: "Configure HMAC or GPG on your hardware key first",
		})
	}

	return slots
}

func detectHMACSlots() []KeySlot {
	var slots []KeySlot

	if !yubikeyAvailable() {
		return nil
	}

	// Use ykman otp info to detect HMAC slots WITHOUT triggering touch.
	// Never use ykchalresp for detection — it requires touch.
	out, err := execCommand("ykman", "otp", "info")
	if err != nil {
		return nil
	}

	lines := strings.Split(out, "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)

		// Look for "Slot X:" lines followed by type info.
		slotNum := ""
		if strings.HasPrefix(lower, "slot 1") {
			slotNum = "1"
		} else if strings.HasPrefix(lower, "slot 2") {
			slotNum = "2"
		}
		if slotNum == "" {
			continue
		}

		// Check if this slot or the next line mentions challenge-response/HMAC.
		slotInfo := lower
		if i+1 < len(lines) {
			slotInfo += " " + strings.ToLower(strings.TrimSpace(lines[i+1]))
		}

		if strings.Contains(slotInfo, "challenge-response") || strings.Contains(slotInfo, "hmac") || strings.Contains(slotInfo, "programmed") {
			slots = append(slots, KeySlot{
				ID:     "hmac:slot" + slotNum,
				Type:   "hmac",
				Label:  "HMAC-SHA1 Slot " + slotNum,
				InUse:  true,
				Detail: strings.TrimSpace(line),
			})
		}
	}

	return slots
}

func detectGPGSlots() []KeySlot {
	var slots []KeySlot

	if !gpgAvailable() {
		return nil
	}

	// List GPG keys available on the smartcard/YubiKey.
	out, err := execCommand("gpg", "--card-status", "--with-colons")
	if err != nil {
		// Try without --with-colons.
		out, err = execCommand("gpg", "--card-status")
	}
	if err != nil {
		return nil
	}

	// Parse key fingerprints from card status.
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		// Look for key fingerprints.
		if strings.Contains(line, "fpr") || (strings.Contains(line, "Key fingerprint") && len(line) > 20) {
			parts := strings.Fields(line)
			for _, p := range parts {
				// A fingerprint is a long hex string.
				if len(p) >= 16 && isHexString(p) {
					short := p
					if len(short) > 16 {
						short = short[len(short)-16:]
					}
					slots = append(slots, KeySlot{
						ID:     "gpg:" + short,
						Type:   "gpg",
						Label:  "GPG: " + short[:8] + "..." + short[len(short)-4:],
						InUse:  true,
						Detail: p,
					})
				}
			}
		}
	}

	return slots
}

// Cached slot detection to avoid running commands on every render.
var (
	cachedSlots     []KeySlot
	cachedSlotsTime time.Time
	cachedSlotsMu   sync.Mutex
)

// DetectKeySlotsCached returns cached key slots, refreshing every 10 seconds.
func DetectKeySlotsCached() []KeySlot {
	cachedSlotsMu.Lock()
	defer cachedSlotsMu.Unlock()
	if time.Since(cachedSlotsTime) < 10*time.Second && cachedSlots != nil {
		return cachedSlots
	}
	cachedSlots = DetectKeySlots()
	cachedSlotsTime = time.Now()
	return cachedSlots
}

// TouchCallback is called before and after YubiKey operations that require touch.
// Set this to update the UI with a touch prompt.
var TouchCallback func(active bool)

func notifyTouch(active bool) {
	if TouchCallback != nil {
		TouchCallback(active)
	}
}

// execCommandWithTouch runs a command that requires YubiKey touch,
// notifying the UI before and after.
func execCommandWithTouch(name string, args ...string) (string, error) {
	notifyTouch(true)
	defer notifyTouch(false)
	cmd := exec.Command(name, args...)
	cmd.Env = os.Environ()
	cmd.WaitDelay = 30 * time.Second // longer timeout for touch
	out, err := cmd.Output()
	return string(out), err
}

func execCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = os.Environ()
	cmd.WaitDelay = 3 * time.Second
	out, err := cmd.Output()
	return string(out), err
}

func sanitizeSlotID(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "/", "-")
	if len(s) > 30 {
		s = s[:30]
	}
	return s
}

func truncateLabel(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}

// DeleteKeystore removes a keystore from the registry and deletes its file.
func DeleteKeystore(name string) error {
	name = strings.TrimSpace(name)
	regPath := RegistryPath()
	var reg keystoreRegistry
	if raw, err := safeio.ReadFile(regPath); err == nil {
		_ = json.Unmarshal(raw, &reg)
	}
	found := false
	remaining := make([]KeystoreEntry, 0, len(reg.Keystores))
	for _, e := range reg.Keystores {
		if e.Name == name {
			found = true
			// Delete the keystore file.
			_ = os.Remove(e.Path)
			// Also remove the key file if it exists.
			if strings.HasSuffix(strings.ToLower(e.Path), ".enc") {
				_ = os.Remove(e.Path[:len(e.Path)-4] + ".key")
			}
			continue
		}
		remaining = append(remaining, e)
	}
	if !found {
		return fmt.Errorf("keystore not found: %s", name)
	}
	reg.Keystores = remaining
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(regPath, data, fileMode)
}

// MethodLabel returns a display label for a security method ID.
func MethodLabel(method string) string {
	switch strings.TrimSpace(strings.ToLower(method)) {
	case "gpg":
		return "GPG Key"
	case "yubikey":
		return "Hardware Key"
	default:
		return "Local Key"
	}
}

func sanitizeValues(values map[string]string) map[string]string {
	out := make(map[string]string, len(ManagedKeys))
	for _, key := range ManagedKeys {
		out[key] = strings.TrimSpace(values[key])
	}
	return out
}

func loadMasterKey(dataPath string, create bool) ([]byte, error) {
	keyPath := KeyPath(dataPath)
	raw, err := safeio.ReadFile(keyPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) || !create {
			return nil, err
		}
		key := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, err
		}
		dir := filepath.Dir(keyPath)
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, dirMode); err != nil {
				return nil, err
			}
		}
		encoded := base64.StdEncoding.EncodeToString(key) + "\n"
		if err := os.WriteFile(keyPath, []byte(encoded), fileMode); err != nil {
			return nil, err
		}
		return key, nil
	}

	raw = bytes.TrimSpace(raw)
	if len(raw) == 32 {
		return raw, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil {
		return nil, fmt.Errorf("invalid keystore key file")
	}
	if len(decoded) != 32 {
		return nil, fmt.Errorf("invalid keystore key length")
	}
	return decoded, nil
}

