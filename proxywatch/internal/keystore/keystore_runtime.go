package keystore

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"proxywatch/internal/safeio"
)

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
	ClearVault()
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

// ── Hardware Key Detection ──────────────────────────────────────────────────

// Cached hardware key detection.
var (
	cachedHWAvail  bool
	cachedHWDetail string
	cachedHWTime   time.Time
	cachedHWMu     sync.Mutex
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

func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}
