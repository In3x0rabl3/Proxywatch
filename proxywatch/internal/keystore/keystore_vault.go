package keystore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"proxywatch/internal/safeio"
)

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

	method := "local"
	if secure {
		method = "yubikey"
	}
	entry := KeystoreEntry{
		Name:      name,
		Path:      path,
		Secure:    secure,
		Method:    method,
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

// CreatePasswordKeystore creates a new password-protected keystore.
func CreatePasswordKeystore(name, password string) (KeystoreEntry, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return KeystoreEntry{}, fmt.Errorf("keystore name is required")
	}
	if password == "" {
		return KeystoreEntry{}, fmt.Errorf("password is required")
	}

	home := safeio.UserHomeDir()
	dir := filepath.Join(home, ".proxywatch", "keystores")
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return KeystoreEntry{}, err
	}

	safeName := strings.ReplaceAll(strings.ToLower(name), " ", "-")
	path := filepath.Join(dir, safeName+".enc")

	entry := KeystoreEntry{
		Name:      name,
		Path:      path,
		Secure:    true,
		Method:    "password",
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	emptyValues := EmptyValues()
	if err := SavePassword(path, password, emptyValues); err != nil {
		return KeystoreEntry{}, fmt.Errorf("create password keystore: %w", err)
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
		return entry, nil
	}
	regDir := filepath.Dir(regPath)
	if regDir != "" && regDir != "." {
		_ = os.MkdirAll(regDir, dirMode)
	}
	_ = os.WriteFile(regPath, regData, fileMode)

	return entry, nil
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

// EmptyValues returns a map with all managed keys set to empty strings.
func EmptyValues() map[string]string {
	out := make(map[string]string, len(ManagedKeys))
	for _, key := range ManagedKeys {
		out[key] = ""
	}
	return out
}

// ── Vault File API ──────────────────────────────────────────────────────────
// StoreFile/LoadFile/DeleteFile operate on the in-memory vault. Files are
// persisted to the encrypted keystore when Save/Lock is called.

// VaultActive returns true if the vault is available (keystore unlocked).
func VaultActive() bool {
	vaultFilesMu.RLock()
	defer vaultFilesMu.RUnlock()
	return vaultFiles != nil
}

// StoreFile saves named data into the in-memory vault.
func StoreFile(name string, data []byte) {
	vaultFilesMu.Lock()
	defer vaultFilesMu.Unlock()
	if vaultFiles == nil {
		vaultFiles = make(map[string][]byte)
	}
	vaultFiles[name] = append([]byte(nil), data...)
}

// LoadFile retrieves named data from the vault.
func LoadFile(name string) ([]byte, bool) {
	vaultFilesMu.RLock()
	defer vaultFilesMu.RUnlock()
	if vaultFiles == nil {
		return nil, false
	}
	data, ok := vaultFiles[name]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), data...), true
}

// VaultWrite stores data in vault if active, otherwise writes to disk.
// This is the primary API for modules to write data.
func VaultWrite(name string, data []byte, diskFallback string) error {
	if VaultActive() {
		StoreFile(name, data)
	}
	// Always write to disk so data persists across restarts.
	dir := filepath.Dir(diskFallback)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, dirMode)
	}
	return os.WriteFile(diskFallback, data, fileMode)
}

// VaultRead reads data from vault if available, otherwise from disk.
func VaultRead(name string, diskFallback string) ([]byte, error) {
	if data, ok := LoadFile(name); ok {
		return data, nil
	}
	return safeio.ReadFile(diskFallback)
}

// initVaultFiles loads vault files from a payload after decryption.
func initVaultFiles(pl payload) {
	vaultFilesMu.Lock()
	defer vaultFilesMu.Unlock()
	vaultFiles = make(map[string][]byte, len(pl.Files))
	for name, b64 := range pl.Files {
		data, err := base64.StdEncoding.DecodeString(b64)
		if err == nil {
			vaultFiles[name] = data
		}
	}
}

// exportVaultFiles returns the vault files as base64 for payload serialization.
func exportVaultFiles() map[string]string {
	vaultFilesMu.RLock()
	defer vaultFilesMu.RUnlock()
	if len(vaultFiles) == 0 {
		return nil
	}
	out := make(map[string]string, len(vaultFiles))
	for name, data := range vaultFiles {
		out[name] = base64.StdEncoding.EncodeToString(data)
	}
	return out
}

// ClearVault wipes all vault files from memory (called on lock).
func ClearVault() {
	vaultFilesMu.Lock()
	defer vaultFilesMu.Unlock()
	vaultFiles = nil
}

// SaveLastActiveKeystore persists the name of the last activated keystore
// so it can be auto-loaded on restart.
func SaveLastActiveKeystore(name string) {
	path := filepath.Join(safeio.ProxywatchDataRoot(), "runtime", "active-keystore.txt")
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o700)
	}
	_ = os.WriteFile(path, []byte(name), 0o600)
}

// LoadLastActiveKeystore returns the name of the last activated keystore.
func LoadLastActiveKeystore() string {
	path := filepath.Join(safeio.ProxywatchDataRoot(), "runtime", "active-keystore.txt")
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
