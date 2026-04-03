package keystore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/pbkdf2"
	"proxywatch/internal/safeio"
)

// secureEnvelope wraps the encrypted data with the HMAC challenge.
type secureEnvelope struct {
	Version    int    `json:"version"`
	Secure     bool   `json:"secure"`
	Slot       string `json:"slot"`      // HMAC slot used (e.g., "1" or "2")
	Challenge  string `json:"challenge"` // hex-encoded random challenge
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

const pbkdf2Iterations = 600_000

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
		Files:     exportVaultFiles(),
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
	initVaultFiles(pl)
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
	initVaultFiles(pl)
	return sanitizeValues(pl.Values), nil
}

// SaveNonSecure saves a non-encrypted keystore (plain JSON).
func SaveNonSecure(path string, values map[string]string) error {
	data, err := json.MarshalIndent(payload{
		UpdatedAt: time.Now().UTC(),
		Values:    sanitizeValues(values),
		Files:     exportVaultFiles(),
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

// ── Password-protected keystore ─────────────────────────────────────────────
// Uses PBKDF2-SHA256 (600k iterations) + AES-256-GCM. The salt is stored in
// the secureEnvelope's Challenge field; Slot is set to "password".

// SavePassword encrypts and saves a keystore using a password.
func SavePassword(path, password string, values map[string]string) error {
	if password == "" {
		return fmt.Errorf("password is required")
	}

	// Generate random 32-byte salt.
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("salt generation: %w", err)
	}

	// Derive AES-256 key from password + salt.
	key := pbkdf2.Key([]byte(password), salt, pbkdf2Iterations, 32, sha256.New)

	toStore := sanitizeValues(values)
	data, err := json.Marshal(payload{
		UpdatedAt: time.Now().UTC(),
		Values:    toStore,
		Files:     exportVaultFiles(),
	})
	if err != nil {
		return err
	}

	// Encrypt with AES-256-GCM.
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
	env := secureEnvelope{
		Version:    2,
		Secure:     true,
		Slot:       "password",
		Challenge:  hex.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, dirMode)
	}
	return os.WriteFile(path, out, fileMode)
}

// LoadPassword decrypts a password-protected keystore.
func LoadPassword(path, password string) (map[string]string, error) {
	raw, err := safeio.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var env secureEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("invalid keystore file")
	}
	if env.Slot != "password" {
		return nil, fmt.Errorf("not a password-protected keystore")
	}

	// Decode salt from challenge field.
	salt, err := hex.DecodeString(env.Challenge)
	if err != nil || len(salt) == 0 {
		return nil, fmt.Errorf("invalid salt in keystore")
	}

	// Derive key from password + salt.
	key := pbkdf2.Key([]byte(password), salt, pbkdf2Iterations, 32, sha256.New)

	// Decode nonce and ciphertext.
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext")
	}

	// Decrypt with AES-256-GCM.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("wrong password or corrupted keystore")
	}

	var pl payload
	if err := json.Unmarshal(plaintext, &pl); err != nil {
		return nil, fmt.Errorf("invalid decrypted payload")
	}
	initVaultFiles(pl)
	return sanitizeValues(pl.Values), nil
}

// IsPasswordKeystore returns true if the file at path is a password-protected keystore.
func IsPasswordKeystore(path string) bool {
	raw, err := safeio.ReadFile(path)
	if err != nil {
		return false
	}
	var env secureEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return false
	}
	return env.Secure && env.Slot == "password"
}

// Save encrypts and saves a keystore using the local machine key.
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
		Files:     exportVaultFiles(),
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

// Load decrypts and loads a keystore using the local machine key.
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
	initVaultFiles(pl)
	return sanitizeValues(pl.Values), nil
}

// sanitizeValues returns a clean copy of the values map with only managed keys.
func sanitizeValues(values map[string]string) map[string]string {
	out := make(map[string]string, len(ManagedKeys))
	for _, key := range ManagedKeys {
		out[key] = strings.TrimSpace(values[key])
	}
	return out
}

// loadMasterKey loads or creates the local encryption key for a keystore.
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
