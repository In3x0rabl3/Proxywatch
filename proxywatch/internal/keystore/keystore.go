package keystore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
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

func DefaultPath() string {
	return defaultPath
}

func NormalizePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		path = defaultPath
	}
	path = expandHomePath(path)
	if filepath.IsAbs(path) {
		return path
	}
	rel := sanitizeRelativePath(path, "keystore.enc")
	home := userHomeDir()
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

func RuntimeValue(key string) string {
	runtimeMu.RLock()
	defer runtimeMu.RUnlock()
	return strings.TrimSpace(runtimeValues[strings.TrimSpace(key)])
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
		return value
	}
	if len(value) <= 6 {
		return strings.Repeat("*", len(value))
	}
	return value[:3] + strings.Repeat("*", len(value)-6) + value[len(value)-3:]
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

func expandHomePath(path string) string {
	if path == "" || path[0] != '~' {
		return path
	}
	home := userHomeDir()
	if home == "" {
		return path
	}
	if path == "~" {
		return home
	}
	if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, "~\\") {
		return filepath.Join(home, path[2:])
	}
	return path
}

func userHomeDir() string {
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		return strings.TrimSpace(home)
	}
	for _, key := range []string{"HOME", "USERPROFILE"} {
		if val := strings.TrimSpace(os.Getenv(key)); val != "" {
			return val
		}
	}
	drive := strings.TrimSpace(os.Getenv("HOMEDRIVE"))
	path := strings.TrimSpace(os.Getenv("HOMEPATH"))
	if drive != "" && path != "" {
		return drive + path
	}
	return ""
}

func sanitizeRelativePath(path, fallback string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return fallback
	}
	path = filepath.Clean(path)
	if path == "." || path == "" {
		return fallback
	}
	if strings.HasPrefix(path, ".proxywatch"+string(filepath.Separator)) {
		path = strings.TrimPrefix(path, ".proxywatch"+string(filepath.Separator))
	}
	for strings.HasPrefix(path, "."+string(filepath.Separator)) {
		path = strings.TrimPrefix(path, "."+string(filepath.Separator))
	}
	path = strings.TrimLeft(path, string(filepath.Separator))
	parentPrefix := ".." + string(filepath.Separator)
	for path == ".." || strings.HasPrefix(path, parentPrefix) {
		if path == ".." {
			return fallback
		}
		path = strings.TrimPrefix(path, parentPrefix)
	}
	if path == "" || path == "." {
		return fallback
	}
	return path
}
