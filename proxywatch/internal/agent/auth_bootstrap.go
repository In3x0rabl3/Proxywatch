package agent

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"proxywatch/internal/keystore"
	"proxywatch/internal/safeio"
)

const (
	agentAuthDirName       = "agent"
	agentTokenFileName     = "token"
	agentBootstrapFileName = "bootstrap.json"
	agentBootstrapVersion  = 1
)

type agentBootstrapBundle struct {
	Version     int    `json:"version"`
	GeneratedAt string `json:"generated_at"`
	ServerName  string `json:"server_name"`
	CACertPEM   string `json:"ca_cert_pem"`
	Token       string `json:"token"`
}

// SetAgentToken persists the shared agent token securely to both runtime
// config and local token storage.
func SetAgentToken(token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("empty agent token")
	}
	if err := writeFileAtomic(agentTokenPath(), []byte(token+"\n"), tlsPrivateFileMode); err != nil {
		return err
	}
	if err := persistAgentTokenToKeystore(token); err != nil {
		return err
	}
	values := keystore.ValuesFromRuntime()
	values["PROXYWATCH_AGENT_TOKEN"] = token
	keystore.ApplyToRuntime(values)
	return nil
}

// EnsureServerAgentToken returns the active server-side agent token,
// creating and persisting it when missing.
func EnsureServerAgentToken() (string, error) {
	return ensureServerAgentToken()
}

func ensureServerAuthBootstrap(material tlsMaterial) error {
	token, err := ensureServerAgentToken()
	if err != nil {
		return err
	}

	bundle := agentBootstrapBundle{
		Version:     agentBootstrapVersion,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		ServerName:  tlsServerName,
		CACertPEM:   string(material.caCertPEM),
		Token:       token,
	}
	blob, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	blob = append(blob, '\n')
	return writeFileAtomic(agentBootstrapPath(), blob, tlsPrivateFileMode)
}

func ensureServerAgentToken() (string, error) {
	token := strings.TrimSpace(keystore.RuntimeValue("PROXYWATCH_AGENT_TOKEN"))
	if token == "" {
		token = strings.TrimSpace(readTokenFile(agentTokenPath()))
	}
	if token == "" {
		var err error
		token, err = generateAgentToken()
		if err != nil {
			return "", err
		}
	}

	if err := writeFileAtomic(agentTokenPath(), []byte(token+"\n"), tlsPrivateFileMode); err != nil {
		return "", err
	}
	if err := persistAgentTokenToKeystore(token); err != nil {
		return "", err
	}

	values := keystore.ValuesFromRuntime()
	values["PROXYWATCH_AGENT_TOKEN"] = token
	keystore.ApplyToRuntime(values)
	return token, nil
}

func persistAgentTokenToKeystore(token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("empty agent token")
	}
	path := keystore.DefaultPath()
	values, err := keystore.Load(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		values = keystore.EmptyValues()
	}
	if strings.TrimSpace(values["PROXYWATCH_AGENT_TOKEN"]) == token {
		return nil
	}
	values["PROXYWATCH_AGENT_TOKEN"] = token
	return keystore.Save(path, values)
}

func generateAgentToken() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func loadBootstrapClientTLS() (*tls.Config, string, error) {
	raw, err := safeio.ReadFile(agentBootstrapPath())
	if err != nil {
		return nil, "", err
	}
	var bundle agentBootstrapBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return nil, "", err
	}
	if bundle.Version != agentBootstrapVersion {
		return nil, "", fmt.Errorf("unsupported bootstrap version: %d", bundle.Version)
	}
	caPEM := []byte(strings.TrimSpace(bundle.CACertPEM))
	if len(caPEM) == 0 {
		return nil, "", errors.New("bootstrap missing CA certificate")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, "", errors.New("bootstrap CA certificate is invalid")
	}
	serverName := strings.TrimSpace(bundle.ServerName)
	if serverName == "" {
		serverName = tlsServerName
	}
	token := strings.TrimSpace(bundle.Token)
	if token == "" {
		token = strings.TrimSpace(keystore.RuntimeValue("PROXYWATCH_AGENT_TOKEN"))
	}
	if token != "" {
		values := keystore.ValuesFromRuntime()
		if strings.TrimSpace(values["PROXYWATCH_AGENT_TOKEN"]) == "" {
			values["PROXYWATCH_AGENT_TOKEN"] = token
			keystore.ApplyToRuntime(values)
		}
		_ = writeFileAtomic(agentTokenPath(), []byte(token+"\n"), tlsPrivateFileMode)
	}
	cfg := &tls.Config{
		RootCAs:    pool,
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	}
	return cfg, token, nil
}

func readTokenFile(path string) string {
	raw, err := safeio.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func agentAuthPath(name string) string {
	return filepath.Join(proxywatchDataRoot(), agentAuthDirName, name)
}

func agentTokenPath() string {
	return agentAuthPath(agentTokenFileName)
}

func agentBootstrapPath() string {
	return agentAuthPath(agentBootstrapFileName)
}
