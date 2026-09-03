package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"proxywatch/internal/keystore"
	"proxywatch/internal/safeio"
)

const (
	agentTrustDirName = "trust"
)

func DialWithPinnedOrTOFU(
	ctxDial func(*tls.Config) error,
	addr string,
) error {
	pin, err := loadPinnedServerFingerprint(addr)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && trustOnFirstUseEnabled() {
			return dialWithTrustOnFirstUse(ctxDial, addr)
		}
		return fmt.Errorf("pinned trust unavailable (%s): %w", AgentTrustPath(addr), err)
	}
	if pin == "" {
		return fmt.Errorf("empty trust pin")
	}
	cfg, err := tlsConfigWithPinnedServerCert(pin)
	if err != nil {
		return err
	}
	return ctxDial(cfg)
}

func loadPinnedServerFingerprint(addr string) (string, error) {
	raw, err := os.ReadFile(AgentTrustPath(addr))
	if err != nil {
		return "", err
	}
	pin := strings.TrimSpace(string(raw))
	if pin == "" {
		return "", fmt.Errorf("empty trust pin")
	}
	if _, err := hex.DecodeString(pin); err != nil {
		return "", fmt.Errorf("invalid trust pin: %w", err)
	}
	return strings.ToLower(pin), nil
}

func tlsConfigWithPinnedServerCert(pin string) (*tls.Config, error) {
	pin = strings.ToLower(strings.TrimSpace(pin))
	if pin == "" {
		return nil, fmt.Errorf("empty trust pin")
	}
	if _, err := hex.DecodeString(pin); err != nil {
		return nil, fmt.Errorf("invalid trust pin: %w", err)
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("server did not present certificate")
			}
			got := CertFingerprint(cs.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare([]byte(got), []byte(pin)) != 1 {
				return fmt.Errorf("server certificate fingerprint mismatch")
			}
			return nil
		},
	}, nil
}

func CertFingerprint(rawCert []byte) string {
	sum := sha256.Sum256(rawCert)
	return hex.EncodeToString(sum[:])
}

func trustOnFirstUseEnabled() bool {
	raw := strings.TrimSpace(strings.ToLower(keystore.RuntimeValue("PROXYWATCH_TRUST_ON_FIRST_USE")))
	switch raw {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func dialWithTrustOnFirstUse(ctxDial func(*tls.Config) error, addr string) error {
	var observedPin string
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("server did not present certificate")
			}
			observedPin = CertFingerprint(cs.PeerCertificates[0].Raw)
			return nil
		},
	}
	if err := ctxDial(cfg); err != nil {
		return err
	}
	if observedPin == "" {
		return errors.New("failed to capture server fingerprint")
	}
	return SavePinnedServerFingerprint(addr, observedPin)
}

func SavePinnedServerFingerprint(addr, pin string) error {
	pin = strings.ToLower(strings.TrimSpace(pin))
	if pin == "" {
		return errors.New("empty trust pin")
	}
	if _, err := hex.DecodeString(pin); err != nil {
		return fmt.Errorf("invalid trust pin: %w", err)
	}
	path := AgentTrustPath(addr)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return WriteFileAtomic(path, []byte(pin+"\n"), TLSPrivateFileMode)
}

func AgentTrustPath(addr string) string {
	name := strings.TrimSpace(strings.ToLower(addr))
	if name == "" {
		name = "server"
	}
	encoded := base64.RawURLEncoding.EncodeToString([]byte(name))
	return filepath.Join(safeio.ProxywatchDataRoot(), AgentAuthDirName, agentTrustDirName, encoded+".pin")
}
