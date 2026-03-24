package agent

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	enrollContextV1 = "proxywatch-enroll-v1"
	enrollMaxSkew   = 5 * time.Minute
)

func buildEnrollClientProof(token, clientNonce string, clientUnix int64) string {
	payload := fmt.Sprintf("%s|client|%s|%d", enrollContextV1, strings.TrimSpace(clientNonce), clientUnix)
	return hmacTokenHex(token, payload)
}

func buildEnrollServerProof(token, clientNonce string, clientUnix int64, serverNonce, serverFingerprint string) string {
	payload := fmt.Sprintf(
		"%s|server|%s|%d|%s|%s",
		enrollContextV1,
		strings.TrimSpace(clientNonce),
		clientUnix,
		strings.TrimSpace(serverNonce),
		strings.ToLower(strings.TrimSpace(serverFingerprint)),
	)
	return hmacTokenHex(token, payload)
}

func hmacTokenHex(token, payload string) string {
	mac := hmac.New(sha256.New, []byte(strings.TrimSpace(token)))
	_, _ = mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func constantTimeHexEqual(a, b string) bool {
	a = strings.ToLower(strings.TrimSpace(a))
	b = strings.ToLower(strings.TrimSpace(b))
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func randomNonceBase64(size int) (string, error) {
	if size <= 0 {
		size = 24
	}
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func withinEnrollmentSkew(clientUnix int64, now time.Time) bool {
	if clientUnix <= 0 {
		return false
	}
	ts := time.Unix(clientUnix, 0).UTC()
	diff := now.UTC().Sub(ts)
	if diff < 0 {
		diff = -diff
	}
	return diff <= enrollMaxSkew
}

func validFingerprintHex(pin string) bool {
	pin = strings.ToLower(strings.TrimSpace(pin))
	if pin == "" {
		return false
	}
	if _, err := hex.DecodeString(pin); err != nil {
		return false
	}
	return len(pin) == sha256.Size*2
}

func tlsConfigLeafFingerprint(cfg *tls.Config) (string, error) {
	if cfg == nil || len(cfg.Certificates) == 0 {
		return "", errors.New("missing server certificate")
	}
	chain := cfg.Certificates[0].Certificate
	if len(chain) == 0 || len(chain[0]) == 0 {
		return "", errors.New("missing server leaf certificate")
	}
	return certFingerprint(chain[0]), nil
}
