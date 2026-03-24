package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"proxywatch/internal/keystore"
)

const (
	defaultTLSDir       = "tls"
	tlsServerName       = "proxywatch"
	tlsCertFileMode     = 0o644
	tlsPrivateFileMode  = 0o600
	tlsLockRetryDelay   = 100 * time.Millisecond
	tlsLockRetryTimeout = 10 * time.Second
)

type tlsMaterial struct {
	caCertPEM     []byte
	serverCertPEM []byte
	serverKeyPEM  []byte
	clientCertPEM []byte
	clientKeyPEM  []byte
}

type tlsMaterialPaths struct {
	dir        string
	lock       string
	caCert     string
	serverCert string
	serverKey  string
	clientCert string
	clientKey  string
}

var tlsMaterialMu sync.Mutex

func ServerTLSConfig() (*tls.Config, error) {
	material, err := loadOrCreateTLSMaterial()
	if err != nil {
		return nil, err
	}
	if err := ensureServerAuthBootstrap(material); err != nil {
		return nil, err
	}
	serverCert, err := tls.X509KeyPair(material.serverCertPEM, material.serverKeyPEM)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(material.caCertPEM) {
		return nil, errors.New("failed to parse generated CA")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		// Support secure certless agents via token auth while still validating
		// client certificates when provided.
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  pool,
		MinVersion: tls.VersionTLS12,
	}, nil
}

func AgentTLSConfig() (*tls.Config, error) {
	material, err := loadOrCreateTLSMaterial()
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(material.caCertPEM) {
		return nil, errors.New("failed to parse generated CA")
	}
	cfg := &tls.Config{
		RootCAs:    pool,
		ServerName: tlsServerName,
		MinVersion: tls.VersionTLS12,
	}
	if !disableClientCertAuth() {
		clientCert, err := tls.X509KeyPair(material.clientCertPEM, material.clientKeyPEM)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{clientCert}
	}
	return cfg, nil
}

func loadOrCreateTLSMaterial() (tlsMaterial, error) {
	tlsMaterialMu.Lock()
	defer tlsMaterialMu.Unlock()

	paths, err := resolveTLSMaterialPaths()
	if err != nil {
		return tlsMaterial{}, err
	}
	if err := os.MkdirAll(paths.dir, 0o700); err != nil {
		return tlsMaterial{}, err
	}

	return withTLSFileLock(paths, func() (tlsMaterial, error) {
		existing, err := readTLSMaterial(paths)
		if err == nil {
			if err := validateTLSMaterial(existing); err == nil {
				return existing, nil
			}
		}

		generated, err := generateTLSMaterial()
		if err != nil {
			return tlsMaterial{}, err
		}
		if err := writeTLSMaterial(paths, generated); err != nil {
			return tlsMaterial{}, err
		}
		return generated, nil
	})
}

func resolveTLSMaterialPaths() (tlsMaterialPaths, error) {
	dir := strings.TrimSpace(keystore.RuntimeValue("PROXYWATCH_TLS_DIR"))
	if dir == "" {
		dir = defaultTLSDir
	}
	if strings.HasPrefix(dir, "~") {
		expanded, err := expandHome(dir)
		if err != nil {
			return tlsMaterialPaths{}, err
		}
		dir = expanded
	}
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(proxywatchDataRoot(), sanitizeRelativeTLSDir(dir, "tls"))
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return tlsMaterialPaths{}, err
	}
	dir = absDir
	return tlsMaterialPaths{
		dir:        dir,
		lock:       filepath.Join(dir, ".lock"),
		caCert:     filepath.Join(dir, "ca.crt"),
		serverCert: filepath.Join(dir, "server.crt"),
		serverKey:  filepath.Join(dir, "server.key"),
		clientCert: filepath.Join(dir, "client.crt"),
		clientKey:  filepath.Join(dir, "client.key"),
	}, nil
}

func withTLSFileLock(paths tlsMaterialPaths, fn func() (tlsMaterial, error)) (tlsMaterial, error) {
	deadline := time.Now().Add(tlsLockRetryTimeout)
	for {
		lockHandle, err := os.OpenFile(paths.lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, tlsPrivateFileMode)
		if err == nil {
			_ = lockHandle.Close()
			defer os.Remove(paths.lock)
			return fn()
		}
		if !errors.Is(err, os.ErrExist) {
			return tlsMaterial{}, err
		}
		if info, statErr := os.Stat(paths.lock); statErr == nil {
			if time.Since(info.ModTime()) > tlsLockRetryTimeout {
				_ = os.Remove(paths.lock)
				continue
			}
		}
		if time.Now().After(deadline) {
			return tlsMaterial{}, fmt.Errorf("timed out waiting for TLS material lock")
		}
		time.Sleep(tlsLockRetryDelay)
	}
}

func readTLSMaterial(paths tlsMaterialPaths) (tlsMaterial, error) {
	caCert, err := os.ReadFile(paths.caCert)
	if err != nil {
		return tlsMaterial{}, err
	}
	serverCert, err := os.ReadFile(paths.serverCert)
	if err != nil {
		return tlsMaterial{}, err
	}
	serverKey, err := os.ReadFile(paths.serverKey)
	if err != nil {
		return tlsMaterial{}, err
	}
	clientCert, err := os.ReadFile(paths.clientCert)
	if err != nil {
		return tlsMaterial{}, err
	}
	clientKey, err := os.ReadFile(paths.clientKey)
	if err != nil {
		return tlsMaterial{}, err
	}
	material := tlsMaterial{
		caCertPEM:     caCert,
		serverCertPEM: serverCert,
		serverKeyPEM:  serverKey,
		clientCertPEM: clientCert,
		clientKeyPEM:  clientKey,
	}
	return material, validateTLSMaterial(material)
}

func validateTLSMaterial(material tlsMaterial) error {
	serverPair, err := tls.X509KeyPair(material.serverCertPEM, material.serverKeyPEM)
	if err != nil {
		return err
	}
	clientPair, err := tls.X509KeyPair(material.clientCertPEM, material.clientKeyPEM)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(material.caCertPEM) {
		return errors.New("invalid CA PEM")
	}
	now := time.Now().UTC()
	serverLeaf, err := leafCertFromPair(serverPair)
	if err != nil {
		return err
	}
	if _, err := serverLeaf.Verify(x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: now,
		DNSName:     tlsServerName,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return err
	}
	clientLeaf, err := leafCertFromPair(clientPair)
	if err != nil {
		return err
	}
	if _, err := clientLeaf.Verify(x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return err
	}
	return nil
}

func leafCertFromPair(pair tls.Certificate) (*x509.Certificate, error) {
	if len(pair.Certificate) == 0 {
		return nil, errors.New("missing leaf certificate")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	return leaf, nil
}

func writeTLSMaterial(paths tlsMaterialPaths, material tlsMaterial) error {
	if err := writeFileAtomic(paths.caCert, material.caCertPEM, tlsCertFileMode); err != nil {
		return err
	}
	if err := writeFileAtomic(paths.serverCert, material.serverCertPEM, tlsCertFileMode); err != nil {
		return err
	}
	if err := writeFileAtomic(paths.serverKey, material.serverKeyPEM, tlsPrivateFileMode); err != nil {
		return err
	}
	if err := writeFileAtomic(paths.clientCert, material.clientCertPEM, tlsCertFileMode); err != nil {
		return err
	}
	if err := writeFileAtomic(paths.clientKey, material.clientKeyPEM, tlsPrivateFileMode); err != nil {
		return err
	}
	return nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		// Windows rename may fail when destination exists.
		_ = os.Remove(path)
		if retryErr := os.Rename(tmp, path); retryErr == nil {
			return nil
		} else {
			_ = os.Remove(tmp)
			return retryErr
		}
	}
	return nil
}

func generateTLSMaterial() (tlsMaterial, error) {
	now := time.Now().UTC()
	notBefore := now.Add(-5 * time.Minute)
	notAfter := now.AddDate(5, 0, 0)

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tlsMaterial{}, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          randomSerialNumber(),
		Subject:               pkix.Name{CommonName: "proxywatch-ca"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return tlsMaterial{}, err
	}
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tlsMaterial{}, err
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: randomSerialNumber(),
		Subject:      pkix.Name{CommonName: tlsServerName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{tlsServerName, "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		return tlsMaterial{}, err
	}
	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})
	serverKeyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		return tlsMaterial{}, err
	}
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER})

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tlsMaterial{}, err
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: randomSerialNumber(),
		Subject:      pkix.Name{CommonName: "proxywatch-client"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientKey.PublicKey, caKey)
	if err != nil {
		return tlsMaterial{}, err
	}
	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})
	clientKeyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		return tlsMaterial{}, err
	}
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyDER})

	return tlsMaterial{
		caCertPEM:     caCertPEM,
		serverCertPEM: serverCertPEM,
		serverKeyPEM:  serverKeyPEM,
		clientCertPEM: clientCertPEM,
		clientKeyPEM:  clientKeyPEM,
	}, nil
}

func randomSerialNumber() *big.Int {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil || serial == nil || serial.Sign() <= 0 {
		return big.NewInt(time.Now().UnixNano())
	}
	return serial
}

func expandHome(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("empty path")
	}
	if path[0] != '~' {
		return path, nil
	}
	home := strings.TrimSpace(userHomeDir())
	if home == "" {
		return "", fmt.Errorf("home directory not available")
	}
	if path == "~" {
		return home, nil
	}
	if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, "~\\") {
		return filepath.Join(home, path[2:]), nil
	}
	return path, nil
}

func proxywatchDataRoot() string {
	home := userHomeDir()
	if home == "" {
		return ".proxywatch"
	}
	return filepath.Join(home, ".proxywatch")
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

func sanitizeRelativeTLSDir(path, fallback string) string {
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
