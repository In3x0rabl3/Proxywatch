package beaconhunter

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"time"
)

func ServerTLSConfig() (*tls.Config, error) {
	caCert, err := parseCert([]byte(generatedCACertPEM))
	if err != nil {
		return nil, err
	}
	caKey, err := parseECPrivateKey([]byte(generatedCAKeyPEM))
	if err != nil {
		return nil, err
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serverTmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: "proxywatch"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"proxywatch"},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTmpl, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	serverCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}),
		mustMarshalECPrivateKey(serverKey),
	)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(generatedCACertPEM)) {
		return nil, errors.New("failed to parse embedded CA")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func AgentTLSConfig(hostID string) (*tls.Config, error) {
	caCert, err := parseCert([]byte(generatedCACertPEM))
	if err != nil {
		return nil, err
	}
	caKey, err := parseECPrivateKey([]byte(generatedCAKeyPEM))
	if err != nil {
		return nil, err
	}

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	clientTmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: hostID},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTmpl, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	clientCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}),
		mustMarshalECPrivateKey(clientKey),
	)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(generatedCACertPEM)) {
		return nil, errors.New("failed to parse embedded CA")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      pool,
		ServerName:   "proxywatch",
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func parseCert(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("invalid certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseECPrivateKey(pemData []byte) (*ecdsa.PrivateKey, error) {
	for {
		block, rest := pem.Decode(pemData)
		if block == nil {
			break
		}
		if block.Type == "EC PRIVATE KEY" {
			return x509.ParseECPrivateKey(block.Bytes)
		}
		pemData = rest
	}
	return nil, errors.New("invalid EC private key PEM")
}

func mustMarshalECPrivateKey(key *ecdsa.PrivateKey) []byte {
	b, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
}

func randomSerial() *big.Int {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 62)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return big.NewInt(1)
	}
	return serial
}
