package agent

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
)

func ServerTLSConfig() (*tls.Config, error) {
	serverCert, err := tls.X509KeyPair([]byte(generatedServerCertPEM), []byte(generatedServerKeyPEM))
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

func AgentTLSConfig() (*tls.Config, error) {
	clientCert, err := tls.X509KeyPair([]byte(generatedClientCertPEM), []byte(generatedClientKeyPEM))
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
