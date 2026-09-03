package auth

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"

	"strings"

	"proxywatch/internal/keystore"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const (
	agentTokenHeader = "x-proxywatch-token"
)

type agentTokenCredentials struct {
	token string
}

func (c agentTokenCredentials) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	token := strings.TrimSpace(c.token)
	if token == "" {
		return map[string]string{}, nil
	}
	return map[string]string{agentTokenHeader: token}, nil
}

func (c agentTokenCredentials) RequireTransportSecurity() bool {
	return true
}

func SecureDialOptionsWithToken(tlsCfg *tls.Config, token string) []grpc.DialOption {
	return SecureDialOptions(tlsCfg, token)
}

func SecureDialOptions(tlsCfg *tls.Config, token string) []grpc.DialOption {
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(JSONCodec())),
	}
	token = strings.TrimSpace(token)
	if token == "" {
		token = strings.TrimSpace(keystore.RuntimeValue("PROXYWATCH_AGENT_TOKEN"))
	}
	if token == "" {
		token = strings.TrimSpace(ReadTokenFile(AgentTokenPath()))
	}
	if token != "" {
		opts = append(opts, grpc.WithPerRPCCredentials(agentTokenCredentials{token: token}))
	}
	return opts
}

func AgentStreamAuthInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv any,
		ss grpc.ServerStream,
		_ *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		if err := AuthorizeAgentConnection(ss.Context()); err != nil {
			return status.Error(codes.Unauthenticated, err.Error())
		}
		return handler(srv, ss)
	}
}

func AuthorizeAgentConnection(ctx context.Context) error {
	if HasVerifiedClientCert(ctx) {
		return nil
	}

	expectedToken := ExpectedAgentToken()
	if expectedToken == "" {
		return errors.New("agent authentication token is not configured")
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return errors.New("missing auth metadata")
	}
	values := md.Get(agentTokenHeader)
	if len(values) == 0 {
		return errors.New("missing agent token")
	}
	actual := strings.TrimSpace(values[0])
	if subtle.ConstantTimeCompare([]byte(actual), []byte(expectedToken)) != 1 {
		return errors.New("invalid agent token")
	}
	return nil
}

func ExpectedAgentToken() string {
	token := strings.TrimSpace(keystore.RuntimeValue("PROXYWATCH_AGENT_TOKEN"))
	if token != "" {
		return token
	}
	return strings.TrimSpace(ReadTokenFile(AgentTokenPath()))
}

func HasVerifiedClientCert(ctx context.Context) bool {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil {
		return false
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return false
	}
	return len(tlsInfo.State.VerifiedChains) > 0
}

func DisableClientCertAuth() bool {
	raw := strings.TrimSpace(strings.ToLower(keystore.RuntimeValue("PROXYWATCH_DISABLE_CLIENT_CERT")))
	switch raw {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}
