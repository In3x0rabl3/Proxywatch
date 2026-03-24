package pb

import (
	"context"

	"google.golang.org/grpc"
)

// ProxyWatchAgentClient is the client API for ProxyWatchAgent service.
type ProxyWatchAgentClient interface {
	StreamCandidates(ctx context.Context, opts ...grpc.CallOption) (ProxyWatchAgent_StreamCandidatesClient, error)
	Enroll(ctx context.Context, in *EnrollRequest, opts ...grpc.CallOption) (*EnrollResponse, error)
}

type proxyWatchAgentClient struct {
	cc grpc.ClientConnInterface
}

func NewProxyWatchAgentClient(cc grpc.ClientConnInterface) ProxyWatchAgentClient {
	return &proxyWatchAgentClient{cc}
}

func (c *proxyWatchAgentClient) StreamCandidates(ctx context.Context, opts ...grpc.CallOption) (ProxyWatchAgent_StreamCandidatesClient, error) {
	stream, err := c.cc.NewStream(ctx, &ProxyWatchAgent_ServiceDesc.Streams[0], "/proxywatch.agent.v1.ProxyWatchAgent/StreamCandidates", opts...)
	if err != nil {
		return nil, err
	}
	return &proxyWatchAgentStreamCandidatesClient{stream}, nil
}

func (c *proxyWatchAgentClient) Enroll(ctx context.Context, in *EnrollRequest, opts ...grpc.CallOption) (*EnrollResponse, error) {
	out := new(EnrollResponse)
	err := c.cc.Invoke(ctx, "/proxywatch.agent.v1.ProxyWatchAgent/Enroll", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ProxyWatchAgentServer is the server API for ProxyWatchAgent service.
type ProxyWatchAgentServer interface {
	StreamCandidates(ProxyWatchAgent_StreamCandidatesServer) error
	Enroll(context.Context, *EnrollRequest) (*EnrollResponse, error)
}

type ProxyWatchAgent_StreamCandidatesClient interface {
	Send(*ClientMessage) error
	Recv() (*ServerCommand, error)
	grpc.ClientStream
}

type proxyWatchAgentStreamCandidatesClient struct {
	grpc.ClientStream
}

func (x *proxyWatchAgentStreamCandidatesClient) Send(m *ClientMessage) error {
	return x.ClientStream.SendMsg(m)
}

func (x *proxyWatchAgentStreamCandidatesClient) Recv() (*ServerCommand, error) {
	m := new(ServerCommand)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

type ProxyWatchAgent_StreamCandidatesServer interface {
	Recv() (*ClientMessage, error)
	Send(*ServerCommand) error
	grpc.ServerStream
}

type proxyWatchAgentStreamCandidatesServer struct {
	grpc.ServerStream
}

func (x *proxyWatchAgentStreamCandidatesServer) Recv() (*ClientMessage, error) {
	m := new(ClientMessage)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (x *proxyWatchAgentStreamCandidatesServer) Send(m *ServerCommand) error {
	return x.ServerStream.SendMsg(m)
}

// RegisterProxyWatchAgentServer registers the service implementation with a gRPC server.
func RegisterProxyWatchAgentServer(s grpc.ServiceRegistrar, srv ProxyWatchAgentServer) {
	s.RegisterService(&ProxyWatchAgent_ServiceDesc, srv)
}

// ProxyWatchAgent_ServiceDesc describes the ProxyWatchAgent service.
var ProxyWatchAgent_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "proxywatch.agent.v1.ProxyWatchAgent",
	HandlerType: (*ProxyWatchAgentServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Enroll",
			Handler:    _ProxyWatchAgent_Enroll_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "StreamCandidates",
			Handler:       _ProxyWatchAgent_StreamCandidates_Handler,
			ClientStreams: true,
			ServerStreams: true,
		},
	},
	Metadata: "proxywatch_agent.proto",
}

func _ProxyWatchAgent_StreamCandidates_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(ProxyWatchAgentServer).StreamCandidates(&proxyWatchAgentStreamCandidatesServer{stream})
}

func _ProxyWatchAgent_Enroll_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EnrollRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ProxyWatchAgentServer).Enroll(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proxywatch.agent.v1.ProxyWatchAgent/Enroll",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ProxyWatchAgentServer).Enroll(ctx, req.(*EnrollRequest))
	}
	return interceptor(ctx, in, info, handler)
}
