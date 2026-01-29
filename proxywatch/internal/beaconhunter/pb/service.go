package pb

import (
	"context"

	"google.golang.org/grpc"
)

// BeaconHunterClient is the client API for BeaconHunter service.
type BeaconHunterClient interface {
	StreamCandidates(ctx context.Context, opts ...grpc.CallOption) (BeaconHunter_StreamCandidatesClient, error)
}

type beaconHunterClient struct {
	cc grpc.ClientConnInterface
}

func NewBeaconHunterClient(cc grpc.ClientConnInterface) BeaconHunterClient {
	return &beaconHunterClient{cc}
}

func (c *beaconHunterClient) StreamCandidates(ctx context.Context, opts ...grpc.CallOption) (BeaconHunter_StreamCandidatesClient, error) {
	stream, err := c.cc.NewStream(ctx, &BeaconHunter_ServiceDesc.Streams[0], "/beaconhunter.v1.BeaconHunter/StreamCandidates", opts...)
	if err != nil {
		return nil, err
	}
	return &beaconHunterStreamCandidatesClient{stream}, nil
}

// BeaconHunterServer is the server API for BeaconHunter service.
type BeaconHunterServer interface {
	StreamCandidates(BeaconHunter_StreamCandidatesServer) error
}

type BeaconHunter_StreamCandidatesClient interface {
	Send(*ClientMessage) error
	Recv() (*ServerCommand, error)
	grpc.ClientStream
}

type beaconHunterStreamCandidatesClient struct {
	grpc.ClientStream
}

func (x *beaconHunterStreamCandidatesClient) Send(m *ClientMessage) error {
	return x.ClientStream.SendMsg(m)
}

func (x *beaconHunterStreamCandidatesClient) Recv() (*ServerCommand, error) {
	m := new(ServerCommand)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

type BeaconHunter_StreamCandidatesServer interface {
	Recv() (*ClientMessage, error)
	Send(*ServerCommand) error
	grpc.ServerStream
}

type beaconHunterStreamCandidatesServer struct {
	grpc.ServerStream
}

func (x *beaconHunterStreamCandidatesServer) Recv() (*ClientMessage, error) {
	m := new(ClientMessage)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (x *beaconHunterStreamCandidatesServer) Send(m *ServerCommand) error {
	return x.ServerStream.SendMsg(m)
}

// RegisterBeaconHunterServer registers the service implementation with a gRPC server.
func RegisterBeaconHunterServer(s grpc.ServiceRegistrar, srv BeaconHunterServer) {
	s.RegisterService(&BeaconHunter_ServiceDesc, srv)
}

// BeaconHunter_ServiceDesc describes the BeaconHunter service.
var BeaconHunter_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "beaconhunter.v1.BeaconHunter",
	HandlerType: (*BeaconHunterServer)(nil),
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "StreamCandidates",
			Handler:       _BeaconHunter_StreamCandidates_Handler,
			ClientStreams: true,
			ServerStreams: true,
		},
	},
	Metadata: "beaconhunter.proto",
}

func _BeaconHunter_StreamCandidates_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(BeaconHunterServer).StreamCandidates(&beaconHunterStreamCandidatesServer{stream})
}
