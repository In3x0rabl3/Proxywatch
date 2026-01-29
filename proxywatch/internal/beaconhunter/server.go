package beaconhunter

import (
	"fmt"
	"io"
	"net"
	"time"

	"proxywatch/internal/beaconhunter/pb"
	"proxywatch/internal/shared"

	"google.golang.org/grpc"
)

type Server struct {
	Store *Store
}

func (s *Server) StreamCandidates(stream pb.BeaconHunter_StreamCandidatesServer) error {
	if s.Store == nil {
		return fmt.Errorf("store not configured")
	}
	for {
		env, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&pb.StreamAck{Message: "ok"})
		}
		if err != nil {
			return err
		}
		host := env.HostId
		ts := time.Unix(env.TimestampUnix, 0).UTC()
		cands := make([]shared.Candidate, 0, len(env.Candidates))
		for _, c := range env.Candidates {
			if c == nil {
				continue
			}
			cands = append(cands, FromPBCandidate(c, host))
		}
		s.Store.Update(host, ts, cands)
	}
}

func ListenAndServe(addr string, store *Store) (*grpc.Server, net.Listener, error) {
	if store == nil {
		return nil, nil, fmt.Errorf("store is nil")
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, err
	}

	grpcServer := grpc.NewServer(grpc.ForceServerCodec(jsonCodec{}))
	pb.RegisterBeaconHunterServer(grpcServer, &Server{Store: store})

	go func() {
		_ = grpcServer.Serve(lis)
	}()

	return grpcServer, lis, nil
}
