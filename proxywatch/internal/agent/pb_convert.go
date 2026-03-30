package agent

import (
	"time"

	"proxywatch/internal/agent/pb"
	"proxywatch/internal/shared"
)

const (
	maxInt32Value = int(^uint32(0) >> 1)
	minInt32Value = -maxInt32Value - 1
)

func ToEnvelope(host string, ts time.Time, cands []shared.Candidate) *pb.CandidateEnvelope {
	out := &pb.CandidateEnvelope{
		HostId:        host,
		TimestampUnix: ts.Unix(),
		Candidates:    make([]*pb.Candidate, 0, len(cands)),
	}
	for i := range cands {
		out.Candidates = append(out.Candidates, ToPBCandidate(cands[i]))
	}
	return out
}

func ToPBCandidate(c shared.Candidate) *pb.Candidate {
	p := ToPBProcess(c.Proc)
	out := &pb.Candidate{
		Host:                   c.Host,
		Proc:                   p,
		Score:                  clampInt32(c.Score),
		Confidence:             clampInt32(c.Confidence),
		Reasons:                append([]string(nil), c.Reasons...),
		Signals:                append([]string(nil), c.Signals...),
		Role:                   c.Role,
		ActiveProxying:         c.ActiveProxying,
		ControlChannel:         ToPBConn(c.ControlChannel),
		ControlDurationSeconds: clampInt32(c.ControlDurationSeconds),
		OutTotal:               clampInt32(c.OutTotal),
		OutExternal:            clampInt32(c.OutExternal),
		OutInternal:            clampInt32(c.OutInternal),
		OutLoopback:            clampInt32(c.OutLoopback),
		OutLongLived:           clampInt32(c.OutLongLived),
		OutShortLived:          clampInt32(c.OutShortLived),
		InboundTotal:           clampInt32(c.InboundTotal),
		TrafficVerified:        c.TrafficVerified,
		StrongEvidence:         c.StrongEvidence,
	}
	for _, l := range c.Listeners {
		out.Listeners = append(out.Listeners, ToPBListener(l))
	}
	for _, cn := range c.Conns {
		out.Conns = append(out.Conns, ToPBConn(&cn))
	}
	for _, ul := range c.UDPListeners {
		out.UDPListeners = append(out.UDPListeners, ToPBUDP(ul))
	}
	return out
}

func FromPBCandidate(p *pb.Candidate, host string) shared.Candidate {
	if p == nil {
		return shared.Candidate{}
	}
	h := p.Host
	if h == "" {
		h = host
	}
	out := shared.Candidate{
		Host:                   h,
		Proc:                   FromPBProcess(p.Proc),
		Score:                  int(p.Score),
		Confidence:             int(p.Confidence),
		Reasons:                append([]string(nil), p.Reasons...),
		Signals:                append([]string(nil), p.Signals...),
		Role:                   p.Role,
		ActiveProxying:         p.ActiveProxying,
		ControlChannel:         FromPBConn(p.ControlChannel),
		ControlDurationSeconds: int(p.ControlDurationSeconds),
		OutTotal:               int(p.OutTotal),
		OutExternal:            int(p.OutExternal),
		OutInternal:            int(p.OutInternal),
		OutLoopback:            int(p.OutLoopback),
		OutLongLived:           int(p.OutLongLived),
		OutShortLived:          int(p.OutShortLived),
		InboundTotal:           int(p.InboundTotal),
		TrafficVerified:        p.TrafficVerified,
		StrongEvidence:         p.StrongEvidence,
	}
	for _, l := range p.Listeners {
		if l == nil {
			continue
		}
		out.Listeners = append(out.Listeners, FromPBListener(l))
	}
	for _, cn := range p.Conns {
		if cn == nil {
			continue
		}
		if v := FromPBConn(cn); v != nil {
			out.Conns = append(out.Conns, *v)
		}
	}
	for _, ul := range p.UDPListeners {
		if ul == nil {
			continue
		}
		out.UDPListeners = append(out.UDPListeners, FromPBUDP(ul))
	}
	return out
}

func ToPBProcess(p *shared.ProcessInfo) *pb.ProcessInfo {
	if p == nil {
		return nil
	}
	return &pb.ProcessInfo{
		Pid:          clampInt32(p.Pid),
		ParentPid:    clampInt32(p.ParentPid),
		Name:         p.Name,
		SessionId:    p.SessionID,
		SessionName:  p.SessionName,
		MemUsage:     p.MemUsage,
		Status:       p.Status,
		UserName:     p.UserName,
		ExePath:      p.ExePath,
		Company:      p.Company,
		Integrity:    p.Integrity,
		IOReadBytes:  p.IOReadBytes,
		IOWriteBytes: p.IOWriteBytes,
		IOOtherBytes: p.IOOtherBytes,
		IOReadBps:    p.IOReadBps,
		IOWriteBps:   p.IOWriteBps,
		IOOtherBps:   p.IOOtherBps,
		CpuTimeNanos: int64(p.CpuTime),
		WindowTitle:  p.WindowTitle,
		CmdLine:      p.CmdLine,
		LoadedLibs:   append([]string(nil), p.LoadedLibs...),
	}
}

func FromPBProcess(p *pb.ProcessInfo) *shared.ProcessInfo {
	if p == nil {
		return nil
	}
	return &shared.ProcessInfo{
		Pid:          int(p.Pid),
		ParentPid:    int(p.ParentPid),
		Name:         p.Name,
		SessionID:    p.SessionId,
		SessionName:  p.SessionName,
		MemUsage:     p.MemUsage,
		Status:       p.Status,
		UserName:     p.UserName,
		ExePath:      p.ExePath,
		Company:      p.Company,
		Integrity:    p.Integrity,
		IOReadBytes:  p.IOReadBytes,
		IOWriteBytes: p.IOWriteBytes,
		IOOtherBytes: p.IOOtherBytes,
		IOReadBps:    p.IOReadBps,
		IOWriteBps:   p.IOWriteBps,
		IOOtherBps:   p.IOOtherBps,
		CpuTime:      time.Duration(p.CpuTimeNanos),
		WindowTitle:  p.WindowTitle,
		CmdLine:      p.CmdLine,
		LoadedLibs:   append([]string(nil), p.LoadedLibs...),
	}
}

func ToPBListener(l shared.ListenerInfo) *pb.ListenerInfo {
	return &pb.ListenerInfo{
		Pid:          clampInt32(l.Pid),
		LocalAddress: l.LocalAddress,
		LocalPort:    clampInt32(l.LocalPort),
		State:        l.State,
	}
}

func FromPBListener(l *pb.ListenerInfo) shared.ListenerInfo {
	return shared.ListenerInfo{
		Pid:          int(l.Pid),
		LocalAddress: l.LocalAddress,
		LocalPort:    int(l.LocalPort),
		State:        l.State,
	}
}

func ToPBConn(cn *shared.ConnectionInfo) *pb.ConnectionInfo {
	if cn == nil {
		return nil
	}
	return &pb.ConnectionInfo{
		Pid:           clampInt32(cn.Pid),
		LocalAddress:  cn.LocalAddress,
		LocalPort:     clampInt32(cn.LocalPort),
		RemoteAddress: cn.RemoteAddress,
		RemotePort:    clampInt32(cn.RemotePort),
		State:         cn.State,
	}
}

func FromPBConn(cn *pb.ConnectionInfo) *shared.ConnectionInfo {
	if cn == nil {
		return nil
	}
	return &shared.ConnectionInfo{
		Pid:           int(cn.Pid),
		LocalAddress:  cn.LocalAddress,
		LocalPort:     int(cn.LocalPort),
		RemoteAddress: cn.RemoteAddress,
		RemotePort:    int(cn.RemotePort),
		State:         cn.State,
	}
}

func ToPBUDP(u shared.UDPListenerInfo) *pb.UDPListenerInfo {
	return &pb.UDPListenerInfo{
		Pid:          clampInt32(u.Pid),
		LocalAddress: u.LocalAddress,
		LocalPort:    clampInt32(u.LocalPort),
	}
}

func FromPBUDP(u *pb.UDPListenerInfo) shared.UDPListenerInfo {
	return shared.UDPListenerInfo{
		Pid:          int(u.Pid),
		LocalAddress: u.LocalAddress,
		LocalPort:    int(u.LocalPort),
	}
}

func clampInt32(v int) int32 {
	if v > maxInt32Value {
		return int32(maxInt32Value)
	}
	if v < minInt32Value {
		return int32(minInt32Value)
	}
	return int32(v)
}
