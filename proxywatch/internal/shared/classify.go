package shared

type ClassifyOptions struct {
	MinScore    int
	RoleFilter  map[string]bool
	Incremental bool
}

type CandidateSignature struct {
	ListenerHash uint64
	ConnHash     uint64
	ProcHash     uint64
}

type ClassifierCache struct {
	Candidates map[int]Candidate
	Signatures map[int]CandidateSignature
}

type ClassifyFunc func(*Snapshot, ClassifyOptions, *ClassifierCache) []Candidate

func RolePriority(role string) int {
	switch role {
	case "reverse-transport":
		return 90
	case "reverse-proxy":
		return 80
	case "proxy-listener":
		return 70
	case "susp-tun":
		return 68
	case "susp-session":
		return 66
	case "susp-beacon":
		return 65
	case "listener-with-clients":
		return 60
	case "listener-with-outbound":
		return 50
	case "reverse-control":
		return 40
	case "reverse-tunnel":
		return 35
	case "listener-only":
		return 30
	case "outbound-only":
		return 10
	default:
		return 0
	}
}

func IsControlChannelRole(role string) bool {
	switch role {
	case "reverse-control", "reverse-transport", "susp-tun", "susp-session", "susp-beacon":
		return true
	default:
		return false
	}
}
