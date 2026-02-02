package shared

// CandidateLess defines a consistent ordering for candidates.
func CandidateLess(a, b Candidate) bool {
	priA := RolePriority(a.Role)
	priB := RolePriority(b.Role)
	if priA != priB {
		return priA > priB
	}
	if a.ActiveProxying != b.ActiveProxying {
		return a.ActiveProxying && !b.ActiveProxying
	}
	if a.OutInternal != b.OutInternal {
		return a.OutInternal > b.OutInternal
	}
	if a.OutTotal != b.OutTotal {
		return a.OutTotal > b.OutTotal
	}
	if a.Score == b.Score && a.Proc != nil && b.Proc != nil {
		return a.Proc.Pid < b.Proc.Pid
	}
	return a.Score > b.Score
}
