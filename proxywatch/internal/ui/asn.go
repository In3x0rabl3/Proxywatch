package ui

import "proxywatch/internal/shared"

func inspectorExternalOrgs(cand *shared.Candidate) (orgs []string, pending int, failed int) {
	if cand == nil {
		return nil, 0, 0
	}
	return shared.ResolveExternalASNOrgs(cand.Conns)
}
