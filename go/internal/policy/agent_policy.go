package policy

import (
	"sort"

	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/hris"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/subject"
)

// Agent access policy — the agent analog of DepartmentRoles. An AI agent's
// access is derived entirely from its declared capability Scope, never granted
// by hand, so a decommissioned agent maps to the empty role set exactly like a
// terminated employee. This is what extends the offboarding-is-total invariant
// (Lean: terminated_subject_loses_all_access) to agent workloads.

// ScopeRoles maps an agent capability to the Teleport roles it needs. Kept
// deliberately least-privilege: a memory store needs only read access, etc.
func (p Policy) scopeRoles() map[string][]string {
	return map[string][]string{
		"kyra-memory":   {"db-readonly"},   // the agent's vector/memory store
		"kyra-calendar": {"crm-access"},    // a calendar tool added on "move"
		"mcp-gateway":   {"k8s-staging"},   // an MCP server fronting tools
	}
}

// RolesForAgent returns the sorted, de-duplicated Teleport roles an agent is
// entitled to. A terminated/decommissioned agent is entitled to nothing.
func (p Policy) RolesForAgent(s subject.Subject) []string {
	if s.Status == hris.Terminated {
		return nil
	}
	sr := p.scopeRoles()
	set := map[string]struct{}{}
	for _, cap := range s.Scope {
		for _, r := range sr[cap] {
			set[r] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// SpiffePathFor returns the SPIFFE path the agent's identity should template to.
// Trust domain is supplied by the cluster; only the path is policy-controlled.
func (p Policy) SpiffePathFor(s subject.Subject) string {
	return "/agents/" + s.Name + "/{{ user.name }}"
}
