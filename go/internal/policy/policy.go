// Package policy is the access policy-as-code that maps an identity to the set
// of Teleport roles it is entitled to. This is the Go mirror of the Terraform
// in ../../terraform — the same department->role mapping expressed twice so the
// engine can reason about it at runtime and Terraform can enforce it as the
// source of truth in the cluster.
//
// Principle: access is derived entirely from the HR record. Nobody is granted a
// role by hand, so offboarding is total by construction — a terminated identity
// maps to the empty role set (see RolesFor + the Lean proof in ../../lean).
package policy

import (
	"sort"
	"time"

	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/hris"
)

// Policy is the full entitlement model.
type Policy struct {
	// DepartmentRoles maps an HR department to the Teleport roles it grants.
	DepartmentRoles map[string][]string
	// TitleRoles grants extra roles based on title (e.g. "Manager" gets the
	// access-reviewer role). Additive on top of department roles.
	TitleRoles map[string][]string
	// AutoApprovableRoles lists roles a user may request just-in-time and have
	// auto-granted without human review, keyed by the role they already hold.
	AutoApprovableRoles map[string][]string
	// MaxSessionTTL caps how long any issued certificate lives. Short-lived by
	// default — this is the whole point of Teleport.
	MaxSessionTTL time.Duration
}

// Default returns the baseline Teleport entitlement model used in the demo.
// In production this is generated from the Terraform state so the two never
// drift.
func Default() Policy {
	return Policy{
		DepartmentRoles: map[string][]string{
			"Engineering": {"dev-access", "k8s-staging"},
			"SRE":         {"dev-access", "k8s-prod", "db-readonly"},
			"Security":    {"auditor", "db-readonly"},
			"IT":          {"it-admin", "device-admin"},
			"Sales":       {"crm-access"},
			"Finance":     {"finance-app", "db-readonly"},
		},
		TitleRoles: map[string][]string{
			"Manager":   {"access-reviewer"},
			"Director":  {"access-reviewer"},
			"VP":        {"access-reviewer"},
			"Incident Commander": {"break-glass-eligible"},
		},
		AutoApprovableRoles: map[string][]string{
			// An SRE holding k8s-prod may auto-request db-readonly for an oncall
			// shift; anything else needs a human approver.
			"dev-access": {"k8s-staging"},
			"k8s-prod":   {"db-readonly"},
		},
		MaxSessionTTL: 8 * time.Hour,
	}
}

// RolesFor computes the complete, sorted, de-duplicated set of Teleport roles an
// employee is entitled to. A terminated employee is entitled to nothing — this
// single line is what makes offboarding provably complete.
func (p Policy) RolesFor(emp hris.Employee) []string {
	if emp.Status == hris.Terminated {
		return nil
	}
	set := map[string]struct{}{}
	for _, r := range p.DepartmentRoles[emp.Department] {
		set[r] = struct{}{}
	}
	for _, r := range p.TitleRoles[emp.Title] {
		set[r] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// CanAutoApprove reports whether a user already holding `held` roles may have
// `requested` granted just-in-time without human review.
func (p Policy) CanAutoApprove(held []string, requested string) bool {
	for _, h := range held {
		for _, allowed := range p.AutoApprovableRoles[h] {
			if allowed == requested {
				return true
			}
		}
	}
	return false
}
