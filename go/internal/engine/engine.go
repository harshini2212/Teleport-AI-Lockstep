// Package engine is the reconciliation core: given a lifecycle event and the
// access policy, it computes the desired Teleport state, diffs it against the
// live cluster, and applies the minimal set of actions to converge. It is the
// "controller" an IT Security & Automation Engineer would run as a daemon
// reacting to Rippling/Okta webhooks.
package engine

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/hris"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/policy"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/teleport"
)

// ActionKind enumerates the access-plane mutations the engine can emit.
type ActionKind string

const (
	Provision   ActionKind = "provision"    // create user with entitled roles
	UpdateRoles ActionKind = "update_roles"  // reconcile roles after a move
	Deprovision ActionKind = "deprovision"   // delete user (leaver)
	Lock        ActionKind = "lock"          // sever active access immediately
	NoOp        ActionKind = "noop"          // already converged
)

// Action is a single decision, recorded for the audit trail and the dashboard.
type Action struct {
	Kind       ActionKind `json:"kind"`
	User       string     `json:"user"`
	Roles      []string   `json:"roles,omitempty"`
	Reason     string     `json:"reason"`
	Source     string     `json:"source"`
	OccurredAt time.Time  `json:"occurred_at"`
}

// Engine wires a policy to a Teleport client. The optional WorkloadClient
// enables the AI-agent identity path (see agent.go); it may be nil for the
// human-only configuration.
type Engine struct {
	pol policy.Policy
	tp  teleport.Client
	wl  teleport.WorkloadClient
}

// New constructs a human-only Engine.
func New(pol policy.Policy, tp teleport.Client) *Engine {
	return &Engine{pol: pol, tp: tp}
}

// NewWithWorkload constructs an Engine that also governs AI-agent / workload
// identities through the Teleport WorkloadClient surface.
func NewWithWorkload(pol policy.Policy, tp teleport.Client, wl teleport.WorkloadClient) *Engine {
	return &Engine{pol: pol, tp: tp, wl: wl}
}

// Policy exposes the engine's policy (read-only) for callers that need to
// pre-compute entitlements (e.g. the audit pass).
func (e *Engine) Policy() policy.Policy { return e.pol }

// Reconcile applies one event and returns the actions taken. The logic is
// intentionally declarative: desired state is a pure function of the HR record
// via policy.RolesFor, so a Leaver always converges to "no user, access
// locked" regardless of prior state.
func (e *Engine) Reconcile(ctx context.Context, ev hris.Event) ([]Action, error) {
	if err := ev.Validate(); err != nil {
		return nil, err
	}
	name := ev.Employee.Email
	desired := e.pol.RolesFor(ev.Employee)

	switch ev.Type {
	case hris.Leaver:
		return e.deprovision(ctx, ev)
	case hris.Joiner, hris.Mover:
		return e.converge(ctx, ev, name, desired)
	default:
		return nil, fmt.Errorf("unhandled event type %q", ev.Type)
	}
}

// converge brings a user to exactly its entitled role set.
func (e *Engine) converge(ctx context.Context, ev hris.Event, name string, desired []string) ([]Action, error) {
	cur, exists, err := e.tp.GetUser(ctx, name)
	if err != nil {
		return nil, err
	}
	if exists && sameRoles(cur.Roles, desired) {
		return []Action{{Kind: NoOp, User: name, Roles: desired,
			Reason: "already converged", Source: ev.Source, OccurredAt: ev.Timestamp}}, nil
	}
	u := teleport.User{
		Name:   name,
		Roles:  desired,
		Traits: map[string][]string{"logins": {usernameFromEmail(name)}},
	}
	if err := e.tp.UpsertUser(ctx, u); err != nil {
		return nil, err
	}
	kind := Provision
	reason := fmt.Sprintf("joiner in %s/%s", ev.Employee.Department, ev.Employee.Title)
	if exists {
		kind = UpdateRoles
		reason = fmt.Sprintf("moved %s -> %s", ev.PriorDepartment, ev.Employee.Department)
	}
	return []Action{{Kind: kind, User: name, Roles: desired,
		Reason: reason, Source: ev.Source, OccurredAt: ev.Timestamp}}, nil
}

// deprovision is total: delete the user AND lock the identity so any in-flight
// certificates/sessions are severed immediately (cert deletion alone would let
// an already-issued short-lived cert run to expiry).
func (e *Engine) deprovision(ctx context.Context, ev hris.Event) ([]Action, error) {
	name := ev.Employee.Email
	actions := []Action{}

	if err := e.tp.CreateLock(ctx, teleport.Lock{
		Target: name,
		Reason: "offboarding: terminated in HRIS",
	}); err != nil {
		return nil, err
	}
	actions = append(actions, Action{Kind: Lock, User: name,
		Reason: "offboarding: lock issued to sever live sessions",
		Source: ev.Source, OccurredAt: ev.Timestamp})

	if err := e.tp.DeleteUser(ctx, name); err != nil {
		return nil, err
	}
	actions = append(actions, Action{Kind: Deprovision, User: name,
		Reason: "offboarding: user and role bindings removed",
		Source: ev.Source, OccurredAt: ev.Timestamp})

	return actions, nil
}

// EvaluateAccessRequest implements just-in-time access: a user requests a role,
// and the engine either auto-approves (per policy) or routes to a human.
type AccessRequest struct {
	User      string `json:"user"`
	Requested string `json:"requested"`
}

// Decision is the outcome of a JIT request.
type Decision struct {
	User        string `json:"user"`
	Requested   string `json:"requested"`
	AutoApprove bool   `json:"auto_approve"`
	Reason      string `json:"reason"`
}

// EvaluateAccessRequest decides a JIT access request against current state.
func (e *Engine) EvaluateAccessRequest(ctx context.Context, req AccessRequest) (Decision, error) {
	u, ok, err := e.tp.GetUser(ctx, req.User)
	if err != nil {
		return Decision{}, err
	}
	if !ok {
		return Decision{User: req.User, Requested: req.Requested, AutoApprove: false,
			Reason: "requester has no provisioned identity"}, nil
	}
	if e.pol.CanAutoApprove(u.Roles, req.Requested) {
		return Decision{User: req.User, Requested: req.Requested, AutoApprove: true,
			Reason: "within auto-approvable escalation path"}, nil
	}
	return Decision{User: req.User, Requested: req.Requested, AutoApprove: false,
		Reason: "outside policy: routed to human approver"}, nil
}

func sameRoles(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

func usernameFromEmail(email string) string {
	for i, c := range email {
		if c == '@' {
			return email[:i]
		}
	}
	return email
}
