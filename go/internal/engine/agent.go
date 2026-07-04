package engine

import (
	"context"
	"fmt"

	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/hris"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/subject"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/teleport"
)

// Agent lifecycle reconciliation. AI agents flow through the SAME Joiner/Mover/
// Leaver control flow as humans — the only difference is the access-plane
// primitive: instead of a Teleport user + roles, an agent gets a SPIFFE
// workload identity + a scoped bot. Crucially, the Leaver path is just as total:
// revoke the identity AND lock the bot, so any already-issued short-lived SVID
// is severed (deleting the identity alone would let it run to its TTL).

// Agent-identity action kinds, added to the universal ActionKind vocabulary.
const (
	IssueIdentity   ActionKind = "issue_identity"
	RescopeIdentity ActionKind = "rescope_identity"
	RevokeIdentity  ActionKind = "revoke_identity"
)

// Operational action kinds for the live console (locks, session control, device
// trust) — the real Teleport operations an IT/Security engineer performs.
const (
	TerminateSession ActionKind = "terminate_session"
	EnrollDevice     ActionKind = "enroll_device"
	Elevate          ActionKind = "elevate"
)

// ReconcileAgent applies one agent lifecycle event. Mirrors Reconcile for humans.
func (e *Engine) ReconcileAgent(ctx context.Context, ev subject.AgentEvent) ([]Action, error) {
	if e.wl == nil {
		return nil, fmt.Errorf("engine has no WorkloadClient: construct with NewWithWorkload")
	}
	if ev.Subject.Kind != subject.KindAgent {
		return nil, fmt.Errorf("ReconcileAgent requires an agent subject, got %q", ev.Subject.Kind)
	}
	switch ev.Type {
	case hris.Joiner:
		return e.joinAgent(ctx, ev)
	case hris.Mover:
		return e.moveAgent(ctx, ev)
	case hris.Leaver:
		return e.leaveAgent(ctx, ev)
	default:
		return nil, fmt.Errorf("unhandled agent event type %q", ev.Type)
	}
}

func (e *Engine) joinAgent(ctx context.Context, ev subject.AgentEvent) ([]Action, error) {
	s := ev.Subject
	roles := e.pol.RolesForAgent(s)
	wi := teleport.WorkloadIdentity{
		Name:             s.Name,
		SpiffeIDTemplate: e.pol.SpiffePathFor(s),
		Hint:             "AI agent workload: " + s.Name,
	}
	if err := e.wl.UpsertWorkloadIdentity(ctx, wi); err != nil {
		return nil, err
	}
	if err := e.wl.AddBot(ctx, teleport.Bot{Name: s.Name, Roles: roles}); err != nil {
		return nil, err
	}
	return []Action{{
		Kind: IssueIdentity, User: s.SpiffeID, Roles: roles,
		Reason: fmt.Sprintf("agent join: SPIFFE identity issued, scoped to %v", roles),
		Source: ev.Source, OccurredAt: ev.Timestamp,
	}}, nil
}

func (e *Engine) moveAgent(ctx context.Context, ev subject.AgentEvent) ([]Action, error) {
	s := ev.Subject
	roles := e.pol.RolesForAgent(s)
	// Re-scope in place: rewrite the workload identity and the bot's roles. No
	// new long-lived secret is minted — the SPIFFE identity is re-issued short.
	if err := e.wl.UpsertWorkloadIdentity(ctx, teleport.WorkloadIdentity{
		Name: s.Name, SpiffeIDTemplate: e.pol.SpiffePathFor(s),
		Hint: "AI agent workload: " + s.Name,
	}); err != nil {
		return nil, err
	}
	if err := e.wl.AddBot(ctx, teleport.Bot{Name: s.Name, Roles: roles}); err != nil {
		return nil, err
	}
	return []Action{{
		Kind: RescopeIdentity, User: s.SpiffeID, Roles: roles,
		Reason: fmt.Sprintf("agent move: re-scoped %v -> %v, no new secret", ev.PriorScope, s.Scope),
		Source: ev.Source, OccurredAt: ev.Timestamp,
	}}, nil
}

// leaveAgent is the agent analog of deprovision(): lock first to sever in-flight
// SVIDs, then remove the bot and delete the workload identity.
func (e *Engine) leaveAgent(ctx context.Context, ev subject.AgentEvent) ([]Action, error) {
	s := ev.Subject
	actions := []Action{}

	if err := e.wl.LockBot(ctx, s.Name, "decommission: agent terminated"); err != nil {
		return nil, err
	}
	actions = append(actions, Action{Kind: Lock, User: s.SpiffeID,
		Reason: "agent decommission: bot locked to sever in-flight SVIDs",
		Source: ev.Source, OccurredAt: ev.Timestamp})

	if err := e.wl.RemoveBot(ctx, s.Name); err != nil {
		return nil, err
	}
	if err := e.wl.DeleteWorkloadIdentity(ctx, s.Name); err != nil {
		return nil, err
	}
	actions = append(actions, Action{Kind: RevokeIdentity, User: s.SpiffeID,
		Reason: "agent decommission: workload identity deleted, bot removed",
		Source: ev.Source, OccurredAt: ev.Timestamp})

	return actions, nil
}
