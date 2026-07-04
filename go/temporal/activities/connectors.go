// Package activities holds the Temporal activity implementations — the ONLY
// place that performs side effects (Teleport API calls, connector I/O, LLM
// calls). Workflows stay deterministic and call these by name. Each activity
// wraps exactly one engine/teleport/connector operation.
package activities

import (
	"context"

	"go.temporal.io/sdk/temporal"

	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/connector"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/connector/zendesk"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/engine"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/hris"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/policy"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/subject"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/teleport"
)

// Activities is dependency-injected: it holds the engine, the Teleport client,
// the policy, the (optional) LLM summarizer, and the connectors. RegisterActivity
// on a *Activities registers every exported method as a named activity.
type Activities struct {
	Eng     *engine.Engine
	TP      teleport.Client
	Pol     policy.Policy
	Sum     Summarizer
	Zendesk *zendesk.Client
	Panther connector.SinkConnector
}

// ReconcileHuman applies a human JML event. A malformed event is a permanent
// (non-retryable) failure; transient Teleport errors stay retryable so Temporal
// backs off and retries.
func (a *Activities) ReconcileHuman(ctx context.Context, ev hris.Event) ([]engine.Action, error) {
	if err := ev.Validate(); err != nil {
		return nil, temporal.NewNonRetryableApplicationError("invalid lifecycle event", "PolicyViolation", err)
	}
	return a.Eng.Reconcile(ctx, ev)
}

// ReconcileAgent applies an AI-agent JML event (issue/rescope/revoke identity).
func (a *Activities) ReconcileAgent(ctx context.Context, ev subject.AgentEvent) ([]engine.Action, error) {
	return a.Eng.ReconcileAgent(ctx, ev)
}

// EvaluateJIT decides a just-in-time access request against current state.
func (a *Activities) EvaluateJIT(ctx context.Context, req engine.AccessRequest) (engine.Decision, error) {
	return a.Eng.EvaluateAccessRequest(ctx, req)
}

// LockIdentity severs a principal's access via a Teleport lock and returns the
// lock's id (used to annotate the originating Zendesk ticket).
func (a *Activities) LockIdentity(ctx context.Context, target, reason string) (string, error) {
	if err := a.TP.CreateLock(ctx, teleport.Lock{Target: target, Reason: reason}); err != nil {
		return "", err
	}
	return "lock-" + target, nil
}

// ClassifyTicket runs the NLP-at-the-edge classifier over a free-text helpdesk
// ticket, extracting a structured lockout intent for the deterministic workflow.
func (a *Activities) ClassifyTicket(ctx context.Context, text string) (zendesk.LockoutRequest, error) {
	return zendesk.ClassifyAndExtract(ctx, text)
}

// UpdateTicket writes status/annotations back to the helpdesk ticket.
func (a *Activities) UpdateTicket(ctx context.Context, id string, patch connector.TicketPatch) (connector.Ticket, error) {
	if a.Zendesk == nil {
		return connector.Ticket{}, nil
	}
	return a.Zendesk.UpdateTicket(ctx, id, patch)
}

// EmitAudit forwards a normalized audit record to the SIEM (Panther). Best
// effort — a SIEM outage must not fail the access-plane workflow.
func (a *Activities) EmitAudit(ctx context.Context, rec connector.AuditRecord) error {
	if a.Panther == nil {
		return nil
	}
	return a.Panther.Emit(ctx, rec)
}
