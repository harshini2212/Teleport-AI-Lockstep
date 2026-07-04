package workflows

import (
	"go.temporal.io/sdk/workflow"

	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/connector"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/connector/zendesk"
	"github.com/harshini2212/teleport-lifecycle-guard/go/temporal/activities"
)

// TicketRef points at the helpdesk ticket that triggered a lockout.
type TicketRef struct {
	TicketID string `json:"ticket_id"`
	Body     string `json:"body"`
}

// LockoutResult is the saga outcome.
type LockoutResult struct {
	Target   string `json:"target"`
	LockID   string `json:"lock_id"`
	Resolved bool   `json:"resolved"`
}

// LockoutWorkflow is the headline helpdesk saga: a free-text lockout ticket
// ("lock out contractor jdoe, laptop stolen") is (1) classified into a
// structured intent by the NLP edge, (2) executed as a Teleport lock by the
// deterministic, Lean-verified offboarding path, (3) written back to the ticket
// with the lock id, and (4) forwarded to the SIEM. The AI proposes; the audited
// pipeline disposes.
func LockoutWorkflow(ctx workflow.Context, ref TicketRef) (LockoutResult, error) {
	ctx = workflow.WithActivityOptions(ctx, defaultActivityOptions())
	logger := workflow.GetLogger(ctx)
	var a *activities.Activities
	var res LockoutResult

	// 1. Classify the free-text ticket.
	var intent zendesk.LockoutRequest
	if err := workflow.ExecuteActivity(ctx, a.ClassifyTicket, ref.Body).Get(ctx, &intent); err != nil {
		return res, err
	}
	if intent.Intent != "lockout" || intent.Target == "" {
		logger.Info("ticket is not an actionable lockout", "ticket", ref.TicketID, "intent", intent.Intent)
		return res, nil
	}
	res.Target = intent.Target

	// 2. Execute the lock.
	var lockID string
	if err := workflow.ExecuteActivity(ctx, a.LockIdentity, intent.Target, intent.Reason).Get(ctx, &lockID); err != nil {
		return res, err
	}
	res.LockID = lockID

	// 3. Resolve the ticket with the lock id.
	patch := connector.TicketPatch{
		Status:       "solved",
		Comment:      "Locked " + intent.Target + " via Teleport (" + lockID + ").",
		CustomFields: map[string]string{"teleport_lock": lockID},
	}
	_ = workflow.ExecuteActivity(ctx, a.UpdateTicket, ref.TicketID, patch).Get(ctx, nil)

	// 4. Forward to the SIEM.
	_ = workflow.ExecuteActivity(ctx, a.EmitAudit,
		connector.AuditRecord{Event: "lock", User: intent.Target}).Get(ctx, nil)

	res.Resolved = true
	return res, nil
}
