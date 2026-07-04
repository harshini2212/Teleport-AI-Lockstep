// Package workflows holds the deterministic Temporal workflows. Determinism
// rules: no time.Now/rand/native goroutines/map-range here — use workflow.Now,
// workflow.NewTimer, workflow.Go, workflow.GetSignalChannel. All side effects go
// through activities.
package workflows

import (
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/connector"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/engine"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/hris"
	"github.com/harshini2212/teleport-lifecycle-guard/go/temporal/activities"
)

// ApprovalSignalName is the signal an approver sends to grant an out-of-policy
// just-in-time access request.
const ApprovalSignalName = "jit-approval"

// ApprovalSignal is the approval payload.
type ApprovalSignal struct {
	Approve  bool   `json:"approve"`
	Approver string `json:"approver"`
	Reason   string `json:"reason"`
}

// LifecycleResult is the outcome of a JML reconcile.
type LifecycleResult struct {
	Actions []engine.Action `json:"actions"`
	// Summary is an optional plain-English narration of the change (empty unless
	// an LLM Summarizer is wired into the worker). Advisory only.
	Summary string `json:"summary,omitempty"`
}

// defaultActivityOptions applies a bounded retry policy. Policy violations are
// non-retryable (matching the activity error type) so Temporal stops retrying a
// permanently-invalid request.
func defaultActivityOptions() workflow.ActivityOptions {
	return workflow.ActivityOptions{
		StartToCloseTimeout: 30 * time.Second,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval:        time.Second,
			BackoffCoefficient:     2.0,
			MaximumInterval:        time.Minute,
			MaximumAttempts:        5,
			NonRetryableErrorTypes: []string{"PolicyViolation"},
		},
	}
}

// JoinerMoverLeaverWorkflow durably reconciles one lifecycle event: it survives
// worker crashes and retries transient failures. It reconciles the identity,
// then emits an audit record per resulting action to the SIEM.
func JoinerMoverLeaverWorkflow(ctx workflow.Context, ev hris.Event) (LifecycleResult, error) {
	ctx = workflow.WithActivityOptions(ctx, defaultActivityOptions())
	logger := workflow.GetLogger(ctx)
	var a *activities.Activities
	var result LifecycleResult

	var actions []engine.Action
	if err := workflow.ExecuteActivity(ctx, a.ReconcileHuman, ev).Get(ctx, &actions); err != nil {
		return result, err
	}
	result.Actions = actions
	logger.Info("reconciled identity", "user", ev.Employee.Email, "type", ev.Type, "actions", len(actions))

	for _, act := range actions {
		rec := connector.AuditRecord{Event: string(act.Kind), User: act.User, Time: ev.Timestamp}
		// Best effort: a SIEM hiccup must not roll back the access change.
		_ = workflow.ExecuteActivity(ctx, a.EmitAudit, rec).Get(ctx, nil)
	}

	// Advisory NLP narration (no-ops without an LLM Summarizer). Isolated in an
	// activity because an LLM call is a non-deterministic side effect.
	var summary string
	_ = workflow.ExecuteActivity(ctx, a.NarrateChange,
		activities.SummaryInput{Event: ev, Actions: actions}).Get(ctx, &summary)
	result.Summary = summary

	return result, nil
}

// AccessRequestWorkflow implements durable just-in-time access with a
// human-in-the-loop signal. Auto-approvable requests resolve immediately;
// everything else blocks on an approval signal with a timeout (auto-deny),
// surviving worker restarts across a multi-day approval wait. A query handler
// exposes live status.
func AccessRequestWorkflow(ctx workflow.Context, req engine.AccessRequest) (engine.Decision, error) {
	ctx = workflow.WithActivityOptions(ctx, defaultActivityOptions())
	var a *activities.Activities

	status := "evaluating"
	if err := workflow.SetQueryHandler(ctx, "status", func() (string, error) { return status, nil }); err != nil {
		return engine.Decision{}, err
	}

	var decision engine.Decision
	if err := workflow.ExecuteActivity(ctx, a.EvaluateJIT, req).Get(ctx, &decision); err != nil {
		return decision, err
	}
	if decision.AutoApprove {
		status = "auto-approved"
		return decision, nil
	}

	status = "awaiting-approval"
	if sig := waitForApproval(ctx, 24*time.Hour); sig != nil && sig.Approve {
		decision.AutoApprove = true
		decision.Reason = "approved by " + sig.Approver + ": " + sig.Reason
		status = "human-approved"
	} else {
		decision.Reason = "denied or approval timed out"
		status = "denied"
	}
	return decision, nil
}

// waitForApproval blocks until an approval signal arrives or the timeout fires.
// Returns nil on timeout (auto-deny). Deterministic: uses the workflow selector,
// signal channel, and timer.
func waitForApproval(ctx workflow.Context, timeout time.Duration) *ApprovalSignal {
	ch := workflow.GetSignalChannel(ctx, ApprovalSignalName)
	var sig ApprovalSignal
	received := false

	sel := workflow.NewSelector(ctx)
	sel.AddReceive(ch, func(c workflow.ReceiveChannel, _ bool) {
		c.Receive(ctx, &sig)
		received = true
	})
	sel.AddFuture(workflow.NewTimer(ctx, timeout), func(workflow.Future) {})
	sel.Select(ctx)

	if received {
		return &sig
	}
	return nil
}
