// Command starter simulates the Rippling/Okta webhook receiver and the helpdesk:
// it starts lifecycle workflows and drives the JIT approval signal. Run it after
// the worker is up and a Temporal dev server is running
// (`temporal server start-dev`).
package main

import (
	"context"
	"log"
	"os"
	"time"

	"go.temporal.io/sdk/client"

	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/engine"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/hris"
	"github.com/harshini2212/teleport-lifecycle-guard/go/temporal/worker"
	"github.com/harshini2212/teleport-lifecycle-guard/go/temporal/workflows"
)

func main() {
	hostPort := envOr("TEMPORAL_ADDRESS", client.DefaultHostPort)
	c, err := client.Dial(client.Options{HostPort: hostPort})
	if err != nil {
		log.Fatalf("dial temporal: %v", err)
	}
	defer c.Close()
	ctx := context.Background()

	// 1. A new hire arrives (Rippling webhook -> JML workflow).
	ev := hris.Event{
		Type: hris.Joiner, Source: "rippling", Timestamp: time.Now(),
		Employee: hris.Employee{
			ID: "E-900", Email: "newhire@goteleport.com", Name: "New Hire",
			Department: "SRE", Title: "Engineer", Status: hris.Active,
		},
	}
	jml, err := c.ExecuteWorkflow(ctx, client.StartWorkflowOptions{
		ID: "jml-" + ev.Employee.ID, TaskQueue: worker.TaskQueue,
	}, workflows.JoinerMoverLeaverWorkflow, ev)
	if err != nil {
		log.Fatalf("start JML: %v", err)
	}
	var jmlRes workflows.LifecycleResult
	if err := jml.Get(ctx, &jmlRes); err != nil {
		log.Fatalf("JML result: %v", err)
	}
	log.Printf("JML complete: %d actions provisioned for %s", len(jmlRes.Actions), ev.Employee.Email)

	// 2. An out-of-policy JIT request -> blocks on approval; we approve by signal.
	req := engine.AccessRequest{User: "newhire@goteleport.com", Requested: "it-admin"}
	jit, err := c.ExecuteWorkflow(ctx, client.StartWorkflowOptions{
		ID: "jit-newhire-itadmin", TaskQueue: worker.TaskQueue,
	}, workflows.AccessRequestWorkflow, req)
	if err != nil {
		log.Fatalf("start JIT: %v", err)
	}
	if err := c.SignalWorkflow(ctx, jit.GetID(), "", workflows.ApprovalSignalName,
		workflows.ApprovalSignal{Approve: true, Approver: "sec-oncall", Reason: "temporary oncall coverage"}); err != nil {
		log.Fatalf("signal JIT: %v", err)
	}
	var decision engine.Decision
	if err := jit.Get(ctx, &decision); err != nil {
		log.Fatalf("JIT result: %v", err)
	}
	log.Printf("JIT decision: approve=%v reason=%q", decision.AutoApprove, decision.Reason)

	// 3. A helpdesk lockout ticket -> classify + lock saga.
	lockout, err := c.ExecuteWorkflow(ctx, client.StartWorkflowOptions{
		ID: "lockout-ZD-4242", TaskQueue: worker.TaskQueue,
	}, workflows.LockoutWorkflow, workflows.TicketRef{
		TicketID: "ZD-4242",
		Body:     "Please lock out contractor dave@goteleport.com immediately — laptop was stolen.",
	})
	if err != nil {
		log.Fatalf("start lockout: %v", err)
	}
	var lockRes workflows.LockoutResult
	if err := lockout.Get(ctx, &lockRes); err != nil {
		log.Fatalf("lockout result: %v", err)
	}
	log.Printf("lockout complete: target=%s lock=%s resolved=%v", lockRes.Target, lockRes.LockID, lockRes.Resolved)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
