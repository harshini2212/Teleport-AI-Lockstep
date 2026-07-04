// Package worker wires the Temporal worker: it dials the Temporal frontend,
// registers the workflows and activities, and runs until interrupted. This is
// the binary that runs as the stateless Kubernetes Deployment (durability lives
// in the Temporal server, not the pod). The activities are backed by the
// in-memory Teleport mock so the durable workflows demo without a live cluster;
// swap teleport.NewMock() for client.New(...) to run against a real Teleport.
package worker

import (
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"

	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/connector/panther"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/connector/zendesk"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/engine"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/policy"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/teleport"
	"github.com/harshini2212/teleport-lifecycle-guard/go/temporal/activities"
	"github.com/harshini2212/teleport-lifecycle-guard/go/temporal/workflows"
)

// TaskQueue is the queue workflows and the worker share. Must match the starter.
const TaskQueue = "lifecycle-guard"

// Run connects to Temporal and serves the lifecycle workflows until interrupted.
func Run(hostPort, namespace string) error {
	tp := teleport.NewMock()
	eng := engine.NewWithWorkload(policy.Default(), tp, tp)
	acts := &activities.Activities{
		Eng:     eng,
		TP:      tp,
		Pol:     policy.Default(),
		Sum:     activities.NoopSummarizer{}, // swap for an Anthropic-backed Summarizer
		Zendesk: zendesk.NewMock(),
		Panther: panther.NewMock(),
	}

	c, err := client.Dial(client.Options{HostPort: hostPort, Namespace: namespace})
	if err != nil {
		return err
	}
	defer c.Close()

	w := worker.New(c, TaskQueue, worker.Options{})
	w.RegisterWorkflow(workflows.JoinerMoverLeaverWorkflow)
	w.RegisterWorkflow(workflows.AccessRequestWorkflow)
	w.RegisterWorkflow(workflows.LockoutWorkflow)
	w.RegisterActivity(acts)

	return w.Run(worker.InterruptCh())
}
