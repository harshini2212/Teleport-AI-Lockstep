// Command lifecycleguard runs the identity-lifecycle automation pipeline end to
// end against an in-memory Teleport cluster and emits:
//   - a human-readable summary to stdout
//   - a machine-readable trace (trace.json) the dashboard renders
//
// It exercises the whole surface offline: human Joiner/Mover/Leaver, AI-agent
// (Kyra) join/move/decommission, just-in-time access, Jamf device-trust gating,
// audit anomaly detection, and (optionally) the LLM access-review copilot.
//
// Usage:
//
//	go run ./cmd/lifecycleguard -out ../dashboard/trace.json
//	ANTHROPIC_API_KEY=... go run ./cmd/lifecycleguard -review
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/audit"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/copilot"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/engine"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/hris"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/jamf"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/policy"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/subject"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/teleport"
)

// generatedAt anchors all deterministic timestamps in the run.
var generatedAt = time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)

// Trace is the full record of a pipeline run, consumed by the dashboard.
type Trace struct {
	GeneratedAt  time.Time         `json:"generated_at"`
	Policy       policySummary     `json:"policy"`
	Steps        []Step            `json:"steps"`
	Agents       []AgentStep       `json:"agents,omitempty"`
	JITDecisions []engine.Decision `json:"jit_decisions"`
	Findings     []audit.Finding   `json:"findings"`
	Devices      []jamf.Device     `json:"devices,omitempty"`
	FinalState   FinalState        `json:"final_state"`
	Review       *copilot.Review   `json:"review,omitempty"`
}

type policySummary struct {
	DepartmentRoles map[string][]string `json:"department_roles"`
	MaxSessionTTL   string              `json:"max_session_ttl"`
}

// Step pairs an inbound human event with the actions the engine took.
type Step struct {
	Event   hris.Event      `json:"event"`
	Actions []engine.Action `json:"actions"`
}

// AgentStep pairs an AI-agent lifecycle event with its actions.
type AgentStep struct {
	Event   subject.AgentEvent `json:"event"`
	Actions []engine.Action    `json:"actions"`
}

// FinalState is the converged cluster snapshot.
type FinalState struct {
	Users    []teleport.User    `json:"users"`
	Locks    []teleport.Lock    `json:"locks"`
	Sessions []teleport.Session `json:"sessions"`
}

func main() {
	eventsPath := flag.String("events", "", "path to a JSON array of HRIS events (default: built-in demo)")
	outPath := flag.String("out", "", "write the run trace JSON to this path")
	reviewFlag := flag.Bool("review", false, "generate an LLM access review (requires ANTHROPIC_API_KEY)")
	flag.Parse()

	pol := policy.Default()
	tp := teleport.NewMock()
	eng := engine.NewWithWorkload(pol, tp, tp)
	ctx := context.Background()

	events, err := loadEvents(*eventsPath)
	if err != nil {
		fail(err)
	}

	trace := Trace{
		GeneratedAt: generatedAt,
		Policy: policySummary{
			DepartmentRoles: pol.DepartmentRoles,
			MaxSessionTTL:   pol.MaxSessionTTL.String(),
		},
	}

	fmt.Println("== Teleport Lifecycle Guard ==")
	fmt.Print("Reconciling HRIS/IdP lifecycle events against the access plane.\n\n")

	entitled := map[string][]string{}
	activeUsers := map[string]bool{}

	for _, ev := range events {
		actions, err := eng.Reconcile(ctx, ev)
		if err != nil {
			fail(fmt.Errorf("reconcile %s: %w", ev.Employee.Email, err))
		}
		trace.Steps = append(trace.Steps, Step{Event: ev, Actions: actions})
		entitled[ev.Employee.Email] = pol.RolesFor(ev.Employee)
		activeUsers[ev.Employee.Email] = ev.Employee.Status == hris.Active

		for _, a := range actions {
			fmt.Printf("  [%-11s] %-26s %s\n", a.Kind, a.User, a.Reason)
			if len(a.Roles) > 0 {
				fmt.Printf("               roles: %v\n", a.Roles)
			}
		}
	}

	// --- AI-agent lifecycle: Kyra is a first-class cryptographic identity ---
	fmt.Println("\n-- AI-agent identity lifecycle (Kyra) --")
	trace.Agents = runAgentDemo(ctx, eng)

	// --- Just-in-time access requests ---
	fmt.Println("\n-- Just-in-time access requests --")
	jitReqs := []engine.AccessRequest{
		{User: "bob@goteleport.com", Requested: "db-readonly"}, // SRE oncall: auto
		{User: "alice@goteleport.com", Requested: "it-admin"},  // not in path: human
	}
	for _, req := range jitReqs {
		d, err := eng.EvaluateAccessRequest(ctx, req)
		if err != nil {
			fail(err)
		}
		trace.JITDecisions = append(trace.JITDecisions, d)
		verdict := "ROUTED TO HUMAN"
		if d.AutoApprove {
			verdict = "AUTO-APPROVED"
		}
		fmt.Printf("  %-22s -> %-15s %-16s (%s)\n", d.User, d.Requested, verdict, d.Reason)
	}

	// --- Inject real-world failure modes for the audit pass to catch ---
	injectAnomalies(ctx, tp, entitled, activeUsers)
	seedDeviceSessions(ctx, tp, activeUsers)

	// --- Jamf device-trust posture feeds the audit detectors ---
	devices := demoDevices()
	trace.Devices = devices
	inv := jamf.NewMock(generatedAt, devices...)
	managed, compliant, err := jamf.PostureMaps(ctx, inv, generatedAt)
	if err != nil {
		fail(err)
	}

	findings, err := audit.Detect(ctx, tp, pol, activeUsers, entitled, demoKnownIPs(), managed, compliant)
	if err != nil {
		fail(err)
	}
	trace.Findings = findings

	fmt.Println("\n-- Audit-stream anomaly detection & device trust --")
	if len(findings) == 0 {
		fmt.Println("  no anomalies")
	}
	for _, f := range findings {
		fmt.Printf("  [%-8s] %-28s %s\n", f.Severity, f.Detector, f.Summary)
		fmt.Printf("             -> %s\n", f.Remediation)
	}

	trace.FinalState = snapshot(ctx, tp)

	// --- Optional: LLM access-review copilot (advisory only) ---
	if *reviewFlag {
		runCopilot(ctx, pol, &trace)
	}

	if *outPath != "" {
		if err := writeTrace(*outPath, trace); err != nil {
			fail(err)
		}
		fmt.Printf("\nTrace written to %s\n", *outPath)
	}
}

// runAgentDemo issues, re-scopes, and revokes the Kyra agent's SPIFFE identity.
func runAgentDemo(ctx context.Context, eng *engine.Engine) []AgentStep {
	sp := subject.SpiffeIDFor("teleport.goteleport.com", "kyra")
	mk := func(status hris.Status, scope []string) subject.Subject {
		return subject.Subject{Kind: subject.KindAgent, ID: "A-kyra", Name: "kyra",
			Status: status, Scope: scope, SpiffeID: sp}
	}
	at := func(min int) time.Time { return time.Date(2026, 7, 2, 10, min, 0, 0, time.UTC) }
	events := []subject.AgentEvent{
		{Type: hris.Joiner, Source: "deploy", Timestamp: at(0), Subject: mk(hris.Active, []string{"kyra-memory"})},
		{Type: hris.Mover, Source: "deploy", Timestamp: at(30), PriorScope: []string{"kyra-memory"},
			Subject: mk(hris.Active, []string{"kyra-memory", "kyra-calendar"})},
		{Type: hris.Leaver, Source: "deploy", Timestamp: at(90), Subject: mk(hris.Terminated, nil)},
	}
	var steps []AgentStep
	for _, ev := range events {
		actions, err := eng.ReconcileAgent(ctx, ev)
		if err != nil {
			fail(err)
		}
		steps = append(steps, AgentStep{Event: ev, Actions: actions})
		for _, a := range actions {
			fmt.Printf("  [%-15s] %-42s %s\n", a.Kind, a.User, a.Reason)
			if len(a.Roles) > 0 {
				fmt.Printf("                    roles: %v\n", a.Roles)
			}
		}
	}
	return steps
}

func runCopilot(ctx context.Context, pol policy.Policy, trace *Trace) {
	fmt.Println("\n-- Access-review copilot --")
	c, err := copilot.NewClient()
	if errors.Is(err, copilot.ErrNoAPIKey) {
		fmt.Println("  skipped: set ANTHROPIC_API_KEY to enable the LLM review")
		return
	}
	if err != nil {
		fmt.Println("  error:", err)
		return
	}
	ev := copilot.BuildEvidence("2026-Q2", pol, trace.Findings,
		trace.FinalState.Users, trace.FinalState.Locks, trace.FinalState.Sessions, trace.JITDecisions)
	review, err := copilot.Generate(ctx, c, ev)
	if err != nil {
		fmt.Println("  error:", err)
		return
	}
	trace.Review = &review
	fmt.Printf("  [%s] %s\n", review.Period, review.Summary)
	for _, r := range review.Recommendations {
		fmt.Printf("    - %-8s %-24s %s\n", r.Action, r.Identity, r.Rationale)
	}
}

// injectAnomalies models two things a clean reconcile loop would not produce on
// its own: a terminated identity with a surviving user + live session, and an
// out-of-band privilege escalation.
func injectAnomalies(ctx context.Context, tp *teleport.Mock, entitled map[string][]string, active map[string]bool) {
	tp.UpsertUser(ctx, teleport.User{Name: "dave@goteleport.com", Roles: []string{"k8s-prod"}})
	tp.SeedSession(teleport.Session{
		ID: "sess-7f3a", User: "dave@goteleport.com", Kind: "k8s",
		Login: "dave", SourceIP: "203.0.113.51",
		Started: time.Date(2026, 7, 2, 11, 40, 0, 0, time.UTC),
	})
	entitled["dave@goteleport.com"] = nil
	active["dave@goteleport.com"] = false

	cur, _, _ := tp.GetUser(ctx, "alice@goteleport.com")
	tp.UpsertUser(ctx, teleport.User{
		Name:  "alice@goteleport.com",
		Roles: append(append([]string(nil), cur.Roles...), "it-admin"),
	})
}

// seedDeviceSessions models two ACTIVE users whose sessions come from a
// non-compliant managed Mac and an unmanaged BYOD device — caught by device trust.
func seedDeviceSessions(ctx context.Context, tp *teleport.Mock, active map[string]bool) {
	tp.SeedSession(teleport.Session{ID: "sess-9c21", User: "erin@goteleport.com", Kind: "ssh",
		Login: "erin", SourceIP: "198.51.100.31", Started: time.Date(2026, 7, 2, 11, 50, 0, 0, time.UTC)})
	tp.SeedSession(teleport.Session{ID: "sess-3e88", User: "frank@goteleport.com", Kind: "db",
		Login: "frank", SourceIP: "198.51.100.77", Started: time.Date(2026, 7, 2, 11, 55, 0, 0, time.UTC)})
	active["erin@goteleport.com"] = true
	active["frank@goteleport.com"] = true
	_ = ctx
}

func demoDevices() []jamf.Device {
	fresh := generatedAt.Add(-1 * time.Hour)
	full := jamf.Compliance{FileVault: true, Firewall: true, Gatekeeper: true, SIP: true,
		ScreenLock: true, AutoUpdates: true, GuestDisabled: true, Overall: true}
	fail := jamf.Compliance{FileVault: false, Firewall: false, Gatekeeper: true, SIP: true,
		ScreenLock: true, AutoUpdates: true, GuestDisabled: true, Overall: false}
	return []jamf.Device{
		{SerialNumber: "C02ALICE", UserEmail: "alice@goteleport.com", Managed: true, Supervised: true, Compliance: full, LastInventoryUpdate: fresh},
		{SerialNumber: "C02BOB", UserEmail: "bob@goteleport.com", Managed: true, Supervised: true, Compliance: full, LastInventoryUpdate: fresh},
		{SerialNumber: "C02DAVE", UserEmail: "dave@goteleport.com", Managed: true, Supervised: true, Compliance: full, LastInventoryUpdate: fresh},
		{SerialNumber: "C02ERIN", UserEmail: "erin@goteleport.com", Managed: true, Supervised: true, Compliance: fail, LastInventoryUpdate: fresh},
		{SerialNumber: "BYOD-FRANK", UserEmail: "frank@goteleport.com", Managed: false, Supervised: false, Compliance: fail, LastInventoryUpdate: fresh},
	}
}

func snapshot(ctx context.Context, tp *teleport.Mock) FinalState {
	locks, _ := tp.ListLocks(ctx)
	sessions, _ := tp.ListSessions(ctx)
	return FinalState{Users: tp.AllUsers(ctx), Locks: locks, Sessions: sessions}
}

func demoKnownIPs() audit.KnownIP {
	return audit.KnownIP{
		"dave@goteleport.com": {"198.51.100.10": {}}, // 203.0.113.51 is new => flagged
	}
}

func loadEvents(path string) ([]hris.Event, error) {
	if path == "" {
		return demoEvents(), nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return hris.ParseStream(raw)
}

func demoEvents() []hris.Event {
	t := func(min int) time.Time { return time.Date(2026, 7, 2, 9, min, 0, 0, time.UTC) }
	return []hris.Event{
		{Type: hris.Joiner, Source: "rippling", Timestamp: t(0), Employee: hris.Employee{
			ID: "E-101", Email: "alice@goteleport.com", Name: "Alice Ng",
			Department: "Engineering", Title: "Engineer", Status: hris.Active}},
		{Type: hris.Joiner, Source: "rippling", Timestamp: t(1), Employee: hris.Employee{
			ID: "E-102", Email: "bob@goteleport.com", Name: "Bob Reyes",
			Department: "SRE", Title: "Incident Commander", Status: hris.Active}},
		{Type: hris.Joiner, Source: "okta", Timestamp: t(2), Employee: hris.Employee{
			ID: "E-103", Email: "carol@goteleport.com", Name: "Carol Diaz",
			Department: "IT", Title: "Manager", Status: hris.Active}},
		{Type: hris.Mover, Source: "rippling", Timestamp: t(30), PriorDepartment: "Engineering",
			Employee: hris.Employee{ID: "E-101", Email: "alice@goteleport.com", Name: "Alice Ng",
				Department: "SRE", Title: "Engineer", Status: hris.Active}},
		{Type: hris.Leaver, Source: "rippling", Timestamp: t(120), Employee: hris.Employee{
			ID: "E-103", Email: "carol@goteleport.com", Name: "Carol Diaz",
			Department: "IT", Title: "Manager", Status: hris.Terminated}},
	}
}

func writeTrace(path string, tr Trace) error {
	b, err := json.MarshalIndent(tr, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
