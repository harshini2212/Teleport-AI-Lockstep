// Package scenario is the stateful "brain" behind both the CLI demo and the live
// HTTP server. It holds an in-memory Teleport cluster + engine and exposes:
//   - Seed():        load the built-in demo (humans, the Kyra agent, anomalies, devices)
//   - ApplyHuman():  reconcile a live human JML event
//   - ApplyAgent():  reconcile a live AI-agent JML event
//   - JIT():         evaluate a just-in-time access request
//   - Trace():       recompute findings + snapshot the whole run as JSON
//
// It is concurrency-safe so the HTTP server can serve it directly.
package scenario

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/audit"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/engine"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/hris"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/jamf"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/policy"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/subject"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/teleport"
)

// anchor is the deterministic clock the demo is stamped against.
var anchor = time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)

const trustDomain = "teleport.goteleport.com"

// --- Trace types (the JSON contract the dashboard renders) ---

// Trace is the full record of the current run.
type Trace struct {
	GeneratedAt  time.Time         `json:"generated_at"`
	Scenario     ScenarioRef       `json:"scenario"`
	Policy       PolicySummary     `json:"policy"`
	Steps        []Step            `json:"steps"`
	Agents       []AgentStep       `json:"agents,omitempty"`
	JITDecisions []engine.Decision `json:"jit_decisions"`
	Findings     []audit.Finding   `json:"findings"`
	Devices      []jamf.Device     `json:"devices,omitempty"`
	FinalState   FinalState        `json:"final_state"`
}

// PolicySummary is the department→roles map + max TTL.
type PolicySummary struct {
	DepartmentRoles map[string][]string `json:"department_roles"`
	MaxSessionTTL   string              `json:"max_session_ttl"`
}

// Step pairs a human event with the actions it produced.
type Step struct {
	Event   hris.Event      `json:"event"`
	Actions []engine.Action `json:"actions"`
}

// AgentStep pairs an AI-agent event with its actions.
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

// --- Runner ---

// Runner owns the live cluster state.
type Runner struct {
	mu          sync.Mutex
	GeneratedAt time.Time
	pol         policy.Policy
	tp          *teleport.Mock
	eng         *engine.Engine
	entitled    map[string][]string
	active      map[string]bool
	steps       []Step
	agents      []AgentStep
	jit         []engine.Decision
	devices     []jamf.Device
	known       audit.KnownIP
	current     string // id of the loaded scenario
}

// New returns a Runner primed with the demo scenario.
func New() *Runner {
	r := &Runner{}
	r.Seed()
	return r
}

func (r *Runner) reset() {
	r.pol = policy.Default()
	r.tp = teleport.NewMock()
	r.eng = engine.NewWithWorkload(r.pol, r.tp, r.tp)
	r.GeneratedAt = anchor
	r.entitled = map[string][]string{}
	r.active = map[string]bool{}
	r.steps = nil
	r.agents = nil
	r.jit = nil
	r.devices = nil
	r.known = audit.KnownIP{}
	r.current = ""
}

// Seed resets state and loads the default (baseline) scenario.
func (r *Runner) Seed() {
	r.mu.Lock()
	defer r.mu.Unlock()
	_ = r.loadLocked("baseline")
}

// Load switches to a named scenario. Returns an error for an unknown id (and
// falls back to baseline so the app never renders an empty state).
func (r *Runner) Load(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.loadLocked(id)
}

// --- public (locking) live operations ---

// ApplyHuman reconciles a human JML event against the live cluster.
func (r *Runner) ApplyHuman(ev hris.Event) ([]engine.Action, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.applyHuman(context.Background(), ev)
}

// ApplyAgent reconciles an AI-agent JML event.
func (r *Runner) ApplyAgent(ev subject.AgentEvent) ([]engine.Action, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.applyAgent(context.Background(), ev)
}

// JIT evaluates a just-in-time access request.
func (r *Runner) JIT(req engine.AccessRequest) (engine.Decision, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.jitEval(context.Background(), req)
}

// Lock severs a principal's access immediately (Teleport `tctl lock`) WITHOUT
// deleting the account — breach containment. The identity stays enrolled but
// locked, so the audit pass treats it as contained.
func (r *Runner) Lock(target, reason string) ([]engine.Action, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if target == "" {
		return nil, fmt.Errorf("lock target required")
	}
	if err := r.tp.CreateLock(context.Background(), teleport.Lock{Target: target, Reason: reason}); err != nil {
		return nil, err
	}
	return []engine.Action{{Kind: engine.Lock, User: target, Reason: "locked: " + reason,
		Source: "api", OccurredAt: r.GeneratedAt}}, nil
}

// TerminateSessions ends every live session for a user (`tsh sessions kill`).
func (r *Runner) TerminateSessions(user string) ([]engine.Action, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx := context.Background()
	sessions, _ := r.tp.ListSessions(ctx)
	var actions []engine.Action
	for _, s := range sessions {
		if s.User == user {
			_ = r.tp.RemoveSession(ctx, s.ID)
			actions = append(actions, engine.Action{Kind: engine.TerminateSession, User: user,
				Reason: "terminated live " + s.Kind + " session " + s.ID, Source: "api", OccurredAt: r.GeneratedAt})
		}
	}
	if len(actions) == 0 {
		actions = append(actions, engine.Action{Kind: engine.NoOp, User: user,
			Reason: "no live sessions to terminate", Source: "api", OccurredAt: r.GeneratedAt})
	}
	return actions, nil
}

// UpsertDevice registers or updates a device's Jamf posture (Device Trust).
func (r *Runner) UpsertDevice(email, serial string, managed, compliant bool) ([]engine.Action, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if email == "" {
		return nil, fmt.Errorf("device owner email required")
	}
	kept := r.devices[:0]
	for _, d := range r.devices {
		if d.UserEmail != email {
			kept = append(kept, d)
		}
	}
	r.devices = kept
	if serial == "" {
		serial = "DEV-" + userLocal(email)
	}
	r.dev(serial, email, managed, compliant)
	reason := "device registered as managed & compliant"
	if !managed {
		reason = "device flagged unmanaged (BYOD)"
	} else if !compliant {
		reason = "device flagged non-compliant (failed hardening baseline)"
	}
	return []engine.Action{{Kind: engine.EnrollDevice, User: email, Reason: reason,
		Source: "api", OccurredAt: r.GeneratedAt}}, nil
}

// Incident runs the "compromised / stolen device" playbook: lock the identity AND
// terminate every live session — the one-click containment an IR team wants. This
// is the synchronous analog of the Temporal lockout saga.
func (r *Runner) Incident(target string) ([]engine.Action, error) {
	lock, err := r.Lock(target, "incident response: suspected compromise / stolen device")
	if err != nil {
		return nil, err
	}
	term, _ := r.TerminateSessions(target)
	return append(lock, term...), nil
}

// Trace recomputes anomaly findings and snapshots the whole run.
func (r *Runner) Trace() Trace {
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx := context.Background()

	var managed, compliant map[string]bool
	if len(r.devices) > 0 {
		managed, compliant, _ = jamf.PostureMaps(ctx, jamf.NewMock(r.GeneratedAt, r.devices...), r.GeneratedAt)
	}
	findings, _ := audit.Detect(ctx, r.tp, r.pol, r.active, r.entitled, r.known, managed, compliant)
	locks, _ := r.tp.ListLocks(ctx)
	sessions, _ := r.tp.ListSessions(ctx)

	return Trace{
		GeneratedAt:  r.GeneratedAt,
		Scenario:     ScenarioRef{ID: r.current, Title: titleFor(r.current)},
		Policy:       PolicySummary{DepartmentRoles: r.pol.DepartmentRoles, MaxSessionTTL: r.pol.MaxSessionTTL.String()},
		Steps:        r.steps,
		Agents:       r.agents,
		JITDecisions: r.jit,
		Findings:     findings,
		Devices:      r.devices,
		FinalState:   FinalState{Users: r.tp.AllUsers(ctx), Locks: locks, Sessions: sessions},
	}
}

// --- private (non-locking) helpers ---

func (r *Runner) applyHuman(ctx context.Context, ev hris.Event) ([]engine.Action, error) {
	actions, err := r.eng.Reconcile(ctx, ev)
	if err != nil {
		return nil, err
	}
	r.steps = append(r.steps, Step{Event: ev, Actions: actions})
	r.entitled[ev.Employee.Email] = r.pol.RolesFor(ev.Employee)
	r.active[ev.Employee.Email] = ev.Employee.Status == hris.Active
	return actions, nil
}

func (r *Runner) applyAgent(ctx context.Context, ev subject.AgentEvent) ([]engine.Action, error) {
	actions, err := r.eng.ReconcileAgent(ctx, ev)
	if err != nil {
		return nil, err
	}
	r.agents = append(r.agents, AgentStep{Event: ev, Actions: actions})
	return actions, nil
}

func (r *Runner) jitEval(ctx context.Context, req engine.AccessRequest) (engine.Decision, error) {
	d, err := r.eng.EvaluateAccessRequest(ctx, req)
	if err != nil {
		return d, err
	}
	r.jit = append(r.jit, d)
	return d, nil
}

func (r *Runner) injectAnomalies(ctx context.Context) {
	r.tp.UpsertUser(ctx, teleport.User{Name: "dave@goteleport.com", Roles: []string{"k8s-prod"}})
	r.tp.SeedSession(teleport.Session{
		ID: "sess-7f3a", User: "dave@goteleport.com", Kind: "k8s",
		Login: "dave", SourceIP: "203.0.113.51",
		Started: time.Date(2026, 7, 2, 11, 40, 0, 0, time.UTC),
	})
	r.entitled["dave@goteleport.com"] = nil
	r.active["dave@goteleport.com"] = false

	cur, _, _ := r.tp.GetUser(ctx, "alice@goteleport.com")
	r.tp.UpsertUser(ctx, teleport.User{
		Name:  "alice@goteleport.com",
		Roles: append(append([]string(nil), cur.Roles...), "it-admin"),
	})
}

func (r *Runner) seedDeviceSessions(ctx context.Context) {
	r.tp.SeedSession(teleport.Session{ID: "sess-9c21", User: "erin@goteleport.com", Kind: "ssh",
		Login: "erin", SourceIP: "198.51.100.31", Started: time.Date(2026, 7, 2, 11, 50, 0, 0, time.UTC)})
	r.tp.SeedSession(teleport.Session{ID: "sess-3e88", User: "frank@goteleport.com", Kind: "db",
		Login: "frank", SourceIP: "198.51.100.77", Started: time.Date(2026, 7, 2, 11, 55, 0, 0, time.UTC)})
	r.active["erin@goteleport.com"] = true
	r.active["frank@goteleport.com"] = true
	_ = ctx
}

// --- demo data ---

func demoHumans() []hris.Event {
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

func demoAgents() []subject.AgentEvent {
	sp := subject.SpiffeIDFor(trustDomain, "kyra")
	mk := func(status hris.Status, scope []string) subject.Subject {
		return subject.Subject{Kind: subject.KindAgent, ID: "A-kyra", Name: "kyra",
			Status: status, Scope: scope, SpiffeID: sp}
	}
	at := func(min int) time.Time { return time.Date(2026, 7, 2, 10, min, 0, 0, time.UTC) }
	return []subject.AgentEvent{
		{Type: hris.Joiner, Source: "deploy", Timestamp: at(0), Subject: mk(hris.Active, []string{"kyra-memory"})},
		{Type: hris.Mover, Source: "deploy", Timestamp: at(30), PriorScope: []string{"kyra-memory"},
			Subject: mk(hris.Active, []string{"kyra-memory", "kyra-calendar"})},
		{Type: hris.Leaver, Source: "deploy", Timestamp: at(90), Subject: mk(hris.Terminated, nil)},
	}
}

func demoDevices(now time.Time) []jamf.Device {
	fresh := now.Add(-1 * time.Hour)
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

// --- constructors for live API input ---

// NewHumanEvent builds a validated human event from primitive fields (API input).
func NewHumanEvent(typ, id, email, name, dept, title, priorDept string, ts time.Time) hris.Event {
	status := hris.Active
	et := hris.EventType(typ)
	if et == hris.Leaver {
		status = hris.Terminated
	}
	return hris.Event{
		Type: et, Source: "api", Timestamp: ts, PriorDepartment: priorDept,
		Employee: hris.Employee{ID: id, Email: email, Name: name, Department: dept, Title: title, Status: status},
	}
}

// NewAgentEvent builds an AI-agent event from primitive fields (API input).
func NewAgentEvent(typ, name string, scope, priorScope []string, ts time.Time) subject.AgentEvent {
	status := hris.Active
	et := hris.EventType(typ)
	if et == hris.Leaver {
		status = hris.Terminated
		scope = nil
	}
	return subject.AgentEvent{
		Type: et, Source: "api", Timestamp: ts, PriorScope: priorScope,
		Subject: subject.Subject{Kind: subject.KindAgent, ID: "A-" + name, Name: name,
			Status: status, Scope: scope, SpiffeID: subject.SpiffeIDFor(trustDomain, name)},
	}
}
