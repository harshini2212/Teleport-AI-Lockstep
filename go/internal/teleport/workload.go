package teleport

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// This file models the Machine & Workload Identity surface of the Teleport API
// client — the primitives that give an AI agent or workload a short-lived,
// cryptographically-verifiable SPIFFE identity instead of a static secret.
//
// Real-client / CLI correspondence:
//
//	UpsertWorkloadIdentity -> create/update a `workload_identity` resource (kind: workload_identity, v1)
//	AddBot / RemoveBot     -> `tctl bots add --roles ...` / `tctl bots rm`
//	IssueSVID              -> what `tbot` does at runtime via the SPIFFE Workload API
//	LockBot                -> `tctl lock --user <bot-user>` — severs an already-issued SVID before its TTL
//
// The lock matters: deleting the workload_identity or bot does NOT instantly
// revoke an SVID that was already minted (it is valid until its short TTL).
// Locking the bot user is the agent analog of the human deprovision lock, and is
// what makes agent offboarding *total* (mirrored in the Lean proof).

// AgentWorkload is the controller-side view of an AI-agent identity.
type AgentWorkload struct {
	SpiffeID    string   `json:"spiffe_id"`
	Name        string   `json:"name"`
	Scope       []string `json:"scope"` // Teleport roles the agent is entitled to
	Status      string   `json:"status"`
	TrustDomain string   `json:"trust_domain"`
}

// WorkloadIdentity mirrors the `workload_identity` resource: it templates the
// SPIFFE ID and the rules under which an SVID is issued.
type WorkloadIdentity struct {
	Name             string      `json:"name"`
	SpiffeIDTemplate string      `json:"spiffe_id_template"` // e.g. /agents/kyra/{{ user.name }}
	Hint             string      `json:"hint,omitempty"`
	AllowRules       []AllowRule `json:"allow_rules,omitempty"`
}

// AllowRule is one attribute-based issuance condition. Op in {eq,not_eq,in,not_in}.
type AllowRule struct {
	Attribute string `json:"attribute"`
	Op        string `json:"op"`
	Value     string `json:"value"`
}

// Bot mirrors a Teleport bot (a Machine ID identity). In reality a bot is three
// linked resources (bot user + bot role + join token); the mock collapses them
// to the fields the lifecycle controller manipulates.
type Bot struct {
	Name         string   `json:"name"`
	Roles        []string `json:"roles"`
	LockedReason string   `json:"locked_reason,omitempty"`
}

// SVID is a (mock) SPIFFE Verifiable Identity Document. A real X509-SVID is a
// short-lived, auto-rotated mTLS certificate.
type SVID struct {
	SpiffeID  string    `json:"spiffe_id"`
	NotAfter  time.Time `json:"not_after"`
	Serial    string    `json:"serial"`
}

// WorkloadClient is the agent-identity surface, a sibling to Client. The real
// api/client implements both, so swapping NewMock() for client.New() keeps the
// engine code unchanged.
type WorkloadClient interface {
	UpsertWorkloadIdentity(ctx context.Context, wi WorkloadIdentity) error
	DeleteWorkloadIdentity(ctx context.Context, name string) error
	AddBot(ctx context.Context, b Bot) error
	RemoveBot(ctx context.Context, name string) error
	IssueSVID(ctx context.Context, name string) (SVID, error)
	LockBot(ctx context.Context, target, reason string) error
}

func (m *Mock) UpsertWorkloadIdentity(_ context.Context, wi WorkloadIdentity) error {
	if wi.Name == "" {
		return fmt.Errorf("workload identity name required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.wis[wi.Name] = wi
	return nil
}

func (m *Mock) DeleteWorkloadIdentity(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.wis, name)
	return nil
}

func (m *Mock) AddBot(_ context.Context, b Bot) error {
	if b.Name == "" {
		return fmt.Errorf("bot name required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	roles := append([]string(nil), b.Roles...)
	sort.Strings(roles)
	b.Roles = roles
	m.bots[b.Name] = b
	return nil
}

func (m *Mock) RemoveBot(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.bots, name)
	return nil
}

// IssueSVID models tbot minting an SVID. It fails (no credential) if the bot is
// locked or its workload identity has been deleted — so a revoked agent can
// obtain no new access, and the lock severs any it already holds.
func (m *Mock) IssueSVID(_ context.Context, name string) (SVID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.bots[name]
	if !ok {
		return SVID{}, fmt.Errorf("no bot %q: identity revoked", name)
	}
	if b.LockedReason != "" {
		return SVID{}, fmt.Errorf("bot %q is locked: %s", name, b.LockedReason)
	}
	wi, ok := m.wis[name]
	if !ok {
		return SVID{}, fmt.Errorf("no workload_identity for %q: cannot issue SVID", name)
	}
	return SVID{SpiffeID: wi.SpiffeIDTemplate, Serial: "svid-" + name}, nil
}

// LockBot marks the bot locked. A locked bot can mint no SVIDs and any in-flight
// SVID is treated as severed.
func (m *Mock) LockBot(_ context.Context, target, reason string) error {
	if target == "" {
		return fmt.Errorf("lock target required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	b := m.bots[target]
	b.Name = target
	b.LockedReason = reason
	m.bots[target] = b
	// A bot lock is also a cluster lock on the bot user.
	m.locks["bot-"+target] = Lock{Target: "bot-" + target, Reason: reason}
	return nil
}

// AllWorkloadIdentities / AllBots expose state for the audit pass and dashboard.
func (m *Mock) AllWorkloadIdentities(_ context.Context) []WorkloadIdentity {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]WorkloadIdentity, 0, len(m.wis))
	for _, wi := range m.wis {
		out = append(out, wi)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (m *Mock) AllBots(_ context.Context) []Bot {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Bot, 0, len(m.bots))
	for _, b := range m.bots {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
