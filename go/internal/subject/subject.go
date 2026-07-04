// Package subject is the unifying identity abstraction. Teleport secures "every
// human, machine, workload, and AI agent" — so the lifecycle controller models
// humans and AI agents as one Subject type that flows through the SAME reconcile
// path. A human Subject maps 1:1 onto hris.Employee; an AI-agent Subject carries
// a SPIFFE identity and a capability Scope instead of a department/title.
//
// The whole point: access is a pure function of the Subject record for both
// kinds, so the "offboarding is total" guarantee (proven in ../../lean) extends
// to agents — a decommissioned agent is entitled to nothing, exactly like a
// terminated employee.
package subject

import (
	"time"

	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/hris"
)

// Kind discriminates a human identity from an AI-agent / workload identity.
type Kind string

const (
	KindHuman Kind = "human"
	KindAgent Kind = "agent"
)

// Subject is one identity the controller governs.
type Subject struct {
	Kind       Kind        `json:"kind"`
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Email      string      `json:"email,omitempty"`
	Department string      `json:"department,omitempty"`
	Title      string      `json:"title,omitempty"`
	Status     hris.Status `json:"status"`
	// Scope is the agent's declared capabilities (e.g. "kyra-memory"); the
	// policy maps each to Teleport roles, just as a department maps to roles.
	Scope []string `json:"scope,omitempty"`
	// SpiffeID is the agent's cryptographic identity, e.g.
	// spiffe://teleport.example.com/agents/kyra.
	SpiffeID string `json:"spiffe_id,omitempty"`
}

// FromEmployee lifts an HRIS employee into a human Subject, so the human path is
// unchanged and the agent path is purely additive.
func FromEmployee(e hris.Employee) Subject {
	return Subject{
		Kind:       KindHuman,
		ID:         e.ID,
		Name:       e.Name,
		Email:      e.Email,
		Department: e.Department,
		Title:      e.Title,
		Status:     e.Status,
	}
}

// SpiffeIDFor builds an agent SPIFFE ID. The trust domain is fixed per Teleport
// cluster; only the path segment after it is templated per agent.
func SpiffeIDFor(trustDomain, name string) string {
	return "spiffe://" + trustDomain + "/agents/" + name
}

// AgentEvent is the agent-side analog of hris.Event — a join/move/leave for an
// AI-agent workload. Reusing hris.EventType keeps one lifecycle vocabulary.
type AgentEvent struct {
	Type      hris.EventType `json:"type"`
	Source    string         `json:"source"`
	Subject   Subject        `json:"subject"`
	PriorScope []string      `json:"prior_scope,omitempty"`
	Timestamp time.Time      `json:"timestamp"`
}
