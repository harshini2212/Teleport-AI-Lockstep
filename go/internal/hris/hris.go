// Package hris models identity lifecycle events coming from an HR system
// (Rippling) or identity provider (Okta). In a real Teleport IT deployment
// these arrive as signed webhooks; here we model the payload and a parser so
// the rest of the engine is source-agnostic.
package hris

import (
	"encoding/json"
	"fmt"
	"time"
)

// EventType is the Joiner/Mover/Leaver (JML) classification that drives all
// downstream access decisions.
type EventType string

const (
	// Joiner: a new identity that needs access provisioned.
	Joiner EventType = "joiner"
	// Mover: an existing identity whose department/title changed, so its
	// access must be reconciled (grant new, revoke stale).
	Mover EventType = "mover"
	// Leaver: a terminated identity whose access must be fully revoked.
	Leaver EventType = "leaver"
)

// Status reflects the employment state reported by the source of truth.
type Status string

const (
	Active     Status = "active"
	Terminated Status = "terminated"
)

// Employee is the normalized identity record. Both Rippling and Okta payloads
// are mapped onto this shape by their respective adapters.
type Employee struct {
	ID         string `json:"id"`
	Email      string `json:"email"`
	Name       string `json:"name"`
	Department string `json:"department"`
	Title      string `json:"title"`
	Status     Status `json:"status"`
}

// Event is a single normalized lifecycle event.
type Event struct {
	Type EventType `json:"type"`
	// Source is "rippling" or "okta" — used for audit attribution.
	Source   string   `json:"source"`
	Employee Employee `json:"employee"`
	// PriorDepartment is set on Mover events so the engine can revoke roles
	// tied to the old department.
	PriorDepartment string    `json:"prior_department,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
}

// Validate guards against malformed events before they touch the access plane.
func (e Event) Validate() error {
	switch e.Type {
	case Joiner, Mover, Leaver:
	default:
		return fmt.Errorf("unknown event type %q", e.Type)
	}
	if e.Employee.Email == "" {
		return fmt.Errorf("event for %q missing employee email", e.Employee.ID)
	}
	if e.Type == Leaver && e.Employee.Status != Terminated {
		return fmt.Errorf("leaver event for %s must carry status=terminated", e.Employee.Email)
	}
	return nil
}

// ParseStream decodes a JSON array of events (as a webhook batch would deliver)
// and validates each one.
func ParseStream(raw []byte) ([]Event, error) {
	var events []Event
	if err := json.Unmarshal(raw, &events); err != nil {
		return nil, fmt.Errorf("decode hris stream: %w", err)
	}
	for i, ev := range events {
		if err := ev.Validate(); err != nil {
			return nil, fmt.Errorf("event %d: %w", i, err)
		}
	}
	return events, nil
}
