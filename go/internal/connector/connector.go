// Package connector defines one vendor-agnostic interface family for the
// system's edges — HRIS, IdP, SIEM, helpdesk, and device signals. Every vendor
// sub-package (rippling, okta, panther, zendesk, chrome) implements these, and
// the Temporal activities call them, so the workflow/engine never depend on a
// vendor package directly. This mirrors the teleport.Client seam: an interface
// plus a Mock, with a `doer` swap point for the real *http.Client.
package connector

import (
	"context"
	"net/http"
	"time"

	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/hris"
)

// Connector is the common base — every edge can name itself and be health-checked.
type Connector interface {
	Name() string
	HealthCheck(ctx context.Context) error
}

// SourceConnector turns vendor lifecycle events into canonical hris.Event values
// (Rippling = HRIS source of truth; Okta = IdP). All vendor events are mapped
// onto hris.Joiner/Mover/Leaver — no new event vocabulary.
type SourceConnector interface {
	Connector
	Poll(ctx context.Context, since time.Time) ([]hris.Event, error)
	ParseWebhook(headers map[string]string, body []byte) ([]hris.Event, error)
}

// SinkConnector ships audit records outward to a SIEM (Panther).
type SinkConnector interface {
	Connector
	Emit(ctx context.Context, rec AuditRecord) error
}

// TicketConnector drives the human helpdesk loop (Zendesk): a lockout/access
// ticket opens a workflow, and the workflow writes status back to the ticket.
type TicketConnector interface {
	Connector
	OpenTicket(ctx context.Context, req TicketRequest) (Ticket, error)
	UpdateTicket(ctx context.Context, id string, patch TicketPatch) (Ticket, error)
}

// SignalConnector yields a device-trust posture signal (Chrome Enterprise).
type SignalConnector interface {
	Connector
	DeviceSignal(ctx context.Context, principal string) (DeviceTrust, error)
}

// AuditRecord is a Teleport audit event normalized for SIEM ingest.
type AuditRecord struct {
	Event string          `json:"event"`
	User  string          `json:"user"`
	Time  time.Time       `json:"time"`
	Raw   map[string]any  `json:"raw,omitempty"`
}

// Ticket is a helpdesk ticket.
type Ticket struct {
	ID           string            `json:"id"`
	Subject      string            `json:"subject"`
	Status       string            `json:"status"`   // new|open|pending|hold|solved|closed
	Priority     string            `json:"priority"` // urgent|high|normal|low
	CustomFields map[string]string `json:"custom_fields,omitempty"`
}

// TicketRequest opens a ticket.
type TicketRequest struct {
	Subject      string
	Body         string
	Priority     string
	CustomFields map[string]string
}

// TicketPatch updates a ticket (e.g. mark solved with the lock UUID).
type TicketPatch struct {
	Status       string
	Comment      string
	CustomFields map[string]string
}

// DeviceTrust is a context-aware-access posture signal.
type DeviceTrust struct {
	DeviceID       string   `json:"device_id"`
	Verified       bool     `json:"verified"`
	BrowserVersion string   `json:"browser_version,omitempty"`
	Reasons        []string `json:"reasons,omitempty"`
}

// doer is the swap point: a Mock in tests/offline, *http.Client in production.
type doer interface {
	Do(*http.Request) (*http.Response, error)
}

// ensure *http.Client satisfies doer at compile time.
var _ doer = (*http.Client)(nil)
