// Package rippling is the HRIS source-of-truth connector. Rippling employee
// lifecycle events are the canonical trigger for Joiner/Mover/Leaver. It
// implements connector.SourceConnector: ParseWebhook normalizes a webhook batch,
// Poll is the API fallback (Rippling production webhooks are partner-gated, so
// polling /employees by lastModified is the honest non-partner path).
package rippling

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/connector"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/hris"
)

const apiBase = "https://api.rippling.com/platform/api"

// doer is the http swap seam (nil in the offline/webhook-only path).
type doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client is the Rippling connector.
type Client struct {
	http doer
	base string
}

// New builds a network-backed client. Pass http.DefaultClient in production.
func New(h doer) *Client { return &Client{http: h, base: apiBase} }

// NewMock builds a webhook-only client (no network); ParseWebhook is pure.
func NewMock() *Client { return &Client{base: apiBase} }

func (c *Client) Name() string { return "rippling" }

func (c *Client) HealthCheck(_ context.Context) error {
	if c.http == nil {
		return nil // webhook-only mode is always "healthy"
	}
	return nil
}

// WebhookEvent is the Rippling webhook envelope.
type WebhookEvent struct {
	Event     string    `json:"event"`
	Data      Employee  `json:"data"`
	Timestamp time.Time `json:"timestamp"`
}

// Employee is the Rippling employee resource (subset).
type Employee struct {
	ID               string `json:"id"`
	WorkEmail        string `json:"workEmail"`
	FirstName        string `json:"firstName"`
	LastName         string `json:"lastName"`
	Department       string `json:"department"`
	PriorDepartment  string `json:"priorDepartment,omitempty"`
	Title            string `json:"title"`
	EmploymentStatus string `json:"employmentStatus"` // ACTIVE | INACTIVE
}

// ParseWebhook maps a JSON array of Rippling webhook events to canonical
// hris.Event values. Unknown event types are skipped, not errored.
func (c *Client) ParseWebhook(_ map[string]string, body []byte) ([]hris.Event, error) {
	var batch []WebhookEvent
	if err := json.Unmarshal(body, &batch); err != nil {
		return nil, fmt.Errorf("rippling: decode webhook: %w", err)
	}
	var out []hris.Event
	for _, w := range batch {
		typ, ok := mapEvent(w.Event)
		if !ok {
			continue
		}
		emp := hris.Employee{
			ID:         w.Data.ID,
			Email:      w.Data.WorkEmail,
			Name:       w.Data.FirstName + " " + w.Data.LastName,
			Department: w.Data.Department,
			Title:      w.Data.Title,
			Status:     statusFor(typ, w.Data.EmploymentStatus),
		}
		out = append(out, hris.Event{
			Type:            typ,
			Source:          "rippling",
			Employee:        emp,
			PriorDepartment: w.Data.PriorDepartment,
			Timestamp:       w.Timestamp,
		})
	}
	return out, nil
}

// Poll is the API fallback: GET /employees?lastModified=. Network-shaped; the
// committed demo uses ParseWebhook, so this is here for the real swap-in.
func (c *Client) Poll(ctx context.Context, since time.Time) ([]hris.Event, error) {
	if c.http == nil {
		return nil, nil // no transport configured (offline/webhook-only)
	}
	url := fmt.Sprintf("%s/employees?lastModified=%s", c.base, since.UTC().Format(time.RFC3339))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var emps []Employee
	if err := json.NewDecoder(resp.Body).Decode(&emps); err != nil {
		return nil, err
	}
	out := make([]hris.Event, 0, len(emps))
	for _, e := range emps {
		typ := hris.Mover
		if e.EmploymentStatus == "INACTIVE" {
			typ = hris.Leaver
		}
		out = append(out, hris.Event{Type: typ, Source: "rippling", Timestamp: since,
			Employee: hris.Employee{ID: e.ID, Email: e.WorkEmail,
				Name: e.FirstName + " " + e.LastName, Department: e.Department,
				Title: e.Title, Status: statusFor(typ, e.EmploymentStatus)}})
	}
	return out, nil
}

func mapEvent(ev string) (hris.EventType, bool) {
	switch ev {
	case "employee.created", "employee.rehired":
		return hris.Joiner, true
	case "employee.terminated":
		return hris.Leaver, true
	case "employee.updated", "employee.department_changed", "employee.manager_changed":
		return hris.Mover, true
	default:
		return "", false
	}
}

func statusFor(typ hris.EventType, employmentStatus string) hris.Status {
	if typ == hris.Leaver || employmentStatus == "INACTIVE" {
		return hris.Terminated
	}
	return hris.Active
}

var _ connector.SourceConnector = (*Client)(nil)
