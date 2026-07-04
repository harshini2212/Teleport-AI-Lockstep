// Package zendesk is the helpdesk connector. It implements
// connector.TicketConnector and drives the headline helpdesk flow: a free-text
// lockout ticket ("lock out contractor jdoe, laptop stolen") is classified into
// a structured intent, the deterministic Temporal workflow executes the lock,
// and the ticket is updated with the resulting lock UUID.
//
// ClassifyAndExtract is the "NLP at the edge" seam — Harshini's strength applied
// where it belongs: turning messy human text into structured input. It ships a
// deterministic keyword classifier here (offline, auditable) and documents the
// LLM upgrade path; either way the AI only proposes — the audited pipeline + the
// Lean-verified offboarding path disposes.
package zendesk

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/connector"
)

// Client is the Zendesk connector (in-memory mock).
type Client struct {
	mu      sync.Mutex
	tickets map[string]connector.Ticket
	seq     int
}

func NewMock() *Client { return &Client{tickets: map[string]connector.Ticket{}} }

func (c *Client) Name() string                     { return "zendesk" }
func (c *Client) HealthCheck(_ context.Context) error { return nil }

func (c *Client) OpenTicket(_ context.Context, req connector.TicketRequest) (connector.Ticket, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	t := connector.Ticket{
		ID:           fmt.Sprintf("ZD-%d", c.seq),
		Subject:      req.Subject,
		Status:       "open",
		Priority:     orDefault(req.Priority, "normal"),
		CustomFields: req.CustomFields,
	}
	c.tickets[t.ID] = t
	return t, nil
}

func (c *Client) UpdateTicket(_ context.Context, id string, patch connector.TicketPatch) (connector.Ticket, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.tickets[id]
	if !ok {
		return connector.Ticket{}, fmt.Errorf("zendesk: no ticket %s", id)
	}
	if patch.Status != "" {
		t.Status = patch.Status
	}
	if t.CustomFields == nil {
		t.CustomFields = map[string]string{}
	}
	for k, v := range patch.CustomFields {
		t.CustomFields[k] = v
	}
	c.tickets[id] = t
	return t, nil
}

// LockoutRequest is the structured intent extracted from a free-text ticket.
type LockoutRequest struct {
	Intent string `json:"intent"` // "lockout" | "access_request" | "unknown"
	Target string `json:"target"` // the principal to act on
	Reason string `json:"reason"`
	TTL    string `json:"ttl,omitempty"`
}

var (
	emailRe   = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	userRe    = regexp.MustCompile(`(?i)\b(?:user|contractor|employee|account)\s+([a-zA-Z0-9._\-]+)`)
	lockWords = []string{"lock", "lockout", "stolen", "compromis", "terminate", "offboard", "revoke", "disable"}
)

// ClassifyAndExtract turns ticket text into a structured LockoutRequest. The
// deterministic classifier keys on intent words and extracts the target via an
// email or "user <name>" pattern. Replace with an LLM call for fuzzier text; the
// downstream workflow is identical because the output schema is the same.
func ClassifyAndExtract(_ context.Context, text string) (LockoutRequest, error) {
	lower := strings.ToLower(text)
	req := LockoutRequest{Intent: "unknown", Reason: strings.TrimSpace(text)}
	for _, w := range lockWords {
		if strings.Contains(lower, w) {
			req.Intent = "lockout"
			break
		}
	}
	if req.Intent == "unknown" && strings.Contains(lower, "access") {
		req.Intent = "access_request"
	}
	if m := emailRe.FindString(text); m != "" {
		req.Target = m
	} else if m := userRe.FindStringSubmatch(text); len(m) == 2 {
		req.Target = m[1]
	}
	return req, nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

var _ connector.TicketConnector = (*Client)(nil)
