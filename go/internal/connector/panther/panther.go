// Package panther is the SIEM connector. Emit pushes Teleport audit events to a
// Panther HTTP log source (the same role the Teleport Event Handler plays);
// ListAlerts pulls open detections via Panther's GraphQL API so the controller
// can react to a Panther finding (e.g. impossible-travel) with a tctl lock.
// toFindings bridges Panther alerts into the existing audit.Finding pipeline.
package panther

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/audit"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/connector"
)

type doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client is the Panther connector.
type Client struct {
	http          doer
	httpSourceURL string // per-source webhook ingest URL
	graphQLURL    string // https://<instance>.runpanther.net/public/graphql
}

func New(h doer, httpSourceURL, graphQLURL string) *Client {
	return &Client{http: h, httpSourceURL: httpSourceURL, graphQLURL: graphQLURL}
}
func NewMock() *Client { return &Client{} }

func (c *Client) Name() string                     { return "panther" }
func (c *Client) HealthCheck(_ context.Context) error { return nil }

// Emit ships one normalized audit record to Panther's HTTP log source.
func (c *Client) Emit(ctx context.Context, rec connector.AuditRecord) error {
	if c.http == nil || c.httpSourceURL == "" {
		return nil // offline / sink not configured
	}
	body, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.httpSourceURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// Alert is a Panther detection (subset). Severity INFO|LOW|MEDIUM|HIGH|CRITICAL;
// Status OPEN|TRIAGED|RESOLVED.
type Alert struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Status   string `json:"status"`
}

// AlertsInput is the GraphQL query input (subset).
type AlertsInput struct {
	Statuses []string `json:"statuses,omitempty"`
	Cursor   string   `json:"cursor,omitempty"`
}

const listAlertsQuery = `query ListAlerts($input: AlertsInput!) {
  alerts(input: $input) {
    edges { node { id title severity status } }
    pageInfo { hasNextPage endCursor }
  }
}`

type alertsResponse struct {
	Data struct {
		Alerts struct {
			Edges []struct {
				Node Alert `json:"node"`
			} `json:"edges"`
			PageInfo struct {
				HasNextPage bool   `json:"hasNextPage"`
				EndCursor   string `json:"endCursor"`
			} `json:"pageInfo"`
		} `json:"alerts"`
	} `json:"data"`
}

// ListAlerts pulls a page of alerts; returns the next cursor (empty when done).
func (c *Client) ListAlerts(ctx context.Context, input AlertsInput) ([]Alert, string, error) {
	if c.http == nil || c.graphQLURL == "" {
		return nil, "", nil
	}
	payload, err := json.Marshal(map[string]any{
		"query":     listAlertsQuery,
		"variables": map[string]any{"input": input},
	})
	if err != nil {
		return nil, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.graphQLURL, bytes.NewReader(payload))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	var out alertsResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, "", err
	}
	alerts := make([]Alert, 0, len(out.Data.Alerts.Edges))
	for _, e := range out.Data.Alerts.Edges {
		alerts = append(alerts, e.Node)
	}
	cursor := ""
	if out.Data.Alerts.PageInfo.HasNextPage {
		cursor = out.Data.Alerts.PageInfo.EndCursor
	}
	return alerts, cursor, nil
}

// ToFindings bridges Panther alerts into the existing audit.Finding model so the
// controller's one remediation pipeline handles both engine- and SIEM-detected
// anomalies.
func ToFindings(alerts []Alert) []audit.Finding {
	out := make([]audit.Finding, 0, len(alerts))
	for _, a := range alerts {
		out = append(out, audit.Finding{
			Detector:    "panther:" + a.ID,
			Severity:    mapSeverity(a.Severity),
			Summary:     fmt.Sprintf("Panther detection %q (%s/%s)", a.Title, a.Severity, a.Status),
			Remediation: "triage in Panther; lock the principal if confirmed malicious",
		})
	}
	return out
}

func mapSeverity(s string) audit.Severity {
	switch s {
	case "CRITICAL":
		return audit.Critical
	case "HIGH":
		return audit.High
	default:
		return audit.Medium
	}
}

var _ connector.SinkConnector = (*Client)(nil)
