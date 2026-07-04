// Package okta is the IdP connector. It models SCIM 2.0 (Users/Groups, the
// group->role mapping) and Okta Event Hooks (the one-time verification handshake
// plus lifecycle deliveries). It implements connector.SourceConnector so Okta
// deprovisioning and group changes flow through the same hris.Event path.
package okta

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/connector"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/hris"
)

type doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client is the Okta connector.
type Client struct {
	http doer
	org  string
}

func New(h doer, org string) *Client { return &Client{http: h, org: org} }
func NewMock() *Client               { return &Client{org: "example"} }

func (c *Client) Name() string                     { return "okta" }
func (c *Client) HealthCheck(_ context.Context) error { return nil }

// SCIMUser is the RFC 7643 core user (subset).
type SCIMUser struct {
	Schemas  []string `json:"schemas"`
	ID       string   `json:"id"`
	UserName string   `json:"userName"`
	Name     struct {
		GivenName  string `json:"givenName"`
		FamilyName string `json:"familyName"`
	} `json:"name"`
	Active bool    `json:"active"`
	Emails []Email `json:"emails"`
}

// Email is a SCIM multi-valued email.
type Email struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary"`
}

// eventHookEnvelope is the Okta Event Hook delivery shape: {data:{events:[...]}}.
type eventHookEnvelope struct {
	Data struct {
		Events []eventHookEvent `json:"events"`
	} `json:"data"`
}

type eventHookEvent struct {
	EventType string `json:"eventType"`
	Published time.Time `json:"published"`
	Target    []struct {
		Type        string `json:"type"`
		ID          string `json:"id"`
		AlternateID string `json:"alternateId"` // the user's email
		DisplayName string `json:"displayName"`
	} `json:"target"`
}

// VerifyHook answers Okta's one-time verification GET by echoing the challenge
// header back as JSON. Returns the body Okta expects.
func (c *Client) VerifyHook(challenge string) map[string]string {
	return map[string]string{"verification": challenge}
}

// ParseWebhook maps Okta event-hook deliveries to canonical hris.Event values.
// Header "X-Okta-Verification-Challenge" short-circuits to a verification (no events).
func (c *Client) ParseWebhook(headers map[string]string, body []byte) ([]hris.Event, error) {
	if _, ok := headers["X-Okta-Verification-Challenge"]; ok {
		return nil, nil // verification handshake carries no lifecycle events
	}
	var env eventHookEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("okta: decode event hook: %w", err)
	}
	var out []hris.Event
	for _, e := range env.Data.Events {
		typ, status, ok := mapEvent(e.EventType)
		if !ok || len(e.Target) == 0 {
			continue
		}
		email := e.Target[0].AlternateID
		out = append(out, hris.Event{
			Type: typ, Source: "okta", Timestamp: e.Published,
			Employee: hris.Employee{
				ID: e.Target[0].ID, Email: email,
				Name: e.Target[0].DisplayName, Status: status,
			},
		})
	}
	return out, nil
}

// Poll is unused for Okta in the demo (event-hook driven); satisfies the interface.
func (c *Client) Poll(_ context.Context, _ time.Time) ([]hris.Event, error) { return nil, nil }

// DeactivateUser is the SCIM deprovision: PATCH active=false. Network-shaped.
func (c *Client) DeactivateUser(ctx context.Context, id string) error {
	if c.http == nil {
		return nil
	}
	url := fmt.Sprintf("https://%s.okta.com/api/v1/scim/v2/Users/%s", c.org, id)
	body := []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],` +
		`"Operations":[{"op":"replace","value":{"active":false}}]}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/scim+json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// GroupRoleMap maps Okta group displayNames to Teleport roles. It deliberately
// mirrors policy.DepartmentRoles so SSO group membership grants the same access
// the lifecycle policy would.
func GroupRoleMap() map[string][]string {
	return map[string][]string{
		"Engineering": {"dev-access", "k8s-staging"},
		"SRE":         {"dev-access", "k8s-prod", "db-readonly"},
		"Security":    {"auditor", "db-readonly"},
		"IT":          {"it-admin", "device-admin"},
		"Sales":       {"crm-access"},
		"Finance":     {"finance-app", "db-readonly"},
	}
}

func mapEvent(et string) (hris.EventType, hris.Status, bool) {
	switch et {
	case "user.lifecycle.activate", "user.lifecycle.create":
		return hris.Joiner, hris.Active, true
	case "user.lifecycle.deactivate", "user.lifecycle.suspend":
		return hris.Leaver, hris.Terminated, true
	case "group.user_membership.add", "group.user_membership.remove":
		return hris.Mover, hris.Active, true
	default:
		return "", "", false
	}
}

var _ connector.SourceConnector = (*Client)(nil)
