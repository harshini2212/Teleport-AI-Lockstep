// Package chrome is the Google Chrome Enterprise connector. It yields a
// device-trust / context-aware-access posture signal from an enrolled managed
// browser (Chrome Enterprise Core / Browser Cloud Management, surfaced via the
// Admin SDK Directory "chromebrowsers" resource). It implements
// connector.SignalConnector so a stale or unenrolled browser can gate access,
// complementing the Jamf endpoint signal.
package chrome

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/connector"
)

type doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client is the Chrome Enterprise connector.
type Client struct {
	http     doer
	customer string // Admin SDK customer id, e.g. "my_customer"
	// minVersion gates on a minimum enrolled browser major version.
	minVersion int
	// seeded posture for the offline mock, keyed by principal (email).
	seeded map[string]connector.DeviceTrust
}

func New(h doer, customer string, minVersion int) *Client {
	return &Client{http: h, customer: customer, minVersion: minVersion, seeded: map[string]connector.DeviceTrust{}}
}

// NewMock returns a connector pre-seeded with per-principal posture.
func NewMock(seed map[string]connector.DeviceTrust) *Client {
	if seed == nil {
		seed = map[string]connector.DeviceTrust{}
	}
	return &Client{seeded: seed, minVersion: 120}
}

func (c *Client) Name() string                     { return "chrome-enterprise" }
func (c *Client) HealthCheck(_ context.Context) error { return nil }

// browserRecord is the Admin SDK Directory chromebrowsers resource (subset).
type browserRecord struct {
	DeviceID           string `json:"deviceId"`
	LastActivityUser   string `json:"lastActivityUserEmail"`
	BrowserVersions    []struct {
		Version string `json:"version"`
		Channel string `json:"channel"`
	} `json:"browserVersions"`
	SafeBrowsingEnabled bool `json:"safeBrowsingClickThroughDisabled"`
}

// DeviceSignal returns the posture for a principal. Offline, it reads seeded
// state; with an http transport it would query the Admin SDK Directory API.
func (c *Client) DeviceSignal(ctx context.Context, principal string) (connector.DeviceTrust, error) {
	if c.http == nil {
		if dt, ok := c.seeded[principal]; ok {
			return dt, nil
		}
		// Unknown principal => unverified (no enrolled managed browser found).
		return connector.DeviceTrust{Verified: false, Reasons: []string{"no enrolled managed browser"}}, nil
	}
	url := fmt.Sprintf(
		"https://admin.googleapis.com/admin/directory/v1.1beta1/customer/%s/devices/chromebrowsers?query=user:%s",
		c.customer, principal)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return connector.DeviceTrust{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return connector.DeviceTrust{}, err
	}
	defer resp.Body.Close()
	var out struct {
		Browsers []browserRecord `json:"browsers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return connector.DeviceTrust{}, err
	}
	if len(out.Browsers) == 0 {
		return connector.DeviceTrust{Verified: false, Reasons: []string{"no enrolled managed browser"}}, nil
	}
	b := out.Browsers[0]
	ver := ""
	if len(b.BrowserVersions) > 0 {
		ver = b.BrowserVersions[0].Version
	}
	return connector.DeviceTrust{
		DeviceID: b.DeviceID, Verified: true, BrowserVersion: ver,
	}, nil
}

var _ connector.SignalConnector = (*Client)(nil)
