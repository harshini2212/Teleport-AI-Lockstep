// Package jamf is the Jamf Pro (macOS MDM) connector. It mirrors Teleport's
// built-in `jamf_service`, which syncs Jamf computer inventory into Teleport's
// device registry on a schedule; "trusted device" then means "in Jamf, managed,
// and compliant." The committed code ships only the in-memory Mock + interface
// (same pattern as internal/teleport); the real client would call the Jamf Pro
// API over net/http. It also parses the JSON emitted by macos/compliance-check.sh.
package jamf

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// Compliance unmarshals the strict JSON document emitted by
// macos/compliance-check.sh. Keys MUST match that script exactly.
type Compliance struct {
	FileVault     bool `json:"filevault"`
	Firewall      bool `json:"firewall"`
	Gatekeeper    bool `json:"gatekeeper"`
	SIP           bool `json:"sip"`
	ScreenLock    bool `json:"screen_lock"`
	AutoUpdates   bool `json:"auto_updates"`
	GuestDisabled bool `json:"guest_disabled"`
	Overall       bool `json:"overall"`
}

// complianceDoc is the full compliance-check.sh document (controls + serial).
type complianceDoc struct {
	Serial string `json:"serial"`
	Compliance
}

// Device is a synced Jamf computer record, joined to Teleport on the hardware
// serial number (Teleport's device asset-tag).
type Device struct {
	SerialNumber        string     `json:"serial_number"`
	UserEmail           string     `json:"user_email"`
	Managed             bool       `json:"managed"`
	Supervised          bool       `json:"supervised"`
	Compliance          Compliance `json:"compliance"`
	LastInventoryUpdate time.Time  `json:"last_inventory_update"`
}

// Config mirrors the Teleport `jamf_service` config block (teleport.yaml).
type Config struct {
	APIEndpoint       string        `json:"api_endpoint"`
	ClientID          string        `json:"client_id"`
	ClientSecretFile  string        `json:"client_secret_file"`
	SyncPeriodPartial time.Duration `json:"sync_period_partial"`
	SyncPeriodFull    time.Duration `json:"sync_period_full"`
	OnMissing         string        `json:"on_missing"` // DELETE | NOOP
	// FilterRSQL is the config-as-code equivalent of a Jamf Smart Group, e.g.
	// "general.remoteManagement.managed==true".
	FilterRSQL string `json:"filter_rsql"`
}

// Client is the device-posture surface the controller consumes.
type Client interface {
	ListDevices(ctx context.Context) ([]Device, error)
	GetDeviceForUser(ctx context.Context, email string) (Device, bool, error)
}

// staleAfter: inventory older than this is treated as non-compliant (we can't
// vouch for a device we haven't heard from).
const staleAfter = 24 * time.Hour

// Mock is an in-memory Jamf inventory.
type Mock struct {
	devices []Device
	now     time.Time
}

// NewMock builds a mock inventory. `now` anchors staleness checks deterministically.
func NewMock(now time.Time, devices ...Device) *Mock {
	return &Mock{devices: devices, now: now}
}

func (m *Mock) ListDevices(_ context.Context) ([]Device, error) {
	out := append([]Device(nil), m.devices...)
	sort.Slice(out, func(i, j int) bool { return out[i].SerialNumber < out[j].SerialNumber })
	return out, nil
}

func (m *Mock) GetDeviceForUser(_ context.Context, email string) (Device, bool, error) {
	for _, d := range m.devices {
		if d.UserEmail == email {
			return d, true, nil
		}
	}
	return Device{}, false, nil
}

// IsCompliant reports whether a device should be treated as compliant right now:
// it must be managed, pass its hardening baseline, and have fresh inventory.
func (d Device) IsCompliant(now time.Time) bool {
	if !d.Managed || !d.Compliance.Overall {
		return false
	}
	return now.Sub(d.LastInventoryUpdate) <= staleAfter
}

// PostureMaps reduces the inventory to the two maps audit.Detect consumes
// (managed / compliant, keyed by user email), keeping audit decoupled from jamf.
func PostureMaps(ctx context.Context, c Client, now time.Time) (managed, compliant map[string]bool, err error) {
	devices, err := c.ListDevices(ctx)
	if err != nil {
		return nil, nil, err
	}
	managed = map[string]bool{}
	compliant = map[string]bool{}
	for _, d := range devices {
		if d.UserEmail == "" {
			continue
		}
		managed[d.UserEmail] = d.Managed
		compliant[d.UserEmail] = d.IsCompliant(now)
	}
	return managed, compliant, nil
}

// ParseComplianceJSON consumes macos/compliance-check.sh stdout.
func ParseComplianceJSON(b []byte) (Compliance, error) {
	var doc complianceDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return Compliance{}, fmt.Errorf("parse compliance json: %w", err)
	}
	return doc.Compliance, nil
}
