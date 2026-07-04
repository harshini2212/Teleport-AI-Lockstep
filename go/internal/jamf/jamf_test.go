package jamf

import (
	"context"
	"testing"
	"time"
)

func TestParseComplianceJSON(t *testing.T) {
	raw := []byte(`{"serial":"C02XY","filevault":true,"firewall":true,"gatekeeper":true,
		"sip":true,"screen_lock":true,"auto_updates":true,"guest_disabled":true,"overall":true}`)
	c, err := ParseComplianceJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Overall || !c.FileVault || !c.GuestDisabled {
		t.Fatalf("expected fully compliant, got %+v", c)
	}
}

func TestDeviceGating(t *testing.T) {
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-1 * time.Hour)
	stale := now.Add(-72 * time.Hour)

	cases := []struct {
		name string
		d    Device
		want bool
	}{
		{"managed+compliant+fresh", Device{Managed: true, Compliance: Compliance{Overall: true}, LastInventoryUpdate: fresh}, true},
		{"managed+noncompliant", Device{Managed: true, Compliance: Compliance{Overall: false}, LastInventoryUpdate: fresh}, false},
		{"unmanaged", Device{Managed: false, Compliance: Compliance{Overall: true}, LastInventoryUpdate: fresh}, false},
		{"stale inventory", Device{Managed: true, Compliance: Compliance{Overall: true}, LastInventoryUpdate: stale}, false},
	}
	for _, tc := range cases {
		if got := tc.d.IsCompliant(now); got != tc.want {
			t.Errorf("%s: IsCompliant=%v want %v", tc.name, got, tc.want)
		}
	}
}

func TestPostureMaps(t *testing.T) {
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	m := NewMock(now,
		Device{SerialNumber: "C1", UserEmail: "good@x.com", Managed: true,
			Compliance: Compliance{Overall: true}, LastInventoryUpdate: now.Add(-time.Hour)},
		Device{SerialNumber: "C2", UserEmail: "byod@x.com", Managed: false,
			Compliance: Compliance{Overall: true}, LastInventoryUpdate: now},
	)
	managed, compliant, err := PostureMaps(context.Background(), m, now)
	if err != nil {
		t.Fatal(err)
	}
	if !managed["good@x.com"] || compliant["byod@x.com"] {
		t.Fatalf("posture maps wrong: managed=%v compliant=%v", managed, compliant)
	}
	if !compliant["good@x.com"] || managed["byod@x.com"] {
		t.Fatalf("posture maps wrong: managed=%v compliant=%v", managed, compliant)
	}
}
