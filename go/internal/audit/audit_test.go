package audit

import (
	"context"
	"testing"
	"time"

	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/policy"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/teleport"
)

func TestDetectFlagsOffboardedActiveSession(t *testing.T) {
	ctx := context.Background()
	tp := teleport.NewMock()
	tp.UpsertUser(ctx, teleport.User{Name: "dave@x.com", Roles: []string{"k8s-prod"}})
	tp.SeedSession(teleport.Session{ID: "s1", User: "dave@x.com", Kind: "k8s", SourceIP: "203.0.113.51"})

	active := map[string]bool{"dave@x.com": false} // terminated in HRIS
	entitled := map[string][]string{"dave@x.com": nil}

	findings, err := Detect(ctx, tp, policy.Default(), active, entitled, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasDetector(findings, "offboarded-active-session") {
		t.Errorf("expected offboarded-active-session, got %+v", findings)
	}
	if !hasDetector(findings, "offboarded-identity-survives") {
		t.Errorf("expected offboarded-identity-survives, got %+v", findings)
	}
}

func TestDetectFlagsPrivilegeEscalation(t *testing.T) {
	ctx := context.Background()
	tp := teleport.NewMock()
	tp.UpsertUser(ctx, teleport.User{Name: "alice@x.com", Roles: []string{"dev-access", "it-admin"}})

	active := map[string]bool{"alice@x.com": true}
	entitled := map[string][]string{"alice@x.com": {"dev-access"}} // it-admin not entitled

	findings, _ := Detect(ctx, tp, policy.Default(), active, entitled, nil, nil, nil)
	if !hasDetector(findings, "privilege-escalation") {
		t.Errorf("expected privilege-escalation for it-admin, got %+v", findings)
	}
}

func TestLockSuppressesOffboardingFinding(t *testing.T) {
	ctx := context.Background()
	tp := teleport.NewMock()
	tp.SeedSession(teleport.Session{ID: "s1", User: "dave@x.com", Kind: "k8s", SourceIP: "203.0.113.51"})
	tp.CreateLock(ctx, teleport.Lock{Target: "dave@x.com", Reason: "offboarding"})

	active := map[string]bool{"dave@x.com": false}
	findings, _ := Detect(ctx, tp, policy.Default(), active, map[string][]string{}, nil, nil, nil)
	if hasDetector(findings, "offboarded-active-session") {
		t.Error("a locked identity should not raise offboarded-active-session")
	}
}

func TestNewGeoDetector(t *testing.T) {
	ctx := context.Background()
	tp := teleport.NewMock()
	tp.UpsertUser(ctx, teleport.User{Name: "bob@x.com", Roles: []string{"dev-access"}})
	tp.SeedSession(teleport.Session{ID: "s1", User: "bob@x.com", Kind: "ssh", SourceIP: "203.0.113.99"})

	active := map[string]bool{"bob@x.com": true}
	entitled := map[string][]string{"bob@x.com": {"dev-access"}}
	known := KnownIP{"bob@x.com": {"198.51.100.10": {}}}

	findings, _ := Detect(ctx, tp, policy.Default(), active, entitled, known, nil, nil)
	if !hasDetector(findings, "new-geo-access") {
		t.Errorf("expected new-geo-access, got %+v", findings)
	}
	_ = time.Now
}

func TestDetectDeviceTrust(t *testing.T) {
	ctx := context.Background()
	tp := teleport.NewMock()
	tp.SeedSession(teleport.Session{ID: "s1", User: "byod@x.com", Kind: "ssh", SourceIP: "203.0.113.7"})
	tp.SeedSession(teleport.Session{ID: "s2", User: "stale@x.com", Kind: "k8s", SourceIP: "198.51.100.4"})

	active := map[string]bool{"byod@x.com": true, "stale@x.com": true}
	entitled := map[string][]string{"byod@x.com": nil, "stale@x.com": nil}
	managed := map[string]bool{"byod@x.com": false, "stale@x.com": true}   // byod unmanaged
	compliant := map[string]bool{"byod@x.com": false, "stale@x.com": false} // stale managed but failing baseline

	findings, _ := Detect(ctx, tp, policy.Default(), active, entitled, nil, managed, compliant)
	if !hasDetector(findings, "unmanaged-device") {
		t.Errorf("expected unmanaged-device for byod, got %+v", findings)
	}
	if !hasDetector(findings, "noncompliant-device") {
		t.Errorf("expected noncompliant-device for stale, got %+v", findings)
	}
}

func hasDetector(fs []Finding, name string) bool {
	for _, f := range fs {
		if f.Detector == name {
			return true
		}
	}
	return false
}
