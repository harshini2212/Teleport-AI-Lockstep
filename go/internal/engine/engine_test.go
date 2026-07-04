package engine

import (
	"context"
	"testing"
	"time"

	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/hris"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/policy"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/teleport"
)

func newEngine() (*Engine, *teleport.Mock) {
	tp := teleport.NewMock()
	return New(policy.Default(), tp), tp
}

func joiner(email, dept, title string) hris.Event {
	return hris.Event{Type: hris.Joiner, Source: "rippling", Timestamp: time.Now(),
		Employee: hris.Employee{ID: "x", Email: email, Department: dept, Title: title, Status: hris.Active}}
}

func TestJoinerProvisionsEntitledRoles(t *testing.T) {
	eng, tp := newEngine()
	if _, err := eng.Reconcile(context.Background(), joiner("a@x.com", "SRE", "Engineer")); err != nil {
		t.Fatal(err)
	}
	u, ok, _ := tp.GetUser(context.Background(), "a@x.com")
	if !ok {
		t.Fatal("user not provisioned")
	}
	if len(u.Roles) != 3 { // dev-access, k8s-prod, db-readonly
		t.Fatalf("got roles %v", u.Roles)
	}
}

func TestMoverReconcilesRoles(t *testing.T) {
	eng, tp := newEngine()
	ctx := context.Background()
	eng.Reconcile(ctx, joiner("a@x.com", "Engineering", "Engineer"))

	move := hris.Event{Type: hris.Mover, Source: "rippling", Timestamp: time.Now(), PriorDepartment: "Engineering",
		Employee: hris.Employee{ID: "x", Email: "a@x.com", Department: "Finance", Title: "Engineer", Status: hris.Active}}
	if _, err := eng.Reconcile(ctx, move); err != nil {
		t.Fatal(err)
	}
	u, _, _ := tp.GetUser(ctx, "a@x.com")
	// Finance => finance-app, db-readonly. The Engineering roles must be gone.
	for _, r := range u.Roles {
		if r == "dev-access" || r == "k8s-staging" {
			t.Fatalf("stale Engineering role survived move: %v", u.Roles)
		}
	}
}

// Offboarding must both delete the user AND issue a lock.
func TestLeaverLocksAndDeprovisions(t *testing.T) {
	eng, tp := newEngine()
	ctx := context.Background()
	eng.Reconcile(ctx, joiner("a@x.com", "SRE", "Engineer"))

	leave := hris.Event{Type: hris.Leaver, Source: "rippling", Timestamp: time.Now(),
		Employee: hris.Employee{ID: "x", Email: "a@x.com", Department: "SRE", Title: "Engineer", Status: hris.Terminated}}
	if _, err := eng.Reconcile(ctx, leave); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := tp.GetUser(ctx, "a@x.com"); ok {
		t.Error("user should be deprovisioned")
	}
	locks, _ := tp.ListLocks(ctx)
	if len(locks) != 1 || locks[0].Target != "a@x.com" {
		t.Errorf("expected a lock on a@x.com, got %v", locks)
	}
}

func TestJITAutoApproveAndDeny(t *testing.T) {
	eng, _ := newEngine()
	ctx := context.Background()
	eng.Reconcile(ctx, joiner("sre@x.com", "SRE", "Engineer")) // holds k8s-prod

	auto, _ := eng.EvaluateAccessRequest(ctx, AccessRequest{User: "sre@x.com", Requested: "db-readonly"})
	if !auto.AutoApprove {
		t.Error("db-readonly should auto-approve for k8s-prod holder")
	}
	deny, _ := eng.EvaluateAccessRequest(ctx, AccessRequest{User: "sre@x.com", Requested: "it-admin"})
	if deny.AutoApprove {
		t.Error("it-admin must route to a human")
	}
}
