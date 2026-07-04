package policy

import (
	"reflect"
	"testing"

	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/hris"
)

func TestRolesForCombinesDepartmentAndTitle(t *testing.T) {
	p := Default()
	got := p.RolesFor(hris.Employee{Department: "IT", Title: "Manager", Status: hris.Active})
	want := []string{"access-reviewer", "device-admin", "it-admin"} // sorted, deduped
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("RolesFor = %v, want %v", got, want)
	}
}

// This is the core safety property the Lean proof formalizes: a terminated
// employee is entitled to nothing, no matter their department or title.
func TestTerminatedEmployeeGetsNoRoles(t *testing.T) {
	p := Default()
	for _, dept := range []string{"Engineering", "SRE", "Security", "IT", "Sales", "Finance"} {
		got := p.RolesFor(hris.Employee{Department: dept, Title: "Director", Status: hris.Terminated})
		if len(got) != 0 {
			t.Errorf("terminated %s employee entitled to %v, want none", dept, got)
		}
	}
}

func TestCanAutoApprove(t *testing.T) {
	p := Default()
	if !p.CanAutoApprove([]string{"k8s-prod"}, "db-readonly") {
		t.Error("SRE holding k8s-prod should auto-approve db-readonly")
	}
	if p.CanAutoApprove([]string{"crm-access"}, "it-admin") {
		t.Error("crm-access must not auto-approve it-admin")
	}
}
