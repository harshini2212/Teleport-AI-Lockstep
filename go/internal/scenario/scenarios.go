package scenario

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/audit"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/engine"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/hris"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/jamf"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/subject"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/teleport"
)

// ScenarioInfo is one entry in the browsable catalog ("projects" the user picks).
type ScenarioInfo struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
}

// ScenarioRef is the currently-loaded scenario, attached to every Trace.
type ScenarioRef struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

var catalog = []ScenarioInfo{
	{"baseline", "Acme Corp — live org",
		"A mixed org mid-quarter: humans onboarded, moved, and offboarded; the Kyra AI agent issued a SPIFFE identity; plus real anomalies to triage.",
		[]string{"humans", "ai-agent", "anomalies", "device-trust"}},
	{"clean", "Nimbus Labs — healthy baseline",
		"A fully compliant org — least-privilege roles, managed & compliant devices, zero anomalies. What 'good' looks like.",
		[]string{"compliant", "zero-findings"}},
	{"offboarding-crisis", "Vertex Bank — offboarding audit",
		"Three terminated employees whose access lingered: surviving accounts and a live production session. The NIST AC-2 nightmare.",
		[]string{"offboarding", "critical", "insider-risk"}},
	{"rogue-agent", "Helios AI — agent security",
		"Several AI agents in production; one workload identity is being abused with escalated roles from a new geography.",
		[]string{"ai-agent", "privilege-escalation", "new-geo"}},
	{"byod-sprawl", "Northwind Remote — device trust",
		"A remote-first team reaching sensitive resources from unmanaged and non-compliant Macs. Device Trust gating in action.",
		[]string{"device-trust", "jamf", "byod"}},
}

// Scenarios returns the catalog.
func Scenarios() []ScenarioInfo { return catalog }

func titleFor(id string) string {
	for _, s := range catalog {
		if s.ID == id {
			return s.Title
		}
	}
	return id
}

var seeders = map[string]func(*Runner){
	"baseline":           seedBaseline,
	"clean":              seedClean,
	"offboarding-crisis": seedOffboardingCrisis,
	"rogue-agent":        seedRogueAgent,
	"byod-sprawl":        seedBYODSprawl,
}

// loadLocked resets and seeds a scenario. Unknown ids fall back to baseline so
// the app never renders empty.
func (r *Runner) loadLocked(id string) error {
	r.reset()
	fn, ok := seeders[id]
	if !ok {
		r.current = "baseline"
		seedBaseline(r)
		return fmt.Errorf("unknown scenario %q", id)
	}
	r.current = id
	fn(r)
	return nil
}

// --- authoring helpers (called with the lock held) ---

func dayT(h, min int) time.Time { return time.Date(2026, 7, 2, h, min, 0, 0, time.UTC) }

func userLocal(email string) string {
	if i := strings.IndexByte(email, '@'); i >= 0 {
		return email[:i]
	}
	return email
}

func (r *Runner) addHuman(source string, typ hris.EventType, id, email, name, dept, title, prior string, min int) {
	st := hris.Active
	if typ == hris.Leaver {
		st = hris.Terminated
	}
	_, _ = r.applyHuman(context.Background(), hris.Event{
		Type: typ, Source: source, Timestamp: dayT(9, min), PriorDepartment: prior,
		Employee: hris.Employee{ID: id, Email: email, Name: name, Department: dept, Title: title, Status: st},
	})
}

func (r *Runner) addAgent(name string, scope []string, min int) {
	_, _ = r.applyAgent(context.Background(), subject.AgentEvent{
		Type: hris.Joiner, Source: "deploy", Timestamp: dayT(10, min),
		Subject: subject.Subject{Kind: subject.KindAgent, ID: "A-" + name, Name: name,
			Status: hris.Active, Scope: scope, SpiffeID: subject.SpiffeIDFor(trustDomain, name)},
	})
}

// survivor injects a provisioned user with NO lifecycle event — models an
// out-of-band grant or an offboarding that never removed the account. `entitled`
// is what policy would actually grant (nil for a terminated identity).
func (r *Runner) survivor(email string, roles, entitled []string, active bool) {
	_ = r.tp.UpsertUser(context.Background(), teleport.User{Name: email, Roles: roles})
	r.entitled[email] = entitled
	r.active[email] = active
}

func (r *Runner) session(id, email, kind, ip string, min int) {
	r.tp.SeedSession(teleport.Session{ID: id, User: email, Kind: kind,
		Login: userLocal(email), SourceIP: ip, Started: dayT(11, min)})
}

func (r *Runner) setActive(email string, active bool) { r.active[email] = active }

func (r *Runner) dev(serial, email string, managed, compliant bool) {
	c := jamf.Compliance{FileVault: true, Firewall: true, Gatekeeper: true, SIP: true,
		ScreenLock: true, AutoUpdates: true, GuestDisabled: true, Overall: true}
	if !compliant {
		c = jamf.Compliance{FileVault: false, Firewall: false, Gatekeeper: true, SIP: true,
			ScreenLock: true, AutoUpdates: true, GuestDisabled: true, Overall: false}
	}
	r.devices = append(r.devices, jamf.Device{SerialNumber: serial, UserEmail: email,
		Managed: managed, Supervised: managed, Compliance: c, LastInventoryUpdate: r.GeneratedAt.Add(-time.Hour)})
}

func (r *Runner) baselineIP(email, ip string) {
	if r.known[email] == nil {
		r.known[email] = map[string]struct{}{}
	}
	r.known[email][ip] = struct{}{}
}

// --- scenarios ---

func seedBaseline(r *Runner) {
	ctx := context.Background()
	for _, ev := range demoHumans() {
		_, _ = r.applyHuman(ctx, ev)
	}
	for _, ev := range demoAgents() {
		_, _ = r.applyAgent(ctx, ev)
	}
	_, _ = r.jitEval(ctx, engine.AccessRequest{User: "bob@goteleport.com", Requested: "db-readonly"})
	_, _ = r.jitEval(ctx, engine.AccessRequest{User: "alice@goteleport.com", Requested: "it-admin"})
	r.injectAnomalies(ctx)
	r.seedDeviceSessions(ctx)
	r.devices = demoDevices(r.GeneratedAt)
	r.known = audit.KnownIP{"dave@goteleport.com": {"198.51.100.10": {}}}
}

// clean: everyone provisioned correctly, compliant managed devices, live but
// healthy sessions => zero findings.
func seedClean(r *Runner) {
	r.addHuman("okta", hris.Joiner, "N-1", "dana@nimbus.io", "Dana Cole", "Engineering", "Engineer", "", 0)
	r.addHuman("okta", hris.Joiner, "N-2", "evan@nimbus.io", "Evan Ruiz", "SRE", "Engineer", "", 1)
	r.addHuman("okta", hris.Joiner, "N-3", "fiona@nimbus.io", "Fiona Park", "Security", "Analyst", "", 2)
	r.addHuman("rippling", hris.Joiner, "N-4", "gwen@nimbus.io", "Gwen Adler", "Finance", "Manager", "", 3)
	r.addAgent("helix", []string{"mcp-gateway"}, 30)

	r.session("s-dana", "dana@nimbus.io", "ssh", "10.0.0.11", 40)
	r.session("s-evan", "evan@nimbus.io", "k8s", "10.0.0.12", 41)
	r.dev("NB-01", "dana@nimbus.io", true, true)
	r.dev("NB-02", "evan@nimbus.io", true, true)
	r.dev("NB-03", "fiona@nimbus.io", true, true)
	r.dev("NB-04", "gwen@nimbus.io", true, true)

	_, _ = r.jitEval(context.Background(), engine.AccessRequest{User: "evan@nimbus.io", Requested: "db-readonly"})
}

// offboarding-crisis: multiple terminated identities whose access lingered.
func seedOffboardingCrisis(r *Runner) {
	r.addHuman("rippling", hris.Joiner, "V-1", "omar@vertex.bank", "Omar Diaz", "SRE", "Engineer", "", 0)
	r.addHuman("rippling", hris.Joiner, "V-2", "pia@vertex.bank", "Pia Novak", "Finance", "Manager", "", 1)
	r.addHuman("okta", hris.Joiner, "V-3", "raj@vertex.bank", "Raj Patel", "IT", "Engineer", "", 2)

	// (a) terminated, but the account AND a live prod session survived.
	r.survivor("quinn@vertex.bank", []string{"db-readonly", "k8s-prod"}, nil, false)
	r.session("s-quinn", "quinn@vertex.bank", "k8s", "203.0.113.9", 40)
	r.dev("VX-Q", "quinn@vertex.bank", true, true)
	// (b) terminated, account survived (no session).
	r.survivor("sam@vertex.bank", []string{"finance-app"}, nil, false)
	// (c) terminated, account removed but a session lingered.
	r.session("s-tara", "tara@vertex.bank", "db", "198.51.100.60", 45)
	r.setActive("tara@vertex.bank", false)
	r.dev("VX-T", "tara@vertex.bank", true, true)

	_, _ = r.jitEval(context.Background(), engine.AccessRequest{User: "raj@vertex.bank", Requested: "it-admin"})
}

// rogue-agent: several agents; one workload identity abused with escalated roles
// from a new geo. No devices seeded (agents aren't Jamf endpoints), so device
// detection stays off and the findings stay focused on the agent.
func seedRogueAgent(r *Runner) {
	r.addHuman("okta", hris.Joiner, "H-1", "mira@helios.ai", "Mira Sol", "SRE", "Engineer", "", 0)
	r.addHuman("okta", hris.Joiner, "H-2", "leo@helios.ai", "Leo Fox", "Engineering", "Engineer", "", 1)

	r.addAgent("summarizer", []string{"kyra-memory"}, 20)
	r.addAgent("scheduler", []string{"kyra-calendar"}, 25)
	r.addAgent("router", []string{"mcp-gateway"}, 30)

	// The 'router' workload is being abused: it legitimately holds k8s-staging
	// (mcp-gateway scope) but is now also carrying it-admin + k8s-prod, and it's
	// connecting from an IP it has never used. Keyed on its SPIFFE id so it merges
	// with the deployed 'router' agent identity in the console.
	rogue := subject.SpiffeIDFor(trustDomain, "router")
	r.survivor(rogue, []string{"k8s-staging", "it-admin", "k8s-prod"}, []string{"k8s-staging"}, true)
	r.baselineIP(rogue, "10.0.5.5")
	r.session("s-router", rogue, "k8s", "185.220.101.44", 40) // never-seen exit node
}

// byod-sprawl: a remote team hitting sensitive resources from unmanaged /
// non-compliant devices.
func seedBYODSprawl(r *Runner) {
	r.addHuman("rippling", hris.Joiner, "W-1", "amy@northwind.io", "Amy Lee", "Engineering", "Engineer", "", 0)
	r.addHuman("rippling", hris.Joiner, "W-2", "ben@northwind.io", "Ben Cruz", "SRE", "Engineer", "", 1)
	r.addHuman("okta", hris.Joiner, "W-3", "cara@northwind.io", "Cara Vex", "Finance", "Manager", "", 2)

	r.session("s-amy", "amy@northwind.io", "ssh", "24.14.7.9", 40)
	r.session("s-ben", "ben@northwind.io", "k8s", "70.9.4.2", 41)
	r.session("s-cara", "cara@northwind.io", "db", "88.6.1.3", 42)

	r.dev("BYOD-AMY", "amy@northwind.io", false, false) // unmanaged personal laptop
	r.dev("NW-BEN", "ben@northwind.io", true, false)    // managed but failing baseline
	r.dev("NW-CARA", "cara@northwind.io", true, true)   // the compliant control
}
