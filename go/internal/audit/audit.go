// Package audit consumes the Teleport audit event stream (in production this is
// the Teleport Event Handler forwarding to Panther/SIEM) and runs detectors
// that flag access anomalies the lifecycle controller should react to. Each
// finding carries a recommended remediation so the pipeline can auto-contain.
package audit

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/policy"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/teleport"
)

// Severity ranks findings for triage.
type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
)

// Finding is a single detected anomaly.
type Finding struct {
	Detector   string   `json:"detector"`
	Severity   Severity `json:"severity"`
	User       string   `json:"user"`
	Summary    string   `json:"summary"`
	Remediation string  `json:"remediation"`
}

// KnownIP is a per-user set of previously-seen source IPs (the baseline an
// impossible-travel/new-geo detector compares against). In production this is a
// rolling feature store; here it is seeded for the demo.
type KnownIP map[string]map[string]struct{}

// Detect runs all detectors over the current cluster state and a roster of who
// should still be active per the HR source of truth.
//
// activeUsers: emails the HRIS still considers employed.
// managed/compliant: per-user device posture from the Jamf connector (keyed by
//   email). Pass nil for both to skip device-trust detection entirely (no
//   baseline) rather than flag every session as unmanaged.
// It flags:
//   - offboarded identities with live sessions or surviving role bindings
//   - privilege escalation: a user holding a role no policy grants them
//   - access from a never-before-seen source IP
//   - sessions from an unmanaged or non-compliant device (Teleport Device Trust)
func Detect(
	ctx context.Context,
	tp teleport.Client,
	pol policy.Policy,
	activeUsers map[string]bool,
	entitledRoles map[string][]string,
	knownIPs KnownIP,
	managed map[string]bool,
	compliant map[string]bool,
) ([]Finding, error) {
	var findings []Finding

	users := collectUsers(ctx, tp)
	sessions, err := tp.ListSessions(ctx)
	if err != nil {
		return nil, err
	}
	locks, err := tp.ListLocks(ctx)
	if err != nil {
		return nil, err
	}
	locked := map[string]bool{}
	for _, l := range locks {
		locked[l.Target] = true
	}

	// Detector 1: offboarded-but-active. A user the HRIS no longer lists as
	// active should have no surviving identity and no live, unlocked session.
	for _, s := range sessions {
		if !activeUsers[s.User] && !locked[s.User] {
			findings = append(findings, Finding{
				Detector: "offboarded-active-session",
				Severity: Critical,
				User:     s.User,
				Summary: fmt.Sprintf("terminated identity %s holds a live %s session (%s) from %s",
					s.User, s.Kind, s.ID, s.SourceIP),
				Remediation: "issue tctl lock immediately; investigate session recording",
			})
		}
	}
	for name := range users {
		if !activeUsers[name] && !locked[name] {
			findings = append(findings, Finding{
				Detector:    "offboarded-identity-survives",
				Severity:    Critical,
				User:        name,
				Summary:     fmt.Sprintf("terminated identity %s still has a provisioned Teleport user", name),
				Remediation: "deprovision and lock; re-run lifecycle reconcile",
			})
		}
	}

	// Detector 2: privilege escalation. Any held role outside the user's
	// policy entitlement was granted out-of-band.
	for name, u := range users {
		entitled := toSet(entitledRoles[name])
		for _, r := range u.Roles {
			if _, ok := entitled[r]; !ok {
				findings = append(findings, Finding{
					Detector: "privilege-escalation",
					Severity: High,
					User:     name,
					Summary: fmt.Sprintf("%s holds role %q not granted by policy", name, r),
					Remediation: "revert to policy-derived roles; audit who granted it",
				})
			}
		}
	}

	// Detector 3: new-geo access. A session from a source IP never seen for
	// this user is worth a step-up challenge.
	for _, s := range sessions {
		seen := knownIPs[s.User]
		if seen == nil {
			continue // no baseline yet; skip rather than false-positive
		}
		if _, ok := seen[s.SourceIP]; !ok {
			findings = append(findings, Finding{
				Detector: "new-geo-access",
				Severity: Medium,
				User:     s.User,
				Summary: fmt.Sprintf("%s active from unseen source IP %s", s.User, s.SourceIP),
				Remediation: "trigger device-trust step-up; confirm with user",
			})
		}
	}

	// Detector 4: device trust. A session must originate from a managed,
	// compliant device. Skipped entirely if no posture signal was supplied.
	if managed != nil || compliant != nil {
		for _, s := range sessions {
			if !managed[s.User] {
				findings = append(findings, Finding{
					Detector: "unmanaged-device",
					Severity: Critical,
					User:     s.User,
					Summary: fmt.Sprintf("%s active from a device not enrolled in Jamf/Teleport inventory (%s)",
						s.User, s.SourceIP),
					Remediation: "enforce device_trust_mode: required; deny access from unmanaged devices",
				})
				continue // unmanaged is the stronger finding; don't also flag non-compliant
			}
			if !compliant[s.User] {
				findings = append(findings, Finding{
					Detector: "noncompliant-device",
					Severity: High,
					User:     s.User,
					Summary: fmt.Sprintf("%s active from a managed but non-compliant Mac (failed hardening baseline)",
						s.User),
					Remediation: "block until compliant; run the Jamf 'Harden' policy (macos/harden.sh)",
				})
			}
		}
	}

	// Total order: severity, then detector, then user — so alerts are
	// reproducible (the committed dashboard trace matches a live run).
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return sevRank(findings[i].Severity) < sevRank(findings[j].Severity)
		}
		if findings[i].Detector != findings[j].Detector {
			return findings[i].Detector < findings[j].Detector
		}
		return findings[i].User < findings[j].User
	})
	return findings, nil
}

func collectUsers(ctx context.Context, tp teleport.Client) map[string]teleport.User {
	out := map[string]teleport.User{}
	// The mock exposes users only through GetUser; for the demo the engine
	// records who it provisioned, so we reconstruct via the session/lock views
	// plus a direct type assertion when available.
	if lister, ok := tp.(interface {
		AllUsers(context.Context) []teleport.User
	}); ok {
		for _, u := range lister.AllUsers(ctx) {
			out[u.Name] = u
		}
	}
	return out
}

func toSet(xs []string) map[string]struct{} {
	s := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		s[x] = struct{}{}
	}
	return s
}

func sevRank(s Severity) int {
	switch s {
	case Critical:
		return 0
	case High:
		return 1
	default:
		return 2
	}
}

var _ = time.Now // reserved for time-window detectors
