// Package copilot is a read-only Access-Review Copilot: it turns the engine's
// deterministic output (audit findings, converged Teleport state, policy, JIT
// decisions) into a plain-English quarterly access review. It imports engine/
// audit/teleport/policy TYPES only — it never calls engine.Reconcile,
// teleport.CreateLock, or any mutating path. The LLM narrates; humans + policy
// decide. This is Harshini's NLP strength applied where it is safe and additive,
// and it mirrors Teleport's 2026 Access-Graph AI summaries.
package copilot

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/audit"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/engine"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/policy"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/teleport"
)

// Evidence is the deterministic input handed to the LLM. Everything here was
// computed by the engine; the copilot only summarizes it.
type Evidence struct {
	Period          string              `json:"period"`
	DepartmentRoles map[string][]string `json:"department_roles"`
	MaxSessionTTL   string              `json:"max_session_ttl"`
	Findings        []audit.Finding     `json:"findings"`
	Users           []teleport.User     `json:"users"`
	Locks           []teleport.Lock     `json:"locks"`
	Sessions        []teleport.Session  `json:"sessions"`
	JIT             []engine.Decision   `json:"jit_decisions"`
}

// Review is the structured output the copilot returns (matches reviewToolSchema).
type Review struct {
	Period          string           `json:"period"`
	Summary         string           `json:"summary"`
	Identities      []IdentityReview `json:"identities"`
	Recommendations []Recommendation `json:"recommendations"`
	SOC2Summary     string           `json:"soc2_summary"`
}

// IdentityReview is a per-identity risk narrative.
type IdentityReview struct {
	Identity  string `json:"identity"`
	RiskLevel string `json:"risk_level"` // low | medium | high | critical
	Narrative string `json:"narrative"`
}

// Recommendation is a proposed action. HumanApprovalRequired is always true —
// the copilot proposes, a human disposes.
type Recommendation struct {
	Identity              string `json:"identity"`
	Action                string `json:"action"` // revoke | review | lock | keep
	Rationale             string `json:"rationale"`
	HumanApprovalRequired bool   `json:"human_approval_required"`
}

// BuildEvidence assembles the deterministic evidence bundle. It defensively
// sorts every slice (on copies, so the caller's slices are untouched) so that
// two logically-equivalent evidence sets always serialize to identical bytes —
// the copilot does not rely on the caller having pre-sorted anything.
func BuildEvidence(
	period string,
	pol policy.Policy,
	findings []audit.Finding,
	users []teleport.User,
	locks []teleport.Lock,
	sessions []teleport.Session,
	jit []engine.Decision,
) Evidence {
	f := append([]audit.Finding(nil), findings...)
	sort.Slice(f, func(i, j int) bool {
		if f[i].Detector != f[j].Detector {
			return f[i].Detector < f[j].Detector
		}
		return f[i].User < f[j].User
	})
	u := append([]teleport.User(nil), users...)
	sort.Slice(u, func(i, j int) bool { return u[i].Name < u[j].Name })
	l := append([]teleport.Lock(nil), locks...)
	sort.Slice(l, func(i, j int) bool { return l[i].Target < l[j].Target })
	s := append([]teleport.Session(nil), sessions...)
	sort.Slice(s, func(i, j int) bool { return s[i].ID < s[j].ID })
	d := append([]engine.Decision(nil), jit...)
	sort.Slice(d, func(i, j int) bool {
		if d[i].User != d[j].User {
			return d[i].User < d[j].User
		}
		return d[i].Requested < d[j].Requested
	})

	return Evidence{
		Period:          period,
		DepartmentRoles: pol.DepartmentRoles,
		MaxSessionTTL:   pol.MaxSessionTTL.String(),
		Findings:        f,
		Users:           u,
		Locks:           l,
		Sessions:        s,
		JIT:             d,
	}
}

// marshalDeterministic renders the evidence as stable JSON. json.Marshal sorts
// map keys, and BuildEvidence sorted every slice, so the same logical state
// always yields the same bytes (good for prompt-caching and reproducibility).
func (e Evidence) marshalDeterministic() ([]byte, error) {
	return json.MarshalIndent(e, "", "  ")
}

// Generate produces the access review by calling the LLM with the evidence.
// It enforces the safety invariant (every recommendation requires human
// approval) regardless of what the model returns.
func Generate(ctx context.Context, c *Client, ev Evidence) (Review, error) {
	payload, err := ev.marshalDeterministic()
	if err != nil {
		return Review{}, err
	}
	user := "Deterministic access-review evidence (JSON) follows. Produce the quarterly review.\n\n" + string(payload)

	raw, err := c.complete(ctx, SystemPrompt, user, toolName, reviewToolSchema)
	if err != nil {
		return Review{}, err
	}
	var r Review
	if err := json.Unmarshal(raw, &r); err != nil {
		return Review{}, fmt.Errorf("decode review: %w", err)
	}
	for i := range r.Recommendations {
		r.Recommendations[i].HumanApprovalRequired = true // non-negotiable
	}
	if r.Period == "" {
		r.Period = ev.Period
	}
	return r, nil
}

// Ask answers a free-text question grounded in the current access state — the
// natural-language bar. Read-only: it explains, it never mutates access.
func Ask(ctx context.Context, c *Client, ev Evidence, question string) (string, error) {
	payload, err := ev.marshalDeterministic()
	if err != nil {
		return "", err
	}
	user := "Current Teleport access-governance state (JSON):\n" + string(payload) +
		"\n\nQuestion: " + question +
		"\n\nAnswer concisely (2-5 sentences), grounded ONLY in the state above. Cite the specific identities/findings involved."
	return c.Chat(ctx, AskSystemPrompt, user)
}
