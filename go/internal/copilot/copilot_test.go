package copilot

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/audit"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/policy"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/teleport"
)

func sampleEvidence() Evidence {
	return BuildEvidence("2026-Q2", policy.Default(),
		[]audit.Finding{
			{Detector: "offboarded-active-session", Severity: audit.Critical, User: "dave@goteleport.com",
				Summary: "terminated identity dave still has a live session", Remediation: "lock now"},
			{Detector: "privilege-escalation", Severity: audit.High, User: "alice@goteleport.com",
				Summary: "alice holds it-admin not granted by policy", Remediation: "revert roles"},
		},
		[]teleport.User{{Name: "alice@goteleport.com", Roles: []string{"db-readonly", "it-admin"}}},
		[]teleport.Lock{{Target: "carol@goteleport.com", Reason: "offboarding"}},
		[]teleport.Session{{ID: "s1", User: "dave@goteleport.com", Kind: "k8s", SourceIP: "203.0.113.51"}},
		nil,
	)
}

// The evidence serialization must be byte-identical across calls so the LLM
// input (and any prompt cache) is stable.
func TestBuildEvidenceDeterministic(t *testing.T) {
	a, err := sampleEvidence().marshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	b, err := sampleEvidence().marshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("evidence serialization is not deterministic")
	}
}

func TestEvidenceCarriesAnomalies(t *testing.T) {
	raw, _ := sampleEvidence().marshalDeterministic()
	s := string(raw)
	for _, want := range []string{"dave@goteleport.com", "alice@goteleport.com", "offboarded-active-session", "privilege-escalation"} {
		if !strings.Contains(s, want) {
			t.Errorf("evidence missing %q", want)
		}
	}
}

// With no API key the copilot degrades cleanly — the pipeline never blocks or
// fabricates a review.
func TestNewClientNoAPIKey(t *testing.T) {
	old := os.Getenv("ANTHROPIC_API_KEY")
	os.Unsetenv("ANTHROPIC_API_KEY")
	defer func() {
		if old != "" {
			os.Setenv("ANTHROPIC_API_KEY", old)
		}
	}()
	if _, err := NewClient(); err != ErrNoAPIKey {
		t.Fatalf("expected ErrNoAPIKey, got %v", err)
	}
}
