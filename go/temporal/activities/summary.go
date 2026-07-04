package activities

import (
	"context"

	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/audit"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/engine"
	"github.com/harshini2212/teleport-lifecycle-guard/go/internal/hris"
)

// Harshini's AI/NLP touch, correctly placed: an LLM call is a non-deterministic
// side effect, so narrating an access change lives in an ACTIVITY, never in the
// deterministic workflow. The approver who receives a JIT signal (or reads the
// audit trail) sees a plain-English summary of what they are approving.

// SummaryInput is the structured change fed to the summarizer.
type SummaryInput struct {
	Event    hris.Event      `json:"event"`
	Actions  []engine.Action `json:"actions"`
	Findings []audit.Finding `json:"findings"`
}

// Summarizer turns a structured change into human-readable prose. Kept as an
// interface so it no-ops without an API key.
type Summarizer interface {
	Summarize(ctx context.Context, in SummaryInput) (string, error)
}

// NoopSummarizer is the default: it returns empty text, so the pipeline runs
// with zero external dependencies. Swap in an Anthropic-backed implementation
// (mirroring internal/copilot) to enable narration.
type NoopSummarizer struct{}

// Summarize implements Summarizer.
func (NoopSummarizer) Summarize(_ context.Context, _ SummaryInput) (string, error) { return "", nil }

// NarrateChange is the activity the workflow invokes to attach a summary.
func (a *Activities) NarrateChange(ctx context.Context, in SummaryInput) (string, error) {
	if a.Sum == nil {
		return "", nil
	}
	return a.Sum.Summarize(ctx, in)
}
