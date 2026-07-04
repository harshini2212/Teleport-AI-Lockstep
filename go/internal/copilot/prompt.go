package copilot

import "encoding/json"

// SystemPrompt keeps the copilot strictly advisory: it explains deterministic
// engine output, it never decides or mutates access. This is the safe, auditable
// way to put an LLM near an access path — the mirror of Teleport Access Graph's
// AI-powered access summaries.
const SystemPrompt = `You are the Access-Review Copilot for "Lifecycle Guard", an identity-governance
controller for Teleport. You are given DETERMINISTIC evidence produced by the engine: audit anomaly
findings, the converged Teleport state (users and their roles, locks, live sessions), the access policy,
and just-in-time access decisions.

Your job is to write a plain-English QUARTERLY ACCESS REVIEW for the IT/Security team:
- a short executive summary,
- a per-identity risk narrative (only for identities that warrant attention),
- concrete recommendations (revoke / review / lock / keep), each requiring human approval,
- a SOC 2 / least-privilege (NIST AC-2, AC-6) style summary.

Rules:
- Ground every statement in the evidence provided. Do NOT invent identities, roles, or events.
- You advise; you never act. Every recommendation is a proposal a human must approve — set
  human_approval_required to true on all of them.
- Prefer precision over breadth. If an identity is clean, do not manufacture concern.
- Call out the highest-severity findings first (offboarded-but-active, privilege escalation,
  unmanaged/non-compliant devices).
Return your review by calling the record_access_review tool exactly once.`

// ToolDescription is the one-line description attached to the forced tool.
const ToolDescription = "Record the structured quarterly access review. Call exactly once."

// AskSystemPrompt powers the natural-language "ask" bar.
const AskSystemPrompt = `You are a Teleport identity-governance analyst embedded in the Lifecycle Guard console.
Answer the user's question about the current access state precisely and concisely, grounded ONLY in the JSON
state provided. Reference the specific identities, roles, findings, devices, or sessions involved. If the state
does not contain the answer, say so plainly rather than guessing. Never invent identities or events. You explain
and advise; you never take actions.`

// reviewToolSchema is the strict JSON schema for the forced tool. It mirrors the
// Review Go type field-for-field (strict: true + additionalProperties: false).
var reviewToolSchema = json.RawMessage(`{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "period": { "type": "string", "description": "The review period, e.g. 2026-Q2." },
    "summary": { "type": "string", "description": "2-4 sentence executive summary." },
    "identities": {
      "type": "array",
      "description": "Per-identity risk narratives for identities that warrant attention.",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "identity": { "type": "string" },
          "risk_level": { "type": "string", "enum": ["low", "medium", "high", "critical"] },
          "narrative": { "type": "string" }
        },
        "required": ["identity", "risk_level", "narrative"]
      }
    },
    "recommendations": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "identity": { "type": "string" },
          "action": { "type": "string", "enum": ["revoke", "review", "lock", "keep"] },
          "rationale": { "type": "string" },
          "human_approval_required": { "type": "boolean" }
        },
        "required": ["identity", "action", "rationale", "human_approval_required"]
      }
    },
    "soc2_summary": { "type": "string", "description": "SOC2/least-privilege posture summary." }
  },
  "required": ["period", "summary", "identities", "recommendations", "soc2_summary"]
}`)
