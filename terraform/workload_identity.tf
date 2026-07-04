// Agentic identity — the AI agent "kyra" as a cryptographic identity-as-code.
//
// This is the machine/agent analog of the human JML lifecycle in roles.tf: an AI
// agent is just another identity that gets *issued* a short-lived credential and
// scoped to least privilege. Here that credential is a SPIFFE SVID (X.509),
// minted by Teleport Workload Identity, bound to a Machine ID bot, and limited to
// one narrow role. The cluster is the source of truth; nothing about "kyra" lives
// as a static secret.
//
// This mirrors Teleport's Agentic Identity Framework thesis (cited in the README):
// agents authenticate with verifiable, attested, expiring identities — not API
// keys — so the same "derive access from identity, issue it ephemerally,
// continuously verify it" model that governs alice/bob/carol/dave also governs
// the agent.
//
// Docs:
//   - Workload Identity:    https://goteleport.com/docs/machine-workload-identity/workload-identity/
//   - tbot / Machine ID:    https://goteleport.com/docs/machine-workload-identity/machine-id/
//   - Terraform provider:   https://goteleport.com/docs/admin-guides/infrastructure-as-code/terraform-provider/
//
// REQUIRES Teleport Enterprise: Workload Identity SVID issuance is an Enterprise
// feature. The resources below are accurate as policy-as-code but will not apply
// against an OSS cluster.

// Trust domain for issued SVIDs == the Teleport cluster name. We template only
// the *path*, so a single workload_identity definition issues a distinct,
// per-bot SVID id (spiffe://<cluster>/agents/kyra/<bot-user>) rather than one
// shared identity. var.cluster_name feeds the hint/labels below for readability.
variable "cluster_name" {
  type        = string
  description = "Teleport cluster name; also the SPIFFE trust domain for issued SVIDs."
  default     = "teleport.goteleport.com"
}

// The agent's cryptographic identity template. version is the snake_case "v1"
// kind workload_identity (NOT a camelCase kind). spec.spiffe.id is a *path*
// template — the trust domain (cluster) is fixed and prepended by the cluster at
// issuance; {{ user.name }} is intended to expand to the authenticated bot user so
// each issued SVID is uniquely attributable in the audit log.
//
// NOTE: the templating attributes available in spec.spiffe.id are VERSION-DEPENDENT
// (documented attributes are namespaced, e.g. workload.* / join.*). Verify
// {{ user.name }} against the Workload Identity attributes reference for your
// cluster version; if it doesn't resolve, use a documented attribute or a static
// path segment instead.
resource "teleport_workload_identity" "kyra_agent" {
  version = "v1"
  metadata = {
    name        = "kyra-agent"
    description = "SPIFFE identity template for the AI agent 'kyra'."
    // Labels are the selector the issuer role (below) authorizes against, the
    // same allow-label pattern used for nodes/k8s/db in roles.tf.
    labels = {
      agent = "kyra"
    }
  }
  spec = {
    spiffe = {
      // Path only. Effective SVID id: spiffe://<cluster_name>/agents/kyra/<bot>.
      id = "/agents/kyra/{{ user.name }}"
      // Human-readable hint stamped into the SVID for operators triaging the
      // audit stream — "what is this cert and who owns it".
      hint = "AI agent 'kyra' — scoped to its own memory store; owned by IT Security."
    }
  }
}

// Issuer role — authorizes a caller to discover/issue the kyra workload identity.
// workload_identity_labels is the agentic analog of node_labels/db_labels in
// roles.tf: it gates *which* identity templates this role may use, by label.
// rules grants read/list on the workload_identity resource so tbot can resolve
// the template at issuance. TTL is deliberately tiny — an issuer credential
// should live minutes, not hours.
resource "teleport_role" "agent_identity_issuer" {
  version = "v7"
  metadata = {
    name        = "agent-identity-issuer"
    description = "Permits issuing the 'kyra' Workload Identity SVID; nothing else."
  }
  spec = {
    options = {
      // Short by design: this role only mints SVIDs, it shouldn't grant a
      // long-lived foothold.
      max_session_ttl = "1h"
    }
    allow = {
      // Selects the kyra_agent template via its `agent = kyra` label.
      workload_identity_labels = {
        agent = ["kyra"]
      }
      rules = [{
        resources = ["workload_identity"]
        verbs     = ["list", "read"]
      }]
    }
  }
}

// The agent's SCOPED least-privilege role — what "kyra" can actually *do* once it
// holds an SVID. Modeled on db-readonly in roles.tf, but narrowed to a single
// database (the agent's own memory store) instead of db_labels {"*"=["*"]}. An
// agent should reach exactly its working set and nothing adjacent.
resource "teleport_role" "agent_scope_kyra" {
  version = "v7"
  metadata = {
    name        = "agent-scope-kyra"
    description = "Least-privilege scope for the 'kyra' agent: its memory store only."
  }
  spec = {
    options = {
      // Agent sessions are short and renewable via tbot; cap tighter than humans.
      max_session_ttl = "1h"
    }
    allow = {
      // Only the database labeled as kyra's memory store, read-only, one db user.
      db_labels = { "app" = ["kyra-memory"] }
      db_users  = ["kyra-readonly"]
      db_names  = ["agent_memory"]
    }
  }
}

// The Machine ID bot identity that runs as kyra. roles binds it to the scoped
// role above; tbot uses this bot to obtain renewable certs and to request the
// kyra_agent SVID. Bot kind is "bot" v1.
resource "teleport_bot" "kyra" {
  // Resource name; the bot user materializes in the cluster as "bot-kyra".
  name  = "kyra"
  roles = ["agent-scope-kyra"]
  // Traits left empty here; in a fuller deployment the issuer role would be
  // delegated to the issuing tbot, not granted to the agent bot itself.
}

// ---------------------------------------------------------------------------
// HONESTY / OPERATIONAL CAVEATS — read before trusting this as a revocation path
// ---------------------------------------------------------------------------
//
// 1. Attestation attribute namespace is VERSION-DEPENDENT. Teleport can bind SVID
//    issuance to workload attestation (Kubernetes / Unix process / Docker meta),
//    but the exact attribute keys and the rules DSL that references them
//    (e.g. workload.kubernetes.* / workload.unix.*) have shifted across releases.
//    This file intentionally does NOT hard-code attestation selectors, because an
//    inaccurate selector silently fails closed (no SVID) or open (wrong workload).
//    Pin them against the docs for YOUR cluster version before enabling
//    attestation-gated issuance.
//
// 2. Deleting this resource does NOT instantly kill an already-issued SVID. The
//    SVID is a short-lived X.509 cert; once minted it is valid until it expires,
//    regardless of whether the workload_identity/bot still exists in Terraform.
//    `terraform destroy` stops *future* issuance only.
//
//    This is exactly the human-offboarding lesson from the README ("Lock, don't
//    just delete") applied to agents. To SEVER an in-flight agent credential you
//    must lock the bot user, the same primitive the Leaver path uses for humans:
//
//        tctl lock --user=bot-kyra --message="kyra deprovisioned" --ttl=720h
//
//    Locking is the agent analog of the human Leaver lock: it cuts live sessions
//    immediately instead of waiting out the cert TTL. Deprovisioning an agent =
//    destroy (stop new issuance) + lock (cut existing creds), never destroy alone.
