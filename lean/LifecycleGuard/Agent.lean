/-
  Lifecycle Guard — extending the offboarding invariant to non-human identities.

  `Basic.lean` proved that a terminated *human* employee reconciles to zero
  effective access. But a modern Teleport fleet has non-human principals too:
  CI bots and AI agents that authenticate with a short-lived SPIFFE SVID issued
  against a `workload_identity` resource and a `bot` resource. These deserve the
  *same* lifecycle guarantee — when an agent is decommissioned, its kill-switch
  must be as total as a human's offboarding.

  In Teleport terms, decommissioning an agent means:
    * revoking its workload identity / SPIFFE SVID (no new SVIDs are minted, so
      the agent can no longer prove its identity to any SPIFFE-aware service), and
    * applying a lock to the underlying `bot` principal (kind "bot" v1), which
      severs any in-flight session cluster-wide rather than waiting for the SVID
      TTL to lapse.

  We model both — for a human and for an agent — as the SAME `deprovision`
  operation already proved correct in `Basic.lean`: strip every role and set the
  lock. That reuse is the whole point: the engine has one offboarding code path,
  so the formal guarantee transfers verbatim to AI agents.

  Mathlib-free: builds with a bare Lean 4 toolchain (`lake build`), same as
  `Basic.lean`.
-/

import LifecycleGuard.Basic

namespace LifecycleGuard

/-- The two kinds of principal the controller manages. A `human` is the
    `Employee` case from `Basic.lean`; an `agent` is a workload identity (an AI
    agent or CI bot) backed by a Teleport `workload_identity` (v1) + `bot` (v1).

    The lifecycle invariant must not depend on which one we're looking at — that
    Kind-independence is exactly what `offboarding_total_regardless_of_kind`
    below makes machine-checked. -/
inductive Kind where
  | human
  | agent
deriving DecidableEq, Repr

/-- A unified principal record. We reuse `Status` (active/terminated) from
    `Basic.lean` so a "terminated" agent means a *decommissioned* one: its SVID
    issuance is revoked and its bot is locked.

    `scope` carries the roles an *active* agent is entitled to (the SPIFFE
    workload's authorized role set, e.g. the demo agent `kyra` scoped to a narrow
    read-only role). For a human this field is unused — human entitlement still
    flows through `rolesFor`/`Policy` in `Basic.lean`; here we only need to prove
    the *offboarding* half, which is Kind-agnostic. -/
structure Subject where
  kind   : Kind
  status : Status
  /-- Authorized Teleport roles for an active agent (the workload's scope).
      Empty / irrelevant for a terminated subject of either kind. -/
  scope  : List String
deriving Repr

/-- Reconcile one subject to its target Teleport state.

    * A *terminated* subject — human OR agent — is run through the exact same
      `deprovision` from `Basic.lean`: zero roles + locked. For an agent this is
      the model of "revoke the workload identity / SPIFFE SVID and lock the bot",
      i.e. the kill-switch. There is deliberately no agent-specific escape hatch.
    * An *active* agent is granted precisely its `scope` and left unlocked, the
      Lean mirror of issuing SVIDs for that `workload_identity`'s role set.

    Note the terminated branch ignores `kind` entirely: that is what makes agent
    offboarding provably identical to human offboarding. -/
def reconcileSubject (s : Subject) (prior : UserState) : UserState :=
  match s.status with
  | Status.terminated => deprovision prior
  | Status.active     => { roles := s.scope, locked := false }

/-! ### Proofs -/

/-- **Theorem (headline safety property, generalized).**
    After the engine reconciles a *terminated* subject, that principal has no
    effective access — for ANY subject `s` (human or agent) and ANY prior state.

    This is the `terminated_employee_loses_all_access` invariant from
    `Basic.lean`, lifted to the unified `Subject`: a decommissioned AI agent
    provably loses all access, because its workload identity is revoked and its
    bot is locked by the very same `deprovision`. -/
theorem terminated_subject_loses_all_access
    (s : Subject) (prior : UserState)
    (h : s.status = Status.terminated) :
    hasAccess (reconcileSubject s prior) = false := by
  simp [reconcileSubject, h, deprovision, hasAccess]

/-- **Corollary (Kind-independence).**
    The offboarding guarantee holds regardless of whether the subject is a human
    or an AI agent: fixing the status to `terminated`, both Kinds reconcile to a
    state with no effective access. Agent offboarding is exactly as total as
    human offboarding — same code path, same proof. -/
theorem offboarding_total_regardless_of_kind
    (k : Kind) (sc : List String) (prior : UserState) :
    hasAccess (reconcileSubject ⟨k, Status.terminated, sc⟩ prior) = false := by
  simp [reconcileSubject, deprovision, hasAccess]

/-- **Corollary.** The decommissioned-agent outcome is independent of any access
    (any SVID-derived roles, any in-flight session) the agent previously held —
    no prior state survives the kill-switch. Mirrors `offboarding_is_total`. -/
theorem agent_offboarding_is_total
    (s : Subject) (h : s.status = Status.terminated) (s₁ s₂ : UserState) :
    reconcileSubject s s₁ = reconcileSubject s s₂ := by
  simp [reconcileSubject, h, deprovision]

end LifecycleGuard
