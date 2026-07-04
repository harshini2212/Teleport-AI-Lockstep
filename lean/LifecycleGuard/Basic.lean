/-
  Lifecycle Guard — formal model of the Teleport access-lifecycle policy.

  We model the offboarding invariant the Go engine implements and *prove* it can
  never be violated: no matter the policy, the employee's department/title, or
  any prior access they held, a terminated identity ends with zero effective
  access. This is the kind of property you want machine-checked rather than
  unit-tested, because a unit test only covers the cases you remembered.

  Mathlib-free: builds with a bare Lean 4 toolchain (`lake build`).
-/

namespace LifecycleGuard

/-- Employment state, the single fact that drives entitlement. -/
inductive Status where
  | active
  | terminated
deriving DecidableEq, Repr

/-- An identity record as delivered by the HRIS (Rippling) / IdP (Okta). -/
structure Employee where
  department : String
  title      : String
  status     : Status

/-- The access policy: department and title each map to a list of Teleport roles.
    Left abstract so the theorems hold for *every* possible policy. -/
structure Policy where
  departmentRoles : String → List String
  titleRoles      : String → List String

/-- Entitlement function — the Lean mirror of `policy.RolesFor` in Go.
    A terminated employee is entitled to the empty role set. -/
def rolesFor (p : Policy) (e : Employee) : List String :=
  match e.status with
  | Status.terminated => []
  | Status.active     => p.departmentRoles e.department ++ p.titleRoles e.title

/-- A user's live state in the Teleport cluster. -/
structure UserState where
  roles  : List String
  locked : Bool

/-- A user has effective access iff they are unlocked and hold ≥ 1 role.
    (A lock severs access cluster-wide even if a short-lived cert is unexpired.) -/
def hasAccess (u : UserState) : Bool :=
  (!u.locked) && (!u.roles.isEmpty)

/-- The engine's offboarding operation: strip all roles *and* lock the identity. -/
def deprovision (u : UserState) : UserState :=
  { roles := [], locked := true }

/-- The engine's full reconcile step for one event. -/
def reconcile (p : Policy) (e : Employee) (prior : UserState) : UserState :=
  match e.status with
  | Status.terminated => deprovision prior
  | Status.active     => { roles := rolesFor p e, locked := false }

/-! ### Proofs -/

/-- **Lemma.** A terminated employee is entitled to no roles, for any policy. -/
theorem terminated_has_no_roles (p : Policy) (e : Employee)
    (h : e.status = Status.terminated) : rolesFor p e = [] := by
  simp [rolesFor, h]

/-- **Lemma.** Deprovisioning always removes effective access, whatever the prior
    state was (even a user mid-session holding admin roles). -/
theorem deprovision_revokes_access (u : UserState) :
    hasAccess (deprovision u) = false := by
  simp [hasAccess, deprovision]

/-- **Theorem (headline safety property).**
    After the engine reconciles a *terminated* employee, that identity has no
    effective access — for ANY policy `p` and ANY prior state `prior`.

    This is the invariant "a terminated user can never retain a valid Teleport
    role/session", machine-checked. -/
theorem terminated_employee_loses_all_access
    (p : Policy) (e : Employee) (prior : UserState)
    (h : e.status = Status.terminated) :
    hasAccess (reconcile p e prior) = false := by
  simp [reconcile, h, deprovision, hasAccess]

/-- **Corollary.** The offboarding outcome is independent of any access the user
    previously held — there is no prior state that survives termination. -/
theorem offboarding_is_total (p : Policy) (e : Employee)
    (h : e.status = Status.terminated) (s₁ s₂ : UserState) :
    reconcile p e s₁ = reconcile p e s₂ := by
  simp [reconcile, h, deprovision]

end LifecycleGuard
