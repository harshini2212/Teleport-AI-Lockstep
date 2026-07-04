# Formal verification — offboarding safety

This module proves, in **Lean 4**, the invariant the Go engine relies on:

> A terminated employee always reconciles to **zero effective access**, for any
> policy and any prior access state.

`Basic.lean` models the policy (`rolesFor`), the cluster user state
(`hasAccess`), and the engine's reconcile step (`reconcile`/`deprovision`), then
proves three theorems — the headline being:

```lean
theorem terminated_employee_loses_all_access
    (p : Policy) (e : Employee) (prior : UserState)
    (h : e.status = Status.terminated) :
    hasAccess (reconcile p e prior) = false
```

Because `p` and `prior` are universally quantified, this is a guarantee over the
*entire* space of policies and prior grants — not a sample of test cases.

## Build

```bash
# install the Lean toolchain manager once:  https://leanprover-community.github.io/get_started.html
lake build
```

`lake build` type-checks the file; if any proof were wrong, the build fails. The
toolchain version is pinned in `lean-toolchain`. No Mathlib dependency — it
builds with a bare Lean 4 install.
