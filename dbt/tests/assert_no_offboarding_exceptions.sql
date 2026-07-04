-- Singular test: the offboarding invariant must hold.
--
-- A dbt singular test passes when it returns ZERO rows. This selects every
-- offboarding exception, so the test is green only when mart_offboarding_exceptions
-- is empty — i.e. no terminated identity produced a post-termination access event.
--
-- This is the dbt encoding of the Lean theorem `terminated_employee_loses_all_access`
-- (lean/LifecycleGuard/Basic.lean) and the Go `offboarded-active-session` detector
-- (go/internal/audit/audit.go). When it fails, `dbt test` exits non-zero exactly
-- like `lake build` does on a broken proof — the invariant is part of the build.
--
-- No package dependency: just a select against the headline mart.

select
    teleport_user,
    terminated_at,
    event_uid,
    event_type,
    access_event_at,
    minutes_after_termination
from {{ ref('mart_offboarding_exceptions') }}
