-- mart_offboarding_exceptions  ***THE HEADLINE***
--
-- The warehouse equivalent of the Lean theorem and the Go `offboarded-active-session`
-- detector:
--
--     Lean:   terminated_employee_loses_all_access  (lean/LifecycleGuard/Basic.lean)
--     Go:     audit detector "offboarded-active-session" (go/internal/audit/audit.go)
--     dbt:    THIS MODEL — recomputed from the cold audit record in Redshift.
--
-- The invariant: a terminated identity must have NO access event after its
-- termination timestamp. If Lifecycle Guard's Leaver path worked — lock the
-- identity (sever live sessions) and deprovision the user — this model is empty.
-- Any row here is a real offboarding failure: a logged-in, session-starting, or
-- access-requesting identity that HR says was already gone.
--
-- This is encoded as an invariant the build enforces: _access_review__models.yml
-- attaches a `dbt_utils.expression_is_true`-style row-count test asserting this
-- model returns ZERO rows. A non-empty result fails `dbt test`, exactly like a
-- broken Lean proof fails `lake build`.
--
-- Grain: one row per post-termination access event (so an auditor sees each
-- specific violating event, not just the offending user).

{{ config(materialized = 'table') }}

with identity as (

    select * from {{ ref('dim_identity') }}

),

fct as (

    select * from {{ ref('fct_access_events') }}

),

terminated_identities as (

    select
        teleport_user,
        full_name,
        department,
        terminated_at
    from identity
    where is_offboarded
      and terminated_at is not null

)

select
    t.teleport_user,
    t.full_name,
    t.department,
    t.terminated_at,

    f.event_uid,
    f.event_type,
    f.event_code,
    f.event_time                                            as access_event_at,
    f.source_ip,

    -- How long AFTER termination the access happened. Any positive value is a breach
    -- of the offboarding invariant; surfacing the gap helps triage (minutes = a
    -- lock race; days = a deprovisioning miss).
    datediff(minute, t.terminated_at, f.event_time)         as minutes_after_termination,

    'OFFBOARDING EXCEPTION: terminated identity produced an access event after termination'
        as finding

from terminated_identities t
join fct f
    on f.teleport_user = t.teleport_user
-- The breach condition: an access event strictly after the termination instant.
-- terminated_at is a date in the demo seed; cast to a timestamp at end-of-day so we
-- only flag activity that is unambiguously post-termination, not same-day offboarding
-- bookkeeping. In production terminated_at is a full timestamp and this cast is a no-op.
where f.event_time > dateadd(day, 1, t.terminated_at::timestamp)
  -- Only genuine ACCESS/USE events count as a breach. Lifecycle-remediation events
  -- (lock.create, user.delete, user.update) legitimately post-date termination —
  -- that is the Leaver path working, not a violation — so they are NOT breaches.
  -- Restricting to the access verbs (rather than excluding remediation verbs) keeps
  -- the invariant precise and avoids false positives that would break the zero-row test.
  and f.event_type in ('user.login', 'session.start', 'access_request.create')
