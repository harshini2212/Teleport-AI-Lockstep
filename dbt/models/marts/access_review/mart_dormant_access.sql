-- mart_dormant_access
--
-- Recertification candidates (NIST 800-53 AC-2 account management / periodic review,
-- SOC 2 CC6.2/CC6.3).
--
-- An identity that still exists in Teleport (the audit stream has seen it) and is
-- still employed, but has had NO interactive session in the last var('dormant_days'),
-- is a stale-access candidate: access nobody is using is access nobody will notice
-- being abused. The recertification action is "confirm still needed or revoke."
--
-- We measure dormancy from the last session.start (actual use), not last login or
-- cert issuance, because a cert can be minted by automation without anyone using it.
--
-- Grain: one row per dormant identity.

{{ config(materialized = 'table') }}

with identity as (

    select * from {{ ref('dim_identity') }}

),

fct as (

    select * from {{ ref('fct_access_events') }}

),

-- Last time each identity actually *used* access (started a session).
last_session as (

    select
        teleport_user,
        max(event_time) as last_session_at
    from fct
    where is_session
    group by 1

)

select
    i.teleport_user,
    i.full_name,
    i.department,
    i.title,
    i.employment_status,
    ls.last_session_at,
    datediff(day, ls.last_session_at, current_date) as days_since_last_session,
    {{ var('dormant_days') }}                        as dormant_threshold_days,
    'AC-2 recertification: active identity with no session in '
        || {{ var('dormant_days') }} || ' days'      as finding
from identity i
left join last_session ls
    on i.teleport_user = ls.teleport_user
-- Only active identities are recertification candidates; terminated ones are the
-- offboarding-exception mart's job, not this one.
where i.employment_status = 'active'
  -- Dormant = either never started a session, or last session is past the threshold.
  and (
        ls.last_session_at is null
        or ls.last_session_at < dateadd(day, -{{ var('dormant_days') }}, current_date)
      )
  -- The agent identity (kyra) is excluded: a workload_identity is expected to run
  -- headless and may legitimately go quiet between automation runs. Reviewing agent
  -- liveness is a separate control from human-account dormancy.
  and coalesce(i.department, '') <> 'Automation'
