-- dim_identity
--
-- One row per identity, joining the HRIS roster (employment truth) to what the
-- Teleport audit stream has actually observed. This is the dimension the access
-- review hangs off: every fact and mart resolves an identity through here.
--
-- "Identity" is deliberately broader than "employee": it includes the AI agent
-- `kyra`, which is a Teleport workload_identity / bot, not a person. We keep it in
-- the dimension (employment_status carried from the roster) so agent access is
-- reviewed by the same controls as human access — the JD's agentic-identity angle.
--
-- Grain: one row per teleport_user.

{{ config(materialized = 'table', sort = 'teleport_user') }}

with events as (

    select * from {{ ref('stg_teleport_events') }}

),

-- Everyone the audit stream has ever seen as a Teleport user, even if they are
-- not (or no longer) in the HRIS roster. A user observed in events but absent from
-- the roster is itself a signal (orphaned/unmanaged identity).
observed_identities as (

    select
        teleport_user,
        min(event_time) as first_seen_at,
        max(event_time) as last_seen_at
    from events
    where teleport_user is not null
    group by 1

),

roster as (

    -- The HRIS source of truth. In production this is Fivetran-synced from Rippling;
    -- here it is a seed (see seeds/hris_roster.csv).
    select
        teleport_user,
        full_name,
        department,
        title,
        employment_status,
        hired_at,
        terminated_at
    from {{ ref('hris_roster') }}

)

select
    -- Prefer the roster spelling of the identity, fall back to what events saw.
    coalesce(r.teleport_user, o.teleport_user)        as teleport_user,
    r.full_name,
    r.department,
    r.title,

    -- Employment status, with audit-observed identities that are missing from HRIS
    -- surfaced explicitly rather than silently dropped.
    coalesce(r.employment_status, 'unknown')          as employment_status,
    r.hired_at,
    r.terminated_at,

    -- Derived offboarding flag — the single boolean the offboarding-exception mart
    -- keys on. Mirrors hris.Terminated in go/internal/policy: a terminated identity
    -- is entitled to nothing, so any post-termination activity is an exception.
    (r.employment_status = 'terminated')              as is_offboarded,

    -- True when the audit stream knows this identity but HRIS does not — an
    -- unmanaged/orphaned Teleport user that lifecycle automation never provisioned.
    (r.teleport_user is null)                         as is_unmanaged,

    o.first_seen_at,
    o.last_seen_at

from roster r
full outer join observed_identities o
    on r.teleport_user = o.teleport_user
