-- mart_access_summaries
--
-- One deterministic, machine-readable summary per identity — the structured input a
-- downstream Anthropic (Claude) narration step turns into a plain-English access
-- review for the reviewer. The division of labor is deliberate:
--
--   * SQL here stays 100% deterministic: same warehouse state -> same summary_payload,
--     byte-for-byte. Auditors can reproduce it; nothing depends on a model's mood.
--   * The LLM only *narrates* this payload (e.g. "Carol, terminated 2026-06-20, has 1
--     post-termination access event from 203.0.113.7 — investigate"). It never sources
--     facts; every claim it makes traces back to a field in summary_payload.
--
-- This mirrors the rest of Lifecycle Guard: deterministic core (engine/proof),
-- with AI on the narration edge, never on the safety-critical path.
--
-- summary_payload is a Redshift SUPER value so the narration consumer gets typed
-- JSON, not a string it has to re-parse.
--
-- Grain: one row per identity.

{{ config(materialized = 'table') }}

with identity as (

    select * from {{ ref('dim_identity') }}

),

fct as (

    select * from {{ ref('fct_access_events') }}

),

-- Recent source IPs per identity (last 30 days), de-duplicated and ordered. Feeds the
-- "where has this identity been connecting from" line of the narration.
recent_ips as (

    select
        teleport_user,
        listagg(distinct source_ip, ',')
            within group (order by source_ip) as recent_source_ips
    from fct
    where source_ip is not null
      and event_time >= dateadd(day, -30, current_date)
    group by 1

),

session_stats as (

    select
        teleport_user,
        max(event_time)                                 as last_session_at,
        -- Redshift has no SQL-standard FILTER clause; use a conditional sum.
        sum(case when is_session then 1 else 0 end)     as session_count_total
    from fct
    group by 1

),

-- Pull the two cross-mart flags so the payload is self-contained for the narrator.
dormant_flag as (
    select teleport_user, true as is_dormant from {{ ref('mart_dormant_access') }}
),

offboarding_flag as (
    select distinct teleport_user, true as has_offboarding_exception
    from {{ ref('mart_offboarding_exceptions') }}
)

select
    i.teleport_user,

    -- The deterministic SUPER payload. object()/array() build native SUPER on
    -- Redshift; the narration layer consumes this verbatim.
    json_parse(
        json_serialize(
            object(
                'teleport_user',             i.teleport_user,
                'full_name',                 i.full_name,
                'department',                i.department,
                'title',                     i.title,
                'employment_status',         i.employment_status,
                'is_offboarded',             i.is_offboarded,
                'is_unmanaged',              i.is_unmanaged,
                'terminated_at',             i.terminated_at,
                'last_session_at',           ss.last_session_at,
                'session_count_total',       coalesce(ss.session_count_total, 0),
                'is_dormant',                coalesce(df.is_dormant, false),
                'has_offboarding_exception', coalesce(of.has_offboarding_exception, false),
                'recent_source_ips',         coalesce(ri.recent_source_ips, '')
            )
        )
    ) as summary_payload

from identity i
left join recent_ips ri       on i.teleport_user = ri.teleport_user
left join session_stats ss    on i.teleport_user = ss.teleport_user
left join dormant_flag df      on i.teleport_user = df.teleport_user
left join offboarding_flag of  on i.teleport_user = of.teleport_user
