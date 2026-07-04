-- fct_access_events
--
-- The access-event fact: one row per access-relevant Teleport audit event, with a
-- foreign key to dim_identity. "Access-relevant" excludes the high-volume neutral
-- chatter (cert.create, session.end heartbeats) and keeps the events a reviewer
-- reasons about: logins, session starts, JIT requests/reviews, lifecycle mutations,
-- and locks.
--
-- Incremental for the same reason as staging — append-only, large, never mutated
-- in place. delete+insert on event_uid keeps it idempotent under Fivetran re-syncs.
--
-- Grain: one row per event_uid (a subset of stg_teleport_events).

{{
  config(
    materialized = 'incremental',
    incremental_strategy = 'delete+insert',
    unique_key = 'event_uid',
    sort = 'event_time',
    dist_key = 'teleport_user'
  )
}}

with events as (

    select * from {{ ref('stg_teleport_events') }}

    where event_type in (
        'user.login',
        'user.create',
        'user.update',
        'user.delete',
        'session.start',
        'access_request.create',
        'access_request.review',
        'lock.create'
    )

    {% if is_incremental() %}
      -- Only fold in events newer than what the fact already holds.
      and event_time > (select coalesce(max(event_time), '1970-01-01'::timestamp) from {{ this }})
    {% endif %}

)

select
    e.event_uid,
    e.event_time,
    e.event_type,
    e.event_code,

    -- FK to dim_identity. Kept as the natural key (teleport_user) rather than a
    -- surrogate so the relationship is legible in ad-hoc audit queries; the
    -- relationships test in _access_review__models.yml enforces referential integrity.
    e.teleport_user,

    e.login,
    e.source_ip,
    e.success,

    -- Convenience flags so marts don't re-pattern-match event_type.
    (e.event_type = 'session.start')          as is_session,
    (e.event_type = 'user.login')             as is_login,
    (e.event_type like 'access_request.%')    as is_jit_request,
    (e.event_type = 'lock.create')            as is_lock,

    e.event_payload

from events e
