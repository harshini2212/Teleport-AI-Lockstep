-- stg_teleport_events
--
-- The one place we unpack the raw Teleport audit event SUPER blob into typed,
-- flat columns. Everything downstream reads from here, never from the raw source,
-- so the SUPER dot/bracket notation lives in exactly one model.
--
-- Materialized incremental because the audit stream is append-only and large:
-- a full refresh would re-scan every S3-landed event on every run. We use
-- delete+insert on event_uid so a Fivetran re-sync of a late/duplicated file
-- replaces rather than duplicates rows (event_uid = Teleport's event `uid`,
-- globally unique per the Audit Events schema).
--
-- Redshift SUPER notes:
--   * `_data.field` is dot-notation into parsed JSON; it yields a SUPER value.
--   * Cast SUPER -> scalar explicitly (::varchar, ::timestamp, ::boolean) or the
--     column stays SUPER and comparisons behave loosely (dynamic typing).
--   * Nested/dotted keys like Teleport's `addr.remote` are NOT a path segment —
--     they're a single key containing a dot, so we bracket-index: `_data['addr.remote']`.

{{
  config(
    materialized = 'incremental',
    incremental_strategy = 'delete+insert',
    unique_key = 'event_uid',
    sort = 'event_time',
    dist = 'even'
  )
}}

with source as (

    select
        _data,
        _fivetran_synced,
        _fivetran_deleted
    from {{ source('raw_teleport', 'audit_events') }}
    -- Honor Fivetran soft-deletes: a tombstoned row must not survive in staging.
    where _fivetran_deleted = false

),

unpacked as (

    select
        -- Identity of the event. Teleport stamps every audit event with a unique
        -- `uid`; this is our grain and incremental unique_key.
        _data.uid::varchar              as event_uid,

        -- `event` is the dotted event type (the tagged-union discriminator):
        -- 'user.login', 'session.start', 'access_request.create', 'user.create',
        -- 'lock.create', etc. `code` is the stable short code (e.g. 'T1000I' for a
        -- successful local login) — handy for filtering without string-matching `event`.
        _data.event::varchar            as event_type,
        _data.code::varchar             as event_code,

        -- `time` is RFC3339; Redshift parses it on the ::timestamp cast.
        _data.time::timestamp           as event_time,

        -- `user` is the Teleport username (here the goteleport.com email). Some
        -- events also carry `login` = the OS/db principal that was assumed.
        _data.user::varchar             as teleport_user,
        _data.login::varchar            as login,

        -- Source IP. Teleport records the remote address under the `addr.remote`
        -- key (a single key literally containing a dot), hence bracket indexing.
        -- We strip the :port suffix to keep just the IP for the geo detectors.
        split_part(_data['addr.remote']::varchar, ':', 1) as source_ip,

        -- `success` is present on auth-style events (login, access_request review).
        -- Absent on neutral events (session.start), where it reads as NULL.
        _data.success::boolean          as success,

        -- Raw passthrough for anything we didn't promote to a column. Lets a
        -- downstream model reach a rare field without re-touching this model.
        _data                           as event_payload,
        _fivetran_synced

    from source

)

select *
from unpacked

{% if is_incremental() %}
-- High-watermark: only process events newer than the latest we've already loaded.
-- Cheap on Redshift because the table is sorted by event_time (see config.sort).
where event_time > (select coalesce(max(event_time), '1970-01-01'::timestamp) from {{ this }})
{% endif %}
