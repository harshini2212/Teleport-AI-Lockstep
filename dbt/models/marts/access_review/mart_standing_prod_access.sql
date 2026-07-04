-- mart_standing_prod_access
--
-- Least-privilege violation finder (NIST 800-53 AC-6, SOC 2 CC6.1/CC6.3).
--
-- Privileged roles — k8s-prod, it-admin, db-readonly — are meant to be held
-- *just-in-time*: requested via an access_request, approved (auto or by a reviewer),
-- granted for one short-lived session, gone at expiry. A holder who has the role
-- as STANDING access (never went through a JIT request) is exactly the
-- always-on-admin anti-pattern AC-6 exists to eliminate.
--
-- Heuristic, stated plainly: we infer "standing" as "used a privileged role's
-- access (a session) without a preceding access_request.create from that user in
-- the review window". The authoritative grant set lives in Teleport role bindings
-- / access lists (Terraform); this mart is the warehouse approximation an auditor
-- can recompute from the event record alone. A user who only ever touches prod via
-- a fresh JIT request will not appear here.
--
-- Grain: one row per (teleport_user, privileged_role) standing-access finding.

{{ config(materialized = 'table') }}

-- The privileged roles whose use should always be JIT-gated. Mirrors the
-- device-trust-required prod roles in terraform/roles.tf and the it-admin rule set.
{% set privileged_roles = ['k8s-prod', 'it-admin', 'db-readonly'] %}

with fct as (

    select * from {{ ref('fct_access_events') }}

),

identity as (

    select * from {{ ref('dim_identity') }}

),

-- Sessions where the assumed role/login indicates a privileged role was exercised.
-- Teleport records requested roles on access_request events; on a session it records
-- the login/roles used. We match the privileged role names against the event payload
-- (the `roles` array on the issued cert/session) so this works regardless of which
-- field carries it across Teleport versions.
privileged_use as (

    select
        f.teleport_user,
        pr.role_name                              as privileged_role,
        min(f.event_time)                         as first_used_at,
        max(f.event_time)                         as last_used_at,
        count(*)                                  as use_count
    from fct f
    -- Unnest the candidate privileged role names and keep the ones that appear in
    -- the event's roles array. `event_payload.roles` is a SUPER array; we test
    -- membership by string-searching the serialized array — robust to field drift.
    cross join (
        {% for r in privileged_roles -%}
        select '{{ r }}'::varchar as role_name
        {%- if not loop.last %} union all {% endif %}
        {% endfor %}
    ) pr
    where f.is_session
      and json_serialize(f.event_payload.roles) like '%"' || pr.role_name || '"%'
    group by 1, 2

),

-- Did this user file a JIT request for that role inside the review window? If so,
-- their prod access is on-demand, not standing, and we do NOT flag it.
jit_requests as (

    select distinct
        f.teleport_user,
        pr.role_name as privileged_role
    from fct f
    cross join (
        {% for r in privileged_roles -%}
        select '{{ r }}'::varchar as role_name
        {%- if not loop.last %} union all {% endif %}
        {% endfor %}
    ) pr
    where f.is_jit_request
      and json_serialize(f.event_payload.roles) like '%"' || pr.role_name || '"%'
      and f.event_time >= dateadd(day, -{{ var('review_period_days') }}, current_date)

)

select
    pu.teleport_user,
    i.full_name,
    i.department,
    i.employment_status,
    pu.privileged_role,
    pu.first_used_at,
    pu.last_used_at,
    pu.use_count,
    -- The control assertion: privileged access used without a JIT request behind it.
    'AC-6 least-privilege: standing privileged access (no JIT request observed)' as finding
from privileged_use pu
left join jit_requests jr
    on pu.teleport_user = jr.teleport_user
   and pu.privileged_role = jr.privileged_role
left join identity i
    on pu.teleport_user = i.teleport_user
where jr.teleport_user is null   -- no JIT request -> standing access -> flag it
