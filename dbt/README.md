# dbt — access-review analytics over Teleport audit events

The **warehouse half** of Lifecycle Guard. The Go engine reacts to lifecycle and
audit events in real time; the Lean proof certifies the offboarding invariant for
*every* policy. This dbt project re-derives the same access-review findings — and
the same invariant — over the **landed audit record in Redshift**, so an auditor
can recompute them from cold storage on their own schedule (SOC 2 / NIST 800-53
periodic access review).

It's also the JD's data-warehousing nice-to-have made concrete: **Redshift +
Fivetran + dbt**, with real idioms — `ref()`/`source()`, incremental models,
Redshift `SUPER` unnesting, Fivetran system columns, and `schema.yml` tests.

---

## The pipeline

```
Teleport cluster
   │  (audit events: user.login, session.start, access_request.create,
   │   user.create, lock.create, …)
   ▼
Teleport Event Handler              # the official forwarder (teleport-event-handler)
   │
   ▼
Fluentd  ──(s3 output plugin)──►  S3 bucket of NDJSON
                                     │   one JSON event per line
                                     ▼
                                 Fivetran  (S3 connector)
                                     │   adds _fivetran_synced / _fivetran_deleted /
                                     │   _file / _line / _modified
                                     ▼
                          Redshift  raw_teleport.audit_events
                                     │   event body in a single SUPER column `_data`
                                     ▼
                                   dbt  (this project)
                          ┌──────────┴───────────┐
                       staging                  marts
                  stg_teleport_events   dim_identity / fct_access_events
                  (SUPER → typed cols)  + 4 access-review marts + summaries
                                                 │
                                                 ▼
                                  Anthropic (Claude) narration step
                                  reads mart_access_summaries.summary_payload
                                  (deterministic SQL in, plain-English review out)
```

Why this shape: Teleport's Event Handler streams the audit log to Fluentd; the
Fluentd S3 plugin batches it to object storage; Fivetran's S3 connector incrementally
loads it into Redshift, landing the event JSON in a `SUPER` column because Teleport's
audit schema is a tagged union (fields depend on the event type). dbt does the
type-safe unnesting once, in `stg_teleport_events`, and everything else builds on
typed columns.

---

## Models

| Layer | Model | Grain | What it is |
|-------|-------|-------|------------|
| staging | `stg_teleport_events` | 1 / event | Unpacks the `_data` SUPER blob into typed columns (incremental, `delete+insert`) |
| marts | `dim_identity` | 1 / identity | HRIS roster ⋈ audit-observed activity (humans **and** the `kyra` agent) |
| marts | `fct_access_events` | 1 / access event | Access-relevant events, FK → `dim_identity` (incremental) |
| marts | `mart_standing_prod_access` | 1 / (user, role) | Privileged-role use with no JIT request behind it |
| marts | `mart_dormant_access` | 1 / identity | Active identities idle past `var('dormant_days')` |
| marts | **`mart_offboarding_exceptions`** | 1 / violating event | **Terminated identity acted after termination — must be empty** |
| marts | `mart_access_summaries` | 1 / identity | Deterministic `SUPER` payload for the Claude narration step |

---

## Mart → control mapping

Each review mart answers a specific control. Auditors recompute the control from the
cold record rather than trusting the real-time engine.

| Mart | NIST 800-53 | SOC 2 (TSC) | Question it answers |
|------|-------------|-------------|---------------------|
| `mart_standing_prod_access` | **AC-6** least privilege | CC6.1, CC6.3 | Who holds `k8s-prod` / `it-admin` / `db-readonly` as standing access instead of JIT? |
| `mart_dormant_access` | **AC-2** account management / review | CC6.2, CC6.3 | Which active accounts haven't been used in `dormant_days` and should be recertified? |
| `mart_offboarding_exceptions` | **AC-2(3)** disable on termination | CC6.2, CC6.3 | Did any terminated identity act after termination? (**should be none**) |
| `mart_access_summaries` | AU-6 audit review (analysis input) | CC4.1, CC7.2 | One deterministic per-identity rollup for narrated review |

---

## How it ties back to the Lean proof and the audit detectors

`mart_offboarding_exceptions` is the **same invariant**, expressed in three places:

| Where | Form | Enforced by |
|-------|------|-------------|
| `lean/LifecycleGuard/Basic.lean` | `theorem terminated_employee_loses_all_access` | `lake build` |
| `go/internal/audit/audit.go` | detector `offboarded-active-session` | `go test ./...` |
| **this project** | `mart_offboarding_exceptions` = ∅ | `dbt test` |

The dbt encoding is the singular test
[`tests/assert_no_offboarding_exceptions.sql`](tests/assert_no_offboarding_exceptions.sql):
it selects the violating rows, and a dbt singular test passes only when it returns
**zero rows**. So a post-termination access event makes `dbt test` exit non-zero —
the warehouse build goes red exactly like a broken Lean proof fails `lake build`.

The other marts mirror the engine's runtime reasoning: `mart_standing_prod_access`
re-derives the least-privilege check the policy enforces (`go/internal/policy`),
and `mart_dormant_access` is the recertification view the engine doesn't compute in
real time but an access review needs.

The demo seed (`seeds/hris_roster.csv`) carries the same identities as the engine
demo — `alice`/`bob` active, `carol`/`dave` terminated, `kyra` the AI agent — so a
clean run over correctly-offboarded data yields **empty** offboarding and (for the
remediated state) standing-access marts. Feed it audit data where the Leaver path
slipped and the headline mart lights up.

---

## Run it

Requires dbt with the Redshift adapter:

```bash
pip install dbt-redshift          # brings in dbt-core
```

Point dbt at a Redshift cluster/serverless workgroup. Copy the example profile and
set the env vars (nothing secret is committed — same posture as the Terraform's
tbot identity file):

```bash
cp profiles.example.yml ~/.dbt/profiles.yml
export REDSHIFT_HOST=my-cluster.xxxx.us-east-1.redshift.amazonaws.com
export REDSHIFT_USER=analytics_ro
export REDSHIFT_PASSWORD=…           # or use IAM auth (see profiles.example.yml prod target)
export REDSHIFT_DATABASE=analytics
```

Then:

```bash
dbt deps           # no-op unless you add packages.yml
dbt seed           # load the HRIS roster seed
dbt run            # build staging + marts
dbt test           # run schema tests AND the zero-row offboarding invariant
dbt source freshness   # warn/error if Fivetran has stopped landing audit events
```

`dbt build` runs seed → run → test in dependency order in one shot.

> **Offline note.** Like the rest of Lifecycle Guard, the model SQL is the artifact;
> it needs a live Redshift + a populated `raw_teleport.audit_events` to execute.
> The HRIS roster is a seed (not a live Fivetran sync) precisely so the access-review
> logic can be read and reasoned about without standing up the warehouse.

---

## Design notes

- **Deterministic SQL, AI on the edge.** `mart_access_summaries` emits a `SUPER`
  payload that is byte-for-byte reproducible from warehouse state. The Anthropic
  (Claude) step only *narrates* that payload into prose — it never sources facts, so
  every sentence in a generated review traces to a column. AI never sits on the
  safety-critical path, matching the engine/proof split.
- **One unnesting site.** All Redshift `SUPER` dot/bracket notation lives in
  `stg_teleport_events`. If Teleport renames an audit field across versions, exactly
  one model changes.
- **Idempotent under re-sync.** Both incremental models use `delete+insert` on the
  Teleport event `uid`, so a Fivetran re-load of a late or duplicated S3 file
  replaces rows instead of double-counting events.
- **Field-name honesty.** Teleport audit field names (`uid`, `event`, `code`,
  `time`, `user`, `login`, `addr.remote`) are taken from the documented Audit Events
  schema. Where a name is version-dependent — e.g. the issued-`roles` array used by
  `mart_standing_prod_access` — the model matches it defensively (serialized-array
  search) and says so in a comment rather than hard-coding a single field path.
```
