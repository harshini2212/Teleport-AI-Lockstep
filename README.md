# Lifecycle Guard — Identity Lifecycle Automation for Teleport

A **durable Joiner/Mover/Leaver (JML) access-automation controller** for Teleport. It turns HRIS
(Rippling) and IdP (Okta) lifecycle events into **least-privilege, short-lived Teleport access for both
humans and AI agents** — provisioning it, reconciling it on role changes, and **provably** revoking it on
termination — then gates access on **Jamf device trust** and watches the audit stream for anomalies,
auto-containing them.

It is built as the thing an **IT Security & Automation Engineer at Teleport** actually ships:
**Temporal + Go workflow automation on Kubernetes**, **Terraform**, and **shell**, integrated with
**Okta, Rippling, Panther, Jamf Pro, Zendesk, and Chrome Enterprise**, that **dogfoods Teleport Identity,
Teleport Policy, and Machine & Workload Identity**.

> **Why this, now.** Teleport is *"the AI Infrastructure Identity Company"* — it gives *"every human,
> machine, workload, and AI agent a cryptographically secured identity."* Lifecycle Guard is the
> internal-IT expression of exactly that thesis: one controller governs a **human** and an **AI agent**
> ([Kyra](../PAPER-2-Software.md)) through the *same* provable lifecycle. It maps to Teleport's 2026
> direction — [Identity Security + Access Graph](https://goteleport.com/platform/identity-security/),
> [Machine & Workload Identity](https://goteleport.com/platform/machine-and-workload-identity/), and the
> [Agentic Identity Framework](https://goteleport.com/about/newsroom/press-releases/teleport-introduces-agentic-identity-framework/).

---

## What it does

| Stage | Input | Action against Teleport |
|------|-------|--------------------------|
| **Joiner** | HRIS/Okta "new hire" (or an AI agent deploy) | Provision a Teleport user + roles, or issue a scoped **SPIFFE workload identity** for an agent |
| **Mover** | "role change" / agent re-scope | Reconcile — grant the new, revoke the stale, no new long-lived secret |
| **Leaver** | "terminated" / agent decommission | **Lock** the identity (sever live sessions/SVIDs) **and** deprovision — proven total in Lean |
| **JIT access** | a role request | Auto-approve within policy escalation paths; else a **durable human-approval signal** (Temporal) with timeout |
| **Device trust** | Jamf inventory + `compliance-check.sh` | Block sessions from unmanaged or non-compliant Macs |
| **Audit watch** | Teleport event stream → Panther/SIEM | Detect offboarding races, privilege escalation, new-geo, device-trust violations; auto-remediate |
| **Access review** | the above, deterministically | An **LLM copilot** writes a plain-English, human-approval-required quarterly review |

The core reconcile is **declarative**: access is a pure function of the identity record
(`policy.RolesFor` / `policy.RolesForAgent`), so a terminated human *and* a decommissioned agent both map
to the empty role set. That property is **machine-checked in Lean 4** — not just unit-tested.

## How it maps to the role (the JD, line by line)

- **Temporal + Go workflow automation on Kubernetes** → `go/temporal/` (durable JML, JIT-approval signal, Zendesk lockout saga) + `k8s/`.
- **Terraform + shell + Go** → `terraform/`, `macos/*.sh`, `go/`.
- **Integrations: Panther, Jamf Pro, Okta, Rippling, Chrome Enterprise, Zendesk** → `go/internal/connector/*` + `go/internal/jamf`.
- **Harden macOS endpoints** → `macos/harden.sh` + `compliance-check.sh` → Teleport Device Trust.
- **Dogfood Teleport Identity & Policy** → roles, access lists, login rules, access requests, locks, and **workload identity** as Terraform + Go.
- **Data warehousing (Redshift/Fivetran/dbt) — nice-to-have** → `dbt/` access-review analytics.
- **Helpdesk (access, lockout)** → the Zendesk lockout workflow: a free-text ticket → NLP intent → `tctl lock`.

## The AI thread (kept honest)

AI lives **at the edge and on top**; the deterministic engine + policy-as-code + Lean proof stay **at the
core**. In every case the AI *proposes or narrates*, it never *decides or mutates* access:

1. **Kyra as a subject** — the voice-first AI agent gets a real SPIFFE identity, is re-scoped when a tool is added, and is decommissioned via the same lock-then-revoke path proven total for humans.
2. **NLP at the edge** — a free-text Zendesk lockout ticket is classified into a structured intent before the deterministic, Lean-verified workflow executes it.
3. **Access-review copilot** — a read-only Anthropic-Claude component narrates deterministic engine output into a SOC 2 quarterly review (mirrors Teleport Access Graph AI summaries).

---

## Repo layout

```
teleport-lifecycle-guard/
├── go/                          # root module (stdlib only — runs & tests offline)
│   ├── cmd/lifecycleguard/      # offline demo: events → actions + trace.json
│   └── internal/
│       ├── hris/ subject/       # human + AI-agent lifecycle event models
│       ├── policy/              # dept/scope → Teleport roles (mirrors Terraform)
│       ├── teleport/            # mock of the Teleport API client (users, locks, workload identity, bots)
│       ├── engine/              # reconcile: human + agent JML; JIT decisions
│       ├── audit/               # anomaly detectors incl. device-trust gating
│       ├── jamf/                # Jamf Pro connector + compliance-check.sh parser
│       ├── connector/{rippling,okta,panther,zendesk,chrome}/  # vendor connectors
│       └── copilot/             # LLM access-review copilot (net/http, read-only)
│   └── temporal/                # NESTED module (Temporal SDK isolated here)
│       ├── activities/ workflows/ worker/ cmd/{worker,starter}
├── terraform/                   # Teleport provider: roles, login rule, access lists, JIT, workload identity, device trust
├── macos/                       # harden.sh + compliance-check.sh (CIS baseline; Jamf-ready)
├── k8s/                         # stateless Temporal worker Deployment
├── dbt/                         # Redshift/Fivetran/dbt access-review analytics
├── lean/                        # Lean 4: offboarding invariant, proven for humans AND agents
└── dashboard/                   # single-file dashboard rendering the engine's trace.json
```

---

## Run it

### 1. The live server + dashboard (Go ≥ 1.22, stdlib only) — start here
```bash
cd go
go run ./cmd/server                              # → http://localhost:8080
```
This serves the dashboard **and** a live JSON API from the same in-memory engine — a real full-stack app,
not a static file. The dashboard's controls (Onboard / Offboard / JIT / Deploy agent / Run review) POST to
the backend and re-render from live state. API:

| Method | Path | Purpose |
|---|---|---|
| `GET`  | `/api/trace` | current run (steps, agents, JIT, findings, devices, state) |
| `POST` | `/api/human-event` | `{type,email,name,department,title}` → reconcile → `{actions,trace}` |
| `POST` | `/api/agent-event` | `{type,name,scope[]}` → issue/rescope/revoke a SPIFFE identity |
| `POST` | `/api/jit` | `{user,requested}` → auto-approve or route to human |
| `POST` | `/api/reset` | reload the demo |
| `POST` | `/api/review` | run the LLM access-review copilot (needs `ANTHROPIC_API_KEY`) |

### 2. The CLI demo + tests
```bash
cd go
go test ./...                                    # policy, engine, audit, jamf, copilot — all pass
go run ./cmd/lifecycleguard -out ../dashboard/trace.json
ANTHROPIC_API_KEY=sk-... go run ./cmd/lifecycleguard -review   # + LLM access review
```
The root module is dependency-free and runs with no network. Swapping `teleport.NewMock()` for
`client.New(ctx, …)` points it at a real Teleport Auth Server — the engine code is unchanged.

The dashboard also opens standalone (`dashboard/index.html`) — it renders an embedded snapshot in
"offline" mode when no backend is reachable, and switches to "LIVE — Go backend" when the server is up.

### 3. The durable workflows (Temporal)
```bash
temporal server start-dev                        # Temporal CLI: frontend :7233, UI :8233
cd go/temporal && go mod tidy                     # generates go.sum (needs network)
go run ./cmd/worker      # in one shell — the K8s worker binary
go run ./cmd/starter     # in another — starts JML, JIT-approval, and lockout workflows
```
> The Temporal SDK lives in the **nested** `go/temporal` module so the root stays stdlib-only and
> offline-buildable. `go/temporal/go.sum` is generated at build time.

### 4. Terraform / macOS / dbt / Lean
```bash
cd terraform && terraform init && terraform plan     # needs a tbot identity file (see provider.tf)
sudo bash macos/harden.sh                            # macOS CIS baseline (see macos/README.md)
cd dbt && dbt build                                  # Redshift access-review marts (see dbt/README.md)
cd lean && lake build                                # type-checks the proofs; fails if any is wrong
```

---

## The formal guarantee

The one property you never want wrong is "a terminated identity cannot retain access." Lifecycle Guard
proves it in Lean 4 for **every** policy, **every** prior state, and **both** kinds of principal:

```lean
theorem terminated_subject_loses_all_access
    (s : Subject) (prior : UserState) (h : s.status = Status.terminated) :
    hasAccess (reconcileSubject s prior) = false
```

A unit test checks the cases you remembered; this checks all of them — for humans *and* AI agents. See
[`lean/LifecycleGuard/`](lean/LifecycleGuard/).

---

## Honest scope notes

- **The root Go module compiles, vets clean, and all unit tests pass** (verified with Go 1.23) — policy,
  engine, audit, jamf, and copilot. The live server and CLI run against it. The **Temporal** module builds
  after `go mod tidy` pulls the SDK (`go/temporal/go.sum` is generated at build time). Lean, Terraform, and
  dbt were adversarially reviewed by a multi-agent pass but need their own toolchains to run (`lake build`,
  `terraform validate`, `dbt build`).
- **Enterprise features are labeled as such** — Teleport Device Trust, `jamf_service`, and Workload
  Identity SVID issuance require Teleport Enterprise; the Terraform/macOS comments say so.
- **macOS honesty** — FileVault can't be silently force-enabled from a script (deferred-enable only), SIP
  is verify-only outside Recovery, and `defaults write` is the standalone baseline; Jamf Configuration
  Profiles are the enforced path. The scripts say all of this in comments.
- **Vendor-API caveats preserved** — Rippling production webhooks are partner-gated (polling is the honest
  fallback); the exact `workload_identity` attestation attribute namespace is version-dependent.
