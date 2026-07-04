# Terraform — Teleport policy-as-code

The enforced half of the access model. These resources are the **source of
truth** the Go engine's `policy` package mirrors.

| File | What it manages |
|------|-----------------|
| `provider.tf` | Teleport provider + `tbot` identity-file auth (no static admin token) |
| `roles.tf` | Per-department roles, short `max_session_ttl`, device-trust on prod, the access-reviewer role |
| `sso_and_access_requests.tf` | Okta SSO login rule, the SRE just-in-time elevation role, and the quarterly prod-access review list |

## Apply

```bash
terraform init
terraform plan
terraform apply
```

Requires a Teleport cluster and a `tbot`-issued identity file (`identity_file_path`
in `provider.tf`) bound to a role allowed to manage `role`, `login_rule`, and
`access_list` resources. See the
[Teleport Terraform provider guide](https://goteleport.com/docs/admin-guides/infrastructure-as-code/terraform-provider/).

## Why it mirrors the Go policy

`roles.tf`'s `local.department_roles` is the same mapping as `policy.Default()`
in `go/internal/policy/policy.go`. Terraform enforces it in the cluster; the
engine reasons about it at runtime to make provisioning/JIT decisions. A CI check
diffing the two is the obvious guard against drift.
