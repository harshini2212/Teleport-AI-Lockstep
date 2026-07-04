# macOS endpoint hardening + compliance → Teleport device trust

The endpoint half of the access model. Lifecycle Guard governs *who* gets access;
this directory governs *from what device*. A hardened, attested Mac is the
precondition for the device-trust step-up that `terraform/device_trust.tf`
enforces on sensitive roles (e.g. `k8s-prod`).

Two scripts, one read-only contract:

| Script | Mode | Purpose |
|--------|------|---------|
| `harden.sh` | root, mutating, idempotent | Applies the CIS macOS baseline (standalone / Jamf policy fallback) |
| `compliance-check.sh` | any user, **read-only** | Emits strict JSON posture; doubles as a Jamf Extension Attribute |

> **Standalone vs. enforced.** `harden.sh` is the readable, auditable baseline and
> a fallback for hosts not yet under full profile management. The **enforced** path
> is **Jamf Pro Configuration Profiles**, which a local admin cannot clear and the
> MDM framework re-asserts. FileVault in particular *cannot* be silently forced
> from a script (it needs interactive auth or deferred-enable with key escrow) —
> see the honesty note in `harden.sh`; the real control is a Jamf FileVault profile.

## Controls → commands

| Control | CIS area | Detect | Apply (`harden.sh`) |
|---------|----------|--------|---------------------|
| FileVault (FDE) | 2.6 | `fdesetup status` | `fdesetup enable -defer …` (Jamf profile enforces for real) |
| Application firewall | 2.x | `socketfilterfw --getglobalstate` | `socketfilterfw --setglobalstate on` + `--setstealthmode on` |
| Gatekeeper | 2.x | `spctl --status` | `spctl --master-enable` |
| Screen lock | 5.x | `defaults -currentHost read com.apple.screensaver askForPassword` | `… askForPassword -int 1`; `… askForPasswordDelay -int 0` |
| Auto updates | 1.x | `defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled` | `softwareupdate --schedule on` + `AutomaticCheckEnabled`/`AutomaticDownload`/`AutomaticallyInstallMacOSUpdates`/`CriticalUpdateInstall -bool true` |
| Guest account | 5.x | `defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled` | `sysadminctl -guestAccount off` + `GuestEnabled -bool false` |
| SIP | — | `csrutil status` | **verify only** — SIP toggles only from Recovery; flagged if off |

`compliance-check.sh` emits one strict JSON object:

```json
{"serial":"C02XXXXXXXXX","filevault":true,"firewall":true,"gatekeeper":true,"sip":true,"screen_lock":true,"auto_updates":true,"guest_disabled":true,"overall":true}
```

`overall` is `true` only when every required control passes. The object
unmarshals cleanly into the `Compliance` struct in `go/internal/jamf` (keys:
`serial`, `filevault`, `firewall`, `gatekeeper`, `sip`, `screen_lock`,
`auto_updates`, `guest_disabled`, `overall`).

## Wire it into Jamf

### 1. Extension Attribute

Create a Jamf Pro **Extension Attribute** (Computer → Extension Attributes),
input type **Script**, and paste `compliance-check.sh` run with `--jamf-ea`:

```bash
/usr/local/bin/compliance-check.sh --jamf-ea
```

`--jamf-ea` wraps the JSON in `<result>…</result>`, which is the format Jamf
requires for a script EA. Jamf stores the value on every inventory check-in.

### 2. "Compliant Macs" Smart Group

Create a Smart Computer Group whose membership criteria are the controls you
require. Two equivalent approaches:

- **Coarse:** EA *contains* `"overall":true` — single criterion, simplest.
- **Granular:** AND together the individual keys (e.g. EA *contains*
  `"filevault":true` AND *contains* `"firewall":true` …) so the group also
  reflects *why* a host is non-compliant.

Smart Group membership re-evaluates automatically as inventory updates, so a host
that drifts out of compliance silently leaves "Compliant Macs."

### 3. Smart Group → Teleport device inventory

Teleport's [`jamf_service`](https://goteleport.com/docs/admin-guides/access-controls/device-trust/jamf-integration/)
syncs Jamf-managed devices into the Teleport device inventory on a schedule. Its
`spec.inventory[].filter_rsql` is a Jamf **RSQL** filter that selects *which*
Jamf computers to import — the natural seam for "only sync compliant Macs."

```yaml
kind: jamf_service
version: v1
metadata:
  name: jamf
spec:
  enabled: true
  api_endpoint: https://your-tenant.jamfcloud.com
  # client_id / client_secret supplied out-of-band, not committed here.
  sync_delay: 0s
  inventory:
    # RSQL evaluated by Jamf's classic/Pro API. Managed devices only; couple this
    # with the "Compliant Macs" Smart Group so non-compliant hosts never enter the
    # Teleport device inventory in the first place.
    - filter_rsql: "general.remoteManagement.managed==true"
      sync_period_partial: 4h
      sync_period_full: 24h
      on_missing: NOOP
```

> **Honesty on the seam.** `filter_rsql` filters Jamf's device records; it does not
> by itself read the Extension Attribute boolean. The robust pattern is to gate on
> the **Smart Group** (compliant hosts only) and treat the EA as the evidence
> behind that group, rather than hand-authoring an EA predicate into RSQL — EA
> fields are not uniformly RSQL-queryable across Jamf API versions, so relying on
> the Smart Group keeps the integration version-independent.

Once a Mac is in the Teleport inventory and enrolled in device trust, roles with
`device_trust_mode: required` (see `terraform/device_trust.tf` and `k8s-prod` in
`terraform/roles.tf`) will only authenticate from that attested, compliant device.

## Pointers

- `go/internal/jamf` — Go client that reads the `compliance-check.sh` JSON
  (`Compliance` struct) and reconciles posture into the device-trust decision;
  the companion to the `teleport`/`engine` packages. *(Planned companion package —
  the JSON contract above is the seam it consumes.)*
- `terraform/device_trust.tf` — cluster-wide device trust
  (`cluster_auth_preference.spec.device_trust.{mode,auto_enroll}`) plus the
  `jamf_service` resource. Per-role enforcement lives in role
  `spec.options.device_trust_mode` (`off` | `optional` | `required` |
  `required-for-humans`). *(Companion Terraform — `k8s-prod` in `roles.tf`
  already sets `device_trust_mode = "required"`.)*

> **Enterprise gate.** Teleport **Device Trust** and the **`jamf_service`**
> integration are **Teleport Enterprise** features. The hardening and compliance
> scripts here are open and run anywhere; the cluster-side enforcement they feed
> requires an Enterprise license. This is called out so nothing in this directory
> overclaims what the open binary can do on its own.
