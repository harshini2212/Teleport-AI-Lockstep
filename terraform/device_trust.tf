// Device trust — make "access requires a known, enrolled device" real at the
// cluster, and wire it to the lifecycle controller.
//
// Device trust binds a Teleport login to a hardware-attested, enrolled device
// (Secure Enclave / TPM), so even a valid short-lived cert on an unmanaged laptop
// can't reach sensitive resources. This is the cluster half of the README's
// device-trust step-up: the audit engine's `new-geo-access` remediation raises
// the bar to "required" for the affected identity, and these are the primitives
// it raises against.
//
// Two layers:
//   - auth_preference.spec.device_trust  → the cluster-wide DEFAULT.
//   - role spec.options.device_trust_mode → per-role OVERRIDE (stricter).
//
// Docs: https://goteleport.com/docs/admin-guides/access-controls/device-trust/
//
// REQUIRES Teleport Enterprise: device trust enforcement (and the jamf_service
// integration below) are Enterprise features. Documented here as accurate
// policy-as-code; they will not enforce on an OSS cluster.

// Cluster-wide default: device trust is "optional" — logins succeed without an
// enrolled device, but an enrolled device is recorded and honored. auto_enroll
// lets a device that authenticates via a trusted source (Jamf inventory, below)
// enroll itself, so IT doesn't hand-enroll every machine. Specific roles then
// upgrade this to "required" (see overrides below).
//
// device_trust.mode accepts: off | optional | required | required-for-humans.
// "required-for-humans" is the pragmatic middle ground: enforce on interactive
// human logins while exempting bots/agents (which present SVIDs, not devices) —
// worth considering once the kyra bot in workload_identity.tf is live.
resource "teleport_auth_preference" "main" {
  version = "v2"
  metadata = {
    name = "cluster-auth-preference"
  }
  spec = {
    device_trust = {
      mode        = "optional"
      auto_enroll = true
    }
  }
}

// ---------------------------------------------------------------------------
// Per-role overrides — bump device-sensitive roles to "required"
// ---------------------------------------------------------------------------
//
// k8s-prod ALREADY sets device_trust_mode = "required" in roles.tf (production
// Kubernetes is the canonical "managed device only" surface). The same one-line
// override belongs on any role that reaches sensitive infra. To avoid two files
// fighting over the same resource, the recommended overrides for it-admin and
// db-readonly are documented here and applied in roles.tf, NOT redeclared:
//
//   resource "teleport_role" "it_admin" {            // in roles.tf
//     spec = {
//       options = {
//         max_session_ttl   = "8h"
//         device_trust_mode = "required"   // <-- IT admin actions from managed devices only
//       }
//       ...
//
//   resource "teleport_role" "db_readonly" {         // in roles.tf
//     spec = {
//       options = {
//         max_session_ttl   = "8h"
//         device_trust_mode = "required"   // <-- DB access from managed devices only
//       }
//       ...
//
// Keeping the cluster default at "optional" + selectively "required" per role is
// the standard rollout: you don't lock everyone out on day one, you ratchet the
// blast-radius roles first. The audit engine can also flip an identity's
// effective requirement to "required" dynamically as a remediation.

// ---------------------------------------------------------------------------
// Jamf inventory source — feeds device trust its "is this a managed Mac?" truth
// ---------------------------------------------------------------------------
//
// IMPORTANT: this is NOT a Terraform resource. jamf_service is a Teleport AGENT
// process config block, declared in the agent's `teleport.yaml`, not in the
// Teleport API / Terraform provider. It is shown here (commented) so the device-
// trust story is complete and so the macOS-endpoint / Jamf integration named in
// the README has a concrete home. Place this under the agent's top-level config:
//
//   # teleport.yaml  (Teleport agent running the Jamf connector)
//   jamf_service:
//     enabled: true
//     api_endpoint: https://yourorg.jamfcloud.com
//     client_id: "<jamf-api-client-id>"
//     # Secret is a file reference, never an inline literal — same secretless
//     # posture as the tbot identity file in provider.tf.
//     client_secret_file: /etc/teleport/jamf-client-secret
//     inventory:
//       - device_type: computers          # sync Jamf "computers" (Macs) as Teleport devices
//         sync_period_partial: 6h         # frequent partial sync: pick up new/changed devices
//         sync_period_full: 24h           # daily full reconcile of the whole inventory
//         on_missing: DELETE              # device gone from Jamf => remove its Teleport device
//                                         # (the device-side analog of the Leaver lock:
//                                         #  an off-managed laptop loses its trusted status)
//         # Only sync actively-managed devices; RSQL is Jamf's query language.
//         filter_rsql: "general.remoteManagement.managed==true"
//
// Once running, devices enrolled in Jamf appear as trusted Teleport devices, and
// roles with device_trust_mode = "required" will admit logins from them while
// rejecting unmanaged hardware. on_missing: DELETE closes the loop: a device that
// leaves Jamf management loses Teleport trust on the next sync.
//
// REQUIRES Teleport Enterprise: jamf_service and device trust enforcement are
// Enterprise-only. (Documented honestly: on OSS this block is inert.)
