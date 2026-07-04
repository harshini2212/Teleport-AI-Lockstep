// SSO login rule + just-in-time access request config.
//
// login rule: when a user authenticates through Okta SSO, normalize their Okta
// claims into Teleport traits. Department ROLES are granted by the per-department
// access lists below (grants.roles pulled from local.department_roles in
// roles.tf), whose membership is synced from the matching Okta group — so the
// group -> role mapping lives in exactly one place. This is the "Joiner" path
// enforced at the cluster.

resource "teleport_login_rule" "okta_groups_to_roles" {
  version  = "v1"
  metadata = { name = "okta-groups-to-roles" }
  priority = 0

  // traits_map values are bare predicate expressions (NOT role-template {{...}}
  // mustache), and each maps to an object with a `values` list.
  traits_map = {
    "logins" = { values = ["email.local(external.email)"] }
    "groups" = { values = ["external.groups"] }
  }
}

// Per-department standing-access lists. grants.roles is pulled from
// local.department_roles (roles.tf) so the department -> role mapping is defined
// once; Okta group -> access-list membership is synced from the IdP. This is what
// actually attaches roles on the Joiner path.
resource "teleport_access_list" "department" {
  for_each = local.department_roles

  header = {
    version  = "v1"
    metadata = { name = "dept-${lower(each.key)}" }
  }
  spec = {
    title       = "${each.key} standing access"
    description = "Roles granted to the ${each.key} department via Okta SSO group membership."
    owners      = [{ name = "it-admin", description = "IT Security owns this review." }]
    grants = {
      roles = each.value
    }
    audit = {
      recurrence = { frequency = 3 } // months between recertifications
    }
  }
}

// Just-in-time elevation: SREs may REQUEST db-readonly for an oncall shift. The
// lifecycle controller auto-approves requests that fall within policy
// (engine.CanAutoApprove); anything broader routes to an access-reviewer. At the
// cluster a request needs one approval by default — genuine cluster-side
// auto-approval is modeled with Access Monitoring Rules (out of scope here).
resource "teleport_role" "sre_oncall_jit" {
  version = "v7"
  metadata = {
    name        = "sre-oncall-jit"
    description = "Lets k8s-prod holders request db-readonly just-in-time."
  }
  spec = {
    options = { max_session_ttl = "4h" }
    allow = {
      request = {
        roles        = ["db-readonly"]
        thresholds   = [{ approve = 1, deny = 1 }]
        max_duration = "8h"
      }
    }
  }
}

// Access list for periodic access reviews — IT/Security run these quarterly for
// SOC 2 / FedRAMP. Membership is the audited "who can reach prod" set.
resource "teleport_access_list" "prod_access" {
  header = {
    version  = "v1"
    metadata = { name = "prod-access" }
  }
  spec = {
    title       = "Production Access"
    description = "Identities with standing production access. Reviewed quarterly."
    owners      = [{ name = "it-admin", description = "IT Security owns this review." }]
    grants = {
      roles = ["k8s-prod"]
    }
    audit = {
      recurrence = {
        frequency = 3 // months between recertifications
      }
    }
    membership_requires = {
      roles = ["k8s-prod"]
    }
  }
}
