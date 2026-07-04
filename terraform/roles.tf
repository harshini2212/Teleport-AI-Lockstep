// Department roles — the enforced half of the policy mirrored in
// go/internal/policy/policy.go. Each maps to short-lived, least-privilege
// access. max_session_ttl is capped at 8h everywhere so every credential is
// ephemeral by construction.

locals {
  // Single source for the per-department -> role mapping, consumed by the
  // login rule so SSO group membership grants exactly these roles.
  department_roles = {
    Engineering = ["dev-access", "k8s-staging"]
    SRE         = ["dev-access", "k8s-prod", "db-readonly"]
    Security    = ["auditor", "db-readonly"]
    IT          = ["it-admin", "device-admin"]
    Sales       = ["crm-access"]
    Finance     = ["finance-app", "db-readonly"]
  }
}

resource "teleport_role" "dev_access" {
  version = "v7"
  metadata = {
    name        = "dev-access"
    description = "Baseline developer access to staging/dev nodes."
  }
  spec = {
    options = {
      max_session_ttl = "8h"
    }
    allow = {
      logins      = ["{{internal.logins}}"]
      node_labels = { "env" = ["dev", "staging"] }
    }
  }
}

resource "teleport_role" "k8s_staging" {
  version = "v7"
  metadata = {
    name        = "k8s-staging"
    description = "Read/write to the staging Kubernetes cluster."
  }
  spec = {
    options = { max_session_ttl = "8h" }
    allow = {
      kubernetes_labels = { "env" = ["staging"] }
      kubernetes_groups = ["developers"]
    }
  }
}

resource "teleport_role" "k8s_prod" {
  version = "v7"
  metadata = {
    name        = "k8s-prod"
    description = "Production Kubernetes access — SRE only, requires device trust."
  }
  spec = {
    options = {
      max_session_ttl    = "4h"
      device_trust_mode  = "required"
    }
    allow = {
      kubernetes_labels = { "env" = ["prod"] }
      kubernetes_groups = ["sre"]
    }
  }
}

resource "teleport_role" "db_readonly" {
  version = "v7"
  metadata = {
    name        = "db-readonly"
    description = "Read-only database access via Teleport DB proxy."
  }
  spec = {
    options = { max_session_ttl = "8h" }
    allow = {
      db_labels = { "*" = ["*"] }
      db_users  = ["readonly"]
      db_names  = ["*"]
    }
  }
}

resource "teleport_role" "it_admin" {
  version = "v7"
  metadata = {
    name        = "it-admin"
    description = "Internal IT administration."
  }
  spec = {
    options = { max_session_ttl = "8h" }
    allow = {
      logins      = ["{{internal.logins}}"]
      node_labels = { "team" = ["it"] }
      rules = [{
        resources = ["user", "role", "lock"]
        verbs     = ["list", "read", "create", "update", "delete"]
      }]
    }
  }
}

resource "teleport_role" "access_reviewer" {
  version = "v7"
  metadata = {
    name        = "access-reviewer"
    description = "Granted to managers — can review and approve access requests."
  }
  spec = {
    options = { max_session_ttl = "8h" }
    allow = {
      review_requests = {
        roles = ["dev-access", "k8s-staging", "db-readonly", "crm-access"]
      }
    }
  }
}
